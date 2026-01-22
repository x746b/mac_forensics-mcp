"""FSEvents parser for macOS forensics.

Wraps FSEParser_V4.1.py to parse .fseventsd directories and query results.
FSEvents record file creation, deletion, modification, and rename operations.
"""

import subprocess
import sqlite3
import tempfile
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Generator

from ..utils.timestamps import format_utc
from ..config import FSEPARSER_PATH


class FSEventsParser:
    """Parser for macOS FSEvents (.fseventsd)."""

    # Map flags to forensically interesting categories
    EVENT_CATEGORIES = {
        "created": ["Created;", "FolderCreated;"],
        "deleted": ["Removed;"],
        "modified": ["Modified;", "InodeMetaMod;"],
        "renamed": ["Renamed;"],
        "mount": ["Mount;", "Unmount;"],
        "hardlink": ["HardLink;", "LastHardLinkRemoved;"],
        "symlink": ["SymbolicLink;"],
        "permission": ["PermissionChange;"],
        "xattr": ["ExtendedAttrModified;", "ExtendedAttrRemoved;"],
    }

    def __init__(self, fseventsd_path: str):
        """Initialize with path to .fseventsd directory.

        Args:
            fseventsd_path: Path to .fseventsd directory or pre-parsed SQLite DB
        """
        self.fseventsd_path = Path(fseventsd_path)
        self._db_path: Optional[Path] = None
        self._output_dir: Optional[Path] = None

    def _ensure_parsed(self) -> Path:
        """Ensure FSEvents are parsed to SQLite database."""
        # Check if input is already a SQLite database
        if self.fseventsd_path.suffix in (".db", ".sqlite") and self.fseventsd_path.exists():
            self._db_path = self.fseventsd_path
            return self._db_path

        # Check for existing parsed output in same directory
        parent = self.fseventsd_path.parent
        for db_name in ["FSEvents.sqlite", "FSEvents.db"]:
            possible_db = parent / "FSEvents" / db_name
            if possible_db.exists():
                self._db_path = possible_db
                return self._db_path
            # Also check in FSE_Reports (FSEParser output)
            possible_db = parent / "FSE_Reports" / db_name
            if possible_db.exists():
                self._db_path = possible_db
                return self._db_path

        # Check temp directory for cached parse
        if self._db_path and self._db_path.exists():
            return self._db_path

        # Need to parse
        if not Path(FSEPARSER_PATH).exists():
            raise FileNotFoundError(
                f"FSEParser not found at {FSEPARSER_PATH}. "
                "Please install it or provide pre-parsed database."
            )

        # Create temp output directory
        self._output_dir = Path(tempfile.mkdtemp(prefix="fsevents_"))

        # Run FSEParser
        cmd = [
            "python3",
            FSEPARSER_PATH,
            "-s", str(self.fseventsd_path),
            "-o", str(self._output_dir),
            "-t", "folder",
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=300)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to parse FSEvents: {e.stderr.decode()}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("FSEvents parsing timed out")

        # Find the output database (FSEParser creates .sqlite, not .db)
        db_files = list(self._output_dir.rglob("*.sqlite"))
        if not db_files:
            db_files = list(self._output_dir.rglob("*.db"))
        if not db_files:
            raise FileNotFoundError(f"No database found after parsing in {self._output_dir}")

        self._db_path = db_files[0]
        return self._db_path

    def search(
        self,
        path_filter: Optional[str] = None,
        filename_filter: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Search FSEvents records.

        Args:
            path_filter: Filter by full path (substring match)
            filename_filter: Filter by filename (substring match)
            event_types: Filter by event type categories (created, deleted, modified, renamed)
            time_start: Filter events after this time (approximate)
            time_end: Filter events before this time (approximate)
            limit: Maximum results to return
            offset: Pagination offset

        Returns:
            Dict with search results and metadata
        """
        db_path = self._ensure_parsed()

        results = []
        total_matched = 0

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row

        try:
            # Build query
            query = "SELECT * FROM fsevents_sorted_by_event_id WHERE 1=1"
            params = []

            if path_filter:
                query += " AND fullpath LIKE ?"
                params.append(f"%{path_filter}%")

            if filename_filter:
                query += " AND filename LIKE ?"
                params.append(f"%{filename_filter}%")

            if event_types:
                # Build flag conditions
                flag_conditions = []
                for event_type in event_types:
                    if event_type in self.EVENT_CATEGORIES:
                        for flag in self.EVENT_CATEGORIES[event_type]:
                            flag_conditions.append("flags LIKE ?")
                            params.append(f"%{flag}%")

                if flag_conditions:
                    query += f" AND ({' OR '.join(flag_conditions)})"

            if time_start:
                query += " AND approx_dates_plus_minus_one_day >= ?"
                params.append(time_start.strftime("%Y-%m-%d"))

            if time_end:
                query += " AND approx_dates_plus_minus_one_day <= ?"
                params.append(time_end.strftime("%Y-%m-%d"))

            # Count total matches
            count_query = query.replace("SELECT *", "SELECT COUNT(*)")
            cursor = conn.execute(count_query, params)
            total_matched = cursor.fetchone()[0]

            # Add pagination
            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = conn.execute(query, params)

            for row in cursor:
                results.append(self._format_result(dict(row)))

        finally:
            conn.close()

        return {
            "results": results,
            "total_matched": total_matched,
            "returned": len(results),
            "has_more": total_matched > offset + limit,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about FSEvents records."""
        db_path = self._ensure_parsed()

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row

        try:
            stats = {
                "total_records": 0,
                "time_range": {},
                "event_counts": {},
                "top_paths": [],
            }

            # Total records
            cursor = conn.execute("SELECT COUNT(*) FROM fsevents_sorted_by_event_id")
            stats["total_records"] = cursor.fetchone()[0]

            # Time range
            cursor = conn.execute(
                "SELECT MIN(approx_dates_plus_minus_one_day), MAX(approx_dates_plus_minus_one_day) "
                "FROM fsevents_sorted_by_event_id WHERE approx_dates_plus_minus_one_day != ''"
            )
            row = cursor.fetchone()
            if row:
                stats["time_range"] = {
                    "earliest": row[0],
                    "latest": row[1],
                }

            # Count by event type
            for category, flags in self.EVENT_CATEGORIES.items():
                conditions = " OR ".join([f"flags LIKE '%{flag}%'" for flag in flags])
                cursor = conn.execute(f"SELECT COUNT(*) FROM fsevents_sorted_by_event_id WHERE {conditions}")
                count = cursor.fetchone()[0]
                if count > 0:
                    stats["event_counts"][category] = count

            # Top directories
            cursor = conn.execute("""
                SELECT
                    CASE
                        WHEN fullpath LIKE '%/%' THEN SUBSTR(fullpath, 1, INSTR(fullpath, '/') +
                            INSTR(SUBSTR(fullpath, INSTR(fullpath, '/') + 1), '/'))
                        ELSE fullpath
                    END as dir,
                    COUNT(*) as cnt
                FROM fsevents_sorted_by_event_id
                GROUP BY dir
                ORDER BY cnt DESC
                LIMIT 20
            """)
            stats["top_paths"] = [{"path": row[0], "count": row[1]} for row in cursor]

        finally:
            conn.close()

        return stats

    def _format_result(self, row: Dict) -> Dict[str, Any]:
        """Format a FSEvents record."""
        result = {
            "event_id": row.get("id"),
            "fullpath": row.get("fullpath", ""),
            "filename": row.get("filename", ""),
            "type": row.get("type", ""),
            "flags": row.get("flags", ""),
            "approx_date": row.get("approx_dates_plus_minus_one_day", ""),
            "node_id": row.get("node_id"),
            "source": row.get("source", ""),
            "source_modified": row.get("source_modified_time", ""),
        }

        # Parse flags into categories
        flags = result["flags"]
        result["event_categories"] = []
        for category, flag_list in self.EVENT_CATEGORIES.items():
            if any(flag in flags for flag in flag_list):
                result["event_categories"].append(category)

        return result

    def get_path_history(
        self,
        path: str,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Get all events for a specific path.

        Args:
            path: Exact path or path prefix to search
            limit: Maximum results

        Returns:
            Timeline of events for the path
        """
        db_path = self._ensure_parsed()

        events = []
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row

        try:
            cursor = conn.execute(
                "SELECT * FROM fsevents_sorted_by_event_id WHERE fullpath LIKE ? ORDER BY id",
                [f"{path}%"]
            )

            for row in cursor:
                if len(events) >= limit:
                    break
                events.append(self._format_result(dict(row)))

        finally:
            conn.close()

        return {
            "path": path,
            "events": events,
            "total": len(events),
        }
