"""SQLite database parser for macOS forensics.

Handles common macOS databases: KnowledgeC, Safari History, TCC, Quarantine, etc.
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..utils.timestamps import mac_absolute_to_utc, webkit_to_utc, format_utc


class SQLiteParser:
    """Generic SQLite parser with macOS-specific helpers."""

    def __init__(self, db_path: str):
        self.path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    def _connect(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            if not self.path.exists():
                raise FileNotFoundError(f"Database not found: {self.path}")
            self._conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def get_tables(self) -> List[str]:
        """Get list of tables in database."""
        conn = self._connect()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        return [row[0] for row in cursor.fetchall()]

    def get_schema(self, table: str) -> List[Dict[str, str]]:
        """Get schema for a table."""
        conn = self._connect()
        cursor = conn.execute(f"PRAGMA table_info({table})")
        return [
            {"name": row[1], "type": row[2], "notnull": bool(row[3]), "pk": bool(row[5])}
            for row in cursor.fetchall()
        ]

    def query(
        self,
        sql: str,
        params: Tuple = (),
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Execute a query with pagination.

        Args:
            sql: SQL query (without LIMIT/OFFSET)
            params: Query parameters
            limit: Max rows to return
            offset: Rows to skip

        Returns:
            Dict with "results", "columns", "row_count"
        """
        conn = self._connect()

        # Add pagination
        paginated_sql = f"{sql} LIMIT {limit} OFFSET {offset}"

        cursor = conn.execute(paginated_sql, params)
        columns = [desc[0] for desc in cursor.description] if cursor.description else []

        results = []
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))

        return {
            "columns": columns,
            "results": results,
            "returned": len(results),
            "has_more": len(results) == limit,
        }


class KnowledgeCParser(SQLiteParser):
    """Parser for KnowledgeC.db (Pattern of Life database)."""

    def get_app_usage(
        self,
        app_name: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get application usage data.

        Args:
            app_name: Filter by app bundle ID (substring match)
            time_start: Filter events after this time
            time_end: Filter events before this time
            limit: Max results
            offset: Pagination

        Returns:
            Dict with app usage records
        """
        conn = self._connect()

        # KnowledgeC schema varies, try common table names
        tables = self.get_tables()

        # Look for app usage table
        usage_table = None
        for t in ["ZOBJECT", "ZINTERACTION"]:
            if t in tables:
                usage_table = t
                break

        if not usage_table:
            return {"error": "Could not find app usage table", "tables": tables}

        # Build query
        sql = f"""
            SELECT
                ZSTREAMNAME,
                ZVALUESTRING,
                ZSTARTDATE,
                ZENDDATE,
                ZCREATIONDATE
            FROM {usage_table}
            WHERE ZSTREAMNAME LIKE '%app%'
        """
        params = []

        if app_name:
            sql += " AND ZVALUESTRING LIKE ?"
            params.append(f"%{app_name}%")

        if time_start:
            mac_start = (time_start.timestamp() - 978307200)
            sql += " AND ZSTARTDATE >= ?"
            params.append(mac_start)

        if time_end:
            mac_end = (time_end.timestamp() - 978307200)
            sql += " AND ZSTARTDATE <= ?"
            params.append(mac_end)

        sql += " ORDER BY ZSTARTDATE DESC"

        result = self.query(sql, tuple(params), limit, offset)

        # Convert timestamps
        for row in result["results"]:
            for key in ["ZSTARTDATE", "ZENDDATE", "ZCREATIONDATE"]:
                if key in row and row[key]:
                    row[f"{key}_utc"] = format_utc(mac_absolute_to_utc(row[key]))

        return result

    def get_device_activity(
        self,
        activity_type: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Get device activity events (screen on/off, lock/unlock).

        Args:
            activity_type: Filter by type (screen_on, screen_off, lock, unlock)
            time_start: Filter after this time
            time_end: Filter before this time
            limit: Max results

        Returns:
            Dict with device activity records
        """
        conn = self._connect()

        activity_streams = {
            "screen_on": "%isScreenOn%",
            "screen_off": "%isScreenOn%",
            "lock": "%isLocked%",
            "unlock": "%isLocked%",
            "power": "%power%",
        }

        stream_filter = activity_streams.get(activity_type, "%device%")

        sql = """
            SELECT
                ZSTREAMNAME,
                ZVALUESTRING,
                ZVALUENUMBER,
                ZSTARTDATE,
                ZENDDATE
            FROM ZOBJECT
            WHERE ZSTREAMNAME LIKE ?
            ORDER BY ZSTARTDATE DESC
        """

        result = self.query(sql, (stream_filter,), limit)

        for row in result["results"]:
            if "ZSTARTDATE" in row and row["ZSTARTDATE"]:
                row["start_utc"] = format_utc(mac_absolute_to_utc(row["ZSTARTDATE"]))
            if "ZENDDATE" in row and row["ZENDDATE"]:
                row["end_utc"] = format_utc(mac_absolute_to_utc(row["ZENDDATE"]))

        return result


class SafariHistoryParser(SQLiteParser):
    """Parser for Safari History.db."""

    def get_history(
        self,
        url_filter: Optional[str] = None,
        title_filter: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get browsing history.

        Args:
            url_filter: Filter by URL (substring)
            title_filter: Filter by page title (substring)
            time_start: Filter visits after this time
            time_end: Filter visits before this time
            limit: Max results
            offset: Pagination

        Returns:
            Dict with history records
        """
        conn = self._connect()

        sql = """
            SELECT
                history_visits.id,
                history_items.url,
                history_visits.title,
                history_visits.visit_time,
                history_visits.redirect_source,
                history_items.visit_count
            FROM history_visits
            JOIN history_items ON history_visits.history_item = history_items.id
            WHERE 1=1
        """
        params = []

        if url_filter:
            sql += " AND history_items.url LIKE ?"
            params.append(f"%{url_filter}%")

        if title_filter:
            sql += " AND history_visits.title LIKE ?"
            params.append(f"%{title_filter}%")

        if time_start:
            mac_start = time_start.timestamp() - 978307200
            sql += " AND history_visits.visit_time >= ?"
            params.append(mac_start)

        if time_end:
            mac_end = time_end.timestamp() - 978307200
            sql += " AND history_visits.visit_time <= ?"
            params.append(mac_end)

        sql += " ORDER BY history_visits.visit_time DESC"

        result = self.query(sql, tuple(params), limit, offset)

        # Convert timestamps
        for row in result["results"]:
            if "visit_time" in row and row["visit_time"]:
                row["visit_time_utc"] = format_utc(mac_absolute_to_utc(row["visit_time"]))

        return result

    def get_searches(
        self,
        query_filter: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Extract search queries from history URLs.

        Parses search queries from Google, Bing, DuckDuckGo, etc.
        """
        import urllib.parse

        history = self.get_history(
            url_filter="search",
            time_start=time_start,
            time_end=time_end,
            limit=500,  # Get more to filter
        )

        searches = []
        seen_queries = set()

        for row in history["results"]:
            url = row.get("url", "")

            # Parse search query from URL
            query = None
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                # Common search parameter names
                for param in ["q", "query", "search", "text", "p"]:
                    if param in params:
                        query = params[param][0]
                        break
            except Exception:
                continue

            if query and query not in seen_queries:
                if query_filter and query_filter.lower() not in query.lower():
                    continue

                seen_queries.add(query)
                searches.append({
                    "query": query,
                    "url": url,
                    "timestamp_utc": row.get("visit_time_utc"),
                    "title": row.get("title"),
                })

                if len(searches) >= limit:
                    break

        return {
            "results": searches,
            "returned": len(searches),
        }


class TCCParser(SQLiteParser):
    """Parser for TCC.db (Transparency, Consent, Control)."""

    SERVICE_NAMES = {
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceCamera": "Camera",
        "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceSystemPolicyDesktopFolder": "Desktop Folder",
        "kTCCServiceSystemPolicyDocumentsFolder": "Documents Folder",
        "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Folder",
    }

    def get_permissions(
        self,
        service: Optional[str] = None,
        client: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Get TCC permissions.

        Args:
            service: Filter by service (e.g., "kTCCServiceScreenCapture")
            client: Filter by client app bundle ID
            limit: Max results

        Returns:
            Dict with permission records
        """
        conn = self._connect()

        sql = """
            SELECT
                service,
                client,
                client_type,
                auth_value,
                auth_reason,
                last_modified,
                indirect_object_identifier
            FROM access
            WHERE 1=1
        """
        params = []

        if service:
            sql += " AND service LIKE ?"
            params.append(f"%{service}%")

        if client:
            sql += " AND client LIKE ?"
            params.append(f"%{client}%")

        sql += " ORDER BY last_modified DESC"

        result = self.query(sql, tuple(params), limit)

        # Enhance results
        for row in result["results"]:
            # Add friendly service name
            svc = row.get("service", "")
            row["service_friendly"] = self.SERVICE_NAMES.get(svc, svc)

            # Decode auth_value
            auth = row.get("auth_value", 0)
            row["allowed"] = auth == 2
            row["denied"] = auth == 0

            # Convert timestamp (TCC.db uses Unix timestamps, not Mac Absolute Time)
            if "last_modified" in row and row["last_modified"]:
                row["last_modified_utc"] = format_utc(
                    datetime.fromtimestamp(row["last_modified"], tz=timezone.utc)
                )

        return result


class QuarantineParser(SQLiteParser):
    """Parser for QuarantineEventsV2 database."""

    def get_events(
        self,
        filename_filter: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Get quarantine events (file downloads).

        Args:
            filename_filter: Filter by filename
            time_start: Filter after this time
            time_end: Filter before this time
            limit: Max results

        Returns:
            Dict with quarantine events
        """
        conn = self._connect()

        sql = """
            SELECT
                LSQuarantineEventIdentifier,
                LSQuarantineTimeStamp,
                LSQuarantineAgentBundleIdentifier,
                LSQuarantineAgentName,
                LSQuarantineDataURLString,
                LSQuarantineOriginURLString,
                LSQuarantineSenderName,
                LSQuarantineSenderAddress
            FROM LSQuarantineEvent
            WHERE 1=1
        """
        params = []

        if filename_filter:
            sql += " AND (LSQuarantineDataURLString LIKE ? OR LSQuarantineOriginURLString LIKE ?)"
            params.extend([f"%{filename_filter}%", f"%{filename_filter}%"])

        if time_start:
            mac_start = time_start.timestamp() - 978307200
            sql += " AND LSQuarantineTimeStamp >= ?"
            params.append(mac_start)

        if time_end:
            mac_end = time_end.timestamp() - 978307200
            sql += " AND LSQuarantineTimeStamp <= ?"
            params.append(mac_end)

        sql += " ORDER BY LSQuarantineTimeStamp DESC"

        result = self.query(sql, tuple(params), limit)

        # Convert timestamps and simplify field names
        for row in result["results"]:
            if "LSQuarantineTimeStamp" in row and row["LSQuarantineTimeStamp"]:
                row["timestamp_utc"] = format_utc(
                    mac_absolute_to_utc(row["LSQuarantineTimeStamp"])
                )
            row["download_url"] = row.pop("LSQuarantineDataURLString", None)
            row["origin_url"] = row.pop("LSQuarantineOriginURLString", None)
            row["app"] = row.pop("LSQuarantineAgentName", None)
            row["sender"] = row.pop("LSQuarantineSenderName", None)

        return result
