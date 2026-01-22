"""Spotlight index parser for macOS forensics.

Wraps the spotlight_parser.py tool to query Spotlight indexes.
Spotlight indexes contain file metadata even after files are deleted.
"""

import csv
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..utils.timestamps import mac_absolute_to_utc, format_utc
from ..config import SPOTLIGHT_PARSER_PATH


class SpotlightParser:
    """Parser for macOS Spotlight indexes."""

    def __init__(self, spotlight_path: str):
        """Initialize with path to Spotlight database.

        Args:
            spotlight_path: Path to .store.db file or .Spotlight-V100 directory
        """
        self.spotlight_path = Path(spotlight_path)
        self._parsed_data: Optional[List[Dict]] = None
        self._output_dir: Optional[Path] = None

    def _ensure_parsed(self) -> Path:
        """Ensure Spotlight data is parsed to TSV."""
        if self._output_dir and (self._output_dir / "spotlight-store_fullpaths.tsv").exists():
            return self._output_dir

        if not Path(SPOTLIGHT_PARSER_PATH).exists():
            raise FileNotFoundError(
                f"spotlight_parser not found at {SPOTLIGHT_PARSER_PATH}. "
                "Please install it or provide pre-parsed output."
            )

        # Create temp output directory
        self._output_dir = Path(tempfile.mkdtemp(prefix="spotlight_"))

        # Find the .store.db file
        store_db = self._find_store_db()
        if not store_db:
            raise FileNotFoundError(f"Could not find .store.db in {self.spotlight_path}")

        # Run spotlight_parser
        cmd = [
            "python3",
            SPOTLIGHT_PARSER_PATH,
            str(store_db),
            str(self._output_dir),
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to parse Spotlight: {e.stderr.decode()}")

        return self._output_dir

    def _find_store_db(self) -> Optional[Path]:
        """Find the .store.db file in Spotlight path."""
        if self.spotlight_path.suffix == ".db":
            return self.spotlight_path

        # Look in common locations
        patterns = [
            "*.db",
            "store.db",
            ".store.db",
            "Store-V2/*/.store.db",
            "*/.store.db",
        ]

        for pattern in patterns:
            matches = list(self.spotlight_path.glob(pattern))
            if matches:
                return matches[0]

        return None

    def _load_parsed_data(self) -> List[Dict]:
        """Load parsed data (TSV or TXT format)."""
        if self._parsed_data is not None:
            return self._parsed_data

        output_dir = self._ensure_parsed()

        # Try TSV first (full paths version)
        tsv_file = output_dir / "spotlight-store_fullpaths.tsv"
        if tsv_file.exists():
            self._parsed_data = []
            with open(tsv_file, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f, delimiter="\t")
                for row in reader:
                    self._parsed_data.append(row)
            return self._parsed_data

        # Try other TSV files
        tsv_files = list(output_dir.glob("*.tsv"))
        if tsv_files:
            self._parsed_data = []
            with open(tsv_files[0], "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f, delimiter="\t")
                for row in reader:
                    self._parsed_data.append(row)
            return self._parsed_data

        # Fall back to TXT format (user/iOS spotlight db)
        txt_file = output_dir / "spotlight-store_data.txt"
        if txt_file.exists():
            self._parsed_data = self._parse_txt_format(txt_file)
            return self._parsed_data

        raise FileNotFoundError(f"No spotlight output found in {output_dir}")

    def _parse_txt_format(self, txt_file: Path) -> List[Dict]:
        """Parse spotlight-store_data.txt format.

        Format: Records separated by dashes, key --> value pairs.
        """
        records = []
        current_record = {}

        with open(txt_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()

                # Record separator
                if line.startswith("----"):
                    if current_record:
                        records.append(current_record)
                    current_record = {}
                    continue

                # Key --> Value pair
                if " --> " in line:
                    key, _, value = line.partition(" --> ")
                    current_record[key.strip()] = value.strip()

        # Don't forget last record
        if current_record:
            records.append(current_record)

        return records

    def search(
        self,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        inode: Optional[int] = None,
        path_contains: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Search Spotlight index.

        Args:
            filename: Filter by filename (substring match)
            content_type: Filter by content type (e.g., "public.executable")
            inode: Find file by inode number
            path_contains: Filter by path substring
            time_start: Filter by modification time after
            time_end: Filter by modification time before
            limit: Maximum results
            offset: Pagination offset

        Returns:
            Dict with search results
        """
        data = self._load_parsed_data()
        results = []
        matched = 0
        skipped = 0

        for row in data:
            # Apply filters
            if filename:
                row_filename = row.get("kMDItemDisplayName", "") or row.get("_kMDItemFileName", "")
                if filename.lower() not in row_filename.lower():
                    continue

            if content_type:
                row_type = row.get("kMDItemContentType", "")
                if content_type.lower() not in row_type.lower():
                    continue

            if inode:
                row_inode = row.get("kMDStoreInodeNumber") or row.get("inode")
                try:
                    if int(row_inode) != inode:
                        continue
                except (ValueError, TypeError):
                    continue

            if path_contains:
                row_path = row.get("full_path", "") or row.get("kMDItemPath", "")
                if path_contains.lower() not in row_path.lower():
                    continue

            # Time filters (if available)
            if time_start or time_end:
                mod_time = row.get("kMDItemContentModificationDate") or row.get("kMDItemFSContentChangeDate")
                if mod_time:
                    try:
                        # Try to parse the timestamp
                        row_time = self._parse_spotlight_time(mod_time)
                        if time_start and row_time < time_start:
                            continue
                        if time_end and row_time > time_end:
                            continue
                    except Exception:
                        pass

            matched += 1

            if skipped < offset:
                skipped += 1
                continue

            if len(results) < limit:
                results.append(self._format_result(row))

        return {
            "results": results,
            "total_matched": matched,
            "returned": len(results),
            "has_more": matched > offset + limit,
        }

    def _parse_spotlight_time(self, time_str: str) -> datetime:
        """Parse Spotlight timestamp to datetime."""
        # Spotlight uses various formats
        # Try Mac Absolute Time first (numeric)
        try:
            mac_time = float(time_str)
            return mac_absolute_to_utc(mac_time)
        except ValueError:
            pass

        # Try ISO format
        try:
            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except ValueError:
            pass

        raise ValueError(f"Cannot parse time: {time_str}")

    def _format_result(self, row: Dict) -> Dict[str, Any]:
        """Format a Spotlight result row."""
        result = {
            "path": row.get("full_path") or row.get("kMDItemPath", ""),
            "filename": row.get("kMDItemDisplayName") or row.get("_kMDItemFileName", ""),
            "inode": None,
            "content_type": row.get("kMDItemContentType") or row.get("kMDItemContentTypeTree", ""),
            "file_size": None,
            "created_utc": None,
            "modified_utc": None,
            "last_updated": None,
        }

        # Parse inode (TXT format uses Inode_Num)
        inode_val = row.get("kMDStoreInodeNumber") or row.get("inode") or row.get("Inode_Num")
        if inode_val:
            try:
                result["inode"] = int(inode_val)
            except ValueError:
                pass

        # Parse file size
        size_val = row.get("kMDItemFSSize") or row.get("kMDItemPhysicalSize")
        if size_val:
            try:
                result["file_size"] = int(size_val)
            except ValueError:
                pass

        # Parse timestamps
        created = row.get("kMDItemFSCreationDate") or row.get("kMDItemDateAdded")
        if created:
            try:
                result["created_utc"] = format_utc(self._parse_spotlight_time(created))
            except Exception:
                pass

        modified = row.get("kMDItemContentModificationDate") or row.get("kMDItemFSContentChangeDate")
        if modified:
            try:
                result["modified_utc"] = format_utc(self._parse_spotlight_time(modified))
            except Exception:
                pass

        # TXT format has Last_Updated
        last_updated = row.get("Last_Updated")
        if last_updated:
            try:
                result["last_updated"] = last_updated  # Already formatted as string
            except Exception:
                pass

        # Check if executable
        result["executable"] = "executable" in result["content_type"].lower()

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the Spotlight index."""
        data = self._load_parsed_data()

        stats = {
            "total_entries": len(data),
            "content_types": {},
            "top_directories": {},
        }

        for row in data:
            # Count content types
            ct = row.get("kMDItemContentType", "unknown")
            stats["content_types"][ct] = stats["content_types"].get(ct, 0) + 1

            # Count directories
            path = row.get("full_path") or row.get("kMDItemPath", "")
            if "/" in path:
                dir_path = "/".join(path.split("/")[:-1])
                stats["top_directories"][dir_path] = stats["top_directories"].get(dir_path, 0) + 1

        # Sort and limit
        stats["top_content_types"] = sorted(
            stats["content_types"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:20]

        stats["top_directories"] = sorted(
            stats["top_directories"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:20]

        del stats["content_types"]

        return stats
