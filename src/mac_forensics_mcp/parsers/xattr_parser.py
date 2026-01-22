"""Extended Attributes parser for macOS forensics.

Parses xattr data including:
- com.apple.quarantine (download quarantine info)
- com.apple.metadata:kMDItemWhereFroms (download URL chain)
- com.apple.metadata:kMDItemDownloadedDate
- com.apple.lastuseddate#PS (last opened by user)

Note: For triage collections, xattr data may be stored in:
1. Separate xattr files (e.g., file.txt._xattr)
2. AppleDouble files (._filename)
3. Resource forks
"""

import os
import plistlib
import struct
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import re

from ..utils.timestamps import mac_absolute_to_utc, format_utc


def parse_quarantine_string(qstring: str) -> Dict[str, Any]:
    """Parse com.apple.quarantine xattr value.

    Format: flags;timestamp;agent_name;UUID (semicolon-separated)
    Example: 0083;5f3a1b2c;Safari;12345678-1234-1234-1234-123456789abc

    Flags:
    - 0x0001: User has been notified
    - 0x0002: App has been launched
    - 0x0040: Downloaded file
    - 0x0080: File has been notarized
    """
    result = {
        "raw": qstring,
        "flags": None,
        "timestamp_utc": None,
        "agent_name": None,
        "uuid": None,
    }

    parts = qstring.split(";")
    if len(parts) >= 1:
        result["flags"] = parts[0]
        # Decode flags
        try:
            flags_int = int(parts[0], 16)
            result["flags_decoded"] = {
                "user_notified": bool(flags_int & 0x0001),
                "app_launched": bool(flags_int & 0x0002),
                "downloaded": bool(flags_int & 0x0040),
                "notarized": bool(flags_int & 0x0080),
            }
        except ValueError:
            pass

    if len(parts) >= 2:
        try:
            # Timestamp is hex-encoded Unix timestamp
            ts = int(parts[1], 16)
            result["timestamp_utc"] = format_utc(
                datetime.fromtimestamp(ts, tz=timezone.utc)
            )
        except (ValueError, OSError):
            pass

    if len(parts) >= 3:
        result["agent_name"] = parts[2]

    if len(parts) >= 4:
        result["uuid"] = parts[3]

    return result


def parse_where_from_plist(data: bytes) -> List[str]:
    """Parse kMDItemWhereFroms plist data.

    Returns list of URLs (download URL, referrer URL, etc.)
    """
    try:
        plist = plistlib.loads(data)
        if isinstance(plist, list):
            return [str(url) for url in plist]
        return [str(plist)]
    except Exception:
        return []


def parse_downloaded_date_plist(data: bytes) -> Optional[str]:
    """Parse kMDItemDownloadedDate plist data."""
    try:
        plist = plistlib.loads(data)
        if isinstance(plist, list) and len(plist) > 0:
            dt = plist[0]
        else:
            dt = plist

        if isinstance(dt, datetime):
            return format_utc(dt)
        return None
    except Exception:
        return None


def parse_last_used_date(data: bytes) -> Optional[str]:
    """Parse com.apple.lastuseddate#PS data.

    This is a binary format: 8-byte little-endian double (Mac Absolute Time)
    """
    try:
        if len(data) >= 8:
            mac_time = struct.unpack("<d", data[:8])[0]
            return format_utc(mac_absolute_to_utc(mac_time))
    except Exception:
        pass
    return None


class XattrParser:
    """Parser for macOS extended attributes."""

    # Common xattr names we're interested in
    FORENSIC_XATTRS = [
        "com.apple.quarantine",
        "com.apple.metadata:kMDItemWhereFroms",
        "com.apple.metadata:kMDItemDownloadedDate",
        "com.apple.lastuseddate#PS",
        "com.apple.metadata:_kMDItemUserTags",
        "com.apple.FinderInfo",
    ]

    def __init__(self, artifacts_dir: str):
        self.artifacts_dir = Path(artifacts_dir)

    def get_xattrs_for_file(self, file_path: str) -> Dict[str, Any]:
        """Get extended attributes for a specific file.

        In a triage collection, xattrs may be stored in:
        1. AppleDouble files (._filename)
        2. Separate .xattr files
        3. Within the file itself (if on APFS/HFS+ volume)
        """
        path = Path(file_path)
        result = {
            "file": str(path),
            "xattrs": {},
            "quarantine": None,
            "where_from": None,
            "downloaded_date_utc": None,
            "last_used_utc": None,
        }

        # Try to read xattrs directly (works on live systems or mounted images)
        try:
            import xattr
            x = xattr.xattr(str(path))
            for attr_name in x.list():
                try:
                    data = x.get(attr_name)
                    result["xattrs"][attr_name] = self._parse_xattr(attr_name, data)
                except Exception:
                    pass
        except ImportError:
            # xattr module not available, try other methods
            pass
        except Exception:
            pass

        # Try AppleDouble file (._filename)
        appledouble_path = path.parent / f"._{path.name}"
        if appledouble_path.exists():
            ad_xattrs = self._parse_appledouble(appledouble_path)
            result["xattrs"].update(ad_xattrs)

        # Extract specific forensic data
        if "com.apple.quarantine" in result["xattrs"]:
            result["quarantine"] = result["xattrs"]["com.apple.quarantine"]

        if "com.apple.metadata:kMDItemWhereFroms" in result["xattrs"]:
            result["where_from"] = result["xattrs"]["com.apple.metadata:kMDItemWhereFroms"]

        if "com.apple.metadata:kMDItemDownloadedDate" in result["xattrs"]:
            result["downloaded_date_utc"] = result["xattrs"]["com.apple.metadata:kMDItemDownloadedDate"]

        if "com.apple.lastuseddate#PS" in result["xattrs"]:
            result["last_used_utc"] = result["xattrs"]["com.apple.lastuseddate#PS"]

        return result

    def _parse_xattr(self, name: str, data: bytes) -> Any:
        """Parse xattr data based on its name."""
        if name == "com.apple.quarantine":
            try:
                qstring = data.decode("utf-8").strip("\x00")
                return parse_quarantine_string(qstring)
            except Exception:
                return {"raw": data.hex()}

        elif name == "com.apple.metadata:kMDItemWhereFroms":
            return parse_where_from_plist(data)

        elif name == "com.apple.metadata:kMDItemDownloadedDate":
            return parse_downloaded_date_plist(data)

        elif name == "com.apple.lastuseddate#PS":
            return parse_last_used_date(data)

        elif name == "com.apple.metadata:_kMDItemUserTags":
            try:
                tags = plistlib.loads(data)
                return tags
            except Exception:
                return {"raw": data.hex()}

        else:
            # Return hex for unknown xattrs
            try:
                return data.decode("utf-8")
            except Exception:
                return {"raw": data.hex()[:200]}  # Limit size

    def _parse_appledouble(self, ad_path: Path) -> Dict[str, Any]:
        """Parse AppleDouble file to extract xattrs.

        AppleDouble format stores resource fork and extended attributes.
        """
        xattrs = {}
        try:
            with open(ad_path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x00\x05\x16\x07":  # AppleDouble magic
                    return xattrs

                version = struct.unpack(">I", f.read(4))[0]
                f.read(16)  # Filler

                num_entries = struct.unpack(">H", f.read(2))[0]

                entries = []
                for _ in range(num_entries):
                    entry_id = struct.unpack(">I", f.read(4))[0]
                    offset = struct.unpack(">I", f.read(4))[0]
                    length = struct.unpack(">I", f.read(4))[0]
                    entries.append((entry_id, offset, length))

                # Entry ID 9 = FinderInfo, 2 = Resource Fork
                # Entry ID 9 often contains xattrs in newer formats
                for entry_id, offset, length in entries:
                    if entry_id == 9 and length > 0:  # Extended attributes
                        f.seek(offset)
                        data = f.read(length)
                        # Parse xattr header
                        xattrs.update(self._parse_xattr_blob(data))
        except Exception:
            pass

        return xattrs

    def _parse_xattr_blob(self, data: bytes) -> Dict[str, Any]:
        """Parse xattr blob from AppleDouble entry."""
        xattrs = {}
        try:
            # Check for xattr magic "ATTR"
            if len(data) < 36 or data[:4] != b"ATTR":
                return xattrs

            # Parse xattr header
            # Offset 12: number of xattrs (2 bytes)
            # Offset 14: xattr data offset (2 bytes)
            num_xattrs = struct.unpack(">H", data[12:14])[0]

            # Each xattr entry: offset (4), length (4), flags (1), name_len (1), name (variable)
            pos = 36  # Start of xattr entries

            for _ in range(num_xattrs):
                if pos + 10 > len(data):
                    break

                xattr_offset = struct.unpack(">I", data[pos:pos+4])[0]
                xattr_length = struct.unpack(">I", data[pos+4:pos+8])[0]
                # flags = data[pos+8]
                name_len = data[pos+9]

                if pos + 10 + name_len > len(data):
                    break

                name = data[pos+10:pos+10+name_len].decode("utf-8", errors="replace")

                # Get xattr data
                if xattr_offset + xattr_length <= len(data):
                    xattr_data = data[xattr_offset:xattr_offset+xattr_length]
                    xattrs[name] = self._parse_xattr(name, xattr_data)

                # Move to next entry (aligned to 4 bytes)
                entry_size = 10 + name_len
                entry_size = (entry_size + 3) & ~3  # Align to 4 bytes
                pos += entry_size
        except Exception:
            pass

        return xattrs

    def scan_directory(
        self,
        directory: str,
        recursive: bool = False,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Scan directory for files with forensically interesting xattrs."""
        results = []
        scanned = 0

        dir_path = Path(directory)
        if not dir_path.exists():
            return {"error": f"Directory not found: {directory}"}

        if recursive:
            files = dir_path.rglob("*")
        else:
            files = dir_path.glob("*")

        for file_path in files:
            if file_path.is_file() and not file_path.name.startswith("._"):
                scanned += 1
                xattr_data = self.get_xattrs_for_file(str(file_path))

                # Only include files with forensic xattrs
                if (xattr_data["quarantine"] or
                    xattr_data["where_from"] or
                    xattr_data["downloaded_date_utc"] or
                    xattr_data["last_used_utc"]):
                    results.append(xattr_data)

                    if len(results) >= limit:
                        break

        return {
            "results": results,
            "scanned": scanned,
            "returned": len(results),
            "has_more": len(results) >= limit,
        }
