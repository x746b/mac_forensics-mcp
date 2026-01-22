"""Plist parser for macOS forensics.

Handles both binary and XML plist formats with automatic type detection.
"""

import plistlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

from ..utils.timestamps import normalize_timestamp, format_utc


class PlistParser:
    """Parser for macOS property list files."""

    def __init__(self, plist_path: str):
        self.path = Path(plist_path)
        self._data = None

    def parse(self) -> Dict[str, Any]:
        """Parse the plist file and return its contents."""
        if self._data is not None:
            return self._data

        if not self.path.exists():
            raise FileNotFoundError(f"Plist not found: {self.path}")

        with open(self.path, "rb") as f:
            try:
                self._data = plistlib.load(f)
            except Exception as e:
                # Try biplist for malformed plists
                try:
                    import biplist
                    self._data = biplist.readPlist(str(self.path))
                except ImportError:
                    raise ValueError(f"Failed to parse plist: {e}")

        return self._data

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get a value using dot-notation key path.

        Args:
            key_path: Dot-separated path like "deletedUsers.0.date"
            default: Default value if key not found

        Returns:
            Value at key path or default
        """
        data = self.parse()
        keys = key_path.replace("[", ".").replace("]", "").split(".")

        current = data
        for key in keys:
            if current is None:
                return default

            if isinstance(current, dict):
                current = current.get(key)
            elif isinstance(current, list):
                try:
                    idx = int(key)
                    current = current[idx] if idx < len(current) else None
                except (ValueError, IndexError):
                    return default
            else:
                return default

        return current if current is not None else default

    def search(self, pattern: str, _data: Any = None, _path: str = "") -> List[Dict[str, Any]]:
        """Search for keys matching a pattern (case-insensitive).

        Args:
            pattern: Search pattern (substring match)

        Returns:
            List of {"path": str, "value": Any} matches
        """
        if _data is None:
            _data = self.parse()

        results = []
        pattern_lower = pattern.lower()

        if isinstance(_data, dict):
            for key, value in _data.items():
                current_path = f"{_path}.{key}" if _path else key

                # Check if key matches
                if pattern_lower in key.lower():
                    results.append({
                        "path": current_path,
                        "key": key,
                        "value": self._serialize_value(value),
                    })

                # Recurse into nested structures
                results.extend(self.search(pattern, value, current_path))

        elif isinstance(_data, list):
            for idx, item in enumerate(_data):
                current_path = f"{_path}[{idx}]"
                results.extend(self.search(pattern, item, current_path))

        return results

    def get_timestamps(self) -> List[Dict[str, Any]]:
        """Extract all timestamp values from the plist.

        Returns:
            List of {"path": str, "value": datetime, "utc": str}
        """
        return self._find_timestamps(self.parse())

    def _find_timestamps(self, data: Any, path: str = "") -> List[Dict[str, Any]]:
        """Recursively find timestamp values."""
        results = []

        if isinstance(data, datetime):
            results.append({
                "path": path,
                "value": data,
                "utc": format_utc(data),
            })
        elif isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # Check for timestamp-like keys
                if isinstance(value, (int, float)) and any(
                    ts_hint in key.lower()
                    for ts_hint in ["date", "time", "stamp", "created", "modified", "accessed"]
                ):
                    normalized = normalize_timestamp(value)
                    if normalized:
                        results.append({
                            "path": current_path,
                            "raw_value": value,
                            "utc": format_utc(normalized),
                        })

                results.extend(self._find_timestamps(value, current_path))

        elif isinstance(data, list):
            for idx, item in enumerate(data):
                results.extend(self._find_timestamps(item, f"{path}[{idx}]"))

        return results

    def _serialize_value(self, value: Any) -> Any:
        """Serialize value for JSON output."""
        if isinstance(value, datetime):
            return format_utc(value)
        elif isinstance(value, bytes):
            return f"<binary data: {len(value)} bytes>"
        elif isinstance(value, (dict, list)):
            return f"<{type(value).__name__}: {len(value)} items>"
        return value

    def to_dict(self) -> Dict[str, Any]:
        """Return parsed data as a serializable dictionary."""
        return self._deep_serialize(self.parse())

    def _deep_serialize(self, data: Any) -> Any:
        """Recursively serialize data for JSON output."""
        if isinstance(data, datetime):
            return format_utc(data)
        elif isinstance(data, bytes):
            # Try to decode as UTF-8, otherwise hex
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.hex()
        elif isinstance(data, dict):
            return {k: self._deep_serialize(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._deep_serialize(item) for item in data]
        return data
