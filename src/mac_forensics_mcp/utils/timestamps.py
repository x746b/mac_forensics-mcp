"""Timestamp normalization utilities for macOS forensics.

macOS uses several different epoch formats:
- Mac Absolute Time (Core Data): seconds since 2001-01-01 00:00:00 UTC
- Unix timestamp: seconds since 1970-01-01 00:00:00 UTC
- WebKit/Chrome: microseconds since 1601-01-01 00:00:00 UTC
- HFS+: seconds since 1904-01-01 00:00:00 local time
"""

from datetime import datetime, timezone
from typing import Optional, Union
import re

# Epoch offsets
MAC_ABSOLUTE_EPOCH = 978307200  # Seconds between Unix epoch and Mac epoch (2001-01-01)
WEBKIT_EPOCH = 11644473600000000  # Microseconds between 1601 and 1970
HFS_EPOCH = 2082844800  # Seconds between 1904 and 1970


def mac_absolute_to_utc(mac_time: Union[int, float]) -> datetime:
    """Convert Mac Absolute Time (Core Data epoch) to UTC datetime.

    Mac Absolute Time is seconds since 2001-01-01 00:00:00 UTC.
    Used in: KnowledgeC, CoreDuet, many Apple databases.
    """
    unix_timestamp = mac_time + MAC_ABSOLUTE_EPOCH
    return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)


def webkit_to_utc(webkit_time: int) -> datetime:
    """Convert WebKit/Chrome timestamp to UTC datetime.

    WebKit time is microseconds since 1601-01-01 00:00:00 UTC.
    Used in: Safari History, Chrome History.
    """
    unix_microseconds = webkit_time - WEBKIT_EPOCH
    unix_seconds = unix_microseconds / 1_000_000
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)


def hfs_to_utc(hfs_time: int, tz_offset_hours: int = 0) -> datetime:
    """Convert HFS+ timestamp to UTC datetime.

    HFS+ time is seconds since 1904-01-01 in local time.
    Used in: older macOS file metadata.
    """
    unix_timestamp = hfs_time - HFS_EPOCH - (tz_offset_hours * 3600)
    return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)


def normalize_timestamp(
    value: Union[str, int, float, datetime],
    source_type: str = "auto"
) -> Optional[datetime]:
    """Normalize various timestamp formats to UTC datetime.

    Args:
        value: Timestamp in various formats
        source_type: One of "auto", "mac_absolute", "webkit", "hfs", "unix", "iso"

    Returns:
        datetime in UTC, or None if parsing fails
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        # Try ISO format first
        try:
            # Handle various ISO formats
            value = value.rstrip('Z')
            if '.' in value:
                dt = datetime.fromisoformat(value)
            else:
                dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

        # Try to parse as number
        try:
            value = float(value)
        except ValueError:
            return None

    if isinstance(value, (int, float)):
        if source_type == "mac_absolute":
            return mac_absolute_to_utc(value)
        elif source_type == "webkit":
            return webkit_to_utc(int(value))
        elif source_type == "hfs":
            return hfs_to_utc(int(value))
        elif source_type == "unix":
            return datetime.fromtimestamp(value, tz=timezone.utc)
        elif source_type == "auto":
            # Heuristic detection
            if value > 1e16:  # WebKit (microseconds, very large)
                return webkit_to_utc(int(value))
            elif value > 1e12:  # Unix milliseconds
                return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
            elif value > 1e9:  # Unix seconds (after ~2001)
                return datetime.fromtimestamp(value, tz=timezone.utc)
            elif value > 0:  # Likely Mac Absolute Time
                return mac_absolute_to_utc(value)

    return None


def format_utc(dt: datetime) -> str:
    """Format datetime as ISO 8601 UTC string.

    Note: Naive datetimes (no tzinfo) are assumed to already be UTC,
    which is correct for Apple plist dates.
    """
    if dt is None:
        return None
    # If naive datetime, assume it's already UTC (Apple plist convention)
    if dt.tzinfo is None:
        utc_dt = dt.replace(tzinfo=timezone.utc)
    else:
        utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def format_local(dt: datetime, tz_offset_hours: int) -> str:
    """Format datetime with local timezone offset."""
    if dt is None:
        return None
    from datetime import timedelta
    local_tz = timezone(timedelta(hours=tz_offset_hours))
    local_dt = dt.astimezone(local_tz)
    sign = "+" if tz_offset_hours >= 0 else ""
    return local_dt.strftime(f"%Y-%m-%dT%H:%M:%S{sign}{tz_offset_hours:02d}:00")


def parse_iso_datetime(value: str) -> Optional[datetime]:
    """Parse ISO 8601 datetime string to UTC datetime.

    Args:
        value: ISO datetime string (e.g., "2025-03-08T07:58:58.378Z")

    Returns:
        datetime in UTC, or None if parsing fails
    """
    if not value:
        return None

    try:
        # Handle Z suffix
        value = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None
