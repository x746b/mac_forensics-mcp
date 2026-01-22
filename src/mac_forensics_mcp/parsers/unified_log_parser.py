"""Unified Log parser for macOS forensics.

Parses pre-extracted unified logs (CSV format from unifiedlog_iterator)
or can invoke unifiedlog_iterator directly on .logarchive bundles.
"""

import csv
import re
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Generator
from dataclasses import dataclass

from ..config import UNIFIEDLOG_ITERATOR_PATH


@dataclass
class LogEntry:
    """Represents a single unified log entry."""
    timestamp: datetime
    subsystem: str
    category: str
    process: str
    pid: int
    message: str
    event_type: str
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp.isoformat() + "Z" if self.timestamp else None,
            "subsystem": self.subsystem,
            "category": self.category,
            "process": self.process,
            "pid": self.pid,
            "message": self.message,
            "event_type": self.event_type,
        }


# Security event patterns for quick filtering
SECURITY_EVENT_PATTERNS = {
    "user_created": [
        r"MMCreateUserAccount.*called",
        r"dscl.*create.*Users",
        r"creating user",
        r"ODRecordCreate.*dsRecTypeStandard:Users",
    ],
    "user_deleted": [
        r"MMDeleteUserAccount.*called",
        r"dscl.*delete.*Users",
        r"deleting user",
        r"ODRecordDelete.*dsRecTypeStandard:Users",
    ],
    "user_modified": [
        r"MMModifyUserAccount",
        r"dscl.*change",
        r"ODRecordSetValue",
    ],
    "ssh_session": [
        r"sshd.*session opened",
        r"sshd.*Accepted",
        r"sshd.*Connection from",
        r"sshd.*session closed",
    ],
    "sudo_usage": [
        r"sudo:.*COMMAND",
        r"sudo:.*authentication",
        r"sudo:.*USER=root",
    ],
    "auth_success": [
        r"Succeeded authorizing right",
        r"authentication succeeded",
        r"TKSmartCardToken.*authenticated",
    ],
    "auth_failure": [
        r"Failed to authorize right",
        r"authentication failed",
        r"incorrect password",
    ],
    "process_exec": [
        r"AMFI: code signature",
        r"execve\(",
        r"posix_spawn",
    ],
    "gatekeeper": [
        r"GateKeeper",
        r"spctl",
        r"SecAssessment",
        r"com.apple.quarantine",
    ],
    "tcc_prompt": [
        r"TCCAccessRequest",
        r"kTCCService",
        r"TCC: Requesting",
    ],
    "login": [
        r"loginwindow.*Login",
        r"sessionDidLogin",
        r"User logged in",
    ],
    "logout": [
        r"loginwindow.*Logout",
        r"sessionWillLogout",
        r"User logged out",
    ],
    "screen_lock": [
        r"screenIsLocked.*true",
        r"CGSSessionScreenIsLocked",
    ],
    "screen_unlock": [
        r"screenIsLocked.*false",
        r"screen unlocked",
    ],
    "remote_login": [
        r"com.apple.remotelogin",
        r"systemsettings.*Remote Login",
        r"sshd-keygen-wrapper",
    ],
    "persistence": [
        r"SMJobBless",
        r"launchd.*load",
        r"LaunchServices.*register",
    ],
}


class UnifiedLogParser:
    """Parser for macOS Unified Logs."""

    def __init__(self, log_source: str):
        """Initialize parser with log source.

        Args:
            log_source: Path to .logarchive bundle OR pre-parsed CSV file
        """
        self.source = Path(log_source)
        self._csv_path: Optional[Path] = None
        self._cached_entries: Optional[List[LogEntry]] = None

    def _ensure_csv(self) -> Path:
        """Ensure we have a CSV file to parse."""
        if self._csv_path and self._csv_path.exists():
            return self._csv_path

        # Check if source is already a CSV
        if self.source.suffix.lower() == ".csv":
            self._csv_path = self.source
            return self._csv_path

        # Check if it's a logarchive that needs parsing
        if self.source.suffix == ".logarchive" or (self.source / "logdata.LiveData.tracev3").exists():
            return self._parse_logarchive()

        # Assume it's a CSV
        self._csv_path = self.source
        return self._csv_path

    def _parse_logarchive(self) -> Path:
        """Parse .logarchive using unifiedlog_iterator."""
        if not Path(UNIFIEDLOG_ITERATOR_PATH).exists():
            raise FileNotFoundError(
                f"unifiedlog_iterator not found at {UNIFIEDLOG_ITERATOR_PATH}. "
                "Please provide a pre-parsed CSV file instead."
            )

        # Create temp output file
        output_dir = tempfile.mkdtemp(prefix="mac_forensics_")
        output_csv = Path(output_dir) / "unified_logs.csv"

        cmd = [
            UNIFIEDLOG_ITERATOR_PATH,
            "-i", str(self.source),
            "-o", str(output_csv),
            "-f", "csv",
            "-m", "log-archive",
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to parse logarchive: {e.stderr.decode()}")

        self._csv_path = output_csv
        return self._csv_path

    def _parse_line(self, row: Dict[str, str]) -> Optional[LogEntry]:
        """Parse a single CSV row into a LogEntry."""
        try:
            # Common CSV column names from unifiedlog_iterator
            timestamp_str = row.get("Timestamp") or row.get("timestamp") or row.get("time")
            message = row.get("Message") or row.get("message") or row.get("eventMessage") or ""

            # Parse timestamp (usually ISO format with Z suffix)
            timestamp = None
            if timestamp_str:
                try:
                    # Handle various formats
                    ts = timestamp_str.rstrip("Z").replace("T", " ")
                    if "." in ts:
                        timestamp = datetime.strptime(ts.split(".")[0], "%Y-%m-%d %H:%M:%S")
                    else:
                        timestamp = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            return LogEntry(
                timestamp=timestamp,
                subsystem=row.get("Subsystem") or row.get("subsystem") or "",
                category=row.get("Category") or row.get("category") or "",
                process=row.get("Process") or row.get("process") or row.get("processImagePath") or "",
                pid=int(row.get("PID") or row.get("pid") or row.get("processID") or 0),
                message=message,
                event_type=row.get("Event Type") or row.get("eventType") or "",
                raw_line=str(row),
            )
        except Exception:
            return None

    def iter_entries(self) -> Generator[LogEntry, None, None]:
        """Iterate through all log entries."""
        csv_path = self._ensure_csv()

        # Read file and remove NUL bytes that break csv.reader
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            # Filter out NUL bytes
            clean_lines = (line.replace("\x00", "") for line in f)
            reader = csv.DictReader(clean_lines)
            for row in reader:
                entry = self._parse_line(row)
                if entry:
                    yield entry

    def search(
        self,
        query: str,
        subsystem: Optional[str] = None,
        category: Optional[str] = None,
        process: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Search unified logs with filters.

        Args:
            query: Text to search for (regex supported)
            subsystem: Filter by subsystem (e.g., "com.apple.opendirectoryd")
            category: Filter by category
            process: Filter by process name
            time_start: Filter entries after this time
            time_end: Filter entries before this time
            limit: Maximum results to return
            offset: Skip first N results

        Returns:
            Dict with "results", "total_matched", "has_more"
        """
        pattern = re.compile(query, re.IGNORECASE)
        results = []
        matched = 0
        skipped = 0

        for entry in self.iter_entries():
            # Apply filters
            if subsystem and subsystem.lower() not in entry.subsystem.lower():
                continue
            if category and category.lower() not in entry.category.lower():
                continue
            if process and process.lower() not in entry.process.lower():
                continue
            if time_start and entry.timestamp and entry.timestamp < time_start:
                continue
            if time_end and entry.timestamp and entry.timestamp > time_end:
                continue

            # Search in message
            if not pattern.search(entry.message):
                continue

            matched += 1

            # Handle pagination
            if skipped < offset:
                skipped += 1
                continue

            if len(results) < limit:
                results.append(entry.to_dict())

        return {
            "results": results,
            "total_matched": matched,
            "returned": len(results),
            "has_more": matched > offset + limit,
        }

    def get_security_events(
        self,
        event_type: str,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get pre-defined security event types.

        Args:
            event_type: One of the SECURITY_EVENT_PATTERNS keys
            time_start: Filter entries after this time
            time_end: Filter entries before this time
            limit: Maximum results
            offset: Pagination offset

        Returns:
            Dict with structured security events
        """
        if event_type not in SECURITY_EVENT_PATTERNS:
            return {
                "error": f"Unknown event type: {event_type}",
                "available_types": list(SECURITY_EVENT_PATTERNS.keys()),
            }

        patterns = SECURITY_EVENT_PATTERNS[event_type]
        combined_pattern = "|".join(f"({p})" for p in patterns)
        regex = re.compile(combined_pattern, re.IGNORECASE)

        results = []
        matched = 0
        skipped = 0

        for entry in self.iter_entries():
            # Time filters
            if time_start and entry.timestamp and entry.timestamp < time_start:
                continue
            if time_end and entry.timestamp and entry.timestamp > time_end:
                continue

            # Pattern match
            match = regex.search(entry.message)
            if not match:
                continue

            matched += 1

            if skipped < offset:
                skipped += 1
                continue

            if len(results) < limit:
                # Extract additional context based on event type
                event_data = entry.to_dict()
                event_data["event_type"] = event_type
                event_data["matched_pattern"] = match.group(0)

                # Parse specific fields for known event types
                if event_type == "user_deleted":
                    uid_match = re.search(r"UID\s*:\s*(\d+)", entry.message)
                    if uid_match:
                        event_data["uid"] = int(uid_match.group(1))

                elif event_type == "user_created":
                    uid_match = re.search(r"UID\s*:\s*(\d+)", entry.message)
                    if uid_match:
                        event_data["uid"] = int(uid_match.group(1))

                elif event_type == "ssh_session":
                    ip_match = re.search(r"from\s+([\d\.]+)", entry.message)
                    if ip_match:
                        event_data["source_ip"] = ip_match.group(1)
                    user_match = re.search(r"for\s+(\w+)", entry.message)
                    if user_match:
                        event_data["username"] = user_match.group(1)

                elif event_type == "sudo_usage":
                    user_match = re.search(r"(\w+)\s*:", entry.message)
                    cmd_match = re.search(r"COMMAND=(.+)$", entry.message)
                    if user_match:
                        event_data["username"] = user_match.group(1)
                    if cmd_match:
                        event_data["command"] = cmd_match.group(1)

                results.append(event_data)

        return {
            "event_type": event_type,
            "results": results,
            "total_matched": matched,
            "returned": len(results),
            "has_more": matched > offset + limit,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the log file."""
        stats = {
            "total_entries": 0,
            "time_range": {"start": None, "end": None},
            "subsystems": {},
            "processes": {},
        }

        min_time = None
        max_time = None

        for entry in self.iter_entries():
            stats["total_entries"] += 1

            if entry.timestamp:
                if min_time is None or entry.timestamp < min_time:
                    min_time = entry.timestamp
                if max_time is None or entry.timestamp > max_time:
                    max_time = entry.timestamp

            if entry.subsystem:
                stats["subsystems"][entry.subsystem] = stats["subsystems"].get(entry.subsystem, 0) + 1

            if entry.process:
                stats["processes"][entry.process] = stats["processes"].get(entry.process, 0) + 1

        if min_time:
            stats["time_range"]["start"] = min_time.isoformat() + "Z"
        if max_time:
            stats["time_range"]["end"] = max_time.isoformat() + "Z"

        # Sort and limit top entries
        stats["top_subsystems"] = sorted(
            stats["subsystems"].items(), key=lambda x: x[1], reverse=True
        )[:20]
        stats["top_processes"] = sorted(
            stats["processes"].items(), key=lambda x: x[1], reverse=True
        )[:20]

        del stats["subsystems"]
        del stats["processes"]

        return stats
