"""Timeline builder for macOS forensics.

Correlates events across multiple artifacts to build unified timelines.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import re

from ..utils.discovery import discover_artifacts
from ..utils.timestamps import format_utc, parse_iso_datetime
from ..parsers.unified_log_parser import UnifiedLogParser
from ..parsers.plist_parser import PlistParser
from ..parsers.sqlite_parser import SQLiteParser


class TimelineBuilder:
    """Builds correlated timelines from multiple forensic artifacts."""

    def __init__(self, artifacts_dir: str):
        """Initialize with artifacts directory.

        Args:
            artifacts_dir: Path to triage collection root
        """
        self.artifacts_dir = Path(artifacts_dir)
        self._artifacts: Optional[Dict] = None

    def _get_artifacts(self) -> Dict:
        """Get discovered artifacts, caching result."""
        if self._artifacts is None:
            self._artifacts = discover_artifacts(str(self.artifacts_dir))
        return self._artifacts

    def build_timeline(
        self,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        sources: Optional[List[str]] = None,
        keyword: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Build a unified timeline from multiple sources.

        Args:
            time_start: Start of time window
            time_end: End of time window
            sources: List of sources to include (unified_logs, safari, knowledgec, plists)
            keyword: Optional keyword to filter across all sources
            limit: Maximum events to return

        Returns:
            Unified timeline with events sorted chronologically
        """
        artifacts = self._get_artifacts()
        all_events = []

        if sources is None:
            sources = ["unified_logs", "safari", "knowledgec", "plists"]

        # Collect events from each source
        if "unified_logs" in sources and artifacts.get("unified_logs"):
            events = self._get_unified_log_events(
                artifacts["unified_logs"],
                time_start, time_end, keyword
            )
            all_events.extend(events)

        if "safari" in sources and artifacts.get("databases", {}).get("safari_history"):
            events = self._get_safari_events(
                artifacts["databases"]["safari_history"],
                time_start, time_end, keyword
            )
            all_events.extend(events)

        if "knowledgec" in sources and artifacts.get("databases", {}).get("knowledgec"):
            events = self._get_knowledgec_events(
                artifacts["databases"]["knowledgec"],
                time_start, time_end, keyword
            )
            all_events.extend(events)

        if "plists" in sources:
            # Check for account-related plists
            plist_events = self._get_plist_events(
                artifacts.get("plists", []),
                time_start, time_end, keyword
            )
            all_events.extend(plist_events)

        # Sort by timestamp
        all_events.sort(key=lambda x: x.get("timestamp_utc", ""))

        # Apply time filters if not already applied at source level
        if time_start:
            all_events = [e for e in all_events if e.get("timestamp_utc", "") >= format_utc(time_start)]
        if time_end:
            all_events = [e for e in all_events if e.get("timestamp_utc", "") <= format_utc(time_end)]

        # Limit results
        total = len(all_events)
        all_events = all_events[:limit]

        return {
            "events": all_events,
            "total_events": total,
            "returned": len(all_events),
            "sources_used": sources,
            "time_range": {
                "start": all_events[0]["timestamp_utc"] if all_events else None,
                "end": all_events[-1]["timestamp_utc"] if all_events else None,
            },
        }

    def _get_unified_log_events(
        self,
        log_path: str,
        time_start: Optional[datetime],
        time_end: Optional[datetime],
        keyword: Optional[str],
    ) -> List[Dict]:
        """Extract events from unified logs."""
        events = []
        try:
            parser = UnifiedLogParser(log_path)

            # Search with keyword if provided
            query = keyword if keyword else ".*"
            results = parser.search(
                query=query,
                time_start=time_start,
                time_end=time_end,
                limit=200,
            )

            for entry in results.get("results", []):
                events.append({
                    "timestamp_utc": entry.get("timestamp_utc"),
                    "source": "unified_logs",
                    "subsystem": entry.get("subsystem"),
                    "process": entry.get("process"),
                    "event": entry.get("message", "")[:500],  # Truncate long messages
                    "category": entry.get("category"),
                })

        except Exception as e:
            pass  # Graceful degradation

        return events

    def _get_safari_events(
        self,
        db_path: str,
        time_start: Optional[datetime],
        time_end: Optional[datetime],
        keyword: Optional[str],
    ) -> List[Dict]:
        """Extract events from Safari history."""
        events = []
        try:
            parser = SQLiteParser(db_path)
            results = parser.get_safari_history(
                url_filter=keyword,
                time_start=time_start,
                time_end=time_end,
                limit=100,
            )

            for entry in results.get("results", []):
                events.append({
                    "timestamp_utc": entry.get("visit_time_utc"),
                    "source": "safari_history",
                    "event": f"Visited: {entry.get('title', '')} ({entry.get('url', '')})",
                    "url": entry.get("url"),
                    "title": entry.get("title"),
                })

        except Exception:
            pass

        return events

    def _get_knowledgec_events(
        self,
        db_path: str,
        time_start: Optional[datetime],
        time_end: Optional[datetime],
        keyword: Optional[str],
    ) -> List[Dict]:
        """Extract events from KnowledgeC."""
        events = []
        try:
            parser = SQLiteParser(db_path)
            results = parser.get_knowledgec_app_usage(
                app_name=keyword,
                time_start=time_start,
                time_end=time_end,
                limit=100,
            )

            for entry in results.get("results", []):
                events.append({
                    "timestamp_utc": entry.get("start_time_utc"),
                    "source": "knowledgec",
                    "event": f"App used: {entry.get('bundle_id', '')}",
                    "bundle_id": entry.get("bundle_id"),
                    "duration_seconds": entry.get("duration_seconds"),
                })

        except Exception:
            pass

        return events

    def _get_plist_events(
        self,
        plist_paths: List[str],
        time_start: Optional[datetime],
        time_end: Optional[datetime],
        keyword: Optional[str],
    ) -> List[Dict]:
        """Extract timestamped events from plists."""
        events = []

        # Focus on forensically interesting plists
        interesting_patterns = [
            "com.apple.preferences.accounts",
            "loginwindow",
            "LaunchServices",
        ]

        for plist_path in plist_paths:
            try:
                # Check if this is an interesting plist
                if not any(p in plist_path for p in interesting_patterns):
                    continue

                parser = PlistParser(plist_path)
                timestamps = parser.extract_timestamps()

                for ts_info in timestamps.get("timestamps", []):
                    # Filter by keyword if provided
                    if keyword and keyword.lower() not in str(ts_info).lower():
                        continue

                    ts_utc = ts_info.get("value_utc")
                    if not ts_utc:
                        continue

                    # Filter by time range
                    if time_start:
                        ts_dt = parse_iso_datetime(ts_utc)
                        if ts_dt and ts_dt < time_start:
                            continue
                    if time_end:
                        ts_dt = parse_iso_datetime(ts_utc)
                        if ts_dt and ts_dt > time_end:
                            continue

                    events.append({
                        "timestamp_utc": ts_utc,
                        "source": "plist",
                        "plist_file": Path(plist_path).name,
                        "event": f"{ts_info.get('key_path', '')}: {ts_info.get('value_utc', '')}",
                        "key_path": ts_info.get("key_path"),
                    })

            except Exception:
                pass

        return events

    def get_user_timeline(
        self,
        username: str,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Build a timeline for a specific user account.

        Args:
            username: Username to investigate
            time_start: Start of time window
            time_end: End of time window
            limit: Maximum events

        Returns:
            User-specific timeline with account events
        """
        artifacts = self._get_artifacts()
        events = []

        # Search unified logs for user-related events
        if artifacts.get("unified_logs"):
            try:
                parser = UnifiedLogParser(artifacts["unified_logs"])

                # Search for user creation/modification/deletion
                user_queries = [
                    f"dscl.*{username}",
                    f"MMDeleteUserAccount.*{username}",
                    f"CreateUserAccount.*{username}",
                    f"uid.*{username}",
                    f"user.*{username}",
                ]

                for query in user_queries:
                    results = parser.search(
                        query=query,
                        time_start=time_start,
                        time_end=time_end,
                        limit=50,
                    )
                    for entry in results.get("results", []):
                        events.append({
                            "timestamp_utc": entry.get("timestamp_utc"),
                            "source": "unified_logs",
                            "event": entry.get("message", "")[:500],
                            "subsystem": entry.get("subsystem"),
                            "process": entry.get("process"),
                        })

            except Exception:
                pass

        # Check deleted users plist
        for plist_path in artifacts.get("plists", []):
            if "com.apple.preferences.accounts" in plist_path:
                try:
                    parser = PlistParser(plist_path)
                    data = parser.read()

                    # Check deletedUsers
                    if "deletedUsers" in data:
                        for deleted_user in data["deletedUsers"]:
                            if deleted_user.get("name") == username:
                                events.append({
                                    "timestamp_utc": format_utc(deleted_user.get("date")) if deleted_user.get("date") else None,
                                    "source": "com.apple.preferences.accounts.plist",
                                    "event": f"User '{username}' deleted",
                                    "details": {
                                        "dsAttrTypeStandard:UniqueID": deleted_user.get("dsAttrTypeStandard:UniqueID"),
                                        "home_dir": deleted_user.get("home"),
                                    },
                                })

                except Exception:
                    pass

        # Sort and deduplicate
        events.sort(key=lambda x: x.get("timestamp_utc", ""))

        # Remove duplicates (same timestamp and event)
        seen = set()
        unique_events = []
        for event in events:
            key = (event.get("timestamp_utc"), event.get("event", "")[:100])
            if key not in seen:
                seen.add(key)
                unique_events.append(event)

        return {
            "username": username,
            "events": unique_events[:limit],
            "total_events": len(unique_events),
            "summary": self._summarize_user_events(unique_events),
        }

    def _summarize_user_events(self, events: List[Dict]) -> Dict[str, Any]:
        """Generate summary of user events."""
        summary = {
            "first_seen": None,
            "last_seen": None,
            "event_count": len(events),
            "key_events": [],
        }

        if not events:
            return summary

        summary["first_seen"] = events[0].get("timestamp_utc")
        summary["last_seen"] = events[-1].get("timestamp_utc")

        # Identify key events
        key_patterns = [
            (r"DeleteUser|delete.*user", "Account deleted"),
            (r"CreateUser|create.*user|dscl.*create", "Account created"),
            (r"ModifyUser|modify.*user|dscl.*append", "Account modified"),
            (r"password|passwd", "Password-related event"),
            (r"sudo|admin", "Privilege event"),
        ]

        for event in events:
            msg = event.get("event", "")
            for pattern, label in key_patterns:
                if re.search(pattern, msg, re.IGNORECASE):
                    summary["key_events"].append({
                        "timestamp_utc": event.get("timestamp_utc"),
                        "type": label,
                        "snippet": msg[:200],
                    })
                    break

        return summary
