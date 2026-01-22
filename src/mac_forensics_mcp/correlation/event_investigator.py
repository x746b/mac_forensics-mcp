"""Event investigator for macOS forensics.

Provides deep investigation capabilities for specific event types,
correlating evidence across multiple artifacts.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import re

from ..utils.discovery import discover_artifacts
from ..utils.timestamps import format_utc, parse_iso_datetime
from ..parsers.unified_log_parser import UnifiedLogParser, SECURITY_EVENT_PATTERNS
from ..parsers.plist_parser import PlistParser
from ..parsers.sqlite_parser import SQLiteParser


class EventInvestigator:
    """Investigates specific events by correlating multiple artifacts."""

    # Event types we can investigate
    EVENT_TYPES = [
        "user_deletion",
        "user_creation",
        "malware_execution",
        "file_download",
        "ssh_session",
        "privilege_escalation",
    ]

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

    def investigate(
        self,
        event_type: str,
        target: str,
        time_window_hours: int = 24,
    ) -> Dict[str, Any]:
        """Investigate a specific event type.

        Args:
            event_type: Type of event to investigate (user_deletion, file_download, etc.)
            target: Target of investigation (username, filename, IP, etc.)
            time_window_hours: Hours around event to search for context

        Returns:
            Investigation results with correlated evidence
        """
        if event_type not in self.EVENT_TYPES:
            return {
                "error": f"Unknown event type: {event_type}",
                "available_types": self.EVENT_TYPES,
            }

        if event_type == "user_deletion":
            return self._investigate_user_deletion(target, time_window_hours)
        elif event_type == "user_creation":
            return self._investigate_user_creation(target, time_window_hours)
        elif event_type == "file_download":
            return self._investigate_file_download(target, time_window_hours)
        elif event_type == "ssh_session":
            return self._investigate_ssh_session(target, time_window_hours)
        elif event_type == "malware_execution":
            return self._investigate_malware_execution(target, time_window_hours)
        elif event_type == "privilege_escalation":
            return self._investigate_privilege_escalation(target, time_window_hours)

        return {"error": "Investigation not implemented"}

    def _investigate_user_deletion(
        self,
        username: str,
        time_window_hours: int,
    ) -> Dict[str, Any]:
        """Investigate user account deletion.

        Correlates:
        - Unified logs for deletion events
        - com.apple.preferences.accounts.plist for deletion record
        - Safari history for research queries
        - FSEvents for home directory removal
        """
        artifacts = self._get_artifacts()
        evidence = []
        primary_timestamp = None
        confidence = "low"

        # 1. Check unified logs for deletion events
        if artifacts.get("unified_logs"):
            try:
                parser = UnifiedLogParser(artifacts["unified_logs"])

                # Search for specific deletion patterns
                deletion_patterns = [
                    f"MMDeleteUserAccount.*{username}",
                    f"MMDeleteUserAccount.*UID",
                    f"deleteUser.*{username}",
                    f"dscl.*delete.*{username}",
                ]

                for pattern in deletion_patterns:
                    results = parser.search(query=pattern, limit=20)
                    for entry in results.get("results", []):
                        evidence.append({
                            "source": "unified_logs",
                            "timestamp_utc": entry.get("timestamp_utc"),
                            "event": entry.get("message", "")[:500],
                            "subsystem": entry.get("subsystem"),
                            "relevance": "high",
                        })
                        if not primary_timestamp:
                            primary_timestamp = entry.get("timestamp_utc")

            except Exception as e:
                pass

        # 2. Check com.apple.preferences.accounts.plist
        for plist_path in artifacts.get("plists", []):
            if "com.apple.preferences.accounts" in plist_path:
                try:
                    parser = PlistParser(plist_path)
                    data = parser.read()

                    if "deletedUsers" in data:
                        for deleted_user in data["deletedUsers"]:
                            if deleted_user.get("name") == username:
                                ts = deleted_user.get("date")
                                ts_utc = format_utc(ts) if ts else None

                                evidence.append({
                                    "source": "com.apple.preferences.accounts.plist",
                                    "timestamp_utc": ts_utc,
                                    "event": f"Deleted user record found",
                                    "details": {
                                        "name": deleted_user.get("name"),
                                        "uid": deleted_user.get("dsAttrTypeStandard:UniqueID"),
                                        "home": deleted_user.get("home"),
                                        "realname": deleted_user.get("dsAttrTypeStandard:RealName"),
                                    },
                                    "relevance": "high",
                                })

                                if not primary_timestamp and ts_utc:
                                    primary_timestamp = ts_utc
                                confidence = "high"

                except Exception:
                    pass

        # 3. Search Safari history for research queries
        if primary_timestamp and artifacts.get("databases", {}).get("safari_history"):
            try:
                # Parse primary timestamp
                event_time = parse_iso_datetime(primary_timestamp)
                if event_time:
                    # Search before the event
                    time_start = event_time - timedelta(hours=time_window_hours)

                    parser = SQLiteParser(artifacts["databases"]["safari_history"])

                    # Search for deletion-related queries
                    search_terms = ["delete", "remove", "user", "account", username]
                    for term in search_terms:
                        results = parser.get_safari_searches(
                            query_filter=term,
                            time_start=time_start,
                            time_end=event_time,
                            limit=10,
                        )
                        for entry in results.get("results", []):
                            evidence.append({
                                "source": "safari_history",
                                "timestamp_utc": entry.get("visit_time_utc"),
                                "event": f"Search query: {entry.get('search_query', '')}",
                                "url": entry.get("url"),
                                "relevance": "medium",
                            })

            except Exception:
                pass

        # Sort evidence by timestamp
        evidence.sort(key=lambda x: x.get("timestamp_utc", ""))

        # Build timeline
        timeline = []
        for e in evidence:
            if e.get("timestamp_utc"):
                timeline.append({
                    "time": e["timestamp_utc"],
                    "event": e["event"][:100],
                    "source": e["source"],
                })

        # Generate summary
        summary = f"User '{username}' "
        if primary_timestamp:
            summary += f"was deleted at {primary_timestamp}"
        else:
            summary += "deletion investigation (no definitive timestamp found)"

        return {
            "event_type": "user_deletion",
            "target": username,
            "summary": summary,
            "confidence": confidence,
            "primary_timestamp_utc": primary_timestamp,
            "evidence": evidence,
            "timeline": timeline,
            "sources_checked": [
                "unified_logs",
                "com.apple.preferences.accounts.plist",
                "safari_history",
            ],
        }

    def _investigate_user_creation(
        self,
        username: str,
        time_window_hours: int,
    ) -> Dict[str, Any]:
        """Investigate user account creation."""
        artifacts = self._get_artifacts()
        evidence = []
        primary_timestamp = None
        confidence = "low"

        # Check unified logs for creation events
        if artifacts.get("unified_logs"):
            try:
                parser = UnifiedLogParser(artifacts["unified_logs"])

                creation_patterns = [
                    f"CreateUserAccount.*{username}",
                    f"dscl.*create.*{username}",
                    f"createdUser.*{username}",
                    f"dslocal.*{username}",
                ]

                for pattern in creation_patterns:
                    results = parser.search(query=pattern, limit=20)
                    for entry in results.get("results", []):
                        evidence.append({
                            "source": "unified_logs",
                            "timestamp_utc": entry.get("timestamp_utc"),
                            "event": entry.get("message", "")[:500],
                            "subsystem": entry.get("subsystem"),
                            "relevance": "high",
                        })
                        if not primary_timestamp:
                            primary_timestamp = entry.get("timestamp_utc")
                            confidence = "high"

            except Exception:
                pass

        # Sort and build response
        evidence.sort(key=lambda x: x.get("timestamp_utc", ""))

        return {
            "event_type": "user_creation",
            "target": username,
            "summary": f"User '{username}' creation investigation",
            "confidence": confidence,
            "primary_timestamp_utc": primary_timestamp,
            "evidence": evidence,
            "timeline": [
                {"time": e["timestamp_utc"], "event": e["event"][:100], "source": e["source"]}
                for e in evidence if e.get("timestamp_utc")
            ],
        }

    def _investigate_file_download(
        self,
        filename: str,
        time_window_hours: int,
    ) -> Dict[str, Any]:
        """Investigate file download."""
        artifacts = self._get_artifacts()
        evidence = []
        primary_timestamp = None
        confidence = "low"

        # Check quarantine events
        quarantine_path = artifacts.get("databases", {}).get("quarantine")
        if quarantine_path:
            try:
                parser = SQLiteParser(quarantine_path)
                results = parser.get_quarantine_events(
                    filename_filter=filename,
                    limit=20,
                )

                for entry in results.get("results", []):
                    evidence.append({
                        "source": "quarantine_db",
                        "timestamp_utc": entry.get("timestamp_utc"),
                        "event": f"Downloaded: {entry.get('data_url', '')}",
                        "details": {
                            "origin_url": entry.get("origin_url"),
                            "agent_name": entry.get("agent_name"),
                        },
                        "relevance": "high",
                    })
                    if not primary_timestamp:
                        primary_timestamp = entry.get("timestamp_utc")
                        confidence = "high"

            except Exception:
                pass

        # Check Safari history for download
        safari_path = artifacts.get("databases", {}).get("safari_history")
        if safari_path:
            try:
                parser = SQLiteParser(safari_path)
                results = parser.get_safari_history(
                    url_filter=filename,
                    limit=20,
                )

                for entry in results.get("results", []):
                    evidence.append({
                        "source": "safari_history",
                        "timestamp_utc": entry.get("visit_time_utc"),
                        "event": f"Visited: {entry.get('url', '')}",
                        "relevance": "medium",
                    })

            except Exception:
                pass

        evidence.sort(key=lambda x: x.get("timestamp_utc", ""))

        return {
            "event_type": "file_download",
            "target": filename,
            "summary": f"Download investigation for '{filename}'",
            "confidence": confidence,
            "primary_timestamp_utc": primary_timestamp,
            "evidence": evidence,
            "timeline": [
                {"time": e["timestamp_utc"], "event": e["event"][:100], "source": e["source"]}
                for e in evidence if e.get("timestamp_utc")
            ],
        }

    def _investigate_ssh_session(
        self,
        target: str,
        time_window_hours: int,
    ) -> Dict[str, Any]:
        """Investigate SSH session (target can be IP or username)."""
        artifacts = self._get_artifacts()
        evidence = []
        confidence = "low"

        if artifacts.get("unified_logs"):
            try:
                parser = UnifiedLogParser(artifacts["unified_logs"])

                # Get SSH events
                results = parser.get_security_events("ssh_session", limit=50)

                for entry in results.get("results", []):
                    msg = entry.get("message", "")
                    if target.lower() in msg.lower():
                        evidence.append({
                            "source": "unified_logs",
                            "timestamp_utc": entry.get("timestamp_utc"),
                            "event": msg[:500],
                            "relevance": "high",
                        })
                        confidence = "high"

            except Exception:
                pass

        evidence.sort(key=lambda x: x.get("timestamp_utc", ""))

        return {
            "event_type": "ssh_session",
            "target": target,
            "summary": f"SSH session investigation for '{target}'",
            "confidence": confidence,
            "evidence": evidence,
            "timeline": [
                {"time": e["timestamp_utc"], "event": e["event"][:100], "source": e["source"]}
                for e in evidence if e.get("timestamp_utc")
            ],
        }

    def _investigate_malware_execution(
        self,
        filename: str,
        time_window_hours: int,
    ) -> Dict[str, Any]:
        """Investigate potential malware execution."""
        artifacts = self._get_artifacts()
        evidence = []
        confidence = "low"

        # Check Gatekeeper events in unified logs
        if artifacts.get("unified_logs"):
            try:
                parser = UnifiedLogParser(artifacts["unified_logs"])

                # Check gatekeeper
                results = parser.get_security_events("gatekeeper", limit=50)
                for entry in results.get("results", []):
                    msg = entry.get("message", "")
                    if filename.lower() in msg.lower():
                        evidence.append({
                            "source": "unified_logs (gatekeeper)",
                            "timestamp_utc": entry.get("timestamp_utc"),
                            "event": msg[:500],
                            "relevance": "high",
                        })
                        confidence = "medium"

                # Check process execution
                results = parser.get_security_events("process_exec", limit=50)
                for entry in results.get("results", []):
                    msg = entry.get("message", "")
                    if filename.lower() in msg.lower():
                        evidence.append({
                            "source": "unified_logs (exec)",
                            "timestamp_utc": entry.get("timestamp_utc"),
                            "event": msg[:500],
                            "relevance": "high",
                        })
                        confidence = "high"

            except Exception:
                pass

        # Check quarantine
        quarantine_path = artifacts.get("databases", {}).get("quarantine")
        if quarantine_path:
            try:
                parser = SQLiteParser(quarantine_path)
                results = parser.get_quarantine_events(
                    filename_filter=filename,
                    limit=10,
                )

                for entry in results.get("results", []):
                    evidence.append({
                        "source": "quarantine_db",
                        "timestamp_utc": entry.get("timestamp_utc"),
                        "event": f"Quarantined download from: {entry.get('origin_url', '')}",
                        "relevance": "medium",
                    })

            except Exception:
                pass

        evidence.sort(key=lambda x: x.get("timestamp_utc", ""))

        return {
            "event_type": "malware_execution",
            "target": filename,
            "summary": f"Malware execution investigation for '{filename}'",
            "confidence": confidence,
            "evidence": evidence,
            "timeline": [
                {"time": e["timestamp_utc"], "event": e["event"][:100], "source": e["source"]}
                for e in evidence if e.get("timestamp_utc")
            ],
        }

    def _investigate_privilege_escalation(
        self,
        target: str,
        time_window_hours: int,
    ) -> Dict[str, Any]:
        """Investigate privilege escalation attempts."""
        artifacts = self._get_artifacts()
        evidence = []
        confidence = "low"

        if artifacts.get("unified_logs"):
            try:
                parser = UnifiedLogParser(artifacts["unified_logs"])

                # Check sudo usage
                results = parser.get_security_events("sudo_usage", limit=50)
                for entry in results.get("results", []):
                    msg = entry.get("message", "")
                    if not target or target.lower() in msg.lower():
                        evidence.append({
                            "source": "unified_logs (sudo)",
                            "timestamp_utc": entry.get("timestamp_utc"),
                            "event": msg[:500],
                            "relevance": "high",
                        })
                        confidence = "medium"

                # Check privilege use
                results = parser.get_security_events("privilege_use", limit=50)
                for entry in results.get("results", []):
                    msg = entry.get("message", "")
                    if not target or target.lower() in msg.lower():
                        evidence.append({
                            "source": "unified_logs (privilege)",
                            "timestamp_utc": entry.get("timestamp_utc"),
                            "event": msg[:500],
                            "relevance": "high",
                        })
                        confidence = "high"

            except Exception:
                pass

        evidence.sort(key=lambda x: x.get("timestamp_utc", ""))

        return {
            "event_type": "privilege_escalation",
            "target": target or "all",
            "summary": f"Privilege escalation investigation",
            "confidence": confidence,
            "evidence": evidence,
            "timeline": [
                {"time": e["timestamp_utc"], "event": e["event"][:100], "source": e["source"]}
                for e in evidence if e.get("timestamp_utc")
            ],
        }
