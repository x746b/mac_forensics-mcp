"""macOS Forensics MCP Server.

Provides tools for macOS Digital Forensics and Incident Response (DFIR).
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .utils.discovery import discover_artifacts, find_artifact
from .utils.timestamps import normalize_timestamp, format_utc
from .parsers.plist_parser import PlistParser
from .parsers.unified_log_parser import UnifiedLogParser, SECURITY_EVENT_PATTERNS
from .parsers.sqlite_parser import (
    KnowledgeCParser,
    SafariHistoryParser,
    TCCParser,
    QuarantineParser,
)
from .parsers.xattr_parser import XattrParser
from .parsers.spotlight_parser import SpotlightParser
from .parsers.fsevents_parser import FSEventsParser
from .parsers.fsck_apfs_parser import FsckApfsParser
from .correlation.timeline_builder import TimelineBuilder
from .correlation.event_investigator import EventInvestigator


# Initialize MCP server
server = Server("mac-forensics-mcp")


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO datetime string to datetime object."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def json_response(data: Any) -> list[TextContent]:
    """Format response as JSON text content."""
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str, ensure_ascii=False))]


# =============================================================================
# Tool Definitions
# =============================================================================

@server.list_tools()
async def list_tools() -> list[Tool]:
    """List all available forensic tools."""
    return [
        # Discovery
        Tool(
            name="mac_list_artifacts",
            description="Discover available forensic artifacts in a macOS triage collection. "
                        "Returns inventory of logs, databases, plists, and user profiles.",
            inputSchema={
                "type": "object",
                "properties": {
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Path to the triage collection root directory",
                    },
                },
                "required": ["artifacts_dir"],
            },
        ),

        # Unified Logs
        Tool(
            name="mac_unified_logs_search",
            description="Search macOS Unified Logs with filters. Supports regex patterns, "
                        "subsystem/category/process filters, and time ranges.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {
                        "type": "string",
                        "description": "Path to unified_logs.csv or .logarchive bundle",
                    },
                    "query": {
                        "type": "string",
                        "description": "Search pattern (regex supported)",
                    },
                    "subsystem": {
                        "type": "string",
                        "description": "Filter by subsystem (e.g., 'com.apple.opendirectoryd')",
                    },
                    "process": {
                        "type": "string",
                        "description": "Filter by process name",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter events after this time",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter events before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "description": "Maximum results to return",
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "description": "Skip first N results for pagination",
                    },
                },
                "required": ["log_path", "query"],
            },
        ),
        Tool(
            name="mac_unified_logs_security_events",
            description="Get pre-defined security events from Unified Logs. "
                        f"Event types: {', '.join(SECURITY_EVENT_PATTERNS.keys())}",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {
                        "type": "string",
                        "description": "Path to unified_logs.csv or .logarchive bundle",
                    },
                    "event_type": {
                        "type": "string",
                        "enum": list(SECURITY_EVENT_PATTERNS.keys()),
                        "description": "Type of security event to search for",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter events after this time",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter events before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                    },
                },
                "required": ["log_path", "event_type"],
            },
        ),
        Tool(
            name="mac_unified_logs_stats",
            description="Get statistics about a Unified Log file: time range, top subsystems, "
                        "top processes, total entry count.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {
                        "type": "string",
                        "description": "Path to unified_logs.csv or .logarchive bundle",
                    },
                },
                "required": ["log_path"],
            },
        ),

        # Plist
        Tool(
            name="mac_plist_read",
            description="Read and parse a macOS plist file. Optionally extract specific key path.",
            inputSchema={
                "type": "object",
                "properties": {
                    "plist_path": {
                        "type": "string",
                        "description": "Path to the plist file",
                    },
                    "key_path": {
                        "type": "string",
                        "description": "Optional dot-notation path (e.g., 'deletedUsers.0.date')",
                    },
                },
                "required": ["plist_path"],
            },
        ),
        Tool(
            name="mac_plist_search",
            description="Search for keys matching a pattern across a plist file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "plist_path": {
                        "type": "string",
                        "description": "Path to the plist file",
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Search pattern for key names (case-insensitive)",
                    },
                },
                "required": ["plist_path", "pattern"],
            },
        ),
        Tool(
            name="mac_plist_timestamps",
            description="Extract all timestamp values from a plist file with UTC conversion.",
            inputSchema={
                "type": "object",
                "properties": {
                    "plist_path": {
                        "type": "string",
                        "description": "Path to the plist file",
                    },
                },
                "required": ["plist_path"],
            },
        ),

        # KnowledgeC
        Tool(
            name="mac_knowledgec_app_usage",
            description="Get application usage data from KnowledgeC.db. "
                        "Shows what apps were used and when.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to knowledgeC.db",
                    },
                    "app_name": {
                        "type": "string",
                        "description": "Filter by app name/bundle ID (substring match)",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter after this time",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                    },
                },
                "required": ["db_path"],
            },
        ),

        # Safari History
        Tool(
            name="mac_safari_history",
            description="Get Safari browsing history with timestamps.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to Safari History.db",
                    },
                    "url_filter": {
                        "type": "string",
                        "description": "Filter by URL (substring)",
                    },
                    "title_filter": {
                        "type": "string",
                        "description": "Filter by page title (substring)",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter after this time",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                    },
                },
                "required": ["db_path"],
            },
        ),
        Tool(
            name="mac_safari_searches",
            description="Extract search queries from Safari history (Google, Bing, etc.).",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to Safari History.db",
                    },
                    "query_filter": {
                        "type": "string",
                        "description": "Filter search queries (substring)",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter after this time",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                    },
                },
                "required": ["db_path"],
            },
        ),

        # TCC
        Tool(
            name="mac_tcc_permissions",
            description="Get TCC (Transparency, Consent, Control) permissions. "
                        "Shows which apps have camera, mic, screen recording access.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to TCC.db",
                    },
                    "service": {
                        "type": "string",
                        "description": "Filter by service (e.g., 'ScreenCapture', 'Microphone')",
                    },
                    "client": {
                        "type": "string",
                        "description": "Filter by app bundle ID",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                    },
                },
                "required": ["db_path"],
            },
        ),

        # Quarantine
        Tool(
            name="mac_quarantine_events",
            description="Get quarantine events (file downloads) from QuarantineEventsV2. "
                        "Shows download source, app that downloaded, timestamp.",
            inputSchema={
                "type": "object",
                "properties": {
                    "db_path": {
                        "type": "string",
                        "description": "Path to QuarantineEventsV2 database",
                    },
                    "filename_filter": {
                        "type": "string",
                        "description": "Filter by filename",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter after this time",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                    },
                },
                "required": ["db_path"],
            },
        ),

        # User Account Analysis
        Tool(
            name="mac_get_user_accounts",
            description="Get user accounts from a triage collection, including deleted users.",
            inputSchema={
                "type": "object",
                "properties": {
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Path to triage collection root",
                    },
                    "include_deleted": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include deleted user accounts",
                    },
                },
                "required": ["artifacts_dir"],
            },
        ),

        # Extended Attributes (NEW)
        Tool(
            name="mac_get_extended_attributes",
            description="Get extended attributes (xattr) for a file. Contains true download times, "
                        "quarantine info, and user-action dates more accurate than DB records.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to file or directory to scan",
                    },
                    "recursive": {
                        "type": "boolean",
                        "default": False,
                        "description": "Scan directory recursively",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                        "description": "Max files to return (for directory scans)",
                    },
                },
                "required": ["file_path"],
            },
        ),

        # Spotlight Search (NEW)
        Tool(
            name="mac_spotlight_search",
            description="Search Spotlight index for file metadata. Contains info even for deleted files.",
            inputSchema={
                "type": "object",
                "properties": {
                    "spotlight_path": {
                        "type": "string",
                        "description": "Path to .store.db or .Spotlight-V100 directory",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Filter by filename (substring)",
                    },
                    "content_type": {
                        "type": "string",
                        "description": "Filter by content type (e.g., 'public.executable')",
                    },
                    "inode": {
                        "type": "integer",
                        "description": "Find file by inode number",
                    },
                    "path_contains": {
                        "type": "string",
                        "description": "Filter by path substring",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter after this time",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                    },
                },
                "required": ["spotlight_path"],
            },
        ),
        Tool(
            name="mac_spotlight_stats",
            description="Get statistics about a Spotlight index: total entries, content types, top directories.",
            inputSchema={
                "type": "object",
                "properties": {
                    "spotlight_path": {
                        "type": "string",
                        "description": "Path to .store.db or .Spotlight-V100 directory",
                    },
                },
                "required": ["spotlight_path"],
            },
        ),

        # FSEvents (NEW)
        Tool(
            name="mac_fsevents_search",
            description="Search FSEvents records for file system activity. Shows file creation, deletion, "
                        "modification, and rename operations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "fseventsd_path": {
                        "type": "string",
                        "description": "Path to .fseventsd directory or pre-parsed SQLite database",
                    },
                    "path_filter": {
                        "type": "string",
                        "description": "Filter by full path (substring match)",
                    },
                    "filename_filter": {
                        "type": "string",
                        "description": "Filter by filename (substring match)",
                    },
                    "event_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by event types: created, deleted, modified, renamed, mount, permission",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter events after this time (approximate)",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter events before this time (approximate)",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                    },
                },
                "required": ["fseventsd_path"],
            },
        ),
        Tool(
            name="mac_fsevents_stats",
            description="Get statistics about FSEvents records: total count, time range, event type counts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "fseventsd_path": {
                        "type": "string",
                        "description": "Path to .fseventsd directory or pre-parsed SQLite database",
                    },
                },
                "required": ["fseventsd_path"],
            },
        ),

        # Timeline & Correlation (NEW)
        Tool(
            name="mac_build_timeline",
            description="Build a unified timeline from multiple forensic artifacts. Correlates events from "
                        "unified logs, Safari history, KnowledgeC, and plists.",
            inputSchema={
                "type": "object",
                "properties": {
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Path to triage collection root",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - start of time window",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - end of time window",
                    },
                    "sources": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sources to include: unified_logs, safari, knowledgec, plists",
                    },
                    "keyword": {
                        "type": "string",
                        "description": "Optional keyword to filter across all sources",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                    },
                },
                "required": ["artifacts_dir"],
            },
        ),
        Tool(
            name="mac_get_user_timeline",
            description="Build a timeline for a specific user account. Shows account creation, modification, "
                        "deletion, and related activity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Path to triage collection root",
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to investigate",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - start of time window",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - end of time window",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 100,
                    },
                },
                "required": ["artifacts_dir", "username"],
            },
        ),
        Tool(
            name="mac_investigate_event",
            description="Deep investigation of a specific event type. Correlates evidence across multiple "
                        "artifacts. Event types: user_deletion, user_creation, file_download, ssh_session, "
                        "malware_execution, privilege_escalation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "artifacts_dir": {
                        "type": "string",
                        "description": "Path to triage collection root",
                    },
                    "event_type": {
                        "type": "string",
                        "enum": ["user_deletion", "user_creation", "file_download", "ssh_session",
                                "malware_execution", "privilege_escalation"],
                        "description": "Type of event to investigate",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target of investigation (username, filename, IP, etc.)",
                    },
                    "time_window_hours": {
                        "type": "integer",
                        "default": 24,
                        "description": "Hours around event to search for context",
                    },
                },
                "required": ["artifacts_dir", "event_type", "target"],
            },
        ),

        # System Logs (NEW)
        Tool(
            name="mac_parse_fsck_apfs_log",
            description="Parse fsck_apfs.log to find volume creation, external device connections, "
                        "and anti-forensics activity. Shows APFS volume formatting operations with timestamps.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {
                        "type": "string",
                        "description": "Path to fsck_apfs.log file",
                    },
                    "device_filter": {
                        "type": "string",
                        "description": "Filter by device path (e.g., 'rdisk4')",
                    },
                    "volume_filter": {
                        "type": "string",
                        "description": "Filter by volume name (substring match)",
                    },
                    "external_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "Only show external device operations (rdisk2+)",
                    },
                    "errors_only": {
                        "type": "boolean",
                        "default": False,
                        "description": "Only show operations with errors",
                    },
                    "time_start": {
                        "type": "string",
                        "description": "ISO datetime - filter operations after this time",
                    },
                    "time_end": {
                        "type": "string",
                        "description": "ISO datetime - filter operations before this time",
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                    },
                },
                "required": ["log_path"],
            },
        ),
        Tool(
            name="mac_fsck_apfs_stats",
            description="Get statistics about fsck_apfs.log: devices checked, volumes found, "
                        "external devices, time range.",
            inputSchema={
                "type": "object",
                "properties": {
                    "log_path": {
                        "type": "string",
                        "description": "Path to fsck_apfs.log file",
                    },
                },
                "required": ["log_path"],
            },
        ),
    ]


# =============================================================================
# Tool Implementations
# =============================================================================

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls."""

    try:
        # Discovery
        if name == "mac_list_artifacts":
            result = discover_artifacts(arguments["artifacts_dir"])
            return json_response(result)

        # Unified Logs
        elif name == "mac_unified_logs_search":
            parser = UnifiedLogParser(arguments["log_path"])
            result = parser.search(
                query=arguments["query"],
                subsystem=arguments.get("subsystem"),
                process=arguments.get("process"),
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 50),
                offset=arguments.get("offset", 0),
            )
            return json_response(result)

        elif name == "mac_unified_logs_security_events":
            parser = UnifiedLogParser(arguments["log_path"])
            result = parser.get_security_events(
                event_type=arguments["event_type"],
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 50),
                offset=arguments.get("offset", 0),
            )
            return json_response(result)

        elif name == "mac_unified_logs_stats":
            parser = UnifiedLogParser(arguments["log_path"])
            result = parser.get_stats()
            return json_response(result)

        # Plist
        elif name == "mac_plist_read":
            parser = PlistParser(arguments["plist_path"])
            if "key_path" in arguments and arguments["key_path"]:
                result = parser.get(arguments["key_path"])
            else:
                result = parser.to_dict()
            return json_response(result)

        elif name == "mac_plist_search":
            parser = PlistParser(arguments["plist_path"])
            result = parser.search(arguments["pattern"])
            return json_response(result)

        elif name == "mac_plist_timestamps":
            parser = PlistParser(arguments["plist_path"])
            result = parser.get_timestamps()
            return json_response(result)

        # KnowledgeC
        elif name == "mac_knowledgec_app_usage":
            parser = KnowledgeCParser(arguments["db_path"])
            result = parser.get_app_usage(
                app_name=arguments.get("app_name"),
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 50),
            )
            parser.close()
            return json_response(result)

        # Safari
        elif name == "mac_safari_history":
            parser = SafariHistoryParser(arguments["db_path"])
            result = parser.get_history(
                url_filter=arguments.get("url_filter"),
                title_filter=arguments.get("title_filter"),
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 50),
            )
            parser.close()
            return json_response(result)

        elif name == "mac_safari_searches":
            parser = SafariHistoryParser(arguments["db_path"])
            result = parser.get_searches(
                query_filter=arguments.get("query_filter"),
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 50),
            )
            parser.close()
            return json_response(result)

        # TCC
        elif name == "mac_tcc_permissions":
            parser = TCCParser(arguments["db_path"])
            result = parser.get_permissions(
                service=arguments.get("service"),
                client=arguments.get("client"),
                limit=arguments.get("limit", 100),
            )
            parser.close()
            return json_response(result)

        # Quarantine
        elif name == "mac_quarantine_events":
            parser = QuarantineParser(arguments["db_path"])
            result = parser.get_events(
                filename_filter=arguments.get("filename_filter"),
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 50),
            )
            parser.close()
            return json_response(result)

        # User Accounts
        elif name == "mac_get_user_accounts":
            discovery = discover_artifacts(arguments["artifacts_dir"])
            users = discovery.get("users", [])

            # Check for deleted users in accounts plist
            if arguments.get("include_deleted", True):
                accounts_plist = discovery.get("artifacts", {}).get("accounts_plist")
                if accounts_plist:
                    try:
                        parser = PlistParser(accounts_plist)
                        deleted = parser.get("deletedUsers", [])
                        for user in deleted:
                            users.append({
                                "username": user.get("name"),
                                "uid": user.get("dsAttrTypeStandard:UniqueID"),
                                "real_name": user.get("dsAttrTypeStandard:RealName"),
                                "status": "deleted",
                                "deleted_at_utc": format_utc(user.get("date")) if user.get("date") else None,
                            })
                    except Exception:
                        pass

            return json_response({"users": users})

        # Extended Attributes (NEW)
        elif name == "mac_get_extended_attributes":
            file_path = Path(arguments["file_path"])
            parser = XattrParser(str(file_path.parent))

            if file_path.is_dir():
                result = parser.scan_directory(
                    str(file_path),
                    recursive=arguments.get("recursive", False),
                    limit=arguments.get("limit", 100),
                )
            else:
                result = parser.get_xattrs_for_file(str(file_path))

            return json_response(result)

        # Spotlight Search (NEW)
        elif name == "mac_spotlight_search":
            parser = SpotlightParser(arguments["spotlight_path"])
            result = parser.search(
                filename=arguments.get("filename"),
                content_type=arguments.get("content_type"),
                inode=arguments.get("inode"),
                path_contains=arguments.get("path_contains"),
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 50),
                offset=arguments.get("offset", 0),
            )
            return json_response(result)

        elif name == "mac_spotlight_stats":
            parser = SpotlightParser(arguments["spotlight_path"])
            result = parser.get_stats()
            return json_response(result)

        # FSEvents (NEW)
        elif name == "mac_fsevents_search":
            parser = FSEventsParser(arguments["fseventsd_path"])
            result = parser.search(
                path_filter=arguments.get("path_filter"),
                filename_filter=arguments.get("filename_filter"),
                event_types=arguments.get("event_types"),
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 50),
                offset=arguments.get("offset", 0),
            )
            return json_response(result)

        elif name == "mac_fsevents_stats":
            parser = FSEventsParser(arguments["fseventsd_path"])
            result = parser.get_stats()
            return json_response(result)

        # Timeline & Correlation (NEW)
        elif name == "mac_build_timeline":
            builder = TimelineBuilder(arguments["artifacts_dir"])
            result = builder.build_timeline(
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                sources=arguments.get("sources"),
                keyword=arguments.get("keyword"),
                limit=arguments.get("limit", 100),
            )
            return json_response(result)

        elif name == "mac_get_user_timeline":
            builder = TimelineBuilder(arguments["artifacts_dir"])
            result = builder.get_user_timeline(
                username=arguments["username"],
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                limit=arguments.get("limit", 100),
            )
            return json_response(result)

        elif name == "mac_investigate_event":
            investigator = EventInvestigator(arguments["artifacts_dir"])
            result = investigator.investigate(
                event_type=arguments["event_type"],
                target=arguments["target"],
                time_window_hours=arguments.get("time_window_hours", 24),
            )
            return json_response(result)

        # fsck_apfs.log (NEW)
        elif name == "mac_parse_fsck_apfs_log":
            parser = FsckApfsParser(arguments["log_path"])
            result = parser.search(
                device_filter=arguments.get("device_filter"),
                volume_filter=arguments.get("volume_filter"),
                time_start=parse_datetime(arguments.get("time_start")),
                time_end=parse_datetime(arguments.get("time_end")),
                errors_only=arguments.get("errors_only", False),
                external_only=arguments.get("external_only", False),
                limit=arguments.get("limit", 50),
            )
            return json_response(result)

        elif name == "mac_fsck_apfs_stats":
            parser = FsckApfsParser(arguments["log_path"])
            result = parser.get_stats()
            return json_response(result)

        else:
            return json_response({"error": f"Unknown tool: {name}"})

    except FileNotFoundError as e:
        return json_response({"error": f"File not found: {e}"})
    except Exception as e:
        return json_response({"error": str(e), "type": type(e).__name__})


# =============================================================================
# Main Entry Point
# =============================================================================

async def run():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    """Main entry point."""
    asyncio.run(run())


if __name__ == "__main__":
    main()
