<img src="mac_icon.png" width="150" alt="macOS Forensics MCP">

# mac_forensics-mcp

MCP (Model Context Protocol) server for macOS Digital Forensics and Incident Response (DFIR).

## Overview

This MCP server provides structured forensic analysis tools for macOS triage collections, reducing context overhead when investigating incidents with LLMs.

**Key Benefits:**
- Structured queries instead of raw grep through massive files
- Automatic timestamp normalization (Mac Absolute Time → UTC)
- Pre-built security event detection patterns
- Cross-artifact correlation and timeline building
- Pagination to avoid context overflow
- Artifact discovery to know what's available

**23 tools** covering: Unified Logs, FSEvents, Spotlight, Plists, SQLite databases, Extended Attributes, System Logs, and more.

## Installation

```bash
cd /opt/macOS/mac_forensics-mcp

# Create virtual environment and install dependencies
uv venv
uv pip install -e .
```

## Claude Code Configuration

### Option 1: Using `claude mcp add` (Recommended)

```bash
# Add to user settings (available in all projects)
claude mcp add mac-forensics -s user -- /opt/macOS/mac_forensics-mcp/.venv/bin/python -m mac_forensics_mcp.server

# Or add to current project only
claude mcp add mac-forensics -- /opt/macOS/mac_forensics-mcp/.venv/bin/python -m mac_forensics_mcp.server
```

To verify it was added:
```bash
claude mcp list
```

To remove:
```bash
claude mcp remove mac-forensics -s user
```

### Option 2: Manual JSON Configuration

Add to `~/.claude/settings.json` (user-level) or `.claude/settings.json` (project-level):

```json
{
  "mcpServers": {
    "mac-forensics": {
      "command": "/opt/macOS/mac_forensics-mcp/.venv/bin/python",
      "args": ["-m", "mac_forensics_mcp.server"],
      "env": {}
    }
  }
}
```

## Available Tools (23)

### Discovery

| Tool | Description |
|------|-------------|
| `mac_list_artifacts` | Discover available artifacts in a triage collection |

### Unified Logs

| Tool | Description |
|------|-------------|
| `mac_unified_logs_search` | Search logs with regex, filters, time range |
| `mac_unified_logs_security_events` | Get pre-defined security events (user_created, ssh_session, etc.) |
| `mac_unified_logs_stats` | Get log statistics: time range, top subsystems |

### Plist Files

| Tool | Description |
|------|-------------|
| `mac_plist_read` | Read and parse plist, optionally extract key path |
| `mac_plist_search` | Search for keys matching pattern |
| `mac_plist_timestamps` | Extract all timestamp values with UTC conversion |

### Databases

| Tool | Description |
|------|-------------|
| `mac_knowledgec_app_usage` | App usage from KnowledgeC.db |
| `mac_safari_history` | Safari browsing history |
| `mac_safari_searches` | Extract search queries from Safari |
| `mac_tcc_permissions` | TCC permissions (camera, mic, screen recording) |
| `mac_quarantine_events` | File download history |

### User Analysis

| Tool | Description |
|------|-------------|
| `mac_get_user_accounts` | List users including deleted accounts |
| `mac_get_user_timeline` | Build timeline for specific user account |

### FSEvents

| Tool | Description |
|------|-------------|
| `mac_fsevents_search` | Search file system events (create, delete, modify, rename) |
| `mac_fsevents_stats` | Get FSEvents statistics |

### Extended Attributes & Spotlight

| Tool | Description |
|------|-------------|
| `mac_get_extended_attributes` | Get xattr for file (quarantine, download URL, etc.) |
| `mac_spotlight_search` | Search Spotlight index for file metadata |
| `mac_spotlight_stats` | Get Spotlight index statistics |

### System Logs

| Tool | Description |
|------|-------------|
| `mac_parse_fsck_apfs_log` | Parse fsck_apfs.log for volume creation, external devices, anti-forensics |
| `mac_fsck_apfs_stats` | Get fsck_apfs.log statistics: devices, volumes, time range |

### Correlation & Investigation

| Tool | Description |
|------|-------------|
| `mac_build_timeline` | Build unified timeline from multiple artifacts |
| `mac_investigate_event` | Deep investigation with evidence correlation |

## Security Event Types

The `mac_unified_logs_security_events` tool supports these event types:

| Event Type | Description |
|------------|-------------|
| `user_created` | User account creation |
| `user_deleted` | User account deletion |
| `user_modified` | User account changes |
| `ssh_session` | SSH connections |
| `sudo_usage` | Sudo command execution |
| `auth_success` | Successful authentication |
| `auth_failure` | Failed authentication |
| `process_exec` | Process execution |
| `gatekeeper` | Gatekeeper/quarantine events |
| `tcc_prompt` | TCC permission prompts |
| `login` | User login |
| `logout` | User logout |
| `screen_lock` | Screen lock events |
| `screen_unlock` | Screen unlock events |
| `remote_login` | Remote Login service |
| `persistence` | Persistence mechanisms |

## Investigation Event Types

The `mac_investigate_event` tool supports deep investigation of these event types:

| Event Type | Description |
|------------|-------------|
| `user_deletion` | Investigate user account deletion with timeline and evidence correlation |
| `user_creation` | Investigate user account creation |
| `file_download` | Investigate file downloads (quarantine, xattr, browser history) |
| `ssh_session` | Investigate SSH session activity |
| `malware_execution` | Investigate potential malware execution |
| `privilege_escalation` | Investigate privilege escalation attempts |

## Usage Examples

### Discover artifacts in a triage

```python
mac_list_artifacts(artifacts_dir="/path/to/triage")
```

### Find user deletion events

```python
mac_unified_logs_security_events(
    log_path="/path/to/unified_logs.csv",
    event_type="user_deleted"
)
```

### Deep investigation of user deletion

```python
mac_investigate_event(
    artifacts_dir="/path/to/triage",
    event_type="user_deletion",
    target="username"
)
```

### Get Safari search history

```python
mac_safari_searches(
    db_path="/path/to/History.db",
    query_filter="delete"
)
```

### Read deleted users from plist

```python
mac_plist_read(
    plist_path="/path/to/com.apple.preferences.accounts.plist",
    key_path="deletedUsers"
)
```

### Find external device activity

```python
mac_parse_fsck_apfs_log(
    log_path="/path/to/fsck_apfs.log",
    external_only=True
)
```

### Search for specific volume

```python
mac_parse_fsck_apfs_log(
    log_path="/path/to/fsck_apfs.log",
    volume_filter="suspicious_volume"
)
```

### Build user activity timeline

```python
mac_get_user_timeline(
    artifacts_dir="/path/to/triage",
    username="username"
)
```

### Search FSEvents for file activity

```python
mac_fsevents_search(
    fseventsd_path="/path/to/.fseventsd",
    path_filter="/Users/username",
    event_types=["created", "deleted"]
)
```

## Configuration

### External Tool Paths

External forensic tools can be configured via environment variables. If not set, defaults to `/opt/macOS/` paths.

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `MAC_FORENSICS_UNIFIEDLOG_ITERATOR_PATH` | `/opt/macOS/unifiedlog_iterator` | Path to unifiedlog_iterator binary |
| `MAC_FORENSICS_FSEPARSER_PATH` | `/opt/macOS/FSEventsParser/FSEParser_V4.1.py` | Path to FSEParser script |
| `MAC_FORENSICS_SPOTLIGHT_PARSER_PATH` | `/opt/macOS/spotlight_parser/spotlight_parser.py` | Path to spotlight_parser script |

Example with custom paths:

```json
{
  "mcpServers": {
    "mac-forensics": {
      "command": "/opt/macOS/mac_forensics-mcp/.venv/bin/python",
      "args": ["-m", "mac_forensics_mcp.server"],
      "env": {
        "MAC_FORENSICS_UNIFIEDLOG_ITERATOR_PATH": "/custom/path/unifiedlog_iterator",
        "MAC_FORENSICS_FSEPARSER_PATH": "/custom/path/FSEParser.py",
        "MAC_FORENSICS_SPOTLIGHT_PARSER_PATH": "/custom/path/spotlight_parser.py"
      }
    }
  }
}
```

## Dependencies

- Python 3.10+
- uv (for virtual environment and package management)
- mcp >= 1.0.0
- biplist (optional, for malformed plists)

External tools (optional, for parsing raw artifacts):
- `unifiedlog_iterator` - for parsing .logarchive bundles
- `FSEParser` - for parsing FSEvents (.fseventsd)
- `spotlight_parser` - for parsing Spotlight indexes

## Architecture

```
mac_forensics_mcp/
├── server.py                # MCP server and tool definitions
├── config.py                # Configurable external tool paths
├── parsers/
│   ├── plist_parser.py      # Plist file parsing
│   ├── unified_log_parser.py # Unified log analysis
│   ├── sqlite_parser.py     # SQLite databases (KnowledgeC, Safari, TCC)
│   ├── fsevents_parser.py   # FSEvents parsing
│   ├── spotlight_parser.py  # Spotlight index parsing
│   ├── xattr_parser.py      # Extended attributes parsing
│   └── fsck_apfs_parser.py  # fsck_apfs.log parsing
├── correlation/
│   ├── timeline_builder.py  # Cross-artifact timeline correlation
│   └── event_investigator.py # Event-specific investigation
└── utils/
    ├── timestamps.py        # Mac/WebKit/HFS timestamp conversion
    └── discovery.py         # Artifact discovery
```

## Forensic Value

This MCP server was developed based on real-world macOS DFIR investigations. Key forensic capabilities:

| Capability | Tools |
|------------|-------|
| User account forensics | `mac_get_user_accounts`, `mac_get_user_timeline`, `mac_investigate_event` |
| File activity tracking | `mac_fsevents_search`, `mac_spotlight_search` |
| Download analysis | `mac_quarantine_events`, `mac_get_extended_attributes` |
| Security event detection | `mac_unified_logs_security_events` |
| External device detection | `mac_parse_fsck_apfs_log` |
| Cross-artifact correlation | `mac_build_timeline`, `mac_investigate_event` |

## References

- [SANS FOR518 Poster](https://www.sans.org/posters/macos-ios-forensic-analysis)
- [mac4n6 Artifacts Spreadsheet](https://www.sans.org/tools/mac4n6-artifacts)
- [SUMURI Mac Forensics Best Practices Guide 2025](https://sumuri.com/wp-content/uploads/2025/09/Mac-Forensics-Best-Practices-Guide-2025.pdf)
- [Google Cloud - Reviewing macOS Unified Logs](https://cloud.google.com/blog/topics/threat-intelligence/reviewing-macos-unified-logs/)

## Contributing

Based on lessons learned from macOS DFIR investigations. Additional tools and event patterns welcome.

---

## Author

**xtk**

Built for the DFIR community.
