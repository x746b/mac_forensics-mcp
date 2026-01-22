"""Artifact discovery for macOS triage collections.

Automatically locates forensic artifacts within a triage directory structure.
Supports common collection tools: Mac-Triage, Aftermath, macosac, etc.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import plistlib


# Common artifact locations (relative to triage root or volume root)
ARTIFACT_PATTERNS = {
    # System Information
    "system_version": [
        "System/Library/CoreServices/SystemVersion.plist",
        "private/var/db/SystemVersion.plist",
    ],

    # Unified Logs
    "unified_logs": [
        "private/var/db/diagnostics",
        "var/db/diagnostics",
        "UnifiedLogs/*.logarchive",
        "UnifiedLogs/unified_logs.csv",
        "*.logarchive",
        "unified_logs.csv",
        "../unified_logs.csv",  # Check parent directory
    ],

    # FSEvents
    "fsevents": [
        ".fseventsd",
        "fseventsd",
    ],

    # User Databases
    "knowledgec_system": [
        "private/var/db/CoreDuet/Knowledge/knowledgeC.db",
    ],
    "knowledgec_user": [
        "Users/*/Library/Application Support/Knowledge/knowledgeC.db",
    ],
    "tcc_system": [
        "Library/Application Support/com.apple.TCC/TCC.db",
    ],
    "tcc_user": [
        "Users/*/Library/Application Support/com.apple.TCC/TCC.db",
    ],

    # Browser History
    "safari_history": [
        "Users/*/Library/Safari/History.db",
    ],
    "chrome_history": [
        "Users/*/Library/Application Support/Google/Chrome/Default/History",
    ],
    "firefox_history": [
        "Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite",
    ],

    # Persistence
    "launch_daemons_system": [
        "Library/LaunchDaemons",
    ],
    "launch_agents_system": [
        "Library/LaunchAgents",
    ],
    "launch_agents_user": [
        "Users/*/Library/LaunchAgents",
    ],

    # User Activity
    "bash_history": [
        "Users/*/.bash_history",
    ],
    "zsh_history": [
        "Users/*/.zsh_history",
    ],

    # Quarantine & Gatekeeper
    "quarantine_events": [
        "Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
    ],

    # Account Management
    "accounts_plist": [
        "Library/Preferences/com.apple.preferences.accounts.plist",
    ],
    "dslocal_users": [
        "private/var/db/dslocal/nodes/Default/users",
    ],

    # Logs
    "system_log": [
        "private/var/log/system.log",
        "var/log/system.log",
    ],
    "install_log": [
        "private/var/log/install.log",
        "var/log/install.log",
    ],
}


def _find_files(base_path: Path, pattern: str) -> List[Path]:
    """Find files matching a pattern (supports * glob)."""
    results = []

    if "*" in pattern:
        # Use glob for wildcard patterns
        try:
            results = list(base_path.glob(pattern))
        except Exception:
            pass
    else:
        # Direct path check
        full_path = base_path / pattern
        if full_path.exists():
            results.append(full_path)

    return results


def _get_system_info(artifacts_dir: Path) -> Dict[str, Any]:
    """Extract system information from SystemVersion.plist."""
    info = {
        "macos_version": None,
        "build": None,
        "hostname": None,
        "timezone": None,
    }

    # Find SystemVersion.plist
    for pattern in ARTIFACT_PATTERNS["system_version"]:
        files = _find_files(artifacts_dir, pattern)
        if files:
            try:
                with open(files[0], "rb") as f:
                    plist = plistlib.load(f)
                    info["macos_version"] = plist.get("ProductVersion")
                    info["build"] = plist.get("ProductBuildVersion")
                    info["product_name"] = plist.get("ProductName")
            except Exception:
                pass
            break

    # Try to find hostname
    hostname_files = [
        "hostname.txt",
        "private/etc/hostname",
    ]
    for hf in hostname_files:
        path = artifacts_dir / hf
        if path.exists():
            try:
                info["hostname"] = path.read_text().strip()
                break
            except Exception:
                pass

    return info


def _get_users(artifacts_dir: Path) -> List[Dict[str, Any]]:
    """Discover user accounts from the triage collection."""
    users = []

    # Check Users directory
    users_dir = artifacts_dir / "Users"
    if users_dir.exists():
        for user_dir in users_dir.iterdir():
            if user_dir.is_dir() and not user_dir.name.startswith("."):
                if user_dir.name not in ["Shared", "Guest"]:
                    users.append({
                        "username": user_dir.name,
                        "home_path": str(user_dir),
                        "has_history": (user_dir / "Library/Safari/History.db").exists(),
                    })

    # Check dslocal for more details
    dslocal_path = artifacts_dir / "private/var/db/dslocal/nodes/Default/users"
    if dslocal_path.exists():
        for plist_file in dslocal_path.glob("*.plist"):
            username = plist_file.stem
            if username.startswith("_"):  # Skip system accounts
                continue
            try:
                with open(plist_file, "rb") as f:
                    plist = plistlib.load(f)
                    # Find or update user entry
                    user_entry = next((u for u in users if u["username"] == username), None)
                    if user_entry is None:
                        user_entry = {"username": username}
                        users.append(user_entry)

                    user_entry["uid"] = plist.get("uid", [None])[0]
                    user_entry["real_name"] = plist.get("realname", [None])[0]
            except Exception:
                pass

    return users


def discover_artifacts(artifacts_dir: str) -> Dict[str, Any]:
    """Discover available forensic artifacts in a triage collection.

    Args:
        artifacts_dir: Path to the triage collection root

    Returns:
        Dictionary with artifact locations and system information
    """
    base_path = Path(artifacts_dir)

    if not base_path.exists():
        return {"error": f"Directory not found: {artifacts_dir}"}

    # Try to find the actual triage root (might be nested)
    triage_roots = [base_path]

    # Check for common triage tool output structures
    for subdir in base_path.iterdir():
        if subdir.is_dir():
            # Mac-Triage style: hostname-Triage/
            if "Triage" in subdir.name or "triage" in subdir.name:
                triage_roots.insert(0, subdir)
            # Check for Users directory as indicator
            if (subdir / "Users").exists() or (subdir / "private").exists():
                triage_roots.insert(0, subdir)

    # Use the most likely root
    root = triage_roots[0]

    result = {
        "triage_root": str(root),
        "system_info": _get_system_info(root),
        "users": _get_users(root),
        "artifacts": {},
        # Convenience keys for common artifacts
        "unified_logs": None,
        "databases": {},
        "plists": [],
    }

    # Discover each artifact type
    for artifact_name, patterns in ARTIFACT_PATTERNS.items():
        found = []
        for pattern in patterns:
            files = _find_files(root, pattern)
            found.extend([str(f) for f in files])

        if found:
            # Deduplicate and sort
            found = sorted(set(found))
            if len(found) == 1:
                result["artifacts"][artifact_name] = found[0]
            else:
                result["artifacts"][artifact_name] = found

    # Set convenience keys
    if result["artifacts"].get("unified_logs"):
        logs = result["artifacts"]["unified_logs"]
        result["unified_logs"] = logs[0] if isinstance(logs, list) else logs

    # Populate databases dict
    db_mappings = {
        "knowledgec": "knowledgec_system",
        "safari_history": "safari_history",
        "tcc": "tcc_system",
        "quarantine": "quarantine_events",
    }
    for key, artifact_name in db_mappings.items():
        if result["artifacts"].get(artifact_name):
            db = result["artifacts"][artifact_name]
            result["databases"][key] = db[0] if isinstance(db, list) else db

    # Collect all plists
    for artifact_name, value in result["artifacts"].items():
        if isinstance(value, str) and value.endswith(".plist"):
            result["plists"].append(value)
        elif isinstance(value, list):
            for v in value:
                if v.endswith(".plist"):
                    result["plists"].append(v)

    return result


def find_artifact(artifacts_dir: str, artifact_type: str) -> Optional[str]:
    """Find a specific artifact type in the triage collection.

    Args:
        artifacts_dir: Path to triage collection
        artifact_type: Type of artifact (e.g., "unified_logs", "safari_history")

    Returns:
        Path to artifact or None if not found
    """
    discovery = discover_artifacts(artifacts_dir)
    artifact = discovery.get("artifacts", {}).get(artifact_type)

    if isinstance(artifact, list):
        return artifact[0] if artifact else None
    return artifact
