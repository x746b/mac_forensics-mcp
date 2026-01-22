"""Parser for macOS fsck_apfs.log files.

Extracts filesystem check operations, volume creation/formatting,
and external device activity from /private/var/log/fsck_apfs.log.

Forensic Value:
- Volume creation/formatting timestamps
- External device connections (new disk devices)
- Volume names (can reveal anti-forensics attempts)
- Tool signatures (newfs_apfs, diskutil, etc.)
"""

import re
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional


class FsckApfsParser:
    """Parser for fsck_apfs.log files."""

    # Regex patterns for parsing
    STARTED_PATTERN = re.compile(
        r'^(/dev/\w+):\s+fsck_apfs started at (.+)$'
    )
    COMPLETED_PATTERN = re.compile(
        r'^(/dev/\w+):\s+fsck_apfs completed at (.+)$'
    )
    VOLUME_INFO_PATTERN = re.compile(
        r'^(/dev/\w+):\s+The volume (.+?) was formatted by (.+?)(?: and last modified by (.+?))?\.?$'
    )
    ERROR_PATTERN = re.compile(
        r'^(/dev/\w+):\s+error:\s+(.+)$'
    )
    RESULT_PATTERN = re.compile(
        r'^(/dev/\w+):\s+\*\*\s+(QUICKCHECK ONLY; FILESYSTEM CLEAN|.+)$'
    )
    CHECKPOINT_PATTERN = re.compile(
        r'^(/dev/\w+):\s+Checking the checkpoint with transaction ID (\d+)\.$'
    )

    def __init__(self, log_path: str):
        """Initialize with path to fsck_apfs.log.

        Args:
            log_path: Path to fsck_apfs.log file
        """
        self.log_path = Path(log_path)
        if not self.log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")

    def _parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse fsck_apfs timestamp format.

        Format: "Sat Mar  8 09:58:55 2025"
        """
        try:
            # Handle double spaces in day (e.g., "Mar  8" vs "Mar 10")
            ts_str = re.sub(r'\s+', ' ', ts_str.strip())
            return datetime.strptime(ts_str, "%a %b %d %H:%M:%S %Y")
        except ValueError:
            return None

    def parse(self) -> Dict[str, Any]:
        """Parse the entire fsck_apfs.log file.

        Returns:
            Dict with parsed check operations and statistics
        """
        operations = []
        current_op = None
        devices_seen = set()
        volumes_found = []

        with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip()
                if not line:
                    continue

                # Check for operation start
                match = self.STARTED_PATTERN.match(line)
                if match:
                    device, ts_str = match.groups()
                    devices_seen.add(device)
                    current_op = {
                        "device": device,
                        "started_at": ts_str,
                        "started_at_parsed": self._parse_timestamp(ts_str),
                        "completed_at": None,
                        "completed_at_parsed": None,
                        "volume_name": None,
                        "formatted_by": None,
                        "last_modified_by": None,
                        "result": None,
                        "errors": [],
                        "transaction_id": None,
                    }
                    continue

                if not current_op:
                    continue

                # Check for completion
                match = self.COMPLETED_PATTERN.match(line)
                if match:
                    device, ts_str = match.groups()
                    if device == current_op["device"]:
                        current_op["completed_at"] = ts_str
                        current_op["completed_at_parsed"] = self._parse_timestamp(ts_str)
                        operations.append(current_op)

                        # Track volumes with names
                        if current_op["volume_name"]:
                            volumes_found.append({
                                "device": current_op["device"],
                                "volume_name": current_op["volume_name"],
                                "formatted_by": current_op["formatted_by"],
                                "timestamp": current_op["started_at"],
                            })
                        current_op = None
                    continue

                # Check for volume info
                match = self.VOLUME_INFO_PATTERN.match(line)
                if match:
                    device, vol_name, formatted_by, modified_by = match.groups()
                    if device == current_op["device"]:
                        current_op["volume_name"] = vol_name
                        current_op["formatted_by"] = formatted_by
                        current_op["last_modified_by"] = modified_by.strip() if modified_by else None
                    continue

                # Check for errors
                match = self.ERROR_PATTERN.match(line)
                if match:
                    device, error_msg = match.groups()
                    if device == current_op["device"]:
                        current_op["errors"].append(error_msg)
                    continue

                # Check for result
                match = self.RESULT_PATTERN.match(line)
                if match:
                    device, result = match.groups()
                    if device == current_op["device"]:
                        if "FILESYSTEM CLEAN" in result or "QUICKCHECK" in result:
                            current_op["result"] = result
                    continue

                # Check for transaction ID
                match = self.CHECKPOINT_PATTERN.match(line)
                if match:
                    device, txn_id = match.groups()
                    if device == current_op["device"]:
                        current_op["transaction_id"] = int(txn_id)

        return {
            "log_path": str(self.log_path),
            "total_operations": len(operations),
            "devices_seen": sorted(devices_seen),
            "volumes_found": volumes_found,
            "operations": operations,
        }

    def get_volumes(self) -> List[Dict[str, Any]]:
        """Get all named volumes found in the log.

        Returns:
            List of volume information dicts
        """
        result = self.parse()
        return result["volumes_found"]

    def get_external_devices(self) -> List[Dict[str, Any]]:
        """Identify potential external devices.

        External devices typically appear as rdisk2+, rdisk3+, etc.
        (rdisk0/rdisk1 are usually internal drives)

        Returns:
            List of operations on potential external devices
        """
        result = self.parse()
        external_ops = []

        for op in result["operations"]:
            device = op["device"]
            # Extract disk number from device path
            match = re.search(r'rdisk(\d+)', device)
            if match:
                disk_num = int(match.group(1))
                # rdisk2+ are typically external
                if disk_num >= 2:
                    external_ops.append(op)

        return external_ops

    def get_new_volumes(self) -> List[Dict[str, Any]]:
        """Find volumes that were newly created/formatted.

        Looks for volumes with low transaction IDs (recently created).

        Returns:
            List of newly created volume operations
        """
        result = self.parse()
        new_volumes = []

        for op in result["operations"]:
            # Low transaction ID suggests new volume
            if op["transaction_id"] and op["transaction_id"] <= 10:
                if op["volume_name"]:
                    new_volumes.append(op)

        return new_volumes

    def search(
        self,
        device_filter: Optional[str] = None,
        volume_filter: Optional[str] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        errors_only: bool = False,
        external_only: bool = False,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Search fsck_apfs operations with filters.

        Args:
            device_filter: Filter by device path (substring match)
            volume_filter: Filter by volume name (substring match)
            time_start: Filter operations after this time
            time_end: Filter operations before this time
            errors_only: Only return operations with errors
            external_only: Only return external device operations
            limit: Maximum results to return

        Returns:
            Dict with filtered results and statistics
        """
        result = self.parse()
        filtered = []

        for op in result["operations"]:
            # Device filter
            if device_filter and device_filter.lower() not in op["device"].lower():
                continue

            # Volume filter
            if volume_filter:
                if not op["volume_name"]:
                    continue
                if volume_filter.lower() not in op["volume_name"].lower():
                    continue

            # Time filters
            if time_start and op["started_at_parsed"]:
                if op["started_at_parsed"] < time_start:
                    continue
            if time_end and op["started_at_parsed"]:
                if op["started_at_parsed"] > time_end:
                    continue

            # Errors only
            if errors_only and not op["errors"]:
                continue

            # External only
            if external_only:
                match = re.search(r'rdisk(\d+)', op["device"])
                if not match or int(match.group(1)) < 2:
                    continue

            filtered.append(op)

            if len(filtered) >= limit:
                break

        return {
            "total_matched": len(filtered),
            "results": filtered,
            "has_more": len(result["operations"]) > len(filtered),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the log file.

        Returns:
            Dict with statistics
        """
        result = self.parse()

        # Count by device
        device_counts = {}
        for op in result["operations"]:
            device = op["device"]
            device_counts[device] = device_counts.get(device, 0) + 1

        # Count errors
        error_count = sum(1 for op in result["operations"] if op["errors"])

        # Time range
        timestamps = [
            op["started_at_parsed"]
            for op in result["operations"]
            if op["started_at_parsed"]
        ]
        time_range = {}
        if timestamps:
            time_range = {
                "earliest": min(timestamps).isoformat(),
                "latest": max(timestamps).isoformat(),
            }

        # External devices
        external_devices = set()
        for op in result["operations"]:
            match = re.search(r'rdisk(\d+)', op["device"])
            if match and int(match.group(1)) >= 2:
                external_devices.add(op["device"])

        return {
            "log_path": str(self.log_path),
            "total_operations": result["total_operations"],
            "unique_devices": len(result["devices_seen"]),
            "device_counts": device_counts,
            "volumes_with_names": len(result["volumes_found"]),
            "operations_with_errors": error_count,
            "external_devices": sorted(external_devices),
            "time_range": time_range,
        }
