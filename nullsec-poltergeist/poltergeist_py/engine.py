"""
👻 poltergeist engine (Python) — /proc Anomaly Detector
Detects hidden processes, deleted executables, and RWX memory mappings.
"""

import os
import re
from dataclasses import dataclass


@dataclass
class ProcessInfo:
    pid: int
    name: str = ""
    state: str = ""
    uid: int = -1
    exe: str = ""
    exe_deleted: bool = False
    rwx_maps: list = None

    def __post_init__(self):
        if self.rwx_maps is None:
            self.rwx_maps = []


@dataclass
class AnomalyReport:
    hidden_pids: list      # PIDs found by brute force but not readdir
    deleted_exes: list     # ProcessInfo with deleted exe
    rwx_mappings: list     # ProcessInfo with RWX anonymous maps
    total_procs: int = 0


def get_readdir_pids() -> set[int]:
    """Get PIDs from /proc via readdir (os.listdir)."""
    pids = set()
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.add(int(entry))
    except PermissionError:
        pass
    return pids


def get_bruteforce_pids(max_pid: int = 65536) -> set[int]:
    """Get PIDs by brute-force checking /proc/PID/stat existence."""
    pids = set()
    for pid in range(1, max_pid + 1):
        if os.path.exists(f"/proc/{pid}/stat"):
            pids.add(pid)
    return pids


def get_process_info(pid: int) -> ProcessInfo:
    """Read process info from /proc."""
    info = ProcessInfo(pid=pid)

    # Read comm
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            info.name = f.read().strip()
    except (PermissionError, OSError):
        info.name = "?"

    # Read status for state and UID
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("State:"):
                    info.state = line.split(":")[1].strip()
                elif line.startswith("Uid:"):
                    info.uid = int(line.split()[1])
    except (PermissionError, OSError):
        pass

    # Check exe symlink
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        info.exe = exe
        info.exe_deleted = "(deleted)" in exe
    except (PermissionError, OSError):
        info.exe = ""

    return info


def check_rwx_maps(pid: int) -> list[str]:
    """Check for anonymous RWX memory mappings."""
    rwx = []
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    perms = parts[1]
                    if perms == "rwxp" and (len(parts) < 6 or parts[5].strip() == ""):
                        addr = parts[0]
                        rwx.append(addr)
    except (PermissionError, OSError):
        pass
    return rwx


def full_scan(bruteforce: bool = False) -> AnomalyReport:
    """Run full anomaly scan."""
    report = AnomalyReport(
        hidden_pids=[],
        deleted_exes=[],
        rwx_mappings=[],
    )

    readdir_pids = get_readdir_pids()
    report.total_procs = len(readdir_pids)

    # Hidden PID detection
    if bruteforce:
        brute_pids = get_bruteforce_pids()
        hidden = brute_pids - readdir_pids
        for pid in sorted(hidden):
            info = get_process_info(pid)
            report.hidden_pids.append(info)

    # Check all visible processes
    for pid in sorted(readdir_pids):
        info = get_process_info(pid)

        # Deleted exe check
        if info.exe_deleted:
            report.deleted_exes.append(info)

        # RWX memory mapping check
        rwx = check_rwx_maps(pid)
        if rwx:
            info.rwx_maps = rwx
            report.rwx_mappings.append(info)

    return report
