"""
Removable-drive (USB) file transfer -> UEBA data-transfer tracker.

Watches whichever removable drives (USB flash drives, external disks) are
currently attached to this machine, and reports how many bytes have been
written to them since the last poll to the UEBA API as
event_type="data_transfer" events. This is the collector that feeds
detectors.detect_data_transfer -- the excessive-data-transfer rule sums
bytes_transferred across a rolling window and compares it against the
entity's configured Low/Medium/High/Critical megabyte thresholds, exactly
the same way the other two detectors work.

Deliberately scoped to removable drives only, not the whole filesystem:
that is the single most common and most legible insider-threat data-
exfiltration path for a standalone workstation (copying files onto a USB
drive to walk out with them), and it's something this collector can watch
cheaply by polling, without needing a kernel-level file-system filter
driver the way a full DLP product would.

How it decides what counts as "transferred": each poll, it lists every
file currently on every attached removable drive and compares that
listing to what it saw last poll (kept in the checkpoint file). A file
that's new, or whose size has grown, contributes (its new size, or the
size increase) to this poll's total bytes_transferred. A file that
shrank, was deleted, or a drive that's been unplugged is not treated as a
transfer in either direction -- this collector only watches for data
arriving on removable media, not leaving it.

Does not require elevation -- reading file sizes on a removable drive
does not need Administrator, unlike windows_event_collector.py.

Usage:
    python file_transfer_monitor.py
    python file_transfer_monitor.py --api-url http://localhost:8000 --interval 30
    python file_transfer_monitor.py --entity-name micha   # keep in sync with
                                                             # windows_event_collector.py's
                                                             # --entity-name if you're
                                                             # using that, so both report
                                                             # under the same laptop entity
    python file_transfer_monitor.py --once             # single poll, for testing
    python file_transfer_monitor.py --watch-path "C:\\Users\\micha\\Desktop\\TestUSB"
        # no physical USB drive needed for testing: watches an ordinary folder
        # as if it were one, so copying files into it simulates a transfer
"""
import argparse
import ctypes
import json
import os
import string
import sys
import time as time_module
from datetime import datetime, timezone

import requests

# Safety caps so a very large or very full removable drive can't make a
# single poll take an unreasonable amount of time. A drive with more files
# or deeper nesting than this just has its remainder skipped for that
# poll -- the checkpoint means anything missed this time is still picked
# up (or at least reconsidered) on the next one.
MAX_FILES_PER_DRIVE = 20_000
MAX_DEPTH = 6

# Windows GetDriveTypeW() return codes we care about.
DRIVE_REMOVABLE = 2

ENTITY_NAME = None  # set once at startup in main(), from --entity-name or COMPUTERNAME


def _list_removable_drives():
    """Returns a list of drive letters (e.g. ['E:\\\\', 'F:\\\\']) currently
    attached and reported by Windows as removable. Re-checked on every
    poll, so a drive plugged in or removed between polls is picked up
    automatically without restarting this script."""
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if not (bitmask & (1 << i)):
            continue
        root = f"{letter}:\\"
        try:
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
        except Exception:
            continue
        if drive_type == DRIVE_REMOVABLE:
            drives.append(root)
    return drives


def _scan_drive(root: str):
    """Walks root (bounded by MAX_DEPTH and MAX_FILES_PER_DRIVE) and
    returns {absolute_path: (size, mtime)} for every file found. Skips
    anything it can't read (permission errors, files that vanish mid-scan,
    etc.) rather than letting one bad file stop the whole scan."""
    snapshot = {}
    root_depth = root.rstrip("\\").count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        depth = dirpath.rstrip("\\").count(os.sep) - root_depth
        if depth >= MAX_DEPTH:
            dirnames[:] = []  # don't descend further from here
            continue
        for name in filenames:
            if len(snapshot) >= MAX_FILES_PER_DRIVE:
                return snapshot
            full_path = os.path.join(dirpath, name)
            try:
                st = os.stat(full_path)
            except OSError:
                continue
            snapshot[full_path] = (st.st_size, st.st_mtime)
    return snapshot


def compute_transfer(previous: dict, current: dict):
    """Compares two {path: (size, mtime)} snapshots of the same drive.
    Returns (bytes_transferred, file_count) for files that are new or have
    grown since `previous`. A file that shrank, was deleted, or is
    unchanged contributes nothing."""
    total_bytes = 0
    file_count = 0
    for path, (size, mtime) in current.items():
        prev = previous.get(path)
        if prev is None:
            # New file: the whole thing counts as transferred.
            total_bytes += size
            file_count += 1
        else:
            prev_size, prev_mtime = prev
            if size > prev_size:
                # Grown since last poll (e.g. a large copy still in
                # progress across two polls) -- only the increase counts,
                # so a file isn't double-counted across polls.
                total_bytes += (size - prev_size)
                file_count += 1
    return total_bytes, file_count


def post_data_transfer_event(api_url: str, bytes_transferred: int, file_count: int, resource: str, api_key: str = None) -> dict:
    payload = {
        "entity_name": ENTITY_NAME,
        "entity_type": "user",
        "event_type": "data_transfer",
        "status": "success",
        "event_time": datetime.now(timezone.utc).isoformat(),
        "resource": resource,
        "bytes_transferred": bytes_transferred,
        "file_count": file_count,
        "raw": {"source": "removable_drive"},
    }
    headers = {"X-Collector-Key": api_key} if api_key else {}
    resp = requests.post(f"{api_url}/events", json=payload, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def load_checkpoint(path: str):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def save_checkpoint(path: str, state: dict):
    with open(path, "w") as f:
        json.dump(state, f)


def run_once(args, state: dict) -> dict:
    """state maps a drive's volume-ish key (its root path, e.g. 'E:\\\\')
    to that drive's last-seen {path: [size, mtime]} snapshot. A drive not
    currently attached is left untouched in state (so unplugging and
    replugging the same drive later still compares against what was there
    before, rather than treating everything on it as new again)."""
    new_state = dict(state)
    posted = 0

    watch_roots = _list_removable_drives() + [p for p in args.watch_path if os.path.isdir(p)]
    for root in watch_roots:
        current = _scan_drive(root)
        previous = {p: tuple(v) for p, v in state.get(root, {}).items()}

        bytes_transferred, file_count = compute_transfer(previous, current)
        if bytes_transferred > 0:
            try:
                post_data_transfer_event(args.api_url, bytes_transferred, file_count, root, args.api_key)
                posted += 1
                print(f"[{datetime.now().isoformat(timespec='seconds')}] "
                      f"{root}: {bytes_transferred:,} byte(s) across {file_count} file(s)")
            except requests.RequestException as e:
                print(f"Failed to post event: {e}", file=sys.stderr)
                # Don't advance the checkpoint for this drive if the post
                # failed -- try again next poll rather than silently
                # losing this transfer from the record.
                continue

        new_state[root] = current

    return new_state


def parse_args():
    p = argparse.ArgumentParser(description="Removable-drive file transfer -> UEBA tracker")
    p.add_argument("--api-url", default=os.environ.get("UEBA_API_URL", "http://localhost:8000"))
    p.add_argument("--api-key", default=os.environ.get("COLLECTOR_API_KEY"),
                   help="Shared secret sent as the X-Collector-Key header. Required if the "
                        "API has COLLECTOR_API_KEY set (e.g. when hosted publicly); leave unset "
                        "for a local/trusted deployment with no key configured.")
    p.add_argument("--interval", type=int, default=30, help="Seconds between polls")
    p.add_argument("--checkpoint-file", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "file_transfer_checkpoint.json"))
    p.add_argument("--entity-name", default=None,
                   help="Entity name to attribute transfers to -- keep this the same as "
                        "windows_event_collector.py's --entity-name if you run both, "
                        "so everything from this laptop lands on one entity "
                        "(default: the COMPUTERNAME environment variable)")
    p.add_argument("--once", action="store_true", help="Run a single poll and exit (for testing)")
    p.add_argument("--watch-path", action="append", default=[],
                   help="Watch this folder as if it were a removable drive, in addition to "
                        "any real ones detected. Repeatable. Meant for testing without "
                        "physical USB hardware -- e.g. --watch-path C:\\Users\\micha\\Desktop\\TestUSB "
                        "then just copy files into that folder to simulate a transfer.")
    return p.parse_args()


def main():
    global ENTITY_NAME
    args = parse_args()
    ENTITY_NAME = args.entity_name or os.environ.get("COMPUTERNAME") or "unknown-computer"

    state = load_checkpoint(args.checkpoint_file)

    print(f"UEBA file transfer monitor starting. Entity={ENTITY_NAME} API={args.api_url} "
          f"interval={args.interval}s checkpoint_file={args.checkpoint_file}")

    while True:
        try:
            state = run_once(args, state)
            save_checkpoint(args.checkpoint_file, state)
        except Exception as e:
            print(f"Collector error: {e}", file=sys.stderr)

        if args.once:
            break
        time_module.sleep(args.interval)


if __name__ == "__main__":
    main()
