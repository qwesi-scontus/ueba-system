"""
Quick one-shot diagnostic: shows exactly what the UEBA system currently
thinks about social-media blocking, in one place, without opening Notepad
or querying anything by hand.

Usage:
    python check_block_status.py
    python check_block_status.py --entity-name micha
    python check_block_status.py --entity-name micha --api-url http://localhost:8000
"""
import argparse
import os
import sys
from datetime import datetime

import requests

BLOCK_MARKER = "# UEBA-BLOCK"


def hosts_file_path() -> str:
    windir = os.environ.get("WINDIR", r"C:\Windows")
    return os.path.join(windir, "System32", "drivers", "etc", "hosts")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--entity-name", default=os.environ.get("COMPUTERNAME") or "unknown-computer")
    p.add_argument("--api-url", default="http://localhost:8000")
    args = p.parse_args()

    print("=" * 60)
    print(f"UEBA block status check -- {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Entity: {args.entity_name}")
    print("=" * 60)

    # 1. What does the backend say should be happening?
    print("\n[1] Backend decision (GET /social-media-block-status):")
    try:
        resp = requests.get(
            f"{args.api_url}/social-media-block-status",
            params={"entity_name": args.entity_name},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        print(f"    entity_found: {data.get('entity_found')}")
        print(f"    should_block: {data.get('should_block')}")
    except requests.RequestException as e:
        print(f"    COULD NOT REACH API: {e}")
        print("    -> Is uvicorn (api.py) running? Check that terminal for errors.")
        data = None

    # 2. What's actually in the hosts file right now?
    print("\n[2] Hosts file (looking for # UEBA-BLOCK lines):")
    path = hosts_file_path()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        block_lines = [l.strip() for l in lines if l.rstrip("\n").endswith(BLOCK_MARKER)]
        if block_lines:
            print(f"    {len(block_lines)} blocking line(s) found:")
            for l in block_lines:
                print(f"      {l}")
        else:
            print("    (none -- hosts file is clean, nothing is being blocked)")
    except PermissionError:
        print(f"    COULD NOT READ {path} -- try running this script as Administrator")
    except FileNotFoundError:
        print(f"    Hosts file not found at expected path: {path}")

    # 3. Put the two together so the verdict is obvious at a glance.
    print("\n[3] Verdict:")
    if data is not None:
        should = data.get("should_block")
        try:
            actually_blocking = bool(block_lines)
        except NameError:
            actually_blocking = None
        if actually_blocking is None:
            print("    Could not determine hosts file state -- see [2] above.")
        elif should == actually_blocking:
            state = "BLOCKING" if should else "NOT blocking"
            print(f"    OK -- backend and hosts file agree: currently {state}.")
            print("    If your browser still shows the old behaviour, this is a")
            print("    browser/DNS caching issue, not a backend problem -- test in")
            print("    a fresh Incognito window.")
        else:
            print(f"    MISMATCH: backend says should_block={should}, but hosts file "
                  f"{'has' if actually_blocking else 'does not have'} block entries.")
            print("    This means the blocker script hasn't caught up yet, isn't ")
            print("    running, or isn't running elevated. Check its terminal.")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
