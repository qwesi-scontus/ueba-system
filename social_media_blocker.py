"""
Social media blocker -- polls the UEBA API for whether this entity should
currently be blocking social media (combines the
social_media_block_enabled config flag with the entity's configured
working hours), and enforces it by redirecting known social media domains
to a local "Access Restricted" page via the Windows hosts file.

Requires elevation (Run as Administrator) -- the hosts file lives in a
system-protected directory, and so does installing the local certificate
authority into Windows' trusted root store. Every hosts-file line this
script adds is tagged with a "# UEBA-BLOCK" marker, so it only ever
adds/removes its own entries and never touches anything else already in
your hosts file.

The block page itself is served over both HTTPS and HTTP from
127.0.0.1, using a locally generated certificate authority (block_pki.py)
so the browser shows the custom "Access Restricted -- denied by your
administrator" page cleanly, instead of a certificate warning. The very
first run installs this CA into Windows' trusted root store (via
certutil) -- your antivirus may flag this the first time, since
installing a root certificate is a meaningful, security-relevant action;
that's expected.

This is a policy nudge, not a hard security control: anyone with admin
rights can edit the hosts file back, remove the installed root
certificate, use a different DNS resolver, or a VPN. It stops
casual/browser-based access during work hours; it isn't meant to be
unbreakable.

Usage:
    python social_media_blocker.py
    python social_media_blocker.py --api-url http://localhost:8000 --interval 60
    python social_media_blocker.py --entity-name micha   # keep in sync with your
                                                           # other collectors'
                                                           # --entity-name
    python social_media_blocker.py --once            # single check, for testing
"""
import argparse
import os
import subprocess
import sys
import time as time_module

import requests

import browser_history_monitor
import block_page_server

BLOCK_MARKER = "# UEBA-BLOCK"
BLOCK_IP = "127.0.0.1"  # routes to our local block-page server, not a dead address


def _hosts_file_path() -> str:
    windir = os.environ.get("WINDIR", r"C:\Windows")
    return os.path.join(windir, "System32", "drivers", "etc", "hosts")


def _read_hosts_lines(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


def _write_hosts_lines(path: str, lines: list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _is_ueba_block_line(line: str) -> bool:
    return line.rstrip("\n").endswith(BLOCK_MARKER)


def _build_block_lines(domains: list) -> list:
    lines = []
    for domain in domains:
        lines.append(f"{BLOCK_IP} {domain}  {BLOCK_MARKER}\n")
        lines.append(f"{BLOCK_IP} www.{domain}  {BLOCK_MARKER}\n")
    return lines


def _flush_dns() -> None:
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=15)
    except (subprocess.SubprocessError, OSError) as e:
        print(f"Could not flush DNS cache (blocking still applied, may take a moment to take effect): {e}",
              file=sys.stderr)


def apply_block(domains: list) -> None:
    """Removes any existing UEBA-BLOCK lines first (so a changed domain
    list doesn't leave stale entries behind), then writes fresh ones for
    the current domain list."""
    path = _hosts_file_path()
    lines = [l for l in _read_hosts_lines(path) if not _is_ueba_block_line(l)]
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines.extend(_build_block_lines(domains))
    _write_hosts_lines(path, lines)
    _flush_dns()


def remove_block() -> None:
    path = _hosts_file_path()
    lines = [l for l in _read_hosts_lines(path) if not _is_ueba_block_line(l)]
    _write_hosts_lines(path, lines)
    _flush_dns()


def check_status(api_url: str, entity_name: str) -> dict:
    resp = requests.get(
        f"{api_url}/social-media-block-status",
        params={"entity_name": entity_name},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def run_once(args, currently_blocking) -> bool:
    """Returns the new currently_blocking state."""
    try:
        status = check_status(args.api_url, args.entity_name)
    except requests.RequestException as e:
        print(f"Could not reach API: {e}", file=sys.stderr)
        return currently_blocking  # leave enforcement as-is until we can check again

    should_block = status["should_block"]
    if should_block == currently_blocking:
        return currently_blocking  # no change -- skip the hosts-file write entirely

    try:
        if should_block:
            apply_block(status.get("domains", []))
            print(f"[{args.entity_name}] Social media blocking ENABLED "
                  f"({len(status.get('domains', []))} domain(s))")
        else:
            remove_block()
            print(f"[{args.entity_name}] Social media blocking DISABLED")
    except PermissionError:
        print(
            "Permission denied writing to the hosts file. This script must be run "
            "elevated (Right-click -> Run as Administrator).",
            file=sys.stderr,
        )
        return currently_blocking  # unchanged -- retry next cycle

    return should_block


def parse_args():
    p = argparse.ArgumentParser(description="UEBA social media blocker (hosts-file based)")
    p.add_argument("--api-url", default=os.environ.get("UEBA_API_URL", "http://localhost:8000"))
    p.add_argument("--interval", type=int, default=60, help="Seconds between checks")
    p.add_argument("--entity-name", default=None,
                   help="Entity name to check block status for -- keep this the same as "
                        "your other collectors' --entity-name "
                        "(default: the COMPUTERNAME environment variable)")
    p.add_argument("--once", action="store_true", help="Run a single check and exit (for testing)")
    return p.parse_args()


def main():
    args = parse_args()
    if args.entity_name is None:
        args.entity_name = os.environ.get("COMPUTERNAME") or "unknown-computer"

    print(f"UEBA social media blocker starting. Entity={args.entity_name} "
          f"API={args.api_url} interval={args.interval}s")

    # Start the block-page servers once, up front -- they sit listening
    # harmlessly until the hosts file actually redirects a domain here.
    block_page_server.start_block_page_servers(browser_history_monitor.SOCIAL_MEDIA_DOMAINS)

    # Don't assume the hosts file starts clean -- if this script was
    # restarted while blocking was already active (or crashed and came
    # back up), stale UEBA-BLOCK entries could otherwise sit in the hosts
    # file indefinitely: the very first poll would see should_block=False,
    # compare it against the guessed currently_blocking=False, conclude
    # "no change needed", and skip removing them. Unconditionally clearing
    # any existing UEBA-BLOCK entries once at startup guarantees a known
    # clean baseline before the normal apply/remove logic takes over.
    try:
        remove_block()
    except PermissionError:
        print(
            "Permission denied writing to the hosts file at startup. This script must be "
            "run elevated (Right-click -> Run as Administrator).",
            file=sys.stderr,
        )
    currently_blocking = False

    while True:
        currently_blocking = run_once(args, currently_blocking)

        if args.once:
            break
        time_module.sleep(args.interval)


if __name__ == "__main__":
    main()
