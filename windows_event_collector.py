"""
Windows Security Event Log collector for the UEBA system.

Polls the local Windows "Security" event log for real logon/logoff activity
and POSTs each relevant event to the UEBA API (POST /events), which runs it
straight through the detection engine.

Event IDs captured:
    4624  successful logon
    4625  failed logon
    4634  logoff
    4648  logon using explicit credentials ("run as different user")
    4672  special privileges assigned (admin/elevated logon)
    4720  user account created

Requirements:
    - Must be run with permission to read the Security log: either an
      elevated ("Run as Administrator") terminal, or a user added to the
      built-in "Event Log Readers" group.
    - Logon/Logoff auditing must be enabled (4624/4625 are on by default;
      4634 often is not). From an elevated terminal:
          auditpol /set /subcategory:"Logon" /success:enable /failure:enable
          auditpol /set /subcategory:"Logoff" /success:enable
    - `pip install requests` (also listed in requirements.txt)

Usage:
    python windows_event_collector.py
    python windows_event_collector.py --api-url http://localhost:8000 --interval 15
    python windows_event_collector.py --entity-name micha   # override the auto-detected computer name
    python windows_event_collector.py --once            # single poll, for testing
    python windows_event_collector.py --lookback-minutes 120   # first-run window
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time as time_module
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

import requests

EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
EVENT_IDS = [4624, 4625, 4634, 4648, 4672, 4720]
SEPARATOR = "###EVENT-SEP###"

EXCLUDED_USERNAMES = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "POSTGRES", "DEFAULTUSER1", "WSIACCOUNT"}

# Matches a GUID like "4EA85BBA-1676-4333-AD71-A2CB50478237" -- these show up
# as virtual/package-identity accounts (e.g. for Windows Store apps) rather
# than a real person, so they're filtered out the same way service accounts are.
_GUID_PATTERN = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")

# The single entity every event from this machine gets attributed to,
# regardless of which Windows account name a given event happens to log
# (Windows' own credential-provider machinery around the lock screen
# generates a surprising number of different placeholder identities --
# QWESISCONTUS$, DefaultUser1, WsiAccount, and others -- none of which
# represent a second, different person). The noise-filtering logic below
# still runs on the *raw* per-event username as before; only the final
# attribution changes. Set once at startup in main(), from --entity-name
# or the COMPUTERNAME environment variable.
ENTITY_NAME = None

# Logon types we don't care about for UEBA purposes (service/system/batch).
# 2=Interactive 3=Network 4=Batch 5=Service 7=Unlock 8=NetworkCleartext
# 9=NewCredentials 10=RemoteInteractive 11=CachedInteractive
NOISY_LOGON_TYPES = {"0", "4", "5"}

PS_SCRIPT_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$startTime = [DateTime]::Parse('%%START_TIME%%').ToUniversalTime()
$ids = @(%%EVENT_IDS%%)
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids; StartTime=$startTime} -ErrorAction Stop
} catch {
    if ($_.Exception.Message -like '*No events were found*') {
        $events = @()
    } else {
        Write-Error $_.Exception.Message
        exit 1
    }
}
foreach ($e in ($events | Where-Object { $_.RecordId -gt %%RECORD_ID%% } | Sort-Object RecordId)) {
    Write-Output $e.ToXml()
    Write-Output '%%SEP%%'
}
"""


def fetch_security_events(start_time_iso: str, since_record_id: int) -> list:
    """Runs a PowerShell Get-WinEvent query and returns a list of raw event
    XML strings. Raises PermissionError with a clear message if the Security
    log can't be read (most common cause: not running elevated)."""
    script = (
        PS_SCRIPT_TEMPLATE
        .replace("%%START_TIME%%", start_time_iso)
        .replace("%%EVENT_IDS%%", ",".join(str(i) for i in EVENT_IDS))
        .replace("%%RECORD_ID%%", str(since_record_id))
        .replace("%%SEP%%", SEPARATOR)
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60,  # never let a stuck PowerShell call freeze the whole collector
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "PowerShell took longer than 60 seconds to respond and was aborted. "
            "This poll cycle was skipped; the next one will retry."
        )

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if "access is denied" in stderr.lower() or "access denied" in stderr.lower():
            raise PermissionError(
                "Access denied reading the Security event log. Run this script from a "
                "terminal opened with 'Run as Administrator', or add your account to the "
                "'Event Log Readers' local group and sign out/in."
            )
        raise RuntimeError(f"PowerShell error: {stderr or 'unknown error'}")

    output = result.stdout or ""
    if not output.strip():
        return []
    return [chunk.strip() for chunk in output.split(SEPARATOR) if chunk.strip()]


def parse_event_xml(xml_text: str):
    root = ET.fromstring(xml_text)
    system = root.find(f"{EVENT_NS}System")
    event_id = int(system.find(f"{EVENT_NS}EventID").text)
    record_id = int(system.find(f"{EVENT_NS}EventRecordID").text)
    time_created = system.find(f"{EVENT_NS}TimeCreated").get("SystemTime")

    data = {}
    event_data = root.find(f"{EVENT_NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{EVENT_NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = d.text
    return event_id, record_id, time_created, data


def _clean_ip(ip: str):
    if not ip or ip in ("-", "::1"):
        return None
    if "%" in ip:  # strip IPv6 zone index, e.g. fe80::1%23 -> not valid for Postgres INET
        ip = ip.split("%")[0]
    return ip


def should_skip_account(username: str, allow_machine_account: bool = False,
                         allow_unresolved_username: bool = False) -> bool:
    if not username or username == "-":
        # Real exception: a failed PIN/password attempt at the Windows lock
        # screen is very commonly logged with NO target username at all
        # ("-") -- Windows records the failure before it has resolved which
        # account was being authenticated. That is exactly the case we most
        # want to catch, not noise to discard, so for 4625 specifically
        # (allow_unresolved_username=True) it is let through and attributed
        # to this collector's own ENTITY_NAME instead of being dropped.
        if allow_unresolved_username:
            return False
        return True
    if username.upper() in EXCLUDED_USERNAMES:
        return True
    if _GUID_PATTERN.match(username):
        return True
    if username.endswith("$") and not allow_machine_account:  # machine accounts
        # Real exception: failed PIN attempts at the Windows lock screen are
        # sometimes attributed to the machine account (COMPUTERNAME$)
        # instead of the actual human, because the failure happens before
        # Windows resolves which user account is being authenticated. When
        # allow_machine_account=True (used for 4625 specifically), a
        # machine-account name is let through instead of silently dropped,
        # so a real failed login isn't lost. Merge that entity into the
        # correct person's via the dashboard's "Merge duplicate into..."
        # action once you notice it -- future events under that same
        # machine-account name will then resolve to the merged entity
        # automatically.
        return True
    if username.startswith("DWM-") or username.startswith("UMFD-"):
        return True
    return False


def map_event(event_id: int, data: dict):
    """Translate a raw Windows Security event into a UEBA event payload dict,
    or return None if this event should be skipped (noise)."""
    # "%%1843" is Windows' message-ID placeholder for "Yes" in this field
    # (ToXml() output doesn't resolve it to literal text the way Event
    # Viewer does). A virtual account is always internal Windows plumbing
    # (e.g. credential-provider machinery around the lock screen) rather
    # than a real person, regardless of event type or success/failure --
    # skip it unconditionally, before any username-based check.
    if data.get("VirtualAccount") == "%%1843":
        return None

    username = data.get("TargetUserName") or data.get("SubjectUserName")
    allow_machine_account = (event_id == 4625)  # failed logon: see should_skip_account
    allow_unresolved_username = (event_id == 4625)  # failed logon: see should_skip_account
    if should_skip_account(username, allow_machine_account=allow_machine_account,
                            allow_unresolved_username=allow_unresolved_username):
        return None

    ip = _clean_ip(data.get("IpAddress"))
    workstation = data.get("WorkstationName") or data.get("TargetServerName")
    logon_type = data.get("LogonType")

    if event_id in (4624, 4625):
        if logon_type in NOISY_LOGON_TYPES:
            return None
        return {
            "entity_name": ENTITY_NAME,
            "event_type": "login",
            "status": "success" if event_id == 4624 else "fail",
            "source_ip": ip,
            "resource": workstation,
        }
    if event_id == 4634:
        return {
            "entity_name": ENTITY_NAME, "event_type": "logoff", "status": "success",
            "source_ip": ip, "resource": workstation,
        }
    if event_id == 4648:
        return {
            "entity_name": ENTITY_NAME, "event_type": "login", "status": "success",
            "source_ip": ip, "resource": data.get("TargetServerName"),
        }
    if event_id == 4672:
        return {
            "entity_name": ENTITY_NAME, "event_type": "privileged_logon", "status": "success",
            "source_ip": ip, "resource": workstation,
        }
    if event_id == 4720:
        return {
            "entity_name": ENTITY_NAME, "event_type": "account_created", "status": "success",
            "source_ip": None, "resource": None,
        }
    return None


def _normalize_timestamp(time_created: str) -> str:
    """Windows TimeCreated SystemTime uses up to 7 fractional-second digits
    (100-nanosecond ticks), e.g. '...123456700Z'. Truncate to a standard
    6-digit microsecond precision so downstream JSON/datetime parsing never
    has to guess about an unusual format."""
    return re.sub(r'(\.\d{6})\d+Z$', r'\1Z', time_created)


def post_event(api_url: str, mapped: dict, event_time_iso: str, raw: dict, api_key: str = None) -> dict:
    payload = {
        "entity_name": mapped["entity_name"],
        "entity_type": "user",
        "event_type": mapped["event_type"],
        "status": mapped["status"],
        "event_time": _normalize_timestamp(event_time_iso),
        "source_ip": mapped.get("source_ip"),
        "resource": mapped.get("resource"),
        "raw": raw,
    }
    headers = {"X-Collector-Key": api_key} if api_key else {}
    resp = requests.post(f"{api_url}/events", json=payload, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def load_checkpoint(path: str):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None


def save_checkpoint(path: str, record_id: int, time_iso: str):
    with open(path, "w") as f:
        json.dump({"last_record_id": record_id, "last_time": time_iso}, f)


def run_once(args, state: dict):
    events = fetch_security_events(state["start_time"], state["last_record_id"])
    processed = 0
    for xml_text in events:
        try:
            event_id, record_id, time_created, data = parse_event_xml(xml_text)
        except ET.ParseError:
            continue

        mapped = map_event(event_id, data)
        if mapped:
            try:
                result = post_event(args.api_url, mapped, time_created, {"windows_event_id": event_id, **data}, args.api_key)
                for a in result.get("anomalies_detected", []):
                    print(f"  !! ANOMALY [{a['severity']}] {mapped['entity_name']}: "
                          f"{a['rule_name']} -- {a['description']}")
                processed += 1
            except requests.RequestException as e:
                print(f"  Failed to POST event (record {record_id}): {e}", file=sys.stderr)

        if record_id > state["last_record_id"]:
            state["last_record_id"] = record_id
            state["start_time"] = time_created

    if processed:
        print(f"[{datetime.now().isoformat(timespec='seconds')}] "
              f"processed {processed} event(s), checkpoint at record {state['last_record_id']}")
    return state


def parse_args():
    p = argparse.ArgumentParser(description="Windows Security Event Log -> UEBA collector")
    p.add_argument("--api-url", default=os.environ.get("UEBA_API_URL", "http://localhost:8000"))
    p.add_argument("--api-key", default=os.environ.get("COLLECTOR_API_KEY"),
                   help="Shared secret sent as the X-Collector-Key header. Required if the "
                        "API has COLLECTOR_API_KEY set (e.g. when hosted publicly); leave unset "
                        "for a local/trusted deployment with no key configured.")
    p.add_argument("--interval", type=int, default=15, help="Seconds between polls")
    p.add_argument("--lookback-minutes", type=int, default=60,
                   help="How far back to look on the very first run (no checkpoint yet)")
    p.add_argument("--checkpoint-file", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "collector_checkpoint.json"))
    p.add_argument("--entity-name", default=None,
                   help="Single entity name every event from this machine is attributed to "
                        "(default: the COMPUTERNAME environment variable)")
    p.add_argument("--once", action="store_true", help="Run a single poll and exit (for testing)")
    return p.parse_args()


def main():
    global ENTITY_NAME
    args = parse_args()
    ENTITY_NAME = args.entity_name or os.environ.get("COMPUTERNAME") or "unknown-computer"

    checkpoint = load_checkpoint(args.checkpoint_file)
    if checkpoint:
        state = {"last_record_id": checkpoint["last_record_id"], "start_time": checkpoint["last_time"]}
    else:
        start = datetime.now(timezone.utc) - timedelta(minutes=args.lookback_minutes)
        state = {"last_record_id": 0, "start_time": start.isoformat()}

    print(f"UEBA Windows collector starting. Entity={ENTITY_NAME} API={args.api_url} "
          f"interval={args.interval}s checkpoint_file={args.checkpoint_file}")

    while True:
        try:
            state = run_once(args, state)
            save_checkpoint(args.checkpoint_file, state["last_record_id"], state["start_time"])
        except PermissionError as e:
            print(str(e), file=sys.stderr)
        except Exception as e:
            print(f"Collector error: {e}", file=sys.stderr)

        if args.once:
            break
        time_module.sleep(args.interval)


if __name__ == "__main__":
    main()
