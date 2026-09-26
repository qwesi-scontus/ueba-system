"""
Browser history -> UEBA social media activity tracker.

Reads Chrome, Edge, and Firefox browsing history for visits to known
social media domains and reports them to the UEBA API as
event_type="social_media_access" events -- one event per continuous
*reading session* on a site, not one per history row (see
SESSION_GAP_SECONDS), so a burst of redirects or a long scroll session
shows up as a single dashboard entry with a start time, an end time, and
a duration, instead of dozens of near-duplicate rows. These are
deliberately NOT anomaly-generating -- they're for visibility only
("Social Media" dashboard tab), flagged with whether they happened during
the entity's configured working hours, using the exact same in/out-of-hours
logic the off-hours detector uses.

Does not require elevation (unlike windows_event_collector.py) -- browser
history files are readable by the owning user account.

Usage:
    python browser_history_monitor.py
    python browser_history_monitor.py --api-url http://localhost:8000 --interval 60
    python browser_history_monitor.py --entity-name micha   # keep in sync with
                                                              # windows_event_collector.py's
                                                              # --entity-name if you're
                                                              # using that, so both report
                                                              # under the same laptop entity
    python browser_history_monitor.py --once            # single poll, for testing
"""
import argparse
import glob
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time as time_module
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

# Not exhaustive -- add to this list if you want to track additional sites.
# Matching is by domain suffix (see _matches_social_media), so adding
# "example.com" here also catches "www.example.com", "m.example.com", etc.
SOCIAL_MEDIA_DOMAINS = {
    "facebook.com", "instagram.com", "twitter.com", "x.com", "tiktok.com",
    "snapchat.com", "reddit.com", "linkedin.com", "pinterest.com",
    "whatsapp.com", "telegram.org",
    "discord.com", "tumblr.com", "threads.net", "youtube.com",
}

CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01 (Chrome/WebKit epoch)

# Browser history stores one row per *navigation*, not one row per "visit"
# in the everyday sense -- a single TikTok tab can generate a burst of rows
# at the same instant (redirects, client-side route changes), and simply
# scrolling a feed keeps appending rows. If the gap since the last visit to
# the SAME domain is under this many seconds, we treat it as a continuation
# of one ongoing "reading session" rather than a separate visit -- that's
# what collapses those bursts into a single dashboard row with one start
# time and one end time, instead of dozens of near-identical rows.
SESSION_GAP_SECONDS = 300

# Firefox's places.sqlite doesn't record a per-visit duration the way
# Chromium does, so we approximate it as the gap until the browser's next
# visit (see fetch_firefox_visits). Cap that gap here -- a tab left open in
# the background for hours isn't "time spent on social media".
FIREFOX_MAX_DWELL_SECONDS = 1800

ENTITY_NAME = None  # set once at startup in main(), from --entity-name or COMPUTERNAME


def _matches_social_media(url: str):
    """Returns the matched domain (e.g. 'facebook.com') if url's host is a
    social media site, else None. Matches by suffix so subdomains count."""
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return None
    host = host.split("@")[-1].split(":")[0]  # strip any userinfo/port
    if host.startswith("www."):
        host = host[4:]
    for domain in SOCIAL_MEDIA_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return domain
    return None


def _chrome_time_to_iso(chrome_micros: int) -> str:
    unix_seconds = (chrome_micros / 1_000_000) - CHROME_EPOCH_OFFSET
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).isoformat()


def _firefox_time_to_iso(ff_micros: int) -> str:
    return datetime.fromtimestamp(ff_micros / 1_000_000, tz=timezone.utc).isoformat()


def _copy_and_open_readonly(db_path: str):
    """Chrome/Edge/Firefox keep their history DB open (and often locked)
    while running. Copying to a temp file first sidesteps any lock
    contention entirely, rather than trying to open the live file directly."""
    if not os.path.exists(db_path):
        return None
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".sqlite")
    os.close(tmp_fd)
    try:
        shutil.copy2(db_path, tmp_path)
        # Chromium/Firefox may also have -wal/-shm sidecar files with
        # not-yet-checkpointed data; copy those too if present, so recent
        # visits aren't missed.
        for suffix in ("-wal", "-shm"):
            side = db_path + suffix
            if os.path.exists(side):
                try:
                    shutil.copy2(side, tmp_path + suffix)
                except OSError:
                    pass  # best-effort; the main copy is enough to work with
        return tmp_path
    except OSError as e:
        print(f"Could not copy {db_path}: {e}", file=sys.stderr)
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return None


def _chromium_profiles(user_data_dir: str):
    """Yields every profile directory under a Chromium user-data dir that
    has a History file -- "Default" plus any "Profile N" folders."""
    if not os.path.isdir(user_data_dir):
        return
    for name in ["Default"] + sorted(glob.glob1(user_data_dir, "Profile *")):
        history_path = os.path.join(user_data_dir, name, "History")
        if os.path.exists(history_path):
            yield history_path


def fetch_chromium_visits(user_data_dir: str, since_iso: str):
    """Chrome/Edge share the same SQLite schema. Returns a list of
    (url, visit_time_iso, duration_seconds) tuples for visits after
    since_iso. Chromium tracks how long each visit stayed the active tab in
    visits.visit_duration (microseconds), so we use that directly -- no
    approximation needed here, unlike Firefox below."""
    results = []
    since_dt = datetime.fromisoformat(since_iso)
    since_chrome = int((since_dt.timestamp() + CHROME_EPOCH_OFFSET) * 1_000_000)

    for history_path in _chromium_profiles(user_data_dir):
        tmp_path = _copy_and_open_readonly(history_path)
        if not tmp_path:
            continue
        try:
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cur = conn.cursor()
            cur.execute(
                """
                SELECT urls.url, visits.visit_time, visits.visit_duration
                FROM visits
                JOIN urls ON visits.url = urls.id
                WHERE visits.visit_time > ?
                ORDER BY visits.visit_time ASC
                """,
                (since_chrome,),
            )
            for url, visit_time, visit_duration in cur.fetchall():
                # visit_duration is 0 both for genuinely instantaneous visits
                # and for visits Chromium never got a chance to time (e.g.
                # the tab is still open); we can't tell those apart, so treat
                # 0 as "unknown" rather than claiming a 0-second visit.
                duration_seconds = int(visit_duration / 1_000_000) if visit_duration else None
                results.append((url, _chrome_time_to_iso(visit_time), duration_seconds))
            conn.close()
        except sqlite3.Error as e:
            print(f"Could not read {history_path}: {e}", file=sys.stderr)
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(tmp_path + suffix)
                except OSError:
                    pass
    return results


def _firefox_profile_dirs():
    profiles_root = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if not os.path.isdir(profiles_root):
        return []
    return glob.glob(os.path.join(profiles_root, "*.default-release")) + \
        glob.glob(os.path.join(profiles_root, "*.default"))


def fetch_firefox_visits(since_iso: str):
    """Returns a list of (url, visit_time_iso, duration_seconds) tuples for
    visits after since_iso.

    Unlike Chromium, Firefox's places.sqlite has no per-visit duration
    column at all, so we approximate dwell time as the gap until the
    browser's NEXT visit (any site, not just social media) -- i.e. how long
    this page stayed the active tab before the user navigated elsewhere.
    That gap is capped at FIREFOX_MAX_DWELL_SECONDS since a tab left open in
    the background for a long time isn't real "time spent" on it. The most
    recent visit in the batch has no "next" visit yet, so its duration is
    left unknown (None) -- a later poll, once something follows it, is the
    first point at which we could compute it, but by then it's already been
    reported, so it simply stays unknown."""
    results = []
    since_dt = datetime.fromisoformat(since_iso)
    since_ff = int(since_dt.timestamp() * 1_000_000)

    for profile_dir in _firefox_profile_dirs():
        places_path = os.path.join(profile_dir, "places.sqlite")
        tmp_path = _copy_and_open_readonly(places_path)
        if not tmp_path:
            continue
        visit_rows = []
        try:
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            cur = conn.cursor()
            cur.execute(
                """
                SELECT moz_places.url, moz_historyvisits.visit_date
                FROM moz_historyvisits
                JOIN moz_places ON moz_historyvisits.place_id = moz_places.id
                WHERE moz_historyvisits.visit_date > ?
                ORDER BY moz_historyvisits.visit_date ASC
                """,
                (since_ff,),
            )
            visit_rows = cur.fetchall()
            conn.close()
        except sqlite3.Error as e:
            print(f"Could not read {places_path}: {e}", file=sys.stderr)
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(tmp_path + suffix)
                except OSError:
                    pass

        for i, (url, visit_date) in enumerate(visit_rows):
            if i + 1 < len(visit_rows):
                gap_micros = visit_rows[i + 1][1] - visit_date
                duration_seconds = min(int(gap_micros / 1_000_000), FIREFOX_MAX_DWELL_SECONDS)
            else:
                duration_seconds = None
            results.append((url, _firefox_time_to_iso(visit_date), duration_seconds))
    return results


def post_social_media_event(api_url: str, domain: str, start_iso: str, source_browser: str,
                             end_iso: str, duration_seconds=None, api_key: str = None) -> dict:
    payload = {
        "entity_name": ENTITY_NAME,
        "entity_type": "user",
        "event_type": "social_media_access",
        "status": "success",
        "event_time": start_iso,
        "resource": domain,
        # duration_seconds is None only when a session is a single visit
        # whose own dwell time we couldn't determine either (see
        # fetch_chromium_visits/fetch_firefox_visits) -- the dashboard shows
        # that as "--" rather than a misleading 0.
        "raw": {"browser": source_browser, "end_time": end_iso, "duration_seconds": duration_seconds},
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


def save_checkpoint(path: str, state: dict):
    with open(path, "w") as f:
        json.dump(state, f)


def _close_session(api_url: str, browser: str, session: dict, api_key: str = None) -> int:
    """Posts a finished reading session as a single social_media_access
    event spanning session['start'] to session['end']. Returns 1 if it
    posted successfully, 0 if the request failed (the session is dropped
    in that case, same as any other event this collector fails to post)."""
    start_dt = datetime.fromisoformat(session["start"])
    end_dt = datetime.fromisoformat(session["end"])
    span_seconds = int((end_dt - start_dt).total_seconds())
    # A session covering more than one visit has a real, directly-measured
    # span -- that's more reliable than any single visit's own duration
    # hint, so it wins. Only fall back to the hint (which may itself be
    # None) for a session that was ever only a single visit.
    duration_seconds = span_seconds if span_seconds > 0 else session.get("duration_hint")
    try:
        post_social_media_event(api_url, session["domain"], session["start"], browser,
                                 session["end"], duration_seconds, api_key)
        return 1
    except requests.RequestException as e:
        print(f"Failed to post event: {e}", file=sys.stderr)
        return 0


def _process_visits(api_url: str, browser: str, visits: list, session, api_key: str = None):
    """Walks one browser's chronological visits, extending or closing the
    passed-in in-progress session (a dict, or None if there isn't one) as
    it goes. Returns (session_at_end_of_this_batch, sessions_posted)."""
    posted = 0
    for url, visit_time_iso, own_duration in visits:
        domain = _matches_social_media(url)
        if domain is None:
            # Visiting something else breaks continuity for any
            # in-progress social media session on this browser.
            if session is not None:
                posted += _close_session(api_url, browser, session, api_key)
                session = None
            continue

        # A visit's own end is its arrival time plus its own dwell time,
        # when known -- not just its arrival timestamp, which would
        # otherwise collapse start and end to the same instant even for a
        # visit Chrome recorded as open for hours.
        if own_duration is not None:
            visit_end_iso = (datetime.fromisoformat(visit_time_iso) +
                              timedelta(seconds=own_duration)).isoformat()
        else:
            visit_end_iso = visit_time_iso

        if session is not None and session["domain"] == domain and (
                datetime.fromisoformat(visit_time_iso) - datetime.fromisoformat(session["end"])
        ).total_seconds() <= SESSION_GAP_SECONDS:
            session["end"] = visit_end_iso
            if own_duration is not None:
                session["duration_hint"] = own_duration
        else:
            if session is not None:
                posted += _close_session(api_url, browser, session, api_key)
            session = {"domain": domain, "start": visit_time_iso, "end": visit_end_iso,
                       "duration_hint": own_duration}
    return session, posted


def run_once(args, state: dict) -> dict:
    localappdata = os.environ.get("LOCALAPPDATA", "")
    sources = {
        "chrome": (fetch_chromium_visits, os.path.join(localappdata, "Google", "Chrome", "User Data")),
        "edge": (fetch_chromium_visits, os.path.join(localappdata, "Microsoft", "Edge", "User Data")),
    }

    processed = 0
    new_state = dict(state)
    open_sessions = dict(state.get("open_sessions", {}))

    for browser, (fetch_fn, user_data_dir) in sources.items():
        since_iso = state.get(browser, state["default_since"])
        visits = fetch_fn(user_data_dir, since_iso)
        # Checkpoint advances past every visit seen (not just social media
        # ones) -- we need the non-social ones too, every poll, to correctly
        # notice when a session has been interrupted by browsing elsewhere.
        latest = max([since_iso] + [v[1] for v in visits]) if visits else since_iso
        session, posted = _process_visits(args.api_url, browser, visits, open_sessions.get(browser), args.api_key)
        open_sessions[browser] = session
        processed += posted
        new_state[browser] = latest

    # Firefox has a different profile-discovery/query path, but the same
    # checkpoint pattern.
    since_iso = state.get("firefox", state["default_since"])
    visits = fetch_firefox_visits(since_iso)
    latest = max([since_iso] + [v[1] for v in visits]) if visits else since_iso
    session, posted = _process_visits(args.api_url, "firefox", visits, open_sessions.get("firefox"), args.api_key)
    open_sessions["firefox"] = session
    processed += posted
    new_state["firefox"] = latest

    # Flush any session that's gone quiet for longer than the gap window,
    # even without a later visit to close it out -- otherwise a session
    # right before the laptop is closed for the day would sit "open"
    # forever and never reach the dashboard.
    now = datetime.now(timezone.utc)
    for browser, session in list(open_sessions.items()):
        if session is None:
            continue
        idle_seconds = (now - datetime.fromisoformat(session["end"])).total_seconds()
        if idle_seconds > SESSION_GAP_SECONDS:
            processed += _close_session(args.api_url, browser, session, args.api_key)
            open_sessions[browser] = None

    new_state["open_sessions"] = open_sessions

    if processed:
        print(f"[{datetime.now().isoformat(timespec='seconds')}] posted {processed} social media session(s)")

    return new_state


def parse_args():
    p = argparse.ArgumentParser(description="Browser history -> UEBA social media tracker")
    p.add_argument("--api-url", default=os.environ.get("UEBA_API_URL", "http://localhost:8000"))
    p.add_argument("--api-key", default=os.environ.get("COLLECTOR_API_KEY"),
                   help="Shared secret sent as the X-Collector-Key header. Required if the "
                        "API has COLLECTOR_API_KEY set (e.g. when hosted publicly); leave unset "
                        "for a local/trusted deployment with no key configured.")
    p.add_argument("--interval", type=int, default=60, help="Seconds between polls")
    p.add_argument("--checkpoint-file", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "browser_history_checkpoint.json"))
    p.add_argument("--entity-name", default=None,
                   help="Entity name to attribute visits to -- keep this the same as "
                        "windows_event_collector.py's --entity-name if you run both, "
                        "so everything from this laptop lands on one entity "
                        "(default: the COMPUTERNAME environment variable)")
    p.add_argument("--once", action="store_true", help="Run a single poll and exit (for testing)")
    return p.parse_args()


def main():
    global ENTITY_NAME
    args = parse_args()
    ENTITY_NAME = args.entity_name or os.environ.get("COMPUTERNAME") or "unknown-computer"

    checkpoint = load_checkpoint(args.checkpoint_file)
    if checkpoint:
        state = checkpoint
    else:
        # First run: only look back 1 hour, not all history -- otherwise
        # the first poll could try to report years of browsing at once.
        default_since = datetime.now(timezone.utc).isoformat()
        state = {"default_since": default_since}

    print(f"UEBA browser history monitor starting. Entity={ENTITY_NAME} API={args.api_url} "
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
