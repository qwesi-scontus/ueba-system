"""
Pluggable anomaly detectors for the UEBA engine.

Every detector has the signature:
    detect(cur, entity_id, event, cfg) -> Optional[dict]

`event` is a dict-row from the `events` table.
`cfg` is the *effective* entity_config dict (defaults merged with any
per-entity override) -- this is where all the adjustable thresholds and
working-hours settings come from.

A detector returns None if nothing anomalous was found, or a dict describing
the anomaly:
    {
        "rule_name": str,
        "severity": str,
        "score": float,
        "description": str,
        "details": dict,
    }
"""
from datetime import timedelta, datetime, time as dt_time
from zoneinfo import ZoneInfo

# Matches the 0=Monday..6=Sunday convention used throughout entity_config.work_days.
WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# Fixed cooldown for duplicate-alert suppression across all detectors. This
# used to be a per-entity configurable field (anomaly_cooldown_minutes), but
# since it wasn't specific to any one detector -- every detector relied on
# it, including the ones still active -- it's now a plain constant so the
# database column could be removed without breaking anything.
DEFAULT_COOLDOWN_MINUTES = 30


def _day_names(day_numbers):
    """Converts a list of weekday integers (0=Mon..6=Sun) into a readable,
    Monday-first, comma-separated list of day names."""
    return ", ".join(WEEKDAY_NAMES[d] for d in sorted(day_numbers) if 0 <= d <= 6)


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _in_cooldown(cur, entity_id, rule_name, cooldown_minutes, new_severity=None):
    """Suppress duplicate alerts for the same rule/entity within the
    configured cooldown window -- UNLESS the situation has escalated to a
    higher severity than the most recent alert of this rule, in which case
    it's let through immediately regardless of cooldown. Without this, a
    "low" alert could silently block a "critical" one from the same rule
    for the rest of the cooldown window."""
    if cooldown_minutes <= 0:
        return False
    cur.execute(
        """
        SELECT severity FROM anomalies
        WHERE entity_id = %s AND rule_name = %s
          AND detected_at > now() - (%s * interval '1 minute')
        ORDER BY detected_at DESC LIMIT 1
        """,
        (entity_id, rule_name, cooldown_minutes),
    )
    row = cur.fetchone()
    if row is None:
        return False
    if new_severity is not None:
        prior_rank = _SEVERITY_RANK.get(row["severity"], 0)
        new_rank = _SEVERITY_RANK.get(new_severity, 0)
        if new_rank > prior_rank:
            return False  # escalated -- don't suppress
    return True


def _tier_severity(value, low, medium, high, critical):
    """Graduated severity: returns the highest tier the value has reached,
    or None if it's below the low tier entirely (meaning no anomaly at
    all -- the low threshold doubles as "is this worth flagging?")."""
    value = float(value)
    if value >= float(critical):
        return "critical"
    if value >= float(high):
        return "high"
    if value >= float(medium):
        return "medium"
    if value >= float(low):
        return "low"
    return None


def is_within_work_hours(event_time, cfg) -> bool:
    """Shared logic: is the given event_time within the entity's
    configured work_start/work_end/work_days/timezone? Used by both the
    off-hours detector and anything that just needs to classify a moment
    as in/out of hours without raising an anomaly (e.g. social media
    activity tracking)."""
    tz = ZoneInfo(cfg.get("timezone") or "Africa/Accra")
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=ZoneInfo("GMT"))
    local_time = event_time.astimezone(tz)

    work_days = cfg.get("work_days") or [0, 1, 2, 3, 4]
    work_start: dt_time = cfg["work_start"]
    work_end: dt_time = cfg["work_end"]

    weekday = local_time.weekday()  # Monday=0 .. Sunday=6
    local_clock = local_time.time()

    if work_start <= work_end:
        is_work_time = work_start <= local_clock <= work_end
        is_work_day = weekday in work_days
    else:
        if local_clock >= work_start:
            is_work_time = True
            is_work_day = weekday in work_days
        elif local_clock <= work_end:
            is_work_time = True
            prev_weekday = (weekday - 1) % 7
            is_work_day = prev_weekday in work_days
        else:
            is_work_time = False
            is_work_day = weekday in work_days

    return is_work_day and is_work_time


# ---------------------------------------------------------------------------
# 1. Off-hours access: event happens outside the entity's configured working
#    hours / working days.
# ---------------------------------------------------------------------------
def detect_off_hours(cur, entity_id, event, cfg):
    if not cfg.get("off_hours_enabled", True):
        return None
    if event["event_type"] != "login":
        return None  # scoped to logins only, not every event type

    if is_within_work_hours(event["event_time"], cfg):
        return None

    tz = ZoneInfo(cfg.get("timezone") or "Africa/Accra")
    event_time = event["event_time"]
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=ZoneInfo("GMT"))
    local_time = event_time.astimezone(tz)

    work_days = cfg.get("work_days") or [0, 1, 2, 3, 4]
    work_start: dt_time = cfg["work_start"]
    work_end: dt_time = cfg["work_end"]

    weekday = local_time.weekday()  # Monday=0 .. Sunday=6
    local_clock = local_time.time()

    # Recompute is_work_day specifically (not just in/out of hours overall)
    # for the day-penalty below -- for an overnight shift, "today" means
    # the day the shift started on, which can be yesterday if we're in the
    # early-morning portion of it.
    if work_start <= work_end:
        is_work_day = weekday in work_days
    else:
        if local_clock >= work_start:
            is_work_day = weekday in work_days
        elif local_clock <= work_end:
            is_work_day = (weekday - 1) % 7 in work_days
        else:
            is_work_day = weekday in work_days

    # How far outside the schedule is this, in hours? Time-of-day distance
    # from the nearest edge of the work window, plus a fixed penalty added
    # if it's on a non-work day at all (so a Saturday afternoon login still
    # reads as meaningfully off-schedule even though the clock time alone
    # might look unremarkable).
    def _hours(t: dt_time) -> float:
        return t.hour + t.minute / 60 + t.second / 3600

    current_hours = _hours(local_clock)
    start_hours = _hours(work_start)
    end_hours = _hours(work_end)

    if work_start <= work_end:
        if current_hours < start_hours:
            time_deviation = start_hours - current_hours
        elif current_hours > end_hours:
            time_deviation = current_hours - end_hours
        else:
            time_deviation = 0.0
    else:
        # Overnight window: already confirmed outside it above, so the
        # deviation is the smaller of the two gaps to either edge.
        time_deviation = min(abs(current_hours - start_hours), abs(current_hours - end_hours))

    day_penalty = 0.0 if is_work_day else 12.0
    deviation_hours = time_deviation + day_penalty

    severity = _tier_severity(
        deviation_hours,
        cfg.get("off_hours_low_hours", 0),
        cfg.get("off_hours_medium_hours", 2),
        cfg.get("off_hours_high_hours", 4),
        cfg.get("off_hours_critical_hours", 8),
    )
    if severity is None:
        return None

    if _in_cooldown(cur, entity_id, "off_hours_access", DEFAULT_COOLDOWN_MINUTES, severity):
        return None

    return {
        "rule_name": "off_hours_access",
        "severity": severity,
        "score": min(30 + deviation_hours * 5, 95),
        "description": (
            f"Activity observed on {local_time.strftime('%A, %d %B %Y at %H:%M')} "
            f"({cfg.get('timezone', 'Africa/Accra')}), outside the configured working hours of "
            f"{work_start.strftime('%H:%M')}-{work_end.strftime('%H:%M')} on "
            f"{_day_names(work_days)} ({deviation_hours:.1f} hour(s) outside schedule)."
        ),
        "details": {
            "local_time": local_time.isoformat(),
            "weekday": weekday,
            "work_days": work_days,
            "work_start": str(work_start),
            "work_end": str(work_end),
            "deviation_hours": round(deviation_hours, 2),
        },
    }


# ---------------------------------------------------------------------------
# 2. Excessive failed logins -- counted as consecutive failures since the
#    entity's last successful login, with no time window at all. Detects
#    immediately the moment the count crosses a threshold, however long
#    that takes to happen.
# ---------------------------------------------------------------------------
def detect_failed_logins(cur, entity_id, event, cfg):
    if not cfg.get("failed_login_enabled", True):
        return None
    if event["event_type"] != "login" or event["status"] != "fail":
        return None

    low = cfg["failed_login_low_threshold"]
    medium = cfg["failed_login_medium_threshold"]
    high = cfg["failed_login_high_threshold"]
    critical = cfg["failed_login_critical_threshold"]

    # Count fails back-to-back from this event, stopping as soon as we hit
    # this entity's most recent successful login (or the start of their
    # history, if they've never succeeded at all).
    cur.execute(
        """
        WITH last_success AS (
            SELECT event_time FROM events
            WHERE entity_id = %s AND event_type = 'login' AND status = 'success'
              AND event_time <= %s
            ORDER BY event_time DESC LIMIT 1
        )
        SELECT count(*) AS cnt FROM events
        WHERE entity_id = %s AND event_type = 'login' AND status = 'fail'
          AND event_time <= %s
          AND event_time > COALESCE((SELECT event_time FROM last_success), '-infinity'::timestamptz)
        """,
        (entity_id, event["event_time"], entity_id, event["event_time"]),
    )
    count = cur.fetchone()["cnt"]

    severity = _tier_severity(count, low, medium, high, critical)
    if severity is None:
        return None

    if _in_cooldown(cur, entity_id, "excessive_failed_logins", DEFAULT_COOLDOWN_MINUTES, severity):
        return None

    return {
        "rule_name": "excessive_failed_logins",
        "severity": severity,
        "score": min(30 + count * 3, 95),
        "description": (
            f"{count} consecutive failed login(s) since the last successful login "
            f"(severity thresholds: low={low}, medium={medium}, high={high}, critical={critical})"
        ),
        "details": {
            "consecutive_failed_count": count,
            "low_threshold": low, "medium_threshold": medium,
            "high_threshold": high, "critical_threshold": critical,
        },
    }


# ---------------------------------------------------------------------------
# 3. Data transfer / exfiltration volume within a rolling window.
# ---------------------------------------------------------------------------
def detect_data_transfer(cur, entity_id, event, cfg):
    if not cfg.get("data_transfer_enabled", True):
        return None
    if not event.get("bytes_transferred"):
        return None

    window_minutes = cfg["data_transfer_window_minutes"]
    low = float(cfg["data_transfer_low_mb"])
    medium = float(cfg["data_transfer_medium_mb"])
    high = float(cfg["data_transfer_high_mb"])
    critical = float(cfg["data_transfer_critical_mb"])

    cur.execute(
        """
        SELECT COALESCE(sum(bytes_transferred), 0) AS total_bytes,
               COALESCE(sum(file_count), 0) AS total_files
        FROM events
        WHERE entity_id = %s
          AND event_time > %s - (%s * interval '1 minute')
          AND event_time <= %s
        """,
        (entity_id, event["event_time"], window_minutes, event["event_time"]),
    )
    row = cur.fetchone()
    total_bytes = row["total_bytes"]
    total_files = row["total_files"]
    total_mb = total_bytes / (1024 * 1024)

    severity = _tier_severity(total_mb, low, medium, high, critical)
    if severity is None:
        return None

    if _in_cooldown(cur, entity_id, "excessive_data_transfer", DEFAULT_COOLDOWN_MINUTES, severity):
        return None

    file_note = f" across {total_files} file(s)" if total_files else ""
    return {
        "rule_name": "excessive_data_transfer",
        "severity": severity,
        "score": min(30 + total_mb / 20, 95),
        "description": (
            f"{total_mb:.1f} MB{file_note} transferred within {window_minutes} minute(s) "
            f"(severity thresholds: low={low}MB, medium={medium}MB, high={high}MB, critical={critical}MB)"
        ),
        "details": {
            "total_mb": round(total_mb, 2), "total_files": total_files, "window_minutes": window_minutes,
            "low_threshold_mb": low, "medium_threshold_mb": medium,
            "high_threshold_mb": high, "critical_threshold_mb": critical,
        },
    }


# All detectors run, in order, for every ingested event.
ALL_DETECTORS = [
    detect_off_hours,
    detect_failed_logins,
    detect_data_transfer,
]
