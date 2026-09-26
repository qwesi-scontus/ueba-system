"""
The UEBA detection engine: pulls effective config for an entity, runs every
enabled detector against an event, and persists any anomalies found.
"""
from typing import List
import psycopg2.extras
import config as config_module
from detectors import ALL_DETECTORS


def process_event(cur, event: dict) -> List[dict]:
    """Run all detectors for a single event row. Returns the list of
    anomalies raised (each already inserted into the anomalies table)."""
    entity_id = event["entity_id"]
    cfg = config_module.get_effective_config(cur, entity_id)

    findings = []
    for detector in ALL_DETECTORS:
        result = detector(cur, entity_id, event, cfg)
        if result is None:
            continue
        cur.execute(
            """
            INSERT INTO anomalies (entity_id, event_id, rule_name, severity, score, description, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                entity_id,
                event["id"],
                result["rule_name"],
                result["severity"],
                result["score"],
                result["description"],
                psycopg2.extras.Json(result.get("details", {})),
            ),
        )
        findings.append(result)

    cur.execute("UPDATE events SET processed = true WHERE id = %s", (event["id"],))
    return findings


def process_unprocessed(cur, limit: int = 500) -> List[dict]:
    """Batch-process any events not yet run through the engine (e.g. events
    inserted directly into the DB rather than via the ingest API)."""
    cur.execute(
        "SELECT * FROM events WHERE processed = false ORDER BY event_time ASC LIMIT %s",
        (limit,),
    )
    events = cur.fetchall()
    all_findings = []
    for event in events:
        all_findings.extend(process_event(cur, dict(event)))
    return all_findings
