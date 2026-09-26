"""
Demo / smoke-test script for the UEBA system.

Creates a couple of entities, configures adjustable thresholds/working hours
(global + one per-entity override), feeds in a mix of normal and anomalous
events, and prints out what got detected.

Usage:
    python seed_demo.py
"""
import random
from datetime import datetime, timedelta, time
from zoneinfo import ZoneInfo

import psycopg2.extras

import db
import config as config_module
import engine


def get_or_create_entity(cur, name, entity_type="user", department=None):
    cur.execute("SELECT * FROM entities WHERE name = %s", (name,))
    row = cur.fetchone()
    if row:
        return dict(row)
    cur.execute(
        "INSERT INTO entities (name, entity_type, department) VALUES (%s, %s, %s) RETURNING *",
        (name, entity_type, department),
    )
    return dict(cur.fetchone())


def insert_event(cur, **kwargs):
    columns = list(kwargs.keys())
    values = [kwargs[c] for c in columns]
    placeholders = ", ".join(["%s"] * len(columns))
    cur.execute(
        f"INSERT INTO events ({', '.join(columns)}) VALUES ({placeholders}) RETURNING *",
        values,
    )
    return dict(cur.fetchone())


def main():
    db.init_pool()
    with db.get_cursor() as (conn, cur):
        # --- 1. Set global defaults: standard 9-5, Mon-Fri, GMT ---------------
        config_module.update_config(
            cur, None,
            {
                "timezone": "GMT",
                "work_start": time(9, 0),
                "work_end": time(18, 0),
                "work_days": [0, 1, 2, 3, 4],
                "failed_login_low_threshold": 5,
                "failed_login_medium_threshold": 8,
                "failed_login_high_threshold": 12,
                "failed_login_critical_threshold": 20,
                "data_transfer_low_mb": 200,
                "data_transfer_medium_mb": 500,
                "data_transfer_high_mb": 1000,
                "data_transfer_critical_mb": 2000,
                "data_transfer_window_minutes": 60,
            },
            changed_by="seed_demo",
        )

        # --- 2. Create entities ------------------------------------------------
        alice = get_or_create_entity(cur, "alice", "user", "finance")
        bob = get_or_create_entity(cur, "bob", "user", "engineering")
        print(f"Entities: alice={alice['id']}, bob={bob['id']}")

        # Bob works a night-shift, so give him a per-entity override for working hours.
        config_module.update_config(
            cur, bob["id"],
            {
                "timezone": "GMT",
                "work_start": time(22, 0),
                "work_end": time(6, 0),  # note: crosses midnight -- see README caveat
                "work_days": [0, 1, 2, 3, 4, 5, 6],
                "failed_login_low_threshold": 8,  # bob's team tolerates a few more retries
            },
            changed_by="seed_demo",
        )

        base_time = datetime.now(ZoneInfo("GMT")).replace(hour=10, minute=0, second=0, microsecond=0)

        print("\n--- Seeding normal baseline activity for alice ---")
        for i in range(10):
            ev = insert_event(
                cur,
                entity_id=alice["id"], event_type="file_access", status="success",
                event_time=base_time - timedelta(days=10 - i, hours=random.randint(0, 2)),
                resource="reports/monthly_summary.xlsx",
                bytes_transferred=random.randint(1_000_000, 5_000_000),  # ~1-5MB, normal
                geo_lat=40.7128, geo_lon=-74.0060, geo_city="New York", geo_country="US",
            )
            engine.process_event(cur, ev)

        print("--- Event 1: normal daytime login for alice (should be clean) ---")
        ev = insert_event(
            cur, entity_id=alice["id"], event_type="login", status="success",
            event_time=base_time, geo_lat=40.7128, geo_lon=-74.0060,
            geo_city="New York", geo_country="US",
        )
        findings = engine.process_event(cur, ev)
        print(f"  -> anomalies: {[f['rule_name'] for f in findings]}")

        print("--- Event 2: alice logs in at 3 AM (off-hours) ---")
        ev = insert_event(
            cur, entity_id=alice["id"], event_type="login", status="success",
            event_time=base_time.replace(hour=3), geo_lat=40.7128, geo_lon=-74.0060,
            geo_city="New York", geo_country="US",
        )
        findings = engine.process_event(cur, ev)
        print(f"  -> anomalies: {[f['rule_name'] for f in findings]}")
        for f in findings:
            print(f"     [{f['severity']}] {f['description']}")

        print("--- Event 3: 6 failed logins in a row for alice ---")
        findings = []
        for i in range(6):
            ev = insert_event(
                cur, entity_id=alice["id"], event_type="login", status="fail",
                event_time=base_time + timedelta(minutes=i),
                geo_lat=40.7128, geo_lon=-74.0060, geo_city="New York", geo_country="US",
            )
            findings = engine.process_event(cur, ev)
        print(f"  -> anomalies on final attempt: {[f['rule_name'] for f in findings]}")
        for f in findings:
            print(f"     [{f['severity']}] {f['description']}")

        print("--- Event 4: alice downloads 500MB across 87 files (data exfiltration) ---")
        ev = insert_event(
            cur, entity_id=alice["id"], event_type="data_transfer", status="success",
            event_time=base_time + timedelta(hours=1),
            bytes_transferred=500 * 1024 * 1024, file_count=87,
            geo_lat=40.7128, geo_lon=-74.0060, geo_city="New York", geo_country="US",
        )
        findings = engine.process_event(cur, ev)
        print(f"  -> anomalies: {[f['rule_name'] for f in findings]}")
        for f in findings:
            print(f"     [{f['severity']}] {f['description']}")

        print("--- Event 6: bob logs in at 11 PM (within his adjusted night-shift hours, should be clean) ---")
        ev = insert_event(
            cur, entity_id=bob["id"], event_type="login", status="success",
            event_time=base_time.replace(hour=23), geo_lat=51.5072, geo_lon=-0.1276,
            geo_city="London", geo_country="GB",
        )
        findings = engine.process_event(cur, ev)
        print(f"  -> anomalies: {[f['rule_name'] for f in findings]}")

        print("\n--- Summary: all open anomalies ---")
        cur.execute(
            """
            SELECT a.id, e.name AS entity, a.rule_name, a.severity, a.score, a.description
            FROM anomalies a JOIN entities e ON e.id = a.entity_id
            WHERE a.status = 'open'
            ORDER BY a.detected_at
            """
        )
        for row in cur.fetchall():
            print(f"  #{row['id']} [{row['severity']:>8}] {row['entity']}: {row['rule_name']} "
                  f"(score={row['score']}) - {row['description']}")


if __name__ == "__main__":
    main()
