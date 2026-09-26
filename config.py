"""
Configuration management for the UEBA system.

Design:
  - Exactly one "default" row exists in entity_config where entity_id IS NULL.
    It holds the global thresholds / working hours used for any entity that
    doesn't have its own override.
  - An entity can get its own override row (entity_id = <id>). When first
    created, it is seeded from the current default values, then individual
    fields can be adjusted independently per entity.
  - Every field change (default or per-entity) is written to
    config_audit_log for traceability.
"""
from typing import Optional, Dict, Any


def _values_equal(old_value: Any, new_value: Any) -> bool:
    """Compare an existing DB value against an incoming update value,
    tolerating type differences (Decimal vs float, list vs list, etc.)
    so we don't log spurious no-op audit entries."""
    if old_value is None or new_value is None:
        return old_value == new_value
    try:
        return float(old_value) == float(new_value)
    except (TypeError, ValueError):
        pass
    if isinstance(old_value, (list, tuple)) or isinstance(new_value, (list, tuple)):
        return list(old_value) == list(new_value)
    return str(old_value) == str(new_value)

# Fields that are safe to update via the API / adjust at runtime.
EDITABLE_FIELDS = {
    "timezone", "work_start", "work_end", "work_days",
    "off_hours_enabled",
    "off_hours_low_hours", "off_hours_medium_hours", "off_hours_high_hours", "off_hours_critical_hours",
    "failed_login_enabled",
    "failed_login_low_threshold", "failed_login_medium_threshold",
    "failed_login_high_threshold", "failed_login_critical_threshold",
    "data_transfer_window_minutes", "data_transfer_enabled",
    "data_transfer_low_mb", "data_transfer_medium_mb",
    "data_transfer_high_mb", "data_transfer_critical_mb",
    "social_media_block_enabled",
}


def get_default_config(cur) -> dict:
    cur.execute("SELECT * FROM entity_config WHERE entity_id IS NULL LIMIT 1")
    row = cur.fetchone()
    if row is None:
        raise RuntimeError(
            "No default entity_config row found. Did you run schema.sql?"
        )
    return dict(row)


def get_entity_override(cur, entity_id: int) -> Optional[dict]:
    cur.execute("SELECT * FROM entity_config WHERE entity_id = %s", (entity_id,))
    row = cur.fetchone()
    return dict(row) if row else None


def get_effective_config(cur, entity_id: Optional[int]) -> dict:
    """Returns the config that actually applies to this entity: its own
    override if one exists, otherwise the global default."""
    if entity_id is not None:
        override = get_entity_override(cur, entity_id)
        if override is not None:
            return override
    return get_default_config(cur)


def _ensure_override_row(cur, entity_id: int) -> dict:
    """Create an override row for the entity (seeded from defaults) if one
    doesn't already exist yet. Returns the row."""
    existing = get_entity_override(cur, entity_id)
    if existing is not None:
        return existing

    default = get_default_config(cur)
    columns = sorted(EDITABLE_FIELDS)
    values = [default[c] for c in columns]
    placeholders = ", ".join(["%s"] * len(columns))
    col_list = ", ".join(columns)
    cur.execute(
        f"""
        INSERT INTO entity_config (entity_id, {col_list})
        VALUES (%s, {placeholders})
        ON CONFLICT (entity_id) DO NOTHING
        RETURNING *
        """,
        [entity_id] + values,
    )
    row = cur.fetchone()
    if row is None:
        # Someone else inserted concurrently; just fetch it.
        row = get_entity_override(cur, entity_id)
    return dict(row)


def update_config(
    cur,
    entity_id: Optional[int],
    fields: Dict[str, Any],
    changed_by: Optional[str] = None,
) -> dict:
    """Update one or more config fields for either the global default
    (entity_id=None) or a specific entity (creating its override row on
    first write). Logs every changed field to config_audit_log.

    Returns the updated, effective config row.
    """
    unknown = set(fields) - EDITABLE_FIELDS
    if unknown:
        raise ValueError(f"Unknown/non-editable config field(s): {sorted(unknown)}")
    if not fields:
        return get_effective_config(cur, entity_id)

    if entity_id is None:
        current = get_default_config(cur)
        row_key = ("entity_id IS NULL", ())
    else:
        current = _ensure_override_row(cur, entity_id)
        row_key = ("entity_id = %s", (entity_id,))

    set_clauses = []
    set_values = []
    for field, new_value in fields.items():
        old_value = current.get(field)
        if _values_equal(old_value, new_value):
            continue  # no actual change, skip audit noise
        set_clauses.append(f"{field} = %s")
        set_values.append(new_value)
        cur.execute(
            """
            INSERT INTO config_audit_log (entity_id, changed_by, field_name, old_value, new_value)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (entity_id, changed_by, field, str(old_value), str(new_value)),
        )

    if set_clauses:
        set_clauses.append("updated_at = now()")
        set_clauses.append("updated_by = %s")
        set_values.append(changed_by)
        where_sql, where_params = row_key
        cur.execute(
            f"UPDATE entity_config SET {', '.join(set_clauses)} WHERE {where_sql}",
            set_values + list(where_params),
        )

    return get_effective_config(cur, entity_id)


def delete_override(cur, entity_id: int, changed_by: Optional[str] = None) -> None:
    """Remove an entity's override so it reverts to the global default."""
    cur.execute(
        "INSERT INTO config_audit_log (entity_id, changed_by, field_name, old_value, new_value) "
        "VALUES (%s, %s, %s, %s, %s)",
        (entity_id, changed_by, "__override__", "present", "removed"),
    )
    cur.execute("DELETE FROM entity_config WHERE entity_id = %s", (entity_id,))
