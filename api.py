"""
UEBA API

Run with:
    uvicorn api:app --reload --port 8000

Key endpoints:
    POST   /auth/signup              self-register as analyst/employee (always requires admin approval)
    POST   /auth/login                sign in with username or email
    POST   /auth/change-password     change your own password (any logged-in role)
    GET    /users                    list every dashboard login (admin)
    GET    /users/pending            list every account awaiting approval (admin)
    POST   /users/{username}/approve approve a pending account, any role (admin)
    POST   /users/{username}/reset-password  reset one account to the system default password (admin)
    POST   /users/reset-all-passwords        reset EVERY account to the system default password (admin)
    DELETE /users/{username}         permanently delete a login from the database (admin)
    POST   /entities                 create an entity to monitor (admin)
    GET    /entities                 list entities, optional ?department= filter (admin, analyst)
    PATCH  /entities/{id}            edit an entity, restrict/unrestrict, or reassign its unit (admin)
    POST   /entities/{keep}/merge/{dup}  merge a duplicate entity into another, keeping history (admin)
    GET    /entities/merges          list merge history (admin)
    POST   /entities/merges/{id}/unmerge  reverse a specific merge exactly (admin)
    GET    /entities/{id}/linked-users  check for a login tied to this entity before deleting it (admin)
    DELETE /entities/{id}            permanently delete an entity + everything tied to it (admin);
                                      ?also_delete_linked_users=true also deletes any linked login
    POST   /events                   ingest one event (runs detection synchronously, no login needed;
                                      requires X-Collector-Key header if COLLECTOR_API_KEY is set)
    POST   /events/batch             ingest many events at once (no login needed; same X-Collector-Key rule)
    GET    /config/default           view global default thresholds/working hours (admin)
    PUT    /config/default           adjust global default thresholds/working hours (admin)
    GET    /config/{entity_id}       view effective config for an entity (admin)
    PUT    /config/{entity_id}       adjust thresholds/working hours for one entity (admin)
    DELETE /config/{entity_id}       remove entity override (revert to default) (admin)
    GET    /anomalies                list/filter detected anomalies, optional ?department= filter (admin, analyst -- scoped)
    GET    /anomalies/by-entity      anomalies grouped per entity with counts + highest severity (admin, analyst -- scoped)
    GET    /social-media-activity    social media visits, tracked but never flagged as anomalies (admin, analyst -- scoped)
    DELETE /social-media-activity/{ids} permanently delete social media activity record(s), comma-separated ids (admin)
    GET    /social-media-block-status  polled by social_media_blocker.py: should this machine block right now? (no auth)
    GET    /entities/social-media-block-settings  every entity's current blocking setting, for the dashboard toggle list (admin, analyst)
    PATCH  /anomalies/{id}           acknowledge / resolve / mark false positive (admin, analyst -- scoped)
    DELETE /anomalies/{id}           permanently delete an anomaly record (admin)
    POST   /detect/run               batch-process any unprocessed events (admin, analyst)
"""
from typing import Optional, List
from datetime import datetime, timezone
import os
from fastapi import FastAPI, HTTPException, Query, Header, Depends
from fastapi.responses import HTMLResponse
import psycopg2.extras

import db
import config as config_module
import engine
import detectors
import browser_history_monitor
import auth as auth_module
import notifications
from models import (
    EntityCreate, EntityUpdate, EntityOut, EventIn, EventBatchIn,
    AnomalyOut, AnomalyStatusUpdate, ConfigUpdate,
    LoginRequest, SignupRequest, LoginResponse, SignupResponse, PendingUserOut, UserOut,
    ChangePasswordRequest, ResetAllPasswordsRequest, PasswordResetOut,
)

app = FastAPI(title="UEBA System", version="1.0.0")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.on_event("startup")
def _startup():
    db.init_pool()


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    """Simple browser dashboard for viewing/triaging anomalies. Visit
    http://localhost:8000/dashboard while the API is running. The page
    itself is public, but every data call it makes requires login."""
    path = os.path.join(STATIC_DIR, "dashboard.html")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Admin authentication
# ---------------------------------------------------------------------------
def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """FastAPI dependency: validates the 'Authorization: Bearer <token>'
    header and returns {username, role, entity_id, entity_name}. Raises 401
    if missing/invalid/expired."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization[len("Bearer "):]
    with db.get_cursor() as (conn, cur):
        username = auth_module.get_session_username(cur, token)
        if username is None:
            raise HTTPException(401, "Session expired or invalid -- please log in again")
        user = auth_module.get_user_context(cur, username)
    if user is None:
        raise HTTPException(401, "Account no longer exists")
    return user


def require_roles(*roles):
    """Dependency factory: only allows the given roles through, else 403."""
    def _checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(403, "You do not have permission to perform this action")
        return user
    return _checker


# The event-ingestion endpoints intentionally have no dashboard-login
# requirement, since collectors post to them unattended with no human
# present to log in. On a trusted local network that was an acceptable
# gap; once the API is reachable from the public internet, anyone who
# finds the URL could otherwise post fabricated events into the database.
#
# This is a shared-secret check, not full authentication: every collector
# on a given deployment uses the same key, purely to prove "this request
# came from something that knows our key" rather than identifying which
# collector sent it. Set COLLECTOR_API_KEY in the environment to enable
# it; leaving it unset preserves the original no-auth behaviour, which
# keeps this a non-breaking change for an existing local-only setup.
COLLECTOR_API_KEY = os.environ.get("COLLECTOR_API_KEY")


def require_collector_key(x_collector_key: Optional[str] = Header(None)):
    if COLLECTOR_API_KEY is None:
        return  # no key configured -- behave exactly as before (local/trusted network)
    if x_collector_key != COLLECTOR_API_KEY:
        raise HTTPException(401, "Missing or incorrect X-Collector-Key header")


@app.post("/auth/signup", response_model=SignupResponse)
def signup(payload: SignupRequest):
    """Self-service account creation for 'analyst' and 'employee'. Admin
    accounts can only be created via create_admin.py, which requires
    access to the machine/server itself.

    Every self-registration -- analyst or employee -- is created pending
    and requires admin approval before it can log in. This closes the gap
    where deleting someone's login didn't stop them from just signing up
    again with slightly different details and getting instant access."""
    self_service_roles = {"analyst", "employee"}
    if payload.role not in self_service_roles:
        raise HTTPException(
            403,
            "Only Analyst and Employee accounts can be self-registered. Admin "
            "accounts are provisioned by the system administrator via create_admin.py.",
        )
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters long.")

    with db.get_cursor() as (conn, cur):
        entity_id = None
        if payload.role == "employee":
            entity_name = payload.entity_name or payload.username
            cur.execute("SELECT id FROM entities WHERE name = %s", (entity_name,))
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO entities (name, entity_type) VALUES (%s, 'user') RETURNING id",
                    (entity_name,),
                )
                row = cur.fetchone()
            entity_id = row["id"]

        try:
            auth_module.register_user(
                cur, payload.username, payload.email, payload.password,
                payload.role, entity_id, is_approved=False,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))

        notifications.notify_admins_of_signup(cur, payload.username, payload.email, payload.role)
        notifications.notify_user_signup_received(payload.email, payload.username, payload.role)

        return {
            "pending_approval": True,
            "message": f"Your {payload.role} account has been created and is awaiting admin approval before you can sign in.",
            "username": payload.username, "role": payload.role,
        }


@app.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    with db.get_cursor() as (conn, cur):
        if not auth_module.authenticate(cur, payload.username, payload.password):
            raise HTTPException(401, "Invalid username/email or password")
        canonical_username = auth_module.resolve_identity(cur, payload.username)
        user = auth_module.get_user_context(cur, canonical_username)
        if not user["is_approved"]:
            raise HTTPException(403, f"Your {user['role']} account is still awaiting admin approval.")
        token, expires_at = auth_module.create_session(cur, canonical_username)
    return {
        "token": token, "username": canonical_username, "role": user["role"],
        "entity_id": user["entity_id"], "entity_name": user["entity_name"],
        "must_change_password": user["must_change_password"],
        "expires_at": expires_at,
    }


@app.post("/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):]
        with db.get_cursor() as (conn, cur):
            auth_module.delete_session(cur, token)
    return {"logged_out": True}


@app.get("/auth/me")
def me(user: dict = Depends(get_current_user)):
    return user


@app.get("/users", response_model=List[UserOut])
def list_users(user: dict = Depends(require_roles("admin"))):
    """Every dashboard login, any role, approved or not -- for the
    admin-only user-management panel."""
    with db.get_cursor() as (conn, cur):
        cur.execute(
            """
            SELECT u.username, u.email, u.role, u.entity_id, u.is_approved,
                   u.must_change_password, u.created_at,
                   e.name AS entity_name
            FROM admin_users u
            LEFT JOIN entities e ON e.id = u.entity_id
            ORDER BY u.created_at
            """
        )
        return [dict(r) for r in cur.fetchall()]


@app.get("/users/pending", response_model=List[PendingUserOut])
def list_pending_users(user: dict = Depends(require_roles("admin"))):
    with db.get_cursor() as (conn, cur):
        cur.execute(
            "SELECT username, email, created_at FROM admin_users "
            "WHERE is_approved = false ORDER BY created_at"
        )
        return [dict(r) for r in cur.fetchall()]


@app.post("/users/{username}/approve")
def approve_user(username: str, user: dict = Depends(require_roles("admin"))):
    with db.get_cursor() as (conn, cur):
        cur.execute(
            "UPDATE admin_users SET is_approved = true "
            "WHERE username = %s RETURNING username, email, role",
            (username,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, "Pending account not found")
        notifications.notify_user_approved(row["email"], row["username"], row["role"])
        return {"username": username, "approved": True}


@app.delete("/users/{username}")
def remove_user(username: str, user: dict = Depends(require_roles("admin"))):
    """Permanently deletes a dashboard login from the database -- a real
    SQL DELETE, not a deactivation or soft-delete. Used both to reject a
    pending sign-up and to remove any existing account outright. An admin
    can't delete their own account through this endpoint, to avoid
    accidentally locking themselves out."""
    if username == user["username"]:
        raise HTTPException(400, "You cannot delete your own account.")
    with db.get_cursor() as (conn, cur):
        cur.execute("DELETE FROM admin_users WHERE username = %s RETURNING username", (username,))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, "User not found")
        return {"username": username, "permanently_deleted": True}


@app.post("/auth/change-password")
def change_own_password(payload: ChangePasswordRequest, user: dict = Depends(get_current_user)):
    """Any logged-in user can change their own password (not admin-only).
    Requires the current password for verification -- this is also how a
    must_change_password account replaces the shared default with one only
    they know."""
    if len(payload.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters long.")
    with db.get_cursor() as (conn, cur):
        if not auth_module.authenticate(cur, user["username"], payload.current_password):
            raise HTTPException(401, "Current password is incorrect.")
        auth_module.change_password(cur, user["username"], payload.new_password)
    return {"changed": True}


@app.post("/users/{username}/reset-password", response_model=PasswordResetOut)
def reset_user_password(username: str, user: dict = Depends(require_roles("admin"))):
    """Resets one account back to the shared system default password and
    forces them to change it on next login. Also signs them out of any
    active session."""
    with db.get_cursor() as (conn, cur):
        found = auth_module.reset_password_to_default(cur, username)
        if not found:
            raise HTTPException(404, "User not found")
    return {"username": username, "default_password": auth_module.DEFAULT_PASSWORD}


@app.post("/users/reset-all-passwords", response_model=PasswordResetOut)
def reset_all_passwords(payload: ResetAllPasswordsRequest, user: dict = Depends(require_roles("admin"))):
    """Resets EVERY account -- including other admins, and the caller's
    own -- to the shared system default password, forces a change on next
    login, and signs everyone out. Requires an explicit confirm:true in
    the request body as a safeguard against accidental calls."""
    if not payload.confirm:
        raise HTTPException(400, "Pass confirm=true to proceed with this destructive action.")
    with db.get_cursor() as (conn, cur):
        count = auth_module.reset_all_passwords_to_default(cur)
    return {"reset_count": count, "default_password": auth_module.DEFAULT_PASSWORD}


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------
@app.post("/entities", response_model=EntityOut)
def create_entity(payload: EntityCreate, user: dict = Depends(require_roles("admin"))):
    with db.get_cursor() as (conn, cur):
        cur.execute(
            """
            INSERT INTO entities (name, entity_type, department, email, metadata)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                payload.name, payload.entity_type, payload.department,
                payload.email, psycopg2.extras.Json(payload.metadata),
            ),
        )
        row = cur.fetchone()
        return dict(row)


@app.get("/entities", response_model=List[EntityOut])
def list_entities(active_only: bool = True, department: Optional[str] = None, user: dict = Depends(require_roles("admin", "analyst"))):
    clauses, params = [], []
    if active_only:
        clauses.append("is_active = true")
    if department is not None:
        clauses.append("department = %s")
        params.append(department)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with db.get_cursor() as (conn, cur):
        cur.execute(f"SELECT * FROM entities {where_sql} ORDER BY id", params)
        return [dict(r) for r in cur.fetchall()]


@app.patch("/entities/{entity_id}", response_model=EntityOut)
def update_entity(entity_id: int, payload: EntityUpdate, user: dict = Depends(require_roles("admin"))):
    """Edit an entity, or restrict/unrestrict it via is_active. A
    restricted (is_active=false) entity is blocked from reporting any new
    events -- see the check in _resolve_entity_id / ingestion below."""
    fields = payload.as_field_dict()
    if not fields:
        raise HTTPException(400, "No fields provided to update.")

    set_clauses, values = [], []
    for key, value in fields.items():
        if key == "metadata":
            set_clauses.append("metadata = %s")
            values.append(psycopg2.extras.Json(value))
        else:
            set_clauses.append(f"{key} = %s")
            values.append(value)
    values.append(entity_id)

    with db.get_cursor() as (conn, cur):
        cur.execute(
            f"UPDATE entities SET {', '.join(set_clauses)} WHERE id = %s RETURNING *",
            values,
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, f"Entity {entity_id} not found")
        return dict(row)


@app.get("/entities/{entity_id}/linked-users")
def get_entity_linked_users(entity_id: int, user: dict = Depends(require_roles("admin"))):
    """Lets the dashboard warn before deleting an entity that still has a
    login tied to it, so an admin doesn't delete a "system" (monitored
    machine) while assuming it also removes that person's dashboard login."""
    with db.get_cursor() as (conn, cur):
        cur.execute(
            "SELECT username, role FROM admin_users WHERE entity_id = %s",
            (entity_id,),
        )
        return [dict(r) for r in cur.fetchall()]


@app.delete("/entities/{entity_id}")
def delete_entity(entity_id: int, also_delete_linked_users: bool = False, user: dict = Depends(require_roles("admin"))):
    """Permanently deletes an entity and everything tied to it (events,
    anomalies, baselines, config overrides -- all cascade). By default any
    login linked to it is kept but unlinked (entity_id set to NULL), not
    deleted -- pass also_delete_linked_users=true to remove those logins
    too in the same action."""
    with db.get_cursor() as (conn, cur):
        if also_delete_linked_users:
            cur.execute("DELETE FROM admin_users WHERE entity_id = %s", (entity_id,))
        cur.execute("DELETE FROM entities WHERE id = %s RETURNING id", (entity_id,))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, f"Entity {entity_id} not found")
        return {"entity_id": entity_id, "deleted": True}


@app.post("/entities/{keep_id}/merge/{duplicate_id}")
def merge_entities(keep_id: int, duplicate_id: int, user: dict = Depends(require_roles("admin"))):
    """Merges duplicate_id into keep_id -- everything the duplicate ever
    reported (events, anomalies) is reattributed to keep_id, any login
    linked to the duplicate is relinked, and the duplicate's name becomes
    an alias so future events reported under that name resolve to keep_id
    automatically instead of recreating the duplicate. The duplicate
    entity itself is then deleted.

    Exactly which records moved is recorded in entity_merges, so this can
    be reversed precisely later via POST /entities/merges/{id}/unmerge --
    not just "move everything currently on keep_id back", but exactly the
    same events/anomalies/logins that were part of this specific merge."""
    if keep_id == duplicate_id:
        raise HTTPException(400, "Cannot merge an entity into itself.")

    with db.get_cursor() as (conn, cur):
        cur.execute("SELECT id, name FROM entities WHERE id = %s", (keep_id,))
        keep = cur.fetchone()
        if keep is None:
            raise HTTPException(404, f"Entity {keep_id} (the one to keep) not found")

        cur.execute("SELECT id, name, entity_type FROM entities WHERE id = %s", (duplicate_id,))
        duplicate = cur.fetchone()
        if duplicate is None:
            raise HTTPException(404, f"Entity {duplicate_id} (the duplicate) not found")

        # Snapshot exactly what's about to move, before moving it.
        cur.execute("SELECT id FROM events WHERE entity_id = %s", (duplicate_id,))
        moved_event_ids = [r["id"] for r in cur.fetchall()]
        cur.execute("SELECT id FROM anomalies WHERE entity_id = %s", (duplicate_id,))
        moved_anomaly_ids = [r["id"] for r in cur.fetchall()]
        cur.execute("SELECT id FROM admin_users WHERE entity_id = %s", (duplicate_id,))
        moved_admin_user_ids = [r["id"] for r in cur.fetchall()]

        cur.execute("UPDATE events SET entity_id = %s WHERE entity_id = %s", (keep_id, duplicate_id))
        cur.execute("UPDATE anomalies SET entity_id = %s WHERE entity_id = %s", (keep_id, duplicate_id))
        cur.execute("UPDATE admin_users SET entity_id = %s WHERE entity_id = %s", (keep_id, duplicate_id))

        # entity_config has a UNIQUE constraint on entity_id -- if the
        # duplicate had its own override, only move it over if keep_id
        # doesn't already have one; otherwise keep_id's override wins and
        # the duplicate's is simply dropped.
        cur.execute("SELECT 1 FROM entity_config WHERE entity_id = %s", (keep_id,))
        keep_has_override = cur.fetchone() is not None
        if keep_has_override:
            cur.execute("DELETE FROM entity_config WHERE entity_id = %s", (duplicate_id,))
        else:
            cur.execute("UPDATE entity_config SET entity_id = %s WHERE entity_id = %s", (keep_id, duplicate_id))

        # Any alias that used to point at the duplicate should now point at
        # keep_id, and the duplicate's own name becomes a new alias so
        # future events under that name resolve here automatically.
        cur.execute("UPDATE entity_aliases SET entity_id = %s WHERE entity_id = %s", (keep_id, duplicate_id))
        cur.execute(
            "INSERT INTO entity_aliases (alias, entity_id) VALUES (%s, %s) "
            "ON CONFLICT (alias) DO UPDATE SET entity_id = EXCLUDED.entity_id",
            (duplicate["name"], keep_id),
        )

        cur.execute("DELETE FROM entities WHERE id = %s", (duplicate_id,))

        cur.execute(
            """
            INSERT INTO entity_merges (
                kept_entity_id, duplicate_entity_name, duplicate_entity_type,
                merged_event_ids, merged_anomaly_ids, affected_admin_user_ids,
                alias_created, merged_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                keep_id, duplicate["name"], duplicate["entity_type"],
                moved_event_ids, moved_anomaly_ids, moved_admin_user_ids,
                duplicate["name"], user["username"],
            ),
        )
        merge_id = cur.fetchone()["id"]

        return {
            "merge_id": merge_id,
            "kept_entity_id": keep_id, "kept_entity_name": keep["name"],
            "merged_entity_name": duplicate["name"], "merged": True,
        }


@app.get("/entities/merges")
def list_entity_merges(active_only: bool = True, user: dict = Depends(require_roles("admin"))):
    """Merge history, for the "unmerge" UI. active_only=true (default)
    shows only merges that haven't already been reversed."""
    where_sql = "WHERE m.unmerged_at IS NULL" if active_only else ""
    with db.get_cursor() as (conn, cur):
        cur.execute(
            f"""
            SELECT m.id, m.kept_entity_id, e.name AS kept_entity_name,
                   m.duplicate_entity_name, m.merged_by, m.merged_at, m.unmerged_at,
                   array_length(m.merged_event_ids, 1) AS event_count,
                   array_length(m.merged_anomaly_ids, 1) AS anomaly_count
            FROM entity_merges m
            LEFT JOIN entities e ON e.id = m.kept_entity_id
            {where_sql}
            ORDER BY m.merged_at DESC
            """
        )
        return [dict(r) for r in cur.fetchall()]


@app.post("/entities/merges/{merge_id}/unmerge")
def unmerge_entities(merge_id: int, user: dict = Depends(require_roles("admin"))):
    """Reverses a specific merge: recreates the duplicate entity under its
    original name, moves back exactly the events/anomalies/logins that
    were part of that merge (by recorded ID, not by current state -- this
    stays correct even if the kept entity has since been merged again
    elsewhere), removes the alias, and marks the merge as unmerged."""
    with db.get_cursor() as (conn, cur):
        cur.execute("SELECT * FROM entity_merges WHERE id = %s", (merge_id,))
        merge = cur.fetchone()
        if merge is None:
            raise HTTPException(404, f"Merge record {merge_id} not found")
        if merge["unmerged_at"] is not None:
            raise HTTPException(400, "This merge has already been undone.")

        cur.execute("SELECT 1 FROM entities WHERE name = %s", (merge["duplicate_entity_name"],))
        if cur.fetchone() is not None:
            raise HTTPException(
                400,
                f"An entity named '{merge['duplicate_entity_name']}' already exists -- "
                f"can't recreate it. Rename or remove that one first.",
            )

        cur.execute(
            "INSERT INTO entities (name, entity_type) VALUES (%s, %s) RETURNING id",
            (merge["duplicate_entity_name"], merge["duplicate_entity_type"]),
        )
        restored_id = cur.fetchone()["id"]

        if merge["merged_event_ids"]:
            cur.execute(
                "UPDATE events SET entity_id = %s WHERE id = ANY(%s)",
                (restored_id, merge["merged_event_ids"]),
            )
        if merge["merged_anomaly_ids"]:
            cur.execute(
                "UPDATE anomalies SET entity_id = %s WHERE id = ANY(%s)",
                (restored_id, merge["merged_anomaly_ids"]),
            )
        if merge["affected_admin_user_ids"]:
            cur.execute(
                "UPDATE admin_users SET entity_id = %s WHERE id = ANY(%s)",
                (restored_id, merge["affected_admin_user_ids"]),
            )

        if merge["alias_created"]:
            cur.execute(
                "DELETE FROM entity_aliases WHERE alias = %s AND entity_id = %s",
                (merge["alias_created"], merge["kept_entity_id"]),
            )

        cur.execute("UPDATE entity_merges SET unmerged_at = now() WHERE id = %s", (merge_id,))

        return {
            "merge_id": merge_id,
            "restored_entity_id": restored_id,
            "restored_entity_name": merge["duplicate_entity_name"],
            "events_restored": len(merge["merged_event_ids"] or []),
            "anomalies_restored": len(merge["merged_anomaly_ids"] or []),
            "unmerged": True,
        }


# ---------------------------------------------------------------------------
# Event ingestion (this is what feeds the detection engine)
# ---------------------------------------------------------------------------
def _resolve_entity_id(cur, payload: EventIn) -> int:
    """Return payload.entity_id if given, otherwise look up (or create)
    an entity by payload.entity_name. This is what lets external collectors
    (like the Windows Event Log collector) send just a username.

    Checks entity_aliases before creating a new entity -- this is how a
    merged duplicate's old name keeps resolving to the canonical entity
    instead of quietly recreating the duplicate on the next event."""
    if payload.entity_id is not None:
        return payload.entity_id
    if not payload.entity_name:
        raise HTTPException(400, "Must provide either entity_id or entity_name")

    cur.execute("SELECT id FROM entities WHERE name = %s", (payload.entity_name,))
    row = cur.fetchone()
    if row is not None:
        return row["id"]

    cur.execute("SELECT entity_id FROM entity_aliases WHERE alias = %s", (payload.entity_name,))
    row = cur.fetchone()
    if row is not None:
        return row["entity_id"]

    cur.execute(
        "INSERT INTO entities (name, entity_type) VALUES (%s, %s) RETURNING id",
        (payload.entity_name, payload.entity_type),
    )
    return cur.fetchone()["id"]


def _assert_entity_active(cur, entity_id: int) -> None:
    """Blocks event ingestion for any entity an admin has restricted
    (is_active=false). This is the enforcement point for "restrict"."""
    cur.execute("SELECT is_active FROM entities WHERE id = %s", (entity_id,))
    row = cur.fetchone()
    if row is None:
        raise HTTPException(404, f"Entity {entity_id} not found")
    if not row["is_active"]:
        raise HTTPException(403, "This entity has been restricted by an administrator and cannot report events.")


def _insert_event(cur, entity_id: int, payload: EventIn) -> dict:
    cur.execute(
        """
        INSERT INTO events (
            entity_id, event_type, event_time, status, source_ip,
            geo_country, geo_city, geo_lat, geo_lon, resource,
            bytes_transferred, file_count, raw
        ) VALUES (
            %s, %s, COALESCE(%s, now()), %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, %s
        )
        RETURNING *
        """,
        (
            entity_id, payload.event_type, payload.event_time, payload.status,
            payload.source_ip, payload.geo_country, payload.geo_city, payload.geo_lat,
            payload.geo_lon, payload.resource, payload.bytes_transferred, payload.file_count,
            psycopg2.extras.Json(payload.raw),
        ),
    )
    return dict(cur.fetchone())


@app.post("/events")
def ingest_event(payload: EventIn, _key: None = Depends(require_collector_key)):
    with db.get_cursor() as (conn, cur):
        entity_id = _resolve_entity_id(cur, payload)
        _assert_entity_active(cur, entity_id)
        event_row = _insert_event(cur, entity_id, payload)
        anomalies = engine.process_event(cur, event_row)
        return {"event_id": event_row["id"], "entity_id": entity_id, "anomalies_detected": anomalies}


@app.post("/events/batch")
def ingest_events_batch(payload: EventBatchIn, _key: None = Depends(require_collector_key)):
    results = []
    with db.get_cursor() as (conn, cur):
        for item in payload.events:
            entity_id = _resolve_entity_id(cur, item)
            _assert_entity_active(cur, entity_id)
            event_row = _insert_event(cur, entity_id, item)
            anomalies = engine.process_event(cur, event_row)
            results.append({"event_id": event_row["id"], "entity_id": entity_id, "anomalies_detected": anomalies})
    return {"processed": len(results), "results": results}


# ---------------------------------------------------------------------------
# Configuration: adjustable thresholds & working hours
# ---------------------------------------------------------------------------
@app.get("/config/default")
def get_default_config(user: dict = Depends(require_roles("admin"))):
    with db.get_cursor() as (conn, cur):
        return config_module.get_default_config(cur)


@app.put("/config/default")
def update_default_config(payload: ConfigUpdate, user: dict = Depends(require_roles("admin"))):
    if payload.social_media_block_enabled is not None:
        raise HTTPException(
            400,
            "social_media_block_enabled can't be set on the global default -- it's deliberately "
            "per-entity only, to prevent accidentally blocking everyone at once. Set it on a "
            "specific entity instead (PUT /config/{entity_id}).",
        )
    with db.get_cursor() as (conn, cur):
        return config_module.update_config(cur, None, payload.as_field_dict(), payload.changed_by)


@app.get("/config/{entity_id}")
def get_entity_config(entity_id: int, user: dict = Depends(require_roles("admin"))):
    with db.get_cursor() as (conn, cur):
        cur.execute("SELECT 1 FROM entities WHERE id = %s", (entity_id,))
        if cur.fetchone() is None:
            raise HTTPException(404, f"Entity {entity_id} not found")
        return config_module.get_effective_config(cur, entity_id)


@app.put("/config/{entity_id}")
def update_entity_config(entity_id: int, payload: ConfigUpdate, user: dict = Depends(require_roles("admin"))):
    with db.get_cursor() as (conn, cur):
        cur.execute("SELECT 1 FROM entities WHERE id = %s", (entity_id,))
        if cur.fetchone() is None:
            raise HTTPException(404, f"Entity {entity_id} not found")
        return config_module.update_config(cur, entity_id, payload.as_field_dict(), payload.changed_by)


@app.delete("/config/{entity_id}")
def remove_entity_override(entity_id: int, changed_by: Optional[str] = None, user: dict = Depends(require_roles("admin"))):
    with db.get_cursor() as (conn, cur):
        config_module.delete_override(cur, entity_id, changed_by)
        return {"entity_id": entity_id, "reverted_to_default": True}


# ---------------------------------------------------------------------------
# Anomalies
# ---------------------------------------------------------------------------
def _build_anomaly_filters(user, entity_id=None, status=None, severity=None, since=None, department=None):
    """Shared WHERE-clause builder for both the flat anomaly list and the
    per-entity grouped summary, so the analyst-scoping rule and every
    filter stay consistent between the two."""
    clauses, params = [], []

    # Analysts only see anomalies for entities linked to an actual employee
    # account -- not admin's or other analysts' own activity. Admins are
    # unrestricted (no clause added for them).
    if user["role"] == "analyst":
        clauses.append(
            "entity_id IN (SELECT entity_id FROM admin_users WHERE role = 'employee' AND entity_id IS NOT NULL)"
        )

    if entity_id is not None:
        clauses.append("entity_id = %s")
        params.append(entity_id)
    if status is not None:
        clauses.append("status = %s")
        params.append(status)
    if severity is not None:
        clauses.append("severity = %s")
        params.append(severity)
    if since is not None:
        clauses.append("detected_at >= %s")
        params.append(since)
    if department is not None:
        clauses.append("entity_id IN (SELECT id FROM entities WHERE department = %s)")
        params.append(department)

    return clauses, params


@app.get("/anomalies/by-entity")
def list_anomalies_by_entity(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[datetime] = None,
    department: Optional[str] = None,
    user: dict = Depends(require_roles("admin", "analyst")),
):
    """One row per entity that has at least one matching anomaly, with a
    count and the highest severity present -- what the dashboard's default
    Anomalies view groups by, so you see 'micha: 3 open, highest severity
    high' instead of 3 separate rows for the same person."""
    clauses, params = _build_anomaly_filters(user, status=status, severity=severity, since=since, department=department)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with db.get_cursor() as (conn, cur):
        cur.execute(
            f"""
            SELECT
                a.entity_id,
                e.name AS entity_name,
                e.department,
                count(*) AS total_count,
                count(*) FILTER (WHERE a.status = 'open') AS open_count,
                MAX(CASE a.severity
                    WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS severity_rank,
                MAX(a.detected_at) AS latest_detected_at
            FROM anomalies a
            JOIN entities e ON e.id = a.entity_id
            {where_sql}
            GROUP BY a.entity_id, e.name, e.department
            ORDER BY latest_detected_at DESC
            """,
            params,
        )
        rank_to_severity = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: None}
        results = []
        for row in cur.fetchall():
            d = dict(row)
            d["highest_severity"] = rank_to_severity.get(d.pop("severity_rank"), None)
            results.append(d)
        return results


@app.get("/anomalies", response_model=List[AnomalyOut])
def list_anomalies(
    entity_id: Optional[int] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[datetime] = None,
    department: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    user: dict = Depends(require_roles("admin", "analyst")),
):
    clauses, params = _build_anomaly_filters(user, entity_id, status, severity, since, department)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with db.get_cursor() as (conn, cur):
        cur.execute(
            f"SELECT * FROM anomalies {where_sql} ORDER BY detected_at DESC LIMIT %s",
            params + [limit],
        )
        return [dict(r) for r in cur.fetchall()]


@app.patch("/anomalies/{anomaly_id}", response_model=AnomalyOut)
def update_anomaly_status(anomaly_id: int, payload: AnomalyStatusUpdate, user: dict = Depends(require_roles("admin", "analyst"))):
    valid_statuses = {"open", "acknowledged", "resolved", "false_positive"}
    if payload.status not in valid_statuses:
        raise HTTPException(400, f"status must be one of {sorted(valid_statuses)}")
    with db.get_cursor() as (conn, cur):
        cur.execute("SELECT entity_id FROM anomalies WHERE id = %s", (anomaly_id,))
        existing = cur.fetchone()
        if existing is None:
            raise HTTPException(404, f"Anomaly {anomaly_id} not found")

        # Same scoping as GET /anomalies: analysts can only act on anomalies
        # tied to an actual employee-linked entity.
        if user["role"] == "analyst":
            cur.execute(
                "SELECT 1 FROM admin_users WHERE role = 'employee' AND entity_id = %s",
                (existing["entity_id"],),
            )
            if cur.fetchone() is None:
                raise HTTPException(403, "Analysts can only act on anomalies for monitored employee entities.")

        cur.execute(
            """
            UPDATE anomalies
            SET status = %s,
                resolved_at = CASE WHEN %s IN ('resolved','false_positive') THEN now() ELSE resolved_at END,
                resolved_by = CASE WHEN %s IN ('resolved','false_positive') THEN %s ELSE resolved_by END
            WHERE id = %s
            RETURNING *
            """,
            (payload.status, payload.status, payload.status, payload.resolved_by, anomaly_id),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, f"Anomaly {anomaly_id} not found")
        return dict(row)


@app.delete("/anomalies/{anomaly_id}")
def delete_anomaly(anomaly_id: int, user: dict = Depends(require_roles("admin"))):
    """Permanently removes an anomaly record. Admin-only -- analysts can
    change an anomaly's status (ack/resolve/false positive) but not erase
    it outright, preserving the audit trail for anyone but an admin."""
    with db.get_cursor() as (conn, cur):
        cur.execute("DELETE FROM anomalies WHERE id = %s RETURNING id", (anomaly_id,))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, f"Anomaly {anomaly_id} not found")
        return {"anomaly_id": anomaly_id, "deleted": True}


# ---------------------------------------------------------------------------
# Social media activity tracking -- deliberately NOT anomaly detection.
# These are just logged and viewable, each flagged with whether it happened
# during the entity's configured working hours, using the exact same
# in/out-of-hours logic the off-hours detector uses (so the two always
# agree), but without raising an anomaly of any kind.
#
# The collector (browser_history_monitor.py) already groups a burst of
# browser-history rows into one "session" event before posting, but that
# grouping only works within a single continuously-running collector
# process -- e.g. if it's instead invoked repeatedly as one-off runs (a
# scheduled task every minute), each run starts with no memory of the
# previous one's in-progress session and posts every visit as its own
# reading. Rather than depend on the collector always being run the "right"
# way, we merge nearby readings again here, at read time -- this is also
# what retroactively cleans up any old duplicate rows already sitting in
# the database from before this existed, with no manual cleanup needed.
# ---------------------------------------------------------------------------
SOCIAL_MEDIA_MERGE_GAP_SECONDS = 300


def _merge_social_media_rows(rows: list) -> list:
    """rows must already be sorted ascending by event_time. Collapses
    consecutive rows for the same (entity_id, site) into one reading
    whenever the gap between one row's end and the next row's start is
    within SOCIAL_MEDIA_MERGE_GAP_SECONDS. Returns merged rows, still
    ascending by start time."""
    merged = []
    open_group = None

    for row in rows:
        start = row["event_time"]
        end = row["end_time"] or row["event_time"]
        key = (row["entity_id"], row["site"])

        if open_group and open_group["key"] == key and \
                (start - open_group["end"]).total_seconds() <= SOCIAL_MEDIA_MERGE_GAP_SECONDS:
            if end > open_group["end"]:
                open_group["end"] = end
            open_group["ids"].append(row["id"])
        else:
            if open_group:
                merged.append(open_group)
            open_group = {
                "key": key, "entity_id": row["entity_id"], "entity_name": row["entity_name"],
                "site": row["site"], "start": start, "end": end, "ids": [row["id"]],
                # Only meaningful if this group never grows past one row --
                # once a second row merges in, the merged span itself
                # becomes the duration (computed below), which is more
                # reliable than any single visit's own duration hint.
                "duration_hint": row["duration_seconds"],
                "during_work_hours": row["during_work_hours"],
            }
    if open_group:
        merged.append(open_group)

    out = []
    for g in merged:
        span_seconds = int((g["end"] - g["start"]).total_seconds())
        duration_seconds = span_seconds if span_seconds > 0 else g["duration_hint"]
        out.append({
            "id": g["ids"][0],
            "ids": g["ids"],
            "entity_id": g["entity_id"],
            "entity_name": g["entity_name"],
            "site": g["site"],
            "event_time": g["start"],
            "end_time": g["end"],
            "duration_seconds": duration_seconds,
            "during_work_hours": g["during_work_hours"],
        })
    return out


@app.get("/social-media-activity")
def list_social_media_activity(
    entity_id: Optional[int] = None,
    department: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = Query(default=200, le=1000),
    user: dict = Depends(require_roles("admin", "analyst")),
):
    clauses, params = ["event_type = 'social_media_access'"], []

    if user["role"] == "analyst":
        clauses.append(
            "entity_id IN (SELECT entity_id FROM admin_users WHERE role = 'employee' AND entity_id IS NOT NULL)"
        )
    if entity_id is not None:
        clauses.append("entity_id = %s")
        params.append(entity_id)
    if department is not None:
        clauses.append("entity_id IN (SELECT id FROM entities WHERE department = %s)")
        params.append(department)
    if since is not None:
        clauses.append("event_time >= %s")
        params.append(since)

    where_sql = f"WHERE {' AND '.join(clauses)}"
    with db.get_cursor() as (conn, cur):
        # Over-fetch the most recent raw rows before merging, since several
        # can collapse into a single displayed reading -- if we only pulled
        # exactly `limit` rows we could undercount how many merged readings
        # that represents. This is bounded rather than unlimited, so a
        # reading whose earliest rows fall just outside the fetched window
        # can occasionally show a slightly later start than it truly had;
        # fine for a visibility-only dashboard.
        cur.execute(
            f"""
            SELECT e.id, e.entity_id, en.name AS entity_name, e.resource AS site, e.event_time,
                   e.raw
            FROM events e
            JOIN entities en ON en.id = e.entity_id
            {where_sql}
            ORDER BY e.event_time DESC
            LIMIT %s
            """,
            params + [min(limit * 5, 2000)],
        )
        rows = [dict(r) for r in cur.fetchall()]
        rows.reverse()  # ascending, so the merge pass below can walk forward in time

        # Each entity might have its own work-hours override, so cache the
        # effective config per entity rather than re-fetching it per row.
        config_cache = {}
        for row in rows:
            eid = row["entity_id"]
            if eid not in config_cache:
                config_cache[eid] = config_module.get_effective_config(cur, eid)
            row["during_work_hours"] = detectors.is_within_work_hours(row["event_time"], config_cache[eid])
            # duration_seconds/end_time are None for events collected before
            # these fields existed, or when the collector couldn't determine
            # dwell time (see browser_history_monitor.py) -- the dashboard
            # shows that as "--" rather than a misleading 0 or a repeated
            # start time.
            raw = row.pop("raw") or {}
            row["duration_seconds"] = raw.get("duration_seconds")
            end_time = raw.get("end_time")
            row["end_time"] = datetime.fromisoformat(end_time) if end_time else None

        merged = _merge_social_media_rows(rows)
        merged.sort(key=lambda r: r["event_time"], reverse=True)
        return merged[:limit]


@app.delete("/social-media-activity/{ids}")
def delete_social_media_activity(ids: str, user: dict = Depends(require_roles("admin"))):
    """Removes one or more social media reading(s). ids is a comma-separated
    list of event ids -- the dashboard merges nearby visits into a single
    displayed reading (see list_social_media_activity above), and deleting
    that reading needs to remove every event id behind it, not just one.
    Scoped to event_type='social_media_access' so this can't be used to
    delete other kinds of events even if someone guesses an id."""
    try:
        id_list = [int(x) for x in ids.split(",") if x.strip()]
    except ValueError:
        raise HTTPException(400, "ids must be a comma-separated list of integers")
    if not id_list:
        raise HTTPException(400, "No ids provided")
    with db.get_cursor() as (conn, cur):
        cur.execute(
            "DELETE FROM events WHERE id = ANY(%s) AND event_type = 'social_media_access' RETURNING id",
            (id_list,),
        )
        deleted_ids = [row["id"] for row in cur.fetchall()]
        if not deleted_ids:
            raise HTTPException(404, "No matching social media activity found")
        return {"deleted_ids": deleted_ids}


# ---------------------------------------------------------------------------
# Social media blocking status -- read-only endpoint polled by
# social_media_blocker.py running on each employee's machine. Answers
# "should this machine be blocking social media right now?" by combining
# the entity's social_media_block_enabled flag with the exact same
# work-hours check the off-hours detector uses. No auth required (same as
# POST /events) since it's called by an unattended collector, not a
# logged-in dashboard user; it doesn't expose or modify anything sensitive.
# ---------------------------------------------------------------------------
@app.get("/social-media-block-status")
def social_media_block_status(entity_name: str):
    with db.get_cursor() as (conn, cur):
        cur.execute("SELECT id FROM entities WHERE name = %s", (entity_name,))
        row = cur.fetchone()
        if row is None:
            cur.execute("SELECT entity_id FROM entity_aliases WHERE alias = %s", (entity_name,))
            row = cur.fetchone()
            entity_id = row["entity_id"] if row else None
        else:
            entity_id = row["id"]

        if entity_id is None:
            # Unknown entity (e.g. this machine hasn't posted any other
            # event yet) -- default to not blocking rather than erroring,
            # since a blocker script polling this shouldn't lock someone
            # out over a name it doesn't recognize yet.
            return {"entity_name": entity_name, "entity_found": False, "should_block": False}

        cfg = config_module.get_effective_config(cur, entity_id)
        should_block = bool(cfg.get("social_media_block_enabled")) and detectors.is_within_work_hours(
            datetime.now(timezone.utc), cfg
        )
        return {
            "entity_name": entity_name,
            "entity_found": True,
            "should_block": should_block,
            "domains": sorted(browser_history_monitor.SOCIAL_MEDIA_DOMAINS),
        }


@app.get("/entities/social-media-block-settings")
def list_social_media_block_settings(user: dict = Depends(require_roles("admin", "analyst"))):
    """Every entity with its current social_media_block_enabled setting
    (its own override if it has one, otherwise the global default) --
    powers the per-entity toggle switches on the Social Media dashboard
    tab, in one query instead of one round-trip per entity."""
    with db.get_cursor() as (conn, cur):
        cur.execute(
            """
            SELECT e.id AS entity_id, e.name AS entity_name, e.department,
                   COALESCE(ec.social_media_block_enabled, dc.social_media_block_enabled) AS social_media_block_enabled,
                   (ec.entity_id IS NOT NULL) AS has_own_override
            FROM entities e
            LEFT JOIN entity_config ec ON ec.entity_id = e.id
            CROSS JOIN (SELECT social_media_block_enabled FROM entity_config WHERE entity_id IS NULL) dc
            ORDER BY e.name
            """
        )
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Manual detection trigger (for events inserted outside the ingest API, or
# to run on a schedule / cron instead of synchronously per-event)
# ---------------------------------------------------------------------------
@app.post("/detect/run")
def run_detection(limit: int = 500, user: dict = Depends(require_roles("admin", "analyst"))):
    with db.get_cursor() as (conn, cur):
        findings = engine.process_unprocessed(cur, limit=limit)
        return {"anomalies_detected": len(findings), "details": findings}


@app.get("/health")
def health():
    return {"status": "ok"}
