"""
Admin authentication for the UEBA dashboard/API.

Uses PBKDF2-HMAC-SHA256 for password hashing (Python stdlib only, no extra
dependencies) and opaque, randomly generated session tokens stored in the
database with an expiry -- a simple, dependency-free alternative to JWTs
that's plenty for a single-admin, localhost-bound deployment like this one.
"""
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

PBKDF2_ITERATIONS = 260_000
SESSION_LIFETIME_HOURS = 12

# The password every first-time / reset account starts with. Not a secret --
# it's meant to be known and communicated to whoever needs to log in for the
# first time, on the understanding that must_change_password forces them to
# replace it before they can do anything else. Override via environment
# variable for a real deployment if you want a different default.
DEFAULT_PASSWORD = os.environ.get("DEFAULT_PASSWORD", "ChangeMe123!")

# Deliberately simple format check (not a deliverability/MX check) -- "active"
# in the everyday sense of "looks like a real email", not SMTP-verified.
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email: str) -> bool:
    return bool(email) and bool(EMAIL_REGEX.match(email.strip()))


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Returns (salt_hex, hash_hex). Pass an existing salt (as bytes) to
    verify a password against a stored hash; omit it to hash a new one."""
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, computed_hex = hash_password(password, salt)
    return hmac.compare_digest(computed_hex, expected_hash_hex)


def create_admin_user(cur, username: str, password: Optional[str] = None, role: str = "admin",
                       entity_id: Optional[int] = None, email: Optional[str] = None) -> bool:
    """CLI-driven creation/reset (create_admin.py). Unlike register_user,
    this doesn't require an email and always overwrites an existing account
    of the same username, since it's an intentional admin action. Always
    immediately approved, regardless of role.

    If password is None, the account is created with the shared
    DEFAULT_PASSWORD and flagged must_change_password=true. Returns True if
    the default password was used, False if a custom one was given."""
    used_default = password is None
    salt_hex, hash_hex = hash_password(password or DEFAULT_PASSWORD)
    cur.execute(
        """
        INSERT INTO admin_users (username, email, password_hash, salt, role, entity_id, is_approved, must_change_password)
        VALUES (%s, %s, %s, %s, %s, %s, true, %s)
        ON CONFLICT (username) DO UPDATE
        SET email = COALESCE(EXCLUDED.email, admin_users.email),
            password_hash = EXCLUDED.password_hash, salt = EXCLUDED.salt,
            role = EXCLUDED.role, entity_id = EXCLUDED.entity_id, is_approved = true,
            must_change_password = EXCLUDED.must_change_password
        """,
        (username, email, hash_hex, salt_hex, role, entity_id, used_default),
    )
    return used_default


def register_user(cur, username: str, email: str, password: str,
                   role: str = "employee", entity_id: Optional[int] = None,
                   is_approved: bool = True) -> None:
    """Self-service sign-up. Raises ValueError with a user-facing message on
    any validation failure (bad email, duplicate username/email).
    is_approved=False leaves the account created but unable to log in until
    an admin approves it (used for self-registered analysts)."""
    if not is_valid_email(email):
        raise ValueError("Please enter a valid email address.")
    email = email.strip().lower()

    cur.execute("SELECT 1 FROM admin_users WHERE username = %s", (username,))
    if cur.fetchone() is not None:
        raise ValueError("That username is already taken.")
    cur.execute("SELECT 1 FROM admin_users WHERE email = %s", (email,))
    if cur.fetchone() is not None:
        raise ValueError("That email address is already registered.")

    salt_hex, hash_hex = hash_password(password)
    cur.execute(
        """
        INSERT INTO admin_users (username, email, password_hash, salt, role, entity_id, is_approved)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (username, email, hash_hex, salt_hex, role, entity_id, is_approved),
    )


def resolve_identity(cur, identifier: str) -> Optional[str]:
    """Given a username OR an email address, returns the account's
    canonical username (or None if no match)."""
    cur.execute(
        "SELECT username FROM admin_users WHERE username = %s OR email = %s",
        (identifier, identifier),
    )
    row = cur.fetchone()
    return row["username"] if row else None


def get_user_context(cur, username: str) -> Optional[dict]:
    """Returns {username, email, role, entity_id, entity_name, is_approved,
    must_change_password} for a logged-in user, joining their linked
    entity's name when they have one (used for the 'employee' role, which
    is scoped to a single entity)."""
    cur.execute(
        """
        SELECT u.username, u.email, u.role, u.entity_id, u.is_approved,
               u.must_change_password, e.name AS entity_name
        FROM admin_users u
        LEFT JOIN entities e ON e.id = u.entity_id
        WHERE u.username = %s
        """,
        (username,),
    )
    row = cur.fetchone()
    return dict(row) if row else None


def authenticate(cur, identifier: str, password: str) -> bool:
    """identifier may be a username or an email address."""
    cur.execute(
        "SELECT password_hash, salt FROM admin_users WHERE username = %s OR email = %s",
        (identifier, identifier),
    )
    row = cur.fetchone()
    if row is None:
        return False
    return verify_password(password, row["salt"], row["password_hash"])


def create_session(cur, username: str) -> Tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_LIFETIME_HOURS)
    cur.execute(
        "INSERT INTO admin_sessions (token, username, expires_at) VALUES (%s, %s, %s)",
        (token, username, expires_at),
    )
    return token, expires_at


def get_session_username(cur, token: str) -> Optional[str]:
    """Returns the logged-in username for a valid, unexpired token, else None."""
    cur.execute("SELECT username, expires_at FROM admin_sessions WHERE token = %s", (token,))
    row = cur.fetchone()
    if row is None:
        return None
    expires_at = row["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        cur.execute("DELETE FROM admin_sessions WHERE token = %s", (token,))
        return None
    return row["username"]


def delete_session(cur, token: str) -> None:
    cur.execute("DELETE FROM admin_sessions WHERE token = %s", (token,))


def reset_password_to_default(cur, username: str) -> bool:
    """Resets one account's password to DEFAULT_PASSWORD and flags it
    must_change_password=true. Returns True if a matching account was
    found and reset, False otherwise. Also invalidates any existing
    sessions for that account, so a stolen/shared session can't outlive
    the reset."""
    salt_hex, hash_hex = hash_password(DEFAULT_PASSWORD)
    cur.execute(
        """
        UPDATE admin_users
        SET password_hash = %s, salt = %s, must_change_password = true
        WHERE username = %s
        RETURNING username
        """,
        (hash_hex, salt_hex, username),
    )
    row = cur.fetchone()
    if row is None:
        return False
    cur.execute("DELETE FROM admin_sessions WHERE username = %s", (username,))
    return True


def reset_all_passwords_to_default(cur) -> int:
    """Resets every account's password to DEFAULT_PASSWORD, flags them all
    must_change_password=true, and invalidates every active session.
    Returns the number of accounts reset. The same hash is computed once
    and reused for every row, since it's the same password for everyone."""
    salt_hex, hash_hex = hash_password(DEFAULT_PASSWORD)
    cur.execute(
        "UPDATE admin_users SET password_hash = %s, salt = %s, must_change_password = true",
        (hash_hex, salt_hex),
    )
    count = cur.rowcount
    cur.execute("DELETE FROM admin_sessions")
    return count


def change_password(cur, username: str, new_password: str) -> None:
    """Sets a new password chosen by the user themselves and clears
    must_change_password. Does not touch other sessions -- changing your
    own password from an active session shouldn't log you out of it."""
    salt_hex, hash_hex = hash_password(new_password)
    cur.execute(
        "UPDATE admin_users SET password_hash = %s, salt = %s, must_change_password = false WHERE username = %s",
        (hash_hex, salt_hex, username),
    )
