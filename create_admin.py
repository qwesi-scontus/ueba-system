"""
Create (or reset) a dashboard login for the UEBA system.

Roles:
    admin    - full access: settings/thresholds/working hours, all
               anomalies across every connected/monitored system, entity
               and user management
    analyst  - can view and triage anomalies for every entity; no
               access to settings or entity management
    employee - can only view anomalies for their own linked entity
               (their own machine's activity), read-only

Employees can also self-register on the dashboard's Sign Up tab with their
own email and password -- this script is for provisioning any role
(including admin) without going through the browser, and is the only way
to create an admin account.

Usage:
    python create_admin.py
"""
import getpass

import db
import auth

VALID_ROLES = {"admin", "analyst", "employee"}


def main():
    db.init_pool()

    username = input("Username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    role = (input("Role (admin / analyst / employee) [admin]: ").strip().lower() or "admin")
    if role not in VALID_ROLES:
        print(f"Role must be one of {sorted(VALID_ROLES)}.")
        return

    entity_id = None
    entity_name = None
    if role == "employee":
        entity_name = input("Which monitored entity (e.g. their Windows username) is this employee? ").strip()
        if not entity_name:
            print("An employee account must be linked to an entity.")
            return
        with db.get_cursor() as (conn, cur):
            cur.execute("SELECT id FROM entities WHERE name = %s", (entity_name,))
            row = cur.fetchone()
            if row is None:
                create = input(
                    f"No entity named '{entity_name}' exists yet. Create it now? [y/N]: "
                ).strip().lower()
                if create != "y":
                    print("Cancelled.")
                    return
                cur.execute(
                    "INSERT INTO entities (name, entity_type) VALUES (%s, 'user') RETURNING id",
                    (entity_name,),
                )
                row = cur.fetchone()
            entity_id = row["id"]

    email = input("Email (optional, press Enter to skip): ").strip() or None
    if email and not auth.is_valid_email(email):
        print("That doesn't look like a valid email address.")
        return

    password_input = getpass.getpass(
        f"Password (press Enter to use the system default, '{auth.DEFAULT_PASSWORD}'): "
    )
    password = None  # None tells create_admin_user to use DEFAULT_PASSWORD
    if password_input:
        confirm = getpass.getpass("Confirm password: ")
        if password_input != confirm:
            print("Passwords did not match. Nothing changed.")
            return
        if len(password_input) < 8:
            print("Please choose a password at least 8 characters long.")
            return
        password = password_input

    with db.get_cursor() as (conn, cur):
        used_default = auth.create_admin_user(cur, username, password, role=role, entity_id=entity_id, email=email)

    suffix = f", linked to entity '{entity_name}'." if entity_id else "."
    print(f"User '{username}' created/updated with role '{role}'{suffix}")
    if used_default:
        print(
            f"Password set to the system default ('{auth.DEFAULT_PASSWORD}'). "
            f"They'll be required to set their own password on first login."
        )


if __name__ == "__main__":
    main()
