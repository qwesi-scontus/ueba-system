"""
Email notifications for account sign-up and approval events.

Configured entirely via environment variables, so no code changes are
needed to point this at a real mail provider:

    SMTP_HOST          e.g. smtp.gmail.com
    SMTP_PORT          e.g. 587 for STARTTLS, 465 for SSL -- default 587
    SMTP_USERNAME      the account to authenticate as
    SMTP_PASSWORD      an app password (see README -- most providers, including
                       Gmail, reject your normal account password here)
    SMTP_FROM_EMAIL    the "From" address recipients see (defaults to SMTP_USERNAME)
    SMTP_USE_TLS       "true"/"false" -- default "true" (STARTTLS on port 587;
                       set "false" only if using implicit SSL on port 465)

If SMTP_HOST isn't set, sending is skipped and a line is printed to the
console instead, so sign-up/approval keep working even before you've
configured a mail provider.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL") or SMTP_USERNAME
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").strip().lower() != "false"


def send_email(to_address: str, subject: str, body: str) -> bool:
    """Sends a plain-text email. Returns True if sent, False if skipped or
    failed -- this never raises, so a mail outage or missing config never
    breaks sign-up or approval."""
    if not to_address:
        return False
    if not SMTP_HOST:
        print(f"[email] SMTP not configured -- would have sent to {to_address}: {subject}")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM_EMAIL or "no-reply@ueba.local"
    msg["To"] = to_address
    msg.set_content(body)

    try:
        if SMTP_USE_TLS:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls(context=ssl.create_default_context())
                if SMTP_USERNAME and SMTP_PASSWORD:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10, context=ssl.create_default_context()) as server:
                if SMTP_USERNAME and SMTP_PASSWORD:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
        return True
    except Exception as e:
        print(f"[email] Failed to send to {to_address}: {e}")
        return False


def notify_admins_of_signup(cur, username: str, signup_email: str, role: str) -> None:
    """Emails every admin with a known email address about a new pending
    sign-up awaiting their approval."""
    cur.execute("SELECT email FROM admin_users WHERE role = 'admin' AND email IS NOT NULL")
    admin_emails = [r["email"] for r in cur.fetchall()]
    if not admin_emails:
        return
    subject = f"UEBA: new {role} sign-up awaiting approval"
    body = (
        f"A new account has signed up and is waiting for your approval.\n\n"
        f"Username: {username}\n"
        f"Email:    {signup_email}\n"
        f"Role:     {role}\n\n"
        f"Approve or reject it from the dashboard: Settings -> Manage Users."
    )
    for admin_email in admin_emails:
        send_email(admin_email, subject, body)


def notify_user_signup_received(email: Optional[str], username: str, role: str) -> None:
    """Confirms to the person who just signed up that their request was
    received and is pending -- so they're not left wondering why they
    can't log in yet."""
    subject = "UEBA: your account is pending approval"
    body = (
        f"Hi {username},\n\n"
        f"Your {role} account has been created and is now waiting for an "
        f"administrator to approve it. You'll get another email once that "
        f"happens, and you won't be able to sign in until then."
    )
    send_email(email, subject, body)


def notify_user_approved(email: Optional[str], username: str, role: str) -> None:
    """Lets a newly approved user know they can now sign in."""
    subject = "UEBA: your account has been approved"
    body = (
        f"Hi {username},\n\n"
        f"Your {role} account has been approved. You can now sign in at "
        f"the UEBA dashboard."
    )
    send_email(email, subject, body)
