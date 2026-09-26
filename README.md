# UEBA System (PostgreSQL-backed)

A User & Entity Behavior Analytics system with:

- **PostgreSQL** as the datastore for entities, raw events, config, baselines, and anomalies
- **Adjustable thresholds** for every detection rule (failed logins, data-transfer volume, geo-velocity, rare-resource access, statistical outliers)
- **Adjustable working hours** (timezone, work days, start/end time — including overnight shifts) either **globally** or **per entity**
- A rule-based + statistical **detection engine** that runs automatically on every ingested event
- A **FastAPI** service to ingest events, tune config, and review/triage anomalies

## 1. Set up PostgreSQL

### macOS / Linux

```bash
createdb ueba
psql -d ueba -f schema.sql
```

### Windows 11

Open **PowerShell** (or Command Prompt). If `psql` isn't recognized, use the
full path instead, e.g. `& "C:\Program Files\PostgreSQL\16\bin\psql.exe"`
(adjust the version number to match what you installed).

```powershell
# Create a dedicated login and database (run inside psql as the postgres superuser)
psql -U postgres
```
Inside the `psql` prompt that opens:
```sql
CREATE USER ueba_user WITH PASSWORD 'change_me';
CREATE DATABASE ueba OWNER ueba_user;
\q
```
Then load the schema (from the folder containing `schema.sql`):
```powershell
psql -U ueba_user -d ueba -h localhost -f schema.sql
```
You'll be prompted for the password you set above. You should see a series
of `CREATE TABLE` / `INSERT 0 1` lines with no errors.

**Alternative (GUI):** open **pgAdmin 4** (installed alongside PostgreSQL on
Windows), create a database called `ueba`, right-click it → **Query Tool**,
paste the contents of `schema.sql`, and run it (F5).

This creates all tables and seeds a single global default config row.

## 2. Install dependencies

### macOS / Linux
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Windows 11 (PowerShell)
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
If PowerShell blocks the activation script with an execution-policy error,
run this once first: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
Then retry `venv\Scripts\Activate.ps1`. (Command Prompt users: run
`venv\Scripts\activate.bat` instead.)

## 3. Configure the connection

### macOS / Linux
```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/ueba"
```

### Windows 11 (PowerShell)
```powershell
$env:DATABASE_URL = "postgresql://ueba_user:change_me@localhost:5432/ueba"
```
This only lasts for the current PowerShell session. To make it permanent,
set it via **System Properties → Environment Variables**, or create a
`.env` file and load it (e.g. with `python-dotenv`) if you'd rather not deal
with session variables at all.

## 4. Run the API

```bash
uvicorn api:app --reload --port 8000
```

Interactive docs: `http://localhost:8000/docs`

## 5. Create your dashboard logins

The dashboard (and every endpoint that reads or changes data — anomalies,
config, entities) requires a logged-in user with one of three roles. Event
ingestion (`POST /events`, used by the collector on every monitored
machine) stays open with no login required, so collectors keep working
unattended.

| Role | Can see | Can do |
|---|---|---|
| `admin` | Every anomaly across every entity/machine, unrestricted (including anomalies tied to analyst accounts' own activity, if any) | Change every threshold and working-hours field, globally or per entity; manage entities; triage anomalies |
| `analyst` | Only anomalies for entities linked to an employee account — **not** other analysts' or admin's own activity | Acknowledge/resolve/mark false positive on those employee-linked anomalies — **no** access to Settings |
| `employee` | Nothing — employees have login credentials but **no visibility into any anomaly data at all**, not even their own | None — the account exists for authentication purposes only, not for viewing security data |

Every scoping rule above is enforced **server-side** on every request — an
analyst can't see or act on non-employee anomalies by editing the query
string, and an employee gets a 403 from the anomalies endpoints regardless
of what the dashboard UI shows.

Each employee logs in with their own email address and a unique password.
A single admin login works across every connected/monitored machine, with
full visibility no other role has.

There are two ways to create a login:

**Self-service sign-up (on the dashboard itself)** — go to
`http://localhost:8000/dashboard`, click **Sign Up**, fill in a username,
email address (validated for a proper `name@domain.tld` format as you
type, before you can even submit), and password, then pick a role from the
dropdown: **1. Analyst** or **2. Employee**. Employees are automatically
linked to the monitored entity matching their username (the same name
their collector reports); if that entity doesn't exist yet, it's created
on the spot. Admin accounts can't be self-registered this way — the API
rejects it even if you edit the request directly.

**Every self-registration — Analyst or Employee — requires admin approval
before it can log in.** After submitting, they see a message saying their
account is pending, and `POST /auth/login` returns a 403 for that account
until an admin approves it. This is deliberate: without it, deleting
someone's login wouldn't actually stop them, since they could just sign up
again with slightly different details and get instant access. With
approval required, a fresh sign-up sits pending until you say otherwise,
no matter how many times someone tries.

Admins manage every login from the dashboard: **Settings → Manage Users**
(a badge shows the count of anyone still awaiting approval) lists every
account — admin, analyst, employee — with an **Approve** button on
anything pending and a **Delete** button on everyone except yourself (you
can't delete your own account, to avoid locking yourself out). Deleting a
user here is a real, permanent SQL `DELETE` from the database — not a
deactivation, and not reversible. Or via the API directly:

```bash
# List every dashboard login
curl http://localhost:8000/users

# List just those waiting on approval
curl http://localhost:8000/users/pending

# Approve one
curl -X POST http://localhost:8000/users/janedoe/approve

# Permanently delete a login (rejects a pending sign-up, or removes anyone else's account)
curl -X DELETE http://localhost:8000/users/janedoe
```

**CLI (the only way to create an Admin account, also usable for
Analyst/Employee)**:

```bash
python create_admin.py
```

It'll prompt for a username, a role (`admin` / `analyst` / `employee`), and
— for `employee` — which entity to link the account to, then an optional
email and a password (hidden as you type). Accounts created this way are
always immediately approved, regardless of role — the approval requirement
only applies to self-registration through the dashboard/API, not to
accounts an admin creates directly. Passwords are stored salted and
hashed — never in plain text, never in any file. Run this again any time
to reset a password or change someone's role. Since creating an *admin*
this way requires running a script on the server machine itself, only
whoever has access to that machine can ever become an admin.

Existing accounts sign in via the **Sign In** tab using either their
username or their email address.

### Email alerts (optional)

Set these environment variables before starting the API to enable email
notifications — one to every admin when someone signs up, and one to the
person themselves once approved:

```powershell
$env:SMTP_HOST = "smtp.gmail.com"
$env:SMTP_PORT = "587"
$env:SMTP_USERNAME = "your-address@gmail.com"
$env:SMTP_PASSWORD = "your-app-password"
```

For Gmail specifically, `SMTP_PASSWORD` must be an **App Password**, not
your normal login password (Gmail rejects plain passwords for SMTP).
Generate one at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
(requires 2-Step Verification to be turned on first). Any other SMTP
provider (Outlook, a school/work mail server, SendGrid, etc.) works the
same way — just point `SMTP_HOST`/`SMTP_PORT` at it.

If these variables aren't set, sign-up and approval work exactly the
same — email sending is skipped with a one-line console notice instead of
failing anything. See `notifications.py` for the full list of variables
(including `SMTP_FROM_EMAIL` and `SMTP_USE_TLS`) and exactly what each
email says.

### Default passwords and resets

Every account created via `create_admin.py` without typing a custom
password (just press Enter at the prompt) gets a shared system default
password instead — `ChangeMe123!` unless overridden by setting the
`DEFAULT_PASSWORD` environment variable before running the script or the
API. Accounts created this way are flagged `must_change_password`, so the
dashboard forces them through a **"Set a new password"** screen (entering
the default once, then their own new one) before they can do anything
else — they never get to skip this.

Admins can also reset a password back to this default at any time from
**Settings → Manage Users**:

- **Reset Password** on any single row — resets just that account, signs
  it out of any active session, and shows you the default password to
  hand off to that person.
- **Reset ALL Passwords to Default** (top of the same page) — resets
  *every* account, including your own, and signs everyone out
  immediately. Requires two confirmations since it's irreversible and
  affects everyone at once.

Via the API directly:

```bash
# Reset one account
curl -X POST http://localhost:8000/users/janedoe/reset-password

# Reset everyone (note the required confirm:true)
curl -X POST http://localhost:8000/users/reset-all-passwords \
  -H "Content-Type: application/json" \
  -d '{"confirm": true}'

# Any logged-in user changes their own password (used by the forced
# "Set a new password" screen, but callable directly too)
curl -X POST http://localhost:8000/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"current_password": "ChangeMe123!", "new_password": "something-only-they-know"}'
```

The default password is deliberately *not* a secret in the way a real
password is — it's meant to be told to whoever needs it, on the
understanding that `must_change_password` stops them from actually using
the system until they've replaced it with something only they know.

## 6. Feed in real events from Windows Security Event Log

The included `windows_event_collector.py` polls your laptop's actual
**Security** event log and pushes real logon/logoff activity into the
system — no synthetic data involved.

**One-time setup (elevated / Administrator PowerShell or Command Prompt):**

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
```

`4624` (successful logon) and `4625` (failed logon) are audited by default
on Windows 11; the commands above additionally ensure `4634` (logoff) is
captured too.

**Run it** (in a **second** terminal, alongside the API from step 4 — this
terminal also needs to be elevated, i.e. "Run as Administrator", since
reading the Security log requires it):

```powershell
python windows_event_collector.py
```

You'll see output like:

```
UEBA Windows collector starting. API=http://localhost:8000 interval=15s checkpoint_file=...
processed 1 event(s), checkpoint at record 987654
  !! ANOMALY [medium] alice: off_hours_access -- Activity outside configured working hours...
```

It polls every 15 seconds by default (`--interval`), remembers its position
between restarts (`collector_checkpoint.json`), and looks back 60 minutes on
its very first run (`--lookback-minutes`). Use `--once` to do a single poll
and exit, handy for testing.

It captures: successful/failed logons (`4624`/`4625`), logoffs (`4634`),
"run as different user" logons (`4648`), privileged/elevated logons
(`4672`), and new local account creation (`4720`) — filtering out noise
like service accounts (`postgres`, `SYSTEM`, etc.), virtual accounts
(`DefaultUser1`, `WsiAccount`, and similar credential-provider placeholder
identities Windows generates around the lock screen), and package-identity
GUIDs (Windows Store app accounts).

**Every event that passes those filters is attributed to one single
entity per machine, not to whichever Windows account name happened to
appear in that specific event.** This matters because Windows' own
credential-provider machinery is inconsistent about which account name it
logs a given lock-screen event under — the same physical PIN attempt on
the same laptop might show up as the real username, the machine account
(`COMPUTERNAME$`), or one of several internal placeholder identities,
depending on exactly where in Windows' authentication negotiation the
event was generated. Rather than creating a new duplicate entity every
time Windows picks a different name, the collector uses one fixed
identity (by default, the `COMPUTERNAME` environment variable — override
it with `--entity-name` if you want something else, e.g.
`--entity-name micha`) for everything real it reports. The original
Windows account name from each individual event is still preserved in
that event's `raw` details for reference; only the entity *attribution*
is unified.

If you already have duplicate entities from before this was fixed (e.g.
one for your real username and others for machine/placeholder accounts),
clean them up the same way as any other duplicate: **Settings → Manage
Systems → "Merge duplicate into..."**.

**Note on default working hours:** the global default is 9:00–18:00,
Mon–Fri. If you use your laptop outside that window (which is normal for a
personal machine), you'll immediately see `off_hours_access` anomalies —
that's expected. Adjust it to match your real schedule:

```bash
curl -X PUT http://localhost:8000/config/default \
  -H "Content-Type: application/json" \
  -d '{"work_start": "07:00:00", "work_end": "23:00:00", "work_days": [0,1,2,3,4,5,6], "changed_by": "you"}'
```

### Tracking social media usage (not an anomaly detector)

A separate, optional collector — `browser_history_monitor.py` — reads
Chrome, Edge, and Firefox browsing history for visits to known social
media domains (Facebook, Instagram, X/Twitter, TikTok, Reddit, LinkedIn,
YouTube, and others — see `SOCIAL_MEDIA_DOMAINS` near the top of the file
to add or remove sites) and reports them as `social_media_access` events.

**This deliberately never generates an anomaly.** It's a visibility
feature, not a detector — visits show up on the dashboard's **Social
Media** tab, each labeled "During Work Hours" or "Outside Work Hours"
using the exact same in/out-of-hours logic the off-hours detector uses,
but nothing about it is flagged as suspicious or contributes to severity
scoring anywhere.

Unlike `windows_event_collector.py`, this one doesn't need elevation —
browser history files are readable by the owning user account:

```powershell
python browser_history_monitor.py --entity-name micha
```

If you're running both collectors on the same machine, use the **same**
`--entity-name` for both, so login activity and social media activity
land on one entity instead of two:

```powershell
# Terminal 1 (elevated)
python windows_event_collector.py --entity-name micha

# Terminal 2 (not elevated)
python browser_history_monitor.py --entity-name micha
```

Each browser's history database is copied to a temp file before reading
(sidesteps file-lock conflicts with the running browser entirely) and
deleted immediately after — nothing is left behind. On the very first
run, only the last hour is checked (not your entire browsing history);
after that, a checkpoint file (`browser_history_checkpoint.json`) tracks
where each browser left off.

### Blocking social media during working hours (optional)

A third, separate script — `social_media_blocker.py` — actively blocks
the same social media domains during an entity's configured working
hours, rather than just tracking visits to them, and shows a clear
**"Access Restricted — denied by your administrator"** page instead of a
generic browser error. This is a policy nudge, not a hard security
control: anyone with admin rights on their own machine can edit the hosts
file back, remove the installed certificate, bypass with a different DNS
resolver, or get around it with a VPN. It stops casual, browser-based
access during work hours; it isn't meant to be unbreakable.

**How the custom block page works.** Since virtually every social media
site is HTTPS-only, simply redirecting a blocked domain to a dead address
would show the browser's generic connection-error page, not a message
attributing the block to anyone. Showing an actual custom page over
HTTPS needs a certificate the browser trusts for that domain — so on
first run, the script:

1. Generates a local certificate authority (`block_pki.py`) and installs
   it into Windows' trusted root certificate store (via `certutil` —
   your antivirus may flag this step, since installing a root certificate
   is a genuinely security-relevant action; that's expected, not a bug)
2. Generates and signs a certificate for each social media domain, using
   that local CA
3. Runs a small local web server (`block_page_server.py`) on
   `127.0.0.1`, serving the block page over both HTTPS (443) and HTTP
   (80), using SNI to present the right certificate for whichever domain
   the browser is asking for

The hosts file then redirects blocked domains to `127.0.0.1` (instead of
a dead address), so the browser lands on this local server, sees a
certificate it trusts (since your machine now trusts the CA that signed
it), and shows the actual block page instead of a warning.

I tested this full chain directly before shipping it — certificate
generation and signing, a real SNI-routed TLS handshake with client-side
validation against the CA, and the actual HTML content served over both
HTTPS and HTTP — not just the individual pieces in isolation.

Everything generated (the CA key/cert and each domain's certificate) is
cached under a `certs/` folder next to the script, created automatically
on first run — subsequent runs reuse the same CA rather than
regenerating and reinstalling it every time.

**Turn it on per entity** two ways:

- **Settings → Thresholds & Working Hours**, per-entity — the checkbox
  "Block social media during working hours" sits right next to the
  work-hours fields it depends on, since blocking only ever applies
  during whatever `work_start`/`work_end`/`work_days`/`timezone` that
  entity has configured (the exact same fields off-hours detection uses —
  there's no separate schedule to maintain).
- **The Social Media tab itself**, in the **Restrictions** table at the
  top — one row per entity, with a direct on/off toggle right there next
  to their social media activity, no need to go into Settings at all.
  Admins can flip it directly; analysts see the current state as a
  read-only badge instead. Both places read and write the exact same
  underlying setting, so they always stay in sync.

**This is deliberately per-entity only — there is no "block everyone"
global switch.** The checkbox doesn't appear at all when editing the
Global Default in Settings (only when a specific entity is selected), and
`PUT /config/default` rejects `social_media_block_enabled` outright if
you try to set it there via the API directly. This is to prevent an
admin from accidentally blocking every employee at once when they only
meant to block one person — you have to deliberately choose an entity
each time you turn blocking on for someone.

Requires elevation (Run as Administrator), since the hosts file, the
trusted root certificate store, and ports 80/443 all need it:

```powershell
python social_media_blocker.py --entity-name micha
```

Every hosts-file line it adds is tagged with a `# UEBA-BLOCK` comment, so
it only ever touches its own entries — nothing else already in your
hosts file is read, modified, or removed. It polls
`GET /social-media-block-status` (no auth required, since it's called by
an unattended script) every 60 seconds by default, and only rewrites the
hosts file when the block state actually changes — not on every poll —
to avoid unnecessary disk writes.

**One important limitation of Chromium/Firefox browsers: "Secure DNS"
(DNS-over-HTTPS) bypasses the hosts file entirely** if it's turned on,
sending lookups straight to an encrypted DNS server instead of consulting
your local hosts file at all. If blocking doesn't seem to be taking
effect, check `chrome://settings/security` (or the equivalent in Edge/
Firefox) and turn Secure DNS off. This isn't something this script can
fix from the outside — it's a browser-level setting.

If you're running all three collectors on the same machine, use the
**same** `--entity-name` for each:

```powershell
# Terminal 1 (elevated) -- required for both Windows Event Log access and hosts-file writes
python windows_event_collector.py --entity-name micha
python social_media_blocker.py --entity-name micha

# Terminal 2 (not elevated)
python browser_history_monitor.py --entity-name micha
```

### Running it continuously (Task Scheduler)

To have the API and collector start automatically:

1. Open **Task Scheduler** → **Create Task**.
2. **General** tab: check "Run with highest privileges" (needed for the
   collector to read the Security log) and "Run whether user is logged on
   or not" if you want it running even when locked.
3. **Triggers**: "At log on" (or "At startup").
4. **Actions**: Action = "Start a program", Program = path to your venv's
   `python.exe` (e.g. `C:\path\to\ueba_system\venv\Scripts\python.exe`),
   Arguments = `windows_event_collector.py`, Start in = the project folder.
5. Repeat as a second task for the API, with Arguments =
   `-m uvicorn api:app --port 8000` (Program still points at `python.exe`).
6. Optionally, repeat again as a third task for social media tracking,
   with Arguments = `browser_history_monitor.py --entity-name micha` (use
   the same `--entity-name` you gave `windows_event_collector.py`) — this
   one does **not** need "Run with highest privileges" checked, since
   browser history doesn't require elevation.
7. If you're also using social media blocking, add a fourth task with
   Arguments = `social_media_blocker.py --entity-name micha` — this one
   **does** need "Run with highest privileges" checked, since it writes
   to the hosts file.

## 7. Deploying the collector across every employee's machine

The database, API, and dashboard only need to run in **one place** (your
machine, or a dedicated server). Every other employee's machine just needs
the lightweight collector, pointed at that central machine over the
network — no login, no database, no FastAPI install required on their end.

**On the central machine (yours):**

1. Make the API listen on the network, not just localhost:
   ```powershell
   uvicorn api:app --host 0.0.0.0 --port 8000
   ```
2. Allow inbound connections to port 8000 (elevated PowerShell, one-time):
   ```powershell
   New-NetFirewallRule -DisplayName "UEBA API" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
   ```
3. Find this machine's IP address on the local network:
   ```powershell
   ipconfig
   ```
   Look for the `IPv4 Address` under your active network adapter (e.g.
   `192.168.1.42`). Employee machines will use this address.

**On each employee's machine**, copy over just two files —
`windows_event_collector.py` and `requirements-collector.txt` — no need
for the rest of the project:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements-collector.txt
```

Enable auditing (elevated terminal, one-time per machine):
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
```

Run the collector pointed at the central machine's IP instead of
`localhost`:
```powershell
python windows_event_collector.py --api-url http://192.168.1.42:8000
```
(replace `192.168.1.42` with whatever `ipconfig` showed on the central
machine).

Set this up as a Task Scheduler entry (same steps as section 6, "Running
it continuously") on each employee machine so it starts automatically and
keeps running without anyone needing to remember to launch it. Each
employee's activity will show up in your dashboard as its own entity,
named after their Windows username — automatically, on first event, no
manual registration needed. If they also sign up for a dashboard login
(section 5), make sure the entity name they enter there matches the
Windows username the collector reports, so their account links to the
right activity.

## 8. (Optional) Smoke-test the engine offline

`seed_demo.py` is still included as an offline sanity check for the
detection logic itself (synthetic events, no real log source needed) —
useful if you want to verify a new detector or threshold change behaves as
expected without waiting for real activity. It's not required for normal
use once the collector is running.

```bash
python seed_demo.py
```

## How detection works

Every event insert (`POST /events`) immediately runs through the engine
(`engine.process_event`), which:

1. Loads the **effective config** for that entity — its own override if one
   exists, otherwise the global default (`config.get_effective_config`).
2. Runs every enabled detector against the event.
3. Persists any anomalies found into the `anomalies` table.
4. Applies a per-rule **cooldown** (a fixed 30-minute internal constant) so
   a burst of bad events doesn't flood you with duplicate alerts.

If you ingest events some other way (bulk load, direct SQL insert), call
`POST /detect/run` to batch-process anything still marked `processed = false`.
This is also how you'd wire in a cron job / scheduler for periodic sweeps.

### Detectors included

This system now only detects three things — Impossible Travel, Rare
Resource Access, and Statistical Outliers were removed entirely (not just
disabled): their detector functions, their config fields, and the
`anomaly_cooldown_minutes` field (which was shared across all detectors,
not specific to those three) are all gone from the code and database.
Duplicate-alert suppression still works the same as before, just via a
fixed 30-minute internal constant instead of a configurable field.

| Rule | What it checks | Key adjustable fields |
|---|---|---|
| `off_hours_access` | **Login** events occurring outside configured working hours/days (handles overnight shifts; logoffs and other event types aren't checked against working hours) | `work_start`, `work_end`, `work_days`, `timezone`, `off_hours_enabled` |
| `excessive_failed_logins` | **Consecutive** failed logins since the entity's last successful login — no time window at all, so it detects the instant the count crosses a threshold, whether that takes 30 seconds or 3 days | none needed beyond the thresholds themselves |
| `excessive_data_transfer` | Too much data moved in a rolling window (file downloads/exfiltration) | `data_transfer_window_minutes` |

Every rule has an `<rule>_enabled` flag, toggleable per entity or globally
from **Settings → Thresholds & Working Hours** or via `PUT /config/default`
/ `PUT /config/{entity_id}`.

**All three use graduated severity instead of one fixed threshold.** Each
has four ascending thresholds — Low, Medium, High, Critical — and the
actual severity assigned is whichever band the observed value reached.
Below the Low threshold, nothing is flagged as an anomaly at all.

**Escalations always break through the cooldown.** Every rule suppresses
repeat alerts of itself for 30 minutes (so one burst of bad events doesn't
flood the anomalies table) — but if a new alert of the same rule would be
a *higher* severity than the most recent one, it's let through
immediately regardless of the cooldown. So a Low alert at attempt 5
doesn't block a Critical alert two minutes later at attempt 20.

On the dashboard, each of these three appears as a **clickable header** in
**Settings → Thresholds & Working Hours** — click "Off-hours Detection",
"Failed Login Detection", or "Data Transfer Detection" to expand a panel
showing its enabled checkbox, any extra settings (like the rolling time
window, where applicable), and all four severity range fields
(Low/Medium/High/Critical) at once, ready to edit together. Click the
header again to collapse it back. Every field's value is preserved
whether the panel is expanded or collapsed, so nothing is lost either way.

| Detector | Measured as | Default Low / Medium / High / Critical |
|---|---|---|
| `off_hours_access` | Hours outside the work window (time-of-day distance from `work_start`/`work_end`, plus a fixed 12-hour penalty if it's a non-work day at all) | 0 / 2 / 4 / 8 hours |
| `excessive_failed_logins` | Consecutive failed logins since the last success | 5 / 8 / 12 / 20 |
| `excessive_data_transfer` | Total MB moved within the window | 200 / 500 / 1000 / 2000 MB |

Because of the day-penalty, a login on a non-work day (e.g. Saturday
afternoon) reaches 12 hours of "deviation" by default — past the default
critical threshold of 8 — so it's always flagged critical regardless of
the time of day. Raise `off_hours_critical_hours` above 12 if you'd rather
weekend logins land in a lower tier.

## Adjusting thresholds & working hours

On the dashboard's **Settings → Thresholds & Working Hours** panel, the
Timezone field is a dropdown of 498 IANA zones (e.g. `Africa/Accra`,
`America/New_York`, `Asia/Tokyo`), each labeled with a friendly name and
offset where available — e.g. "Eastern Time - America/New_York
(GMT-04:00)". **Africa/Accra**, **GMT**, and **UTC** are pinned at the
top, with Africa/Accra as this system's default. If a config already has
a timezone value not in the list, it still shows up (marked "custom") so
nothing gets silently overwritten.

This list is a fixed dataset (`TIMEZONE_DATA` near the top of
`dashboard.html`'s `<script>` section, sourced from a reference IANA
zone/offset table and filtered to only the ~500 names Python's `zoneinfo`
on the backend actually recognizes — roughly 100 legacy aliases like
`US/Eastern` or `Jamaica` were excluded because selecting one would break
the off-hours detector with a server error). The offsets shown are a
snapshot, not live-computed — a zone that observes daylight saving will
show whichever offset was current when the dataset was built, not one
that silently updates across the year. To refresh it or add zones, edit
that array directly; each entry is a `[zone, offset]` pair.

**Global default** (applies to every entity without its own override):

```bash
curl -X PUT http://localhost:8000/config/default \
  -H "Content-Type: application/json" \
  -d '{
        "work_start": "09:00:00",
        "work_end": "18:00:00",
        "work_days": [0,1,2,3,4],
        "failed_login_low_threshold": 5,
        "failed_login_medium_threshold": 8,
        "failed_login_high_threshold": 12,
        "failed_login_critical_threshold": 20,
        "data_transfer_low_mb": 200,
        "data_transfer_medium_mb": 500,
        "data_transfer_high_mb": 1000,
        "data_transfer_critical_mb": 2000,
        "changed_by": "security-team"
      }'
```

**Per-entity override** (e.g. give one user a night shift and a higher
data-transfer allowance before it's flagged at all):

```bash
curl -X PUT http://localhost:8000/config/42 \
  -H "Content-Type: application/json" \
  -d '{
        "work_start": "22:00:00",
        "work_end": "06:00:00",
        "work_days": [0,1,2,3,4,5,6],
        "data_transfer_low_mb": 800,
        "data_transfer_medium_mb": 1500,
        "data_transfer_high_mb": 3000,
        "data_transfer_critical_mb": 6000,
        "changed_by": "security-team"
      }'
```

Send `DELETE /config/42` to remove that entity's override and revert it to
the global default. Every change (global or per-entity) is logged to
`config_audit_log` with old value, new value, who made the change, and when —
so threshold tuning stays auditable over time.

`work_days` uses `0=Monday .. 6=Sunday` (Python's `date.weekday()`
convention).

## Reviewing anomalies

The **Anomalies** view opens on an entity-grouped summary — one row per
entity with an anomaly (its unit, open count, total count, highest
severity present, and when it was last seen), not one row per individual
anomaly. Click an entity's row to drill into that entity's full anomaly
list (the same table as before, filtered to just them) — **← Back to All
Entities** returns to the summary. From there, click any anomaly row to
open its detail page as before.

```bash
# The entity-grouped summary itself
curl "http://localhost:8000/anomalies/by-entity?status=open"

# All open, high-severity anomalies for one entity
curl "http://localhost:8000/anomalies?entity_id=42&status=open&severity=high"

# Acknowledge one
curl -X PATCH http://localhost:8000/anomalies/17 \
  -H "Content-Type: application/json" \
  -d '{"status": "acknowledged"}'

# Mark as resolved / false positive
curl -X PATCH http://localhost:8000/anomalies/17 \
  -H "Content-Type: application/json" \
  -d '{"status": "false_positive", "resolved_by": "analyst_jane"}'

# Admin-only: permanently delete an anomaly record (not just change its status)
curl -X DELETE http://localhost:8000/anomalies/17
```

All of the above (except delete) work the same from the dashboard's
**Anomalies** view. The main table stays compact — click any row to open
its full detail page (description, plain-language detection details, and
the action buttons) without leaving the dashboard; **← Back to Anomalies**
returns you to the list. Admins additionally see a **Delete** button.

Everything on the detail page is written to be read, not decoded: rule
names show as "Excessive Failed Logins" rather than
`excessive_failed_logins`, weekdays show as "Monday" rather than `0`, and
the technical `details` a detector records (thresholds, timestamps,
z-scores, etc.) render as labeled plain-language lines instead of a raw
JSON blob. The underlying API still returns the raw `rule_name` string and
JSON `details` object exactly as before — this formatting happens only in
the dashboard's display layer, so anything scripting against the API
directly is unaffected.

**Resolved anomalies are treated as closed.** Once an anomaly's status is
`resolved`, no further action buttons (Ack, Resolve, False+, or Delete)
appear for it anywhere in the dashboard, whether in the table or on its
detail page — a resolved case stays resolved rather than inviting further
changes. This is enforced only in the dashboard UI, not the API itself:
`PATCH`/`DELETE` on a resolved anomaly still work if called directly, in
case you need to correct a mistaken resolution via `curl` or the API docs.

## Managing systems (entities) vs. managing users

These are two different things that are easy to conflate:

- An **entity** ("system") is a monitored machine/account — what shows up
  in **Manage Systems**. Deleting one removes its events/anomalies, but
  **does not** delete any dashboard login tied to it.
- A **user** is an actual dashboard login (username + password) — what
  shows up in **Manage Users**. This is what actually controls whether
  someone can sign in.

Deleting someone from **Manage Systems** does not revoke their ability to
log in — their `admin_users` row is untouched, just unlinked. To fully
remove their access, delete them from **Manage Users** instead (or use the
combined option below).

On the dashboard, admins have a **Manage Systems** sub-tab under
**Settings** — add a new system, and Restrict or Delete any existing one,
without touching the API directly. If the system you're deleting has a
login linked to it, you'll be asked whether to delete that login too in
the same action. The same actions via `curl`:

```bash
# Add a system
curl -X POST http://localhost:8000/entities \
  -H "Content-Type: application/json" \
  -d '{"name": "alice", "entity_type": "user", "department": "Finance"}'

# Restrict a system -- blocks it from reporting any further events
# (its history is kept; POST /events for this entity will now return 403)
curl -X PATCH http://localhost:8000/entities/42 \
  -H "Content-Type: application/json" \
  -d '{"is_active": false}'

# Unrestrict it again
curl -X PATCH http://localhost:8000/entities/42 \
  -H "Content-Type: application/json" \
  -d '{"is_active": true}'

# Check whether any login is linked to this system before deleting it
curl http://localhost:8000/entities/42/linked-users

# Delete the system only -- any linked login is kept, just unlinked
curl -X DELETE http://localhost:8000/entities/42

# Delete the system AND any login(s) linked to it, in one action
curl -X DELETE "http://localhost:8000/entities/42?also_delete_linked_users=true"

# Merge a duplicate system into another, keeping all history
curl -X POST http://localhost:8000/entities/42/merge/57
```

All of the above are admin-only.

### Merging duplicate systems

Windows sometimes reports the same physical machine/person under two
different names — a Microsoft account email for some events, the local
Windows username for others — which creates two separate entities for
what's really one system (e.g. `micha` and `michaelkesse5@gmail.com`
showing up as if they were different people).

On the dashboard, **Settings → Manage Systems** has a **"Merge duplicate
into..."** column: pick which system to keep from the dropdown next to
the duplicate, click **Merge**, confirm. This:

- Moves every event and anomaly from the duplicate onto the kept entity
  (nothing is lost — it all shows up as one history)
- Relinks any dashboard login that was tied to the duplicate
- Records the duplicate's old name as an **alias**, so if the collector
  reports that same name again in the future, it's automatically
  attributed to the kept entity instead of silently recreating the
  duplicate
- Deletes the now-empty duplicate entity

`POST /entities/{keep_id}/merge/{duplicate_id}` does the same thing via
the API — the URL order matters (`keep_id` first, `duplicate_id` second).

### Undoing a merge

Every merge is reversible, precisely. **Settings → Manage Systems → Merge
History** (below the systems table) lists every merge ever done, with an
**Unmerge** button on any that haven't already been reversed. Unmerging:

- Recreates the duplicate entity under its exact original name
- Moves back **exactly** the events and anomalies that were part of that
  specific merge — tracked by their actual record IDs at merge time, not
  "everything currently on the kept entity" — so it stays correct even if
  the kept entity has since been involved in other merges too
- Removes the alias, so the duplicate's name stops auto-resolving to the
  entity it was merged into
- Marks that merge as undone (each merge can only be unmerged once; if
  you need to redo it, just merge them again)

Via the API: `GET /entities/merges` lists merge history (add
`?active_only=false` to include already-undone ones);
`POST /entities/merges/{merge_id}/unmerge` reverses one by its ID (the ID
returned when you performed the merge, or found via the list endpoint).

## Grouping systems into units (departments)

Every entity has a `department` field it can be assigned to — used to
group monitored systems into organizational units like **Managers**,
**Human Resources (HR)**, **Finance and Accounting**, **Marketing**, and
**Sales**. This isn't a rigid enum in the database (it's still a plain
text column), but the dashboard presents it as a controlled dropdown so
names stay consistent, with an **Other...** option if you need something
not on the list.

**On the dashboard:**
- **Settings → Manage Systems**: pick a unit from the dropdown when adding
  a new system, and reassign any existing system's unit inline via the
  dropdown in its row — it saves immediately, no separate save button.
- **Anomalies view**: a **Unit** filter dropdown next to Status/Severity
  lets you narrow the anomalies list down to just one department at a
  time (e.g., only Finance and Accounting's activity).

**Via the API:**

```bash
# Add a system directly into a unit
curl -X POST http://localhost:8000/entities \
  -H "Content-Type: application/json" \
  -d '{"name": "alice", "entity_type": "user", "department": "Finance and Accounting"}'

# Reassign an existing system's unit
curl -X PATCH http://localhost:8000/entities/42 \
  -H "Content-Type: application/json" \
  -d '{"department": "Marketing"}'

# List every system in one unit
curl "http://localhost:8000/entities?department=Sales"

# List every anomaly for one unit
curl "http://localhost:8000/anomalies?department=Human%20Resources%20%28HR%29"
```

To change the list of available units, edit the `UNITS` array near the
top of the `<script>` section in `static/dashboard.html` — no backend
changes needed, since the department column already accepts any text.

## Feeding in other/additional real event sources

The Windows Event Log collector (section 5 above) is the primary real data
source for this setup, but you can point any other log pipeline (SIEM, auth
provider webhook, VPN gateway, EDR, etc.) at `POST /events` or
`POST /events/batch` the same way. Send either `entity_id` (if you've
pre-registered the entity via `POST /entities`) or `entity_name` (to
auto-create it on first sight, same as the Windows collector does).
`event_type` is the only other required field; everything else (geo, bytes
transferred, resource, status) is optional per event type but powers the
corresponding detector.

## Adding Windows troubleshooting for the collector

- **`Access denied reading the Security event log`**: run the terminal as
  Administrator, or add your account to the built-in **Event Log Readers**
  group (`lusrmgr.msc` on Pro/Enterprise; on Home edition use
  `net localgroup "Event Log Readers" YourUsername /add` from an elevated
  Command Prompt), then sign out and back in.
- **No events showing up at all**: confirm auditing is on —
  `auditpol /get /subcategory:"Logon"` should show Success/Failure both
  "Enabled". Re-run the `auditpol /set ...` commands from section 5 if not.
- **`requests` module not found**: make sure your venv is activated and
  `pip install -r requirements.txt` completed successfully.
- **Collector runs but the API shows nothing**: verify `--api-url` matches
  where `uvicorn` is actually listening, and that both the API and collector
  terminals have the same `DATABASE_URL` context if you're using
  per-terminal environment variables (the collector itself talks to the API
  over HTTP, not the database directly, so only the API's terminal needs
  `DATABASE_URL`).

## Security note

Auth here is deliberately simple: opaque session tokens with a 12-hour
expiry, PBKDF2-HMAC-SHA256 password hashing — all over plain HTTP. That's
appropriate for a **trusted local network** setup like this one (your
machine plus employee machines on the same network, per section 7). It is
*not* meant to be exposed to the open internet as-is; if you ever do that,
put it behind HTTPS (e.g. a reverse proxy with a TLS cert) first.

**Who can become what:**
- `admin` — only via `create_admin.py`, which requires running a command
  on the server machine itself. It cannot be self-registered through the
  dashboard or the `/auth/signup` API, even by editing the request — the
  endpoint rejects any role other than `analyst`/`employee`. Accounts
  created via the CLI (any role) are always immediately approved.
- `analyst` — can self-register via the dashboard's Sign Up tab, or be
  created via the CLI. Self-registered accounts are pending until an admin
  approves them. Scoped server-side to only see/act on anomalies for
  entities linked to an `employee` account.
- `employee` — can self-register via the dashboard's Sign Up tab (auto-
  linked to their monitored entity by username), or be created via the
  CLI. Self-registered accounts are also pending until approved — this
  matters even though employees have zero visibility into anomaly data,
  because without it, deleting someone's login wouldn't stop them from
  just registering again. `GET /anomalies` and `PATCH /anomalies/{id}`
  both return 403 for this role regardless of approval status, since the
  login exists purely as a credential, not as a way to view security data.

**On running the API with `--host 0.0.0.0`** (section 7, for reaching
employee machines on your LAN): this exposes the login and every endpoint
to anyone who can reach that IP and port on your network — still no
different in kind from localhost-only, just a larger trust boundary (your
whole LAN instead of just your machine). Don't do this on a network you
don't trust without adding HTTPS in front of it.

## Extending it

Add a new detector by writing a function with the signature
`detect(cur, entity_id, event, cfg) -> Optional[dict]` in `detectors.py` and
adding it to `ALL_DETECTORS`. Add any new tunable fields to the
`entity_config` table (schema.sql), `config.EDITABLE_FIELDS`, and
`models.ConfigUpdate` so they become adjustable through the same API pattern.

## Windows troubleshooting (database connection)

- **Collector silently stops printing anything for minutes at a time**:
  before this was fixed, a single PowerShell `Get-WinEvent` call with no
  timeout could hang indefinitely, freezing the entire collector until you
  manually pressed Ctrl+C — during which nothing gets detected at all,
  with no error message to explain why. The collector now aborts any
  PowerShell call that takes longer than 60 seconds and automatically
  continues to the next poll cycle, printing
  `PowerShell took longer than 60 seconds to respond and was aborted` to
  the terminal instead of hanging silently. If you see that message
  often, something (antivirus scanning, a very large Security log, disk
  contention) is making `Get-WinEvent` unusually slow on your machine.
- **`ZoneInfoNotFoundError: No time zone found with key GMT`** (or `UTC`,
  if you're on an older copy of this project): Windows doesn't ship the
  IANA timezone database that Python's `zoneinfo` module (used by the
  off-hours detector) needs. Fix: `pip install tzdata` (already in
  `requirements.txt`, but worth calling out since it's easy to miss on a
  fresh Windows setup and the error only surfaces once a real event is
  processed).
- **`password authentication failed` / connection refused**: confirm
  PostgreSQL is running via the **Services** app (look for
  `postgresql-x64-<version>`) — right-click → Start if it's stopped.
- **`no pg_hba.conf entry for host`**: open
  `C:\Program Files\PostgreSQL\<version>\data\pg_hba.conf`, make sure there's
  a line like `host all all 127.0.0.1/32 scram-sha-256`, save, then restart
  the PostgreSQL service from **Services**.
- **`psql` not recognized**: add
  `C:\Program Files\PostgreSQL\<version>\bin` to your PATH, or always call
  the full `psql.exe` path as shown above.
- **Port conflicts**: default PostgreSQL port is `5432` — check
  `C:\Program Files\PostgreSQL\<version>\data\postgresql.conf` if you
  changed it during install, and update `DATABASE_URL` to match.

## Files

- `schema.sql` — PostgreSQL schema (entities, events, config, baselines, anomalies, audit log, admin auth)
- `db.py` — connection pooling
- `config.py` — global default + per-entity config, with audit logging
- `auth.py` — email validation, password hashing, and session token management
- `create_admin.py` — CLI to create/reset admin or analyst logins (the only way to create an admin)
- `detectors.py` — the six anomaly-detection rules
- `engine.py` — runs detectors against events and persists findings
- `models.py` — Pydantic request/response schemas
- `api.py` — FastAPI application (login-protected except event ingestion)
- `static/dashboard.html` — browser dashboard with Sign In/Sign Up, role-based views, and a Settings panel for admins
- `windows_event_collector.py` — polls a machine's real Windows Security event log and feeds it into the API
- `requirements-collector.txt` — minimal dependencies (just `requests`) for deploying the collector on employee machines that don't run the full stack
- `seed_demo.py` — optional offline sanity check for the detection logic (no real log source needed)
