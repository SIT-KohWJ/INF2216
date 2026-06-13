# SITinform — Anonymous Whistleblowing Platform for SIT

A secure, web-based whistleblowing platform built exclusively for the Singapore Institute of Technology (SIT) community. Authenticated members can raise sensitive concerns — misconduct, policy violations, ethical issues — while staying anonymous from start to finish. Access is gated by SIT institutional email, but the platform is built so that **even an administrator with full database access cannot tell who submitted a report**: each report is tied to a one-way `HMAC-SHA256` hash of the user's ID rather than the ID itself, so the link between a person and their report can never be reversed.

Reports move through a clear lifecycle — **Received → Triaged → Investigating → Resolved** — and every administrative action is written to an append-only audit log.

> Module: ICT2213 — Secure Software Development · Team 13

---

## Team

The team works across two tracks: **Software Engineering** builds the application's features, and **Information Security** designs and verifies the controls that protect it.

| Name | Student ID | Track |
|---|---|---|
| Sudipta Kanti Biswas | 2303435 | Information Security |
| Leo Ting Cong | 2401085 | Information Security |
| Teo Wen Tian Brendan | 2401723 | Information Security |
| Glen Tan Qing Heng | 2401233 | Information Security |
| Darren Khong Wai Kidd | 2401309 | Software Engineering |
| Koh Wen Jun | 2401646 | Software Engineering |
| Muhammad Mikhail Bin Mazlan | 2402298 | Software Engineering |

---

## Roles

### Whistleblower
SIT students and staff who use the platform to raise concerns. They register with their SIT email, log in, and manage their own account. Once authenticated, they can submit a report — choosing a category and adding a title, description, and optional supporting files — and immediately receive a reference number confirming the submission. They can view and track only their own reports as those reports move through the status stages, receive notifications when something changes, and see a safe summary of the final outcome. They can log out securely at any time.

*Security behind it:* anonymity is enforced cryptographically (the user→report link is irreversible), passwords are hashed, sensitive fields and uploads are encrypted, and a whistleblower can only ever see their own reports.

### Investigator
Internal reviewers who handle the cases assigned to them. After logging in, an investigator sees a dashboard limited to their assigned reports. They can review the report's details and evidence, record notes and findings as the investigation progresses, update the report's status within the allowed workflow, recommend an outcome, and close cases they are authorised to close.

*Security behind it:* investigators can only open the reports and evidence assigned to them, every status change passes a server-side permission check, and all their actions are logged.

### Report Admin
Operators who manage the overall flow of reports. They get a dashboard of all incoming reports with statuses, categories, timestamps, and assigned investigators, and can search and filter across them. They triage new reports to decide whether an investigation is needed, assign investigators, update statuses, and manage each report through its full lifecycle. They can also view audit logs and review unusual activity such as repeated failed logins or bulk access.

*Security behind it:* admin actions are bounded by server-side role checks, audit-log access is restricted, and bulk or out-of-scope access to report content raises an alert.

### System Admin
Overseers of the platform itself rather than the reports. They create and manage user accounts, assign and adjust roles, and configure permissions according to least privilege. They can suspend accounts suspected of compromise, view system-level audit logs covering account, role, and access-control events, and manage security-related settings.

*Security behind it:* no user — including a System Admin — can grant themselves extra privileges or alter the audit log, and account management can never undo the platform's anonymity guarantee.

---

## Security Sprint (14 Jun – 30 Jun)

A **dedicated security sprint**: once the core SITinform features are in place, the whole team spends this sprint on application security alone. Every story in the sprint is security-related, and **all code is peer-reviewed before it is accepted** — no security story is "done" until another team member has reviewed it. The backlog is organised into the standard security-story types (authentication, authorisation, input validation, logging, and the technical risks such as XSS and SQL injection), with an added cryptography/anonymity story since that is the heart of this platform.

The Information Security members lead each story; the Software Engineering members implement the fixes and act as code reviewers.

### Sprint goal
Harden the platform so every feature is protected by its security controls, every control is tested (including a negative/abuse test), and every change has been code-reviewed before merge.

### Definition of Done (applies to every story)
- Implemented and enforced **server-side** (cannot be bypassed from the client).
- Covered by at least one test, including a negative test proving the attack it defends against is blocked.
- **Peer code-reviewed and approved** by another team member.
- No secrets, credentials, report content, or decrypted values written to logs.

### Backlog

**1. Authentication story** · *Lead: Leo · Review: Darren*
Restrict registration to `@singaporetech.edu.sg`, hash passwords with bcrypt, enforce a password-complexity policy, regenerate the session on login and privilege change, set hardened cookies (HttpOnly / Secure / SameSite), issue expiring JWTs, enforce login lockout / back-off, add a secure time-limited password reset, return non-enumerating auth errors, and invalidate sessions server-side on logout, password change, and account deletion.

**2. Authorisation story** · *Lead: Sudipta · Review: Wen Jun*
Enforce server-side role checks on every protected endpoint, define each role's permitted actions in a single central access-control policy (least privilege), verify report ownership on retrieval to block horizontal IDOR, use UUIDs as public identifiers to prevent enumeration, and prevent any user — including System Admin — from escalating their own privileges.

**3. Input validation story** · *Lead: Brendan · Review: Mikhail*
Apply server-side whitelist validation and length limits to every form input, and validate uploaded files by inspecting magic bytes (not the content-type header), sanitising filenames, and enforcing size limits.

**4. Technical risks: XSS, SQLi, CSRF** · *Lead: Glen · Review: Wen Jun*
Use SQLAlchemy parameterised queries only (no raw SQL) to stop SQL injection, sanitise input with bleach and rely on Jinja2 auto-escaping to stop XSS, apply Flask-WTF CSRF tokens to all state-changing requests, and rate-limit the login and report-submission endpoints to resist brute-force and mass submission.

**5. Logging story** · *Lead: Sudipta · Review: Brendan*
Maintain an append-only audit log of privileged actions with timestamps and the acting user's UUID and role, keep report content and decrypted values out of the logs to preserve anonymity, raise SIEM (Splunk) alerts on bulk or out-of-scope access, and ensure all endpoints use structured error handling so no stack traces leak.

**6. Cryptography & anonymity** · *Lead: Glen · Review: Darren*
Implement the HMAC-SHA256 anonymity engine so the user→report link is irreversible, encrypt sensitive fields and uploaded evidence at rest with AES-256-GCM, and serve all traffic over HTTPS. Record the key co-location gap (HMAC/AES keys on the app host, no separate trust domain) as a known limitation to carry into a future sprint.

### Schedule
| Dates | Focus | Stories |
|---|---|---|
| 14–18 Jun | Identity & access hardening | Authentication, Authorisation |
| 19–24 Jun | Input safety & data protection | Input validation, Technical risks (XSS/SQLi/CSRF), Cryptography & anonymity |
| 25–30 Jun | Monitoring & verification | Logging, full code review, security testing, sprint sign-off |

### Sprint exit criteria
The sprint is complete only when **every** story meets the Definition of Done, all code has been reviewed, and the security tests pass. If any security story is unfinished, the sprint is deemed incomplete and the platform is not released.

---

## Getting started

The application stack runs in Docker. PostgreSQL runs in two places — each developer runs their own copy locally, and one shared instance runs on the team's EC2 server for integration testing and the demo. Both use the same schema (`scripts/init.sql`) but hold separate data.

### Prerequisites
- Docker and Docker Compose (Docker Desktop on macOS/Windows; Docker Engine on the Linux VM)

### Setup files in the repo
| File | Purpose |
|---|---|
| `compose.yaml` | Local development setup (your laptop) |
| `compose.prod.yaml` | Shared EC2 server setup (hardened) |
| `scripts/init.sql` | Database schema — creates all 8 tables on first boot |
| `.env.example` | Template for environment variables (safe to commit) |
| `.env` | Real secrets — **never committed** (git-ignored) |

### Local development (compose.yaml)
Each person runs their own local database:

```bash
git pull
cp .env.example .env        # fill in your own local values (throwaway keys are fine)
docker compose up -d
docker compose exec db psql -U sitinform_user -d sitinform_db -c "\dt"
```

The last command should list all 8 tables. The local database is exposed on host port **5433** (not 5432) to avoid clashing with any native PostgreSQL already installed on your machine — so connect your app and database tools to `localhost:5433`. Inside Docker, Postgres is still on 5432.

> Each developer fills in their own `.env` from `.env.example`. Never commit `.env` — it holds the database password and cryptographic keys and is git-ignored.

---

## Security architecture (reference)

| Concern | Technology |
|---|---|
| Web framework | Python, Flask |
| Reverse proxy / TLS termination | Nginx |
| Database & ORM | PostgreSQL, SQLAlchemy |
| Anonymity engine | `hmac` + `hashlib` (HMAC-SHA256) |
| Auth & passwords | PyJWT, bcrypt |
| CSRF protection | Flask-WTF |
| Rate limiting | Flask-Limiter |
| XSS prevention | Bleach + Jinja2 auto-escaping |
| Encryption at rest | `cryptography` (AES-256-GCM) |
| IDOR prevention | UUID identifiers |
| SIEM / log aggregation | Splunk |

---

*Derived from ICT2213 Project Report 1 (SITinform secure-software requirements).*