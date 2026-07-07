-- ============================================================================
-- DEMO / SEED ACCOUNTS  — LOCAL DEVELOPMENT ONLY. NEVER MOUNT IN PRODUCTION.
--
-- These credentials are committed to the repository and therefore public.
-- compose.yaml (local dev) mounts this file into /docker-entrypoint-initdb.d/
-- alongside init.sql; compose.prod.yaml mounts ONLY init.sql, so a production
-- database never contains these accounts.
--
-- Runs on the FIRST boot of an empty volume (after init.sql, alphabetical
-- order). The block is idempotent (ON CONFLICT (email) ...), so it is also
-- safe to re-run by hand against a live dev container:
--   docker compose exec -T db psql -U sitinform_user -d sitinform_db < scripts/seed_dev.sql
--
-- Passwords are bcrypt-hashed INSIDE Postgres via pgcrypto's crypt()/gen_salt.
-- The resulting $2a$ hashes verify against the Python `bcrypt` library the app
-- uses. id values are generated here as uuid4-style strings to match the ORM.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO users (id, email, password_hash, first_name, last_name, role) VALUES
  (gen_random_uuid()::text, 'whistleblower1@sit.singaporetech.edu.sg', crypt('Password123!', gen_salt('bf', 12)), 'Whistleblower', 'One',  'whistleblower'),
  (gen_random_uuid()::text, 'whistleblower2@sit.singaporetech.edu.sg', crypt('Password123!', gen_salt('bf', 12)), 'Whistleblower', 'Two',  'whistleblower'),
  (gen_random_uuid()::text, 'investigator1@sit.singaporetech.edu.sg',  crypt('Password123!', gen_salt('bf', 12)), 'Investigator',  'One',  'investigator'),
  (gen_random_uuid()::text, 'reportadmin@sit.singaporetech.edu.sg',    crypt('Admin123!',    gen_salt('bf', 12)), 'Report',        'Admin','report_admin'),
  (gen_random_uuid()::text, 'sysadmin@sit.singaporetech.edu.sg',       crypt('Sysadmin123!', gen_salt('bf', 12)), 'System',        'Admin','system_admin')
ON CONFLICT (email) DO UPDATE
  SET password_hash = EXCLUDED.password_hash,
      role          = EXCLUDED.role,
      first_name    = EXCLUDED.first_name,
      last_name     = EXCLUDED.last_name,
      is_active     = TRUE;
