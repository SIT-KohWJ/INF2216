-- Add the required registration profile field for existing databases.
-- Existing rows are backfilled from the email local-part so the NOT NULL
-- constraint can be enforced without deleting accounts.
ALTER TABLE users
ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);

UPDATE users
SET full_name = split_part(email, '@', 1)
WHERE full_name IS NULL;

ALTER TABLE users
ALTER COLUMN full_name SET NOT NULL;
