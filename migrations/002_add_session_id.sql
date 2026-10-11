-- 002_add_session_id.sql
--
-- A session is one login on one device, identified by session_id. Rotations
-- keep the session; reuse revocation and logout scope to it, so two logins
-- that happen to share a device_name no longer share a fate.
--
-- Rows issued before this migration are backfilled with the old group
-- identity, user_id || ':' || device_name, so a replay of a pre-migration
-- token revokes the same set of rows the old code would have. New logins
-- get a UUID, which cannot collide with that form.

ALTER TABLE access_tokens ADD COLUMN session_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN session_id TEXT NOT NULL DEFAULT '';

UPDATE access_tokens SET session_id = user_id || ':' || device_name WHERE session_id = '';
UPDATE refresh_tokens SET session_id = user_id || ':' || device_name WHERE session_id = '';

-- The (user_id, device_name) index served the old group-scoped revocation;
-- device_name is informational now, so keep only the user_id prefix.
DROP INDEX idx_refresh_tokens_user_device;
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
