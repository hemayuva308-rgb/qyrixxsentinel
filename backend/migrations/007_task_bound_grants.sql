-- v1.5 P1: agent-, task- and policy-version-bound grants. ADDITIVE ONLY.
-- * New nullable columns, no defaults => metadata-only ALTER (no table rewrite), existing rows untouched (NULL).
-- * Nothing is dropped, renamed or reset. Rolling back the application leaves these columns unused.
-- * Privileges unchanged on purpose: the runtime role's table-level SELECT/INSERT (003) covers the new columns, and its
--   UPDATE stays limited to (used_at, revoked_at, revoked_by) - the runtime account can never rewrite a grant's binding.
-- * Legacy rows (NULL agent_id / policy_version) can no longer be consumed through the API: the atomic consume requires
--   an exact binding match (fail closed). Grants live for QYRIX_GRANT_TTL_SECONDS (default 120 s), so this affects
--   at most the grants in flight during the upgrade.
ALTER TABLE grants
  ADD COLUMN IF NOT EXISTS agent_id       text,
  ADD COLUMN IF NOT EXISTS task_id        text,
  ADD COLUMN IF NOT EXISTS policy_version char(64);

ALTER TABLE gate_evaluations
  ADD COLUMN IF NOT EXISTS agent_id       text,
  ADD COLUMN IF NOT EXISTS task_id        text,
  ADD COLUMN IF NOT EXISTS policy_version char(64),
  ADD COLUMN IF NOT EXISTS correlation_id text;
