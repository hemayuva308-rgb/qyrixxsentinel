-- Phase C2 (design §10): observer outbox, gap-free event counter, heartbeat counter, grants.execution_id. ADDITIVE ONLY.
-- * New tables and one nullable column (metadata-only ALTER); nothing existing is dropped, rewritten or reset.
-- * Inactive until QYRIX_OBSERVER_URL is set: no row is written to these tables otherwise.
-- * Rollback: unset QYRIX_OBSERVER_URL. The tables stay (no destructive down-migration).
--
-- Least privilege (tighter than the §10 sketch, same intent): the runtime role has NO direct INSERT on the outbox and
-- NO UPDATE on either counter. Allocation + outbox insert happen only inside SECURITY DEFINER functions owned by the
-- NOLOGIN role qyrix_feed, called in the SAME transaction as the decision/grant write. So the runtime account can
-- neither skip nor rewind a number, nor change the epoch; epochs change only through the operator recovery tool
-- (`python -m app.recovery observer-epoch`, admin account + operator recovery key, §5.4).

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_feed') THEN
    CREATE ROLE qyrix_feed NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END $$;
DO $$ BEGIN EXECUTE format('GRANT qyrix_feed TO %I', current_user); END $$;
GRANT USAGE ON SCHEMA public TO qyrix_feed;

-- heartbeat counter per producer; its `epoch` column is the producer's CURRENT epoch (§5.1, §5.4)
CREATE TABLE IF NOT EXISTS observer_hb_seq (
  producer_id text PRIMARY KEY,
  epoch       integer NOT NULL DEFAULT 1 CHECK (epoch >= 1),
  n           bigint  NOT NULL DEFAULT 0 CHECK (n >= 0)
);

-- gap-free event counter per (tenant, epoch); the outbox key includes the epoch because seq restarts at 1 per epoch
CREATE TABLE IF NOT EXISTS observer_seq (
  tenant_id text    NOT NULL,
  epoch     integer NOT NULL CHECK (epoch >= 1),
  n         bigint  NOT NULL CHECK (n >= 0),
  PRIMARY KEY (tenant_id, epoch)
);

CREATE TABLE IF NOT EXISTS observer_outbox (
  tenant_id   text        NOT NULL,
  epoch       integer     NOT NULL,
  seq         bigint      NOT NULL CHECK (seq >= 1),
  event_id    uuid        NOT NULL UNIQUE,
  producer_id text        NOT NULL,
  type        text        NOT NULL CHECK (type IN ('decision', 'grant')),
  body        jsonb       NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
  sent_at     timestamptz,
  attempts    integer     NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, epoch, seq)
);
CREATE INDEX IF NOT EXISTS observer_outbox_unsent ON observer_outbox (tenant_id, epoch, seq) WHERE sent_at IS NULL;

ALTER TABLE grants ADD COLUMN IF NOT EXISTS execution_id uuid;     -- set at INSERT (table-level INSERT, 003)

ALTER TABLE observer_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE observer_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON observer_outbox TO qyrix_app USING (tenant_id = qyrix_tenant()) WITH CHECK (tenant_id = qyrix_tenant());
CREATE POLICY feed_write ON observer_outbox FOR INSERT TO qyrix_feed WITH CHECK (tenant_id = qyrix_tenant());
CREATE POLICY feed_read ON observer_outbox FOR SELECT TO qyrix_feed USING (true);         -- counts only (qyrix_observer_feed)
CREATE POLICY maint_prune ON observer_outbox FOR ALL TO qyrix_maint USING (sent_at IS NOT NULL);

REVOKE ALL ON observer_outbox, observer_seq, observer_hb_seq FROM PUBLIC;
GRANT SELECT ON observer_outbox TO qyrix_app;
GRANT UPDATE (sent_at, attempts) ON observer_outbox TO qyrix_app;
GRANT SELECT, INSERT ON observer_outbox TO qyrix_feed;
GRANT SELECT, INSERT, UPDATE ON observer_seq, observer_hb_seq TO qyrix_feed;
GRANT SELECT, DELETE ON observer_outbox TO qyrix_maint;

-- allocate the next gap-free seq of the CURRENT tenant and write the outbox row (caller's transaction)
CREATE OR REPLACE FUNCTION qyrix_observer_emit(p_producer text, p_type text, p_event_id uuid, p_body jsonb)
RETURNS TABLE (out_epoch integer, out_seq bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  t text := nullif(current_setting('qyrix.tenant_id', true), '');
  e integer;
  s bigint;
BEGIN
  IF t IS NULL THEN RAISE EXCEPTION 'observer emit requires a tenant context'; END IF;
  IF p_producer IS NULL OR p_producer !~ '^gate:[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'invalid producer id'; END IF;
  INSERT INTO public.observer_hb_seq AS h (producer_id) VALUES (p_producer) ON CONFLICT (producer_id) DO NOTHING;
  SELECT h.epoch INTO e FROM public.observer_hb_seq h WHERE h.producer_id = p_producer FOR SHARE;
  INSERT INTO public.observer_seq AS o (tenant_id, epoch, n) VALUES (t, e, 1)
    ON CONFLICT (tenant_id, epoch) DO UPDATE SET n = o.n + 1
    RETURNING o.n INTO s;                                   -- row lock: concurrent writers serialize; rollback undoes
  INSERT INTO public.observer_outbox (tenant_id, epoch, seq, event_id, producer_id, type, body)
    VALUES (t, e, s, p_event_id, p_producer, p_type, p_body);
  RETURN QUERY SELECT e, s;
END $$;

-- next heartbeat number (outside event transactions; gaps allowed) and the producer's current epoch
CREATE OR REPLACE FUNCTION qyrix_observer_next_hb(p_producer text)
RETURNS TABLE (out_epoch integer, out_hb_seq bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE e integer; n_ bigint;
BEGIN
  IF p_producer IS NULL OR p_producer !~ '^gate:[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'invalid producer id'; END IF;
  INSERT INTO public.observer_hb_seq AS h (producer_id, n) VALUES (p_producer, 1)
    ON CONFLICT (producer_id) DO UPDATE SET n = h.n + 1
    RETURNING h.epoch, h.n INTO e, n_;
  RETURN QUERY SELECT e, n_;
END $$;

-- feed metadata across tenants for the publisher/heartbeat: counters and unsent counts only, never event content
CREATE OR REPLACE FUNCTION qyrix_observer_feed(p_producer text)
RETURNS TABLE (out_tenant text, out_epoch integer, out_allocated bigint, out_unsent bigint, out_stale_unsent bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE e integer;
BEGIN
  SELECT h.epoch INTO e FROM public.observer_hb_seq h WHERE h.producer_id = p_producer;
  e := coalesce(e, 1);
  RETURN QUERY
    SELECT s.tenant_id, s.epoch, s.n,
           (SELECT count(*) FROM public.observer_outbox o WHERE o.tenant_id = s.tenant_id AND o.epoch = s.epoch AND o.sent_at IS NULL),
           (SELECT count(*) FROM public.observer_outbox o WHERE o.tenant_id = s.tenant_id AND o.epoch < e AND o.sent_at IS NULL)
      FROM public.observer_seq s WHERE s.epoch = e ORDER BY s.tenant_id;
END $$;

-- operator maintenance: prune rows already delivered (EXECUTE granted to nobody; run with the admin account)
CREATE OR REPLACE FUNCTION qyrix_observer_prune(p_before timestamptz) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE c bigint;
BEGIN
  DELETE FROM public.observer_outbox WHERE sent_at IS NOT NULL AND sent_at < p_before;
  GET DIAGNOSTICS c = ROW_COUNT;
  RETURN c;
END $$;

ALTER FUNCTION qyrix_observer_emit(text, text, uuid, jsonb) OWNER TO qyrix_feed;
ALTER FUNCTION qyrix_observer_next_hb(text) OWNER TO qyrix_feed;
ALTER FUNCTION qyrix_observer_feed(text) OWNER TO qyrix_feed;
ALTER FUNCTION qyrix_observer_prune(timestamptz) OWNER TO qyrix_maint;
REVOKE ALL ON FUNCTION qyrix_observer_emit(text, text, uuid, jsonb), qyrix_observer_next_hb(text),
                       qyrix_observer_feed(text), qyrix_observer_prune(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qyrix_observer_emit(text, text, uuid, jsonb), qyrix_observer_next_hb(text),
                          qyrix_observer_feed(text) TO qyrix_app;
GRANT EXECUTE ON FUNCTION qyrix_tenant() TO qyrix_feed;
