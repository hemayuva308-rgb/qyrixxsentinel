-- QYRIX OBSERVER - O005: egress authorization lookup (final C5 hardening, audit N2). ADDITIVE; observer-db only.
-- The egress proxy must decide, for an X-Qyrix-Execution id, whether a SIGNED, SEQUENCED grant claim exists for it -
-- without knowing the tenant. This adds ONE read-only SECURITY DEFINER function owned by the NOLOGIN role
-- observer_lookup (created in O002), a read policy for that role on `events`, and an expression index. It returns
-- routing / authorization fields only; nothing is altered or removed.

CREATE INDEX IF NOT EXISTS events_grant_execution ON events ((envelope->'body'->>'execution_id')) WHERE type = 'grant';
CREATE INDEX IF NOT EXISTS events_decision_eval ON events ((envelope->'body'->>'gate_evaluation_id')) WHERE type = 'decision';

GRANT SELECT ON events, streams, producers TO observer_lookup;
CREATE POLICY lookup_read ON events FOR SELECT TO observer_lookup USING (true);

CREATE OR REPLACE FUNCTION observer_grant_lookup(p_exec text)
RETURNS TABLE (out_tenant text, out_kinds text[], out_first_issued timestamptz, out_verdict text, out_dest_host text,
               out_stream_ok boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH g AS (
    SELECT e.tenant_id, e.producer_id, e.epoch, e.envelope->'body'->>'kind' AS kind, e.issued_at,
           e.envelope->'body'->>'gate_evaluation_id' AS geid
      FROM public.events e
     WHERE e.type = 'grant' AND e.envelope->'body'->>'execution_id' = p_exec
       AND p_exec ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ), d AS (
    SELECT e.envelope->'body'->>'verdict' AS verdict, e.envelope->'body'->>'dest_host' AS dest_host,
           e.envelope->'body'->>'reversed_from' AS reversed_from
      FROM public.events e JOIN g ON e.tenant_id = g.tenant_id
     WHERE e.type = 'decision' AND e.envelope->'body'->>'gate_evaluation_id' = g.geid
  )
  SELECT min(g.tenant_id), array_agg(DISTINCT g.kind), min(g.issued_at) FILTER (WHERE g.kind = 'issued'),
         CASE WHEN bool_or(d.reversed_from IS NOT NULL) THEN 'REVERSED' ELSE min(d.verdict) END,
         min(d.dest_host),
         bool_and(EXISTS (SELECT 1 FROM public.streams s JOIN public.producers p ON p.producer_id = s.producer_id
                           WHERE s.producer_id = g.producer_id AND s.epoch = g.epoch AND s.status = 'active'
                             AND p.current_epoch = s.epoch))
    FROM g LEFT JOIN d ON true
  HAVING count(g.*) > 0 AND count(DISTINCT g.tenant_id) = 1      -- an id claimed in two tenants is never authorised
$$;
ALTER FUNCTION observer_grant_lookup(text) OWNER TO observer_lookup;
REVOKE ALL ON FUNCTION observer_grant_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION observer_grant_lookup(text) TO observer_runtime;
