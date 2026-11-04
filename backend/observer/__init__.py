"""Qyrix Observer Service (Phase C, slices C1-C2).

Separate process (`python -m observer.main`), separate database (observer-db, migration O001), separate keys. It
imports NOTHING from the backend package `app` (gateway, persistence, identity): the helpers it needs (canonical
JSON, hash chain, Ed25519) are vendored here, so a backend bug or compromise cannot change how the observer checks it.

Implemented (C1): signed ingest (envelope, signatures, scopes, tenants, replay, skew, conflicts), key manifest signed by
the offline root key, gap-free sequence watermarks, heartbeats, epochs and quarantine, window-closure state machine,
signed hash-chained ledger, health/status. NOT implemented (C3-C7): sensors, canaries, coverage, reconciliation. With
no sensor there is no observer-originated evidence, so nothing here can ever produce ENFORCEMENT_VERIFIED.
"""
FORMAT_EVENT = "qyrix.event/v1"
