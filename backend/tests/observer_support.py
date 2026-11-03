"""Shared helpers for observer tests: a throwaway REAL PostgreSQL cluster for observer-db (separate from any backend
cluster), test keys, a root-signed manifest, signed envelopes and a controllable clock."""
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone

from observer import crypto, migrate as omigrate
from observer.canonical import canonical
from observer.db import Database
from observer.feed import Config
from observer.ingest import Observer
from observer.manifest import Manifest, sign_manifest
from tests.test_persistence import PG_BIN, HAVE_PG, _free_port  # noqa: F401  (HAVE_PG re-exported)

T0 = 1_800_000_000.0           # fixed observer time base for deterministic tests


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


class ObserverCluster:
    """initdb + pg_ctl in a temp dir; O001 applied by the ADMIN account; tests use observer_runtime (least privilege)."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="qyrix-obsdb-")
        self.port = _free_port()
        self.as_user = ["runuser", "-u", "postgres", "--"] if os.geteuid() == 0 else []
        if self.as_user:
            shutil.chown(self.dir, "postgres")
        self._pg("initdb", "-D", self.dir + "/data", "-A", "trust", "-U", "observer_admin")
        self._pg("pg_ctl", "-D", self.dir + "/data", "-w", "-o",
                 "-p %d -k %s -c listen_addresses=127.0.0.1" % (self.port, self.dir), "-l", self.dir + "/log", "start")
        self.admin_url = "postgresql://observer_admin@127.0.0.1:%d/postgres" % self.port
        omigrate.migrate(self.admin_url)
        self.url = "postgresql://observer_runtime@127.0.0.1:%d/postgres" % self.port

    def new_db(self):
        """A fresh, migrated database in this cluster; returns (runtime_url, admin_url)."""
        name = "obs_" + uuid.uuid4().hex[:12]
        import psycopg
        with psycopg.connect(self.admin_url, autocommit=True) as c:
            c.execute("CREATE DATABASE %s" % name)
        admin = "postgresql://observer_admin@127.0.0.1:%d/%s" % (self.port, name)
        omigrate.migrate(admin)
        return "postgresql://observer_runtime@127.0.0.1:%d/%s" % (self.port, name), admin

    def _pg(self, tool, *args):
        subprocess.run(self.as_user + [os.path.join(PG_BIN, tool), *args], check=True, capture_output=True)

    def admin(self, sql, params=(), url=None):
        import psycopg
        with psycopg.connect(url or self.admin_url, autocommit=True) as c:
            return c.execute(sql, params).fetchall() if sql.lstrip().upper().startswith("SELECT") else c.execute(sql, params)

    def destroy(self):
        try:
            self._pg("pg_ctl", "-D", self.dir + "/data", "-w", "-m", "fast", "stop")
        except Exception:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


class Keys:
    def __init__(self):
        self.root, self.observer, self.gate, self.adapter, self.recovery, self.other = (crypto.generate() for _ in range(6))
        self.install_id = str(uuid.uuid4())
        self.gate_pid = "gate:" + self.install_id
        self.adapter_pid = "adapter:mcp_proxy"

    def kid(self, k):
        return crypto.describe(k)[0]

    def entry(self, k, **extra):
        kid, pub = crypto.describe(k)
        return {"key_id": kid, "public_key": pub, "valid_from": iso(1_000_000_000), **extra}

    def manifest_doc(self, version=1, tenants=("*",), observer_extra=None, gate_extra=None, adapter_tenants=("default", "tenant-b")):
        return {"manifest_version": version, "issued_at": iso(T0),
                "observer_keys": [self.entry(self.observer, **(observer_extra or {}))],
                "producers": [
                    {"producer_id": self.gate_pid, "tenants": list(tenants),
                     "keys": [self.entry(self.gate, scopes=["decision", "grant", "heartbeat"], **(gate_extra or {}))]},
                    {"producer_id": self.adapter_pid, "tenants": list(adapter_tenants),
                     "keys": [self.entry(self.adapter, scopes=["adapter_report"])]}],
                "recovery_keys": [self.entry(self.recovery)]}

    def manifest(self, **kw) -> Manifest:
        return Manifest(sign_manifest(self.manifest_doc(**kw), self.root), self.root_pub())

    def root_pub(self):
        return crypto.describe(self.root)[1]


def envelope(key, producer_id, type_, body, tenant="default", seq=None, hb_seq=None, epoch=1, issued=T0,
             event_id=None, key_id=None):
    env = {"schema": "qyrix.event/v1", "event_id": event_id or str(uuid.uuid4()), "producer_id": producer_id,
           "key_id": key_id or crypto.describe(key)[0], "epoch": epoch, "seq": seq, "hb_seq": hb_seq,
           "issued_at": iso(issued), "tenant": tenant, "type": type_, "body": body}
    env["sig"] = crypto.sign(key, canonical(env))
    return env


def raw(env):
    return json.dumps(env).encode()


def decision(keys, seq, tenant="default", epoch=1, **kw):
    body = kw.pop("body", {"gate_evaluation_id": str(uuid.uuid4()), "verdict": "BLOCK", "rule_ids": ["R1_DEST_NOT_APPROVED"]})
    return envelope(keys.gate, keys.gate_pid, "decision", body, tenant=tenant, seq=seq, epoch=epoch, **kw)


def heartbeat(keys, hb_seq, tenants, epoch=1, issued=T0, **kw):
    body = {"gate_clock": iso(issued), "outbox_depth": 0, "tenants": tenants}
    return envelope(keys.gate, keys.gate_pid, "heartbeat", body, tenant=None, hb_seq=hb_seq, epoch=epoch, issued=issued, **kw)


def make_observer(url, keys, clock=None, manifest=None, cfg=Config()) -> Observer:
    obs = Observer(Database(url), manifest or keys.manifest(), keys.observer, cfg, clock or Clock())
    obs.install_manifest()
    return obs
