"""Encrypted, tamper-evident backup / restore of Qyrix Sentinel durable state (v1.4).

WHAT is backed up: PostgreSQL (all tenants' evidence, identity, keys, sessions, users, MFA material - already encrypted
at the application layer where secret) and the proof chain files. NOT backed up, on purpose: the state witness
(app/integrity.py) - it is the independent record that makes restoring old data visible - and any keys or secrets.

ENCRYPTION: age (https://age-encryption.org, X25519 + ChaCha20-Poly1305 STREAM). Files are encrypted to one or more
PUBLIC recipients (QYRIX_BACKUP_RECIPIENTS_FILE, `age -R`); the backup host never holds a decryption key. The private
identity (QYRIX_BACKUP_IDENTITY_FILE) is needed only to restore and is kept offline / in escrow. No plaintext is ever
written to disk: pg_dump and the chain tar are streamed straight into age.

TAMPER EVIDENCE: age authenticates every chunk (any modified byte => decryption fails). Because age has no sender
authentication (anyone with the public recipient can encrypt), the manifest - file names, SHA-256 of each ciphertext,
format, timestamp, installation id - is HMAC-SHA256 signed with QYRIX_BACKUP_SIGNING_KEY_FILE. Swapped, truncated,
re-encrypted or forged files are rejected BEFORE anything is restored.

ORDERING: database FIRST, chain SECOND (the backend requires the DB proof mirror to be a prefix of the chain).

RESTORE is staged: verify signature + hashes -> trial-decrypt everything (wrong key / corruption => stop, nothing
touched) -> pg_restore in ONE transaction (failure => database unchanged) -> chain extracted to a staging directory
and swapped in only after the database succeeded (failure => previous chain put back) -> migrations re-applied.
The backend then reports RECOVERY_REQUIRED (restored data is older than the witness) until an operator runs
`python -m app.recovery accept --reason ...` - restoring old data is never silent.

    python scripts/backup.py backup  --chain-dir /data --out /backups/2026-11-02T0600Z
    python scripts/backup.py verify  --from /backups/2026-11-02T0600Z [--decrypt]
    python scripts/backup.py restore --chain-dir /data --from /backups/2026-11-02T0600Z [--force]
Admin DB connection (never the runtime account): QYRIX_ADMIN_DATABASE_URL or QYRIX_DB_HOST + QYRIX_DB_ADMIN_*.
Off-site copy: QYRIX_BACKUP_UPLOAD_CMD (e.g. `rclone copy {dir} offsite:qyrix`) runs on the finished, encrypted
directory only.
"""
import argparse, glob, hashlib, hmac, io, json, os, shlex, shutil, subprocess, sys, tarfile, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FORMAT = "qyrix-backup/2"
FILES = ("db.dump.age", "chain.tar.age")


class BackupError(SystemExit):
    pass


def _pg_env(dsn: str):
    """Split the password out of the DSN so it is passed through the environment, never argv (visible in `ps`)."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    d = conninfo_to_dict(dsn)
    pw = d.pop("password", None)
    env = dict(os.environ)
    if pw:
        env["PGPASSWORD"] = pw
    return make_conninfo(**d), env


def _tool(name: str) -> str:
    for d in [os.getenv("QYRIX_PG_BIN", "")] + sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True):
        if d and os.path.exists(os.path.join(d, name)):
            return os.path.join(d, name)
    p = shutil.which(name)
    if not p:
        raise BackupError("%s not found" % name)
    return p


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _keyfile(env: str, what: str, min_len: int = 0) -> str:
    p = os.getenv(env, "").strip()
    if not p or not os.path.exists(p):
        raise BackupError("%s not configured (%s)" % (what, env))
    if min_len and len(open(p, "rb").read().strip()) < min_len:
        raise BackupError("%s too short (%s)" % (what, env))
    return p


def _sign_key() -> bytes:
    return open(_keyfile("QYRIX_BACKUP_SIGNING_KEY_FILE", "backup signing key", 32), "rb").read().strip()


def _canon(m: dict) -> bytes:
    return json.dumps(m, sort_keys=True, separators=(",", ":")).encode()


def _age_encrypt_cmd():
    return [_tool("age"), "--encrypt", "-R", _keyfile("QYRIX_BACKUP_RECIPIENTS_FILE", "backup recipients (public keys)")]


def _age_decrypt_cmd():
    return [_tool("age"), "--decrypt", "-i", _keyfile("QYRIX_BACKUP_IDENTITY_FILE", "backup identity (private key)")]


def _install_id(conn, env):
    try:
        out = subprocess.run([_tool("psql"), "--no-psqlrc", "-tA", "-c", "SELECT install_id FROM installation", "--dbname", conn],
                             env=env, capture_output=True, text=True, check=True).stdout.strip()
        return out or None
    except Exception:
        return None


# ---------------- backup ----------------
def backup(dsn: str, chain_dir: str, out: str) -> dict:
    sign = _sign_key()                                      # fail before doing any work if keys are missing
    enc = _age_encrypt_cmd()
    os.makedirs(out, mode=0o700, exist_ok=False)            # never overwrite an existing backup
    os.chmod(out, 0o700)
    conn, env = _pg_env(dsn)
    t0 = time.time()
    try:
        # 1) database FIRST: pg_dump (custom format, ownership kept) streamed straight into age
        with open(os.path.join(out, FILES[0]), "wb") as f:
            age = subprocess.Popen(enc, stdin=subprocess.PIPE, stdout=f, stderr=subprocess.PIPE)
            dump = subprocess.Popen([_tool("pg_dump"), "--format=custom", "--dbname", conn], stdout=age.stdin, stderr=subprocess.PIPE, env=env)
            age.stdin.close()
            dump_err = dump.communicate()[1]
            age_err = age.communicate()[1]
            if dump.returncode or age.returncode:
                raise BackupError("database dump failed: %s %s" % (dump_err.decode()[-300:], age_err.decode()[-200:]))
        # 2) chain files SECOND, tar streamed into age
        with open(os.path.join(out, FILES[1]), "wb") as f:
            age = subprocess.Popen(enc, stdin=subprocess.PIPE, stdout=f, stderr=subprocess.PIPE)
            with tarfile.open(fileobj=age.stdin, mode="w|") as tar:
                if os.path.isdir(chain_dir):
                    for root, _, files in os.walk(chain_dir):
                        for name in sorted(files):
                            if name.endswith(".jsonl"):
                                p = os.path.join(root, name)
                                tar.add(p, arcname=os.path.relpath(p, chain_dir))
            age.stdin.close()
            if age.wait():
                raise BackupError("chain encryption failed: " + age.stderr.read().decode()[-200:])
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)              # never leave a half-written backup that looks valid
        raise
    m = seal(out, _install_id(conn, env), t0)
    cmd = os.getenv("QYRIX_BACKUP_UPLOAD_CMD", "").strip()
    if cmd:                                                  # off-site boundary: only encrypted files leave the host
        r = subprocess.run(shlex.split(cmd.replace("{dir}", out)), capture_output=True)
        m["offsite"] = "ok" if r.returncode == 0 else "FAILED"
        if r.returncode:
            raise BackupError("off-site upload failed (backup kept locally at %s)" % out)
    return m


def seal(out: str, install_id, t0: float) -> dict:
    """Write the HMAC-signed manifest for the encrypted files in `out` (also used by scripts/backup.sh)."""
    sign = _sign_key()
    m = {"format": FORMAT, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)), "order": list(FILES),
         "install_id": install_id or None, "encryption": "age (X25519, ChaCha20-Poly1305)",
         "files": {n: {"sha256": _sha(os.path.join(out, n)), "bytes": os.path.getsize(os.path.join(out, n))} for n in FILES},
         "duration_seconds": round(time.time() - t0, 3)}
    for n in FILES:
        if not open(os.path.join(out, n), "rb").read(22).startswith(b"age-encryption.org/v1"):
            raise BackupError("%s is not an age file - refusing to seal plaintext" % n)
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump({"manifest": m, "hmac_sha256": hmac.new(sign, _canon(m), hashlib.sha256).hexdigest()}, f, indent=2)
    for n in FILES + ("manifest.json",):
        os.chmod(os.path.join(out, n), 0o600)
    return m


# ---------------- verify ----------------
def verify(src: str, decrypt: bool = False) -> dict:
    p = os.path.join(src, "manifest.json")
    if not os.path.exists(p):
        raise BackupError("manifest.json missing")
    try:
        doc = json.load(open(p))
        m, mac = doc["manifest"], doc["hmac_sha256"]
    except Exception:
        raise BackupError("manifest unreadable") from None
    if not hmac.compare_digest(hmac.new(_sign_key(), _canon(m), hashlib.sha256).hexdigest(), str(mac)):
        raise BackupError("manifest signature invalid (forged, altered or wrong signing key)")
    if m.get("format") != FORMAT or list(m.get("files", {})) != list(FILES):
        raise BackupError("unknown backup format")
    for n, meta in m["files"].items():
        f = os.path.join(src, n)
        if not os.path.exists(f):
            raise BackupError("backup file %s missing" % n)
        if _sha(f) != meta["sha256"]:
            raise BackupError("backup file %s does not match its manifest hash (corrupted, swapped or tampered)" % n)
    if decrypt:                                              # full trial decryption: authenticates every age chunk
        for n in FILES:
            with open(os.path.join(src, n), "rb") as f:
                r = subprocess.run(_age_decrypt_cmd(), stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if r.returncode:
                raise BackupError("cannot decrypt %s (wrong identity or corrupted ciphertext)" % n)
    return m


# ---------------- restore ----------------
def restore(dsn: str, chain_dir: str, src: str, force: bool = False) -> dict:
    m = verify(src, decrypt=True)                            # nothing is touched before this succeeds
    existing = [f for _, _, fs in os.walk(chain_dir) for f in fs if f.endswith(".jsonl")] if os.path.isdir(chain_dir) else []
    if existing and not force:
        raise BackupError("chain directory is not empty; stop the backend and pass --force to replace it")
    parent = os.path.dirname(os.path.abspath(chain_dir.rstrip("/"))) or "/"
    staging = tempfile.mkdtemp(prefix=".qyrix-restore-", dir=parent)
    try:
        # decrypt + extract the chain into STAGING first (validates the archive before the DB is changed)
        with open(os.path.join(src, FILES[1]), "rb") as f:
            age = subprocess.Popen(_age_decrypt_cmd(), stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            data = age.stdout.read()
            if age.wait():
                raise BackupError("chain decryption failed")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
            tar.extractall(staging, filter="data")           # no absolute paths / traversal / devices / links out
        # database: roles, then ONE transaction (any failure => rollback, database unchanged), then migrations
        conn, env = _pg_env(dsn)
        from app import migrate as _migrate
        _migrate.ensure_roles(dsn)
        with open(os.path.join(src, FILES[0]), "rb") as f:
            age = subprocess.Popen(_age_decrypt_cmd(), stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            r = subprocess.run([_tool("pg_restore"), "--clean", "--if-exists", "--single-transaction", "--exit-on-error",
                                "--dbname", conn], stdin=age.stdout, env=env, capture_output=True)
            age.stdout.close()
            if age.wait() or r.returncode:
                raise BackupError("database restore failed and was rolled back (database unchanged): %s" % r.stderr.decode()[-300:])
        _migrate.migrate(dsn)
        # chain: swap staging in; on failure put the previous chain back
        old = None
        if os.path.isdir(chain_dir):
            old = chain_dir.rstrip("/") + ".pre-restore-%d" % int(time.time())
            os.replace(chain_dir, old)
        try:
            os.replace(staging, chain_dir)
        except BaseException:
            if old:
                os.replace(old, chain_dir)
            raise
        staging = None
        if old:
            shutil.rmtree(old, ignore_errors=True)
    finally:
        if staging and os.path.isdir(staging):
            shutil.rmtree(staging, ignore_errors=True)
    return {**m, "restored": True,
            "next": "start the backend: it reports RECOVERY_REQUIRED until `python -m app.recovery accept --reason ...`"}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["backup", "restore", "verify", "seal"])
    ap.add_argument("--install-id", default="")
    ap.add_argument("--started", type=float, default=0.0)
    ap.add_argument("--chain-dir")
    ap.add_argument("--out")
    ap.add_argument("--from", dest="src")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--decrypt", action="store_true", help="verify: also trial-decrypt (needs the identity)")
    a = ap.parse_args(argv)
    if a.cmd == "verify":
        print(json.dumps(verify(a.src, a.decrypt), indent=2)); return 0
    if a.cmd == "seal":
        print(json.dumps(seal(a.out, a.install_id, a.started or time.time()), indent=2)); return 0
    from app import persistence                          # only backup/restore need the app (seal/verify are stdlib + age)
    dsn = persistence.admin_dsn_from_env()
    if not dsn:
        raise BackupError("no administrative database connection configured")
    out = backup(dsn, a.chain_dir, a.out) if a.cmd == "backup" else restore(dsn, a.chain_dir, a.src, a.force)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
