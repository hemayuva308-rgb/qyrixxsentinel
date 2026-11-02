# QYRIX SENTINEL — Disaster Recovery (v1.4)

## 1. What must survive, and where it lives

| Data | Location | In backups? | Notes |
|---|---|---|---|
| Evidence, provenance, approvals, evaluations, grants, tenants, API-key hashes, sessions, users, memberships, MFA material (TOTP secrets AES-GCM encrypted), installation id | PostgreSQL (`pgdata` volume) | yes (`db.dump.age`) | dumped with ownership so SECURITY DEFINER functions stay owned by NOLOGIN roles |
| Proof chains + anchors (per tenant) | `chain` volume | yes (`chain.tar.age`) | primary tamper-evident record |
| State witness (data-loss detector) | `witness` volume | **no, never** | the independent record that makes restores of older data visible |
| Secrets (`./secrets/*`), backup keys, operator tokens | host / secret store | **no** | back up separately in a password manager / HSM / escrow |

Losing `data_key` makes stored TOTP secrets unreadable (users re-enrol through an admin MFA reset). Losing
`state_witness_key` requires `app.recovery accept --reinitialize-witness`. Losing the backup *identity* makes every
backup encrypted to it unrecoverable — keep it in two offline places (or encrypt to an additional escrow recipient).

## 2. Backup design (scripts/backup.sh, backend/scripts/backup.py)
* **Order:** database FIRST, chain SECOND — the backend requires the DB proof mirror to be a prefix of the chain.
* **Encryption:** age (X25519 + ChaCha20-Poly1305 STREAM) to the public recipients in `QYRIX_BACKUP_RECIPIENTS_FILE`.
  The backup host cannot decrypt. Streams go straight into age: no plaintext on disk.
* **Tamper evidence:** age authenticates every chunk; the manifest (file names, SHA-256 of ciphertexts, install id,
  format) is HMAC-SHA256 signed with `QYRIX_BACKUP_SIGNING_KEY_FILE` (age has no sender authentication, so without the
  signature anyone holding the public key could produce a "valid" backup).
* **Access:** directory 700 / files 600; `backups/` is git-ignored; no HTTP route can serve backups (tested).
* **Off-site:** `QYRIX_BACKUP_UPLOAD_CMD` (e.g. `rclone copy {dir} offsite:qyrix`) runs on the finished encrypted
  directory only. Use object storage with versioning + object lock (WORM) and separate credentials.
* **Monitoring:** `backups/qyrix_backup.prom` (node_exporter textfile) → alert `QyrixBackupTooOld` (> 26 h).

Key setup (on an offline machine for the identity):
```bash
age-keygen -o backup.identity                 # PRIVATE - store offline, never on the backup host
age-keygen -y backup.identity > backup.recipients   # PUBLIC - copy to the backup host (add an escrow key line too)
openssl rand -hex 32 > backup.signing.key     # on the backup host AND with the identity (needed to verify)
```

## 3. Restore procedure (scripts/restore.sh)
1. Bring the identity and signing key to the restore host; `export QYRIX_BACKUP_IDENTITY_FILE=… QYRIX_BACKUP_SIGNING_KEY_FILE=…`.
2. `python3 backend/scripts/backup.py verify --from backups/<ts> --decrypt` (optional; restore.sh does it anyway).
3. `scripts/restore.sh backups/<ts> --yes` — verifies signature, hashes and full decryption **before** touching
   anything; stops the app; recreates roles; `pg_restore` in **one transaction** (failure ⇒ database unchanged);
   re-runs `migrate`; extracts the chain into a staging directory inside the volume and swaps it in (previous chain
   kept as `/data/.pre-restore-<ts>`); leaves the backend **stopped**.
4. `docker compose run --rm backend python -m app.recovery status` — compare install ids and chain lengths.
5. `docker compose run --rm backend python -m app.recovery accept --reason "<backup id> after <incident id>"`.
6. `docker compose start backend frontend`; check `/api/v1/ready`; the chain now ends with `RECOVERY_ACCEPTED`.
7. Grants/approvals issued after the backup no longer exist (safe: cannot execute); executions recorded in a newer
   chain but missing from an older DB are loaded as *used* (replay-safe; tested).

## 4. Integrity reasons and what they mean (app/integrity.py)

| Reason | Typical cause | Expected after a restore? |
|---|---|---|
| `PROOF_CHAIN_REGRESSED` | chain shorter than the witness mark: deletion, truncation, older restore | yes (accept) |
| `DATABASE_EVIDENCE_REGRESSED` | DB proof rows fewer than the mark | yes if the DB was restored alone; else investigate |
| `DATABASE_LOST_OR_REPLACED` | DB has no installation id while the witness has one | after a total loss, until restore |
| `DATABASE_EVIDENCE_EMPTIED` | identity row present but all evidence gone | no — investigate |
| `INSTALLATION_MISMATCH` / `_EXPECTED` | DB from another installation / config pin differs | no — wrong database? |
| `PROOF_CHAIN_DIVERGED` | different history at the marked position | no — tampering or wrong chain |
| `WITNESS_MISSING` / `WITNESS_FORGED_OR_WRONG_KEY` / `WITNESS_UNREADABLE` | witness volume lost / altered / key rotated | no — investigate, then `--reinitialize-witness` |
| `EXPECTED_INSTALLATION_MISSING` | everything gone but `QYRIX_EXPECTED_INSTALL_ID` is set | total loss — restore |
| `WITNESS_NOT_CONFIGURED` / `WITNESS_KEY_*` | misconfiguration | fix configuration |

Trust assumptions: an attacker who can modify the database **and** the chain volume **and** the witness volume **and**
read the witness key, with no `QYRIX_EXPECTED_INSTALL_ID` configured, can make a total loss look like a fresh install
(tested and documented as a limitation). Put the witness on different storage and set `QYRIX_EXPECTED_INSTALL_ID`.

## 5. RPO / RTO — assumptions and the only measurement available

| | Value | Basis |
|---|---|---|
| RPO | = backup interval (recommended ≤ 24 h, daily alert at 26 h) | no WAL archiving / PITR implemented |
| RTO (technical, small data) | restore 0.21 s + boot 0.07 s for 2 000 decisions (`evidence/dr-drill.json`); Compose restore script 4.0 s on a small dataset (`evidence/production-hardening-v1.4.txt`) | single host, local disk, synthetic data |
| RTO (real) | **not measured** | excludes detection, decision, key retrieval, provisioning, off-site download, large datasets |

No disaster-recovery guarantee is claimed. Before production: WAL archiving / PITR, a timed restore of a
production-sized dataset from off-site storage, and a quarterly drill with the on-call team.

## 6. Key rotation
* **Backup recipients:** add the new public key to the recipients file (old backups stay decryptable with the old
  identity — keep it until they expire under the retention policy), then remove the old recipient.
* **Signing key:** new backups use the new key; keep the old one to verify old backups (or re-sign after verifying).
* Other keys: see `docs/OPERATIONS.md` §4.
