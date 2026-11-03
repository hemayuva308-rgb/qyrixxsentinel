# Red-team case generator (v1.5 P2, phase A)

`backend/app/redteam.py`: an offline-capable generator and isolated runner for adversarial Gate test cases.

## Security model
- **The LLM only writes candidate test cases.** Its reply is untrusted data. Every case goes through, in order:
  1. a strict Pydantic schema (unknown fields refused, sizes bounded, rule and refusal codes allow-listed);
  2. a safety filter: only synthetic RFC 2606 hosts (`*.example.com/.net/.org`, `.example`, `.test`, `.invalid`),
     IP literals for SSRF probes and workspace-relative files are allowed, and real-credential formats (AWS, GitHub,
     Slack, Google, OpenAI-style keys, private keys, JWTs) are rejected;
  3. deduplication by a content fingerprint.
- **The model cannot approve its own cases.** It cannot set `test_id`, `review_status`, `reviewer` or `repro`; the
  generator overwrites them. Model output stays `candidate` until a human runs `review --approve`.
- **The deterministic Gate decides every case.** The model's expected outcome is only compared with the Gate's
  actual decision. A wrong expectation is flagged `EXPECTATION_REVIEW`; it never changes the decision.
- **Runs are isolated.** Each case gets a fresh GateContext: synthetic approved hosts, a temporary synthetic
  workspace, and the sandbox adapter for every tool, so there is no network, no real file read and no command.
  The runner records egress per case and treats any egress as `ERROR_EGRESS`. The production proof chain is never
  touched.
- **Not a production dependency.** The API process never imports `app.redteam`, and a test checks this. Provider
  failure raises `GenerationUnavailable`: nothing is generated and nothing falls back silently.

## Case schema
Each case carries:
- `test_id` (content fingerprint), `category` (15 attack categories + `safe_control`), `threat`, `severity`;
- `tool`, `action`, `target`, `payload`, `command`;
- optional `setup` provenance steps, `filler_steps`, `lineage_from`, `approved_claim`, `mcp` (derived through the MCP
  proxy's own mapping code) and `misuse` (`cross_agent`, `delegation`, `cross_task`, `policy_change`, `replay`,
  `digest_tamper`);
- `expected` {decision, rules, enforcement};
- `repro` {generator, generator_version, provider, model, prompt_version, prompt_sha256, source_sha256, seed,
  temperature, created_at}.

## Usage
```bash
cd backend
python -m app.redteam generate --generator template --seed 7 --per-category 3 --out cases.jsonl
python -m app.redteam generate --generator llama --provider meta --per-category 2 --out cases.jsonl --save-response raw.json
python -m app.redteam generate --generator llama --replay-response raw.json --out cases.jsonl   # deterministic, offline
python -m app.redteam review cases.jsonl --approve <test_id> ... --reviewer <name>
python -m app.redteam run cases.jsonl --report report.json [--include-candidates]
```
- **Live generation** needs `META_API_KEY` + `META_MODEL` (or `BASETEN_API_KEY` + `BASETEN_MODEL`) set as environment
  secrets. Models whose ID contains "contributor" are refused unless `QYRIX_ALLOW_CONTRIBUTOR_MODEL=1`.
- **Replay is tamper-evident:** the stored reply must match its recorded SHA-256.
- **Stored case files are re-validated on load**, including the schema, the safety filter and the ID/content match.

## Status and results (honest)
- **Live Llama generation is NOT verified.** No provider credentials are configured in this environment. The provider
  path is tested with a mock transport only: request shape, repro metadata, failures, off-schema replies, and the model
  trying to self-approve.
- **The committed corpus is template-generated, not model output.** `evidence/redteam/template-v1.cases.jsonl` has 40
  reviewed cases covering all 16 categories, generated with seed 7. Its report is
  `evidence/redteam/template-v1.report.json`. These are preliminary, synthetic tests, not a security guarantee.
- **Synthetic secrets are low-entropy** (`sk-synth-aaaa`): the Gate's detector still matches them, and secret
  scanners do not mistake them for real credentials. No scanner suppression was added.

| Run | Attack cases stopped | False negatives | Safe controls allowed | False positives | Egress |
|---|---|---|---|---|---|
| Phase A (commit `65e7174`, before hardening) | 33 / 36 | 3 | 3 / 3 | 0 | 0 |
| After R19 + R20 (this change) | **37 / 37** | **0** | 3 / 3 | 0 | 0 |

After the hardening, single-run latency was p50 0.18 ms, p95 0.31 ms and p99 0.59 ms. This is in-process
evaluation only and noisy. The corpus gained two cases: a right-to-left override in a host, and an UNVERIFIED skill
triggering a PUT.

### Findings and fixes (owner-approved)
| Finding (Phase A) | Fix | Regression tests |
|---|---|---|
| Untrusted lineage POSTs non-secret data to an **approved** host → ALLOW | **R19_UNTRUSTED_STATE_CHANGE** (details below) | `tests/test_gate_hardening.py`: the verbatim finding plus positive and negative cases |
| Zero-width characters in an approved host (`a\u200bp\u200bi.partner.example.com`) → ALLOW | **R20_DECEPTIVE_HOSTNAME** (strict canonicalization) | same file: verbatim finding plus 14 deceptive variants |
| Fullwidth dots (`api\uff0epartner\uff0eexample\uff0ecom`) → ALLOW | R20 | same file: verbatim finding |

**R19.** For `http` POST, PUT, PATCH and DELETE, if any instruction in the lineage is tainted (UNTRUSTED or
UNVERIFIED, directly or inherited), the action is blocked **even to an approved host**:
- **Approved destinations are not enough.** The only override is a valid human approval of this exact action. Approvals
  are bound to the action's digest, are single-use and expire, and agents cannot approve.
- **Unaffected:** trusted-lineage state changes, and reads (GET/HEAD) after untrusted input.
- **Missing lineage still fails closed** (R13), and R1, R2, R3 and R7 are unchanged and still fire.

**R20.** Host names are canonicalized strictly, using the pinned `idna` 3.20 library (IDNA2008, RFC 5891–5893):
- **Refused:** invisible, format and bidi-control characters; look-alike dots (fullwidth, ideographic, halfwidth and
  others); compatibility forms (NFKC differs); non-NFC text; and labels that mix scripts. Han may combine with kana or
  Hangul.
- **Malformed names give R1.** Empty or over-long labels, a leading or trailing hyphen, reserved `??--` labels, and
  punycode that does not round-trip are rejected as malformed.
- **Accepted:** genuine single-script IDNs, such as German, Russian, Japanese, Hindi and Greek names.
- **One unambiguous form:** policy comparison, logs, proof records and the `dest_host` response field all use the
  **A-label** (`xn--…`). Allowlist entries are canonicalized the same way, so a Unicode entry and its A-label match
  the same host. Refused hosts are logged with invisible characters made visible (`\u200b`).

The Gate engine version moved to `gate-rules/2026-11-03.2`. By the P1 design this invalidates grants issued under
the previous rules, and a test covers it.

### Remaining limitation (documented and tested)
**Whole-script homographs** are not detected: an all-Cyrillic `\u0430\u0440\u0440\u04cf\u0435` that looks like
"apple" is a legal single-script IDN. It is shown only as its A-label (`xn--…`) and can never match the ASCII
allowlist entry it imitates, so it is NOT_APPROVED. Detecting it as a confusable would need Unicode confusables data
(UTS #39); that is not implemented.

## Not covered yet
- No public benchmarks yet (AgentDojo, InjecAgent): Phase B, after a licence review.
- Delegation abuse is modelled as one credential's grant used by another. There is no real multi-agent runtime.
- Per-adapter CEV bypass detection is covered by `tests/test_cev.py`, not by this runner.
