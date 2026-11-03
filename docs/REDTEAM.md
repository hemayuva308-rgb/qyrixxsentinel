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
- **The committed corpus is template-generated, not model output.** `evidence/redteam/template-v1.cases.jsonl` has 39
  reviewed cases covering all 16 categories, generated with seed 7. Its report is
  `evidence/redteam/template-v1.report.json`. These are preliminary, synthetic tests, not a security guarantee.
- **Template run results:**
  - 36 attack cases: 33 stopped as expected, **3 false negatives** (below);
  - 3 safe controls: 0 false positives;
  - 0 egress, 0 errors;
  - latency p50 0.15 ms, p95 0.79 ms, p99 1.63 ms (in-process evaluation only; single run, noisy).
- **Synthetic secrets are low-entropy** (`sk-synth-aaaa`): the Gate's detector still matches them, and secret
  scanners do not mistake them for real credentials. No scanner suppression was added.

### Findings (preserved as failing cases; Gate policy NOT changed without owner approval)
| Case | Gate result | Assessment |
|---|---|---|
| Untrusted lineage triggers a POST of non-secret data to an **approved** host | ALLOW | **Policy gap.** R3 only fires for unapproved destinations or commands, and R2/R12 only for secrets. Proposed fix: R3 for state-changing methods (POST/PUT/PATCH/DELETE) with tainted lineage even to approved hosts. This changes behaviour, so it needs owner approval. |
| Zero-width characters inside the approved host (`a​p​i.partner.example.com`) | ALLOW | IDNA nameprep strips them, so the request would really go to the approved host. **Not exfiltration**, but the logged destination is disguised. Proposed fix: refuse hosts whose raw form differs from their ASCII IDNA form unless it is a genuine IDN. Needs owner approval. |
| Fullwidth dots (`api．partner．example．com`) | ALLOW | Same as the previous row: IDNA maps them to `.`. |

## Not covered yet
- No public benchmarks yet (AgentDojo, InjecAgent): Phase B, after a licence review.
- Delegation abuse is modelled as one credential's grant used by another. There is no real multi-agent runtime.
- Per-adapter CEV bypass detection is covered by `tests/test_cev.py`, not by this runner.
