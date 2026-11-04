# Hackathon submission text (fill the `<…>` placeholders, then paste into the portal)

Portal fields: project title and description, demo video link (YouTube), public GitHub repo link, which Meta models you used.

## Project title
Qyrix Sentinel: Trust Every Execution. Verify Every Action.

## One-line description
A deterministic security checkpoint between AI agents and their tools: authorize before execution, control outbound egress, and keep verifiable evidence, with Meta's model as an advisory second opinion.

## Short description (about 300 characters)
AI agents call real tools, and a poisoned README can make them leak secrets. Qyrix Sentinel puts a deterministic Gate in front of every protected action: scoped single-use grants, controlled egress, and tamper-evident evidence. Meta's model classifies and explains risky text, but can never allow an action.

## Full description
**The problem.** Once an AI agent can call tools, the question is no longer only what it says but what it is allowed to do. Prompt filters and logs can raise an alert, but they do not guarantee that the final action was safe.

**What we built.** Qyrix Sentinel is a Trust-to-Execution Guard.
- A **deterministic, default-deny Gate** evaluates each protected action (destination, method, data, provenance) and returns ALLOW with a short-lived, single-use grant bound to the exact request, or BLOCK with rule IDs.
- **Trust provenance:** every instruction source carries a trust label, and a derived step can never be more trusted than its ancestors.
- **Controlled egress:** supported outbound calls go through a proxy that opens a tunnel only for an execution with a recorded, redeemed grant.
- **Verifiable evidence:** hash-linked records verified offline, plus a separate Observer service. We keep adapter self-reports (E1) apart from independently observed evidence (E3), and missing evidence is reported as INCONCLUSIVE.
- **Integrations (prototypes):** MCP over stdio and Streamable HTTP, and an n8n custom HTTP node.

**New: AI attacks, AI judges, the Gate decides.** A Llama model hosted on Baseten writes adversarial test cases; every reply is treated as untrusted (strict schema, safety filter, dedupe) and run through the real Gate in an isolated sandbox with zero network egress. A Meta Muse model acts as an advisory judge on the same cases, and we report a 2x2 of "AI flagged or missed" against "Gate blocked or allowed". Result of our live run: `<fill from campaign.json: attack cases N, stopped M, candidate bypasses K, live AI missed but Gate blocked J>`. `<If you did not run it live, delete this whole paragraph; the code and offline tests exist, but we must not claim results we do not have.>`

**A real model as the agent.** `scripts/meta_agent_demo.py` lets a Meta (or Baseten-hosted Llama) model act as a deliberately trusting agent. It reads a poisoned README, proposes tool calls on its own, and the real Gate evaluates each one in isolation (nothing executed, no network). Its reply is untrusted: strict parse, allow-listed tools, unknown fields refused. Result of our live run: `<fill from the printed outcome: for example INJECTION_FOLLOWED_GATE_BLOCKED, or INJECTION_RESISTED_BY_MODEL; say exactly what happened>`. `<If you did not run it live, delete this paragraph.>`

**How we use Meta.** The Meta Model API classifies untrusted instruction text and explains why it looks risky. Only redacted, bounded text is sent, off-schema model output is discarded, and if the API is unreachable the system falls back to a deterministic heuristic and says so on screen. The model is advisory only; authorization is deterministic policy, by design.

**What we verified.** Backend suite 1116 passed (1 skipped), including real PostgreSQL suites; a 10-case benchmark with 7/7 attacks blocked and 0 false positives on safe tasks; mutation checks that deliberately break the n8n node and egress-proxy security checks and confirm the tests catch each one; independent audit findings listed openly in the repository.

**Honest limits.** Prototype, not production-ready, not independently certified. It protects only traffic that passes through its adapters, and egress control depends on network isolation around the protected workload. n8n support covers one custom node on self-hosted n8n 2.46.5, not n8n Cloud and not other nodes.

**Themes.** Build for Your World (a real problem for anyone deploying AI agents); Push the Frontier (execution-time enforcement with verifiable evidence rather than detection alone).

## Meta models used
- Meta Model API, model id: `<fill: the exact value you set in META_MODEL and verified with scripts/verify_meta.py>`, used for advisory classification and explanation of untrusted instruction text.
- Agent under test (only if you ran the agent demo): the model id you set in `META_MODEL` or `BASETEN_MODEL`: `<fill>`.
- Attack generator (only if you ran the campaign): a Llama model on Baseten, model id `<fill>`.
- Advisory judge (only if you ran it): a Meta Muse model, model id `<fill>`.
- List **only** models you actually called. Do not list others.

## Links
- Public GitHub repo: https://github.com/hemayuva308-rgb/qyrixxsentinel
- Demo video (YouTube): `<fill after upload; make sure it opens without logging in>`
- Live deployment (optional): `<fill or delete this line>`

## How a judge can run it
```bash
printf 'QYRIX_ADMIN_TOKEN=%s\nQYRIX_AGENT_TOKEN=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
# optional, live Meta classifier: printf 'META_API_KEY=...\nMETA_MODEL=<model id>\n' >> .env
mkdir -p secrets && for f in db_admin_password db_runtime_password state_witness_key data_key client_sig_key; do openssl rand -hex 32 > secrets/$f; done && chmod 644 secrets/*
docker compose up --build   # http://127.0.0.1:3000, sign in at /login with the admin token
```

## YouTube description (paste under the video)
Qyrix Sentinel is a deterministic security checkpoint between AI agents and the tools they call. This 3-minute demo shows Meta's model flagging a poisoned instruction live, the Gate blocking the exfiltration, and tamper-evident evidence. The model is advisory only; the Gate decides.
Prototype, not production-ready. Code: https://github.com/hemayuva308-rgb/qyrixxsentinel
Timestamps: 0:00 hook · 0:15 live Meta classification · 0:50 trust chain · 1:15 Gate blocks · 2:15 evidence · 2:40 limits
