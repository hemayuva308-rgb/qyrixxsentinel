# QYRIX SENTINEL — narration (≈ 3:00, ~140 words/min)

Read at a calm pace. Bracketed text is the on-screen action. Do not ad-lib numbers: every figure you say must be visible on screen.

**0:00 – Problem** *[homepage hero, slow scroll to "The problem"]*
> AI agents now read instructions and call real tools — APIs, files, deployments. The danger isn't only a bad prompt.
> A malicious line can hide in a trusted-looking skill, survive being summarised, and arrive twenty steps later.
> Monitoring tells you after the tool already ran. Detection is not prevention.

**0:25 – Skill Inspection** *[dashboard → paste the skill README → INSPECT; add provenance steps]*
> Here's a third-party skill. Qyrix Sentinel's Skill Inspector finds an unapproved destination and a credential reference.
> The Llama classifier gives an advisory label — advisory only, it can never allow an action.
> The README is UNVERIFIED. The agent turns it into its own plan and calls that plan trusted — but provenance says no:
> a child can never be more trusted than its source. It stays UNVERIFIED.

**0:55 – Attack Simulation** *[fill the Execution Gate with the attack, select the plan step, CHECK SECURITY]*
> Now the agent tries to act: a POST to an unknown host, carrying a synthetic API key, derived from that untrusted README.

**1:30 – Execution Gate** *[point at BLOCK, the three rules, no execute button, external calls]*
> Blocked — before execution. Destination not approved, secret exfiltration, untrusted lineage.
> No grant was issued, so there is nothing to execute, and external calls stay at zero. The decision is deterministic policy, not AI.

**2:00 – Verifiable Proof** *[forensic lab → VERIFY CHAIN → SIMULATE TAMPER]*
> Every decision is recorded before anything runs, as canonical JSON chained with SHA-256.
> If anyone edits one record, verification fails at that record. We report partial-unanchored, not pass,
> because this deployment has no external timestamp authority configured — and we don't claim what we haven't verified.

**2:30 – Safe Execution** *[trusted operator step, file.read README → ALLOW → EXECUTE WITH GRANT]*
> Blocking attacks must not stop real work. A trusted task is allowed, gets a single-use grant bound to its exact parameters,
> and executes through the controlled adapter.

**2:50 – Impact** *[homepage final CTA]*
> Put a checkpoint between your AI and every tool.
> **Qyrix Sentinel — Secure Every AI Action. Before Execution.**

---
If Meta Llama is live-verified before recording, replace "The Llama classifier gives an advisory label" with
"Meta Llama classifies it as untrusted — advisory only" **only if the badge on screen shows the live provider**.
If an RFC 3161 TSA is configured and ANCHOR HEAD shows PASS, replace the last two lines of 2:00 with:
"The chain head is anchored with an RFC 3161 trusted timestamp — anyone can verify it with OpenSSL. Verification: PASS."
