// Honest status of each security gate in THIS build. Keep in sync with security/security-gates/*.md.
// IMPLEMENTED = code exists; TESTED = automated test executed in this repo; PARTIAL = part of the control missing;
// NOT RUN = verification step not executed; NOT IMPLEMENTED = absent.
export type GateStatus = "TESTED" | "PARTIAL" | "NOT IMPLEMENTED";
export const SECURITY_GATES: { id: string; name: string; status: GateStatus; done: string; open: string }[] = [
  { id: "SG-01", name: "No direct egress", status: "PARTIAL",
    done: "Only the controlled adapter performs requests, and only for a valid single-use grant. Evaluation never resolves DNS. Blocked actions make zero external calls (tested).",
    open: "Egress is measured by an in-process counter; a network-level egress firewall on the containers is not configured or tested." },
  { id: "SG-02", name: "Default deny & schema validation", status: "TESTED",
    done: "Unknown tool, destination, label or lineage blocks. Strict request models; /tools/execute rejects any client parameter with 400 CLIENT_PARAMS_NOT_ALLOWED before lookup.", open: "-" },
  { id: "SG-03", name: "SSRF defence", status: "PARTIAL",
    done: "Loopback, private, link-local, NAT64/6to4/Teredo, userinfo and numeric-host tricks blocked; all A/AAAA answers validated; IP pinned; no second lookup; redirects never followed and re-gated (max 5).",
    open: "TLS SNI/certificate behaviour of the pinned request is not verified against a live host; DNS has no explicit timeout." },
  { id: "SG-04", name: "Secret handling & file jail", status: "TESTED",
    done: "Secrets redacted before storage, proof records and AI calls. File reads are descriptor-relative with O_NOFOLLOW, no symlinks, no traversal, regular files only, 1 MB limit.", open: "Secret pattern is broad and can over-match." },
  { id: "SG-05", name: "Approval replay & atomicity", status: "TESTED",
    done: "Approvals are exact-scope, expiring and single-use; consumed atomically with grant creation; 20 parallel resubmissions yield exactly one grant; failures roll back.", open: "State is in memory (lost on restart)." },
  { id: "SG-06", name: "Audit / proof integrity", status: "PARTIAL",
    done: "Canonical JSON SHA-256 hash chain, written before execution, fsync'd; tampered, reordered or missing records FAIL; empty bundle rejected; offline verifier.",
    open: "No external WORM/S3 Object Lock anchoring: best result is PARTIAL_UNANCHORED. Clock-anomaly handling not implemented." },
  { id: "SG-07", name: "RBAC & ownership", status: "PARTIAL",
    done: "Every API call authenticated; admin vs agent roles; agents cannot approve, reset or run the benchmark.",
    open: "No organisations, tenants, per-object ownership or the full role set (owner, reviewer, auditor...). Multi-tenancy is not implemented." },
  { id: "SG-08", name: "UI quality & no secret leakage", status: "PARTIAL",
    done: "API token kept in an httpOnly SameSite=Strict cookie; same-origin proxy with CSRF header; no secrets in the browser bundle; public demo shows only redacted fixtures.",
    open: "No Content-Security-Policy header yet; no automated accessibility test suite." },
];
