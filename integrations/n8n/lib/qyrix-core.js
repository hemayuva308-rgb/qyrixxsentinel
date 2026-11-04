'use strict';
/*
 * Qyrix Sentinel - n8n integration core (Phase 1A PROTOTYPE, n8n 2.46.5 self-hosted only).
 *
 * Holds NO policy. The deterministic Sentinel Gate is the only authority:
 *   deploymentCheck() -> refuses to run unless the pinned n8n hardening settings are present (fail closed)
 *   buildRequest()  -> strict allow-list validation, one frozen request object (what will be sent, byte for byte).
 *                      Phase 1A remediation: GET and HEAD only, https on port 443 only.
 *   toAction()      -> the existing Gate Action contract  {tool:'http', method, dest, cmd:'', data, lineage, correlation_id, task_id}
 *   paramsDigest()  -> the Gate's params_digest, reproduced exactly (app/gateway.py _digest)
 *   authorize()     -> POST /api/v1/sentinel/gate/evaluate (must be ALLOW) -> POST /api/v1/tools/redeem (single use)
 *   send()          -> ONLY through the C5 egress proxy: CONNECT <pinned-ip>:443 + X-Qyrix-Host + X-Qyrix-Execution,
 *                      then TLS (SNI + certificate verification for the hostname). There is no direct-network path.
 * Every failure is a QyrixError with a stable code, safe identifiers (correlation / evaluation / execution id) and an
 * explicit outcome: NOT_SENT, NOT_SENT_GRANT_CONSUMED (redeemed, nothing reached the upstream) or UNKNOWN (bytes may
 * have reached the upstream). Nothing here logs. Tokens never appear in errors. Output is an E1 adapter self-report: never independent evidence, never ENFORCEMENT_VERIFIED.
 */
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const dns = require('dns');

const INTEGRATION = 'n8n_http';                       // X-Qyrix-Integration (app/api.py: ^[a-z0-9_-]{1,64}$)
const LIMITS = Object.freeze({ DATA_MAX: 65536, DEST_MAX: 2048, HEADERS_MAX: 20, HEADER_VALUE_MAX: 4096,
  LINEAGE_MAX: 50, GATE_RESPONSE_MAX: 1 << 20, UPSTREAM_RESPONSE_MAX: 1 << 20 });
// Phase 1A remediation: state-changing methods are NOT supported. Provenance labels are caller-declared, so the Gate's
// lineage rules (R13/R19) cannot be relied on to authorise a state change from a workflow (security review HIGH-2).
const METHODS = new Set(['GET', 'HEAD']);
const UPSTREAM_PORT = 443;                             // the egress proxy only accepts tagged CONNECT to 443
// n8n 2.46.5 node types that can run code, read local files (the token file) or reach the network outside this node.
// NODES_EXCLUDE must name ALL of them (setting NODES_EXCLUDE replaces n8n's own defaults).
const REQUIRED_NODES_EXCLUDE = Object.freeze([
  'n8n-nodes-base.code', 'n8n-nodes-base.function', 'n8n-nodes-base.functionItem', 'n8n-nodes-base.executeCommand',
  'n8n-nodes-base.ssh', 'n8n-nodes-base.ftp', 'n8n-nodes-base.git', 'n8n-nodes-base.httpRequest',
  'n8n-nodes-base.readWriteFile', 'n8n-nodes-base.readBinaryFile', 'n8n-nodes-base.readBinaryFiles',
  'n8n-nodes-base.writeBinaryFile', 'n8n-nodes-base.localFileTrigger',
  '@n8n/n8n-nodes-langchain.code', '@n8n/n8n-nodes-langchain.toolCode', '@n8n/n8n-nodes-langchain.toolHttpRequest',
  '@n8n/n8n-nodes-langchain.mcpClient', '@n8n/n8n-nodes-langchain.mcpClientTool']);
const BODY_TYPES = new Set(['none', 'json', 'text']);
const ALLOWED_ARGS = new Set(['url', 'method', 'headers', 'bodyType', 'body', 'lineage']);
// Never accepted from a workflow: transport framing (derived deterministically below), proxy tags, and credentials
// (Phase 1A forwards no credentials at all).
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'connection', 'transfer-encoding', 'te', 'trailer', 'upgrade',
  'keep-alive', 'expect', 'proxy-authorization', 'proxy-authenticate', 'proxy-connection', 'authorization', 'cookie',
  'set-cookie', 'x-api-key', 'api-key', 'x-auth-token', 'x-access-token', 'x-qyrix-host', 'x-qyrix-execution', 'x-qyrix-integration']);
const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}$/;
const ALABEL_RE = /^[a-z0-9.-]{1,253}$/;                // app/netguard.py _ALABEL (proxy tag contract)
const EXEC_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;   // app/netguard.py _EXEC_ID
const CORR_RE = /^[A-Za-z0-9_.:-]{1,64}$/;              // Gate Action.correlation_id / task_id pattern
const HEX64_RE = /^[0-9a-f]{64}$/;
// Audit A-2 (node side): RFC 3986 canonical percent-encoding. An encoded unreserved character (%5F for "_") or a
// lowercase hex digit is a non-canonical spelling of the same URL; it can hide a secret from a scanner that matches
// literal text. The URL must already be canonical (no normalization is applied, as for the rest of the URL).
const UNRESERVED_RE = /^[A-Za-z0-9\-._~]$/;
function nonCanonicalPercent(s) {
  if (/%(?![0-9A-Fa-f]{2})/.test(s)) return true;                         // stray "%"
  for (const m of s.matchAll(/%([0-9A-Fa-f]{2})/g)) {
    if (/[a-f]/.test(m[1])) return true;                                    // lowercase hex digit
    if (UNRESERVED_RE.test(String.fromCharCode(parseInt(m[1], 16)))) return true;   // encoded unreserved character
  }
  return false;
}

const OUTCOMES = new Set(['NOT_SENT', 'NOT_SENT_GRANT_CONSUMED', 'UNKNOWN']);
class QyrixError extends Error {
  constructor(code, message) {
    super('Qyrix Sentinel: ' + code + (message ? ' - ' + message : ''));
    this.code = code; this.name = 'QyrixError'; this.outcome = 'NOT_SENT'; this.ids = {};
  }
  /** Attach SAFE identifiers (opaque ids only, never tokens, headers or bodies) and the outcome; idempotent. */
  withContext(ids, outcome) {
    for (const [k, v] of Object.entries(ids || {})) if (typeof v === 'string' && CORR_RE.test(v) && !this.ids[k]) this.ids[k] = v;
    if (OUTCOMES.has(outcome) && this.outcome === 'NOT_SENT') this.outcome = outcome;
    const tail = Object.entries(this.ids).map(([k, v]) => k + '=' + v).concat('outcome=' + this.outcome).join(', ');
    this.message = this.message.replace(/ \[[^\]]*\]$/, '') + ' [' + tail + ']';
    return this;
  }
}
const fail = (code, msg) => { throw new QyrixError(code, msg); };
const safeCode = (s) => String(s == null ? '' : s).replace(/[^A-Za-z0-9_:.,-]/g, '_').slice(0, 120);

// ---------------- digest (exact reproduction of app/gateway.py) ----------------
const sha256 = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
function pyJsonStr(s) {                                // python json.dumps(str) with the default ensure_ascii=True
  let o = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]; const c = s.charCodeAt(i);
    if (ch === '"') o += '\\"'; else if (ch === '\\') o += '\\\\'; else if (ch === '\n') o += '\\n';
    else if (ch === '\r') o += '\\r'; else if (ch === '\t') o += '\\t'; else if (ch === '\b') o += '\\b';
    else if (ch === '\f') o += '\\f'; else if (c < 0x20 || c > 0x7e) o += '\\u' + c.toString(16).padStart(4, '0'); else o += ch;
  }
  return o + '"';
}
/** _digest(tool, method, dest, cmd, data) = sha256(json.dumps([tool, method.upper(), dest.strip(), cmd, sha256(data)])) */
function gateDigest(tool, method, dest, cmd, data) {
  const parts = [tool, String(method).toUpperCase(), String(dest || '').trim(), cmd, sha256(data || '')];
  return sha256('[' + parts.map(pyJsonStr).join(', ') + ']');
}
const paramsDigest = (a) => gateDigest(a.tool, a.method, a.dest, a.cmd, a.data);

// ---------------- request construction (strict; nothing is normalized or appended later) ----------------
function deepFreeze(o) { Object.values(o).forEach((v) => { if (v && typeof v === 'object') deepFreeze(v); }); return Object.freeze(o); }

function buildRequest(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) fail('ARGS_INVALID', 'arguments must be an object');
  for (const k of Object.keys(args)) if (!ALLOWED_ARGS.has(k)) fail('ARGS_NOT_ALLOWED', safeCode(k));
  const { url, method } = args;
  const bodyType = args.bodyType === undefined ? 'none' : args.bodyType;
  const body = args.body === undefined ? '' : args.body;
  const headersIn = args.headers === undefined ? {} : args.headers;
  const lineage = args.lineage === undefined ? [] : args.lineage;

  if (typeof method !== 'string' || !METHODS.has(method)) fail('METHOD_NOT_SUPPORTED', safeCode(method) + ' (Phase 1A supports GET and HEAD only)');
  if (typeof url !== 'string' || !url || url.length > LIMITS.DEST_MAX) fail('URL_INVALID', 'missing or too long');
  let u;
  try { u = new URL(url); } catch (e) { fail('URL_INVALID', 'not a URL'); }
  if (u.protocol !== 'https:') fail('URL_NOT_SUPPORTED', 'only https:// is supported (tagged CONNECT tunnel)');
  if (u.username || u.password) fail('URL_INVALID', 'userinfo is not allowed');
  if (u.hash || url.includes('#')) fail('URL_INVALID', 'fragments are not allowed');
  if (u.href !== url && u.href !== url + '/') fail('URL_NOT_CANONICAL', 'the URL must already be in canonical form (no normalization is applied)');
  const host = u.hostname;
  if (!ALABEL_RE.test(host) || host.startsWith('[')) fail('URL_INVALID', 'host must be a lowercase A-label hostname');
  const port = u.port ? Number(u.port) : UPSTREAM_PORT;
  if (port !== UPSTREAM_PORT) fail('URL_NOT_SUPPORTED', 'only port 443 is supported (the egress proxy refuses other ports)');
  const path = (u.pathname || '/') + (u.search || '');
  if (nonCanonicalPercent(path)) fail('URL_NOT_CANONICAL', 'percent-encoding must be canonical (uppercase hex; no encoded unreserved characters)');

  if (!BODY_TYPES.has(bodyType)) fail('BODY_TYPE_NOT_SUPPORTED', safeCode(bodyType));
  if (typeof body !== 'string') fail('BODY_NOT_SUPPORTED', 'only string bodies (json or text) are supported; binary is not');
  if (bodyType === 'none' && body !== '') fail('ARGS_AMBIGUOUS', 'bodyType none with a body');
  if (bodyType !== 'none' && (method === 'GET' || method === 'HEAD')) fail('ARGS_AMBIGUOUS', 'GET/HEAD with a body');
  if (bodyType === 'json') {
    let parsed;
    try { parsed = JSON.parse(body); } catch (e) { fail('BODY_INVALID', 'bodyType json but the body is not valid JSON'); }
    if (parsed === null || typeof parsed !== 'object') fail('BODY_INVALID', 'json body must be an object or an array');
  }

  if (!headersIn || typeof headersIn !== 'object' || Array.isArray(headersIn)) fail('ARGS_INVALID', 'headers must be an object');
  const names = Object.keys(headersIn);
  if (names.length > LIMITS.HEADERS_MAX) fail('ARGS_INVALID', 'too many headers');
  const seen = new Set(); const userHeaders = [];
  for (const name of names) {
    const v = headersIn[name]; const lower = name.toLowerCase();
    if (!TOKEN_RE.test(name)) fail('HEADER_INVALID', 'invalid header name');
    if (FORBIDDEN_HEADERS.has(lower) || lower.startsWith('proxy-')) fail('HEADER_NOT_ALLOWED', safeCode(lower));
    if (seen.has(lower)) fail('ARGS_AMBIGUOUS', 'duplicate header ' + safeCode(lower));
    seen.add(lower);
    if (typeof v !== 'string' || v.length > LIMITS.HEADER_VALUE_MAX || /[\r\n\0]/.test(v)) fail('HEADER_INVALID', 'header values must be single-line strings');
    userHeaders.push([name, v]);
  }
  userHeaders.sort((a, b) => (a[0].toLowerCase() < b[0].toLowerCase() ? -1 : 1));

  if (!Array.isArray(lineage) || lineage.length > LIMITS.LINEAGE_MAX || !lineage.every((x) => typeof x === 'string' && CORR_RE.test(x))) {
    fail('ARGS_INVALID', 'lineage must be a list of provenance step ids');
  }
  // Transport framing is DERIVED here, before authorization, and is part of the digested description.
  const headers = [['Host', port === 443 ? host : host + ':' + port], ...userHeaders];
  if (bodyType !== 'none') headers.push(['Content-Length', String(Buffer.byteLength(body, 'utf8'))]);
  headers.push(['Connection', 'close']);
  const description = { body, body_type: bodyType, headers, method, url };   // keys in sorted order
  const data = JSON.stringify(description);
  if (data.length > LIMITS.DATA_MAX) fail('PAYLOAD_TOO_LARGE', 'the request exceeds the Gate data limit of ' + LIMITS.DATA_MAX + ' characters');
  return deepFreeze({ url, host, port, path, method, headers, body, bodyType, lineage: [...lineage], data });
}

function wireBytes(req) {
  let head = req.method + ' ' + req.path + ' HTTP/1.1\r\n';
  for (const [n, v] of req.headers) head += n + ': ' + v + '\r\n';
  return Buffer.concat([Buffer.from(head + '\r\n', 'utf8'), Buffer.from(req.bodyType === 'none' ? '' : req.body, 'utf8')]);
}

function toAction(req, ctx) {
  if (!ctx || !CORR_RE.test(ctx.correlationId || '') || !CORR_RE.test(ctx.taskId || '')) fail('CONTEXT_INVALID', 'correlation/task id');
  const a = { tool: 'http', method: req.method, dest: req.url, cmd: '', data: req.data, correlation_id: ctx.correlationId, task_id: ctx.taskId };
  if (req.lineage.length) a.lineage = [...req.lineage];
  return a;
}

// ---------------- configuration (fail closed when anything is missing) ----------------
function config(env = process.env) {
  const base = String(env.QYRIX_SENTINEL_URL || '').replace(/\/+$/, '');
  let token = env.QYRIX_SENTINEL_TOKEN || '';
  if (!token && env.QYRIX_SENTINEL_TOKEN_FILE) {
    try { token = fs.readFileSync(env.QYRIX_SENTINEL_TOKEN_FILE, 'utf8').trim(); } catch (e) { fail('CONFIG_INVALID', 'token file unreadable'); }
  }
  // The bearer token is only ever sent over verified TLS: plain http is refused for every host, loopback included.
  if (!/^https:\/\/[^/]+$/.test(base)) fail('CONFIG_INVALID', 'QYRIX_SENTINEL_URL must be https://host[:port] (plain http is refused)');
  if (!token) fail('CONFIG_INVALID', 'QYRIX_SENTINEL_TOKEN or QYRIX_SENTINEL_TOKEN_FILE is required');
  const proxy = String(env.QYRIX_EGRESS_PROXY_URL || '');
  const pm = /^http:\/\/([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):(\d{1,5})$/.exec(proxy);
  if (!pm) fail('EGRESS_NOT_CONFIGURED', 'QYRIX_EGRESS_PROXY_URL (http://host:port) is required; there is no direct-network fallback');
  let staticHosts = {};
  if (env.QYRIX_STATIC_HOSTS) {
    try { staticHosts = JSON.parse(env.QYRIX_STATIC_HOSTS); } catch (e) { fail('CONFIG_INVALID', 'QYRIX_STATIC_HOSTS must be JSON'); }
  }
  const ms = (v, d) => { const n = Number(v || d); return Number.isFinite(n) && n >= 100 && n <= 120000 ? n : d; };
  return Object.freeze({ base, token, proxyHost: pm[1].replace(/^\[|\]$/g, ''), proxyPort: Number(pm[2]), staticHosts,
    gateTimeoutMs: ms(env.QYRIX_GATE_TIMEOUT_MS, 10000), egressTimeoutMs: ms(env.QYRIX_EGRESS_TIMEOUT_MS, 30000),
    upstreamCa: env.QYRIX_UPSTREAM_CA_FILE || null, gateCa: env.QYRIX_SENTINEL_CA_FILE || null });
}

// ---------------- deployment hardening (n8n settings the node depends on; fail closed) ----------------
function expandHome(p, env) { return p.startsWith('~') ? p.replace('~', env.HOME || require('os').homedir()) : p; }
function inside(child, dir) {
  const path = require('path');
  const rel = path.relative(path.resolve(dir), path.resolve(child));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}
/** Refuses to run unless the pinned n8n hardening is in place. Values are only inspected, never logged or returned. */
function deploymentCheck(env = process.env) {
  // Audit A-1: a process-wide switch that turns off TLS verification is incompatible with sending a bearer token.
  if (env.NODE_TLS_REJECT_UNAUTHORIZED !== undefined && env.NODE_TLS_REJECT_UNAUTHORIZED !== '' && env.NODE_TLS_REJECT_UNAUTHORIZED !== '1') {
    fail('DEPLOYMENT_INSECURE', 'NODE_TLS_REJECT_UNAUTHORIZED must not be set (TLS verification may not be disabled)');
  }
  if (env.N8N_BLOCK_ENV_ACCESS_IN_NODE !== 'true') fail('DEPLOYMENT_INSECURE', 'N8N_BLOCK_ENV_ACCESS_IN_NODE must be "true"');
  if (env.N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES !== 'true') fail('DEPLOYMENT_INSECURE', 'N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES must be "true"');
  const allowed = String(env.N8N_RESTRICT_FILE_ACCESS_TO || '').split(';').map((x) => x.trim()).filter(Boolean).map((x) => expandHome(x, env));
  if (!allowed.length) fail('DEPLOYMENT_INSECURE', 'N8N_RESTRICT_FILE_ACCESS_TO must name an explicit directory');
  if (!allowed.every((x) => require('path').isAbsolute(x))) fail('DEPLOYMENT_INSECURE', 'N8N_RESTRICT_FILE_ACCESS_TO entries must be absolute');
  for (const f of [env.QYRIX_SENTINEL_TOKEN_FILE, env.QYRIX_SENTINEL_CA_FILE, env.QYRIX_UPSTREAM_CA_FILE].filter(Boolean)) {
    if (allowed.some((d) => inside(f, d) || inside(d, f))) fail('DEPLOYMENT_INSECURE', 'Qyrix secret/CA files must be outside N8N_RESTRICT_FILE_ACCESS_TO');
  }
  let ex;
  try { ex = JSON.parse(env.NODES_EXCLUDE || ''); } catch (e) { fail('DEPLOYMENT_INSECURE', 'NODES_EXCLUDE must be a JSON array'); }
  if (!Array.isArray(ex)) fail('DEPLOYMENT_INSECURE', 'NODES_EXCLUDE must be a JSON array');
  const missing = REQUIRED_NODES_EXCLUDE.filter((n) => !ex.includes(n));
  if (missing.length) fail('DEPLOYMENT_INSECURE', 'NODES_EXCLUDE is missing ' + missing.length + ' required node type(s), e.g. ' + safeCode(missing[0]));
}

// ---------------- Gate client ----------------
function gatePost(cfg, path, body, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(cfg.base + path); const lib = u.protocol === 'https:' ? https : http;
    const payload = Buffer.from(JSON.stringify(body), 'utf8');
    const opts = { hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80), path: u.pathname, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length, Authorization: 'Bearer ' + cfg.token, ...extraHeaders } };
    if (cfg.gateCa) opts.ca = fs.readFileSync(cfg.gateCa);
    // Audit A-1: verification is requested EXPLICITLY. Without this, NODE_TLS_REJECT_UNAUTHORIZED=0 in the environment
    // silently disables certificate checks for https.request and the bearer token goes to whoever answers.
    if (u.protocol === 'https:') opts.rejectUnauthorized = true;
    let settled = false; const done = (f, v) => { if (!settled) { settled = true; clearTimeout(t); f(v); } };
    const req = lib.request(opts, (res) => {
      const chunks = []; let size = 0;
      res.on('data', (c) => { size += c.length; if (size > LIMITS.GATE_RESPONSE_MAX) { req.destroy(); done(reject, new QyrixError('GATE_MALFORMED', 'response too large')); } else chunks.push(c); });
      res.on('end', () => {
        let j;
        try { j = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) { return done(reject, new QyrixError(res.statusCode === 200 ? 'GATE_MALFORMED' : 'GATE_HTTP_' + res.statusCode, 'non-JSON response')); }
        if (res.statusCode !== 200) return done(reject, new QyrixError('GATE_REFUSED', 'HTTP ' + res.statusCode + ' ' + safeCode(j && j.detail)));
        if (!j || typeof j !== 'object' || Array.isArray(j)) return done(reject, new QyrixError('GATE_MALFORMED', 'response is not an object'));
        done(resolve, j);
      });
      res.on('error', () => done(reject, new QyrixError('GATE_UNREACHABLE', 'response stream error')));
    });
    const t = setTimeout(() => { req.destroy(); done(reject, new QyrixError('GATE_TIMEOUT', 'no response within ' + cfg.gateTimeoutMs + ' ms')); }, cfg.gateTimeoutMs);
    req.on('error', (e) => done(reject, new QyrixError('GATE_UNREACHABLE', safeCode(e.code || 'connection error'))));
    req.end(payload);
  });
}

async function evaluate(cfg, action) {
  const localDigest = paramsDigest(action);
  const d = await gatePost(cfg, '/api/v1/sentinel/gate/evaluate', action);
  if (typeof d.verdict !== 'string') fail('GATE_MALFORMED', 'no verdict');
  if (d.verdict !== 'ALLOW') fail('GATE_BLOCK', (Array.isArray(d.rules) ? d.rules : []).map(safeCode).join(',') || 'BLOCK');
  if (typeof d.grant_id !== 'string' || !/^grt_[0-9a-f]{32}$/.test(d.grant_id)) fail('GRANT_MISSING', 'ALLOW without a valid grant');
  if (typeof d.gate_evaluation_id !== 'string' || !CORR_RE.test(d.gate_evaluation_id)) fail('GATE_MALFORMED', 'gate_evaluation_id');
  if (typeof d.params_digest !== 'string' || !HEX64_RE.test(d.params_digest)) fail('GATE_MALFORMED', 'params_digest');
  if (d.params_digest !== localDigest) fail('DIGEST_MISMATCH', 'the Gate evaluated different parameters; not redeeming');
  if (d.correlation_id !== action.correlation_id) fail('GATE_MALFORMED', 'correlation_id does not match the request');
  if (d.task_id !== action.task_id) fail('GATE_MALFORMED', 'task_id does not match the request');
  return { gateEvaluationId: d.gate_evaluation_id, grantId: d.grant_id, paramsDigest: localDigest, rules: d.rules || [] };
}

async function redeem(cfg, decision, digestOfWhatWillRun, ctx) {
  const r = await gatePost(cfg, '/api/v1/tools/redeem', { gate_evaluation_id: decision.gateEvaluationId, grant_id: decision.grantId,
    params_digest: digestOfWhatWillRun, correlation_id: ctx.correlationId, task_id: ctx.taskId }, { 'X-Qyrix-Integration': INTEGRATION });
  if (r.redeemed !== true || r.params_digest !== digestOfWhatWillRun) fail('GATE_MALFORMED', 'redemption not confirmed for this digest');
  if (r.gate_evaluation_id !== decision.gateEvaluationId) fail('GATE_MALFORMED', 'gate_evaluation_id does not match the evaluation');
  if (r.correlation_id !== ctx.correlationId) fail('GATE_MALFORMED', 'correlation_id does not match the request');
  if (typeof r.execution_id !== 'string' || !EXEC_RE.test(r.execution_id)) fail('GATE_MALFORMED', 'execution_id');
  return { executionId: r.execution_id, correlationId: r.correlation_id };
}

/** Evaluate, then redeem the digest of the SAME frozen request that send() will transmit. */
async function authorize(cfg, req, ctx, ids = {}) {
  const action = toAction(req, ctx);
  const decision = await evaluate(cfg, action);
  ids.gate_evaluation_id = decision.gateEvaluationId;
  const red = await redeem(cfg, decision, paramsDigest(toAction(req, ctx)), ctx);
  ids.execution_id = red.executionId;
  return { ...decision, ...red };
}

// ---------------- egress: tagged CONNECT through the C5 proxy only ----------------
function pinnedIp(cfg, host) {
  return new Promise((resolve, reject) => {
    const hint = cfg.staticHosts[host];
    if (typeof hint === 'string' && hint) return resolve(hint);          // pinning hint; the proxy re-validates against its own resolution
    dns.lookup(host, { all: true }, (err, addrs) => {
      if (err || !addrs || !addrs.length) return reject(new QyrixError('EGRESS_UNRESOLVABLE', safeCode(host)));
      resolve(addrs[0].address);
    });
  });
}

function parseResponse(buf) {
  const idx = buf.indexOf('\r\n\r\n');
  if (idx < 0) fail('UPSTREAM_MALFORMED', 'no header terminator');
  const head = buf.slice(0, idx).toString('latin1').split('\r\n');
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(head[0] || '');
  if (!m) fail('UPSTREAM_MALFORMED', 'bad status line');
  const headers = {};
  for (const line of head.slice(1)) { const i = line.indexOf(':'); if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim(); }
  let body = buf.slice(idx + 4);
  if ((headers['transfer-encoding'] || '').toLowerCase() === 'chunked') {
    const out = []; let p = 0;
    for (;;) {
      const e = body.indexOf('\r\n', p); if (e < 0) fail('UPSTREAM_MALFORMED', 'chunk');
      const n = parseInt(body.slice(p, e).toString('latin1'), 16); if (!Number.isFinite(n)) fail('UPSTREAM_MALFORMED', 'chunk size');
      if (n === 0) break;
      out.push(body.slice(e + 2, e + 2 + n)); p = e + 2 + n + 2;
    }
    body = Buffer.concat(out);
  }
  return { status: Number(m[1]), headers, body: body.toString('utf8') };
}

function send(cfg, req, executionId, pinIp, progress = {}) {
  if (!EXEC_RE.test(executionId || '')) return Promise.reject(new QyrixError('EGRESS_REFUSED', 'no Gate-issued execution_id'));
  if (req.port !== UPSTREAM_PORT) return Promise.reject(new QyrixError('EGRESS_REFUSED', 'only port 443'));
  return new Promise((resolve, reject) => {
    let settled = false; const done = (f, v) => { if (!settled) { settled = true; clearTimeout(t); f(v); } };
    const target = (pinIp.includes(':') ? '[' + pinIp + ']' : pinIp) + ':' + req.port;
    const c = http.request({ host: cfg.proxyHost, port: cfg.proxyPort, method: 'CONNECT', path: target,
      headers: { Host: target, 'X-Qyrix-Host': req.host, 'X-Qyrix-Execution': executionId } });
    const t = setTimeout(() => { c.destroy(); done(reject, new QyrixError('EGRESS_TIMEOUT', 'no response within ' + cfg.egressTimeoutMs + ' ms')); }, cfg.egressTimeoutMs);
    c.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); return done(reject, new QyrixError('EGRESS_REFUSED', 'proxy answered HTTP ' + res.statusCode)); }
      const opts = { socket, servername: req.host, minVersion: 'TLSv1.2', rejectUnauthorized: true };
      if (cfg.upstreamCa) opts.ca = fs.readFileSync(cfg.upstreamCa);
      const s = tls.connect(opts, () => { progress.wrote = true; s.write(wireBytes(req)); });
      const chunks = []; let size = 0;
      s.on('data', (d) => { size += d.length; if (size > LIMITS.UPSTREAM_RESPONSE_MAX) { s.destroy(); done(reject, new QyrixError('UPSTREAM_TOO_LARGE', 'response exceeds limit')); } else chunks.push(d); });
      s.on('end', () => { try { done(resolve, parseResponse(Buffer.concat(chunks))); } catch (e) { done(reject, e); } });
      s.on('error', (e) => done(reject, new QyrixError('EGRESS_TLS_FAILED', safeCode(e.code || 'tls error'))));
    });
    c.on('error', (e) => done(reject, new QyrixError('EGRESS_UNREACHABLE', safeCode(e.code || 'proxy connection error'))));
    c.end();
  });
}

/** Full flow for one request. Fails closed at every step; send() is reached only after a confirmed redemption. */
async function execute(env, args, ctx) {
  const ids = { correlation_id: ctx && ctx.correlationId, task_id: ctx && ctx.taskId };
  const progress = { wrote: false };
  let auth;
  try {
    deploymentCheck(env);                       // before anything: an unhardened n8n never reaches the Gate
    const cfg = config(env);                    // before the Gate: misconfiguration never consumes a grant
    const req = buildRequest(args);             // before the Gate: invalid / oversized input never reaches it
    auth = await authorize(cfg, req, ctx, ids);
    const ip = await pinnedIp(cfg, req.host);
    var res = await send(cfg, req, auth.executionId, ip, progress);
  } catch (e) {
    const err = e instanceof QyrixError ? e : new QyrixError('INTERNAL_ERROR', 'unexpected failure (fail closed)');
    const outcome = progress.wrote ? 'UNKNOWN' : (ids.execution_id ? 'NOT_SENT_GRANT_CONSUMED' : 'NOT_SENT');
    throw err.withContext(ids, outcome);
  }
  return { response: res, qyrix: { verdict: 'ALLOW', gate_evaluation_id: auth.gateEvaluationId, execution_id: auth.executionId,
    correlation_id: auth.correlationId, task_id: ctx.taskId, params_digest: auth.paramsDigest,
    evidence: 'E1_ADAPTER_SELF_REPORT', note: 'Gate decision and single-use redemption recorded by Sentinel; this node output is not independent verification' } };
}

module.exports = { INTEGRATION, LIMITS, QyrixError, buildRequest, toAction, paramsDigest, gateDigest, pyJsonStr, wireBytes,
  config, deploymentCheck, REQUIRED_NODES_EXCLUDE, gatePost, evaluate, redeem, authorize, pinnedIp, send, execute, CORR_RE };
