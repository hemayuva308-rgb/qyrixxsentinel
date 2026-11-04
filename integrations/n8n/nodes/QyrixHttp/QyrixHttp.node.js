'use strict';
/*
 * Qyrix Sentinel HTTP node for n8n 2.46.5 (self-hosted) - Phase 1A PROTOTYPE.
 * Every item: deployment check -> strict argument allow-list (GET/HEAD only, https:443 only) -> Gate evaluate (must be
 * ALLOW) -> single-use grant redemption of the exact request digest -> the request is sent ONLY through the C5 egress
 * proxy tunnel tagged with the Gate-issued execution_id. There is no direct-network path and no fallback. Lineage must be
 * a fixed value: expressions are refused (item data must never choose provenance). The node logs nothing. Its output is
 * an E1 adapter self-report. Failures carry safe ids and an outcome (NOT_SENT / NOT_SENT_GRANT_CONSUMED / UNKNOWN).
 */
const crypto = require('crypto');
const core = require('../../lib/qyrix-core.js');

function correlationId(wfId, execId, nodeId, item) {
  const raw = ['n8n', wfId, execId, nodeId, item].map((x) => String(x == null ? '' : x)).join(':');
  const clean = raw.replace(/[^A-Za-z0-9_.:-]/g, '_');
  return clean.length <= 64 ? clean : 'n8n:h:' + crypto.createHash('sha256').update(raw).digest('hex').slice(0, 40);
}

function taskId(wfId) {                       // caller-provided task context (as everywhere in Sentinel): binds grants to this workflow
  const t = ('n8n-wf-' + String(wfId == null ? 'unsaved' : wfId)).replace(/[^A-Za-z0-9_.:-]/g, '_');
  return t.length <= 64 ? t : 'n8n-wf-h:' + crypto.createHash('sha256').update(t).digest('hex').slice(0, 40);
}

function parseHeaders(text) {
  if (text === undefined || text === null || text === '') return {};
  let h;
  try { h = JSON.parse(text); } catch (e) { throw new core.QyrixError('ARGS_INVALID', 'headers must be a JSON object of string values'); }
  return h;                                   // structure is validated strictly by core.buildRequest
}

// Restricted mode (audit A-3, A-5): method, URL, headers and lineage must be FIXED values. Item data must never choose a
// destination, a header or a provenance reference. Verified on n8n 2.46.5: for a noDataExpression parameter n8n strips the
// leading "=" and does NOT evaluate the text, so an expression arrives as the literal "{{ ... }}". We therefore refuse both
// spellings (a leading "=" as stored in the workflow, and "{{" as it reaches the node) and any non-string value.
const FIXED_ONLY = ['method', 'url', 'headers', 'lineage'];
function expressionParameter(node) {
  const params = node && node.parameters ? node.parameters : {};
  for (const name of FIXED_ONLY) {
    const raw = params[name];
    if (raw === undefined || raw === null) continue;
    if (typeof raw !== 'string' || raw.trimStart().startsWith('=') || raw.includes('{{')) return name;
  }
  return null;
}

function parseLineage(text) {
  if (!text) return [];
  return String(text).split(',').map((s) => s.trim()).filter(Boolean);
}

class QyrixHttp {
  constructor() {
    this.description = {
      displayName: 'Qyrix Sentinel HTTP (prototype)',
      name: 'qyrixHttp',
      icon: 'fa:shield-alt',
      group: ['transform'],
      version: 1,
      description: 'HTTPS request authorized by the Qyrix Sentinel Gate and sent only through the Sentinel egress proxy',
      defaults: { name: 'Qyrix Sentinel HTTP' },
      inputs: ['main'],
      outputs: ['main'],
      properties: [
        { displayName: 'Method', name: 'method', type: 'options', default: 'GET', noDataExpression: true,
          options: ['GET', 'HEAD'].map((m) => ({ name: m, value: m })) },   // Phase 1A: no state-changing methods
        { displayName: 'URL (https on port 443 only, canonical form)', name: 'url', type: 'string', default: '', required: true, noDataExpression: true },
        { displayName: 'Headers (JSON object, no credentials)', name: 'headers', type: 'string', default: '{}', noDataExpression: true },
        { displayName: 'Provenance Lineage IDs (comma separated, fixed value - expressions are refused)', name: 'lineage',
          type: 'string', default: '', noDataExpression: true },
        { displayName: 'Do not enable "Retry On Fail" for this node: a failure after redemption has an UNKNOWN outcome and a retry is a new, separately authorised request.',
          name: 'retryNotice', type: 'notice', default: '' },
      ],
    };
  }

  async execute() {
    const items = this.getInputData();
    const wf = this.getWorkflow(); const node = this.getNode(); const execId = this.getExecutionId();
    const out = [];
    for (let i = 0; i < items.length; i++) {
      const ctx = { correlationId: correlationId(wf && wf.id, execId, node && node.id, i), taskId: taskId(wf && wf.id) };
      try {
        // Audit A-6: n8n's "Retry On Fail" would re-run a failed item, and a failure after redemption may already have reached the
        // upstream. The node refuses to run when it is enabled (the setting is visible in the node definition).
        if (node && node.retryOnFail === true) throw new core.QyrixError('RETRY_ON_FAIL_NOT_ALLOWED', 'disable "Retry On Fail" on this node: a retry is a new, separately authorised request');
        const exprParam = expressionParameter(node);
        if (exprParam === 'lineage') throw new core.QyrixError('LINEAGE_EXPRESSION_NOT_ALLOWED', 'lineage must be a fixed value, not an expression');
        if (exprParam) throw new core.QyrixError('EXPRESSION_NOT_ALLOWED', exprParam + ' must be a fixed value, not an expression (restricted mode)');
        const args = {
          url: this.getNodeParameter('url', i),
          method: this.getNodeParameter('method', i),
          headers: parseHeaders(this.getNodeParameter('headers', i, '{}')),
          lineage: parseLineage(this.getNodeParameter('lineage', i, '')),
        };
        const r = await core.execute(process.env, args, ctx);
        out.push({ json: { status: r.response.status, headers: r.response.headers, body: r.response.body, qyrix: r.qyrix }, pairedItem: { item: i } });
      } catch (e) {
        const err = (e instanceof core.QyrixError ? e : new core.QyrixError('INTERNAL_ERROR', 'unexpected failure (fail closed)'))
          .withContext({ correlation_id: ctx.correlationId, task_id: ctx.taskId });
        if (this.continueOnFail && this.continueOnFail()) {
          out.push({ json: { qyrix: { error: err.code, message: err.message, outcome: err.outcome, sent: err.outcome === 'UNKNOWN' ? 'unknown' : false,
            correlation_id: ctx.correlationId, task_id: ctx.taskId, gate_evaluation_id: err.ids.gate_evaluation_id || null,
            execution_id: err.ids.execution_id || null, evidence: 'E1_ADAPTER_SELF_REPORT' } }, pairedItem: { item: i } });
          continue;
        }
        throw err;
      }
    }
    return [out];
  }
}

module.exports = { QyrixHttp };
