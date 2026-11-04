'use strict';
// Test harness (not shipped to n8n): runs the REAL node class / core functions with a minimal n8n execute context.
// stdin: {"mode": "node"|"core", ...}. stdout: one JSON line {ok, output|code, message}. Used by backend/tests/test_n8n_http_node.py.
const core = require('../lib/qyrix-core.js');
const { QyrixHttp } = require('../nodes/QyrixHttp/QyrixHttp.node.js');
let input = '';
process.stdin.on('data', (c) => { input += c; });
process.stdin.on('end', async () => {
  const spec = JSON.parse(input);
  const emit = (o) => process.stdout.write(JSON.stringify(o) + '\n');
  try {
    if (spec.mode === 'digest') { emit({ ok: true, output: spec.vectors.map((v) => core.gateDigest(...v)) }); return; }
    if (spec.mode === 'build') { const r = core.buildRequest(spec.args); emit({ ok: true, output: { data: r.data, wire: core.wireBytes(r).toString('utf8'), frozen: Object.isFrozen(r) && Object.isFrozen(r.headers) } }); return; }
    if (spec.mode === 'raw-evaluate') { const cfg = core.config(process.env); emit({ ok: true, output: await core.evaluate(cfg, spec.action) }); return; }
    if (spec.mode === 'replay') {            // evaluate + redeem, then redeem the SAME grant again
      const cfg = core.config(process.env); const req = core.buildRequest(spec.args);
      const a = await core.authorize(cfg, req, spec.ctx);
      try { await core.redeem(cfg, { gateEvaluationId: a.gateEvaluationId, grantId: a.grantId }, a.paramsDigest, spec.ctx); emit({ ok: true, output: 'SECOND_REDEEM_SUCCEEDED' }); }
      catch (e) { emit({ ok: false, code: e.code, message: e.message, first: a.executionId }); }
      return;
    }
    if (spec.mode === 'tamper') {             // authorize request A, then try to redeem the digest of request B
      const cfg = core.config(process.env); const a = core.buildRequest(spec.args); const b = core.buildRequest(spec.tampered);
      const d = await core.evaluate(cfg, core.toAction(a, spec.ctx));
      await core.redeem(cfg, d, core.paramsDigest(core.toAction(b, spec.ctx)), spec.ctx);
      emit({ ok: true, output: 'TAMPERED_REDEEM_SUCCEEDED' }); return;
    }
    if (spec.mode === 'cross-credential') {   // evaluate with this credential, redeem with OTHER_TOKEN
      const cfg = core.config(process.env); const req = core.buildRequest(spec.args);
      const d = await core.evaluate(cfg, core.toAction(req, spec.ctx));
      const other = core.config({ ...process.env, QYRIX_SENTINEL_TOKEN: process.env.OTHER_TOKEN, QYRIX_SENTINEL_TOKEN_FILE: '' });
      await core.redeem(other, d, d.paramsDigest, spec.ctx); emit({ ok: true, output: 'CROSS_CREDENTIAL_REDEEM_SUCCEEDED' }); return;
    }
    // mode "node": the n8n node class with a minimal IExecuteFunctions
    const params = spec.params || {};
    const ctx = {
      getInputData: () => Array.from({ length: spec.items || 1 }, () => ({ json: {} })),
      getNodeParameter: (n, i, d) => (n in params ? params[n] : d),
      getWorkflow: () => ({ id: spec.workflowId || 'wfTest01' }),
      // raw (unresolved) parameters, as n8n stores them: an expression is a string starting with "="
      getNode: () => ({ id: spec.nodeId || 'node-1', name: 'Qyrix Sentinel HTTP', parameters: spec.rawParams || params, retryOnFail: spec.retryOnFail === true }),
      getExecutionId: () => spec.executionId || '42',
      continueOnFail: () => !!spec.continueOnFail,
    };
    const out = await new QyrixHttp().execute.call(ctx);
    emit({ ok: true, output: out[0].map((x) => x.json) });
  } catch (e) {
    emit({ ok: false, code: e && e.code, message: e && e.message, outcome: e && e.outcome, ids: e && e.ids });
  }
});
