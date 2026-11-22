import { parseModule, disassemble, traceFunction, demoModule, parseHex, hexRows } from './wasm.mjs';
import { sha256, sectionMap, callGraph, auditModule, sandboxPlan, marshalArgs, runExport,
  reportJSON, reportCSV, shareHash, restoreHash, runSelfTests,
  WORKER_RUNNER_SOURCE, SHARE_LIMIT } from './analysis.mjs';

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

export function inspectionMarkup(mod, selectedSection = null) {
  const sections = mod.sections.slice(0, 500).map((s, index) => '<tr><td><button type="button" class="section-button" data-section="' +
    index + '">' + escapeHtml(s.name) + '</button></td><td>' + s.offset + '</td><td>' + s.payloadOffset +
    '</td><td>' + s.size + '</td></tr>').join('');
  const prefix = mod.bytes.subarray(0, 16384);
  const hex = hexRows(prefix).map((r) => '<div class="hex-row' + (selectedSection &&
    r.offset < selectedSection.end && r.offset + 16 > selectedSection.offset ? ' is-selected' : '') +
    '"><span class="hex-offset">' + r.offset.toString(16).padStart(6, '0') + '</span><span>' + r.hex +
    '</span><span class="hex-ascii">' + escapeHtml(r.ascii) + '</span></div>').join('');
  const integers = mod.lebSpans.slice(0, 200).map((span) => '<tr><td>' + span.offset + '</td><td>' +
    (span.end - span.offset) + '</td><td>' + span.kind + '</td><td>' + span.value + '</td></tr>').join('');
  return { sections, hex, integers, visibleBytes: prefix.length, visibleSections: Math.min(500, mod.sections.length) };
}

export function sectionMapMarkup(mod) {
  const entries = sectionMap(mod);
  const seg = (e) => 'seg seg-' + e.name.replace(/\s+/g, '-');
  const bar = entries.map((e) => '<button type="button" class="' + seg(e) + '" style="flex-grow:' + Math.max(e.size, 1) +
    '" data-range="' + e.offset + '-' + e.end + '" data-name="' + escapeHtml(e.name) + '" title="' + escapeHtml(e.name) + ', ' +
    e.size + ' bytes, ' + (e.share * 100).toFixed(1) + '%">' + (e.share >= 0.06 ? '<span>' + escapeHtml(e.name) + '</span>' : '') +
    '</button>').join('');
  const rows = entries.map((e) => '<tr><td><button type="button" class="section-button" data-range="' + e.offset + '-' + e.end +
    '" data-name="' + escapeHtml(e.name) + '">' + escapeHtml(e.name) + '</button></td><td>' + e.offset + '</td><td>' +
    e.size + '</td><td>' + (e.share * 100).toFixed(1) + '%</td></tr>').join('');
  return { bar, rows, entries };
}

const shorten = (name, limit = 14) => (name.length > limit ? name.slice(0, limit - 1) + '…' : name);

export function callGraphMarkup(graph) {
  if (!graph.nodes.length) return { svg: '', note: 'No functions exist in this module.' };
  const shown = graph.nodes.slice(0, 40);
  const hidden = graph.nodes.length - shown.length;
  const positions = new Map();
  const n = shown.length;
  const radius = Math.max(90, Math.min(300, n * 13));
  const width = 840, height = radius * 2 + 130;
  const cx = width / 2, cy = height / 2;
  shown.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / n - Math.PI / 2;
    positions.set(node.index, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle), node });
  });
  const parts = ['<svg viewBox="0 0 ' + width + ' ' + height + '" xmlns="http://www.w3.org/2000/svg">',
    '<defs><marker id="cg-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">' +
    '<path d="M0 1L9 5L0 9z" class="cg-arrow"/></marker></defs>'];
  let drawnEdges = 0;
  for (const edge of graph.edges) {
    if (!positions.has(edge.from) || !positions.has(edge.to)) continue;
    const a = positions.get(edge.from), b = positions.get(edge.to);
    drawnEdges++;
    if (edge.from === edge.to) {
      parts.push('<path d="M' + (a.x + 20) + ' ' + (a.y - 18) + ' a13 13 0 1 1 -0.1 0" class="cg-edge" fill="none"/>');
      continue;
    }
    const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
    const inset = 46;
    const x1 = a.x + (dx / len) * inset, y1 = a.y + (dy / len) * inset;
    const x2 = b.x - (dx / len) * inset, y2 = b.y - (dy / len) * inset;
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    const bend = Math.min(70, len * 0.14);
    const px = mx + (dy / len) * bend, py = my - (dx / len) * bend;
    parts.push('<path d="M' + x1.toFixed(1) + ' ' + y1.toFixed(1) + ' Q' + px.toFixed(1) + ' ' + py.toFixed(1) + ' ' +
      x2.toFixed(1) + ' ' + y2.toFixed(1) + '" class="cg-edge" fill="none" marker-end="url(#cg-arrow)"/>');
  }
  for (const [, p] of positions) {
    const node = p.node;
    const cls = 'cg-node ' + (node.kind === 'imported' ? 'cg-import' : node.dead ? 'cg-dead' : node.exported.length ? 'cg-export' : 'cg-defined');
    const w = 104, h = 34;
    const title = '#' + node.index + ' ' + node.name + ', ' + node.instructions + ' instructions' +
      (node.exported.length ? ', exports: ' + node.exported.join(', ') : '') +
      (node.start ? ', start function' : '') + (node.dead ? ', unreachable from roots' : '') +
      (node.indirect ? ', uses call_indirect' : '') + (node.calls.length ? ', calls ' + node.calls.map((c) => '$f' + c).join(' ') : '');
    parts.push('<g class="' + cls + '"><title>' + escapeHtml(title) + '</title>' +
      '<rect x="' + (p.x - w / 2).toFixed(1) + '" y="' + (p.y - h / 2).toFixed(1) + '" width="' + w + '" height="' + h + '" rx="7"/>' +
      '<text class="cg-label" x="' + p.x.toFixed(1) + '" y="' + (p.y - 1).toFixed(1) + '" text-anchor="middle">' + escapeHtml(shorten(node.name)) + '</text>' +
      '<text class="cg-count" x="' + p.x.toFixed(1) + '" y="' + (p.y + 11).toFixed(1) + '" text-anchor="middle">' +
      node.instructions + ' ins' + (node.indirect ? ' · ind' : '') + '</text></g>');
  }
  parts.push('</svg>');
  const svg = parts.join('');
  const dead = graph.nodes.filter((x) => x.dead).length;
  const note = graph.nodes.length + ' function(s) (' + graph.importCount + ' imported), ' + graph.edges.length +
    ' direct call edge(s)' + (drawnEdges !== graph.edges.length ? ', ' + drawnEdges + ' drawn' : '') + ', ' +
    graph.nodes.filter((x) => x.exported.length).length + ' exported, ' + dead + ' unreachable' +
    (graph.hasIndirect ? ', indirect dispatch present' : '') + (hidden ? ', ' + hidden + ' nodes omitted from the drawing' : '') + '.';
  return { svg, note };
}

export function auditMarkup(audit) {
  return audit.findings.map((f) => '<li class="finding ' + f.severity + '"><span class="finding-title">' +
    escapeHtml(f.title) + '</span> ' + escapeHtml(f.detail) + '</li>').join('');
}

export function selfTestMarkup(results) {
  return results.map((r) => '<li class="' + (r.ok ? 'pass' : 'fail') + '"><span class="finding-title">' +
    escapeHtml(r.name) + '</span> ' + escapeHtml(r.detail) + '</li>').join('');
}

export function mount(doc, win) {
  const $ = (id) => doc.getElementById(id);
  const state = { module: null, wat: '', trace: null, requestVersion: 0, plan: null, fingerprint: '' };
  const status = (message, error = false) => {
    $('status').textContent = message;
    $('status').classList.toggle('is-error', error);
  };
  const clearable = ['sections-body', 'integers-body', 'hex-view', 'wat-view', 'trace-view', 'step-state',
    'summary', 'hex-note', 'integer-note', 'sections-note', 'wat-note', 'section-map', 'section-map-body',
    'section-map-note', 'call-graph', 'call-graph-note', 'audit-list', 'audit-summary', 'run-result',
    'run-note', 'fingerprint', 'self-test-view', 'report-note'];
  function clear() {
    state.requestVersion++;
    state.module = null; state.wat = ''; state.trace = null; state.plan = null; state.fingerprint = '';
    for (const id of clearable) $(id).textContent = '';
    $('trace-function').textContent = '';
    $('run-function').textContent = '';
    $('trace-run').disabled = true; $('wat-copy').disabled = true;
    $('run-export').disabled = true;
    $('dl-wat').disabled = true; $('dl-json').disabled = true; $('dl-csv').disabled = true; $('share-link').disabled = true;
    $('trace-step').disabled = true; $('step-number').textContent = '0';
  }
  function resetArguments() {
    if (!state.module) return;
    const exported = state.module.exports.find((e) => e.kind === 'func' && e.name === $('trace-function').value);
    const imported = state.module.imports.filter((e) => e.kind === 'func');
    const fn = exported && (exported.index < imported.length ? imported[exported.index] : state.module.functions[exported.index - imported.length]);
    const type = fn && state.module.types[fn.typeIndex];
    $('trace-args').value = JSON.stringify(type ? type.params.map(() => 0) : []);
    state.trace = null;
    $('trace-view').textContent = ''; $('step-state').textContent = '';
    $('trace-step').disabled = true; $('step-number').textContent = '0';
  }
  function resetRunArgs() {
    if (!state.plan) return;
    const cand = state.plan.candidates.find((c) => c.name === $('run-function').value && c.runnable) ||
      state.plan.candidates.find((c) => c.runnable);
    $('run-args').value = JSON.stringify(cand ? cand.params.map(() => 0) : []);
    $('run-result').textContent = '';
  }
  function workerRun(cand, args) {
    return new Promise((resolve) => {
      let url;
      try { url = win.URL.createObjectURL(new win.Blob([WORKER_RUNNER_SOURCE], { type: 'text/javascript' })); }
      catch { resolve(null); return; }
      const worker = new win.Worker(url);
      const timer = setTimeout(() => {
        worker.terminate();
        resolve({ ok: false, error: 'Execution exceeded the 1500 ms sandbox budget and the worker was terminated.' });
      }, 1500);
      worker.onmessage = (event) => {
        clearTimeout(timer); worker.terminate();
        if (win.URL.revokeObjectURL) win.URL.revokeObjectURL(url);
        resolve(event.data && event.data.ok ? { ok: true, results: event.data.values } :
          { ok: false, error: (event.data && event.data.error) || 'Worker execution failed' });
      };
      worker.onerror = (event) => {
        clearTimeout(timer); worker.terminate();
        resolve({ ok: false, error: event.message || 'Worker execution failed' });
      };
      worker.postMessage({ bytes: state.module.bytes, name: cand.name, params: cand.params, results: cand.results,
        args: args.map((v) => (typeof v === 'bigint' ? String(v) : v)) });
    });
  }
  async function executeExport(cand, rawArgs) {
    let args;
    try { args = marshalArgs(cand.params, rawArgs); }
    catch (error) { return { ok: false, error: error.message }; }
    const canWorker = typeof win.Worker === 'function' && win.URL && typeof win.URL.createObjectURL === 'function';
    if (canWorker) {
      const result = await workerRun(cand, args);
      if (result) return result;
    }
    const result = runExport(state.module, cand.name, rawArgs);
    return result.ok ? { ok: true, results: result.results, ms: result.ms } : { ok: false, error: result.error };
  }
  function load(bytes, label) {
    clear();
    try {
      const mod = parseModule(bytes), content = inspectionMarkup(mod);
      state.module = mod; state.wat = disassemble(mod);
      $('sections-body').innerHTML = content.sections;
      $('integers-body').innerHTML = content.integers;
      $('hex-view').innerHTML = content.hex;
      $('hex-note').textContent = 'Showing ' + content.visibleBytes + ' of ' + mod.bytes.length + ' bytes.';
      $('sections-note').textContent = 'Showing ' + content.visibleSections + ' of ' + mod.sections.length + ' sections.';
      $('integer-note').textContent = 'Showing ' + Math.min(200, mod.lebSpans.length) + ' of ' +
        (mod.lebTotal === undefined ? mod.lebSpans.length : mod.lebTotal) + ' decoded integers.';
      $('wat-view').textContent = state.wat.slice(0, 200000);
      $('wat-note').textContent = state.wat.length > 200000 ? 'The visible listing is truncated. Copy retrieves the complete listing.' : 'The listing comes from parsed instructions and section fields.';
      $('summary').textContent = mod.bytes.length + ' bytes, ' + mod.sections.length + ' sections, ' +
        mod.functions.length + ' defined functions, ' + mod.exports.length + ' exports. Native validation passed.';
      const map = sectionMapMarkup(mod);
      $('section-map').innerHTML = map.bar;
      $('section-map-body').innerHTML = map.rows;
      $('section-map-note').textContent = mod.bytes.length + ' bytes across ' + map.entries.length + ' regions. Select a segment to highlight its bytes.';
      const graph = callGraphMarkup(callGraph(mod));
      $('call-graph').innerHTML = graph.svg;
      $('call-graph-note').textContent = graph.note;
      const audit = auditModule(mod);
      $('audit-list').innerHTML = auditMarkup(audit);
      $('audit-summary').textContent = audit.findings.length + ' findings: ' + audit.counts.flags + ' flagged, ' + audit.counts.notices + ' notices.';
      state.plan = sandboxPlan(mod);
      state.fingerprint = sha256(mod.bytes);
      $('fingerprint').textContent = state.fingerprint;
      for (const cand of state.plan.candidates) {
        const option = doc.createElement('option');
        option.value = cand.name;
        option.textContent = cand.name + (cand.runnable ? '' : ' (unavailable)');
        option.disabled = !cand.runnable;
        $('run-function').appendChild(option);
      }
      const runnableCount = state.plan.candidates.filter((c) => c.runnable).length;
      $('run-export').disabled = !runnableCount;
      $('run-note').textContent = state.plan.reason + (runnableCount ?
        ' Runs inside a dedicated worker thread, terminated after 1500 ms, with an empty import object.' : '');
      for (const e of mod.exports.filter((e) => e.kind === 'func')) {
        const option = doc.createElement('option');
        option.value = e.name; option.textContent = e.name; $('trace-function').appendChild(option);
      }
      $('trace-run').disabled = !mod.exports.some((e) => e.kind === 'func');
      $('wat-copy').disabled = false;
      $('dl-wat').disabled = false; $('dl-json').disabled = false; $('dl-csv').disabled = false;
      $('share-link').disabled = mod.bytes.length > SHARE_LIMIT;
      resetArguments();
      resetRunArgs();
      status('Inspected ' + label + '.');
      return true;
    } catch (error) {
      $('hex-note').textContent = ''; $('integer-note').textContent = ''; $('sections-note').textContent = ''; $('wat-note').textContent = '';
      status(error.message, true);
      return false;
    }
  }
  function renderStep() {
    if (!state.trace || !state.trace.events.length) return;
    const requested = Number($('trace-step').value);
    const index = Number.isFinite(requested) ? Math.max(0, Math.min(state.trace.events.length - 1, Math.floor(requested) - 1)) : 0;
    const event = state.trace.events[index];
    $('step-number').textContent = String(index + 1);
    $('step-state').textContent = 'Function ' + event.functionIndex + ', byte ' + event.offset + ', ' + event.op +
      '\nStack before ' + JSON.stringify(event.before) + '\nStack after ' + JSON.stringify(event.after || []) +
      '\nLocals before ' + JSON.stringify(event.localsBefore) + '\nLocals after ' + JSON.stringify(event.localsAfter || []) +
      (event.error ? '\nStopped: ' + event.error : '');
  }
  function download(name, text, type) {
    try {
      const url = win.URL.createObjectURL(new win.Blob([text], { type }));
      const anchor = doc.createElement('a');
      anchor.href = url;
      anchor.download = name;
      if (typeof anchor.click === 'function') anchor.click();
      setTimeout(() => { if (win.URL.revokeObjectURL) win.URL.revokeObjectURL(url); }, 4000);
      status('Saved ' + name + '.');
    } catch { status('File download is unavailable in this environment.', true); }
  }
  const demoArgs = { add: '[2,3]', sum: '[10]', select: '[1]' };
  $('demo-load').addEventListener('click', () => {
    const kind = $('demo-select').value;
    load(demoModule(kind), kind + ' demonstration');
    const preset = demoArgs[kind] || '[2,3]';
    $('trace-args').value = preset;
    $('run-args').value = preset;
  });
  $('hex-load').addEventListener('click', () => {
    try { load(parseHex($('hex-input').value), 'pasted bytes'); }
    catch (error) { clear(); status(error.message, true); }
  });
  $('file-input').addEventListener('change', async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    clear();
    const version = state.requestVersion;
    if (file.size > 4 * 1024 * 1024) { clear(); status('Input exceeds the 4 MiB inspection limit', true); return; }
    status('Reading the selected binary.');
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (version === state.requestVersion) load(bytes, file.name);
    }
    catch (error) { if (version === state.requestVersion) { clear(); status(error.message, true); } }
  });
  $('sections-body').addEventListener('click', (event) => {
    const button = event.target.closest('[data-section]');
    if (!button || !state.module) return;
    const section = state.module.sections[Number(button.dataset.section)];
    if (!section) return;
    $('hex-view').innerHTML = inspectionMarkup(state.module, section).hex;
    status(section.name + ' section spans bytes ' + section.offset + ' through ' + (section.end - 1) + '.');
  });
  const rangePick = (event) => {
    const button = event.target.closest('[data-range]');
    if (!button || !state.module) return;
    const [start, end] = button.dataset.range.split('-').map(Number);
    $('hex-view').innerHTML = inspectionMarkup(state.module, { offset: start, end }).hex;
    status(button.dataset.name + ' spans bytes ' + start + ' through ' + (end - 1) + '.');
  };
  $('section-map').addEventListener('click', rangePick);
  $('section-map-body').addEventListener('click', rangePick);
  $('trace-function').addEventListener('change', resetArguments);
  $('run-function').addEventListener('change', resetRunArgs);
  $('trace-run').addEventListener('click', () => {
    if (!state.module) return;
    try {
      const args = JSON.parse($('trace-args').value);
      if (!Array.isArray(args)) throw new Error('Parameters must be a JSON array of integers');
      const trace = traceFunction(state.module, $('trace-function').value, args, { maxSteps: Number($('trace-limit').value) });
      state.trace = trace;
      $('trace-view').textContent = trace.ok ? 'Result ' + JSON.stringify(trace.results) + '. Executed ' +
        trace.events.length + ' instructions.' : 'Stopped after ' + trace.events.length + ' instructions. ' + trace.error;
      $('trace-step').max = String(Math.max(1, trace.events.length));
      $('trace-step').value = '1'; $('trace-step').disabled = !trace.events.length;
      renderStep();
      status(trace.ok ? 'Integer trace completed.' : trace.error, !trace.ok);
    } catch (error) { state.trace = null; $('trace-view').textContent = ''; $('step-state').textContent = '';
      $('trace-step').disabled = true; $('step-number').textContent = '0'; status(error.message, true); }
  });
  $('run-export').addEventListener('click', async () => {
    if (!state.module || !state.plan) return;
    const cand = state.plan.candidates.find((c) => c.name === $('run-function').value);
    if (!cand) { status('Select an exported function to run.', true); return; }
    if (!cand.runnable) { status(cand.reason, true); return; }
    let raw;
    try { raw = JSON.parse($('run-args').value); }
    catch { status('Parameters must be a JSON array', true); return; }
    $('run-result').textContent = 'Running ' + cand.name + ' in the sandbox worker.';
    const result = await executeExport(cand, raw);
    $('run-result').textContent = result.ok
      ? cand.name + '(' + raw.map((v) => JSON.stringify(v)).join(', ') + ') returned ' +
        result.results.map((r) => r.display).join(', ') + '.'
      : 'Stopped: ' + result.error;
    status(result.ok ? 'Sandboxed execution returned.' : result.error, !result.ok);
  });
  $('trace-step').addEventListener('input', renderStep);
  $('wat-copy').addEventListener('click', async () => {
    try { await win.navigator.clipboard.writeText(state.wat); status('Copied the text listing.'); }
    catch { status('Copy is unavailable. Select the listing to copy it.', true); }
  });
  $('dl-wat').addEventListener('click', () => {
    if (state.module) download('disassembly.wat', state.wat, 'text/plain');
  });
  $('dl-json').addEventListener('click', () => {
    if (state.module) download('audit-report.json', JSON.stringify(reportJSON(state.module, { fingerprint: state.fingerprint }), null, 2), 'application/json');
  });
  $('dl-csv').addEventListener('click', () => {
    if (state.module) download('sections-and-opcodes.csv', reportCSV(state.module), 'text/csv');
  });
  $('share-link').addEventListener('click', async () => {
    if (!state.module) return;
    const hash = shareHash(state.module.bytes);
    if (hash === null) { status('Modules above ' + SHARE_LIMIT + ' bytes are too large for a share link.', true); return; }
    const base = win.location && win.location.href ? win.location.href.split('#')[0] : '';
    try { await win.navigator.clipboard.writeText(base + hash); status('Copied a share link that restores this module.'); }
    catch { status('Share link: ' + base + hash, false); }
  });
  $('self-test-run').addEventListener('click', () => {
    const results = runSelfTests();
    $('self-test-view').innerHTML = selfTestMarkup(results);
    const passed = results.filter((r) => r.ok).length;
    $('report-note').textContent = 'Self-tests verify integer codecs, header checks, hashes, native parity and graph integrity.';
    status(passed + ' of ' + results.length + ' self-tests passed.', passed !== results.length);
  });
  let restored = false;
  try {
    const bytes = win.location && win.location.hash ? restoreHash(win.location.hash) : null;
    if (bytes && bytes.length) restored = load(bytes, 'the module in the share link');
  } catch { status('The share link could not be decoded.', true); }
  if (!restored) {
    load(demoModule(), 'add demonstration');
    $('trace-args').value = '[2,3]';
    $('run-args').value = '[2,3]';
  }
  return { state, load, clear };
}

if (typeof document !== 'undefined') mount(document, window);
