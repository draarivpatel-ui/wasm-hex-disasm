import { parseModule, disassemble, traceFunction, demoModule, parseHex, hexRows } from './wasm.mjs';

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

export function mount(doc, win) {
  const $ = (id) => doc.getElementById(id);
  const state = { module: null, wat: '', trace: null, requestVersion: 0 };
  const status = (message, error = false) => {
    $('status').textContent = message;
    $('status').classList.toggle('is-error', error);
  };
  function clear() {
    state.requestVersion++;
    state.module = null; state.wat = ''; state.trace = null;
    for (const id of ['sections-body', 'integers-body', 'hex-view', 'wat-view', 'trace-view', 'step-state', 'summary', 'hex-note', 'integer-note', 'sections-note', 'wat-note']) $(id).textContent = '';
    $('trace-function').textContent = '';
    $('trace-run').disabled = true; $('wat-copy').disabled = true;
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
      for (const e of mod.exports.filter((e) => e.kind === 'func')) {
        const option = doc.createElement('option');
        option.value = e.name; option.textContent = e.name; $('trace-function').appendChild(option);
      }
      $('trace-run').disabled = !mod.exports.some((e) => e.kind === 'func');
      $('wat-copy').disabled = false;
      resetArguments();
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
  $('demo-load').addEventListener('click', () => {
    const kind = $('demo-select').value;
    load(demoModule(kind), kind + ' demonstration');
    if (kind === 'sum') $('trace-args').value = '[10]';
    else if (kind === 'add') $('trace-args').value = '[2,3]';
    else $('trace-args').value = '[1]';
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
  $('trace-function').addEventListener('change', resetArguments);
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
  $('trace-step').addEventListener('input', renderStep);
  $('wat-copy').addEventListener('click', async () => {
    try { await win.navigator.clipboard.writeText(state.wat); status('Copied the text listing.'); }
    catch { status('Copy is unavailable. Select the listing to copy it.', true); }
  });
  load(demoModule(), 'add demonstration');
  $('trace-args').value = '[2,3]';
  return { state, load, clear };
}

if (typeof document !== 'undefined') mount(document, window);
