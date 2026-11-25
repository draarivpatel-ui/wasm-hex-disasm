import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mount, inspectionMarkup, escapeHtml } from '../src/app.mjs';
import { demoModule, parseModule } from '../src/wasm.mjs';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
class Element {
  constructor(id, tag = 'div') {
    this.id = id; this.tag = tag; this.value = ''; this.children = []; this.listeners = {};
    this.disabled = false; this._text = ''; this._html = '';
    this.classList = { toggle() {} };
  }
  get textContent() { return this._text; }
  set textContent(value) { this._text = String(value); this._html = ''; this.children = []; if (this.tag === 'select') this.value = ''; }
  get innerHTML() { return this._html; }
  set innerHTML(value) { this._html = String(value); this._text = ''; this.children = []; }
  appendChild(child) { this.children.push(child); if (this.tag === 'select' && this.children.length === 1) this.value = child.value; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  emit(type, event = {}) { return this.listeners[type]({ target: this, ...event }); }
}
function mounted() {
  const nodes = Object.fromEntries(Array.from(html.matchAll(/<([a-z]+)[^>]*\bid="([^"]+)"/g), (m) => [m[2], new Element(m[2], m[1])]));
  nodes['demo-select'].value = 'add'; nodes['trace-limit'].value = '2000'; nodes['trace-step'].value = '1';
  const doc = { getElementById: (id) => nodes[id], createElement: (tag) => new Element('', tag) };
  const win = { navigator: { clipboard: { writeText: async () => {} } } };
  return { app: mount(doc, win), nodes, win };
}

test('Markup has unique ids, usable labels and one page title', () => {
  const ids = Array.from(html.matchAll(/\bid="([^"]+)"/g), (m) => m[1]);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal((html.match(/<h1\b/g) || []).length, 1);
  for (const m of html.matchAll(/<label for="([^"]+)"/g)) assert.ok(ids.includes(m[1]));
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /script type="module" src="src\/app.mjs"/);
});

test('Controller boot fills actual sections, integer spans, bytes and listing', () => {
  const { app, nodes } = mounted();
  assert.equal(app.state.module.nativeValid, true);
  assert.match(nodes['sections-body'].innerHTML, /data-section/);
  assert.match(nodes['integers-body'].innerHTML, /u32/);
  assert.match(nodes['hex-view'].innerHTML, /hex-row/);
  assert.match(nodes['wat-view'].textContent, /i32.add/);
  assert.match(nodes.summary.textContent, /1 defined function, 1 export\./);
  assert.equal(nodes['trace-run'].disabled, false);
});

test('Every demonstration switch loads matching exports and fresh parameters', () => {
  const { app, nodes } = mounted();
  nodes['demo-select'].value = 'sum'; nodes['demo-load'].emit('click');
  assert.equal(app.state.module.exports[0].name, 'sum');
  assert.equal(nodes['trace-args'].value, '[10]');
  nodes['trace-run'].emit('click');
  assert.equal(app.state.trace.results[0], 55);
  assert.match(nodes['trace-view'].textContent, /55/);
  assert.equal(nodes['trace-step'].disabled, false);
});

test('The step control reports real stack and locals for its selected instruction', () => {
  const { nodes } = mounted();
  nodes['trace-run'].emit('click'); nodes['trace-step'].value = '3'; nodes['trace-step'].emit('input');
  assert.match(nodes['step-state'].textContent, /i32.add/);
  assert.match(nodes['step-state'].textContent, /Stack before \[2,3\]/);
  assert.match(nodes['step-state'].textContent, /Stack after \[5\]/);
});

test('Invalid pasted input clears every result and disables stale actions', () => {
  const { app, nodes } = mounted();
  nodes['hex-input'].value = 'xyz'; nodes['hex-load'].emit('click');
  assert.equal(app.state.module, null);
  for (const id of ['summary', 'wat-view', 'hex-view', 'hex-note', 'integer-note', 'wat-note']) assert.equal(nodes[id].textContent, '');
  assert.equal(nodes['wat-copy'].disabled, true);
  assert.equal(nodes['trace-run'].disabled, true);
  assert.match(nodes.status.textContent, /byte pairs/);
});

test('Bad parameters and execution limits show a stop instead of an invented result', () => {
  const { nodes, app } = mounted();
  nodes['trace-args'].value = '{}'; nodes['trace-run'].emit('click');
  assert.match(nodes.status.textContent, /JSON array/);
  assert.equal(app.state.trace, null);
  nodes['demo-select'].value = 'sum'; nodes['demo-load'].emit('click');
  nodes['trace-args'].value = '[-1]'; nodes['trace-limit'].value = '5'; nodes['trace-run'].emit('click');
  assert.equal(app.state.trace.ok, false);
  assert.equal(app.state.trace.events.length, 5);
  assert.match(nodes['trace-view'].textContent, /step limit/);
});

test('Slow local reads cannot overwrite a newer demonstration', async () => {
  const { app, nodes } = mounted();
  let resolve;
  const data = new Promise((done) => { resolve = done; });
  const pending = nodes['file-input'].emit('change', { target: { files: [{ name: 'slow.wasm', size: 100, arrayBuffer: () => data }] } });
  nodes['demo-select'].value = 'select'; nodes['demo-load'].emit('click');
  resolve(demoModule('sum').buffer); await pending;
  assert.equal(app.state.module.exports[0].name, 'select');
});

test('Invalid pasted bytes cancel a pending file read and preserve its error', async () => {
  const { app, nodes } = mounted();
  let resolve;
  const data = new Promise((done) => { resolve = done; });
  const pending = nodes['file-input'].emit('change', { target: { files: [{ name: 'slow.wasm', size: 100, arrayBuffer: () => data }] } });
  assert.equal(nodes['trace-run'].disabled, true);
  nodes['hex-input'].value = 'invalid'; nodes['hex-load'].emit('click');
  resolve(demoModule('sum').buffer); await pending;
  assert.equal(app.state.module, null);
  assert.equal(nodes['trace-run'].disabled, true);
  assert.match(nodes.status.textContent, /byte pairs/);
});

test('Oversized files are rejected before their data is read', async () => {
  const { app, nodes } = mounted();
  let reads = 0;
  await nodes['file-input'].emit('change', { target: { files: [{ name: 'large.wasm', size: 4 * 1024 * 1024 + 1, arrayBuffer() { reads++; } }] } });
  assert.equal(reads, 0);
  assert.equal(app.state.module, null);
  assert.match(nodes.status.textContent, /4 MiB/);
});

test('Section selection highlights actual bytes and escaped content cannot become markup', () => {
  const mod = parseModule(demoModule());
  const markup = inspectionMarkup(mod, mod.sections[0]);
  assert.match(markup.hex, /is-selected/);
  assert.equal(escapeHtml('<>&"'), '&lt;&gt;&amp;&quot;');
  const { nodes } = mounted();
  nodes['sections-body'].emit('click', { target: { closest: () => ({ dataset: { section: '0' } }) } });
  assert.match(nodes.status.textContent, /spans bytes/);
});

test('Unavailable clipboard access is recoverable', async () => {
  const { nodes, win } = mounted();
  win.navigator.clipboard.writeText = async () => { throw new Error('unavailable'); };
  await nodes['wat-copy'].emit('click');
  assert.match(nodes.status.textContent, /Select the listing/);
});
