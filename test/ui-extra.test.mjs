import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mount, sectionMapMarkup, callGraphMarkup, auditMarkup, selfTestMarkup, escapeHtml } from '../src/app.mjs';
import { demoModule, parseModule, encodeULEB } from '../src/wasm.mjs';
import { auditModule, callGraph, bytesToBase64url, sha256 } from '../src/analysis.mjs';
import { moduleBytes, section, nameBytes, nameSection, importEntry } from './helpers/fixture.mjs';

const uleb = encodeULEB;
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
class Element {
  constructor(id, tag = 'div') {
    this.id = id; this.tag = tag; this.value = ''; this.children = []; this.listeners = {};
    this.disabled = false; this._text = ''; this._html = ''; this.clicks = 0;
    this.classList = { toggle() {} };
  }
  get textContent() { return this._text; }
  set textContent(value) { this._text = String(value); this._html = ''; this.children = []; if (this.tag === 'select') this.value = ''; }
  get innerHTML() { return this._html; }
  set innerHTML(value) { this._html = String(value); this._text = ''; this.children = []; }
  appendChild(child) { this.children.push(child); if (this.tag === 'select' && this.children.length === 1) this.value = child.value; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  emit(type, event = {}) { return this.listeners[type]({ target: this, ...event }); }
  click() { this.clicks++; }
}
function mounted({ hash = '', clipboard, url, blob } = {}) {
  const nodes = Object.fromEntries(Array.from(html.matchAll(/<([a-z]+)[^>]*\bid="([^"]+)"/g), (m) => [m[2], new Element(m[2], m[1])]));
  nodes['demo-select'].value = 'add'; nodes['trace-limit'].value = '2000'; nodes['trace-step'].value = '1';
  const anchors = [];
  const doc = {
    getElementById: (id) => nodes[id],
    createElement: (tag) => { const el = new Element('', tag); if (tag === 'a') anchors.push(el); return el; }
  };
  const win = {
    navigator: { clipboard: clipboard || { text: null, async writeText(t) { this.text = t; } } },
    location: { href: 'http://localhost:8000/', hash },
    URL: url || { created: [], createObjectURL() { this.created.push('u'); return 'blob:fake'; }, revokeObjectURL() {} },
    Blob: blob || class { constructor(parts, opts) { this.parts = parts; this.type = opts && opts.type; } }
  };
  return { app: mount(doc, win), nodes, win, anchors };
}

const callModule = moduleBytes(
  nameSection([[0, 'host'], [1, 'runner'], [2, 'helper'], [3, 'ghost']]),
  section(1, [1, 0x60, 0, 1, 0x7f]),
  section(2, [1].concat(importEntry('env', 'host', [0, 0]))),
  section(3, [3, 0, 0, 0]),
  section(7, [1].concat(nameBytes('run'), [0, 1])),
  section(10, [3].concat(uleb(7), [0, 0x10, 0, 0x1a, 0x10, 2, 0x0b])
    .concat(uleb(4), [0, 0x10, 0, 0x0b], uleb(4), [0, 0x41, 9, 0x0b])));

test('Boot fills the section map, call graph, audit, fingerprint and runner', () => {
  const { app, nodes } = mounted();
  assert.equal(app.state.module.nativeValid, true);
  assert.match(nodes['section-map'].innerHTML, /seg-code/);
  assert.match(nodes['section-map-body'].innerHTML, /data-range/);
  assert.match(nodes['call-graph'].innerHTML, /<svg/);
  assert.match(nodes['call-graph'].innerHTML, /cg-export/);
  assert.match(nodes['audit-list'].innerHTML, /finding/);
  assert.equal(nodes['fingerprint'].textContent, sha256(app.state.module.bytes));
  assert.ok(nodes['run-function'].children.length > 0);
  assert.equal(nodes['run-export'].disabled, false);
  assert.equal(nodes['dl-wat'].disabled, false);
});

test('Section map bar buttons are proportional to real byte spans', () => {
  const mod = parseModule(demoModule());
  const { bar, rows } = sectionMapMarkup(mod);
  for (const s of mod.sections) {
    const span = s.end - s.offset;
    assert.ok(bar.includes('flex-grow:' + span), 'missing span ' + span);
  }
  assert.match(bar, /data-range="0-8"/);
  assert.match(rows, /%<\/td>/);
});

test('Section map clicks highlight the same bytes as the sections table', () => {
  const { nodes } = mounted();
  nodes['section-map'].emit('click', { target: { closest: () => ({ dataset: { range: '8-14', name: 'type' } }) } });
  assert.match(nodes.status.textContent, /type spans bytes 8 through 13/);
  assert.match(nodes['hex-view'].innerHTML, /is-selected/);
  nodes['section-map-body'].emit('click', { target: { closest: () => ({ dataset: { range: '0-8', name: 'header' } }) } });
  assert.match(nodes.status.textContent, /header spans bytes 0 through 7/);
});

test('Section map clicks are ignored without a module', () => {
  const { nodes, app } = mounted();
  app.clear();
  nodes['section-map'].emit('click', { target: { closest: () => ({ dataset: { range: '0-8', name: 'header' } }) } });
  assert.equal(app.state.module, null);
});

test('Call graph markup draws nodes, edges and severity classes', () => {
  const mod = parseModule(callModule, { validate: false });
  const { svg, note } = callGraphMarkup(callGraph(mod));
  assert.match(svg, /cg-import/);
  assert.match(svg, /cg-dead/);
  assert.match(svg, /cg-export/);
  assert.match(svg, /marker-end/);
  assert.match(note, /4 function\(s\)/);
  assert.match(note, /1 unreachable/);
});

test('Call graph markup escapes hostile names into text', () => {
  const evil = moduleBytes(nameSection([[0, '<script>alert(1)</script>']]),
    section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(7, [1].concat(nameBytes('run'), [0, 0])),
    section(10, [1].concat(uleb(2), [0, 0x0b])));
  const { svg } = callGraphMarkup(callGraph(parseModule(evil, { validate: false })));
  assert.equal(svg.includes('<script>'), false);
  assert.ok(svg.includes('&lt;script&gt;'));
});

test('Call graph reports an empty module without a drawing', () => {
  const { svg, note } = callGraphMarkup(callGraph(parseModule(moduleBytes())));
  assert.equal(svg, '');
  assert.match(note, /No functions/);
});

test('Audit markup escapes finding text', () => {
  const audit = { findings: [{ id: 'x', severity: 'flag', title: '<b>t</b>', detail: 'a "b" c' }] };
  const markup = auditMarkup(audit);
  assert.ok(markup.includes('&lt;b&gt;'));
  assert.ok(!markup.includes('<b>'));
  assert.match(markup, /class="finding flag"/);
});

test('Self test markup reflects pass and fail states', () => {
  const markup = selfTestMarkup([{ name: 'one', ok: true, detail: 'fine' }, { name: 'two', ok: false, detail: 'bad' }]);
  assert.match(markup, /class="pass"/);
  assert.match(markup, /class="fail"/);
});

test('Sandboxed runner returns a real result through the sync path', async () => {
  const { nodes } = mounted();
  nodes['run-args'].value = '[2,3]';
  await nodes['run-export'].emit('click');
  assert.match(nodes['run-result'].textContent, /add\(2, 3\) returned 5/);
  assert.match(nodes.status.textContent, /Sandboxed execution returned/);
});

test('Sandboxed runner reports malformed parameters', async () => {
  const { nodes } = mounted();
  nodes['run-args'].value = 'not json';
  await nodes['run-export'].emit('click');
  assert.match(nodes.status.textContent, /JSON array/);
  nodes['run-args'].value = '[1]';
  await nodes['run-export'].emit('click');
  assert.match(nodes.status.textContent, /2 parameter/);
  assert.match(nodes['run-result'].textContent, /Stopped/);
});

test('Sandboxed runner surfaces native traps as stops', async () => {
  const { app, nodes } = mounted();
  assert.equal(app.load(functionBytesTrap(), 'trapper'), true);
  await nodes['run-export'].emit('click');
  assert.match(nodes['run-result'].textContent, /Stopped/);
});

test('Modules without runnable exports disable the sandbox runner', () => {
  const { app, nodes } = mounted();
  const bytes = moduleBytes(section(5, [1, 0, 1]), section(7, [1].concat(nameBytes('mem'), [2, 0])));
  assert.equal(app.load(bytes, 'memory only'), true);
  assert.equal(nodes['run-export'].disabled, true);
  assert.match(nodes['run-note'].textContent, /empty import object/);
});

test('Modules with imports keep the sandbox runner refused', () => {
  const { app, nodes } = mounted();
  assert.equal(app.load(callModule, 'importer'), true);
  assert.match(nodes['run-note'].textContent, /host import/);
  assert.equal(nodes['run-export'].disabled, true);
});

test('Downloads produce real report payloads through the anchor path', () => {
  const { nodes, win, anchors } = mounted();
  nodes['dl-wat'].emit('click');
  assert.equal(anchors[0].download, 'disassembly.wat');
  assert.equal(anchors[0].clicks, 1);
  nodes['dl-json'].emit('click');
  nodes['dl-csv'].emit('click');
  assert.equal(anchors.length, 3);
  assert.equal(nodes['dl-csv'].disabled, false);
});

test('Download JSON report embeds the displayed fingerprint', () => {
  const blobs = [];
  const blob = class { constructor(parts) { blobs.push(parts[0]); } };
  const { nodes } = mounted({ blob });
  nodes['dl-json'].emit('click');
  const report = JSON.parse(blobs[0]);
  assert.equal(report.fingerprint.hex, nodes['fingerprint'].textContent);
  assert.equal(report.tool, 'wasm-hex-disasm');
});

test('Download CSV contains the section table and opcode histogram', () => {
  const blobs = [];
  const blob = class { constructor(parts) { blobs.push(parts[0]); } };
  const { nodes } = mounted({ blob });
  nodes['dl-csv'].emit('click');
  assert.match(blobs[0], /section,code/);
  assert.match(blobs[0], /opcode,i32.add/);
});

test('Share link copies a bookmark URL that restores the module', async () => {
  const { nodes, win, app } = mounted();
  await nodes['share-link'].emit('click');
  const link = win.navigator.clipboard.text;
  assert.match(link, /^http:\/\/localhost:8000\/#b=/);
  const bytes = demoModule();
  assert.deepEqual([...app.state.module.bytes], [...bytes]);
  assert.equal(link, 'http://localhost:8000/#b=' + bytesToBase64url(bytes));
});

test('Share link stays usable when the clipboard is unavailable', async () => {
  const clipboard = { async writeText() { throw new Error('denied'); } };
  const { nodes } = mounted({ clipboard });
  await nodes['share-link'].emit('click');
  assert.match(nodes.status.textContent, /Share link: http:\/\/localhost:8000\/#b=/);
});

test('Modules above the share limit disable the share button', () => {
  const { app, nodes } = mounted();
  const data = [0, 0x41, 0, 0x0b].concat(uleb(40000), Array(40000).fill(0));
  const bytes = moduleBytes(section(5, [1, 0, 10]), section(11, [1].concat(data)));
  assert.equal(app.load(bytes, 'big'), true);
  assert.equal(nodes['share-link'].disabled, true);
});

test('Self test button renders one passing row per check', () => {
  const { nodes } = mounted();
  nodes['self-test-run'].emit('click');
  const passes = (nodes['self-test-view'].innerHTML.match(/class="pass"/g) || []).length;
  assert.ok(passes >= 9);
  assert.match(nodes.status.textContent, /self-tests passed/);
  assert.match(nodes['report-note'].textContent, /verify/);
});

test('A share link hash restores its module on boot', () => {
  const hash = '#b=' + bytesToBase64url(demoModule('select'));
  const { app } = mounted({ hash });
  assert.equal(app.state.module.exports[0].name, 'select');
});

test('A corrupt share link falls back to the demonstration', () => {
  const { app, nodes } = mounted({ hash: '#b=!!!' });
  assert.equal(app.state.module.exports[0].name, 'add');
});

test('Invalid pasted input clears every new panel too', () => {
  const { nodes, app } = mounted();
  nodes['hex-input'].value = 'xyz'; nodes['hex-load'].emit('click');
  for (const id of ['section-map', 'section-map-body', 'call-graph', 'audit-list', 'fingerprint', 'run-result', 'self-test-view']) {
    assert.equal(nodes[id].textContent, '', id);
  }
  assert.equal(nodes['run-export'].disabled, true);
  assert.equal(nodes['dl-json'].disabled, true);
  assert.equal(app.state.module, null);
});

test('Runner argument presets follow the selected demonstration', () => {
  const { nodes } = mounted();
  nodes['demo-select'].value = 'sum'; nodes['demo-load'].emit('click');
  assert.equal(nodes['run-args'].value, '[10]');
  nodes['demo-select'].value = 'select'; nodes['demo-load'].emit('click');
  assert.equal(nodes['run-args'].value, '[1]');
});

test('Changing the runner function resets parameter defaults', () => {
  const { nodes } = mounted();
  nodes['run-function'].emit('change');
  assert.equal(nodes['run-args'].value, '[0,0]');
});

test('index.html wires the favicon, CSP worker rule and every control id', () => {
  assert.match(html, /rel="icon" href="data:image\/svg\+xml/);
  assert.match(html, /worker-src blob:/);
  for (const id of ['section-map', 'section-map-body', 'call-graph', 'audit-list', 'run-function', 'run-args', 'run-export',
    'run-result', 'fingerprint', 'dl-wat', 'dl-json', 'dl-csv', 'share-link', 'self-test-run', 'self-test-view']) {
    assert.ok(html.includes('id="' + id + '"'), id + ' missing');
  }
});

test('escapeHtml keeps its contract on all dangerous characters', () => {
  assert.equal(escapeHtml(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
});

function functionBytesTrap() {
  return moduleBytes(
    section(1, [1, 0x60, 0, 0]),
    section(3, [1, 0]),
    section(7, [1].concat(nameBytes('trap'), [0, 0])),
    section(10, [1].concat(uleb(3), [0, 0x00, 0x0b])));
}
