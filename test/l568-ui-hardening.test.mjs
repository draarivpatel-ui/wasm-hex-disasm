import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mount } from '../src/app.mjs';
import { demoModule } from '../src/wasm.mjs';

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
}
function mounted(workerClass) {
  const nodes = Object.fromEntries(Array.from(html.matchAll(/<([a-z]+)[^>]*\bid="([^"]+)"/g), (m) => [m[2], new Element(m[2], m[1])]));
  nodes['demo-select'].value = 'add'; nodes['trace-limit'].value = '2000'; nodes['trace-step'].value = '1';
  const revoked = [];
  const doc = {
    getElementById: (id) => nodes[id],
    createElement: (tag) => new Element('', tag)
  };
  const win = {
    navigator: { clipboard: { async writeText() {} } },
    location: { href: 'http://localhost:8000/', hash: '' },
    URL: { createObjectURL: () => 'blob:worker', revokeObjectURL: (url) => revoked.push(url) },
    Blob: class { constructor(parts, opts) { this.parts = parts; this.type = opts && opts.type; } },
    Worker: workerClass
  };
  return { app: mount(doc, win), nodes, win, revoked };
}

test('a stale sandbox worker result cannot overwrite a newly loaded module', async () => {
  const instances = [];
  class HangingWorker {
    constructor() { instances.push(this); }
    postMessage(message) { this.message = message; }
    terminate() { this.terminated = true; }
  }
  const { app, nodes } = mounted(HangingWorker);
  nodes['run-args'].value = '[2,3]';
  const pending = nodes['run-export'].emit('click');
  assert.equal(instances.length, 1);
  assert.equal(app.load(demoModule('sum'), 'sum demonstration'), true);
  instances[0].onmessage({ data: { ok: true, values: [{ type: 'i32', display: '5' }] } });
  await pending;
  assert.equal(nodes['run-result'].textContent, '');
  assert.equal(nodes.status.textContent, 'Inspected sum demonstration.');
});

test('a worker error revokes its object URL before reporting failure', async () => {
  const instances = [];
  class ErrorWorker {
    constructor() { instances.push(this); }
    postMessage() {}
    terminate() { this.terminated = true; }
  }
  const { nodes, revoked } = mounted(ErrorWorker);
  nodes['run-args'].value = '[2,3]';
  const pending = nodes['run-export'].emit('click');
  instances[0].onerror({ message: 'worker refused' });
  await pending;
  assert.deepEqual(revoked, ['blob:worker']);
  assert.match(nodes['run-result'].textContent, /worker refused/);
});

test('a worker constructor failure declines execution instead of an untimeboxed page-thread fallback', async () => {
  class BrokenWorker { constructor() { throw new Error('blocked by policy'); } }
  const { nodes, revoked } = mounted(BrokenWorker);
  nodes['run-args'].value = '[2,3]';
  await nodes['run-export'].emit('click');
  assert.deepEqual(revoked, ['blob:worker']);
  assert.match(nodes['run-result'].textContent, /Sandbox worker unavailable/);
  assert.match(nodes.status.textContent, /Sandbox worker unavailable/);
});

test('starting a newer sandbox run invalidates an older result', async () => {
  const instances = [];
  class HangingWorker {
    constructor() { instances.push(this); }
    postMessage(message) { this.message = message; }
    terminate() { this.terminated = true; }
  }
  const { nodes } = mounted(HangingWorker);
  nodes['run-args'].value = '[2,3]';
  const first = nodes['run-export'].emit('click');
  const second = nodes['run-export'].emit('click');
  assert.equal(instances.length, 2);
  instances[0].onmessage({ data: { ok: true, values: [{ type: 'i32', display: '5' }] } });
  await first;
  assert.equal(nodes['run-result'].textContent, 'Running add in the sandbox worker.');
  instances[1].onmessage({ data: { ok: true, values: [{ type: 'i32', display: '5' }] } });
  await second;
  assert.match(nodes['run-result'].textContent, /returned 5/);
});
