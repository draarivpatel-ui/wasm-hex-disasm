// Static analysis, capability audit, fingerprinting, reporting and sandboxed
// execution on top of the bounded parser. Nothing here instantiates a module
// with host imports or performs any network access.
import { Reader, BinaryError, encodeULEB, encodeSLEB, parseModule, disassemble, demoModule } from './wasm.mjs';

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];
const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

function byteInput(input) {
  if (!(input instanceof Uint8Array) && !Array.isArray(input)) throw new TypeError('Expected an array of byte values');
  for (let i = 0; i < input.length; i++) {
    if (!Number.isInteger(input[i]) || input[i] < 0 || input[i] > 255) throw new TypeError('Expected an array of byte values');
  }
  return input instanceof Uint8Array ? input : Uint8Array.from(input);
}

export function sha256(input) {
  const bytes = byteInput(input);
  const length = bytes.length;
  const total = ((length + 9 + 63) >> 6) << 6;
  const data = new Uint8Array(total);
  data.set(bytes);
  data[length] = 0x80;
  const view = new DataView(data.buffer);
  view.setUint32(total - 8, Math.floor(length / 0x20000000));
  view.setUint32(total - 4, (length * 8) >>> 0);
  const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const w = new Uint32Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + s1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return h.map((x) => x.toString(16).padStart(8, '0')).join('');
}

export function sectionMap(mod) {
  const entries = [];
  const first = mod.sections.length ? mod.sections[0].offset : mod.bytes.length;
  if (first > 0) entries.push({ index: -1, id: -1, name: 'header', offset: 0, end: first, size: first, share: first / mod.bytes.length });
  mod.sections.forEach((s, i) => entries.push({ index: i, id: s.id, name: s.name, offset: s.offset, end: s.end, size: s.end - s.offset, share: (s.end - s.offset) / mod.bytes.length }));
  return entries;
}

export function functionNames(mod) {
  const names = new Map();
  for (const custom of mod.custom) {
    if (custom.name !== 'name') continue;
    try {
      const r = new Reader(custom.bytes);
      while (r.offset < r.end) {
        const id = r.byte(), size = r.u32(), stop = r.offset + size;
        if (stop > r.end) break;
        if (id === 1) {
          const sub = new Reader(custom.bytes, r.offset, stop);
          const count = sub.u32();
          for (let i = 0; i < count && sub.offset < sub.end; i++) {
            const index = sub.u32();
            names.set(index, sub.name());
          }
        }
        r.offset = stop;
      }
    } catch { /* A malformed name section is ignored, never fatal. */ }
  }
  return names;
}

export function callGraph(mod) {
  const imported = mod.imports.filter((i) => i.kind === 'func');
  const names = functionNames(mod);
  const nodes = [];
  imported.forEach((imp, index) => nodes.push({ index, kind: 'imported', name: names.get(index) || imp.module + '.' + imp.name,
    importedFrom: imp.module + '.' + imp.name, instructions: 0, calls: [], indirect: false, exported: [], start: false, dead: false }));
  mod.functions.forEach((fn, n) => {
    const index = n + imported.length;
    const calls = [];
    let indirect = false;
    for (const ins of fn.code) {
      if (ins.op === 'call' && !calls.includes(ins.args[0])) calls.push(ins.args[0]);
      else if (ins.op === 'call_indirect') indirect = true;
    }
    nodes.push({ index, kind: 'defined', name: names.get(index) || '$f' + index, instructions: fn.code.length,
      calls, indirect, exported: [], start: mod.start === index, dead: false });
  });
  mod.exports.filter((e) => e.kind === 'func').forEach((e) => {
    const node = nodes[e.index];
    if (node) node.exported.push(e.name);
  });
  const reachable = new Set();
  const roots = [];
  for (const e of mod.exports) if (e.kind === 'func') roots.push(e.index);
  if (mod.start !== null) roots.push(mod.start);
  for (const seg of mod.elements) roots.push(...seg.functions);
  const queue = roots.filter((i) => i >= 0 && i < nodes.length);
  while (queue.length) {
    const index = queue.shift();
    if (reachable.has(index) || index >= nodes.length) continue;
    reachable.add(index);
    for (const target of nodes[index].calls) if (!reachable.has(target)) queue.push(target);
  }
  const hasIndirect = nodes.some((n) => n.indirect) || mod.elements.length > 0;
  nodes.forEach((node) => {
    if (node.kind !== 'defined') return;
    const tableTarget = mod.elements.some((seg) => seg.functions.includes(node.index));
    node.dead = !reachable.has(node.index) && !tableTarget;
  });
  const edges = [];
  nodes.forEach((node) => node.calls.forEach((to) => edges.push({ from: node.index, to })));
  return { nodes, edges, reachable: [...reachable].sort((a, b) => a - b), importCount: imported.length, hasIndirect };
}

export function opcodeHistogram(mod) {
  const counts = new Map();
  for (const fn of mod.functions) for (const ins of fn.code) counts.set(ins.op, (counts.get(ins.op) || 0) + 1);
  return [...counts.entries()].map(([op, count]) => ({ op, count })).sort((a, b) => b.count - a.count || a.op.localeCompare(b.op));
}

export function sandboxPlan(mod) {
  const imports = mod.imports.length;
  const runnable = imports === 0 && mod.start === null;
  const reason = imports ? 'This module declares ' + imports + ' host import(s) that a sandbox cannot satisfy.'
    : mod.start !== null ? 'Instantiation would run the module start function $f' + mod.start + '.'
    : 'Instantiates with an empty import object and no start function.';
  const funcImports = mod.imports.filter((i) => i.kind === 'func').length;
  const candidates = mod.exports.filter((e) => e.kind === 'func').map((e) => {
    const defined = e.index >= funcImports ? mod.functions[e.index - funcImports] : null;
    const type = defined ? mod.types[defined.typeIndex] : null;
    const params = type ? type.params : [], results = type ? type.results : [];
    const integer = params.every((t) => t === 'i32' || t === 'i64') && results.every((t) => t === 'i32' || t === 'i64');
    const ok = Boolean(defined && integer && runnable);
    const why = !defined ? 'An imported function needs host code.'
      : !integer ? 'Only pure integer signatures run in the sandbox.'
      : !runnable ? reason : 'Ready to run.';
    return { name: e.name, index: e.index, params, results, runnable: ok, reason: why };
  });
  return { runnable, reason, candidates };
}

export function marshalArgs(params, rawArgs) {
  if (!Array.isArray(rawArgs)) throw new Error('Parameters must be a JSON array');
  if (rawArgs.length !== params.length) throw new Error('This function takes ' + params.length + ' parameter(s), got ' + rawArgs.length);
  return params.map((type, i) => {
    const value = rawArgs[i];
    const numericInput = typeof value === 'number' || typeof value === 'bigint' ||
      (typeof value === 'string' && value.trim() !== '');
    if (type === 'i64') {
      if (!numericInput || typeof value === 'boolean') throw new Error('Parameter ' + (i + 1) + ' must be an integer');
      if (typeof value === 'number' && !Number.isInteger(value)) throw new Error('Parameter ' + (i + 1) + ' must be an integer');
      try { return BigInt(value); } catch { throw new Error('Parameter ' + (i + 1) + ' must be an integer'); }
    }
    if (type === 'i32') {
      if (!numericInput || typeof value === 'bigint') throw new Error('Parameter ' + (i + 1) + ' must be an integer');
      const n = Number(value);
      if (!Number.isFinite(n) || !Number.isInteger(n)) throw new Error('Parameter ' + (i + 1) + ' must be an integer');
      return n | 0;
    }
    if (type === 'f32' || type === 'f64') {
      if (!numericInput || typeof value === 'bigint') throw new Error('Parameter ' + (i + 1) + ' must be a number');
      const n = Number(value);
      if (!Number.isFinite(n)) throw new Error('Parameter ' + (i + 1) + ' must be a number');
      return n;
    }
    throw new Error('Parameter type ' + type + ' cannot be supplied from this page');
  });
}

function marshalResults(types, out) {
  const list = types.length === 0 ? [] : types.length === 1 ? [out] : out;
  return list.map((value, i) => ({ type: types[i], display: typeof value === 'bigint' ? String(value) + 'n' : String(value) }));
}

export function runExport(mod, name, rawArgs, { instantiate } = {}) {
  const plan = sandboxPlan(mod);
  if (!plan.runnable) return { ok: false, error: plan.reason };
  const candidate = plan.candidates.find((c) => c.name === name);
  if (!candidate) return { ok: false, error: 'Export ' + JSON.stringify(name) + ' is not a function.' };
  if (!candidate.runnable) return { ok: false, error: candidate.reason };
  let args;
  try { args = marshalArgs(candidate.params, rawArgs); }
  catch (error) { return { ok: false, error: error.message }; }
  const build = instantiate || ((bytes) => new WebAssembly.Instance(new WebAssembly.Module(bytes)));
  try {
    const started = Date.now();
    const instance = build(mod.bytes);
    const fn = instance.exports[name];
    if (typeof fn !== 'function') return { ok: false, error: 'Export ' + JSON.stringify(name) + ' is not callable.' };
    const results = marshalResults(candidate.results, fn(...args));
    return { ok: true, name, results, ms: Date.now() - started };
  } catch (error) {
    return { ok: false, error: String((error && error.message) || error), trapped: error instanceof WebAssembly.RuntimeError };
  }
}

export const WORKER_RUNNER_SOURCE = `'use strict';
self.onmessage = (event) => {
  const { bytes, name, params, results } = event.data;
  try {
    const instance = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array(bytes)));
    const fn = instance.exports[name];
    if (typeof fn !== 'function') throw new Error('Export is not callable');
    const args = params.map((type, i) => type === 'i64' ? BigInt(event.data.args[i]) : event.data.args[i]);
    const out = results.length === 0 ? [] : results.length === 1 ? [fn(...args)] : fn(...args);
    self.postMessage({ ok: true, values: out.map((v, i) => ({ type: results[i], display: typeof v === 'bigint' ? String(v) + 'n' : String(v) })) });
  } catch (error) {
    self.postMessage({ ok: false, error: String((error && error.message) || error) });
  }
};`;

export function reportJSON(mod, { fingerprint, wat } = {}) {
  const graph = callGraph(mod);
  const audit = auditModule(mod, fingerprint);
  return {
    tool: 'wasm-hex-disasm',
    reportVersion: 1,
    fingerprint: { algorithm: 'SHA-256', hex: fingerprint || sha256(mod.bytes) },
    bytes: mod.bytes.length,
    nativeValid: mod.nativeValid,
    sections: mod.sections.map((s) => ({ id: s.id, name: s.name, offset: s.offset, payloadOffset: s.payloadOffset, end: s.end, size: s.end - s.offset })),
    imports: mod.imports.map((i) => ({ module: i.module, name: i.name, kind: i.kind })),
    exports: mod.exports.map((e) => ({ name: e.name, kind: e.kind, index: e.index })),
    functions: graph.nodes.map((n) => ({ index: n.index, kind: n.kind, name: n.name, instructions: n.instructions,
      calls: n.calls, indirect: n.indirect, exported: n.exported, start: n.start, dead: n.dead })),
    callEdges: graph.edges,
    audit: audit.findings,
    opcodeHistogram: opcodeHistogram(mod),
    wat: wat === undefined ? disassemble(mod) : wat
  };
}

const FORMULA_FIRST = new Set(['=', '+', '-', '@', '\t', '\r']);
const csvCell = (value) => {
  let text = String(value);
  const first = text.trimStart().charAt(0);
  if (first && FORMULA_FIRST.has(first)) text = "'" + text;
  return /[",\n\r]/.test(text) || text !== text.trim() ? '"' + text.replace(/"/g, '""') + '"' : text;
};

export function reportCSV(mod) {
  const rows = ['kind,name,size,offset_start,offset_end,count,detail'];
  for (const entry of sectionMap(mod)) rows.push(['section', entry.name, entry.size, entry.offset, entry.end, '', entry.id < 0 ? 'module header' : 'id ' + entry.id].map(csvCell).join(','));
  for (const h of opcodeHistogram(mod)) rows.push(['opcode', h.op, '', '', '', h.count, ''].map(csvCell).join(','));
  for (const i of mod.imports) rows.push(['import', i.module + '.' + i.name, '', '', '', '', i.kind].map(csvCell).join(','));
  for (const e of mod.exports) rows.push(['export', e.name, '', '', '', '', e.kind + ' ' + e.index].map(csvCell).join(','));
  return rows.join('\n') + '\n';
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
export function bytesToBase64url(bytes) {
  const data = byteInput(bytes);
  let out = '';
  for (let i = 0; i < data.length; i += 3) {
    const a = data[i], b = i + 1 < data.length ? data[i + 1] : null, c = i + 2 < data.length ? data[i + 2] : null;
    out += B64[a >> 2] + B64[((a & 3) << 4) | (b === null ? 0 : b >> 4)];
    if (b !== null) out += B64[((b & 15) << 2) | (c === null ? 0 : c >> 6)];
    if (c !== null) out += B64[c & 63];
  }
  return out;
}

export function base64urlToBytes(text) {
  const input = String(text).replace(/=+$/, '');
  if (!/^[A-Za-z0-9_-]*$/.test(input)) throw new Error('Share link data is not base64url');
  if (input.length % 4 === 1) throw new Error('Share link data has an invalid base64url length');
  const lookup = new Map(Array.from(B64, (ch, i) => [ch, i]));
  const remainder = input.length % 4;
  const last = input.length ? lookup.get(input[input.length - 1]) : 0;
  if ((remainder === 2 && (last & 15) !== 0) || (remainder === 3 && (last & 3) !== 0)) {
    throw new Error('Share link data has non-canonical base64url padding bits');
  }
  const out = [];
  for (let i = 0; i < input.length; i += 4) {
    const chunk = input.slice(i, i + 4);
    const values = Array.from(chunk, (ch) => lookup.get(ch));
    out.push((values[0] << 2) | (values.length > 1 ? values[1] >> 4 : 0));
    if (values.length > 2) out.push(((values[1] & 15) << 4) | (values[2] >> 2));
    if (values.length > 3) out.push(((values[2] & 3) << 6) | values[3]);
  }
  return Uint8Array.from(out);
}

export const SHARE_LIMIT = 32768;
export function shareHash(bytes) {
  const data = byteInput(bytes);
  if (data.length > SHARE_LIMIT) return null;
  return '#b=' + bytesToBase64url(data);
}

export function restoreHash(hash) {
  const text = String(hash || '');
  if (!text.startsWith('#b=')) return null;
  const encoded = text.slice(3).replace(/=+$/, '');
  const maxEncodedLength = Math.floor(SHARE_LIMIT / 3) * 4 + (SHARE_LIMIT % 3 ? SHARE_LIMIT % 3 + 1 : 0);
  if (encoded.length > maxEncodedLength) throw new Error('Share link data exceeds the ' + SHARE_LIMIT + ' byte limit');
  return base64urlToBytes(encoded);
}

export function auditModule(mod, fingerprint) {
  const findings = [];
  const add = (id, severity, title, detail) => findings.push({ id, severity, title, detail });
  const funcImports = mod.imports.filter((i) => i.kind === 'func');
  const otherImports = mod.imports.filter((i) => i.kind !== 'func');
  if (mod.imports.length) {
    const list = mod.imports.slice(0, 8).map((i) => i.module + '.' + i.name + ' (' + i.kind + ')').join(', ');
    add('imports', 'flag', 'Host imports required', 'This module needs ' + mod.imports.length + ' host-provided import(s): ' + list +
      (mod.imports.length > 8 ? ', and ' + (mod.imports.length - 8) + ' more' : '') + '. Imported capabilities decide what the host must supply.');
  } else add('imports', 'info', 'No host imports', 'The module instantiates with an empty import object.');
  if (otherImports.length) add('import-kinds', 'notice', 'Non-function imports', otherImports.map((i) => i.kind).join(', ') + ' state arrives from the host.');
  const memories = mod.memories.length + mod.imports.filter((i) => i.kind === 'memory').length;
  const grows = mod.functions.reduce((n, fn) => n + fn.code.filter((i) => i.op === 'memory.grow').length, 0);
  const loadsStores = mod.functions.reduce((n, fn) => n + fn.code.filter((i) => /load|store/.test(i.op)).length, 0);
  if (memories || loadsStores) {
    const headroom = mod.memories.some((m) => m.max === null || m.max > m.min);
    add('memory', 'flag', 'Linear memory in use', mod.memories.length + ' declared memory region(s)' +
      (mod.imports.some((i) => i.kind === 'memory') ? ' plus imported memory' : '') + ', ' + loadsStores +
      ' load/store instruction(s)' + (grows ? ', ' + grows + ' memory.grow site(s)' : '') +
      (headroom ? ', growth headroom beyond the initial size' : '') + '.');
  } else add('memory', 'info', 'No linear memory', 'The module neither declares nor touches linear memory.');
  const indirect = mod.functions.reduce((n, fn) => n + fn.code.filter((i) => i.op === 'call_indirect').length, 0);
  const tableSlots = mod.elements.reduce((n, s) => n + s.functions.length, 0);
  if (indirect || mod.tables.length) add('indirect', 'flag', 'Indirect dispatch present', indirect + ' call_indirect site(s), ' +
    mod.tables.length + ' declared table(s), ' + tableSlots + ' table slot(s). Runtime targets are chosen dynamically.');
  else add('indirect', 'info', 'Only direct calls', 'Every call target is fixed in the bytecode.');
  const traps = mod.functions.reduce((n, fn) => n + fn.code.filter((i) => i.op === 'unreachable').length, 0);
  add('unreachable', traps ? 'notice' : 'info', traps ? 'Trap instructions present' : 'No trap instructions',
    traps + ' unreachable trap(s) abort execution with a RuntimeError when reached.');
  const named = mod.custom.map((c) => c.name);
  if (named.includes('name')) {
    const count = functionNames(mod).size;
    add('names', 'notice', 'Debug names embedded', 'The name custom section exposes ' + count + ' original function symbol(s).');
  }
  const others = named.filter((n) => n !== 'name');
  if (others.length) add('custom', 'notice', 'Custom section payload', 'Nonstandard section(s): ' + others.join(', ') + '.');
  if (mod.start !== null) add('start', 'flag', 'Start function present', 'Function $f' + mod.start + ' runs automatically at instantiation.');
  const mutableGlobals = mod.globals.filter((g) => g.mutable).length;
  if (mutableGlobals) add('globals', 'notice', 'Mutable globals', mutableGlobals + ' mutable global(s) hold module-level state.');
  const graph = callGraph(mod);
  const dead = graph.nodes.filter((n) => n.dead);
  if (dead.length) add('dead', 'notice', 'Unreachable functions', dead.length + ' defined function(s) are not reachable from exports, start or tables: ' +
    dead.slice(0, 8).map((n) => n.name).join(', ') + (dead.length > 8 ? ', ...' : '') + '.');
  add('fingerprint', 'info', 'SHA-256 fingerprint', fingerprint || sha256(mod.bytes));
  add('valid', mod.nativeValid === true ? 'info' : mod.nativeValid === false ? 'flag' : 'notice',
    mod.nativeValid === true ? 'Native validation passed' : mod.nativeValid === false ? 'Native validation failed' : 'Native validation unavailable',
    mod.nativeValid === null ? 'This environment has no WebAssembly object to check parity.' : 'WebAssembly.validate() agrees with the parse result.');
  const plan = sandboxPlan(mod);
  add('runner', plan.runnable ? 'info' : 'notice', plan.runnable ? 'Sandbox runner available' : 'Sandboxed execution declined', plan.reason);
  return { findings, counts: { flags: findings.filter((f) => f.severity === 'flag').length, notices: findings.filter((f) => f.severity === 'notice').length } };
}

export function runSelfTests() {
  const results = [];
  const check = (id, name, fn) => {
    try { results.push({ id, name, ok: true, detail: fn() }); }
    catch (error) { results.push({ id, name, ok: false, detail: String((error && error.message) || error) }); }
  };
  const fail = (m) => { throw new Error(m); };
  check('leb-u32', 'Unsigned LEB128 round trip', () => {
    for (const n of [0, 1, 127, 128, 255, 16383, 16384, 2097151, 624485, 4294967295]) {
      const r = new Reader(Uint8Array.from(encodeULEB(n)));
      if (r.u32() !== n) fail('u32 mismatch at ' + n);
    }
    return '10 boundary values decoded exactly';
  });
  check('leb-s32', 'Signed LEB128 round trip', () => {
    for (const n of [0, 1, -1, 63, 64, -63, -64, -129, -128, 8191, -8192, 2147483647, -2147483648]) {
      if (new Reader(Uint8Array.from(encodeSLEB(n))).s32() !== n) fail('s32 mismatch at ' + n);
    }
    return '13 signed values decoded exactly';
  });
  check('leb-s64', 'Signed 64-bit LEB128 round trip', () => {
    for (const n of [0n, -1n, 1n << 62n, -(1n << 62n), (1n << 63n) - 1n, -(1n << 63n)]) {
      if (new Reader(Uint8Array.from(encodeSLEB(n))).s64() !== n) fail('s64 mismatch at ' + n);
    }
    return '6 sixty-four-bit values decoded exactly';
  });
  check('magic-version', 'Magic and version enforcement', () => {
    parseModule(demoModule());
    for (const index of [0, 2, 4, 7]) {
      const broken = demoModule().slice();
      broken[index] ^= 1;
      let threw = false;
      try { parseModule(broken); } catch (error) { threw = error instanceof BinaryError; }
      if (!threw) fail('byte ' + index + ' corruption was accepted');
    }
    return 'corrupted magic and version bytes rejected at 4 positions';
  });
  check('sha256', 'SHA-256 known vectors', () => {
    const vectors = [
      ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
      ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
      ['The quick brown fox jumps over the lazy dog', 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592']
    ];
    for (const [text, hex] of vectors) {
      if (sha256(new TextEncoder().encode(text)) !== hex) fail('vector mismatch for ' + JSON.stringify(text.slice(0, 12)));
    }
    return '3 published vectors verified';
  });
  check('validate-parity', 'WebAssembly.validate() parity', () => {
    if (typeof WebAssembly === 'undefined') return 'skipped, no WebAssembly object';
    for (const kind of ['add', 'sum', 'select']) {
      const bytes = demoModule(kind), mod = parseModule(bytes);
      if (mod.nativeValid !== WebAssembly.validate(bytes) || mod.nativeValid !== true) fail('parity mismatch on ' + kind);
    }
    const invalid = Uint8Array.from([0, 97, 115, 109, 1, 0, 0, 0,
      1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 10, 6, 1, 4, 0, 0x10, 99, 0x0b]);
    const mod = parseModule(invalid, { validate: false });
    if (mod.nativeValid !== false || mod.nativeValid !== WebAssembly.validate(invalid)) fail('parity mismatch on invalid input');
    return 'parser verdict matches native validate on 4 inputs';
  });
  check('disassembly', 'Listing reflects decoded instructions', () => {
    const wat = disassemble(parseModule(demoModule('add')));
    if (!/local\.get 0/.test(wat) || !/i32\.add/.test(wat)) fail('missing decoded instructions');
    return 'decoded body rendered in the text listing';
  });
  check('callgraph', 'Call graph edge integrity', () => {
    const graph = callGraph(parseModule(demoModule('add')));
    if (graph.nodes.length !== 1 || graph.nodes[0].exported[0] !== 'add' || graph.nodes[0].dead) fail('graph shape wrong');
    for (const edge of graph.edges) if (!graph.nodes[edge.from] || !graph.nodes[edge.to]) fail('edge endpoint missing');
    return '1 node, every edge lands on a real function';
  });
  check('histogram', 'Opcode histogram totals', () => {
    const mod = parseModule(demoModule('sum'));
    const hist = opcodeHistogram(mod);
    const total = hist.reduce((n, h) => n + h.count, 0);
    const actual = mod.functions.reduce((n, fn) => n + fn.code.length, 0);
    if (total !== actual) fail('histogram total ' + total + ' != ' + actual);
    return total + ' instructions accounted for';
  });
  check('share-hash', 'Share link round trip', () => {
    const bytes = demoModule('select');
    const restored = restoreHash(shareHash(bytes));
    if (!restored || restored.length !== bytes.length || restored.some((b, i) => b !== bytes[i])) fail('restored bytes differ');
    return bytes.length + ' bytes encoded and restored exactly';
  });
  return results;
}
