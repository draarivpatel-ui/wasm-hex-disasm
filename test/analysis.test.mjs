import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  sha256, sectionMap, functionNames, callGraph, auditModule, sandboxPlan, marshalArgs,
  runExport, opcodeHistogram, reportJSON, reportCSV, bytesToBase64url, base64urlToBytes,
  shareHash, restoreHash, runSelfTests, WORKER_RUNNER_SOURCE, SHARE_LIMIT
} from '../src/analysis.mjs';
import { parseModule, demoModule, encodeULEB } from '../src/wasm.mjs';
import { moduleBytes, section, nameBytes, functionModule, constant, nameSection, customSection, importEntry } from './helpers/fixture.mjs';

const uleb = encodeULEB;
const enc = (s) => new TextEncoder().encode(s);
const parse = (bytes, opts) => parseModule(bytes, { validate: false, ...opts });

const reference = (bytes) => createHash('sha256').update(bytes).digest('hex');

// ---- sha256 ----

test('sha256 matches the published empty-message vector', () => {
  assert.equal(sha256(new Uint8Array(0)), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});
test('sha256 matches the published abc vector', () => {
  assert.equal(sha256(enc('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
test('sha256 matches the published quick brown fox vector', () => {
  assert.equal(sha256(enc('The quick brown fox jumps over the lazy dog')), 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
});
test('sha256 matches the million-a vector', () => {
  assert.equal(sha256(new Uint8Array(1000000).fill(97)), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
});
for (const n of [55, 56, 63, 64, 65, 119, 120, 127, 128]) {
  test('sha256 handles the ' + n + '-byte padding boundary', () => {
    const data = Uint8Array.from({ length: n }, (_, i) => (i * 31 + n) & 255);
    assert.equal(sha256(data), reference(data));
  });
}
for (const n of [1, 3, 17, 256, 1024]) {
  test('sha256 agrees with node:crypto on ' + n + ' arbitrary bytes', () => {
    const data = Uint8Array.from({ length: n }, (_, i) => (i * 167 + 13) & 255);
    assert.equal(sha256(data), reference(data));
  });
}
test('sha256 output is always 64 lowercase hex characters', () => {
  for (const kind of ['add', 'sum', 'select']) assert.match(sha256(demoModule(kind)), /^[0-9a-f]{64}$/);
});
test('sha256 accepts plain arrays as well as Uint8Array', () => {
  assert.equal(sha256([97, 98, 99]), sha256(enc('abc')));
});

// ---- sectionMap ----

test('sectionMap leads with a header region covering the 8 magic bytes', () => {
  const map = sectionMap(parseModule(demoModule()));
  assert.equal(map[0].name, 'header');
  assert.equal(map[0].offset, 0);
  assert.equal(map[0].end, 8);
});
test('sectionMap sizes sum exactly to the module byte length', () => {
  for (const kind of ['add', 'sum', 'select']) {
    const mod = parseModule(demoModule(kind));
    const total = sectionMap(mod).reduce((n, e) => n + e.size, 0);
    assert.equal(total, mod.bytes.length);
  }
});
test('sectionMap shares are positive and sum to one', () => {
  const mod = parseModule(demoModule('sum'));
  const shares = sectionMap(mod).map((e) => e.share);
  assert.ok(shares.every((s) => s > 0 && s <= 1));
  assert.ok(Math.abs(shares.reduce((a, b) => a + b, 0) - 1) < 1e-9);
});
test('sectionMap order follows file order including custom sections', () => {
  const mod = parseModule(moduleBytes(
    customSection('lead', [1, 2, 3]),
    section(1, [1, 0x60, 0, 0]),
    customSection('tail', [9])));
  assert.deepEqual(sectionMap(mod).map((e) => e.name), ['header', 'custom', 'type', 'custom']);
});
test('sectionMap on a header-only module is a single full-width region', () => {
  const mod = parseModule(moduleBytes());
  const map = sectionMap(mod);
  assert.equal(map.length, 1);
  assert.equal(map[0].share, 1);
});
test('sectionMap regions carry their section index for selection', () => {
  const mod = parseModule(demoModule());
  const map = sectionMap(mod);
  assert.equal(map[0].index, -1);
  assert.equal(map[1].index, 0);
  assert.equal(map[1].offset, mod.sections[0].offset);
});

// ---- functionNames ----

test('functionNames reads function indices from the name custom section', () => {
  const bytes = moduleBytes(nameSection([[0, 'first'], [1, 'second']]),
    section(1, [1, 0x60, 0, 0]), section(3, [2, 0, 0]),
    section(10, [2].concat(uleb(2), [0, 0x0b], uleb(2), [0, 0x0b])));
  const names = functionNames(parse(bytes));
  assert.equal(names.get(0), 'first');
  assert.equal(names.get(1), 'second');
});
test('functionNames is empty without a name section', () => {
  assert.equal(functionNames(parseModule(demoModule())).size, 0);
});
test('functionNames ignores malformed subsection payloads', () => {
  const broken = moduleBytes(customSection('name', [1, 200, 0, 3, 65]),
    section(1, [1, 0x60, 0, 0]));
  assert.equal(functionNames(parse(broken)).size, 0);
});
test('functionNames ignores custom sections with other names', () => {
  const bytes = moduleBytes(customSection('other', nameBytes('fake').concat([0])),
    section(1, [1, 0x60, 0, 0]));
  assert.equal(functionNames(parse(bytes)).size, 0);
});
test('functionNames skips unknown subsections inside the name section', () => {
  const unknown = [9, 2, 1, 2];
  const inner = [1, 0].concat(nameBytes('kept'));
  const payload = nameBytes('name').concat(unknown, [1], uleb(inner.length), inner);
  const bytes = moduleBytes(section(0, payload), section(1, [1, 0x60, 0, 0]));
  assert.equal(functionNames(parse(bytes)).get(0), 'kept');
});

// ---- callGraph ----

const callModule = (extra = []) => moduleBytes(
  nameSection([[0, 'host'], [1, 'runner'], [2, 'helper'], [3, 'ghost']]),
  section(1, [1, 0x60, 0, 1, 0x7f]),
  section(2, [1].concat(importEntry('env', 'host', [0, 0]))),
  section(3, [3, 0, 0, 0]),
  section(7, [1].concat(nameBytes('run'), [0, 1])),
  ...extra,
  section(10, [3]
    .concat(uleb(7), [0, 0x10, 0, 0x1a, 0x10, 2, 0x0b])
    .concat(uleb(4), [0, 0x10, 0, 0x0b])
    .concat(uleb(4), [0, 0x41, 9, 0x0b])));

test('callGraph labels imported and defined functions', () => {
  const graph = callGraph(parse(callModule()));
  assert.equal(graph.nodes[0].kind, 'imported');
  assert.equal(graph.nodes[0].importedFrom, 'env.host');
  assert.equal(graph.nodes[1].kind, 'defined');
});
test('callGraph resolves names from the name section', () => {
  const graph = callGraph(parse(callModule()));
  assert.equal(graph.nodes[1].name, 'runner');
  assert.equal(graph.nodes[3].name, 'ghost');
});
test('callGraph falls back to index names without a name section', () => {
  const graph = callGraph(parseModule(demoModule()));
  assert.equal(graph.nodes[0].name, '$f0');
});
test('callGraph records deduplicated direct call edges', () => {
  const graph = callGraph(parse(callModule()));
  assert.deepEqual(graph.nodes[1].calls, [0, 2]);
  assert.deepEqual(graph.edges.map((e) => e.from + '>' + e.to).sort(), ['1>0', '1>2', '2>0']);
});
test('callGraph marks unreachable defined functions as dead', () => {
  const graph = callGraph(parse(callModule()));
  assert.equal(graph.nodes[3].dead, true);
  assert.equal(graph.nodes[1].dead, false);
  assert.equal(graph.nodes[2].dead, false);
});
test('callGraph keeps imported nodes out of the dead classification', () => {
  const graph = callGraph(parse(callModule()));
  assert.equal(graph.nodes[0].dead, false);
});
test('callGraph treats table element targets as reachable roots', () => {
  const bytes = moduleBytes(
    section(1, [1, 0x60, 0, 1, 0x7f]),
    section(3, [1, 0]),
    section(4, [1, 0x70, 0, 2]),
    section(9, [1, 0, 0x41, 0, 0x0b, 1, 0]),
    section(10, [1].concat(uleb(4), [0, 0x41, 9, 0x0b])));
  const graph = callGraph(parse(bytes));
  assert.equal(graph.nodes[0].dead, false);
});
test('callGraph marks the start function and keeps it alive', () => {
  const bytes = moduleBytes(
    section(1, [1, 0x60, 0, 0]),
    section(3, [2, 0, 0]),
    section(8, [1]),
    section(10, [2].concat(uleb(2), [0, 0x0b], uleb(2), [0, 0x0b])));
  const graph = callGraph(parse(bytes));
  assert.equal(graph.nodes[1].start, true);
  assert.equal(graph.nodes[1].dead, false);
});
test('callGraph flags call_indirect usage per function', () => {
  const table = section(4, [1, 0x70, 0, 1]);
  const body = [0x20, 0, 0x11, 0, 0, 0x1a];
  const bytes = functionModule(body, { params: [0x7f], results: [], extra: [table] });
  const graph = callGraph(parse(bytes));
  assert.equal(graph.nodes[0].indirect, true);
  assert.equal(graph.hasIndirect, true);
});
test('callGraph keeps self-recursive edges', () => {
  const bytes = functionModule([0x10, 0], { params: [], results: [] });
  const graph = callGraph(parse(bytes));
  assert.deepEqual(graph.edges, [{ from: 0, to: 0 }]);
});
test('callGraph counts real instruction totals per node', () => {
  const mod = parseModule(demoModule('add'));
  const graph = callGraph(mod);
  assert.equal(graph.nodes[0].instructions, mod.functions[0].code.length);
});
test('callGraph on a module without functions is empty', () => {
  const graph = callGraph(parseModule(moduleBytes(section(5, [1, 0, 1]))));
  assert.equal(graph.nodes.length, 0);
  assert.equal(graph.edges.length, 0);
});
test('callGraph reachable set lists every index the exports can reach', () => {
  const graph = callGraph(parse(callModule()));
  assert.deepEqual(graph.reachable, [0, 1, 2]);
});
test('callGraph reports export names on their nodes', () => {
  const graph = callGraph(parse(callModule()));
  assert.deepEqual(graph.nodes[1].exported, ['run']);
  assert.deepEqual(graph.nodes[2].exported, []);
});

// ---- auditModule ----

const finding = (audit, id) => audit.findings.find((f) => f.id === id);

test('audit flags host imports with their module and name', () => {
  const audit = auditModule(parse(callModule()));
  assert.equal(finding(audit, 'imports').severity, 'flag');
  assert.match(finding(audit, 'imports').detail, /env\.host/);
});
test('audit reports an empty import object as informational', () => {
  const audit = auditModule(parseModule(demoModule()));
  assert.equal(finding(audit, 'imports').severity, 'info');
});
test('audit flags declared linear memory and load store usage', () => {
  const mod = parse(moduleBytes(
    section(1, [1, 0x60, 0, 0]), section(3, [1, 0]), section(5, [1, 0, 1]),
    section(10, [1].concat(uleb(7), [0, 0x41, 0, 0x36, 2, 0, 0x0b]))));
  const memory = finding(auditModule(mod), 'memory');
  assert.equal(memory.severity, 'flag');
  assert.match(memory.detail, /1 declared memory/);
});
test('audit counts memory.grow sites separately', () => {
  const mod = parse(moduleBytes(
    section(1, [1, 0x60, 0, 0]), section(3, [1, 0]), section(5, [1, 0, 1]),
    section(10, [1].concat(uleb(5), [0, 0x40, 0, 0x1a, 0x0b]))));
  assert.match(finding(auditModule(mod), 'memory').detail, /memory\.grow/);
});
test('audit reports modules with no linear memory', () => {
  const audit = auditModule(parseModule(demoModule()));
  assert.equal(finding(audit, 'memory').severity, 'info');
});
test('audit flags indirect dispatch sites and table slots', () => {
  const body = [0, 0x20, 0, 0x11, 0, 0, 0x1a, 0x0b];
  const bytes = moduleBytes(
    section(1, [1, 0x60, 1, 0x7f, 0]),
    section(3, [1, 0]),
    section(4, [1, 0x70, 0, 2]),
    section(7, [1].concat(nameBytes('run'), [0, 0])),
    section(9, [1, 0, 0x41, 0, 0x0b, 1, 0]),
    section(10, [1].concat(uleb(body.length), body)));
  const f = finding(auditModule(parse(bytes)), 'indirect');
  assert.equal(f.severity, 'flag');
  assert.match(f.detail, /1 call_indirect site/);
});
test('audit counts unreachable trap instructions', () => {
  const mod = parse(functionModule([0x00], { params: [], results: [] }));
  assert.match(finding(auditModule(mod), 'unreachable').detail, /1 unreachable trap/);
});
test('audit notes embedded debug names', () => {
  const mod = parse(moduleBytes(nameSection([[0, 'secret_symbol']]),
    section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(10, [1].concat(uleb(2), [0, 0x0b]))));
  const f = finding(auditModule(mod), 'names');
  assert.equal(f.severity, 'notice');
  assert.match(f.detail, /1 original function symbol/);
});
test('audit notes nonstandard custom sections', () => {
  const mod = parse(moduleBytes(customSection('producers', [1, 2, 3])));
  assert.match(finding(auditModule(mod), 'custom').detail, /producers/);
});
test('audit flags automatic start functions', () => {
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(8, [0]), section(10, [1].concat(uleb(2), [0, 0x0b])));
  const f = finding(auditModule(parse(bytes)), 'start');
  assert.equal(f.severity, 'flag');
  assert.match(f.detail, /\$f0/);
});
test('audit counts mutable globals', () => {
  const bytes = moduleBytes(section(6, [1, 0x7f, 1, 0x41, 0, 0x0b]));
  assert.match(finding(auditModule(parse(bytes)), 'globals').detail, /1 mutable global/);
});
test('audit names unreachable functions it finds', () => {
  const audit = auditModule(parse(callModule()));
  assert.match(finding(audit, 'dead').detail, /ghost/);
});
test('audit embeds the module fingerprint as a finding', () => {
  const mod = parseModule(demoModule());
  assert.equal(finding(auditModule(mod), 'fingerprint').detail, sha256(mod.bytes));
});
test('audit severity counts are internally consistent', () => {
  const audit = auditModule(parse(callModule()));
  assert.equal(audit.counts.flags, audit.findings.filter((f) => f.severity === 'flag').length);
  assert.equal(audit.counts.notices, audit.findings.filter((f) => f.severity === 'notice').length);
});
test('audit accepts a precomputed fingerprint', () => {
  const audit = auditModule(parseModule(demoModule()), 'ff'.repeat(32));
  assert.equal(finding(audit, 'fingerprint').detail, 'ff'.repeat(32));
});

// ---- sandboxPlan ----

test('sandboxPlan allows the zero-import demonstrations', () => {
  for (const kind of ['add', 'sum', 'select']) assert.equal(sandboxPlan(parseModule(demoModule(kind))).runnable, true);
});
test('sandboxPlan refuses modules that need host imports', () => {
  const plan = sandboxPlan(parse(callModule()));
  assert.equal(plan.runnable, false);
  assert.match(plan.reason, /host import/);
});
test('sandboxPlan refuses modules with an automatic start', () => {
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(8, [0]), section(10, [1].concat(uleb(2), [0, 0x0b])));
  const plan = sandboxPlan(parse(bytes));
  assert.equal(plan.runnable, false);
  assert.match(plan.reason, /start function/);
});
test('sandboxPlan lists runnable integer exports with signatures', () => {
  const plan = sandboxPlan(parseModule(demoModule('add')));
  assert.equal(plan.candidates.length, 1);
  assert.deepEqual(plan.candidates[0].params, ['i32', 'i32']);
  assert.deepEqual(plan.candidates[0].results, ['i32']);
  assert.equal(plan.candidates[0].runnable, true);
});
test('sandboxPlan marks non-integer signatures as unavailable', () => {
  const mod = parseModule(functionModule([0x20, 0], { params: [0x7c], results: [0x7c] }));
  const plan = sandboxPlan(mod);
  assert.equal(plan.candidates[0].runnable, false);
  assert.match(plan.candidates[0].reason, /integer/);
});
test('sandboxPlan accepts i64 integer signatures', () => {
  const mod = parseModule(functionModule([0x20, 0], { params: [0x7e], results: [0x7e] }));
  assert.equal(sandboxPlan(mod).candidates[0].runnable, true);
});
test('sandboxPlan skips non-function exports', () => {
  const bytes = moduleBytes(section(5, [1, 0, 1]), section(7, [1].concat(nameBytes('mem'), [2, 0])));
  assert.equal(sandboxPlan(parse(bytes)).candidates.length, 0);
});
test('sandboxPlan on a module without exports has no candidates', () => {
  assert.equal(sandboxPlan(parseModule(moduleBytes())).candidates.length, 0);
});

// ---- marshalArgs ----

test('marshalArgs converts integer parameters', () => {
  assert.deepEqual(marshalArgs(['i32', 'i32'], [2, 3]), [2, 3]);
});
test('marshalArgs converts string integers for i64 to BigInt', () => {
  assert.deepEqual(marshalArgs(['i64'], ['9007199254740993']), [9007199254740993n]);
});
test('marshalArgs rejects a wrong argument count', () => {
  assert.throws(() => marshalArgs(['i32', 'i32'], [1]), /takes 2 parameter/);
});
test('marshalArgs rejects non-array input', () => {
  assert.throws(() => marshalArgs(['i32'], 7), /JSON array/);
});
test('marshalArgs rejects fractional and nonnumeric i32 values', () => {
  for (const v of [1.5, 'x', NaN, Infinity, undefined]) assert.throws(() => marshalArgs(['i32'], [v]), /integer/);
});
test('marshalArgs wraps out-of-range i32 values like a real call', () => {
  assert.equal(marshalArgs(['i32'], [4294967296])[0], 0);
});
test('marshalArgs rejects unmarshalable i64 values', () => {
  assert.throws(() => marshalArgs(['i64'], ['nope']), /integer/);
});
test('marshalArgs passes finite numbers to float parameters', () => {
  assert.equal(marshalArgs(['f64'], ['1.5'])[0], 1.5);
});
test('marshalArgs refuses reference-typed parameters', () => {
  assert.throws(() => marshalArgs(['funcref'], [0]), /cannot be supplied/);
});

// ---- runExport ----

test('runExport executes a zero-import addition natively', () => {
  const result = runExport(parseModule(demoModule('add')), 'add', [2, 3]);
  assert.equal(result.ok, true);
  assert.equal(result.results[0].display, '5');
  assert.equal(result.results[0].type, 'i32');
});
test('runExport reports a real millisecond duration', () => {
  const result = runExport(parseModule(demoModule('add')), 'add', [1, 2]);
  assert.ok(Number.isFinite(result.ms) && result.ms >= 0);
});
test('runExport declines modules that need imports', () => {
  const result = runExport(parse(callModule()), 'run', []);
  assert.equal(result.ok, false);
  assert.match(result.error, /host import/);
});
test('runExport declines names that are not function exports', () => {
  const result = runExport(parseModule(demoModule()), 'missing', []);
  assert.equal(result.ok, false);
  assert.match(result.error, /not a function/);
});
test('runExport surfaces argument errors without executing', () => {
  const result = runExport(parseModule(demoModule('add')), 'add', [1]);
  assert.equal(result.ok, false);
  assert.match(result.error, /2 parameter/);
});
test('runExport converts i64 results to their tagged display form', () => {
  const mod = parseModule(functionModule([0x20, 0], { params: [0x7e], results: [0x7e] }));
  const result = runExport(mod, 'run', ['9007199254740993']);
  assert.equal(result.ok, true);
  assert.equal(result.results[0].display, '9007199254740993n');
});
test('runExport marks native traps as trapped failures', () => {
  const mod = parseModule(functionModule([0x00], { params: [], results: [] }));
  const result = runExport(mod, 'run', []);
  assert.equal(result.ok, false);
  assert.equal(result.trapped, true);
});
test('runExport returns every result of a multi-value function', () => {
  const mod = parseModule(functionModule([0x20, 0, 0x20, 1], { params: [0x7f, 0x7f], results: [0x7f, 0x7f] }));
  const result = runExport(mod, 'run', [4, 9]);
  assert.deepEqual(result.results.map((r) => r.display), ['4', '9']);
});
test('runExport supports an injected instantiation backend', () => {
  const mod = parseModule(demoModule('add'));
  let seen = 0;
  const result = runExport(mod, 'add', [20, 22], {
    instantiate: (bytes) => { seen = bytes.length; return { exports: { add: (a, b) => a + b } }; }
  });
  assert.equal(result.ok, true);
  assert.equal(result.results[0].display, '42');
  assert.equal(seen, mod.bytes.length);
});
test('WORKER_RUNNER_SOURCE is self-contained and instantiates only what it is given', () => {
  assert.match(WORKER_RUNNER_SOURCE, /WebAssembly\.Instance/);
  assert.doesNotMatch(WORKER_RUNNER_SOURCE, /fetch|XMLHttpRequest|import\(/);
});

// ---- opcodeHistogram ----

test('opcodeHistogram counts every decoded instruction', () => {
  const mod = parseModule(demoModule('add'));
  const hist = Object.fromEntries(opcodeHistogram(mod).map((h) => [h.op, h.count]));
  assert.equal(hist['local.get'], 2);
  assert.equal(hist['i32.add'], 1);
  assert.equal(hist['end'], 1);
});
test('opcodeHistogram is sorted by descending frequency', () => {
  const hist = opcodeHistogram(parseModule(demoModule('sum')));
  for (let i = 1; i < hist.length; i++) assert.ok(hist[i - 1].count >= hist[i].count);
});
test('opcodeHistogram totals equal the sum of function code lengths', () => {
  for (const kind of ['add', 'sum', 'select']) {
    const mod = parseModule(demoModule(kind));
    const total = opcodeHistogram(mod).reduce((n, h) => n + h.count, 0);
    assert.equal(total, mod.functions.reduce((n, fn) => n + fn.code.length, 0));
  }
});
test('opcodeHistogram ignores imported functions that carry no code', () => {
  const hist = opcodeHistogram(parse(callModule()));
  const total = hist.reduce((n, h) => n + h.count, 0);
  assert.equal(total, 8);
});
test('opcodeHistogram is empty for a module with no code', () => {
  assert.deepEqual(opcodeHistogram(parseModule(moduleBytes())), []);
});

// ---- reportJSON ----

test('reportJSON carries the tool name, version and fingerprint', () => {
  const mod = parseModule(demoModule());
  const report = reportJSON(mod);
  assert.equal(report.tool, 'wasm-hex-disasm');
  assert.equal(report.fingerprint.hex, sha256(mod.bytes));
  assert.equal(report.fingerprint.algorithm, 'SHA-256');
});
test('reportJSON sections account for every byte', () => {
  const mod = parseModule(demoModule('sum'));
  const report = reportJSON(mod);
  assert.equal(report.bytes, mod.bytes.length);
  const covered = report.sections.reduce((n, s) => n + s.size, 0);
  assert.equal(covered, mod.bytes.length - 8);
});
test('reportJSON survives a JSON round trip unchanged', () => {
  const mod = parse(callModule());
  const report = reportJSON(mod);
  assert.deepEqual(JSON.parse(JSON.stringify(report)), report);
});
test('reportJSON is deterministic for the same module', () => {
  const mod = parseModule(demoModule('select'));
  assert.equal(JSON.stringify(reportJSON(mod)), JSON.stringify(reportJSON(mod)));
});
test('reportJSON function entries carry dead and indirect flags', () => {
  const report = reportJSON(parse(callModule()));
  const ghost = report.functions.find((f) => f.name === 'ghost');
  assert.equal(ghost.dead, true);
});
test('reportJSON embeds the audit findings and the listing', () => {
  const report = reportJSON(parseModule(demoModule('sum')));
  assert.ok(report.audit.length > 5);
  assert.match(report.wat, /\(module/);
});
test('reportJSON lists imports and exports with kinds and indices', () => {
  const report = reportJSON(parse(callModule()));
  assert.deepEqual(report.imports, [{ module: 'env', name: 'host', kind: 'func' }]);
  assert.deepEqual(report.exports, [{ name: 'run', kind: 'func', index: 1 }]);
});
test('reportJSON includes the opcode histogram', () => {
  const report = reportJSON(parseModule(demoModule('add')));
  assert.ok(report.opcodeHistogram.some((h) => h.op === 'i32.add'));
});

// ---- reportCSV ----

test('reportCSV starts with a fixed header row', () => {
  assert.ok(reportCSV(parseModule(demoModule())).startsWith('kind,name,size,offset_start,offset_end,count,detail\n'));
});
test('reportCSV contains a section row for every mapped region', () => {
  const mod = parseModule(demoModule());
  const rows = reportCSV(mod).trimEnd().split('\n');
  const sections = rows.filter((r) => r.startsWith('section,'));
  assert.equal(sections.length, sectionMap(mod).length);
  assert.match(sections[0], /^section,header,8,0,8/);
});
test('reportCSV contains opcode rows with real counts', () => {
  const rows = reportCSV(parseModule(demoModule('add'))).split('\n');
  assert.ok(rows.some((r) => r === 'opcode,i32.add,,,,1,'));
});
test('reportCSV quotes names containing commas or quotes', () => {
  const bytes = moduleBytes(
    section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(7, [1].concat(nameBytes('weird,"name'), [0, 0])),
    section(10, [1].concat(uleb(2), [0, 0x0b])));
  const csv = reportCSV(parseModule(bytes));
  assert.ok(csv.includes('export,"weird,""name"'));
});
test('reportCSV lists import and export rows', () => {
  const csv = reportCSV(parse(callModule()));
  assert.ok(csv.includes('import,env.host,,,,,func'));
  assert.ok(csv.includes('export,run,,,,,func 1'));
});

// ---- base64url and share links ----

test('bytesToBase64url round trips every byte value', () => {
  const data = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.deepEqual(base64urlToBytes(bytesToBase64url(data)), data);
});
for (const n of [1, 2, 3, 4, 5, 7, 8, 33]) {
  test('base64url round trips a ' + n + '-byte payload without padding', () => {
    const data = Uint8Array.from({ length: n }, (_, i) => i * 37 + n);
    const text = bytesToBase64url(data);
    assert.equal(text.includes('='), false);
    assert.deepEqual([...base64urlToBytes(text)], [...data]);
  });
}
test('base64url uses only URL safe characters', () => {
  const text = bytesToBase64url(Uint8Array.from([251, 255, 190, 239, 0, 255]));
  assert.match(text, /^[A-Za-z0-9_-]+$/);
});
test('base64url of three 0xff bytes is the known pattern', () => {
  assert.equal(bytesToBase64url(Uint8Array.from([255, 255, 255])), '____');
});
test('base64urlToBytes rejects characters outside the alphabet', () => {
  assert.throws(() => base64urlToBytes('a+b/c=='), /base64url/);
  assert.throws(() => base64urlToBytes('abc!'), /base64url/);
});
test('base64urlToBytes tolerates padding characters', () => {
  assert.deepEqual([...base64urlToBytes('YQ==')], [97]);
});
test('shareHash produces a restoreable bookmark for small modules', () => {
  const bytes = demoModule('select');
  const hash = shareHash(bytes);
  assert.ok(hash.startsWith('#b='));
  assert.deepEqual([...restoreHash(hash)], [...bytes]);
});
test('shareHash refuses modules beyond the bookmark limit', () => {
  assert.equal(shareHash(new Uint8Array(SHARE_LIMIT + 1)), null);
  assert.equal(typeof shareHash(new Uint8Array(SHARE_LIMIT)), 'string');
});
test('restoreHash returns null for unrelated fragments', () => {
  assert.equal(restoreHash(''), null);
  assert.equal(restoreHash('#section'), null);
  assert.equal(restoreHash(null), null);
});
test('restoreHash throws on corrupt bookmark data', () => {
  assert.throws(() => restoreHash('#b=!!!'), /base64url/);
});

// ---- runSelfTests ----

test('runSelfTests returns a full battery that all passes', () => {
  const results = runSelfTests();
  assert.ok(results.length >= 9);
  for (const r of results) assert.equal(r.ok, true, r.id + ' failed: ' + r.detail);
});
test('runSelfTests entries carry stable ids, names and details', () => {
  for (const r of runSelfTests()) {
    assert.match(r.id, /^[a-z0-9-]+$/);
    assert.ok(r.name.length > 3);
    assert.ok(r.detail.length > 3);
  }
});
test('runSelfTests covers the required verification areas', () => {
  const ids = runSelfTests().map((r) => r.id);
  for (const id of ['leb-u32', 'leb-s32', 'leb-s64', 'magic-version', 'sha256', 'validate-parity', 'callgraph', 'histogram', 'share-hash']) {
    assert.ok(ids.includes(id), id + ' missing');
  }
});
