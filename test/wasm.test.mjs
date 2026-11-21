import test from 'node:test';
import assert from 'node:assert/strict';
import { Reader, BinaryError, encodeULEB, encodeSLEB, parseModule, disassemble, traceFunction, demoModule, parseHex, hexRows } from '../src/wasm.mjs';
import { functionModule, moduleBytes, section, nameBytes, constant } from './helpers/fixture.mjs';

test('Unsigned integer decoder agrees with exact 32-bit boundary values', () => {
  for (const n of [0, 1, 127, 128, 624485, 4294967295]) {
    const bytes = Uint8Array.from(encodeULEB(n)), r = new Reader(bytes);
    assert.equal(r.u32(), n); r.done();
    assert.equal(r.spans[0].end, bytes.length);
  }
});

test('Signed integer decoders retain both 32 and 64-bit extremes', () => {
  for (const n of [-2147483648, -624485, -129, -128, -1, 0, 127, 128, 2147483647]) assert.equal(new Reader(Uint8Array.from(encodeSLEB(n))).s32(), n);
  for (const n of [-(1n << 63n), -1n, 0n, (1n << 63n) - 1n]) assert.equal(new Reader(Uint8Array.from(encodeSLEB(n))).s64(), n);
});

test('Redundant bounded encodings are accepted while oversized ones fail', () => {
  assert.equal(new Reader(Uint8Array.from([0x80, 0])).u32(), 0);
  assert.equal(new Reader(Uint8Array.from([0xff, 0x7f])).s32(), -1);
  for (const bytes of [[0x80], [0x80, 0x80, 0x80, 0x80, 0x80, 0], [0xff, 0xff, 0xff, 0xff, 0x10]]) {
    assert.throws(() => new Reader(Uint8Array.from(bytes)).u32(), BinaryError);
  }
  assert.throws(() => new Reader(Uint8Array.from(encodeSLEB(2147483648))).s32(), BinaryError);
});

test('Reader byte ranges and UTF-8 strings fail with a real offset', () => {
  assert.throws(() => new Reader(Uint8Array.from([1])).take(2), /byte 0/);
  assert.throws(() => new Reader(Uint8Array.from([1, 255])).name(), /Invalid UTF-8/);
  assert.throws(() => new Reader(new Uint8Array(2), 0, 3), /Invalid byte range/);
});

test('All bundled demonstrations are valid native modules', () => {
  for (const kind of ['add', 'sum', 'select']) {
    const bytes = demoModule(kind), mod = parseModule(bytes);
    assert.equal(WebAssembly.validate(bytes), true);
    assert.equal(mod.nativeValid, true);
    assert.equal(mod.exports[0].name, kind);
    assert.equal(mod.functions.length, 1);
    assert.ok(mod.lebSpans.length > 5);
  }
});

test('Parser rejects wrong magic, version, truncation and trailing instructions', () => {
  const original = demoModule();
  for (const index of [0, 1, 4]) { const b = original.slice(); b[index] ^= 1; assert.throws(() => parseModule(b), BinaryError); }
  for (let n = 0; n < original.length; n++) {
    const b = original.slice(0, n);
    if (!WebAssembly.validate(b)) assert.throws(() => parseModule(b), BinaryError);
  }
  assert.throws(() => parseModule(functionModule([0x20, 0, 0x0b, 0x01])), /Unconsumed/);
});

test('Duplicate, unordered and unknown sections cannot produce a clean inspection', () => {
  assert.throws(() => parseModule(moduleBytes(section(1, [0]), section(1, [0]))), /Duplicate/);
  assert.throws(() => parseModule(moduleBytes(section(3, [0]), section(1, [0]))), /out of order/);
  assert.throws(() => parseModule(moduleBytes(section(13, []))), /Unsupported section/);
  assert.throws(() => parseModule(moduleBytes([1, 127, 0])), /beyond the module/);
});

test('Missing code bodies and inconsistent function counts are rejected', () => {
  assert.throws(() => parseModule(moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 0]))), /no matching code/);
  assert.throws(() => parseModule(moduleBytes(section(3, [0]), section(10, [1, 2, 0, 0x0b]))), /counts differ/);
});

test('Native validation guards stack types and out of range indices', () => {
  assert.throws(() => parseModule(functionModule([0x20, 99])), /Native validation/);
  assert.throws(() => parseModule(functionModule([0x41, 1], { results: [0x7c] })), /Native validation/);
});

test('Custom sections retain their payload and do not execute it', () => {
  const bytes = moduleBytes(section(0, nameBytes('notes').concat([3, 2, 1])));
  const mod = parseModule(bytes);
  assert.equal(mod.custom[0].name, 'notes');
  assert.deepEqual(Array.from(mod.custom[0].bytes), [3, 2, 1]);
  assert.equal(mod.sections[0].size, 9);
});

test('Import function indices are preserved by the text listing', () => {
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 1, 0x7f]),
    section(2, [1].concat(nameBytes('env'), nameBytes('value'), [0, 0])),
    section(7, [1].concat(nameBytes('value'), [0, 0])));
  const mod = parseModule(bytes);
  assert.match(disassemble(mod), /\(import "env" "value" \(func \$f0/);
  assert.equal(traceFunction(mod, 'value').ok, false);
});

test('Memory and data inspection retains exact bytes', () => {
  const data = [1, 0, 0x41, 0, 0x0b, 3, 97, 98, 99];
  const mod = parseModule(moduleBytes(section(5, [1, 1, 1, 2]), section(11, data)));
  assert.equal(mod.memories[0].min, 1);
  assert.equal(mod.memories[0].max, 2);
  assert.deepEqual(Array.from(mod.data[0].bytes), [97, 98, 99]);
  assert.match(disassemble(mod), /\\61\\62\\63/);
});

test('Data count section uses its real ordering before code and data', () => {
  const mod = parseModule(moduleBytes(section(12, [1]), section(11, [1, 1, 1, 90])));
  assert.equal(mod.dataCount, 1);
  assert.equal(mod.data[0].offset, null);
  assert.throws(() => parseModule(moduleBytes(section(12, [2]), section(11, [1, 1, 1, 90]))), /Data count differs/);
});

test('Global initializers and memory instructions decode without invented immediates', () => {
  const mod = parseModule(moduleBytes(section(6, [1, 0x7f, 0, 0x41, 7, 0x0b])));
  assert.match(disassemble(mod), /\(global i32 \(i32.const 7\)\)/);
  const load = parseModule(functionModule([0x20, 0, 0x28, 2, 0], { params: [0x7f], extra: [section(5, [1, 0, 1])] }));
  assert.match(disassemble(load), /i32.load offset=0 align=4/);
  assert.match(traceFunction(load, 'run', [0]).error, /outside the tracer subset/);
});

test('Unsupported prefixed instructions are explicitly rejected', () => {
  assert.throws(() => parseModule(functionModule([0xfc, 0])), /Unsupported opcode/);
  assert.throws(() => parseModule(functionModule([0x05])), /Else without/);
});

test('Hex parsing rejects partial bytes, punctuation and oversized input', () => {
  assert.deepEqual(Array.from(parseHex('0x00 61\n73 6d')), [0, 97, 115, 109]);
  for (const value of ['', 'a', 'gg', '00,11']) assert.throws(() => parseHex(value), /byte pairs/);
  assert.throws(() => parseModule(new Uint8Array(4 * 1024 * 1024 + 1)), /4 MiB/);
});

test('Hex rows preserve offset, byte count and printable text', () => {
  const bytes = Uint8Array.from([0, 65, 66, 127, 255]);
  const rows = hexRows(bytes, 4);
  assert.equal(rows[0].ascii, '.AB.');
  assert.equal(rows[1].offset, 4);
  assert.equal(rows[1].hex, 'ff');
});

test('Disassembly reflects actual local reads, arithmetic and nested control flow', () => {
  const add = disassemble(parseModule(demoModule()));
  assert.match(add, /local.get 0\n\s+local.get 1\n\s+i32.add/);
  const loop = disassemble(parseModule(demoModule('sum')));
  assert.match(loop, /block\n\s+loop/);
  assert.match(loop, /br_if 1/);
  assert.match(disassemble(parseModule(demoModule('select'))), /if \(result i32\)/);
});

test('Addition trace matches native execution including signed overflow', () => {
  const bytes = demoModule(), mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
  for (const args of [[2, 3], [-7, 10], [2147483647, 1], [-2147483648, -1]]) {
    const trace = traceFunction(mod, 'add', args);
    assert.equal(trace.ok, true);
    assert.equal(trace.results[0], native.exports.add(...args));
    assert.deepEqual(trace.events[2].before, args.map((n) => n | 0));
    assert.ok(trace.events.every((e) => e.offset >= 8 && Array.isArray(e.after)));
  }
});

test('Loop and branch execution matches the native sum for all small nonnegative inputs', () => {
  const bytes = demoModule('sum'), mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
  for (let n = 0; n <= 20; n++) {
    const trace = traceFunction(mod, 'sum', [n]);
    assert.equal(trace.ok, true, trace.error);
    assert.equal(trace.results[0], native.exports.sum(n));
  }
});

test('If and else choose the native result on zero, positive and negative conditions', () => {
  const bytes = demoModule('select'), mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
  for (const value of [0, 1, -1]) assert.equal(traceFunction(mod, 'select', [value]).results[0], native.exports.select(value));
});

const binaryOpcodes = [0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f];
test('Every supported binary integer operation is compared with native execution', () => {
  for (const opcode of binaryOpcodes) {
    const bytes = functionModule([0x20, 0, 0x20, 1, opcode]), mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
    for (const args of [[17, 3], [-2147483648, 2], [-1, 31], [0, 1]]) {
      const trace = traceFunction(mod, 'run', args);
      assert.equal(trace.ok, true, trace.error);
      assert.equal(trace.results[0], native.exports.run(...args), 'opcode ' + opcode);
    }
  }
});

test('Unary bit operations agree with native execution at zero and signed boundaries', () => {
  for (const opcode of [0x45, 0x67, 0x68, 0x69, 0xc0, 0xc1]) {
    const bytes = functionModule([0x20, 0, opcode], { params: [0x7f] }), mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
    for (const n of [0, -1, -2147483648, 255, 65535]) assert.equal(traceFunction(mod, 'run', [n]).results[0], native.exports.run(n));
  }
});

test('Division traps retain executed events and agree with native trap behavior', () => {
  for (const args of [[1, 0], [-2147483648, -1]]) {
    const bytes = functionModule([0x20, 0, 0x20, 1, 0x6d]), mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
    assert.throws(() => native.exports.run(...args), WebAssembly.RuntimeError);
    const trace = traceFunction(mod, 'run', args);
    assert.equal(trace.ok, false);
    assert.ok(trace.events.length >= 3);
    assert.match(trace.error, /division/);
  }
});

test('Tracing has hard step bounds and cannot execute an infinite loop', () => {
  const trace = traceFunction(parseModule(demoModule('sum')), 'sum', [-1], { maxSteps: 20 });
  assert.equal(trace.ok, false);
  assert.equal(trace.events.length, 20);
  assert.match(trace.error, /step limit/);
});

test('Unknown functions, wrong arity and noninteger parameters produce clear errors', () => {
  const mod = parseModule(demoModule());
  for (const [name, args] of [['missing', []], ['add', [1]], ['add', [1, 0.5]], ['add', [NaN, 1]]]) assert.equal(traceFunction(mod, name, args).ok, false);
});

test('Drop, select, local tee and return preserve actual operand state', () => {
  const bytes = functionModule(constant(1).concat([0x1a, 0x20, 0, 0x22, 0, 0x20, 1, 0x20, 0, 0x1b, 0x0f]));
  const mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
  for (const args of [[0, 7], [3, 7]]) assert.equal(traceFunction(mod, 'run', args).results[0], native.exports.run(...args));
});

test('I64 and floating functions are inspected but never represented as integer traces', () => {
  const bytes = functionModule([0x42, 0], { params: [], results: [0x7e] });
  const mod = parseModule(bytes);
  assert.match(disassemble(mod), /i64.const 0/);
  assert.match(traceFunction(mod, 'run', []).error, /i32/);
});

test('Text strings escape quotes, backslashes and non-ASCII bytes safely', () => {
  const bytes = functionModule(constant(7), { params: [], exportName: 'a"\\é' });
  const wat = disassemble(parseModule(bytes));
  assert.match(wat, /\\22\\5c\\c3\\a9/);
});

test('Direct calls use the imported-function index space and preserve parent event order', () => {
  const first = [0, 0x20, 0, 0x10, 1, 0x0b], second = [0, 0x20, 0, 0x41, 2, 0x6c, 0x0b];
  const bytes = moduleBytes(section(1, [1, 0x60, 1, 0x7f, 1, 0x7f]), section(3, [2, 0, 0]),
    section(7, [1].concat(nameBytes('run'), [0, 0])),
    section(10, [2].concat(encodeULEB(first.length), first, encodeULEB(second.length), second)));
  const mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
  const trace = traceFunction(mod, 'run', [7]);
  assert.equal(trace.ok, true);
  assert.equal(trace.results[0], native.exports.run(7));
  assert.equal(trace.events.find((e) => e.op === 'call').after[0], 14);
  assert.ok(trace.events.some((e) => e.functionIndex === 1 && e.depth === 1));
});

test('Branch tables resolve nested label depths and the default target like the native runtime', () => {
  const body = [0x02, 0x7f, 0x02, 0x7f, 0x41, 7, 0x20, 0, 0x0e, 2, 0, 1, 1,
    0x0b, 0x41, 5, 0x6a, 0x0b];
  const bytes = functionModule(body, { params: [0x7f] }), mod = parseModule(bytes), native = new WebAssembly.Instance(new WebAssembly.Module(bytes));
  for (const n of [0, 1, 2, -1]) {
    const trace = traceFunction(mod, 'run', [n]);
    assert.equal(trace.ok, true, trace.error);
    assert.equal(trace.results[0], native.exports.run(n));
  }
});

test('Recursive calls stop at their depth limit without invoking the native function', () => {
  const mod = parseModule(functionModule([0x10, 0], { params: [] }));
  const trace = traceFunction(mod, 'run', [], { maxDepth: 4 });
  assert.equal(trace.ok, false);
  assert.match(trace.error, /depth limit/);
  assert.equal(trace.events.length, 4);
});

test('Decoded instruction limits reject a large body before native execution', () => {
  const bytes = functionModule(Array(100001).fill(0x01), { params: [], results: [] });
  assert.throws(() => parseModule(bytes), /instruction count/);
});

test('Trace local storage limits prevent oversized per-step snapshots', () => {
  const bytes = functionModule(constant(1), { params: [], locals: Array(257).fill(0x7f) });
  const trace = traceFunction(parseModule(bytes), 'run', []);
  assert.equal(trace.ok, false);
  assert.match(trace.error, /local value limit/);
});

test('Reader bounds reject fractional and nonfinite offsets before decoding', () => {
  for (const value of [NaN, Infinity, -Infinity, 0.5]) {
    assert.throws(() => new Reader(new Uint8Array(2), value, 2), /Invalid byte range/);
    assert.throws(() => new Reader(new Uint8Array(2), 0, value), /Invalid byte range/);
  }
});

test('Parsed local counts are bounded across the whole module', () => {
  const body = [1].concat(encodeULEB(60000), [0x7f, 0x0b]);
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [2, 0, 0]),
    section(10, [2].concat(encodeULEB(body.length), body, encodeULEB(body.length), body)));
  assert.throws(() => parseModule(bytes), /Local count exceeds/);
});

test('Control nesting has a fixed bound before listing indentation can grow', () => {
  const nested = Array.from({ length: 257 }, () => [0x02, 0x40]).flat().concat(Array(257).fill(0x0b));
  assert.throws(() => parseModule(functionModule(nested, { params: [], results: [] })), /256-level/);
});
