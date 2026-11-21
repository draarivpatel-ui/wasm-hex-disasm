import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  BinaryError, Reader, encodeULEB, encodeSLEB, parseModule, disassemble,
  traceFunction, hexRows, parseHex, demoModule
} from '../src/wasm.mjs';
import { escapeHtml, inspectionMarkup } from '../src/app.mjs';
import { moduleBytes, section, nameBytes, functionModule, constant } from './helpers/fixture.mjs';
const uleb = encodeULEB, sleb = encodeSLEB;

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(join(root, 'index.html'), 'utf8');
const css = readFileSync(join(root, 'styles.css'), 'utf8');
const readerOf = (bytes, opts = {}) => new Reader(Uint8Array.from(bytes), 0, bytes.length, opts.spans || []);

// ---- LEB128 integer boundaries ----

test('u32 decodes every canonical boundary value', () => {
  for (const n of [0, 1, 127, 128, 255, 16383, 16384, 2097151, 2097152, 268435455, 268435456, 4294967295]) {
    assert.equal(readerOf(uleb(n)).u32(), n);
  }
});

test('u32 rejects values beyond 32 bits on the terminating byte', () => {
  assert.throws(() => readerOf([0xff, 0xff, 0xff, 0xff, 0x7f]).u32(), /exceeds 32 bits/);
});

test('u32 rejects a sixth continuation byte', () => {
  assert.throws(() => readerOf([0x80, 0x80, 0x80, 0x80, 0x80, 0x01]).u32(), /Unterminated or oversized/);
});

test('u32 accepts a padded five-byte encoding of zero', () => {
  assert.equal(readerOf([0x80, 0x80, 0x80, 0x80, 0x00]).u32(), 0);
});

test('s32 decodes every canonical boundary value', () => {
  for (const n of [0, 1, -1, 63, 64, -63, -64, 8191, 8192, -8191, -8192, 2147483647, -2147483648]) {
    assert.equal(readerOf(sleb(n)).s32(), n);
  }
});

test('s32 rejects 2147483648 and negative underflow', () => {
  assert.throws(() => readerOf(sleb(2147483648n)).s32(), /exceeds 32 bits/);
  assert.throws(() => readerOf(sleb(-2147483649n)).s32(), /exceeds 32 bits/);
});

test('s64 returns BigInt at the 64-bit extremes', () => {
  assert.equal(readerOf(sleb(-1n)).s64(), -1n);
  assert.equal(readerOf(sleb(9223372036854775807n)).s64(), 9223372036854775807n);
  assert.equal(readerOf(sleb(-9223372036854775808n)).s64(), -9223372036854775808n);
});

test('s64 rejects values beyond 64 bits', () => {
  assert.throws(() => readerOf(sleb(9223372036854775808n)).s64(), /exceeds 64 bits/);
});

test('leb spans record offset, width, kind and value', () => {
  const spans = [];
  readerOf(uleb(624485), { spans }).u32();
  assert.deepEqual(spans, [{ offset: 0, end: 3, kind: 'u32', value: '624485' }]);
});

// ---- Reader bounds ----

test('Reader rejects fractional and inverted ranges', () => {
  assert.throws(() => new Reader([1, 2], 1.5, 2), /Invalid byte range/);
  assert.throws(() => new Reader([1, 2], 2, 1), /Invalid byte range/);
  assert.throws(() => new Reader([1, 2], 0, 5), /Invalid byte range/);
  assert.throws(() => new Reader([1, 2], -1, 1), /Invalid byte range/);
});

test('Reader.take rejects negative and overflowing lengths', () => {
  const r = readerOf([1, 2, 3]);
  assert.throws(() => r.take(-1), /Truncated byte range/);
  assert.throws(() => r.take(4), /Truncated byte range/);
  assert.deepEqual([...r.take(2)], [1, 2]);
});

test('Reader.byte at the end reports exhaustion', () => {
  const r = readerOf([9]);
  r.byte();
  assert.throws(() => r.byte(), /Unexpected end of input/);
});

test('Reader.name rejects invalid UTF-8 bytes', () => {
  assert.throws(() => readerOf([1, 0xff]).name(), /Invalid UTF-8/);
});

test('Reader.vector rejects a count beyond the remaining bytes', () => {
  const r = readerOf([5, 1]);
  assert.throws(() => r.vector((x) => x.u32()), /Vector count exceeds/);
});

test('Reader.vector accepts a zero count', () => {
  assert.deepEqual(readerOf([0]).vector((x) => x.u32()), []);
});

test('valueType accepts every MVP type and rejects unknowns', () => {
  const cases = [[0x7f, 'i32'], [0x7e, 'i64'], [0x7d, 'f32'], [0x7c, 'f64'], [0x70, 'funcref'], [0x6f, 'externref']];
  for (const [byte, name] of cases) assert.equal(readerOf([byte]).valueType(), name);
  assert.throws(() => readerOf([0x05]).valueType(), /Unsupported value type/);
});

test('done() reports leftover bytes inside a bounded reader', () => {
  const r = new Reader([1, 2], 0, 2, []);
  r.byte();
  assert.throws(() => r.done(), /Unconsumed/);
});

// ---- Section-level parsing ----

test('header rejects truncated input and wrong magic bytes', () => {
  assert.throws(() => parseModule([]), /Unexpected end of input|Invalid magic/);
  assert.throws(() => parseModule([0, 97, 115, 109]), /Unexpected end of input/);
  assert.throws(() => parseModule([0, 97, 115, 110, 1, 0, 0, 0]), /Invalid magic/);
  assert.throws(() => parseModule([0, 97, 115, 109, 2, 0, 0, 0]), /Invalid magic/);
});

test('section id 13 is rejected as unsupported', () => {
  assert.throws(() => parseModule(moduleBytes([13, 0])), /Unsupported section id/);
});

test('section sizes extending beyond the module are rejected', () => {
  assert.throws(() => parseModule(Uint8Array.from([0, 97, 115, 109, 1, 0, 0, 0, 1, 10, 1, 2])), /Section extends beyond/);
});

test('unconsumed bytes inside a section are rejected', () => {
  assert.throws(() => parseModule(moduleBytes([3, 3, 1, 0, 0xff])), /Unconsumed|code|function/i);
});

test('custom sections may appear anywhere and keep their payload', () => {
  const mod = parseModule(moduleBytes(
    section(0, nameBytes('lead').concat([1, 2, 3])),
    section(1, [1, 0x60, 0, 0]),
    section(0, nameBytes('tail').concat([9]))));
  assert.equal(mod.custom.length, 2);
  assert.equal(mod.custom[0].name, 'lead');
  assert.deepEqual([...mod.custom[0].bytes], [1, 2, 3]);
  assert.equal(mod.custom[1].name, 'tail');
});

test('duplicate sections are rejected', () => {
  const type = section(1, [1, 0x60, 0, 0]);
  assert.throws(() => parseModule(moduleBytes(type, type)), /Duplicate or out of order/);
});

test('out of order sections are rejected', () => {
  const type = section(1, [1, 0x60, 0, 0]), fns = section(3, [1, 0]);
  assert.throws(() => parseModule(moduleBytes(fns, type)), /Duplicate or out of order/);
});

test('type section requires the 0x60 function form', () => {
  assert.throws(() => parseModule(moduleBytes(section(1, [1, 0x61, 0, 0]))), /Expected function type/);
});

test('import section supports every descriptor kind', () => {
  const imp = (m, n, desc) => nameBytes(m).concat(nameBytes(n), desc);
  const mod = parseModule(moduleBytes(section(1, [1, 0x60, 0, 0]), section(2, [4]
    .concat(imp('a', 'f', [0, 0]), imp('a', 't', [1, 0x70, 0, 1]), imp('a', 'm', [2, 0, 1]), imp('a', 'g', [3, 0x7f, 0])))));
  assert.deepEqual(mod.imports.map((i) => i.kind), ['func', 'table', 'memory', 'global']);
  assert.equal(mod.imports[0].typeIndex, 0);
  assert.equal(mod.imports[3].type, 'i32');
});

test('import kind beyond 3 is rejected', () => {
  const imp = nameBytes('a').concat(nameBytes('x'), [4]);
  assert.throws(() => parseModule(moduleBytes(section(2, [1].concat(imp)))), /Unsupported import kind/);
});

test('table section rejects non-reference value types', () => {
  const table = [1, 0x7f, 0, 1];
  assert.throws(() => parseModule(moduleBytes(section(4, table))), /Invalid table reference type/);
});

test('limits reject shared flags and inverted bounds', () => {
  assert.throws(() => parseModule(moduleBytes(section(5, [1, 3, 1, 1]))), /Shared and 64-bit limits/);
  assert.throws(() => parseModule(moduleBytes(section(5, [1, 1, 5, 2]))), /Maximum limit is below minimum/);
});

test('memory section parses min and max', () => {
  const mod = parseModule(moduleBytes(section(5, [1, 1, 2, 9])));
  assert.deepEqual(mod.memories, [{ min: 2, max: 9 }]);
});

test('global mutability byte above one is rejected', () => {
  const global = [1, 0x7f, 2, 0x41, 0, 0x0b];
  assert.throws(() => parseModule(moduleBytes(section(6, global))), /Invalid global mutability/);
});

test('global init expressions are parsed as instructions', () => {
  const global = [1, 0x7f, 0, 0x41, 42, 0x0b];
  const mod = parseModule(moduleBytes(section(6, global)));
  assert.equal(mod.globals[0].init[0].op, 'i32.const');
  assert.equal(mod.globals[0].init[0].args[0], 42);
});

test('export section parses all kinds and rejects bad kinds', () => {
  const entry = (name, kind, index) => nameBytes(name).concat([kind, index]);
  const mod = parseModule(moduleBytes(section(7, [4]
    .concat(entry('f', 0, 0), entry('t', 1, 0), entry('m', 2, 0), entry('g', 3, 0)))), { validate: false });
  assert.deepEqual(mod.exports.map((e) => e.kind), ['func', 'table', 'memory', 'global']);
  assert.throws(() => parseModule(moduleBytes(section(7, [1].concat(entry('x', 4, 0))))), /Unsupported export kind/);
});

test('start section index is captured and trailing bytes rejected', () => {
  const good = parseModule(moduleBytes(section(8, [7])), { validate: false });
  assert.equal(good.start, 7);
  assert.throws(() => parseModule(moduleBytes(section(8, [7, 0]))), /Unconsumed/);
});

test('element segments keep function indices and reject newer flags', () => {
  const elem = [1, 0, 0x41, 0, 0x0b, 2, 0, 1];
  const mod = parseModule(moduleBytes(section(9, elem)), { validate: false });
  assert.deepEqual(mod.elements[0].functions, [0, 1]);
  assert.throws(() => parseModule(moduleBytes(section(9, [1, 1, 0x41, 0, 0x0b, 0]))), /Only active MVP element/);
});

test('function bodies exceeding the code section are rejected', () => {
  const code = [1, 20, 0, 0x41, 1, 0x0b];
  assert.throws(() => parseModule(moduleBytes(section(3, [1, 0]), section(10, code))), /Function body exceeds/);
});

test('data count section must match data segment count', () => {
  const data = section(11, [1, 0, 0x41, 0, 0x0b, 1, 0xaa]);
  assert.throws(() => parseModule(moduleBytes(section(12, [2]), data)), /Data count differs/);
  assert.doesNotThrow(() => parseModule(moduleBytes(section(12, [1]), data), { validate: false }));
});

test('data segments support active and passive forms and reject flag three', () => {
  const mod = parseModule(moduleBytes(section(11, [2, 1, 1, 0xaa, 0, 0x41, 0, 0x0b, 1, 0xbb])), { validate: false });
  assert.equal(mod.data[0].offset, null);
  assert.equal(mod.data[1].offset[0].op, 'i32.const');
  assert.throws(() => parseModule(moduleBytes(section(11, [1, 3, 0]))), /Unsupported data segment flag/);
});

test('active data with an explicit memory index parses', () => {
  const mod = parseModule(moduleBytes(section(11, [1, 2, 0, 0x41, 0, 0x0b, 1, 0xcc])), { validate: false });
  assert.equal(mod.data[0].memory, 0);
});

test('modules larger than 4 MiB are rejected before parsing', () => {
  const big = new Uint8Array(4 * 1024 * 1024 + 1);
  assert.throws(() => parseModule(big), /4 MiB/);
});

test('parseModule accepts plain arrays and returns byte spans', () => {
  const mod = parseModule([0, 97, 115, 109, 1, 0, 0, 0]);
  assert.equal(mod.sections.length, 0);
  assert.ok(Array.isArray(mod.lebSpans));
});

test('native validation failures surface as BinaryError and can be bypassed', () => {
  const badType = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 5]),
    section(10, [1, 2, 0, 0x0b]));
  assert.throws(() => parseModule(badType), /Native validation/);
  const mod = parseModule(badType, { validate: false });
  assert.equal(mod.nativeValid, false);
});

// ---- Instruction decoding ----

test('unknown opcodes report their byte value', () => {
  assert.throws(() => parseModule(functionModule([0xfe])), /Unsupported opcode 0xfe/);
});

test('prefixed instruction families are rejected outright', () => {
  assert.throws(() => parseModule(functionModule([0xfc, 0x08, 0])), /Unsupported opcode/);
  assert.throws(() => parseModule(functionModule([0xfd, 0x00])), /Unsupported opcode/);
});

test('f32 and f64 constants decode their IEEE payloads', () => {
  const f32 = parseModule(functionModule([0x43, 0, 0, 0xc0, 0x7f], { params: [], results: [0x7d] }));
  assert.ok(Number.isNaN(f32.functions[0].code[0].args[0]));
  const f64 = parseModule(functionModule([0x44, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f], { params: [], results: [0x7c] }));
  assert.equal(f64.functions[0].code[0].args[0], 1);
});

test('i64 constants decode negative BigInt values', () => {
  const mod = parseModule(functionModule([0x42, 0x7f], { params: [], results: [0x7e] }));
  assert.equal(mod.functions[0].code[0].args[0], -1n);
});

test('memory immediates capture alignment then offset', () => {
  const mod = parseModule(functionModule([0x20, 0, 0x28, 2, 8],
    { results: [0x7f], extra: [section(5, [1, 0, 1])] }));
  const load = mod.functions[0].code[1];
  assert.equal(load.op, 'i32.load');
  assert.deepEqual(load.args, [2, 8]);
});

test('call_indirect captures type and table operands', () => {
  const mod = parseModule(functionModule([0x20, 0, 0x11, 0, 0],
    { results: [0x7f], extra: [section(4, [1, 0x70, 0, 1])] }), { validate: false });
  const call = mod.functions[0].code[1];
  assert.equal(call.op, 'call_indirect');
  assert.deepEqual(call.args, [0, 0]);
});

test('br_table captures the target vector and default depth', () => {
  const mod = parseModule(functionModule([0x02, 0x40, 0x20, 0, 0x0e, 2, 0, 0, 0, 0x0b], { results: [] }));
  const br = mod.functions[0].code[2];
  assert.equal(br.op, 'br_table');
  assert.deepEqual(br.targets, [0, 0]);
  assert.equal(br.args[0], 0);
});

test('else without a matching if is rejected', () => {
  assert.throws(() => parseModule(functionModule([0x05])), /Else without an unmatched if/);
});

test('double else inside one if is rejected', () => {
  assert.throws(() => parseModule(functionModule([0x20, 0, 0x04, 0x40, 0x05, 0x05])), /Else without an unmatched if/);
});

test('truncated bodies report end of input not a crash', () => {
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(10, [1, 3, 0, 0x41]));
  assert.throws(() => parseModule(bytes), /Unexpected end|Truncated|Unconsumed|exceeds/);
});

test('else and end indices link back to their opening instruction', () => {
  const mod = parseModule(functionModule([0x20, 0, 0x04, 0x40, 0x01, 0x05, 0x01, 0x0b], { results: [] }));
  const code = mod.functions[0].code;
  assert.equal(code[1].elseIndex, 3);
  assert.equal(code[1].endIndex, 5);
  assert.equal(code[3].endIndex, 5);
  assert.equal(code[5].openingIndex, 1);
});

test('block type accepts type indices as a structured operand', () => {
  const mod = parseModule(moduleBytes(section(1, [2, 0x60, 0, 0, 0x60, 0, 0]),
    section(3, [1, 0]), section(7, [1].concat(nameBytes('f'), [0, 0])),
    section(10, [1, 5, 0, 0x02, 1, 0x0b, 0x0b])));
  assert.deepEqual(mod.functions[0].code[0].blockType, { typeIndex: 1 });
});

test('negative block type encodings that are not value types are rejected', () => {
  assert.throws(() => parseModule(functionModule([0x02, 0x50, 0x0b])), /Invalid block type/);
});

test('control nesting beyond 256 levels is refused', () => {
  const body = Array(257).fill([0x02, 0x40]).flat();
  assert.throws(() => parseModule(functionModule(body)), /Control nesting exceeds/);
});

test('declared locals beyond 100000 are refused', () => {
  const localsDecl = [1].concat(uleb(100001), [0x7f]);
  const body = localsDecl.concat([0x0b]);
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(10, [1].concat(uleb(body.length), body)));
  assert.throws(() => parseModule(bytes), /Local count exceeds/);
});

test('instruction streams beyond 100000 are refused', () => {
  const body = Array(100002).fill(0x01);
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(10, [1].concat(uleb(body.length + 2), [0].concat(body, [0x0b]))));
  assert.throws(() => parseModule(bytes), /instruction count exceeds/i);
});

test('local declaration runs use multiple type groups', () => {
  const localsDecl = [2, 3, 0x7f, 1, 0x7d];
  const body = localsDecl.concat([0x0b]);
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(10, [1].concat(uleb(body.length), body)));
  const mod = parseModule(bytes);
  assert.deepEqual(mod.functions[0].locals, ['i32', 'i32', 'i32', 'f32']);
});

// ---- Disassembly ----

test('listings render params, results and locals', () => {
  const wat = disassemble(parseModule(functionModule([0x20, 0, 0x0b].slice(0, -1), { locals: ['i32', 'i32'] })));
  assert.match(wat, /\(type \$t0 \(func \(param i32 i32\) \(result i32\)\)\)/);
  assert.match(wat, /\(local i32 i32\)/);
});

test('listings render imports of every kind', () => {
  const imp = (m, n, desc) => nameBytes(m).concat(nameBytes(n), desc);
  const mod = parseModule(moduleBytes(section(1, [1, 0x60, 0, 0]), section(2, [4]
    .concat(imp('env', 'fn', [0, 0]), imp('env', 'tbl', [1, 0x70, 1, 0, 2]), imp('env', 'mem', [2, 1, 0, 1]), imp('env', 'g', [3, 0x7e, 1])))));
  const wat = disassemble(mod);
  assert.match(wat, /\(import "env" "fn" \(func \$f0 \(type \$t0\)\)\)/);
  assert.match(wat, /\(import "env" "tbl" \(table 0 2 funcref\)\)/);
  assert.match(wat, /\(import "env" "mem" \(memory 0 1\)\)/);
  assert.match(wat, /\(import "env" "g" \(global \(mut i64\)\)\)/);
});

test('listings quote hostile names instead of emitting them', () => {
  const entry = nameBytes('a"b\\c\x01').concat([0, 0]);
  const mod = parseModule(moduleBytes(section(7, [1].concat(entry))), { validate: false });
  const wat = disassemble(mod);
  assert.match(wat, /\(export "a\\22b\\5cc\\01" \(func \$f0\)\)/);
  assert.ok(!wat.includes('a"b\\c'));
});

test('listings render memory immediates as align and offset', () => {
  const mod = parseModule(moduleBytes(
    section(1, [1, 0x60, 0, 1, 0x7f]), section(3, [1, 0]), section(5, [1, 0, 1]),
    section(7, [1].concat(nameBytes('f'), [0, 0])),
    section(10, [1, 11, 0, 0x41, 0, 0x41, 7, 0x36, 2, 4, 0x41, 1, 0x0b])));
  assert.match(disassemble(mod), /i32\.store offset=4 align=4/);
});

test('listings render floating specials readably', () => {
  const mod = parseModule(functionModule([0x43, 0, 0, 0x80, 0x7f], { params: [], results: [0x7d] }));
  assert.match(disassemble(mod), /f32\.const inf/);
  const nan = parseModule(functionModule([0x44, 0, 0, 0, 0, 0, 0, 0xf8, 0x7f], { params: [], results: [0x7c] }));
  assert.match(disassemble(nan), /f64\.const nan/);
});

test('listings render start and element segments', () => {
  const bytes = moduleBytes(section(1, [1, 0x60, 0, 0]), section(3, [1, 0]),
    section(4, [1, 0x70, 0, 1]), section(7, [1].concat(nameBytes('f'), [0, 0])),
    section(8, [0]), section(9, [1, 0, 0x41, 0, 0x0b, 1, 0]),
    section(10, [1, 2, 0, 0x0b]));
  const wat = disassemble(parseModule(bytes));
  assert.match(wat, /\(start \$f0\)/);
  assert.match(wat, /\(elem \(i32\.const 0\) func \$f0\)/);
});

test('listings render active and passive data', () => {
  const bytes = moduleBytes(section(5, [1, 0, 1]),
    section(11, [2, 0, 0x41, 0, 0x0b, 1, 0xaa, 1, 1, 0xbb]));
  const wat = disassemble(parseModule(bytes));
  assert.match(wat, /\(data \(i32\.const 0\) "\\aa"\)/);
  assert.match(wat, /\(data "\\bb"\)/);
});

test('call instructions render their function index', () => {
  const mod = parseModule(functionModule([0x10, 0], { params: [], results: [0x7f] }));
  assert.match(disassemble(mod), /call \$f0/);
});

// ---- Integer tracer ----

const traced = (body, args, opts = {}) => {
  const mod = parseModule(functionModule(body, opts.module || {}));
  const native = new WebAssembly.Instance(new WebAssembly.Module(mod.bytes)).exports.run(...args);
  const trace = traceFunction(mod, 'run', args, opts.trace || {});
  assert.equal(trace.ok, true, trace.error);
  assert.equal(trace.results[0], native | 0);
  return trace;
};

test('rotate left and right match native execution', () => {
  traced([0x20, 0, 0x20, 1, 0x77], [-2147483648, 1]);
  traced([0x20, 0, 0x20, 1, 0x78], [1, 4]);
});

test('unsigned comparisons match native execution', () => {
  for (const [op, a, b] of [[0x49, -1, 1], [0x4b, -1, 1], [0x4d, -5, -5], [0x4f, 7, -7]]) {
    traced([0x20, 0, 0x20, 1, op], [a, b]);
  }
});

test('counting and sign-extension operators match native execution', () => {
  const one = { module: { params: [0x7f] } };
  traced([0x20, 0, 0x67], [1], one);
  traced([0x20, 0, 0x68], [0], one);
  traced([0x20, 0, 0x69], [-1], one);
  traced([0x20, 0, 0xc0], [255], one);
  traced([0x20, 0, 0xc1], [65535], one);
});

test('shift counts are masked to five bits like the native engine', () => {
  traced([0x20, 0, 0x20, 1, 0x74], [1, 33]);
  traced([0x20, 0, 0x20, 1, 0x75], [-1, 40]);
});

test('local tee leaves the value on the stack', () => {
  const trace = traced([0x20, 0, 0x22, 0, 0x20, 0, 0x6a], [21], { module: { params: [0x7f] } });
  assert.equal(trace.results[0], 42);
});

test('select returns the first operand when the condition is true', () => {
  traced([0x20, 0, 0x20, 1, 0x20, 2, 0x1b], [3, 4, 1], { module: { params: [0x7f, 0x7f, 0x7f] } });
  traced([0x20, 0, 0x20, 1, 0x20, 2, 0x1b], [3, 4, 0], { module: { params: [0x7f, 0x7f, 0x7f] } });
});

test('nop executes without changing the stack', () => {
  const trace = traced([0x01].concat(constant(5)), [], { module: { params: [] } });
  const nopEvent = trace.events[0];
  assert.equal(nopEvent.op, 'nop');
  assert.deepEqual(nopEvent.after, []);
});

test('unreachable traps at runtime', () => {
  const mod = parseModule(functionModule([0x00], { params: [], results: [0x7f] }));
  const trace = traceFunction(mod, 'run', []);
  assert.equal(trace.ok, false);
  assert.match(trace.error, /unreachable/);
});

test('division overflow and remainder edge cases follow the spec', () => {
  const mod = parseModule(functionModule([0x20, 0, 0x20, 1, 0x6d]));
  const trap = traceFunction(mod, 'run', [-2147483648, -1]);
  assert.equal(trap.ok, false);
  assert.match(trap.error, /overflow/);
  const rem = parseModule(functionModule([0x20, 0, 0x20, 1, 0x6f]));
  const trace = traceFunction(rem, 'run', [-2147483648, -1]);
  assert.equal(trace.results[0], 0);
});

test('tracing by numeric index resolves exported functions', () => {
  const mod = parseModule(functionModule(constant(9), { params: [] }));
  const trace = traceFunction(mod, 0, []);
  assert.equal(trace.ok, true);
  assert.equal(trace.results[0], 9);
});

test('unknown export names and imported indices are refused', () => {
  const mod = parseModule(functionModule(constant(1), { params: [] }));
  const byName = traceFunction(mod, 'missing', []);
  assert.equal(byName.ok, false);
  assert.match(byName.error, /exported function/);
});

test('non-integer arguments are refused', () => {
  const mod = parseModule(functionModule([0x20, 0]));
  for (const arg of [NaN, 1.5, 'x']) {
    const trace = traceFunction(mod, 'run', [arg]);
    assert.equal(trace.ok, false);
    assert.match(trace.error, /integer/);
  }
});

test('argument count mismatches are refused', () => {
  const mod = parseModule(functionModule([0x20, 0], { params: [0x7f] }));
  assert.match(traceFunction(mod, 'run', []).error, /one integer/);
  assert.match(traceFunction(mod, 'run', [1, 2]).error, /one integer/);
});

test('floating point functions are outside the tracer subset', () => {
  const mod = parseModule(functionModule([0x20, 0], { params: [0x7d], results: [0x7d] }));
  const trace = traceFunction(mod, 'run', [1]);
  assert.match(trace.error, /i32 functions and locals/);
});

test('memory instructions trap inside the tracer', () => {
  const mod = parseModule(moduleBytes(section(1, [1, 0x60, 0, 1, 0x7f]), section(3, [1, 0]),
    section(5, [1, 0, 1]), section(7, [1].concat(nameBytes('f'), [0, 0])),
    section(10, [1, 4, 0, 0x3f, 0, 0x0b])));
  const trace = traceFunction(mod, 'f', []);
  assert.equal(trace.ok, false);
  assert.match(trace.error, /tracer subset/);
});

test('global access traps inside the tracer', () => {
  const mod = parseModule(moduleBytes(section(1, [1, 0x60, 0, 1, 0x7f]), section(3, [1, 0]),
    section(6, [1, 0x7f, 0, 0x41, 7, 0x0b]), section(7, [1].concat(nameBytes('f'), [0, 0])),
    section(10, [1, 4, 0, 0x23, 0, 0x0b])));
  const trace = traceFunction(mod, 'f', []);
  assert.equal(trace.ok, false);
});

test('unbounded recursion hits the configured depth limit', () => {
  const mod = parseModule(functionModule([0x10, 0], { params: [], results: [0x7f] }));
  const trace = traceFunction(mod, 'run', [], { maxDepth: 4 });
  assert.match(trace.error, /depth limit/i);
});

test('infinite loops hit the configured step limit', () => {
  const mod = parseModule(functionModule([0x03, 0x40, 0x0c, 0, 0x0b], { params: [], results: [] }));
  const trace = traceFunction(mod, 'run', [], { maxSteps: 9 });
  assert.match(trace.error, /step limit/i);
  assert.equal(trace.events.length, 9);
});

test('step and depth limits are clamped to documented bounds', () => {
  const mod = parseModule(functionModule(constant(1), { params: [] }));
  assert.equal(traceFunction(mod, 'run', [], { maxSteps: 99999 }).maxSteps, 10000);
  assert.equal(traceFunction(mod, 'run', [], { maxSteps: 0 }).maxSteps, 1);
});

test('the final event carries the trap message', () => {
  const mod = parseModule(functionModule([0x00], { params: [], results: [0x7f] }));
  const trace = traceFunction(mod, 'run', []);
  assert.match(trace.events[trace.events.length - 1].error, /unreachable/);
});

test('trace events expose before, after and local snapshots', () => {
  const trace = traced([0x20, 0, 0x20, 1, 0x6a], [4, 5]);
  const add = trace.events.find((e) => e.op === 'i32.add');
  assert.deepEqual(add.before, [4, 5]);
  assert.deepEqual(add.after, [9]);
  assert.deepEqual(add.localsBefore, [4, 5]);
});

// ---- Hexadecimal helpers ----

test('hexRows marks printable ASCII and dots the rest', () => {
  const rows = hexRows(Uint8Array.from([0x41, 0x00, 0x7f, 0x20, 0x7e]), 8);
  assert.equal(rows[0].ascii, 'A.. ~');
  assert.equal(rows[0].offset, 0);
  assert.equal(rows[0].hex, '41 00 7f 20 7e');
});

test('hexRows clamps unreasonable widths to sixteen', () => {
  assert.equal(hexRows(new Uint8Array(40), 0).length, 3);
  assert.equal(hexRows(new Uint8Array(33), 500).length, 3);
  assert.equal(hexRows(new Uint8Array(33), 500)[2].hex.length, 2);
  assert.equal(hexRows(new Uint8Array(9), 4).length, 3);
});

test('hexRows handles empty input', () => {
  assert.deepEqual(hexRows(new Uint8Array(0)), []);
});

test('parseHex strips prefixes, case and internal whitespace', () => {
  assert.deepEqual([...parseHex('0x00 0X61\n6D 01 0A')], [0, 97, 109, 1, 10]);
});

test('parseHex rejects odd lengths, non-hex and empty input', () => {
  assert.throws(() => parseHex('abc'), /byte pairs/);
  assert.throws(() => parseHex('zz'), /byte pairs/);
  assert.throws(() => parseHex('   '), /byte pairs/);
  assert.throws(() => parseHex(''), /byte pairs/);
});

test('parseHex enforces the size ceiling', () => {
  assert.throws(() => parseHex('00'.repeat(4 * 1024 * 1024 + 1)), /4 MiB/);
});

// ---- Demonstration modules ----

test('every demonstration module validates natively', () => {
  for (const kind of ['add', 'sum', 'select']) {
    const mod = parseModule(demoModule(kind));
    assert.equal(mod.nativeValid, true, kind);
    assert.equal(mod.exports[0].name, kind);
  }
});

test('demonstration modules trace to correct answers', () => {
  const add = parseModule(demoModule('add'));
  assert.equal(traceFunction(add, 'add', [20, 22]).results[0], 42);
  const sum = parseModule(demoModule('sum'));
  assert.equal(traceFunction(sum, 'sum', [10]).results[0], 55);
  const sel = parseModule(demoModule('select'));
  assert.equal(traceFunction(sel, 'select', [0]).results[0], 9);
});

// ---- Output escaping and markup ----

test('escapeHtml neutralizes all five dangerous characters', () => {
  assert.equal(escapeHtml(`<a href="x">&'`), '&lt;a href=&quot;x&quot;&gt;&amp;&#39;');
});

test('hex view escapes ASCII control characters in module bytes', () => {
  const mod = parseModule(moduleBytes(section(0, nameBytes('c').concat([0x3c, 0x3e, 0x26]))));
  const markup = inspectionMarkup(mod);
  assert.ok(!markup.hex.includes('<>.'), 'raw markup bytes leaked');
  assert.match(markup.hex, /&lt;&gt;&amp;/);
});

test('section and integer tables stay bounded', () => {
  const mod = parseModule(demoModule('add'));
  const markup = inspectionMarkup(mod);
  assert.ok(markup.sections.includes('code'));
  assert.ok(markup.integers.length > 0);
  assert.equal(markup.visibleBytes, mod.bytes.length);
});

// ---- Document accessibility and CSP ----

test('the document carries a locked-down content security policy', () => {
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/);
  assert.ok(csp, 'missing CSP meta');
  for (const directive of ["default-src 'self'", "script-src 'self'", "connect-src 'none'", "object-src 'none'"]) {
    assert.ok(csp[1].includes(directive), 'CSP missing ' + directive);
  }
});

test('every interactive control has an accessible label', () => {
  const controls = [...html.matchAll(/<(input|textarea|select)[^>]*id="([^"]+)"/g)];
  assert.ok(controls.length >= 6);
  for (const [, tag, id] of controls) {
    assert.ok(html.includes('for="' + id + '"'), tag + '#' + id + ' lacks a label');
  }
});

test('status regions announce updates politely', () => {
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /role="status"/);
});

test('document language, charset and viewport are set', () => {
  assert.match(html, /<html lang="en">/);
  assert.match(html, /<meta charset="utf-8">/);
  assert.match(html, /name="viewport"/);
});

test('a skip link targets the main landmark', () => {
  assert.match(html, /class="skip-link" href="#main"/);
  assert.match(html, /id="main"/);
});

test('focus visibility, touch targets and motion preferences are styled', () => {
  assert.match(css, /:focus-visible/);
  assert.match(css, /min-height:\s*44px/);
  assert.match(css, /prefers-reduced-motion/);
  assert.doesNotMatch(css, /scroll-behavior:\s*smooth/);
});

test('no single-character keyboard shortcuts exist', () => {
  assert.doesNotMatch(html, /accesskey=/);
});

test('a noscript fallback explains the requirement', () => {
  assert.match(html, /<noscript>/);
});

test('the error status style exists for failed loads', () => {
  assert.match(css, /#status\.is-error/);
});

test('inspection markup marks the selected section rows', () => {
  const mod = parseModule(demoModule('add'));
  const markup = inspectionMarkup(mod, mod.sections[0]);
  assert.match(markup.hex, /is-selected/);
});

test('empty hex input leaves parseHex to report pairs not a crash', () => {
  assert.throws(() => parseHex(null), /byte pairs/);
  assert.throws(() => parseHex(0xbeef), /byte pairs/);
});

// ---- adversarial audit regressions ----

test('section count is bounded below the audit repro', () => {
  const many = [];
  for (let i = 0; i < 4097; i++) many.push(0, 1, 0);
  assert.throws(() => parseModule(moduleBytes(many), { validate: false }), /Section count exceeds/);
  const atCap = parseModule(moduleBytes(many.slice(0, 4096 * 3)), { validate: false });
  assert.equal(atCap.sections.length, 4096);
});

test('decoded-integer recording is bounded while lebTotal stays honest', () => {
  /* 100,000 memories of the form "min 1, max 1" produce ~300,000 LEB reads. */
  const payload = encodeULEB(100000);
  for (let i = 0; i < 100000; i++) payload.push(1, 1, 1);
  const mod = parseModule(moduleBytes(section(5, payload)), { validate: false });
  assert.equal(mod.lebSpans.length, 100000, 'recording stops at the bound');
  assert.ok(mod.lebTotal > mod.lebSpans.length, 'lebTotal counts every decoded integer');
});

test('inspectionMarkup caps the rendered section table', () => {
  const body = [];
  for (let i = 0; i < 600; i++) body.push(0, 1, 0);
  const mod = parseModule(moduleBytes(body), { validate: false });
  const markup = inspectionMarkup(mod);
  assert.equal((markup.sections.match(/<tr>/g) || []).length, 500);
  assert.equal(markup.visibleSections, 500);
});

test('parseHex strips a leading 0x per token but rejects interior 0x', () => {
  assert.deepEqual([...parseHex('0x00 0X61\n6D 01')], [0, 97, 109, 1]);
  assert.throws(() => parseHex('10x2'), /byte pairs/);
  assert.throws(() => parseHex('dead0xbeef'), /byte pairs/);
  assert.throws(() => parseHex('0x'), /byte pairs/);
});

test('the documented post-MVP boundary holds in both directions', () => {
  /* Accepted: data-count, a second table, a second memory, a passive
     data segment and an explicitly indexed active one. */
  const mod = parseModule(moduleBytes(
    section(4, [2, 0x70, 0, 1, 0x70, 0, 1]),
    section(5, [2, 0, 1, 0, 1]),
    section(12, [2]),
    section(11, [2, 1, 0, 2, 0, 0x41, 0, 0x0b, 0])), { validate: false });
  assert.equal(mod.dataCount, 2);
  assert.equal(mod.tables.length, 2);
  assert.equal(mod.memories.length, 2);
  assert.equal(mod.data.length, 2);
  /* Rejected by name: element flags 1-7, other reference types, typed select. */
  assert.throws(() => parseModule(moduleBytes(section(9, [1, 1, 0, 0])), { validate: false }), /element segment/);
  assert.throws(() => parseModule(moduleBytes(section(9, [1, 7, 0x70, 0, 0x41, 0, 0x0b, 0])), { validate: false }), /element segment/);
  assert.throws(() => parseModule(moduleBytes(section(4, [1, 0x6e, 0, 1])), { validate: false }), /value type/i);
  assert.throws(() => parseModule(functionModule([0x1c, 1, 0x7f])), /opcode/i);
});

test('trace stepping announces through live regions', () => {
  assert.match(html, /id="step-number"[^>]*aria-live="polite"/);
  assert.match(html, /id="step-state"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);
});

test('the meta CSP stays header-free of directives meta cannot enforce', () => {
  assert.doesNotMatch(html, /frame-ancestors/);
});
