// Bounded binary inspection and an integer execution tracer.
// Parsing never instantiates a module or runs imported host functions.
export class BinaryError extends Error {
  constructor(message, offset) {
    super(message + ' at byte ' + offset);
    this.name = 'BinaryError';
    this.offset = offset;
  }
}

const VALUE_TYPES = { 0x7f: 'i32', 0x7e: 'i64', 0x7d: 'f32', 0x7c: 'f64', 0x70: 'funcref', 0x6f: 'externref' };
const SECTION_NAMES = ['custom', 'type', 'import', 'function', 'table', 'memory', 'global', 'export', 'start', 'element', 'code', 'data', 'data count'];
const KINDS = ['func', 'table', 'memory', 'global'];
const MAX_SECTIONS = 4096;
const MAX_LEB_SPANS = 100000;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function byteInput(input) {
  if (!(input instanceof Uint8Array) && !Array.isArray(input)) throw new TypeError('Expected an array of byte values');
  for (let i = 0; i < input.length; i++) {
    if (!Number.isInteger(input[i]) || input[i] < 0 || input[i] > 255) throw new TypeError('Expected an array of byte values');
  }
  return input instanceof Uint8Array ? input : Uint8Array.from(input);
}

export class Reader {
  constructor(bytes, start = 0, end = bytes.length, spans = [], budget = { instructions: 0, locals: 0 }) {
    this.bytes = byteInput(bytes);
    this.offset = start;
    this.end = end;
    this.spans = spans;
    this.budget = budget;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || end > this.bytes.length) throw new BinaryError('Invalid byte range', start);
  }
  byte() {
    if (this.offset >= this.end) throw new BinaryError('Unexpected end of input', this.offset);
    return this.bytes[this.offset++];
  }
  take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.end - this.offset) throw new BinaryError('Truncated byte range', this.offset);
    const out = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }
  leb(bits, signed) {
    const start = this.offset;
    let value = 0n, shift = 0n;
    const count = Math.ceil(bits / 7);
    for (let i = 0; i < count; i++) {
      const byte = this.byte();
      value |= BigInt(byte & 127) << shift;
      shift += 7n;
      if ((byte & 128) === 0) {
        if (signed && (byte & 64)) value -= 1n << shift;
        const low = signed ? -(1n << BigInt(bits - 1)) : 0n;
        const high = signed ? (1n << BigInt(bits - 1)) - 1n : (1n << BigInt(bits)) - 1n;
        if (value < low || value > high) throw new BinaryError('Integer representation exceeds ' + bits + ' bits', start);
        const result = bits > 32 ? value : Number(value);
        this.budget.lebCount = (this.budget.lebCount || 0) + 1;
        if (this.spans.length < MAX_LEB_SPANS) {
          this.spans.push({ offset: start, end: this.offset, kind: (signed ? 's' : 'u') + bits, value: String(result) });
        }
        return result;
      }
    }
    throw new BinaryError('Unterminated or oversized integer', start);
  }
  u32() { return this.leb(32, false); }
  s32() { return this.leb(32, true); }
  s64() { return this.leb(64, true); }
  name() {
    const start = this.offset;
    const data = this.take(this.u32());
    try { return decoder.decode(data); }
    catch { throw new BinaryError('Invalid UTF-8 name', start); }
  }
  vector(read) {
    const n = this.u32();
    if (n > 100000 || n > this.end - this.offset) throw new BinaryError('Vector count exceeds available input', this.offset);
    const out = [];
    for (let i = 0; i < n; i++) out.push(read(this, i));
    return out;
  }
  valueType() {
    const position = this.offset, type = VALUE_TYPES[this.byte()];
    if (!type) throw new BinaryError('Unsupported value type', position);
    return type;
  }
  done() {
    if (this.offset !== this.end) throw new BinaryError('Unconsumed section or function bytes', this.offset);
  }
}

export function encodeULEB(value) {
  let n = BigInt(value);
  if (n < 0n) throw new RangeError('Unsigned integers cannot be negative');
  const out = [];
  do { let b = Number(n & 127n); n >>= 7n; if (n) b |= 128; out.push(b); } while (n);
  return out;
}

export function encodeSLEB(value) {
  let n = BigInt(value);
  const out = [];
  while (true) {
    const b = Number(n & 127n);
    n >>= 7n;
    const finished = (n === 0n && !(b & 64)) || (n === -1n && Boolean(b & 64));
    out.push(finished ? b : b | 128);
    if (finished) return out;
  }
}

const OPS = {
  0x00: 'unreachable', 0x01: 'nop', 0x02: 'block', 0x03: 'loop', 0x04: 'if',
  0x05: 'else', 0x0b: 'end', 0x0c: 'br', 0x0d: 'br_if', 0x0e: 'br_table',
  0x0f: 'return', 0x10: 'call', 0x11: 'call_indirect', 0x1a: 'drop', 0x1b: 'select',
  0x20: 'local.get', 0x21: 'local.set', 0x22: 'local.tee', 0x23: 'global.get', 0x24: 'global.set',
  0x3f: 'memory.size', 0x40: 'memory.grow', 0x41: 'i32.const', 0x42: 'i64.const',
  0x43: 'f32.const', 0x44: 'f64.const'
};
function opcodeRange(start, names) { names.split(' ').forEach((name, i) => { OPS[start + i] = name; }); }
opcodeRange(0x28, 'i32.load i64.load f32.load f64.load i32.load8_s i32.load8_u i32.load16_s i32.load16_u i64.load8_s i64.load8_u i64.load16_s i64.load16_u i64.load32_s i64.load32_u i32.store i64.store f32.store f64.store i32.store8 i32.store16 i64.store8 i64.store16 i64.store32');
opcodeRange(0x45, 'i32.eqz i32.eq i32.ne i32.lt_s i32.lt_u i32.gt_s i32.gt_u i32.le_s i32.le_u i32.ge_s i32.ge_u i64.eqz i64.eq i64.ne i64.lt_s i64.lt_u i64.gt_s i64.gt_u i64.le_s i64.le_u i64.ge_s i64.ge_u f32.eq f32.ne f32.lt f32.gt f32.le f32.ge f64.eq f64.ne f64.lt f64.gt f64.le f64.ge');
opcodeRange(0x67, 'i32.clz i32.ctz i32.popcnt i32.add i32.sub i32.mul i32.div_s i32.div_u i32.rem_s i32.rem_u i32.and i32.or i32.xor i32.shl i32.shr_s i32.shr_u i32.rotl i32.rotr');
opcodeRange(0x79, 'i64.clz i64.ctz i64.popcnt i64.add i64.sub i64.mul i64.div_s i64.div_u i64.rem_s i64.rem_u i64.and i64.or i64.xor i64.shl i64.shr_s i64.shr_u i64.rotl i64.rotr');
opcodeRange(0x8b, 'f32.abs f32.neg f32.ceil f32.floor f32.trunc f32.nearest f32.sqrt f32.add f32.sub f32.mul f32.div f32.min f32.max f32.copysign f64.abs f64.neg f64.ceil f64.floor f64.trunc f64.nearest f64.sqrt f64.add f64.sub f64.mul f64.div f64.min f64.max f64.copysign');
opcodeRange(0xa7, 'i32.wrap_i64 i32.trunc_f32_s i32.trunc_f32_u i32.trunc_f64_s i32.trunc_f64_u i64.extend_i32_s i64.extend_i32_u i64.trunc_f32_s i64.trunc_f32_u i64.trunc_f64_s i64.trunc_f64_u f32.convert_i32_s f32.convert_i32_u f32.convert_i64_s f32.convert_i64_u f32.demote_f64 f64.convert_i32_s f64.convert_i32_u f64.convert_i64_s f64.convert_i64_u f64.promote_f32 i32.reinterpret_f32 i64.reinterpret_f64 f32.reinterpret_i32 f64.reinterpret_i64');
opcodeRange(0xc0, 'i32.extend8_s i32.extend16_s i64.extend8_s i64.extend16_s i64.extend32_s');

function blockType(r) {
  const byte = r.bytes[r.offset];
  if (byte === 0x40) { r.byte(); return 'void'; }
  if (VALUE_TYPES[byte]) return r.valueType();
  const type = r.leb(33, true);
  if (type < 0n) throw new BinaryError('Invalid block type', r.offset);
  return { typeIndex: Number(type) };
}

function instructions(r) {
  const out = [], labels = [{ index: -1, kind: 'function' }];
  while (labels.length) {
    if (++r.budget.instructions > 100000) throw new BinaryError('Decoded instruction count exceeds inspection limit', r.offset);
    const offset = r.offset, opcode = r.byte(), op = OPS[opcode];
    if (!op) throw new BinaryError('Unsupported opcode 0x' + opcode.toString(16), offset);
    const ins = { offset, opcode, op, args: [] }, index = out.length;
    if (opcode >= 2 && opcode <= 4) {
      if (labels.length > 256) throw new BinaryError('Control nesting exceeds the 256-level inspection limit', offset);
      ins.blockType = blockType(r);
      labels.push({ index, kind: op, hasElse: false });
    } else if ([0x0c, 0x0d, 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x3f, 0x40].includes(opcode)) {
      ins.args.push(r.u32());
    } else if (opcode === 0x0e) {
      ins.targets = r.vector((x) => x.u32());
      ins.args.push(r.u32());
    } else if (opcode === 0x11) {
      ins.args.push(r.u32(), r.u32());
    } else if (opcode >= 0x28 && opcode <= 0x3e) {
      ins.args.push(r.u32(), r.u32());
    } else if (opcode === 0x41) ins.args.push(r.s32());
    else if (opcode === 0x42) ins.args.push(r.s64());
    else if (opcode === 0x43 || opcode === 0x44) {
      const data = r.take(opcode === 0x43 ? 4 : 8);
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      ins.args.push(opcode === 0x43 ? view.getFloat32(0, true) : view.getFloat64(0, true));
    } else if (opcode === 0x05) {
      const label = labels[labels.length - 1];
      if (label.kind !== 'if' || label.hasElse) throw new BinaryError('Else without an unmatched if', offset);
      label.hasElse = true;
      out[label.index].elseIndex = index;
      ins.openingIndex = label.index;
    } else if (opcode === 0x0b) {
      const label = labels.pop();
      ins.openingIndex = label.index;
      if (label.index >= 0) {
        out[label.index].endIndex = index;
        if (out[label.index].elseIndex !== undefined) out[out[label.index].elseIndex].endIndex = index;
      }
    }
    ins.end = r.offset;
    out.push(ins);
  }
  return out;
}

function limits(r) {
  const flag = r.u32();
  if (flag > 1) throw new BinaryError('Shared and 64-bit limits are outside this inspector', r.offset);
  const min = r.u32(), max = flag ? r.u32() : null;
  if (max !== null && max < min) throw new BinaryError('Maximum limit is below minimum', r.offset);
  return { min, max };
}
function globalType(r) {
  const type = r.valueType(), mutable = r.byte();
  if (mutable > 1) throw new BinaryError('Invalid global mutability', r.offset - 1);
  return { type, mutable: Boolean(mutable) };
}
function tableType(r) {
  const type = r.valueType();
  if (!['funcref', 'externref'].includes(type)) throw new BinaryError('Invalid table reference type', r.offset - 1);
  return { type, limits: limits(r) };
}

export function parseModule(input, { validate = true } = {}) {
  const bytes = byteInput(input);
  if (bytes.length > 4 * 1024 * 1024) throw new BinaryError('Input exceeds the 4 MiB inspection limit', 0);
  const spans = [], r = new Reader(bytes, 0, bytes.length, spans);
  const header = [0, 97, 115, 109, 1, 0, 0, 0];
  for (const b of header) if (r.byte() !== b) throw new BinaryError('Invalid magic or version', r.offset - 1);
  const mod = { bytes, sections: [], lebSpans: spans, types: [], imports: [], functions: [], tables: [],
    memories: [], globals: [], exports: [], elements: [], data: [], start: null, custom: [] };
  const seen = new Set();
  let lastRank = 0;
  while (r.offset < r.end) {
    const offset = r.offset;
    if (mod.sections.length >= MAX_SECTIONS) throw new BinaryError('Section count exceeds the ' + MAX_SECTIONS + '-section inspection limit', offset);
    const id = r.byte(), size = r.u32(), payloadOffset = r.offset;
    if (id > 12) throw new BinaryError('Unsupported section id', offset);
    const end = payloadOffset + size;
    if (end > r.end) throw new BinaryError('Section extends beyond the module', payloadOffset);
    const rank = id === 12 ? 9.5 : id;
    if (id && (seen.has(id) || rank < lastRank)) throw new BinaryError('Duplicate or out of order section', offset);
    if (id) { seen.add(id); lastRank = rank; }
    const x = new Reader(bytes, payloadOffset, end, spans, r.budget);
    mod.sections.push({ id, name: SECTION_NAMES[id], offset, payloadOffset, end, size });
    if (id === 0) mod.custom.push({ name: x.name(), bytes: x.take(x.end - x.offset) });
    else if (id === 1) mod.types = x.vector((v) => {
      if (v.byte() !== 0x60) throw new BinaryError('Expected function type', v.offset - 1);
      return { params: v.vector((t) => t.valueType()), results: v.vector((t) => t.valueType()) };
    });
    else if (id === 2) mod.imports = x.vector((v) => {
      const module = v.name(), name = v.name(), kind = v.byte();
      if (kind > 3) throw new BinaryError('Unsupported import kind', v.offset - 1);
      const descriptor = kind === 0 ? { typeIndex: v.u32() } : kind === 1 ? tableType(v) : kind === 2 ? limits(v) : globalType(v);
      return { module, name, kind: KINDS[kind], ...descriptor };
    });
    else if (id === 3) mod.functions = x.vector((v) => ({ typeIndex: v.u32() }));
    else if (id === 4) mod.tables = x.vector(tableType);
    else if (id === 5) mod.memories = x.vector(limits);
    else if (id === 6) mod.globals = x.vector((v) => ({ ...globalType(v), init: instructions(v) }));
    else if (id === 7) mod.exports = x.vector((v) => {
      const name = v.name(), kind = v.byte(), index = v.u32();
      if (kind > 3) throw new BinaryError('Unsupported export kind', v.offset);
      return { name, kind: KINDS[kind], index };
    });
    else if (id === 8) mod.start = x.u32();
    else if (id === 9) mod.elements = x.vector((v) => {
      if (v.u32() !== 0) throw new BinaryError('Only active MVP element segments are supported', v.offset);
      return { offset: instructions(v), functions: v.vector((t) => t.u32()) };
    });
    else if (id === 10) {
      const bodies = x.vector((v) => {
        const length = v.u32(), begin = v.offset, stop = begin + length;
        if (stop > v.end) throw new BinaryError('Function body exceeds code section', begin);
        const body = new Reader(bytes, begin, stop, spans, r.budget), locals = [];
        body.vector((t) => {
          const count = t.u32(), type = t.valueType();
          r.budget.locals = (r.budget.locals || 0) + count;
          if (r.budget.locals > 100000) throw new BinaryError('Local count exceeds inspection limit', t.offset);
          for (let i = 0; i < count; i++) locals.push(type);
        });
        const code = instructions(body);
        body.done();
        v.offset = stop;
        return { offset: begin, end: stop, locals, code };
      });
      if (bodies.length !== mod.functions.length) throw new BinaryError('Function and code counts differ', payloadOffset);
      mod.functions.forEach((fn, i) => Object.assign(fn, bodies[i]));
    } else if (id === 11) mod.data = x.vector((v) => {
      const flag = v.u32();
      if (flag > 2) throw new BinaryError('Unsupported data segment flag', v.offset);
      const memory = flag === 2 ? v.u32() : 0;
      const expr = flag === 1 ? null : instructions(v);
      return { memory, offset: expr, bytes: v.take(v.u32()) };
    });
    else if (id === 12) mod.dataCount = x.u32();
    x.done();
    r.offset = end;
  }
  if (mod.functions.some((fn) => !fn.code)) throw new BinaryError('Function section has no matching code', bytes.length);
  if (mod.dataCount !== undefined && mod.dataCount !== mod.data.length) throw new BinaryError('Data count differs from data segments', bytes.length);
  mod.lebTotal = r.budget.lebCount || spans.length;
  mod.nativeValid = typeof WebAssembly !== 'undefined' ? WebAssembly.validate(bytes) : null;
  if (validate && mod.nativeValid === false) throw new BinaryError('Native validation rejected the module type or index structure', 0);
  return mod;
}

function quoted(text) {
  return '"' + Array.from(encoder.encode(text), (b) => b >= 32 && b <= 126 && b !== 34 && b !== 92
    ? String.fromCharCode(b) : '\\' + b.toString(16).padStart(2, '0')).join('') + '"';
}
function watLimits(l) { return l.min + (l.max === null ? '' : ' ' + l.max); }
function numeric(v) {
  if (typeof v === 'bigint') return String(v);
  if (Number.isNaN(v)) return 'nan';
  if (v === Infinity) return 'inf';
  if (v === -Infinity) return '-inf';
  if (Object.is(v, -0)) return '-0';
  return String(v);
}
function instructionText(ins) {
  if (ins.blockType) return ins.op + (ins.blockType === 'void' ? '' : typeof ins.blockType === 'string'
    ? ' (result ' + ins.blockType + ')' : ' (type $t' + ins.blockType.typeIndex + ')');
  if (ins.op === 'call') return 'call $f' + ins.args[0];
  if (ins.op === 'call_indirect') return 'call_indirect (type $t' + ins.args[0] + ')' + (ins.args[1] ? ' (table ' + ins.args[1] + ')' : '');
  if (ins.op === 'br_table') return ins.op + ' ' + ins.targets.concat(ins.args).join(' ');
  if (ins.opcode >= 0x28 && ins.opcode <= 0x3e) return ins.op + ' offset=' + ins.args[1] + ' align=' + Math.pow(2, ins.args[0]);
  if (ins.op === 'memory.size' || ins.op === 'memory.grow') return ins.op + (ins.args[0] ? ' ' + ins.args[0] : '');
  return ins.op + (ins.args.length ? ' ' + ins.args.map(numeric).join(' ') : '');
}
function expression(code) { return code.filter((i) => i.op !== 'end').map((i) => '(' + instructionText(i) + ')').join(' '); }
export function disassemble(mod) {
  const lines = ['(module'];
  mod.types.forEach((t, i) => lines.push('  (type $t' + i + ' (func' +
    (t.params.length ? ' (param ' + t.params.join(' ') + ')' : '') +
    (t.results.length ? ' (result ' + t.results.join(' ') + ')' : '') + '))'));
  let importedFunctions = 0;
  mod.imports.forEach((item) => {
    const type = item.kind === 'func' ? 'func $f' + importedFunctions++ + ' (type $t' + item.typeIndex + ')'
      : item.kind === 'memory' ? 'memory ' + watLimits(item) : item.kind === 'table' ? 'table ' + watLimits(item.limits) + ' ' + item.type
        : 'global ' + (item.mutable ? '(mut ' + item.type + ')' : item.type);
    lines.push('  (import ' + quoted(item.module) + ' ' + quoted(item.name) + ' (' + type + '))');
  });
  mod.tables.forEach((t) => lines.push('  (table ' + watLimits(t.limits) + ' ' + t.type + ')'));
  mod.memories.forEach((m) => lines.push('  (memory ' + watLimits(m) + ')'));
  mod.globals.forEach((g) => lines.push('  (global ' + (g.mutable ? '(mut ' + g.type + ')' : g.type) + ' ' + expression(g.init) + ')'));
  mod.functions.forEach((fn, n) => {
    lines.push('  (func $f' + (n + importedFunctions) + ' (type $t' + fn.typeIndex + ')' +
      (fn.locals.length ? ' (local ' + fn.locals.join(' ') + ')' : ''));
    let depth = 2;
    fn.code.forEach((ins, i) => {
      if (i === fn.code.length - 1 && ins.op === 'end') return;
      if (ins.op === 'end' || ins.op === 'else') depth--;
      lines.push('  '.repeat(depth) + instructionText(ins));
      if (['block', 'loop', 'if', 'else'].includes(ins.op)) depth++;
    });
    lines.push('  )');
  });
  mod.exports.forEach((e) => lines.push('  (export ' + quoted(e.name) + ' (' + e.kind + ' ' + (e.kind === 'func' ? '$f' : '') + e.index + '))'));
  if (mod.start !== null) lines.push('  (start $f' + mod.start + ')');
  mod.elements.forEach((e) => lines.push('  (elem ' + expression(e.offset) + ' func ' + e.functions.map((n) => '$f' + n).join(' ') + ')'));
  mod.data.forEach((d) => lines.push('  (data ' + (d.offset ? (d.memory ? '(memory ' + d.memory + ') ' : '') + expression(d.offset) + ' ' : '') +
    '"' + Array.from(d.bytes, (b) => '\\' + b.toString(16).padStart(2, '0')).join('') + '")'));
  lines.push(')');
  return lines.join('\n');
}

function trap(message) { throw new Error(message); }
function popCount(value) {
  let n = value >>> 0, count = 0;
  while (n) { n &= n - 1; count++; }
  return count;
}
function integerOperation(op, stack) {
  const pop = () => { if (!stack.length) trap('Operand stack underflow'); return stack.pop(); };
  if (['i32.eqz', 'i32.clz', 'i32.ctz', 'i32.popcnt', 'i32.extend8_s', 'i32.extend16_s'].includes(op)) {
    const a = pop();
    stack.push(op === 'i32.eqz' ? Number(a === 0) : op === 'i32.clz' ? Math.clz32(a) :
      op === 'i32.ctz' ? (a === 0 ? 32 : 31 - Math.clz32(a & -a)) : op === 'i32.popcnt' ? popCount(a) :
        op === 'i32.extend8_s' ? a << 24 >> 24 : a << 16 >> 16);
    return true;
  }
  const suffix = op.slice(4);
  if (!op.startsWith('i32.') || !['add', 'sub', 'mul', 'div_s', 'div_u', 'rem_s', 'rem_u', 'and', 'or', 'xor', 'shl', 'shr_s', 'shr_u', 'rotl', 'rotr', 'eq', 'ne', 'lt_s', 'lt_u', 'gt_s', 'gt_u', 'le_s', 'le_u', 'ge_s', 'ge_u'].includes(suffix)) return false;
  const b = pop(), a = pop(), shift = b & 31;
  if (['div_s', 'div_u', 'rem_s', 'rem_u'].includes(suffix) && b === 0) trap('Integer division by zero');
  if (suffix === 'div_s' && a === -2147483648 && b === -1) trap('Signed integer division overflow');
  const values = {
    add: () => (a + b) | 0, sub: () => (a - b) | 0, mul: () => Math.imul(a, b),
    div_s: () => Math.trunc(a / b) | 0, div_u: () => Math.floor((a >>> 0) / (b >>> 0)) | 0,
    rem_s: () => a % b | 0, rem_u: () => (a >>> 0) % (b >>> 0) | 0,
    and: () => a & b, or: () => a | b, xor: () => a ^ b, shl: () => a << shift,
    shr_s: () => a >> shift, shr_u: () => a >>> shift | 0,
    rotl: () => (a << shift | a >>> (32 - shift)) | 0, rotr: () => (a >>> shift | a << (32 - shift)) | 0,
    eq: () => Number(a === b), ne: () => Number(a !== b),
    lt_s: () => Number(a < b), lt_u: () => Number((a >>> 0) < (b >>> 0)),
    gt_s: () => Number(a > b), gt_u: () => Number((a >>> 0) > (b >>> 0)),
    le_s: () => Number(a <= b), le_u: () => Number((a >>> 0) <= (b >>> 0)),
    ge_s: () => Number(a >= b), ge_u: () => Number((a >>> 0) >= (b >>> 0))
  };
  stack.push(values[suffix]());
  return true;
}

export function traceFunction(mod, functionName, args = [], { maxSteps = 2000, maxDepth = 64 } = {}) {
  const events = [], imports = mod.imports.filter((x) => x.kind === 'func');
  const exported = typeof functionName === 'string' ? mod.exports.find((e) => e.kind === 'func' && e.name === functionName) : null;
  const index = typeof functionName === 'number' ? functionName : exported && exported.index;
  const limit = Number.isFinite(maxSteps) ? Math.max(1, Math.min(10000, Math.floor(maxSteps))) : 2000;
  const depthLimit = Number.isFinite(maxDepth) ? Math.max(1, Math.min(128, Math.floor(maxDepth))) : 64;
  function invoke(functionIndex, values, depth) {
    if (depth >= depthLimit) trap('Call depth limit reached');
    if (!Number.isInteger(functionIndex) || functionIndex < imports.length) trap('Imported or unknown functions are outside the tracer');
    const fn = mod.functions[functionIndex - imports.length], type = fn && mod.types[fn.typeIndex];
    if (!fn || !type) trap('Unknown function index');
    if (type.params.concat(type.results, fn.locals).some((t) => t !== 'i32')) trap('The execution tracer supports i32 functions and locals');
    if (type.params.length + fn.locals.length > 256) trap('Trace local value limit reached');
    if (values.length !== type.params.length || values.some((v) => !Number.isFinite(v) || !Number.isInteger(v))) trap('Provide one integer for each function parameter');
    const locals = values.map((v) => v | 0).concat(fn.locals.map(() => 0)), stack = [];
    const labels = [{ kind: 'function', height: 0, arity: type.results.length, end: fn.code.length - 1 }];
    let pc = 0;
    const pop = () => { if (!stack.length) trap('Operand stack underflow'); return stack.pop(); };
    const take = (n) => { if (stack.length < n) trap('Operand stack underflow'); return stack.splice(stack.length - n, n); };
    const branch = (targetDepth) => {
      const at = labels.length - 1 - targetDepth, target = labels[at];
      if (!target) trap('Branch depth is outside the active labels');
      const carry = take(target.kind === 'loop' ? 0 : target.arity);
      stack.length = target.height; stack.push(...carry);
      labels.length = target.kind === 'loop' ? at + 1 : at;
      pc = target.kind === 'loop' ? target.start + 1 : target.end + 1;
    };
    while (pc < fn.code.length) {
      if (events.length >= limit) trap('Execution step limit reached');
      const ins = fn.code[pc], event = { step: events.length + 1, functionIndex, depth, offset: ins.offset,
        op: ins.op, before: stack.slice(), localsBefore: locals.slice() };
      events.push(event);
      let next = pc + 1;
      const op = ins.op;
      if (op === 'unreachable') trap('Executed unreachable instruction');
      else if (op === 'nop') {}
      else if (op === 'i32.const') stack.push(ins.args[0] | 0);
      else if (op === 'local.get') stack.push(locals[ins.args[0]]);
      else if (op === 'local.set' || op === 'local.tee') { const v = pop(); locals[ins.args[0]] = v; if (op === 'local.tee') stack.push(v); }
      else if (op === 'drop') pop();
      else if (op === 'select') { const condition = pop(), b = pop(), a = pop(); stack.push(condition ? a : b); }
      else if (['block', 'loop', 'if'].includes(op)) {
        if (typeof ins.blockType !== 'string' || !['void', 'i32'].includes(ins.blockType)) trap('Typed block signatures are outside the integer tracer');
        const condition = op === 'if' ? pop() : 1;
        labels.push({ kind: op, start: pc, end: ins.endIndex, height: stack.length, arity: ins.blockType === 'i32' ? 1 : 0 });
        if (!condition) next = ins.elseIndex === undefined ? ins.endIndex : ins.elseIndex + 1;
      } else if (op === 'else') next = ins.endIndex;
      else if (op === 'end') {
        const label = labels.pop();
        if (!label) trap('Control stack underflow');
        const carry = take(label.arity);
        stack.length = label.height; stack.push(...carry);
      } else if (op === 'br' || op === 'br_if' || op === 'br_table') {
        let target = ins.args[0], shouldBranch = true;
        if (op === 'br_if') shouldBranch = pop() !== 0;
        if (op === 'br_table') { const selection = pop() >>> 0; target = selection < ins.targets.length ? ins.targets[selection] : ins.args[0]; }
        if (shouldBranch) { branch(target); next = pc; }
      } else if (op === 'return') {
        const carry = take(type.results.length); stack.length = 0; stack.push(...carry); next = fn.code.length;
      } else if (op === 'call') {
        const calledIndex = ins.args[0], called = mod.functions[calledIndex - imports.length];
        if (!called) trap('Imported functions are outside the tracer');
        const calledType = mod.types[called.typeIndex];
        stack.push(...invoke(calledIndex, take(calledType.params.length), depth + 1));
      } else if (!integerOperation(op, stack)) trap('Instruction outside the tracer subset: ' + op);
      if (stack.length > 512) trap('Trace operand stack limit reached');
      event.after = stack.slice(); event.localsAfter = locals.slice();
      pc = next;
    }
    if (stack.length !== type.results.length) trap('Unexpected result stack height');
    return stack;
  }
  try {
    if (mod.nativeValid !== true) trap('Trace requires a module that passed native validation');
    if (index === null || index === undefined) trap('Select an exported function');
    const results = invoke(index, args, 0);
    return { ok: true, functionIndex: index, results, events, maxSteps: limit };
  } catch (error) {
    if (events.length && !events[events.length - 1].after) events[events.length - 1].error = error.message;
    return { ok: false, functionIndex: index, results: [], events, error: error.message, maxSteps: limit };
  }
}

export function hexRows(bytes, width = 16) {
  const columns = Number.isInteger(width) && width >= 1 && width <= 64 ? width : 16, out = [];
  for (let offset = 0; offset < bytes.length; offset += columns) {
    const row = Array.from(bytes.subarray(offset, offset + columns));
    out.push({ offset, hex: row.map((b) => b.toString(16).padStart(2, '0')).join(' '),
      ascii: row.map((b) => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('') });
  }
  return out;
}

export function parseHex(text) {
  /* A leading 0x is allowed on each whitespace separated token; an 0x in
     the middle of a token is corrupt input, not a second prefix. */
  const normalized = String(text).split(/\s+/).map((t) => t.replace(/^0x/i, '')).join('');
  if (!normalized || normalized.length % 2 || /[^0-9a-f]/i.test(normalized)) throw new Error('Paste complete hexadecimal byte pairs');
  if (normalized.length > 8 * 1024 * 1024) throw new Error('Input exceeds the 4 MiB inspection limit');
  return Uint8Array.from(normalized.match(/../g), (pair) => parseInt(pair, 16));
}

export function demoModule(kind = 'add') {
  const string = (s) => { const data = Array.from(encoder.encode(s)); return encodeULEB(data.length).concat(data); };
  const section = (id, data) => [id].concat(encodeULEB(data.length), data);
  let params, body, locals = [];
  if (kind === 'sum') {
    params = [0x7f];
    locals = [1, 1, 0x7f];
    body = [0x02, 0x40, 0x03, 0x40, 0x20, 0, 0x45, 0x0d, 1,
      0x20, 1, 0x20, 0, 0x6a, 0x21, 1, 0x20, 0, 0x41, 1, 0x6b, 0x21, 0,
      0x0c, 0, 0x0b, 0x0b, 0x20, 1, 0x0b];
  } else if (kind === 'select') {
    params = [0x7f];
    body = [0x20, 0, 0x04, 0x7f, 0x41, 7, 0x05, 0x41, 9, 0x0b, 0x0b];
  } else {
    kind = 'add'; params = [0x7f, 0x7f]; body = [0x20, 0, 0x20, 1, 0x6a, 0x0b];
  }
  const functionBody = (locals.length ? locals : [0]).concat(body);
  return Uint8Array.from([0, 97, 115, 109, 1, 0, 0, 0]
    .concat(section(1, [1, 0x60, params.length].concat(params, [1, 0x7f])))
    .concat(section(3, [1, 0]))
    .concat(section(7, [1].concat(string(kind), [0, 0])))
    .concat(section(10, [1].concat(encodeULEB(functionBody.length), functionBody))));
}
