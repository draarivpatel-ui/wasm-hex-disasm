import test from 'node:test';
import assert from 'node:assert/strict';
import { Reader, parseModule, demoModule } from '../src/wasm.mjs';
import { sha256, bytesToBase64url, base64urlToBytes, restoreHash, reportCSV, marshalArgs, SHARE_LIMIT } from '../src/analysis.mjs';


test('parseModule rejects non-byte array values instead of coercing them', () => {
  const bytes = Array.from(demoModule());
  bytes[7] = 256;
  assert.throws(() => parseModule(bytes), /byte/i);
  assert.throws(() => parseModule([0, 97, 115, 109, 1, 0, 0, null]), /byte/i);
  assert.throws(() => parseModule('not bytes'), /byte/i);
});

test('Reader rejects non-byte array values before decoding', () => {
  assert.throws(() => new Reader([256]), /byte/i);
  assert.throws(() => new Reader('abc'), /byte/i);
});

test('sha256 rejects non-byte array values instead of coercing them', () => {
  for (const value of [[256], [-1], [1.5], [null], [undefined], ['0'], [NaN]]) {
    assert.throws(() => sha256(value), /byte/i, JSON.stringify(value));
  }
});

test('base64url encoding rejects non-byte array values', () => {
  assert.throws(() => bytesToBase64url([256]), /byte/i);
  assert.throws(() => bytesToBase64url([null]), /byte/i);
});

test('base64urlToBytes rejects impossible one-character final chunks', () => {
  assert.throws(() => base64urlToBytes('A'), /length/i);
  assert.throws(() => base64urlToBytes('AAAAA'), /length/i);
  assert.throws(() => base64urlToBytes('A==='), /length/i);
});

test('restoreHash rejects payloads above the share limit before decoding', () => {
  const encoded = bytesToBase64url(new Uint8Array(SHARE_LIMIT + 1));
  assert.throws(() => restoreHash('#b=' + encoded), /limit/i);
});

test('restoreHash still accepts a payload at the exact share limit', () => {
  const bytes = new Uint8Array(SHARE_LIMIT);
  bytes[0] = 1;
  bytes[SHARE_LIMIT - 1] = 2;
  const restored = restoreHash('#b=' + bytesToBase64url(bytes));
  assert.equal(restored.length, SHARE_LIMIT);
  assert.equal(restored[0], 1);
  assert.equal(restored[SHARE_LIMIT - 1], 2);
});

test('reportCSV defuses spreadsheet formulas even after leading whitespace', () => {
  const mod = parseModule(demoModule());
  for (const hostile of ['=cmd', '  =cmd', ' \t+HYPERLINK("x")', '@evil', '\t-10']) {
    mod.exports[0].name = hostile;
    const row = reportCSV(mod).split('\n').find((line) => line.startsWith('export,'));
    assert.ok(row, 'export row exists');
    assert.ok(!/^export,(=|\+|-|@|\t|\r)/.test(row), row);
    assert.ok(row.includes("'"), row);
  }
});

test('reportCSV quotes formula cells that contain commas or whitespace', () => {
  const mod = parseModule(demoModule());
  mod.exports[0].name = '  =cmd,still hostile';
  const row = reportCSV(mod).split('\n').find((line) => line.startsWith('export,'));
  assert.equal(row, 'export,"\'  =cmd,still hostile",,,,,func 0');
});

test('marshalArgs rejects booleans and null for integer parameters', () => {
  for (const type of ['i32', 'i64']) {
    for (const value of [null, true, false, [], {}]) {
      assert.throws(() => marshalArgs([type], [value]), /integer/i, type + ' ' + JSON.stringify(value));
    }
  }
});

test('marshalArgs rejects blank strings and fractional numbers for i64', () => {
  for (const value of ['', '   ', 1.5, NaN, Infinity]) {
    assert.throws(() => marshalArgs(['i64'], [value]), /integer/i, String(value));
  }
});
