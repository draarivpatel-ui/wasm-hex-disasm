import { encodeULEB, encodeSLEB } from '../../src/wasm.mjs';
export const nameBytes = (s) => { const b = Array.from(new TextEncoder().encode(s)); return encodeULEB(b.length).concat(b); };
export const section = (id, data) => [id].concat(encodeULEB(data.length), data);
export const moduleBytes = (...sections) => Uint8Array.from([0, 97, 115, 109, 1, 0, 0, 0].concat(...sections));
export function functionModule(body, { params = [0x7f, 0x7f], results = [0x7f], locals = [], exportName = 'run', extra = [] } = {}) {
  const localGroups = locals.length ? [1].concat(encodeULEB(locals.length), [0x7f]) : [0];
  const bytes = localGroups.concat(body, [0x0b]);
  return moduleBytes(section(1, [1, 0x60, params.length].concat(params, [results.length], results)),
    section(3, [1, 0]), ...extra, section(7, [1].concat(nameBytes(exportName), [0, 0])),
    section(10, [1].concat(encodeULEB(bytes.length), bytes)));
}
export const constant = (n) => [0x41].concat(encodeSLEB(n));
export const nameSection = (pairs) => {
  const inner = [pairs.length].concat(...pairs.map(([index, text]) => [index].concat(nameBytes(text))));
  return section(0, nameBytes('name').concat([1], encodeULEB(inner.length), inner));
};
export const customSection = (name, payload) => section(0, nameBytes(name).concat(payload));
export const importEntry = (module, name, descriptor) => nameBytes(module).concat(nameBytes(name), descriptor);
