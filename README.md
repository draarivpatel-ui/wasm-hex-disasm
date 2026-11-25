# WebAssembly Hex Disassembler

A local binary inspector, bounded LEB128 decoder, text disassembler, call graph renderer, capability auditor, sandboxed export runner and integer execution tracer. The module is parsed before native validation, and inspection never instantiates a module or invokes imported host functions.

**Live demo:** [https://aariv.me/wasm-hex-disasm/](https://aariv.me/wasm-hex-disasm/)

## Workbench

- Load a local binary, paste hexadecimal byte pairs or choose one of three valid demonstration modules.
- Inspect actual section sizes and offsets, decoded signed and unsigned integers, and byte-aligned hexadecimal rows.
- See a proportional byte map across every region (header, type, import, function, table, memory, global, export, start, element, code, data, data count and custom) and select a segment to highlight its real bytes.
- Read a static call graph drawn as SVG: imported and defined functions, direct call edges, per-function instruction counts, exported entries, and functions unreachable from exports, start or tables flagged as dead.
- Read a capability audit that flags host imports by module and name, linear memory use and growth sites, indirect `call_indirect` dispatch and table slots, `unreachable` traps, embedded debug names, mutable globals, automatic start functions and unreachable code, alongside the SHA-256 fingerprint and native validation parity.
- Run zero-import integer exports natively in a dedicated worker thread with a 1500 ms budget and an empty import object; non-integer signatures and import-dependent modules are declined with reasons.
- Export a text listing, a SHA-256 fingerprinted JSON audit report and a CSV section and opcode histogram table, or copy a URL-hash share link that restores a small module on load.
- Run the in-page self-test battery covering LEB128 round trips, magic and version enforcement, SHA-256 known vectors, native validation parity, listing, call graph, histogram and share link integrity.
- Execute supported i32 functions and inspect operand stacks and local values at each real instruction.

## Supported scope

The inspector handles an MVP profile plus the post-MVP data-count section, passive and explicitly indexed data segments, and multiple tables and memories. It still rejects element segment flags 1 through 7, reference types beyond funcref and externref, the typed select opcode, unsupported prefixed instructions, shared memory and 64-bit memory, and names the rejected construct in the error. Native validation checks type and index validity after bounded parsing.

The tracer supports i32 arithmetic, bit operations, comparisons, locals, direct calls, blocks, loops, conditionals, branches, drop, select and return. Memory operations, floating-point functions, i64 functions and host imports produce an explicit stop. Module start functions are never run.

The sandboxed runner accepts i32 and i64 signatures, marshals i64 arguments through BigInt, executes inside a worker thread it can terminate on a 1500 ms budget, and declines every module that declares host imports or a start function. It is an inspection aid, not a security boundary.

Bounds are 4 MiB input, 4,096 sections, 100,000 decoded instructions, 100,000 parsed locals across the module, 256 nested control levels, 256 traced local values, 512 traced stack values, at most 10,000 execution steps and at most 128 call frames. The decoded-integer ledger records the first 100,000 entries while counting the rest. The UI defaults to 2,000 steps. Visible byte, section and integer tables have explicit prefix limits. Copying a listing retrieves the full listing even when its visible preview is truncated. Share links restore modules up to 32 KiB and the call graph draws its first 40 nodes.

The text listing is inspection output. This repository does not include a text assembler or claim a binary round trip.

## Run and verify

Node 18 or newer, without installing packages.

```bash
npm test
python3 -m http.server 8000
```

Open the server URL. The ES module page requires a static server. All input stays local, and fonts are self hosted with their licenses in `fonts/OFL.txt`. The test suite holds 337 checks covering decoder boundaries, parser regressions, native execution parity, the analysis engine, reporting, share links and the mounted controller.

## Files

- `src/wasm.mjs` contains bounded readers, opcode decoding, parsing, disassembly and tracing.
- `src/analysis.mjs` contains SHA-256, the section map, call graph, capability audit, sandbox planning and execution, reports, share links and the self-test battery.
- `src/app.mjs`, `index.html` and `styles.css` contain the interactive inspector.
- `test/` contains native numerical comparisons, parser regressions, analysis and report tests, mounted controller tests and content checks.

<!-- verification -->

MIT. See `LICENSE`.
