# WebAssembly Hex Disassembler

A local binary inspector, bounded LEB128 decoder, text disassembler and integer execution tracer. The module is parsed before native validation, and inspection never instantiates a module or invokes imported host functions.

**Live demo:** [https://aariv.me/wasm-hex-disasm/](https://aariv.me/wasm-hex-disasm/)

## Workbench

- Load a local binary, paste hexadecimal byte pairs or choose one of three valid demonstration modules.
- Inspect actual section sizes and offsets, decoded signed and unsigned integers, and byte-aligned hexadecimal rows.
- Read a text listing produced from parsed types, imports, functions, memory, globals, exports and data.
- Execute supported i32 functions and inspect operand stacks and local values at each real instruction.
- Compare all supported integer arithmetic, bit and comparison operations, loops and conditionals against native execution in the tests.

## Supported scope

The inspector handles an MVP profile plus the post-MVP data-count section, passive and explicitly indexed data segments, and multiple tables and memories. It still rejects element segment flags 1 through 7, reference types beyond funcref and externref, the typed select opcode, unsupported prefixed instructions, shared memory and 64-bit memory, and names the rejected construct in the error. Native validation checks type and index validity after bounded parsing.

The tracer supports i32 arithmetic, bit operations, comparisons, locals, direct calls, blocks, loops, conditionals, branches, drop, select and return. Memory operations, floating-point functions, i64 functions and host imports produce an explicit stop. Module start functions are never run.

Bounds are 4 MiB input, 4,096 sections, 100,000 decoded instructions, 100,000 parsed locals across the module, 256 nested control levels, 256 traced local values, 512 traced stack values, at most 10,000 execution steps and at most 128 call frames. The decoded-integer ledger records the first 100,000 entries while counting the rest. The UI defaults to 2,000 steps. Visible byte, section and integer tables have explicit prefix limits. Copying a listing retrieves the full listing even when its visible preview is truncated.

The text listing is inspection output. This repository does not include a text assembler or claim a binary round trip.

## Run and verify

Node 18 or newer, without installing packages.

```bash
npm test
python3 -m http.server 8000
```

Open the server URL. The ES module page requires a static server. All input stays local, and fonts are self hosted with their licenses in `fonts/OFL.txt`.

## Files

- `src/wasm.mjs` contains bounded readers, opcode decoding, parsing, disassembly and tracing.
- `src/app.mjs`, `index.html` and `styles.css` contain the interactive inspector.
- `test/` contains native numerical comparisons, parser regressions, mounted controller tests and content checks.

<!-- verification -->

MIT. See `LICENSE`.
