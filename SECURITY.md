# Security policy

## Reporting a vulnerability

Use the private GitHub Security Advisory form at [Report a vulnerability](https://github.com/draarivpatel-ui/wasm-hex-disasm/security/advisories/new). Do not open a public issue, pull request or discussion with exploit details.

Never include a live secret, token, cookie, private key, victim hostname or proprietary payload in a report. Use synthetic values and redacted transcripts.

## Supported versions

| Version | Status |
| --- | --- |
| latest `main` | Supported |

Security fixes are applied to the latest state of the default branch.

## Scope

This policy covers the static Wasm Hex Disassembler browser application, including WebAssembly binary parsing, hex inspection, disassembly display, trace output, local state and browser rendering.

In scope:

- A cross-site scripting or HTML injection path through binary metadata, parsed instructions, hex display, trace output or imported text.
- A parser or decoder validation flaw that turns a crafted binary into attacker-controlled script execution.
- A file export or copy-output flaw that makes generated output execute a formula or script when opened.
- A local persistence or browser state flaw that crosses a trust boundary or sends uploaded binary data off the device.

Out of scope:

- Browser vulnerabilities, operating system compromise or physical access to the machine.
- Damage caused by modified copies of the static application that do not come from this repository.
- The documented limits of an offline educational model or simulator, unless a report shows a specific validation or output integrity failure.

## Coordinated disclosure

- Acknowledgment: within 3 business days.
- Initial triage: within 14 calendar days.
- Fix or mitigation target: within 90 calendar days for confirmed reports.
- Coordinated public disclosure: up to 90 days by default, adjusted by mutual agreement when exploitation or user risk requires a different date.
