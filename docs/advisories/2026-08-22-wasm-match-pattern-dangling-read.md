# Capa security advisory, 2026-08-22: a Wasm `match` on a String-literal pattern read dangling memory and could spuriously match

> **Status.** Published with the `1.32.0` release. The finding below is a Wasm
> Component Model backend codegen bug: a `match` or destructure whose pattern
> carried a `String` literal appearing nowhere else in the module read dangling
> memory, so the comparison could take a wrong branch or SPURIOUSLY MATCH,
> bypassing an authorization check. It is a soundness / codegen fix; it ships as a
> **MINOR** bump under the [`STABILITY.md`](../../STABILITY.md) security exception.

This advisory satisfies the `STABILITY.md` requirement that a security fix
changing observable behaviour without a major bump "ships with a security
advisory ... [that] states explicitly what changed and why the change is not
subject to the major-bump rule."

**Severity:** Moderate. The primary consequence is a **backend-specific incorrect
result** that can be an authorization bypass: a `match` arm used to gate access on
a literal string could match when it should not. The bug is confined to the Wasm
backend; the legacy transpiler and the CIR Python backend were never affected, so
a program run or tested on the Python backend behaved correctly, which makes the
Wasm-only divergence the dangerous property. There is no arbitrary memory write,
no host escape, and the module still passed `wasm-tools validate` (the read is of
in-bounds but uninitialised linear memory).

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` (~4.2). CVSS is an imperfect fit:
the flaw is a compiler codegen bug, not a runtime service vulnerability. `AC:H`
reflects that the string literal must appear SOLELY in the pattern (a copy
materialised anywhere else masked the bug); whether a wrong branch is a security
event depends on the program. The confidentiality / integrity impact is marked
low because the misread is of the module's own uninitialised heap, and the
observable effect is a wrong control-flow branch rather than a direct data
disclosure.

**CWE:** CWE-908 (use of uninitialised resource), with an authorization-bypass
consequence (CWE-863, incorrect authorization) when the mis-compiled `match` gates
access.

**Affected versions:** `< 1.32.0` on the `1.x` line, Wasm Component Model backend
only (`--wasm` / `--wasi`). The Python backends are unaffected. The bug was
reproduced on the current `main` before the fix; the exact earliest affected
release was not bisected by executing each historical binary.

**Fixed in:** `1.32.0`.

**GHSA:** GHSA-22qh-gw83-x9mj.

**Reporter / process:** internal hardening pass for the `1.32.0` release,
following the audit of the whole compiler (audit finding C-F2). Fix commit
`614ded7`.

**Channel:** this advisory; cross-referenced from the `1.32.0` `CHANGELOG.md`
entry.

## Why this is a security fix, not a breaking change

The Wasm backend emitted code that read uninitialised memory for a valid program,
so a `match` could take an incorrect branch and defeat an authorization gate the
source expresses. Correcting the codegen restores the documented semantics and the
byte-identical-output promise between the Python and Wasm backends. The direction
of the change is codegen-correcting and reject-only for the guard it adds; only a
program that was already mis-compiled is affected. It ships as a **MINOR** bump.

## Details

On the Wasm backend a `match` or destructure whose pattern carried a `String`
literal that appeared nowhere else in the module read dangling memory: the string
discovery pass never descended into `arm.pattern` (the instruction walk skips it
and the value enumeration reached no pattern slot), so the literal was first
interned at match-emit time, PAST the frozen `heap_start`, with a fresh offset but
no backing `(data ...)` block. The `$str_eq` comparison then ran against undefined
bytes: usually a silent wrong branch, occasionally a spurious match, which when
the arm gates access is an authorization bypass. The bug bit only when the literal
appeared SOLELY in the pattern; a copy materialised elsewhere (printed,
interpolated) interned it early and masked it.

```capa
fun authorize(role: String) -> Bool
    match role
        "admin" -> true                # "admin" appears only here
        _ -> false
```

If `"admin"` occurs nowhere else in the module, the compare on the Wasm backend
read undefined bytes and could return `true` for a non-admin role.

## The fix

`614ded7` interns every match-pattern String literal during the discovery pass,
before the data segment freezes, in `capa/ir/_emit_wasm/_discovery.py`:

- `_pattern_str_literals` (`capa/ir/_emit_wasm/_discovery.py:76`) is a recursive
  collector that yields every `String` literal in a pattern at any nesting depth
  (variant payload, tuple element, struct field, or-alternative), and a `Match`
  branch in the discovery walk interns each. The five match-emit sites in
  `capa/ir/_emit_wasm/_match.py` then dedup to the pre-frozen offset.
- A one-way `_strings_frozen` high-water flag (`capa/ir/_emit_wasm/__init__.py:324`,
  set at `capa/ir/_emit_wasm/__init__.py:1260` once the data segment is written)
  makes `_intern_string` (`capa/ir/_emit_wasm/__init__.py:1490`) raise a
  `WasmEmissionError` naming any brand-new string interned after the freeze, so a
  future regression of this class fails loud at emit time instead of emitting a
  dangling read. The dedup path for an already-present string is unchanged.

The same commit also hoists the four fixed `Fs` error messages out of the
static-ceiling sub-block so a dynamic-preopen program pre-interns them before its
`$Fs_*` wrappers emit (a related pre-freeze coverage gap surfaced by the new
guard).

The fix is Wasm-backend-only and soundness / reject-only. Because Wasm strings are
self-describing `(ptr, len)`, the earlier data-segment offsets shift but the
output of every correct program is unchanged.

## Remediation

**Upgrade to `1.32.0`.** On affected versions, a workaround was to ensure any
security-relevant literal pattern also appeared elsewhere in the module (so it
interned early), but that is fragile and not a reliable mitigation. Upgrading is
the only remedy that closes the class.

## Verification

Adds
[`tests/test_wasm_match_pattern_intern.py`](../../tests/test_wasm_match_pattern_intern.py):
the five emit sites plus nesting via heap-built scrutinees, diffed across the
legacy-Python, CIR-Python, and Wasm backends; a same-length spurious-grant
security shape; the dedup no-op; the dynamic-preopen `Fs` data-block assertion;
and a high-water-guard-fires test. The cross-backend diff establishes byte-level
output parity for the corrected programs.

## Credit

Found and fixed during the internal hardening pass for the `1.32.0` release
(audit finding C-F2).
