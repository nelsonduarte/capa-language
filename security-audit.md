# Capa security audit, 2026-05-25

Scope as briefed: capability discipline, `Unsafe` / `py_interop`,
package manager + supply chain, SBOM / SLSA emissions, lexer / parser
robustness, runtime privilege posture. Read-only on source. Findings
that duplicate closed audit items (holes A, B, C and the `478edb3`
supply-chain pair) are omitted.

## Executive summary

- **Hole D (new): consume-discipline is `Ident`-only.**
  `_mark_consumed_args` in
  [`capa/analyzer/_discipline.py:42-65`](capa/analyzer/_discipline.py#L42)
  skips every non-`A.Ident` argument, so `f(consume box.cap)` followed
  by `box.cap.use()` passes the analyzer. The fix for holes A+B
  canonicalised FieldAccess paths for the aliasing check but did not
  thread the same canonicalisation through use-after-consume.
- **`vendor/<name>` path-traversal at install time.** TOML allows
  arbitrary quoted keys in `[dependencies."../evil"]`. The manifest
  parser does not validate `dep.name`, so
  [`capa/pkg/_install.py:186`](capa/pkg/_install.py#L186)
  resolves `vendor_dir / "../evil"` outside the project's `vendor/`.
  A malicious upstream that publishes a `capa.toml` with a crafted
  dependency name can overwrite paths anywhere the install user can
  write.
- **Git pin (`tag` / `rev`) strings are never validated.** The
  `478edb3` allow-list locked down the `git` URL but the pin string
  is passed straight to `git clone --branch <pin>`,
  `git checkout --detach <pin>`, and `git verify-tag <pin>`. A pin
  like `--upload-pack=...` won't be parsed as a flag by git in those
  exact positions (the URL is the option-position), but the pin does
  flow into `git verify-tag --raw <pin>` where it is the sole
  positional and easier to abuse. Same shape as the URL hole, half
  closed.
- **Wasm host bridges blindly trust the guest for attenuation.**
  `Fs.restrict_to` is a documented no-op
  ([`capa/runtime/_wasm_host.py:398-403`](capa/runtime/_wasm_host.py#L398),
  [`capa/runtime/_wasm_component_host.py:117-122`](capa/runtime/_wasm_component_host.py#L117)).
  Static discipline is enforced only against Capa-compiled WAT; a
  hand-rolled or modified Wasm module loaded by `WasmHost.run_main`
  has unrestricted `fs.read` / `fs.write` on the host filesystem.
- **SBOM/SPDX emit missing required-by-some-consumers fields.**
  Neither `_spdx.py` nor `_cyclonedx.py` populate `licenseConcluded`
  / `licenseDeclared` / `downloadLocation` (other than `NOASSERTION`)
  / `supplier` / `copyrightText`. OpenChain-grade consumers and
  `spdx-tool validate` will refuse or downgrade these documents.

## Critical findings

### [CLOSED b21dd73] C1. Path traversal via dependency name

[`capa/pkg/_install.py:186`](capa/pkg/_install.py#L186) writes a
fresh clone to `vendor_dir / dep.name` and unconditionally
`_rmtree_force`s any prior entry there. `dep.name` is the table key
under `[dependencies.X]` and is plumbed verbatim through
`_parse_dep` in [`capa/pkg/_manifest.py:228-281`](capa/pkg/_manifest.py#L228)
with no allow-list. TOML's lexical syntax accepts arbitrary quoted
keys including `../foo`, `./foo`, absolute paths under Windows
(`C:\foo`), and characters that are illegal in package identifiers
(`*`, `?`, control chars).

**Attack**: a malicious upstream that gets a contributor to add their
package as a sub-dependency ships a `capa.toml` whose own
`[dependencies."../../$HOME/.bashrc"]` entry pivots the eventual
`_rmtree_force` outside the project. With the recursive removal of
arbitrary directories on `install`, this is a hostile-file-deletion
primitive at minimum and an overwrite primitive (the clone writes
the upstream's tree on top of whatever was there).

**Recommended fix**: enforce a name regex at manifest-load time, e.g.
`^[a-zA-Z_][a-zA-Z0-9_-]{0,63}$`; reject anything else with the same
shape as `_validate_git_url`. Also resolve the final destination with
`Path.resolve()` and assert it is under `vendor_dir.resolve()` before
any rmtree / clone.

### C2. Wasm `Fs.restrict_to` is a runtime no-op

[`capa/runtime/_wasm_host.py:389-404`](capa/runtime/_wasm_host.py#L389)
("fs.restrict_to is a no-op at the Wasm level") and the parallel
[`capa/runtime/_wasm_component_host.py:117-122`](capa/runtime/_wasm_component_host.py#L117)
both ignore the prefix argument and return `None`. The doc says
"the analyzer enforces it"; that holds only for code Capa itself
compiled. Two break paths exist:

1. A `.wasm` artefact built outside Capa (or hand-edited after
   `capa --wasm --output`) imported into `WasmHost.run_main` gets
   unconditional `fs.read` / `fs.write` on any path. The Wasm host
   is the same trust boundary as a sandbox, but does not behave like
   one.
2. Even Capa-compiled output: a malicious Capa source can declare
   `fs.restrict_to("data/")` then call `fs.read("/etc/passwd")` and
   the runtime will obey the second call. The analyzer rejects this
   for `--python` (the runtime `Fs` instance carries the prefix set,
   see [`capa/runtime/_capabilities.py:114-160`](capa/runtime/_capabilities.py#L114))
   but not for `--wasm`.

This contradicts `docs/positioning.md`'s "attenuation is monotonic
by construction" claim for the Wasm backend.

**Recommended fix**: thread a per-instance prefix set in the host,
populate it on `restrict-to`, and validate paths in `fs_read` /
`fs_write` against the same `_path_allowed` logic Python's
`Fs.allows` already implements. The Wasm-CM path also needs an
`Env.restrict_to_keys` honouring branch; today
[`_wasm_component_host.py:81-88`](capa/runtime/_wasm_component_host.py#L81)
exposes raw `os.environ.get`.

## High-priority findings

### [CLOSED 022cb13] H1. Consume discipline misses FieldAccess sources (Hole D)

[`capa/analyzer/_discipline.py:42-65`](capa/analyzer/_discipline.py#L42)
gates the entire body on `isinstance(arg, A.Ident)`. The aliasing
check was canonicalised to walk Ident-rooted FieldAccess chains
when closing holes A+B; the use-after-consume check was not.

Repro shape:
```capa
type Box { cap: Stdio }
fun two(s: consume Stdio, t: Stdio)
    ...
fun bug(box: Box)
    consume_one(box.cap)   // analyzer should mark consumed
    box.cap.println("oops") // analyzer accepts; runtime races
```
The `_consumed.add(arg.name)` line at
[`_discipline.py:65`](capa/analyzer/_discipline.py#L65) never runs
for FieldAccess args, so subsequent uses of the same path slip
through.

**Recommended fix**: replace the `arg.name` keying with the canonical
dotted path returned by `_path_of` (the helper already exists at
line 125). Track `_consumed` as a set of dotted paths; the aliasing
check already proves paths compare correctly.

### [CLOSED 47bbdc4] H2. Git pin string flows unvalidated into `git verify-tag`

[`capa/pkg/_install.py:265`](capa/pkg/_install.py#L265) calls
`["git", "-C", str(dest), git_cmd, "--raw", pin]`. Same shell-safe
arg-list pattern as `_run_git`, so direct command injection is
closed, but the pin still ends up as a *git refspec* parsed by git
itself. A pin string like `--no-such-flag` is the option position
for `verify-tag` (git checks options after `--raw`). Today git
treats unknown options as errors so the install fails closed, but
that is a property of git's option parser, not Capa's validation.
Pin strings should be locked down by Capa: at the manifest layer
reject pins containing `/`, `..`, leading `-`, or characters outside
`[a-zA-Z0-9._+\-]`.

[`_install.py:206`](capa/pkg/_install.py#L206)'s
`clone --depth 1 --branch <pin>` is on the same footing.

### [CLOSED 0d57139] H3. Lockfile rewrite ordering: `vendor/<name>` is overwritten before SHA mismatch fires

[`capa/pkg/_install.py:122-167`](capa/pkg/_install.py#L122) loop:
`_fetch_git_dep` calls `_rmtree_force(dest)` and then re-clones,
*then* the SHA is compared to the lockfile entry. If a tag moved
upstream, the vendored tree on disk has already been replaced with
the attacker-controlled commit by the time `LockMismatchError` is
raised. The user is given the error and refuses to commit the new
lockfile - but their working tree now contains the malicious
sources, and any IDE / language server / `capa build` invocation
before they notice the error reads from the new tree.

**Recommended fix**: clone to a temp directory, compare SHA to the
lock entry, swap-or-discard atomically. Or at minimum, restore the
prior `vendor/<name>` from a `.git/HEAD~1` snapshot before raising.

### [CLOSED 3752972] H4. JSON parser bundled in the Wasm guest has no depth limit

[`capa/ir/_builtin_json.capa`](capa/ir/_builtin_json.capa) parser
recurses through `__cj_parse_value` -> `__cj_parse_array` ->
`__cj_parse_value` (and the object equivalent) with no maximum
depth. A guest that compiles in this parser and feeds it
adversarial input `[[[[ ... ]]]]` runs to either Wasm stack overflow
(trap) or, more interestingly, deep recursion before failing -
making `parse_json` a viable DoS surface for any Wasm module that
exposes JSON parsing to untrusted input. The host-side
`json.loads` (Python's `json` module, used by `_wasm_host._register_json`)
has its own native limit so the core-wasm path is safe; the bundled
parser is the new surface.

**Recommended fix**: hard depth cap (1000 levels is the de-facto
limit `json.loads` uses internally) in `__cj_parse_value`; return
`Err("max depth exceeded")` past it.

### [CLOSED 2570eec] H5. SBOM / SPDX missing required fields for compliance consumers

[`capa/manifest/_spdx.py:127-134`](capa/manifest/_spdx.py#L127)
emits packages with only `name`, `SPDXID`, `versionInfo`,
`downloadLocation: NOASSERTION`, `filesAnalyzed: false`. SPDX 2.3
requires (for compliance consumers like OpenChain) `licenseConcluded`,
`licenseDeclared`, `copyrightText` (typically `NOASSERTION` is
acceptable but the *field* must be present).
[`capa/manifest/_cyclonedx.py:208-214`](capa/manifest/_cyclonedx.py#L208)
emits components without `licenses[]` or `supplier`. A consumer
running `cyclonedx-cli validate --strict` will refuse these
documents.

If the audit pipeline is the "visible payoff" per
`docs/positioning.md`, an SBOM that strict tooling rejects undercuts
the claim. The README and `docs/regulatory.md` say Capa emits
CRA / NIS2-compatible artefacts; today's output is "valid" only by
permissive validators.

**Recommended fix**: emit `licenseConcluded: NOASSERTION` and
`copyrightText: NOASSERTION` on every SPDX package; add
`licenses: [{license: {id: "NOASSERTION"}}]` on every CycloneDX
component. Then run `spdx-tool validate` and `cyclonedx-cli validate
--strict` in CI to lock the property in.

## Medium / low / informational

- **M1. SBOM properties accept user `@security(...)` attrs verbatim.**
  [`capa/manifest/_cyclonedx.py:196-206`](capa/manifest/_cyclonedx.py#L196)
  interpolates `attr["args"]` values into `properties[]` without
  shape validation. The JSON encoder escapes JSON-special characters
  so injection into the document is closed, but a hostile attribute
  arg of unbounded length can blow downstream SBOM diff tools. Add a
  per-value length cap (4 KiB) at the emitter.
- **M2. Parser has no recursion cap.**
  [`capa/parser/_expressions.py:45`](capa/parser/_expressions.py#L45)
  recursive descent on `_parse_expr` with no depth limit. Adversarial
  source like `((((((((...))))))))` hits Python's `RecursionError`
  before useful work happens, but since `capa --check` is one of the
  surfaces a build farm would point at untrusted input, a depth cap
  (say 200) with a clean diagnostic is cheap insurance.
- **M3. `install.sh` SHA-256 fetched over the same redirect chain as
  the binary.** [`deploy/install.sh:91-99`](deploy/install.sh#L91)
  fetches `$URL` and `$URL.sha256` from the same GitHub release
  endpoint. A MITM that owns the redirect chain (or a CDN-level
  cache poisoning) sees both fetches; the verification only catches
  an attacker who corrupted the binary but not the `.sha256`. Pinning
  the expected hash *in the script* (or fetching it from a different
  origin / over a different channel) raises the bar. Trade-off: hash
  pinning means the script can't be the "latest" entry point any
  more.
- **M4. `gh attestation verify` graceful-skip is fail-open by design.**
  [`capa/pkg/_install.py:332-417`](capa/pkg/_install.py#L332) silently
  skips when the asset is missing or `gh` is not on PATH. The
  comment acknowledges this and proposes a future
  `verify_provenance = "required"` field. Until that lands, every
  consumer is fail-open on SLSA verification; the README and
  `CHANGELOG.md` (2026-05-23) phrase the three-layer stack as if it
  fires whenever `verify_key` is set. Worth a doc clarification at
  minimum.
- **M5. Wasm `env.get` and `env.args` expose host environment
  unconditionally.**
  [`_wasm_host.py:163-202`](capa/runtime/_wasm_host.py#L163) /
  [`_wasm_component_host.py:81-88`](capa/runtime/_wasm_component_host.py#L81)
  read raw `os.environ`; the analyzer's
  `Env.restrict_to_keys` is unenforced in both Wasm hosts (same root
  cause as C2). Lower severity because Env exposure is
  read-only and far less damaging than Fs writes.
- **L1. `_alloc_export` calls in the Wasm host are unchecked.** If a
  guest's `$alloc` returns 0 (OOM in the bump allocator), the host
  writes a UTF-8 buffer at address 0, scribbling on the data
  segment. Not exploitable across the trust boundary (the guest's
  own memory) but breaks the diagnostic for OOM. Surface in
  `_alloc_utf8` / `_alloc_string` ([`_wasm_host.py:302`](capa/runtime/_wasm_host.py#L302),
  [`:469`](capa/runtime/_wasm_host.py#L469)).
- **L2. CycloneDX VEX `analysis.firstIssued` reuses build timestamp.**
  [`capa/manifest/_vex.py:102`](capa/manifest/_vex.py#L102) stamps
  every VEX entry with the build's timestamp. The spec means
  "when the VEX statement was first published"; downstream tooling
  reading the field as a real publication date will be misled. Pass
  the date through from the `@vex` attribute if declared.
- **I1. `Net` capability has no Wasm host bridge at all.** Capa
  programs that take `Net` cannot be compiled to Wasm in the current
  shape; this is consistent with the documented Phase 6/7 scope, but
  it means the `examples/cve_*.capa` Net-using studies do not have
  Wasm parity coverage. Not a finding against current claims,
  documented for context.

## Out of scope / explicitly cleared

- **Capability hole C (generic-instantiation cap leak)**: closed
  cleanly in commit `8e76046`. `_reject_cap_leak_via_substitution`
  fires in both
  [`capa/analyzer/_dispatch.py:305-315`](capa/analyzer/_dispatch.py#L305)
  (free fn) and `:475-487` (method dispatch). The
  pre-substitution-already-named-cap escape is correctly
  short-circuited. Re-tested against the TODO.md reference shape.
- **Aliasing on FieldAccess paths (Hole B)**: closed in `a4ad4ab`.
  `_is_capability_ident` correctly returns a dotted path for
  FieldAccess chains; the aliasing check compares paths. The same
  helper is the building block H1 asks to reuse for consume.
- **`Unsafe` capability at the analyzer level**: enforced by normal
  type checking via the
  [`capa/builtins.py:240-241`](capa/builtins.py#L240) function
  signatures (`py_import`, `py_invoke` require `TyName("Unsafe")`
  as first param). The runtime double-check in
  [`_pyinterop.py:16-22`](capa/runtime/_pyinterop.py#L16) catches
  mis-generated code. No bypass surfaced.
- **`git clone` URL allow-list**: the `478edb3` regex + ext::
  rejection are tight. `ext::`, `-uupload-pack=`, and the
  `git@host:-x` shortcut all hit the validator. No residual.
- **Provenance emission**: [`capa/manifest/_provenance.py`](capa/manifest/_provenance.py)
  is faithful to SLSA Build L1; the document does not over-claim
  signing (it explicitly notes "No signing. Signature lifts the
  attestation to L2; left to external tooling").

## Recommended sequencing

1. **C1 first** (dependency-name path traversal). Cheapest fix,
   highest impact; the install command is the most user-facing
   write-anywhere surface in the project.
2. **H1** (consume discipline on FieldAccess). Single-function
   change in `_discipline.py`; the existing `_path_of` helper makes
   this a few-line patch. Closing it before the paper / launch
   matters because hole D undercuts the "single-flow" soundness
   claim the same way A and B did.
3. **C2** (Wasm `Fs.restrict_to` no-op) and **M5** (Env). One
   coordinated change in both Wasm hosts; the Python implementation
   in `_capabilities.py` is the reference. After this lands, the
   `--wasm` and `--python` backends finally agree on attenuation
   semantics.
4. **H2 + H3** (pin validation, atomic vendor swap). Both are
   tightening already-good supply-chain code; H3 in particular is
   a small refactor of `_fetch_git_dep` to a temp directory.
5. **H5** (SBOM compliance fields). Mostly mechanical, gated on
   adding `cyclonedx-cli validate --strict` to CI so the property
   doesn't regress.
6. **H4** (JSON depth cap), **M1** / **M2** (cap user-input sizes /
   parser depth). Hardening; no known incident driving them, but
   each is a few lines and closes a DoS surface against `capa
   --check` of untrusted input.
