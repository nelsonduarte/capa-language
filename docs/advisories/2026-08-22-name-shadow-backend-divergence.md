# Capa security advisory, 2026-08-22: a name-shadow diverged between the Python and Wasm backends and could silently disclose a `@secret`

> **Status.** Published with the `1.32.0` release. The finding below is a
> silent backend divergence: a binding whose name shadowed an enclosing binding
> or a module-level const / function was accepted by `capa --check` yet compiled
> to DIFFERENT behaviour on the Python backends and the Wasm Component Model
> backend, so for a captured or read `@secret` one backend disclosed the secret
> while the other crashed or bound a different value. It is claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** (the soundness-fix
> carve-out) and is therefore shipped as a **MINOR** bump, not a MAJOR one.

This advisory satisfies the `STABILITY.md` requirement that a security fix
changing observable behaviour without a major bump "ships with a security
advisory ... [that] states explicitly what changed and why the change is not
subject to the major-bump rule."

**Severity:** Moderate. The consequence is a **silent, backend-specific
disclosure of a `@secret`** (or a wrong value / validation failure for a
non-secret) that breaks Capa's byte-identical-output promise between the Python
interpreter and the Wasm Component Model backend. A program that passed
`capa --check` and ran correctly on the Python backend could disclose the secret
when built to Wasm (or vice versa, depending on the shape). There is no host
escape, no memory-unsafety, and no capability bypass. It is scoped down by the
specific requirement that a name genuinely shadow an enclosing binding or a
read module symbol.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` (~5.6). CVSS is an imperfect fit:
the flaw is a compiler soundness / divergence bug. `AC:H` reflects the specific
name-shadow shape that must be present; the low integrity term reflects the
wrong-value / validation-failure face for non-secret shadows.

**CWE:** CWE-200 (exposure of sensitive information) for the `@secret`-disclosure
face, with the underlying cause an inconsistent scoping model between the two
backends (a behavioural-difference class).

**Affected versions:** `< 1.32.0` on the `1.x` line. The divergence was
reproduced on the current `main` before the fix (the minimal repro printed the
secret on one backend and the public value on the other); the exact earliest
affected release was not bisected by executing each historical binary.

**Fixed in:** `1.32.0`.

**GHSA:** GHSA-XXXX-XXXX-XXXX (to be assigned at publication).

**Reporter / process:** internal hardening pass following the `1.31.0` release
(this was disclosed as an open backlog residual when `1.31.0` shipped). Fix
commits: `4b9c9e6` (reject a lambda-body binding that shadows an enclosing scope),
`887f0c3` (reject a plain-function shadow of a module const / function it reads),
`0e306b5` (stop a lambda-body bind from corrupting an enclosing const read on
Wasm), and `3673fd4` (record call routing at lowering so a Fun-typed name-shadow
call no longer diverges).

**Channel:** this advisory; cross-referenced from the `1.32.0` `CHANGELOG.md`
entry.

## Why this is a security fix, not a breaking change

Capa promises byte-identical output on the Python interpreter and the Wasm
backend, and information-flow control over `@secret` data; a name-shadow that made
the two backends disagree, silently disclosing a secret on one of them, violated
both. The prior behaviour was a soundness / codegen bug, so the analyzer
rejections and the codegen corrections fall under the `STABILITY.md` security
exception. The analyzer changes reject only programs that already compiled to
divergent behaviour, and the codegen changes correct only programs that were
already mis-compiled; a byte-identical, non-diverging shadow stays legal. It
ships as a **MINOR** bump.

## Details

Capa's scoping model is "function scope, no block shadowing" on the Python
transpiler, but the Wasm lowerer keeps a lexical / closure capture. A binding
whose name shadowed a different binding therefore resolved to different values on
the two backends. Four faces, split by what the name binds to:

1. **A lambda-body bind that shadows an enclosing parameter or local** always
   diverges: the Wasm environment captures the enclosing value even when it is
   never read, so a captured `@secret` was printed on Wasm while Python crashed or
   bound a different value.
2. **A plain function (or a lambda) that both shadows a module-level const /
   function AND reads that symbol.** Python's function scope makes the name a
   function-local for the whole body, so the genuine read binds to the (possibly
   unassigned or block-local) shadow, while Wasm keeps the module global. For a
   `@secret` const this silently disclosed the secret on Wasm while Python crashed.
3. **A lambda-body bind of a name equal to a module const, read textually AFTER
   the lambda.** The stale local left in the lowerer's `_locals` map made
   `_lower_ident` emit a local read instead of the module global, so Wasm returned
   empty / 0 / a wrong value while Python returned the const.
4. **A Fun-typed name-shadow that the enclosing function then CALLS.** Python
   direct-called the module function; Wasm re-routed the call to a closure-call on
   the dead lambda local. The minimal repro printed the secret on Python and the
   public value on Wasm, or produced a validation failure / wrong value.

Each face was `--check`-clean, so the divergence was silent.

## The fix

**Analyzer (reject the diverging programs).**

- `4b9c9e6` marks a lambda body's root with `is_lambda_root`
  (`capa/analyzer/__init__.py:265`) and rejects, in the ident-pattern binder, the
  struct-shorthand binder, and the var binder, a binding that resolves through the
  enclosing scope chain past that lambda root to a shadow the two backends compile
  differently (`_enclosing_scope_local`, `capa/analyzer/_patterns.py:308`). An
  enclosing parameter or local is a blanket reject; a module const / function is
  rejected only when read outward (a self-read in the initializer, or a read
  before the shadowing bind in a closure body).
- `887f0c3` closes the plain-function face with a whole-function post-pass,
  `_check_module_shadow_divergence` (`capa/analyzer/_items.py:535`): after the body
  is analysed and every read is resolved, it rejects the function once per module
  const / function that is both name-shadowed (`_collect_plain_shadow_binds`,
  `capa/analyzer/_items.py:588`, enumerating every pattern-bound name) and read by
  an identifier resolving to it. Resolution-based reads exclude a same-named
  match-arm bind, `for` variable, nested-block `let`, or nested-lambda parameter,
  so a byte-identical program is not over-rejected. It also fires across a module
  boundary.

**Codegen (correct the divergence that stays legal).**

- `0e306b5` adds a per-function `_live_locals` set to the lowerer
  (`capa/ir/_lower.py:88`), snapshotted and restored across a lambda body the same
  way `_params` is, so a lambda's own binds drop out of the enclosing resolution
  while `_locals` keeps their types for the closure emitter. `_bind_local`
  (`capa/ir/_lower.py:417`) records into it and `_lower_ident` gates the local
  branch on it.
- `3673fd4` moves the direct-vs-closure call decision from the emitter to
  lowering: a new `Call.route` field (`capa/ir/_nodes.py`, documented at line 118)
  is set by `_classify_call_route` (`capa/ir/_lower_expr.py:660`) and honoured by
  the Wasm `_emit_user_call` (`capa/ir/_emit_wasm/__init__.py:2259`), so a
  shadowed call routes to the same target on both backends.

## Scope and known residuals

An ordinary shadow that neither self-reads nor reads a module global before the
shadowing bind stays legal and byte-identical (a genuine local shadow). Two
disclosed-open codegen gaps remain (pinned as known-open): a struct-module-const
Wasm global read, and a module const whose value is a `Fun` (which fails loud with
"unknown func" identically on both backends, a separate documented gap).

## Remediation

**Upgrade to `1.32.0`.** On affected versions the divergence was silent at
`--check`, so no analyzer configuration would have surfaced it; the only reliable
signal was diffing the two backends' runtime output. After upgrading, the
diverging shadows are rejected at compile time and the legal shadows compile
byte-identically.

## Verification

Pinned in the shadow-scoping test suite: `4b9c9e6` / `887f0c3` flip the six
divergent `TestSecretConstShadowScoping` fixtures to assert the rejection
tier-independently while keeping the genuine-local-shadow negatives legal, and the
codegen commits add byte-identity pins across the legacy-Python, CIR-Python, and
Wasm backends for the closed variants plus known-open pins for the two remaining
gaps.

## Credit

Found and fixed during the internal hardening pass following the `1.31.0`
release, from the disclosed name-shadow backlog residual.
