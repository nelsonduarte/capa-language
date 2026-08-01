# Stability policy

Capa ships as `1.25.1` (released 2026-08-01). The
**stability commitment described below is now in effect**: the
surfaces listed are covered by SemVer from this release on. The
commitment is the only thing that changed at 1.0; the language
itself did not jump features when the version flipped.

## Stable surfaces (after 1.0)

The following surfaces follow [SemVer 2.0.0](https://semver.org/):
breaking changes require a **major** version bump; additions
ship as **minor**; bug fixes ship as **patch**.

| Surface | Source of truth |
|---------|-----------------|
| Language grammar | [`docs/reference.md`](docs/reference.md), [`Capa-EBNF.md`](Capa-EBNF.md) |
| Standard library types and methods | [`docs/stdlib.md`](docs/stdlib.md) |
| Built-in capability surface (`Fs`, `Net`, `Env`, `Clock`, `Random`, `Stdio`, `Proc`, `Db`, `Serve`, `Unsafe`) | [`docs/stdlib.md`](docs/stdlib.md) |
| Public CLI subcommands and flags | [`README.md`](README.md), `--help` output |
| Capability manifest JSON schema | [`capa-language.com/manifest.html`](https://capa-language.com/manifest.html) |
| CycloneDX / SPDX / VEX / SLSA emitted schemas | the respective external specs the compiler conforms to |
| Package-manager manifest format (`capa.toml`) and lockfile (`capa.lock`) | [`docs/packages.md`](docs/packages.md) |
| Numbered diagnostic codes (planned, see Roadmap below) | `docs/diagnostics.md` (planned, not yet added) |
| Module loader resolution order | [`docs/packages.md`](docs/packages.md) |
| Programmatic Python API: `Lexer`, `Parser`, `analyze`, `transpile` re-exported from `capa` | [`docs/reference.md`](docs/reference.md) |

Anything in a frozen surface above can be **added to** without a
major bump (new methods on stdlib types, new CLI flags, new
optional manifest fields, new variants on payload-bearing sum
types behind `_` arms). It cannot be removed, renamed, or have
its type narrowed without a major bump.

## Explicitly unstable

The following are not covered by the stability commitment.
They can change at any time without a major bump:

- **Diagnostic message wording**. "Did you mean ..." hints,
  the exact phrasing of an error, and the formatting of error
  output. Numbered codes (when added) are stable; the prose is
  not.
- **The transpiled Python output**. `capa --transpile` is a
  development affordance, not a contract. Future versions may
  emit different (faster, smaller, less readable) Python for
  the same Capa input.
- **Internal Python modules** under `capa/`. Anything not
  re-exported from `capa.__init__` is implementation detail.
  Tests, the LSP server, hooks, and tools that reach into
  `capa.analyzer`, `capa.transpiler`, `capa.runtime._*`, etc.
  may break across minor releases.
- **Performance characteristics**. The benchmarks suite tracks
  trends, not guarantees. Improvements are welcome and not a
  breaking change; regressions are bugs but not API breakages.
- **Pre-1.0 versions (historical)**. The `0.x` line
  (`0.2.0-alpha` through `0.8.4-beta`) predated the commitment
  and made no compatibility promise across versions. It is
  closed; the commitment took effect at `1.0.0`.
- **`1.0.0-rc.N` candidates (historical)**. The release
  candidates `rc.0` through `rc.7` (2026-05-19 to 2026-06-03)
  were published to gather feedback on the proposed frozen
  surface; the commitment started when the rc cycle produced
  `1.0.0` on 2026-06-03.
- **The LSP wire format**. LSP is itself a versioned
  protocol; we follow the spec, but if the spec evolves, we
  evolve with it.

## What counts as breaking

A change is **breaking** (requires a major bump) when it:

- Removes or renames a name in a stable surface.
- Changes the type of a stable function or method
  (parameter type, return type, arity).
- Adds a required parameter to a stable function or method.
- Tightens runtime validation so an input that previously
  succeeded now produces `Err`, and the previous success was
  documented behaviour. (If the previous success was a
  security vulnerability, see the security exception below.)
- Changes the static analysis so a program that previously
  compiled now produces an error, *unless* the previous
  acceptance was a documented bug.
- Changes the JSON schema of a manifest or SBOM output
  emitted by `capa --manifest`, `capa --cyclonedx`,
  `capa --spdx`, `capa --vex`, or `capa --provenance` in a way
  a downstream consumer would notice.

## What counts as additive

A change is **additive** (minor bump) when it:

- Adds a new keyword, operator, or syntax form that does not
  collide with valid programs in earlier 1.x versions.
- Adds new methods to stdlib types, new CLI subcommands /
  flags, new optional manifest fields.
- Adds new built-in capabilities, *if* they do not require
  changes to existing `main` signatures.
- Adds new variants to payload-bearing sum types that already
  carry a wildcard arm in idiomatic use.

If introducing a new keyword would break an existing valid
program (because the program uses the new word as an
identifier), the keyword must go through a deprecation cycle:
announce in `N`, optional-warning in `N+1`, take effect in
`N+2`. See "Deprecation" below.

## What counts as patch

A change is a **patch** (patch bump) when it:

- Fixes a bug so the actual behaviour matches the documented
  behaviour.
- Improves a diagnostic message.
- Improves performance.
- Refactors internals without changing the observable surface.
- Updates documentation, examples, or tests.

## Deprecation

To remove or change a stable surface element, ship it through
the following window:

1. Announce in the release notes of version `X.Y`, mark the
   element with a deprecation note in its docs.
2. In version `X.(Y+1)` or later, the compiler emits a
   warning when the deprecated element is used. The warning
   is suppressible with a future `--allow-deprecated` flag.
3. The actual removal lands no earlier than `(X+1).0`, the
   next major.

This gives users at least one minor release with a warning
before any breakage hits.

## Security exception

A security fix may change observable behaviour without a major
bump when the previous behaviour was itself a vulnerability,
even if it was documented. The fix ships with a security
advisory through the channel described in
[`SECURITY.md`](SECURITY.md). The advisory states explicitly
what changed and why the change is not subject to the major-
bump rule.

This is the same exception virtually every language follows
(Rust's "soundness fix" carve-out, Python's CVE flow, ...).
It exists to keep "we found a way to bypass the capability
discipline" from being held up by SemVer.

## Roadmap

`1.0.0` shipped on 2026-06-03 (after the `rc.0`..`rc.7` cycle)
and the commitment above has been in effect ever since; the
language is now at `1.25.1`. Remaining work ships as
**additive** changes under the SemVer rules above: new minor or
patch releases that extend the frozen surfaces rather than
break them. The current short list:

- **Numbered diagnostic codes**. Today's diagnostics are
  message-only; a future `Cxxxx` code per category would let
  tooling refer to them stably, with a new `docs/diagnostics.md`
  as the index. Additive: the codes would sit alongside the
  existing (unstable) message prose, so they change no frozen
  surface.
- **Additional stdlib helpers** as gaps surface from real
  downstream programs. Each new method is a minor bump.

Considered and explicitly deferred:

- **Block-form `if`-as-expression**. Only the ternary form
  (`if cond then a else b`) is an expression today; block-form
  `if` is a statement. The workaround is
  `let x = match cond { true -> ..., false -> ... }` (or its
  multi-line variant), which the block-as-expression match-arm
  rule already supports. The workaround is clean enough that
  elevating block-form `if` to an expression does not justify
  the parser + analyzer surgery. If it ever lands, it is a new
  syntax form that does not collide with valid `1.x` programs,
  so it ships as a minor.

There is no committed date for any of this. Additions land when
they are ready and carry their SemVer weight (minor for new
surface, patch for fixes); nothing on this list requires a
breaking change.

## Reporting compatibility regressions

If you find a documented program that worked on a previous
`1.x` release and breaks on a later minor or patch release:

- File an issue with a minimal reproducer.
- We treat it as a regression; the fix should land in the next
  patch, unless the original behaviour was itself a bug being
  fixed (see the security exception above).

This applies from `1.0.0` on. The historical `0.x` line
(closed at `1.0.0`) carried no such promise.

## Related documents

- [`SECURITY.md`](SECURITY.md) - vulnerability reporting
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - contribution flow
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) - community
  norms
- [`docs/reference.md`](docs/reference.md) - language reference
- [`docs/packages.md`](docs/packages.md) - package manager
