# Positioning: what is and is not unique about Capa

A note for reviewers, prospective contributors, and anyone preparing
to publish work that depends on Capa. The honest case for the
language, with the marketing turned off.

## TL;DR

The novelty of Capa is **not** the SBOM ↔ policy audit. That is a
JSON-diff in any language. The novelty is **the epistemic basis of
the SBOM's capability claims**: in Capa they are derived from the
type system at compile time, by construction, and the compiler
rejects programs that would let those claims be wrong. The audit
pipeline is the visible payoff of that property.

## The trivial part

Given a CycloneDX SBOM whose components carry per-function
capability declarations and a JSON policy that says which functions
are allowed which capabilities, comparing the two sets is a
five-line operation in every general-purpose programming language.
Python in 30 lines; Go in 50; Rust in 100. The audit demo at
`examples/sbom_capability_audit.capa` is short for the same reason.

If the contribution were the audit itself, no new language would be
warranted.

## What is genuinely hard, today

The hard part is making the SBOM's capability claims *true*. In
existing ecosystems, the source of those claims is one of:

1. **Author-authored manifest** (npm `permissions`, Deno's
   `--allow-*` flags, Android's `AndroidManifest.xml`). The author
   declares by hand. The runtime enforces. The static side relies
   on trust that the author was honest and complete; humans are
   neither.

2. **Heuristic static analysis** (Slither for Solidity, Joern and
   CodeQL for C / Java / Python, Semgrep, security scanners). A
   post-hoc taint analysis approximates the capability surface from
   the source. Output is incomplete (false negatives on indirect
   call patterns the analyser does not model) and noisy (false
   positives on patterns it conservatively flags). Adversarial code
   can hide deliberately.

3. **Runtime sandbox observation** (seccomp filters, Linux audit
   subsystem, Deno permission prompts, eBPF tracing). Records what
   the program *did* during a run. Cannot describe what the program
   *can do* on a code path that was not exercised. A reviewer has
   to read the absence of an entry as either "this code never
   touches X" or "this code did not touch X during this test", and
   the two are indistinguishable from the log alone.

None of these supports the property an auditor wants: *the SBOM
declares everything this program could touch, and the compiler
rejected the program if the declaration was less than that.* That
is the contract Capa is built around.

## Other languages with related approaches

The capability-typing idea is not new and not unique to Capa. Honest
adjacencies:

- **Pony** has reference capabilities (`iso`, `trn`, `ref`, `val`,
  `box`, `tag`) attached to types. Pony's discipline is about
  aliasing and data-race freedom in a concurrent actor model, not
  about who is authorised to perform external IO. Different problem,
  same intellectual family.

- **Koka** and **Eff** (and OCaml 5's effect handlers) provide
  effect systems. Effects can stand in for capabilities in
  principle: a function whose effect row includes `<net>` is the
  same shape as a function that takes a `Net` parameter. The
  ecosystem around these languages is research-grade; there is no
  SBOM tooling story today.

- **Haskell** can simulate capabilities with phantom types and the
  `ReaderT`-of-capability-record pattern. `RankNTypes` plus
  `IORef`-style tokens give you a soundness property close to
  Capa's, but it is a library convention, not a language guarantee.
  A new contributor to a Haskell codebase can bypass it by
  importing `IO` directly.

- **Roc** (Richard Feldman) ships capabilities by platform: the
  platform provides effectful primitives, the program receives them
  as values. Closest in spirit to Capa among production-aimed new
  languages. Still pre-1.0; the SBOM story is not there yet.

- **WebAssembly Component Model + WIT** is the most credible
  *production* contender. Each component declares its imports in a
  WIT interface; those imports are effectively the component's
  capability surface. Deriving a capability SBOM from a `.wit`
  file is mechanical. **The key difference**: Wasm-CM operates at
  the **module** boundary, not at the **function** boundary. A
  reviewer looking at a Wasm-CM SBOM learns *which modules can
  touch the network*; they do not learn *which functions inside
  those modules can*. For CRA-style audit work, the function-level
  granularity is what matters.

## What Capa can claim

- **By-construction soundness**: the type checker enforces that
  every external capability use is reachable only through a
  capability parameter in the function's signature. There is no
  back-door (ambient state, global IO, hidden import). The
  underlying property is stated formally in
  [`docs/semantics.md`](semantics.md) as the *Capability
  Soundness* theorem over the *λ_cap* calculus; the proof
  sketch is in section 6 of that document.
- **Function-level SBOM granularity**: each function in
  `--cyclonedx` carries its own `capa:declared_capability` list,
  not an aggregate over a module.
- **Mechanical SBOM ↔ source correspondence**: an auditor can
  verify, deterministically, that the SBOM was produced from the
  source by running `capa --cyclonedx` themselves. No additional
  analyser, no calibration, no false positives.
- **Diff-comparable SBOMs across releases**: the SBOM diff tool
  ([`examples/sbom_diff.capa`](../examples/sbom_diff.capa))
  reports per-function capability widenings and narrowings
  between two SBOMs. Because granularity is per-function, the
  diff catches authority changes that PURL-level SBOM diffs
  cannot see (a dependency widening internally without bumping
  its version).

## What Capa cannot claim

- **Novel theoretical mechanism**: capability typing as an idea
  predates Capa by decades. The mechanism is well understood.
- **Production readiness**: Capa is pre-1.0 alpha; the runtime
  performance is Python's; there is no native backend yet.
- **Language ecosystem maturity**: Capa has a CLI, an LSP, a
  formatter, an SBOM emitter, an SBOM diff tool, a runtime-
  overhead benchmark suite, a CRA article-by-article mapping,
  six CVE case studies, an empirical SBOM-diff
  micro-validation, and a small standard library. It does not
  have a package manager, a debugger story beyond Python's,
  third-party libraries, or industrial adopters.
- **A monopoly on the auditable supply chain pitch**: WebAssembly
  Component Model is genuinely competing for the same role at the
  module granularity, and it has a much larger ecosystem.

## The one-sentence thesis claim

> The contribution of Capa is not the audit but the closure of the
> *type → SBOM → audit* pipeline by construction: each step is
> machine-verifiable, the SBOM granularity is per-function, and the
> compiler rejects any program whose SBOM would be smaller than its
> actual capability footprint.

If a reviewer challenges Capa with "you could do the audit in
Python", the right reply is "you could, but the SBOM you would be
auditing would not have the property that justifies the audit".
