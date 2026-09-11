# Capa technical specification: index

This folder is the CANONICAL technical specification of the Capa
language, its reference compiler, the two backends and the
supply-chain artefacts. A Portuguese-language specification set, from
which this one was derived, is maintained outside the repository as a
translation; where the two differ, this set governs.

## Conventions of the set

- **Scope.** The specification describes what is implemented and
  working in the compiler at the pinned commit. Statements of the
  SCOPE of a guarantee (what a check covers, which tier it runs at,
  where an analysis stops) are part of a feature's definition and are
  kept, at the level published in
  [`docs/trust-model.md`](../docs/trust-model.md) and the advisories
  under [`docs/advisories/`](../docs/advisories/).
- **Version.** The whole set is measured at `main` commit `8e2c609`
  (`capa 1.32.0` plus unreleased commits), on 2026-09-10/11. Each
  chapter's header repeats the pin.
- **Verification.** Every behavioural claim is traceable to something
  READ (`file:line`, test name, advisory) or EXECUTED (command plus
  pasted output). Transcripts are real runs at the pinned commit;
  programs with runtime behaviour were run on both backends (`--run`
  and `--run --wasm`, plus `--run --ir` where stated) and the
  agreement is recorded. Where a claim rests on a named test rather
  than a fresh run, the chapter says so. Toolchain of the
  measurements: `wasm-tools 1.249.0`, wasmtime-py 46.0.1, one Windows
  machine.
- **Warn versus error.** The set never writes "cannot" for a
  warn-tier check. The IFC default tier warns; `@strict_ifc` and
  `@constant_time` are hard errors; the distinction is preserved
  everywhere.
- **`docs/` versus `specs/`.** [`../docs/`](../docs/reference.md) is
  the user-facing reference; this folder is the design record and
  internals. Chapters cross-link to `docs/` instead of duplicating
  it.

## The chapters

### A. Overview and model

| # | File | Subject |
|---|---|---|
| 01 | [01-overview.md](01-overview.md) | What Capa is; the thesis; the two backends; where the guarantees hold |
| 02 | [02-authority-in-types.md](02-authority-in-types.md) | The model: object-capabilities, POLA, confused deputy, attenuation, the manifest idea |

### B. The language

| # | File | Subject |
|---|---|---|
| 03 | [03-lexis-and-layout.md](03-lexis-and-layout.md) | Tokens, keywords, literals, indentation |
| 04 | [04-grammar.md](04-grammar.md) | The EBNF summary, anchored in the parser and `Capa-EBNF.md` |
| 05 | [05-base-and-composite-types.md](05-base-and-composite-types.md) | Scalars, structs, sums, tuples, Option/Result, containers, equality |
| 06 | [06-generics-and-traits.md](06-generics-and-traits.md) | Type parameters, traits, impl, monomorphisation |
| 07 | [07-pattern-matching.md](07-pattern-matching.md) | `match`, patterns, exhaustiveness, destructuring and its type check |
| 08 | [08-functions-closures-modules.md](08-functions-closures-modules.md) | Functions, the seven attributes, `consume`/`borrow`, closures, modules |
| 09 | [09-expressions-and-control.md](09-expressions-and-control.md) | Precedence, control flow, `?`, operator semantics |

### C. Capabilities

| # | File | Subject |
|---|---|---|
| 10 | [10-capability-model.md](10-capability-model.md) | How authority enters and propagates; no ambient authority |
| 11 | [11-builtin-capabilities.md](11-builtin-capabilities.md) | The exact ten, their methods, Python-only members |
| 12 | [12-attenuation.md](12-attenuation.md) | `restrict_to` and kin; monotonicity; runtime enforcement |
| 13 | [13-user-defined-capabilities.md](13-user-defined-capabilities.md) | `capability`, the implementor pattern, the cap-bearing relaxation |

### D. Linearity and information flow

| # | File | Subject |
|---|---|---|
| 14 | [14-linearity-consume-typestates.md](14-linearity-consume-typestates.md) | `consume`, `linear type`, carriers, typestates, the place resolver |
| 15 | [15-ifc-model-and-labels.md](15-ifc-model-and-labels.md) | The two-point lattice, sources, sinks, `declassify` |
| 16 | [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md) | Warn versus `@strict_ifc`, cross-function summaries, `@constant_time`, the guarantee-scope register |

### E. The compiler and the backends

| # | File | Subject |
|---|---|---|
| 18 | [18-compiler-pipeline.md](18-compiler-pipeline.md) | Lexer -> parser -> analyzer -> (legacy \| CIR) -> emitters |
| 21 | [21-python-backend.md](21-python-backend.md) | The Python transpiler and the runtime materialization of capabilities |
| 22 | [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md) | The Wasm emitter, WIT, encodings, the `capa-manifest` section, the hosts |
| 23 | [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md) | The `--wasi` mode, ceilings, preopens, `--allow-host`, foreign limits |
| 24 | [24-backend-parity.md](24-backend-parity.md) | The byte-identical promise, its measured corpus and its exact scope |

### F. CLI and supply chain

| # | File | Subject |
|---|---|---|
| 25 | [25-cli-commands-and-flags.md](25-cli-commands-and-flags.md) | Every flag and subcommand |
| 29 | [29-capability-manifest.md](29-capability-manifest.md) | `--manifest`, the canonical envelope, composition, diff, policies |
| 30 | [30-sbom-cyclonedx-spdx.md](30-sbom-cyclonedx-spdx.md) | The CycloneDX and SPDX wrappers and the purl rule |

## Numbering

Chapter numbers follow the source set's organization; numbers absent
from this folder are unassigned. The formal proofs are referenced
where they bear (chapters 02, 10, 12, 15, 16, 29) through
[`proofs/README.md`](../proofs/README.md), which states precisely
what is mechanized (in Agda, under `--safe`) and what is not.
