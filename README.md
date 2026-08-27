<p align="left">
  <img src="https://raw.githubusercontent.com/nelsonduarte/capa-language/main/capa_logo.svg" alt="Capa logo" height="80">
</p>

# Capa

[![tests](https://github.com/nelsonduarte/capa-language/actions/workflows/tests.yml/badge.svg)](https://github.com/nelsonduarte/capa-language/actions/workflows/tests.yml)
[![release](https://img.shields.io/github/v/release/nelsonduarte/capa-language?include_prereleases&label=release&color=blue)](https://github.com/nelsonduarte/capa-language/releases)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/nelsonduarte/capa-language/blob/main/LICENSE)
[![python: >=3.10](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)](https://github.com/nelsonduarte/capa-language/blob/main/pyproject.toml)
[![SLSA Level 1](https://slsa.dev/images/gh-badge-level1.svg)](https://slsa.dev/spec/v1.0/levels#build-l1)
[![Discussions](https://img.shields.io/github/discussions/nelsonduarte/capa-language?logo=github&color=blueviolet)](https://github.com/nelsonduarte/capa-language/discussions)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](https://github.com/nelsonduarte/capa-language/blob/main/CONTRIBUTING.md)

**Website: <https://capa-language.com/>**

**Machine-verifiable supply-chain SBOMs by construction.**

Capa is a small, capability-typed programming language. Every
function declares the authorities it holds (`Fs`, `Net`, `Stdio`,
`Clock`, `Random`, `Env`, `Db`, `Proc`, `Serve`, `Unsafe`), the analyzer
enforces those declarations statically, and the compiler emits
**CycloneDX SBOM**, **SPDX 2.3**, **VEX**, and **SLSA Build L1
provenance** documents directly from the same capability signatures.
You get supply-chain artefacts that match the code, not a separate
scanner approximating them after the fact.

The toolchain is a complete Python 3.10+ implementation: lexer,
parser, semantic analyzer, transpiler to Python, runtime, language
server, formatter, documentation generator, and a **WebAssembly
Component Model backend** (`capa --wasm`) that compiles the same
source to a `.wasm` component with a WIT spec per capability, runnable
on any Component-Model-aware runtime or inline through the bundled
wasmtime host. Top-level functions tagged `@export()` are lifted into
that component's WIT world alongside `main`, callable directly from a
Component-Model host; this covers scalar (`Int`/`Float`/`Bool`/`Unit`)
signatures today, with `String` and composite types across the
boundary still deferred.

```bash
$ capa --run examples/grades.capa
=== Roster ===
  Ana: 17.5 (Excellent)
  Bruno: 13.0 (Pass)
  Carla: 8.5 (Fail)
  Diogo: 15.5 (Good)
  Eva: 11.0 (Pass)
  Filipe: 19.0 (Excellent)

Statistics:
  Average: 14.083333333333334
  Minimum: 8.5
  Maximum: 19.0
  Passed:  5
  Failed:  1
```

## The 30-second story

A pure helper declares no capabilities; the analyzer enforces it.

```capa
fun classify(score: Float) -> String
    if score >= 9.5
        return "Excellent"
    if score >= 8.0
        return "Good"
    if score >= 6.5
        return "Pass"
    return "Fail"
```

A function that prints needs `Stdio`; a function that reads files
needs `Fs`. The signature is the contract:

```capa
fun summarise(stdio: Stdio, fs: Fs, path: String) -> Result<Unit, IoError>
    let body = fs.read(path)?
    match body.split("\n").get(0)
        Some(first) -> stdio.println("first line: ${first}")
        None -> stdio.println("empty file")
    return Ok(())
```

`capa --manifest <file>` emits the same information as JSON. The
auditor reading the manifest sees exactly which functions can
write to disk, talk to the network, or read the clock. There is
no "hidden Stdio": the compiler refuses to compile a `classify`
that suddenly calls `stdio.println(...)` because `classify` does
not take `stdio: Stdio`.

Capabilities can also be **attenuated**: `fs.restrict_to("data/")`
returns a fresh `Fs` whose authority is narrowed to that prefix,
and the narrowing is monotonic by construction.

Capabilities control *which* effects a function may exercise;
**information-flow control** constrains *where* data may flow. Mark
data `@secret` and the analyzer tracks it to every public sink (a log
line, a network call, a file write): by default reaching a sink is a
**warning** that names the exact flow, and a function annotated
`@strict_ifc()` turns that warning into a hard **error**. Either way
the one audited escape hatch is `declassify`:

```capa
fun leak(env: Env, stdio: Stdio)
    match env.get("API_KEY")              // env.get is @secret by default
        Some(key) -> stdio.println(key)   // analyzer flags this: @secret to a public sink
        None -> stdio.println("no key")
```

`declassify(value, reason: "...")` is the single auditable
secret-to-public bridge, and every use is recorded in the SBOM as
`declassification_sites`, so the manifest says exactly where, and why,
a program discloses sensitive data. The
[tour](https://capa-language.com/tour.html) walks through the
rest of the feature set.

## Install

```bash
# Linux / macOS Apple Silicon (one-liner)
curl -fsSL https://raw.githubusercontent.com/nelsonduarte/capa-language/main/deploy/install.sh | bash
```

```powershell
# Windows
irm https://raw.githubusercontent.com/nelsonduarte/capa-language/main/deploy/install.ps1 | iex
```

```bash
# From source (any platform with Python 3.10+)
git clone https://github.com/nelsonduarte/capa-language
cd capa-language && pip install -e .
```

After install, `capa --version` should work from any directory.
For the manual binary download, language-server setup, and the
VSCode extension, see [`docs/getting-started.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/getting-started.md).

## CLI

```bash
capa --run                  file.capa   # transpile + execute via Python
capa --check                file.capa   # lex + parse + semantic check
capa --transpile            file.capa   # emit Python to stdout
capa --ir --run             file.capa   # run via the CIR middle-end
                                        # (AST->CIR->Python); falls back
                                        # to the legacy transpiler for
                                        # constructs CIR does not cover
capa --wasm --run           file.capa   # compile + run on wasmtime
capa --wasm --component --run    file.capa
                                        # wrap as a Component Model
                                        # artifact + run via
                                        # wasmtime.component
capa --wasm --component --output app.wasm  file.capa
                                        # write a standalone .wasm
                                        # component (WIT embedded)
capa --wit                  file.capa   # emit the WIT spec to stdout
capa --manifest             file.capa   # JSON capability manifest
capa --cyclonedx            file.capa   # CycloneDX 1.6 SBOM (caps embedded)
capa --spdx                 file.capa   # SPDX 2.3 (caps embedded)
capa --vex                  file.capa   # standalone VEX document
capa --provenance           file.capa   # in-toto + SLSA Provenance v1.0
capa --doc                  file.capa   # HTML doc page from /// comments
capa --fmt                  file.capa   # canonical-style rewrite
capa init                   my-project  # project scaffold
capa install                            # fetch capa.toml dependencies
capa test                               # run tests/test_*.capa; exit 0 = pass
                                        # (--wasm: Wasm backend; --both: run on
                                        # both backends AND diff their stdout,
                                        # divergence fails; see docs/testing.md)
capa migrate                file.capa   # Python->Capa hardening progress
                                        # (--json for the machine form;
                                        # see docs/migration.md)
capa lsp                                # language server (stdio)
```

Arguments after `--` are forwarded to the program (visible via
`env.args()`):

```bash
capa --run myprog.capa -- input.json --verbose
```

## Real programs written in Capa

These live in standalone repositories, each around 500-1500 lines
of Capa. Dependencies on the seed libraries are declared in a
`capa.toml` and fetched by `capa install`; every demo's `README`
walks through the audit manifest.

| Repo | What it does | What it stresses |
|------|--------------|------------------|
| [audit-trail-reporter](https://github.com/nelsonduarte/audit-trail-reporter) | Reads a JSONL financial transaction log, runs four AML rules (threshold, watchlist, structuring, velocity), emits CSV + JSON + alerts | Multi-module project; capability attenuation (read `Fs` for `data/`, write `Fs` for output); every rule provably pure |
| [sbom-watch](https://github.com/nelsonduarte/sbom-watch) | Reads a CycloneDX SBOM + an OSV-style CVE DB + a policy file, emits a risk report. CI-friendly exit code | Cross-source matching shape. Consumes exactly what `capa --cyclonedx` produces |
| [policy-eval](https://github.com/nelsonduarte/policy-eval) | Evaluates a JSON-encoded policy AST (with recursive `all_of`/`any_of`/`not`) against a subject document | Tree-walk interpreter shape; exercises recursive sum types |

Each demo's `--manifest` is a good way to see what the capability
discipline catches in practice: the rule functions and the
renderers declare no capabilities; only parsers and writers
ever see `Fs`.

All three also run end-to-end under the Wasm backend with output
bit-identical to the Python reference path, in both modes:
`capa --wasm --run` (core wasm on wasmtime) and `capa --wasm
--component --run` (Component Model artifact instantiated via
`wasmtime.component`, no host-side memory bridges). The JSON
parser is bundled into the guest module so no `capa:host/json`
import is needed at the Component Model boundary.

## Standard library + seed libraries

The runtime ships built-in types (`Result`, `Option`, `List`,
`Map`, `Set`, `JsonValue`) and ten built-in capabilities (`Stdio`,
`Fs`, `Net`, `Env`, `Clock`, `Random`, `Db`, `Proc`, `Serve`,
`Unsafe`). `Serve` (inbound TCP) and `Unsafe` are Python-backend
only; `capa --wasm` rejects a program whose signatures reach either.
Full reference in [`docs/stdlib.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/stdlib.md).

Eight **seed libraries** live in standalone repos and are
consumed via the package manager:

| Library | Repo | Surface |
|---------|------|---------|
| `capa_cli` | [nelsonduarte/capa_cli](https://github.com/nelsonduarte/capa_cli) | argument parser: positionals, flags, options, `--help` |
| `capa_csv` | [nelsonduarte/capa_csv](https://github.com/nelsonduarte/capa_csv) | RFC 4180 CSV parser, header view, and writer; zero-capability |
| `capa_datetime` | [nelsonduarte/capa_datetime](https://github.com/nelsonduarte/capa_datetime) | ISO 8601 parsing + Y/M/D/h/m/s arithmetic, zero-capability |
| `capa_hash` | [nelsonduarte/capa_hash](https://github.com/nelsonduarte/capa_hash) | SHA-256/SHA-224/HMAC-SHA256, zero-capability, with constant-time tag comparison |
| `capa_http` | [nelsonduarte/capa_http](https://github.com/nelsonduarte/capa_http) | capability-typed HTTP client over `urllib`; caller sees `Http`, never `Unsafe` |
| `capa_log` | [nelsonduarte/capa_log](https://github.com/nelsonduarte/capa_log) | levelled logging (`DEBUG`/`INFO`/`WARN`/`ERROR`) via a `Logger` capability over `Stdio` |
| `capa_sbom` | [nelsonduarte/capa_sbom](https://github.com/nelsonduarte/capa_sbom) | CycloneDX + SPDX JSON parsing with `capa:*` capability queries; zero-capability |
| `capa_test` | [nelsonduarte/capa_test](https://github.com/nelsonduarte/capa_test) | tiny assertion library for the `capa test` runner; `Stdio`-only |

To use any of them in a project:

```toml
# capa.toml
[package]
name = "my-project"
version = "0.1.0"

[dependencies]
# For production: pin to an immutable commit SHA. Tags are
# convenient but mutable upstream (a force-push moves them);
# rev = "<sha>" is what audit-grade builds want.
capa_log = { git = "https://github.com/nelsonduarte/capa_log", rev = "<commit-sha>" }

# For development the friendlier tag form works too; ``capa install``
# records the resolved SHA in capa.lock and *refuses* on subsequent
# runs when the upstream tag has been re-pointed at a different
# commit. Pass ``--update`` to accept a new SHA deliberately.
# capa_log = { git = "https://github.com/nelsonduarte/capa_log", tag = "v0.1" }

# For audit-grade builds: add the publisher's GPG fingerprint and
# ``capa install`` runs ``git verify-tag`` against your keyring,
# refusing to install unless the signature matches. Defends against
# account compromise + tag tampering even when the lockfile is empty.
[dependencies.capa_log]
git = "https://github.com/nelsonduarte/capa_log"
tag = "v0.1"
verify_key = "1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678"

# Test/tooling-only deps go under [dev-dependencies]: same schema,
# same validation, installed only when THIS project is the install
# root. Consumers of your package never fetch them. Declare from
# the CLI with `capa add --dev <name> ...`.
[dev-dependencies]
capa_testkit = { git = "https://github.com/user/capa_testkit", tag = "v0.2" }
```

Then `capa install` materialises the deps under `./vendor/` and
the loader picks them up automatically. See
[`docs/packages.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/packages.md) for the manifest schema,
lockfile semantics, and resolution order.

## Project layout (sketch)

```
capa/                 # Python package: compiler + runtime + pkg manager
  lexer/  parser/  analyzer/  transpiler/  runtime/
  ir/                 # CIR + Python and Wasm Component Model backends + WIT emitter
  manifest/  docgen/  lsp/    pkg/    cli/
tests/                # 5,600+ unit, end-to-end, and property tests
examples/             # .capa programs (basics, CVE case studies, LLM sandbox)
# (seed libraries now all live in standalone repos; see Standard library section)
docs/                 # public website (HTML) + design writeups (.md)
proofs/               # mechanised soundness theorems for lambda_cap (Agda)
benchmarks/           # Capa vs hand-Python micro-benchmarks
Capa-EBNF.md          # formal grammar
pyproject.toml        # package metadata + optional [test] / [lsp] extras
LICENSE  STABILITY.md  CONTRIBUTING.md  SECURITY.md  README.md
```

## Status

Capa ships as **`1.32.0`** (released 2026-08-22), with the full
security axis (information-flow control, constant-time markers, and
typestate protocols) and the fully functional Wasm backend (see
[`CHANGELOG.md`](https://github.com/nelsonduarte/capa-language/blob/main/CHANGELOG.md)). The stability commitment in
[`STABILITY.md`](https://github.com/nelsonduarte/capa-language/blob/main/STABILITY.md) is now **in effect**: post-1.0,
breaking changes to the covered surfaces require a major bump, and
deprecations get one minor release of warning first.

**5,600+ tests** spanning the lexer, parser, analyzer, transpiler,
LSP, formatter, attribute-schema validation, package manager, the
information-flow / constant-time / typestate checkers, the Wasm
backend (with a Python/Wasm output parity harness), and
Hypothesis-based property tests. The transpiler
suite actually executes the generated Python and checks stdout; the
property suite fuzzes the full pipeline with arbitrary text and
syntax-aware Capa programs. The Wasm backend runs every capability it
supports (Fs, Env, Clock, Stdio, Net, Random, Db, Proc, all but the
Python-only Serve and Unsafe, which it rejects loudly) and the full
language surface with output byte-identical to the Python reference, and
cross-function capability attenuation is enforced by host-side handle
tables for a Capa-emitted artifact; the enforcement lives in the
trusted emitter/host, not the runtime boundary, so the executed
artifact is part of the TCB (see
[`docs/design/wasm-cap-handles.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/design/wasm-cap-handles.md)
and [`trust-model.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/trust-model.md)).

Run them:

```bash
pip install -e '.[test]'          # hypothesis + PyYAML: without them,
                                  # whole test modules skip rather than fail
python -m unittest discover tests
```

That is the exact command CI runs, so a green local run means the same
thing as a green CI run. The `[test]` extra also brings pytest, which is
useful as a *selector* over the same suite (`python -m pytest -k
capability`, `-x`, `--lf`) when you are iterating on one area; the
authoritative full run stays `unittest discover`. The suite must be run
with the extra installed either way: it was a missing PyYAML that let
eleven supply-chain tests skip while the run printed OK.

Capa also **dogfoods its own supply-chain posture in its own build**.
The compiler has **zero third-party runtime dependencies** (it is pure
Python standard library), so the published wheel and sdist are
dependency-free and `pip install capa-language` pulls nothing from
third parties; the optional extras in
[`pyproject.toml`](https://github.com/nelsonduarte/capa-language/blob/main/pyproject.toml)
are version floors for dev/CI tooling, never runtime pins. In CI, those
dev/CI dependencies (test, wasm, and LSP tooling) are installed from
universal, hash-pinned lockfiles
([`requirements-test.lock`](https://github.com/nelsonduarte/capa-language/blob/main/requirements-test.lock)
and [`requirements-ci.lock`](https://github.com/nelsonduarte/capa-language/blob/main/requirements-ci.lock),
both `uv`-generated) under `pip install --require-hashes`, so every CI
dependency is verified byte-for-byte against a sha256 and a tampered or
drifted dependency fails the build closed. This is build- and CI-level
reproducibility and tamper-evidence for how Capa is developed, not a
runtime or user-install guarantee (there are no runtime dependencies to
protect). It sits alongside SHA-pinned GitHub Actions, PyPI Trusted
Publishing (OIDC + PEP 740 attestations), and a `pip-audit` CVE gate on
the dev surface.

The Tier 1 supply-chain artefacts are **all shipping** today:

| Artefact | Command | Notes |
|----------|---------|-------|
| Capability manifest | `capa --manifest`     | per-function caps + attributes |
| CycloneDX 1.6 SBOM  | `capa --cyclonedx`    | capability metadata via `properties[]` |
| SPDX 2.3 SBOM       | `capa --spdx`         | capability metadata via `annotations[]` |
| VEX                 | `capa --vex`          | per-function exploitability claims via `@vex(...)` |
| SLSA Build L1       | `capa --provenance`   | in-toto Statement v1 + Provenance v1.0 predicate |
| WIT spec            | `capa --wit`          | one interface per capability the program touches |
| Wasm CM component   | `capa --wasm --component --output app.wasm` | WIT embedded, canonical ABI |

An [**empirical study**](https://capa-language.com/study.html)
backs the capability-aware SBOM claim. Under closed-world semantics
Capa emits **zero false clearances (0/48)**, against CodeQL (10/48,
the strongest real dataflow tool tested), Semgrep (12/48), and a
dependency-level SBOM (48/48). On positive attribution Capa **ties**
CodeQL at 38/48; it does not beat it. The reproducible artefacts live
in [`evaluation/empirical_study/`](https://github.com/nelsonduarte/capa-language/blob/main/evaluation/empirical_study/).

Tier 2 (regulatory mapping) is **complete**:
[`docs/regulatory.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/regulatory.md) covers the EU CRA,
NIS2, DORA (cybersecurity articles), NIST SSDF, and OWASP SCVS
side-by-side; the article-by-article CRA mapping lives in
[`docs/cra.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/cra.md).

What each of these artefacts actually guarantees, separating
fail-closed from best-effort from trusted premise, is consolidated in
the [**trust model**](https://github.com/nelsonduarte/capa-language/blob/main/docs/trust-model.md).

The `lambda_cap` soundness theorems are **mechanised in Agda**,
no `postulate` remaining. Roughly 600 lines of self-contained
Agda (no `agda-stdlib` dependency) cover Progress, Preservation,
Capability Soundness, and a multi-step Manifest Completeness
theorem. CI typechecks the proofs on every push to
[`proofs/`](https://github.com/nelsonduarte/capa-language/blob/main/proofs/). The full roadmap is at
[`capa-language.com/roadmap.html`](https://capa-language.com/roadmap.html).

## Documentation map

The marketing + rendered learning pages live at
[`capa-language.com`](https://capa-language.com), source in the
[`capa-language-website`](https://github.com/nelsonduarte/capa-language-website)
repo. The deeper Markdown documents below stay here, next to the
code they describe.

For a guided, beginner-friendly path there is a book,
**[Capa: The Capability-Typed Programming Language](https://github.com/nelsonduarte/capa-book)**:
a hands-on introduction (~278 pages, free PDF) with didactic
chapters, exercises, three practical projects, and an appendix of
exercise solutions, written for compiler `v1.12.0`. Content is
licensed CC BY-NC 4.0.

| Doc | What it is |
|-----|------------|
| [`capa-language.com`](https://capa-language.com/) | landing page, with the case for the language |
| [`capa-language.com/start.html`](https://capa-language.com/start.html) | install + first program + CLI |
| [`capa-language.com/learn/`](https://capa-language.com/learn/) | 12-page tutorial sequence |
| [`capa-language.com/manifest.html`](https://capa-language.com/manifest.html) | the manifest format + how to read it |
| [`capa-language.com/roadmap.html`](https://capa-language.com/roadmap.html) | status + what's planned |
| [`docs/getting-started.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/getting-started.md) | text version, plus LSP / editor setup |
| [`docs/tutorial.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/tutorial.md) | longer walkthrough |
| [`docs/reference.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/reference.md) | language reference (syntax + semantics) |
| [`docs/stdlib.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/stdlib.md) | runtime + library APIs |
| [`docs/packages.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/packages.md) | `capa.toml` + `capa install` + lockfile semantics |
| [`docs/trust-model.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/trust-model.md) | what is fail-closed vs best-effort vs trusted premise vs out-of-model |
| [`docs/testing.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/testing.md) | `capa test`: discovery, result contract, `--both` parity diff |
| [`docs/positioning.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/positioning.md) | honest comparison vs Pony, Koka, Roc, Wasm CM, Zero |
| [`docs/semantics.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/semantics.md) | lambda_cap calculus sketch + soundness theorems |
| [`docs/cra.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/cra.md) + [`regulatory.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/regulatory.md) | EU CRA + multi-jurisdiction regulatory mapping |
| [`docs/migration.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/migration.md) | porting Python code to Capa |
| [`docs/paper-draft.md`](https://github.com/nelsonduarte/capa-language/blob/main/docs/paper-draft.md) | workshop-paper draft |
| `docs/cve_*.md` and `docs/demo-event-stream.md` | walkthroughs of real CVEs against Capa |

## Programmatic use

```python
from capa import Lexer, Parser, analyze, transpile

source = open("program.capa", encoding="utf-8").read()
tokens = Lexer(source, filename="program.capa").lex()
module = Parser(tokens, source=source, filename="program.capa").parse_module()

result = analyze(module, source=source, filename="program.capa")
if not result.ok:
    for e in result.errors:
        print(e.format())
else:
    code = transpile(module, filename="program.capa")
    print(code)
```

## Contributing + community

Questions, ideas, and showing off what you built with Capa all
live in [**GitHub Discussions**](https://github.com/nelsonduarte/capa-language/discussions):

- **[Q&A](https://github.com/nelsonduarte/capa-language/discussions/categories/q-a)** for "the analyzer told me X and I don't understand why".
- **[Ideas](https://github.com/nelsonduarte/capa-language/discussions/categories/ideas)** for feature requests and "what if Capa had X".
- **[Show and tell](https://github.com/nelsonduarte/capa-language/discussions/categories/show-and-tell)** for programs, manifests, integrations.
- **[Announcements](https://github.com/nelsonduarte/capa-language/discussions/categories/announcements)** for release notes.

Pull requests welcome; see [`CONTRIBUTING.md`](https://github.com/nelsonduarte/capa-language/blob/main/CONTRIBUTING.md).
For security issues, please use the private vulnerability
reporting channel at
<https://github.com/nelsonduarte/capa-language/security/advisories/new>;
the disclosure flow is in [`SECURITY.md`](https://github.com/nelsonduarte/capa-language/blob/main/SECURITY.md).

## License

Dual-licensed under either [MIT](https://github.com/nelsonduarte/capa-language/blob/main/LICENSE-MIT) or
[Apache-2.0](https://github.com/nelsonduarte/capa-language/blob/main/LICENSE-APACHE) at your option. SPDX expression
`MIT OR Apache-2.0` (the Rust idiom). See [`LICENSE`](https://github.com/nelsonduarte/capa-language/blob/main/LICENSE)
for the rationale and the contribution clause.
