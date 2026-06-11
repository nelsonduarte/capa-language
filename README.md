<p align="left">
  <img src="capa_logo.svg" alt="Capa logo" height="80">
</p>

# Capa

[![tests](https://github.com/nelsonduarte/capa-language/actions/workflows/tests.yml/badge.svg)](https://github.com/nelsonduarte/capa-language/actions/workflows/tests.yml)
[![release](https://img.shields.io/github/v/release/nelsonduarte/capa-language?include_prereleases&label=release&color=blue)](https://github.com/nelsonduarte/capa-language/releases)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![python: >=3.10](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)](pyproject.toml)
[![SLSA Level 1](https://slsa.dev/images/gh-badge-level1.svg)](https://slsa.dev/spec/v1.0/levels#build-l1)
[![Discussions](https://img.shields.io/github/discussions/nelsonduarte/capa-language?logo=github&color=blueviolet)](https://github.com/nelsonduarte/capa-language/discussions)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Website: <https://capa-language.com/>**

Capa is a small, capability-typed programming language. Every
function declares the authorities it holds (`Fs`, `Net`, `Stdio`,
`Clock`, `Random`, `Env`, `Db`, `Proc`, `Unsafe`), the analyzer
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
wasmtime host.

```bash
$ capa --run examples/grades.capa
=== Roster ===
  Ana: 17.5 (Excellent)
  Bruno: 13.0 (Pass)
  Carla: 8.5 (Fail)

Statistics:
  Average: 14.083333333333334
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
    stdio.println("first line: ${body.split("\n").get(0)}")
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
data `@secret` and the compiler proves it cannot reach a public sink
(a log line, a network call, a file write) unless you route it
through an audited `declassify`:

```capa
fun leak(env: Env, stdio: Stdio)
    match env.get("API_KEY")              // env.get is @secret by default
        Some(key) -> stdio.println(key)   // information-flow violation: secret to a public sink
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
VSCode extension, see [`docs/getting-started.md`](docs/getting-started.md).

## CLI

```bash
capa --run                  file.capa   # transpile + execute via Python
capa --check                file.capa   # lex + parse + semantic check
capa --transpile            file.capa   # emit Python to stdout
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
capa --cyclonedx            file.capa   # CycloneDX 1.5 SBOM (caps embedded)
capa --spdx                 file.capa   # SPDX 2.3 (caps embedded)
capa --vex                  file.capa   # standalone VEX document
capa --provenance           file.capa   # in-toto + SLSA Provenance v1.0
capa --doc                  file.capa   # HTML doc page from /// comments
capa --fmt                  file.capa   # canonical-style rewrite
capa init                   my-project  # project scaffold
capa install                            # fetch capa.toml dependencies
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
`Map`, `Set`, `JsonValue`) and built-in capabilities (`Stdio`,
`Fs`, `Net`, `Env`, `Clock`, `Random`, `Db`, `Proc`, `Unsafe`).
Full reference in [`docs/stdlib.md`](docs/stdlib.md).

Four **seed libraries** live in standalone repos and are
consumed via the package manager:

| Library | Repo | Surface |
|---------|------|---------|
| `capa_cli` | [nelsonduarte/capa_cli](https://github.com/nelsonduarte/capa_cli) | argument parser: positionals, flags, options, `--help` |
| `capa_datetime` | [nelsonduarte/capa_datetime](https://github.com/nelsonduarte/capa_datetime) | ISO 8601 parsing + Y/M/D/h/m/s arithmetic, zero-capability |
| `capa_log` | [nelsonduarte/capa_log](https://github.com/nelsonduarte/capa_log) | levelled logging (`DEBUG`/`INFO`/`WARN`/`ERROR`) via a `Logger` capability over `Stdio` |
| `capa_http` | [nelsonduarte/capa_http](https://github.com/nelsonduarte/capa_http) | capability-typed HTTP client over `urllib`; caller sees `Http`, never `Unsafe` |

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
[`docs/packages.md`](docs/packages.md) for the manifest schema,
lockfile semantics, and resolution order.

## Project layout (sketch)

```
capa/                 # Python package: compiler + runtime + pkg manager
  lexer/  parser/  analyzer/  transpiler/  runtime/
  ir/                 # CIR + Wasm Component Model backend + WIT emitter
  manifest/  docgen/  lsp/    pkg/    cli.py
tests/                # 2593 unit, end-to-end, and property tests
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

Capa ships as **`1.0.0`** (released 2026-06-03), with the full
security axis (information-flow control, constant-time markers, and
typestate protocols) and the fully functional Wasm backend (see
[`CHANGELOG.md`](CHANGELOG.md)). The stability commitment in
[`STABILITY.md`](STABILITY.md) is now **in effect**: post-1.0,
breaking changes to the covered surfaces require a major bump, and
deprecations get one minor release of warning first.

**2593 tests** spanning the lexer, parser, analyzer, transpiler,
LSP, formatter, attribute-schema validation, package manager, the
information-flow / constant-time / typestate checkers, the Wasm
backend (with a Python/Wasm output parity harness), and
Hypothesis-based property tests. The transpiler
suite actually executes the generated Python and checks stdout; the
property suite fuzzes the full pipeline with arbitrary text and
syntax-aware Capa programs. The Wasm backend runs every capability
(Fs, Env, Clock, Stdio, Net, Random, Db, Proc) and the full language
surface with output byte-identical to the Python reference, and
cross-function capability attenuation is enforced soundly at the Wasm
runtime via host-side handle tables.

Run them:

```bash
python -m unittest discover tests
# or
pip install -e '.[test]' && python -m pytest
```

The Tier 1 supply-chain artefacts are **all shipping** today:

| Artefact | Command | Notes |
|----------|---------|-------|
| Capability manifest | `capa --manifest`     | per-function caps + attributes |
| CycloneDX 1.5 SBOM  | `capa --cyclonedx`    | capability metadata via `properties[]` |
| SPDX 2.3 SBOM       | `capa --spdx`         | capability metadata via `annotations[]` |
| VEX                 | `capa --vex`          | per-function exploitability claims via `@vex(...)` |
| SLSA Build L1       | `capa --provenance`   | in-toto Statement v1 + Provenance v1.0 predicate |
| WIT spec            | `capa --wit`          | one interface per capability the program touches |
| Wasm CM component   | `capa --wasm --component --output app.wasm` | WIT embedded, canonical ABI |

Tier 2 (regulatory mapping) is **complete**:
[`docs/regulatory.md`](docs/regulatory.md) covers the EU CRA,
NIS2, DORA (cybersecurity articles), NIST SSDF, and OWASP SCVS
side-by-side; the article-by-article CRA mapping lives in
[`docs/cra.md`](docs/cra.md).

The `lambda_cap` soundness theorems are **mechanised in Agda**,
no `postulate` remaining. Roughly 600 lines of self-contained
Agda (no `agda-stdlib` dependency) cover Progress, Preservation,
Capability Soundness, and a multi-step Manifest Completeness
theorem. CI typechecks the proofs on every push to
[`proofs/`](proofs/). The full roadmap is at
[`capa-language.com/roadmap.html`](https://capa-language.com/roadmap.html).

## Documentation map

The marketing + rendered learning pages live at
[`capa-language.com`](https://capa-language.com), source in the
[`capa-language-website`](https://github.com/nelsonduarte/capa-language-website)
repo. The deeper Markdown documents below stay here, next to the
code they describe.

| Doc | What it is |
|-----|------------|
| [`capa-language.com`](https://capa-language.com/) | landing page, with the case for the language |
| [`capa-language.com/start.html`](https://capa-language.com/start.html) | install + first program + CLI |
| [`capa-language.com/learn/`](https://capa-language.com/learn/) | 12-page tutorial sequence |
| [`capa-language.com/manifest.html`](https://capa-language.com/manifest.html) | the manifest format + how to read it |
| [`capa-language.com/roadmap.html`](https://capa-language.com/roadmap.html) | status + what's planned |
| [`docs/getting-started.md`](docs/getting-started.md) | text version, plus LSP / editor setup |
| [`docs/tutorial.md`](docs/tutorial.md) | longer walkthrough |
| [`docs/reference.md`](docs/reference.md) | language reference (syntax + semantics) |
| [`docs/stdlib.md`](docs/stdlib.md) | runtime + library APIs |
| [`docs/packages.md`](docs/packages.md) | `capa.toml` + `capa install` + lockfile semantics |
| [`docs/positioning.md`](docs/positioning.md) | honest comparison vs Pony, Koka, Roc, Wasm CM, Zero |
| [`docs/semantics.md`](docs/semantics.md) | lambda_cap calculus sketch + soundness theorems |
| [`docs/cra.md`](docs/cra.md) + [`regulatory.md`](docs/regulatory.md) | EU CRA + multi-jurisdiction regulatory mapping |
| [`docs/migration.md`](docs/migration.md) | porting Python code to Capa |
| [`docs/paper-draft.md`](docs/paper-draft.md) | workshop-paper draft |
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

Pull requests welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
For security issues, please use the private vulnerability
reporting channel at
<https://github.com/nelsonduarte/capa-language/security/advisories/new>;
the disclosure flow is in [`SECURITY.md`](SECURITY.md).

## License

Dual-licensed under either [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option. SPDX expression
`MIT OR Apache-2.0` (the Rust idiom). See [`LICENSE`](LICENSE)
for the rationale and the contribution clause.
