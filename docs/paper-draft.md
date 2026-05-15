# Capa: Capability-Typed Source as a Foundation for Software Supply-Chain Governance

**Working draft v1, 2026-05-15.** Target venue: PLAS (Programming
Languages and Analysis for Security) workshop, or similar
security-and-PL workshops at S&P / NDSS / EuroS&P. Workshop
length, 6 to 8 pages in the standard ACM SIG format.

**Author**: Nelson Duarte, ISLA Santarém / Independent.

> This is a working draft, not a submission. Sections marked
> with > status notes describe what still needs work. The
> repository it documents is publicly available at
> `https://github.com/nelsonduarte/capa`; all empirical artefacts
> (CVE case studies, benchmarks, SBOM diff, regulatory mapping)
> are reproducible from a single tagged release.

---

## Abstract

Software supply-chain attacks have escalated from incident to
systemic risk: event-stream 2018, eslint-scope 2018,
ua-parser-js 2021, torchtriton 2022, node-ipc 2022, and
xz-utils 2024 collectively compromised millions of installs in
a six-year window. Regulators have responded with mandatory
machine-readable Software Bill of Materials (SBOM) requirements
under the EU Cyber Resilience Act, NIS2, DORA, and the US NIST
Secure Software Development Framework. The SBOM, however,
describes *which* components ship in a product; it does not
describe *what each component is authorised to do*. We present
**Capa**, a capability-typed programming language whose
compiler emits the full supply-chain governance artefact set
(CycloneDX 1.5 SBOM, SPDX 2.3 SBOM, CycloneDX VEX, SLSA Build
L1 provenance) at *per-function* granularity, grounded in the
type system rather than in a separate static analyser. We
report on six CVE case studies the discipline structurally
rejects, a runtime-overhead benchmark suite (1.00x to 1.45x
versus hand-Python on representative workloads), an empirical
SBOM-diff micro-validation against an idiomatic Python
implementation of the same workload, and a multi-jurisdiction
mapping to five regulatory frameworks. The artefact is open
source under the MIT licence.

---

## 1. Introduction

> **Status**: complete first draft. Will tighten on revision.

Most modern programming languages were designed in an era when
**ambient authority** was a convenience. A function in Python,
JavaScript, Java, Go, or C# inherits the surrounding process's
authority to read the filesystem, open network sockets, query
the environment, and spawn subprocesses, without that authority
being mentioned in the function's type signature. The language
treats authority as the runtime's business, not the type
system's.

This convenience has, in the past decade, become an existential
liability for software supply chains. **event-stream** (npm,
November 2018) shipped a Bitcoin-wallet-stealing payload as a
nominally pure stream-transformation library. **eslint-scope**
(npm, July 2018) had its maintainer's credentials compromised
and pushed a tampered release that exfiltrated `~/.npmrc`
tokens. **ua-parser-js** (npm, October 2021) was hijacked
through the maintainer's account and shipped a cryptominer plus
a credential-stealing RAT to roughly 7 to 8 million weekly
installs. **torchtriton** (PyPI, December 2022) typosquatted
PyTorch's nightly dependency and exfiltrated SSH keys.
**node-ipc** (npm, March 2022) was sabotaged by a legitimate
maintainer making a political point. **xz-utils** (Linux,
February 2024) shipped a multi-year-engineered backdoor in
`sshd` via dynamic-linker indirection.

The pattern is uniform: the malicious code requires authority
the function's *declared* role does not need, and the language
gives it that authority anyway.

Regulators have responded not at the language layer but at the
*evidence* layer. The EU Cyber Resilience Act (Regulation (EU)
2024/2847), in full application from December 2027, requires
manufacturers of products with digital elements to ship a
machine-readable SBOM. NIS2 (Directive (EU) 2022/2555) requires
essential entities to assess supplier risk. DORA (Regulation
(EU) 2022/2554) requires financial entities to inventory their
ICT third-party dependencies. The US NIST Secure Software
Development Framework (SP 800-218) requires federal-procurement
suppliers to ship SBOMs. OWASP's Software Component
Verification Standard codifies a vendor-neutral graded
verification model. The common denominator is the SBOM: a
machine-readable list of components.

The SBOM, in every existing format, describes *which*
components ship. It does not describe *what each component is
authorised to do*. The information simply does not exist in the
source of mainstream languages; no SBOM emitter can attribute
authority to functions the compiler did not track in the first
place. The closest existing approximations are heuristic
taint-analysis tools (Semgrep, CodeQL, Slither) and runtime
sandbox observation (Deno permissions, seccomp filters). Both
are post-hoc, both are incomplete, and neither produces a
contract a compiler can enforce.

This paper makes a different proposal: **move the authority
declaration into the type system**, and let the compiler emit
the SBOM, the VEX, and the provenance attestation as native
outputs. The contribution is not novel at the type-system layer
(capability typing predates the supply-chain attack era by four
decades). The contribution is the **integration**: a single
compiler that emits the full governance artefact triangle
(SBOM, VEX, provenance) at per-function granularity, grounded
in a soundness theorem rather than in a separate analyser's
heuristics. We argue this is the right shape for the
regulatory artefacts the next decade will demand.

We make four concrete claims:

1. **The integration is technically feasible.** Section 5
   describes the implementation, a transpile-to-Python compiler
   in ~12k lines of hand-written Python.

2. **The runtime overhead is acceptable.** Section 6.2 reports
   1.00x to 1.45x against hand-Python on representative
   workloads.

3. **The structural discipline catches real attacks.** Section
   6.1 transliterates six CVEs from the 2018-2024 window; four
   are structurally rejected, two are partial losses that we
   report honestly.

4. **The artefact set maps to live regulation.** Section 7
   maps each output to specific clauses of five frameworks
   (CRA, NIS2, DORA, NIST SSDF, OWASP SCVS).

---

## 2. Background and Related Work

> **Status**: complete first draft. May need tightening for
> length.

### 2.1. Capability typing in programming languages

The capability-based security model originates with **Dennis
and Van Horn** (1966) and was developed at OS level in
**KeyKOS** (1985) and **EROS** (1999). Object-capability
models in programming languages have been pursued for at least
two decades:

- **E** and **Joe-E** [Miller 2006] establish the object-
  capability model as a JavaScript discipline.
- **Wyvern** [Aldrich et al.] combines object capabilities with
  a module system; capability handles travel as values.
- **Pony** [Clebsch et al.] uses *reference capabilities*
  (`iso`, `trn`, `ref`, `val`, `box`, `tag`) for actor-level
  data-race safety. The discipline is concurrency-oriented
  rather than authority-oriented, but borrows the same vocabulary.
- **Austral** combines linear types with capability-secure
  modules; arguably the closest extant academic match to Capa's
  design.
- **Koka** [Leijen] provides effect rows. An effect can stand
  in for a capability: a function whose row contains `<net>`
  is shape-equivalent to a function that takes a `Net`
  parameter.
- **Roc** [Feldman] threads platform-provided effectful
  primitives as values, an industrially-aimed restatement of
  the object-capability model.
- **Hylo** combines linear types with subscript-style mutable
  borrowing.

At the hardware layer, **CHERI** [Watson et al.] retrofits C
and C++ with capability pointers, with empirical CVE-class
mitigation studies.

At the runtime layer, **WebAssembly Component Model + WIT**
provides per-module capability declarations as a runtime
contract, the most credible production-aimed contender for the
auditable-supply-chain pitch.

None of these systems emit a CRA-aligned SBOM as a first-class
compiler output. None emits VEX at function granularity. None
maps explicitly to CRA / NIS2 / DORA / SSDF / SCVS.

### 2.2. SBOM, VEX, and provenance formats

**CycloneDX 1.5** (OWASP) and **SPDX 2.3** (Linux Foundation)
are the two industry-adopted SBOM formats. **CycloneDX VEX**
(integrated since 1.4) and **CSAF VEX** (OASIS, separate
document) provide the schema for per-component exploitability
claims. **SLSA Provenance v1.0** (CNCF, [slsa.dev]) and the
**in-toto attestation** framework provide the build-time
provenance schema; **Sigstore / cosign** provide the signing
infrastructure that lifts SLSA L1 to L2 and beyond. The
**OWASP Software Component Verification Standard** codifies a
vendor-neutral graded checklist across six domains (Inventory,
SBOM, Build Environment, Package Management, Component
Analysis, Pedigree and Provenance).

Tooling consuming these formats (Dependency-Track, Anchore,
syft, grype, slsa-verifier) operates at *package* granularity.
We are not aware of prior work emitting any of them at
*function* granularity from a compiler. The closest related
artefact is the WebAssembly Component Model's WIT export, which
operates at *module* granularity.

### 2.3. Regulation and supply-chain governance

The regulatory landscape Capa is built to serve:

- **EU Cyber Resilience Act** (Regulation (EU) 2024/2847),
  in full application 11 December 2027. Annex I Part II (1)
  is the SBOM clause; Annex I Part I (2)(a)-(m) is the
  essential-cybersecurity-requirements catalogue.
- **NIS2** (Directive (EU) 2022/2555), transposed by 17 October
  2024. Article 21(2)(d) is the supply-chain clause.
- **DORA** (Regulation (EU) 2022/2554), applies from 17 January
  2025. Article 8 is the inventory clause; Articles 28-30
  govern ICT third-party risk.
- **NIST SSDF** (SP 800-218), the US federal baseline for
  secure development; cited by Executive Order 14028.
- **OWASP SCVS**, vendor-neutral, three verification levels.

We map Capa's artefacts onto each in Section 7.

---

## 3. The Capa Discipline

> **Status**: complete first draft. Tightens with code excerpts
> in the camera-ready version.

Capa's capability discipline operates at three layers:

### 3.1. Structural

A function may exercise an external authority (filesystem,
network, environment, clock, RNG, database, subprocess, or the
`Unsafe` Python boundary) only if a parameter of the
corresponding capability type appears in its signature. The
capability values are unforgeable, in the standard
object-capability sense: there is no constructor that
fabricates a `Net` handle from nothing. `main` receives the
initial set from the runtime; everything else receives
capabilities by parameter passing.

```capa
fun parse_user_agent(ua: String) -> UserAgent
    // No Net in scope. The body cannot reach the network,
    // statically.
    ...

fun fetch_user(net: Net, id: String) -> Result<String, IoError>
    return net.get("https://api.example.com/users/${id}")
```

### 3.2. Flow (attenuation)

A capability holder may produce a narrower capability via
`restrict_to` chains. The narrowing is monotonic; the type
system tracks it so audit metadata can report the effective
attenuation at each call site.

```capa
fun main(net: Net)
    let api = net.restrict_to("api.example.com")
    fetch_user(api, "alice")  // api can reach only one host
```

### 3.3. Linear (consume)

A capability may be marked `consume` in a parameter list, in
which case the caller's reference is moved into the callee and
cannot be used afterwards. The use-after-consume bookkeeping
is enforced by the analyzer.

```capa
fun cancel(stdio: consume Stdio) -> Unit
    stdio.println("goodbye")
    // stdio no longer reachable in the caller after this
```

### 3.4. Soundness

The three layers compose into a calculus we sketch as
**λ_cap** (working name) in the companion document
[`docs/semantics.md`]. We state two theorems:

- **Theorem 1 (Capability Soundness).** Well-typed Capa
  programs do not exercise capabilities they do not declare.
  Progress and preservation in the Wright-Felleisen style.
- **Theorem 2 (Manifest Completeness).** The manifest emitted
  by `--manifest` declares exactly the capabilities a
  well-typed program *can* exercise; no false negatives, no
  false positives.

Proof sketches are in `docs/semantics.md` § 6 and § 7. The
mechanisation in Agda or Coq is workshop-paper-sized future
work.

---

## 4. Implementation

> **Status**: complete first draft. May extend with
> architecture diagram in revision.

Capa is a hand-written transpiler in ~12k lines of Python 3.10+,
split into eight subpackages (lexer, parser, analyzer,
transpiler, runtime, manifest, docgen, capa_ast, lsp). It
transpiles Capa source to Python source; the transpiled Python
is executed by CPython. There is no native backend, by design:
the goal is to demonstrate the discipline-plus-artefacts model,
not to compete with Rust on raw performance.

Key implementation choices:

- **Capability values are runtime objects**. The `Net`, `Fs`,
  etc. classes in `capa/runtime/_capabilities.py` are plain
  Python classes whose constructors hold an internal `allowed`
  set. The capability discipline is enforced *statically*; the
  runtime cannot fail-closed by itself (it would for attenuated
  capabilities, but the structural layer rules out the failure
  modes first).

- **The manifest is built from the analysed AST**, not the
  transpiled Python. `capa/manifest/_funrec.py` walks the AST
  and produces a JSON record per function. Five emitters wrap
  that record in different envelopes: `--manifest` (raw JSON),
  `--cyclonedx` (CycloneDX 1.5), `--spdx` (SPDX 2.3), `--vex`
  (CycloneDX VEX), `--provenance` (in-toto + SLSA Provenance
  v1.0).

- **The `@vex` attribute** is parsed alongside `@security`,
  `@deprecated`, and `@audited`. The analyzer's
  `_ATTRIBUTE_SCHEMA` validates allowed keys; the VEX emitter
  walks the validated attributes and produces one CycloneDX
  vulnerability entry per `@vex` declaration.

- **The SBOM diff and audit pipeline are themselves Capa
  programs**, in `examples/sbom_diff.capa` and
  `examples/sbom_capability_audit.capa`. Capa eats its own
  dogfood.

- **CI runs 776 tests** across 8 test files: lexer, parser,
  analyzer, transpiler, formatter, LSP, attributes (including
  SPDX / VEX / provenance), docs, init-project, plus a
  Hypothesis-driven property suite.

---

## 5. Empirical Evaluation

> **Status**: complete first draft. The numbers and examples
> are taken from artefacts already in the repository; nothing
> here is synthetic.

### 5.1. CVE case studies

We transliterated six CVE-class supply-chain incidents from
the 2018-2024 window into Capa. Each is paired in the
repository as a runnable `examples/cve_*.capa` and an
explanatory `docs/cve_*.md`. The verdict per case:

| Case study | Year | Mechanism | Capa verdict |
|---|---|---|---|
| event-stream | 2018 | malicious dependency injection | **rejected** |
| eslint-scope | 2018 | credential theft via Fs + Net | **rejected** |
| ua-parser-js | 2021 | cryptominer + RAT via account hijack | **rejected** |
| torchtriton | 2022 | PyPI typosquat | **rejected** |
| node-ipc | 2022 | legitimate-authority abuse | partial (attenuation) |
| xz-utils | 2024 | below-language build attack | partial (orthogonal) |

**Four clean rejections** establish that Capa addresses real
attacks across multiple years, ecosystems (npm + PyPI), and
payloads (data theft, cryptominer + RAT, kernel exfiltration).
The two partial losses are deliberately included so the
empirical claim is calibrated: a defensible position
acknowledges what the discipline cannot reach.

The structural rejection is uniform across the four wins. The
attack's malicious behaviour required `Fs` or `Net` or
`Unsafe`, the legitimate function's signature did not declare
them, the analyzer rejects any attempt to use them. The diff
between a legitimate and a malicious version of the same
library is loud in code review, in pull-request review, and in
the SBOM emitted by `--cyclonedx`.

### 5.2. Runtime overhead

We measured Capa's runtime cost against idiomatic hand-Python
on three representative workloads, with `timeit.repeat`. All
numbers are on CPython 3.14, Windows 11, `--iterations 30
--repeat 7`. Stable across runs to within roughly 5 to 10 %.

| Workload | Description | Capa | Python | Ratio |
|---|---|---:|---:|---:|
| `fib(25)` | pure compute, recursive | ~7.3 ms | ~7.4 ms | **1.00x** |
| `scope_analyser(1000)` | list-heavy | ~0.67 ms | ~0.57 ms | **1.20x** |
| `ua_parse(1000)` | string + struct | ~0.60 ms | ~0.42 ms | **1.45x** |

The pure-compute workload runs at parity; Capa's transpiler
emits ordinary Python function calls for code paths that do
not use the `?` operator. List operations incur ~20 %
overhead from `CapaList`'s method-dispatch wrapping;
string-plus-struct paths add ~45 % overhead from `match`-on-
enum lowering plus dataclass construction. Closing these gaps
is mechanical (specialise on the type) but has not yet been
prioritised. The headline claim, **single-digit overhead on
pure compute, low-double-digit on list-heavy, mid-double-digit
on combined workloads**, is the kind of overhead a regulated
industry can absorb in exchange for the artefact set.

### 5.3. SBOM diff: information gain over PURL-only

We constructed a microservice config-loader pattern in two
forms: an idiomatic Python implementation
([`examples/empirical_config_naive.py`]) that conflates
filesystem, environment, and HTTP access in a single
`load_config(path) -> dict` function, and a Capa equivalent
([`examples/empirical_config.capa`]) that splits the same
logic into five functions whose signatures declare exactly
which capabilities they need.

The SBOM emitted by `capa --cyclonedx` shows per-function
attribution:

```
parse_config_text:      []
load_local_config:      [Fs]
apply_env_overrides:    [Env]
fetch_remote_overrides: [Net]
load_full_config:       [Fs, Env, Net]
main:                   [Stdio]
```

A PURL-based SBOM for the Python equivalent (the output any
`syft`-style tool produces today) lists `json`, `os`, and
`urllib.request` at module level, with no per-function
attribution. The capability-aware SBOM is a **strict
information gain**.

---

## 6. Regulatory Mapping

> **Status**: complete first draft. Long-form per-framework
> sections are in `docs/regulatory.md` and `docs/cra.md`; the
> table below is the paper-length distillation.

Capa's artefact set maps to five frameworks. The header rows
are the artefacts; the body rows are which clause each
framework's text addresses.

| Capa output | CRA Annex I | NIS2 Art. 21 | DORA | NIST SSDF | OWASP SCVS |
|---|---|---|---|---|---|
| CycloneDX SBOM | II(1) **direct** | 21(2)(d) **direct** | Art. 8 **direct** | PS.3 **direct** | Domain 2 **direct** |
| SPDX SBOM | II(1) **direct** | 21(2)(d) **direct** | Art. 8 **direct** | PS.3 **direct** | Domain 2 **direct** |
| CycloneDX VEX | II(2) partial | Art. 23 indirect | Arts. 17-19 partial | RV.1, RV.2 **direct** | Domain 5 **direct** |
| SLSA L1 provenance | I(2)(f) indirect | 21(2)(d) indirect | Arts. 28-30 partial | PS.3, PS.4 **direct** | Domain 6 **direct** |
| Audit pipeline | II(1) indirect | 21(2)(d) **direct** | Arts. 28-30 **direct** | PO.5 indirect | Domain 1 partial |
| SBOM diff tool | II(2) indirect | 21(2)(d) partial | Arts. 17-19 partial | RV.1 partial | Domain 2 partial |

The full reading, with per-framework deeper sections, is in
the companion document `docs/regulatory.md`. We are not aware
of any other compiler that targets this artefact set as
first-class output.

---

## 7. Discussion and Limitations

> **Status**: complete first draft. Honest scope statement.

Capa is not a silver bullet. The honest limits:

- **Capa does not deliver compliance.** Each of the five
  frameworks combines technical artefacts (where Capa helps)
  with organisational processes (vulnerability disclosure,
  24-hour incident notification, supplier due diligence,
  conformity assessment). Capa addresses the technical-artefact
  row and leaves the organisational rows to the organisation.

- **A capability holder with bad intent is still dangerous.**
  Attenuation reduces blast radius but does not eliminate
  trust. node-ipc is the clearest illustration: an IPC library
  legitimately needs `Net` and `Fs`, so the structural rule
  does not apply.

- **Below-language attacks are out of reach.** xz-utils 2024
  is the canonical example: the malicious payload was bytes in
  test fixtures, build-script assembly via autotools `.m4`,
  and dynamic-linker symbol replacement at `ld.so` load time.
  None of those is visible at the source-language layer.
  Orthogonal defences (reproducible builds, code signing,
  transparency logs) are needed for that row of the attack
  stack.

- **The `Unsafe` boundary is a real hole.** `py_import` and
  `py_invoke` cross into Python, beyond Capa's analysis. The
  `capa:has_unsafe` property surfaces this in the SBOM so
  reviewers can budget trust accordingly; the analyzer does
  not pretend to analyse what happens past that boundary.

- **Capa is alpha.** The compiler runs and the test suite is
  green, but the runtime is Python's; there is no native
  backend; there is no third-party library ecosystem; module
  imports are parsed but analyzer-rejected. The artefact
  outputs (manifest, SBOM, VEX, provenance) are stable enough
  to integrate into compliance pipelines; the runtime is not
  yet suitable for high-performance production deployments.

- **The mapping in Section 6 is the author's reading**,
  reviewable but not authoritative. An organisation's
  auditors may classify the same Capa artefact differently.

---

## 8. Conclusion and Future Work

> **Status**: complete first draft.

We have presented **Capa**, a capability-typed programming
language whose compiler natively emits the full supply-chain
governance artefact set (manifest, CycloneDX, SPDX, VEX, SLSA
provenance) at per-function granularity. The contribution is
not the type system in isolation, where four decades of prior
art exist, but the **integration** between the type system and
the regulatory-artefact stack the next decade will demand. We
have demonstrated the discipline structurally rejects four out
of six representative supply-chain CVEs, runs at 1.00x to
1.45x overhead against hand-Python, and yields a strict
information gain over PURL-only SBOMs.

The immediate future work:

1. **Mechanise Theorem 1 in Agda or Coq.** The proof sketch
   in `docs/semantics.md` is tractable; a mechanised version
   would close the soundness claim.
2. **Empirical study at scale.** The six CVE case studies and
   the one micro-validation make a point; a quantitative
   study transliterating tens of real-world libraries and
   measuring the SBOM diff would test it.
3. **Sign provenance attestations.** Capa emits SLSA L1; L2
   requires signing, which is mechanical via cosign / Sigstore.
4. **Native backend.** A Cranelift or LLVM target would close
   the "Python overhead" objection definitively; the IR design
   is open.

The Capa source, test suite, regulatory mapping, and all
empirical artefacts in this paper are available at
`https://github.com/nelsonduarte/capa` under the MIT licence.

---

## References

> **Status**: list of canonical sources to be expanded into
> formal citations in the camera-ready version. The links are
> stable; the bibliographic record needs polishing.

- Dennis, J. B., and Van Horn, E. C. *Programming Semantics for
  Multiprogrammed Computations*. CACM 9(3), 1966.
- Hardy, N. *KeyKOS Architecture*. ACM OSR, 1985.
- Shapiro, J., Smith, J., Farber, D. *EROS: a fast capability
  system*. SOSP 1999.
- Miller, M. *Robust Composition*. PhD thesis, JHU, 2006.
- Watson, R. N. M., et al. *CHERI: A Hybrid Capability-System
  Architecture*. IEEE S&P, 2015.
- Wright, A. K., Felleisen, M. *A syntactic approach to type
  soundness*. Information and Computation, 1994.
- CycloneDX 1.5 specification.
  https://cyclonedx.org/docs/1.5/json/
- SPDX 2.3 specification.
  https://spdx.github.io/spdx-spec/v2.3/
- SLSA v1.0 specification. https://slsa.dev/spec/v1.0/
- in-toto Statement v1.
  https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- Regulation (EU) 2024/2847 (Cyber Resilience Act).
  https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- Directive (EU) 2022/2555 (NIS2).
  https://eur-lex.europa.eu/eli/dir/2022/2555/oj
- Regulation (EU) 2022/2554 (DORA).
  https://eur-lex.europa.eu/eli/reg/2022/2554/oj
- NIST SP 800-218 v1.1 (SSDF).
  https://csrc.nist.gov/Projects/ssdf
- OWASP Software Component Verification Standard.
  https://owasp.org/www-project-software-component-verification-standard/

---

## Appendix A: Reproduction

All numerical claims in this paper are reproducible from the
repository. The relevant commands:

```bash
# Six CVE case studies, runnable
capa --run examples/demo_event_stream.capa
capa --run examples/cve_eslint_scope.capa
capa --run examples/cve_ua_parser_js.capa
capa --run examples/cve_torchtriton.capa
capa --run examples/cve_node_ipc.capa
capa --run examples/cve_xz_utils.capa

# Runtime overhead benchmarks
python benchmarks/runner.py --iterations 30 --repeat 7 --markdown

# Empirical micro-validation: Python side
cat examples/empirical_config_naive.py
# Empirical micro-validation: Capa side + SBOM
capa --run examples/empirical_config.capa
capa --cyclonedx examples/empirical_config.capa

# SBOM diff tool
capa --run examples/sbom_diff.capa

# The artefact triangle from a single source
capa --cyclonedx examples/vex_demo.capa
capa --spdx     examples/vex_demo.capa
capa --vex      examples/vex_demo.capa
capa --provenance examples/vex_demo.capa
```

Companion documents in the repository:

- `docs/semantics.md`: λ_cap calculus sketch and soundness theorems
- `docs/positioning.md`: comparative positioning vs related work
- `docs/cra.md`: CRA article-by-article mapping
- `docs/regulatory.md`: multi-jurisdiction comparative mapping
- `docs/empirical_micro.md`: Python vs Capa SBOM diff walkthrough
- `docs/cve_*.md`: the six CVE case studies
- `benchmarks/README.md`: benchmark methodology

---

## Appendix B: What this paper does *not* claim

For symmetry with Section 7 and so the contribution is honestly
calibrated, this paper does not claim:

- That capability typing is a new idea. It is not. The
  contribution is the integration with the SBOM/VEX/provenance
  stack.
- That Capa is production-ready. It is not.
- That the regulatory mapping is authoritative. It is the
  author's reading.
- That every Capa user will adopt the discipline correctly.
  Capa makes the discipline checkable, not automatic; the
  `Unsafe` boundary remains the responsibility of the
  reviewer.
- That CRA / NIS2 / DORA / SSDF / SCVS compliance can be
  achieved by adopting Capa alone. Compliance is an
  organisational outcome; Capa contributes the technical
  artefacts that organisational compliance consumes.
