# 30. SBOM: CycloneDX and SPDX

> **What this chapter covers.** The two external-format SBOM emitters
> that wrap the internal capability manifest in a document existing
> supply-chain tooling can read: `--cyclonedx` (CycloneDX) and
> `--spdx` (SPDX). It describes what each EMITS (from real output, not
> intent): the exact format versions, the SINGLE dependency-identity
> source both consume, the package-URL (purl) rule, the concrete
> component/package/graph shapes, and the `capa:` annotation layer
> that is Capa's added value over an ordinary SBOM. Source:
> [`capa/manifest/_cyclonedx.py`](../capa/manifest/_cyclonedx.py),
> [`capa/manifest/_spdx.py`](../capa/manifest/_spdx.py) and the single
> identity producer in
> [`capa/manifest/_compose.py`](../capa/manifest/_compose.py). The
> CONTENT of the internal manifest is
> [29-capability-manifest.md](29-capability-manifest.md)'s subject;
> the dependency model is documented in
> [`docs/packages.md`](../docs/packages.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification. Invocations ran from a scratch folder with a product
tree built for the purpose: a root package `app`, a GitHub git
dependency (`logger`, resolved by `capa.lock` to a SHA), a non-GitHub
git dependency (`httpcore`, not covered by the lock), a path
dependency (`localutil`), and a declared-but-NEVER-vendored git
dependency (`ghost`). No absolute personal path appears in the
outputs. The tree used `vendor/` checkouts without a real `.git`, so
build-time supply-chain verification was bypassed with
`CAPA_NO_VERIFY=1` (this does NOT affect the SBOM's SHAPE, which is
this chapter's object).

Depends on: [29-capability-manifest.md](29-capability-manifest.md).

---

## 1. Two emitters, one manifest, one identity source

`--cyclonedx` and `--spdx` are NOT independent analyses: they are two
FORMAT WRAPPERS over exactly the internal manifest
[29-capability-manifest.md](29-capability-manifest.md) describes. Each
calls `build_manifest` and then RE-EXPRESSES that manifest in the
shape its target format demands (`_spdx.py` docstring: "Companion to
`_cyclonedx.py`. Emits the same per-function capability metadata in
SPDX 2.3 JSON"). Design consequence: everything chapter 29 says about
the four per-function capability fields, the voided exclusion proof,
and the `CAPABILITY_NAMES` source of truth holds for BOTH SBOMs
without re-derivation; this chapter describes only the format
projection.

There is a SECOND single source, specific to `capa.toml` dependencies:
the identity of each resolved dependency (name, version, purl) is
computed ONCE, by `resolve_dependency_identities`
([`capa/manifest/_compose.py`](../capa/manifest/_compose.py) line
614), and the two emitters are PURE CONSUMERS of that list. The
region's header comment is explicit: "The single source of truth for
'what are this product's real declared dependencies, and how is each
one named as a package-URL'. A CycloneDX (and future SPDX-3) emitter
is a pure CONSUMER of these records: it never re-parses capa.toml /
capa.lock and never assembles a purl of its own." The two renderers
(`_dependency_component`, `_cyclonedx.py` line 483;
`_dependency_package` in `_spdx.py`) read `bom_ref`, `version` and
`purl` VERBATIM.

**A cross-emitter agreement test pins the anti-drift invariant.**
[`tests/test_sbom_dependency_parity.py`](../tests/test_sbom_dependency_parity.py)
(`TestCrossEmitterPurlAgreement`) builds BOTH documents from ONE
`resolve_dependency_identities(root)` call, reads the purl of the
BUILT CycloneDX component and the `externalRefs[0].referenceLocator`
of the BUILT SPDX package, and asserts both equal `record.purl`, and
that the three purl sets (record, CycloneDX, SPDX) are set-identical.
Run at `8e2c609`: **50 passed** over
`test_sbom_dependency_parity.py`, `test_cyclonedx_dependencies.py`,
`test_spdx_dependencies.py`, `test_dependency_identity.py`.

The design in one sentence: **one identity source, two pure
consumers.** No SBOM emitter assembles its own `pkg:` string; none
parses `capa.toml` or `capa.lock`.

---

## 2. The exact format versions

Measured from the emitted documents' own version fields:

| Emitter | Flag | Emitted field | Value | Source constant |
|---|---|---|---|---|
| CycloneDX | `--cyclonedx` | `bomFormat` / `specVersion` | `"CycloneDX"` / `"1.6"` | `CYCLONEDX_SPEC_VERSION = "1.6"` (`_cyclonedx.py` line 52) |
| SPDX | `--spdx` | `spdxVersion` / `dataLicense` | `"SPDX-2.3"` / `"CC0-1.0"` | `SPDX_SPEC_VERSION` (`_spdx.py` line 60), `SPDX_DATA_LICENSE` (line 64) |

The code comment dates each choice. CycloneDX: "1.6 adds no required
fields over 1.5 and keeps the object-form `metadata.tools` and every
field Capa emits valid; the bump only widens what consumers accept."
SPDX: "2.3 is the current stable (2024) and the version every major
tool understands. 3.0 is JSON-Lite-shaped and breaks compatibility;
not adopted yet."

---

## 3. The package-URL rule

`_construct_purl` ([`capa/manifest/_compose.py`](../capa/manifest/_compose.py)
line 498) is the compiler's ONLY purl producer (docstring: "This is
the SOLE purl producer in Capa: no SBOM emitter ever assembles a
`pkg:` string of its own"). It takes `name`, `version`,
`source_kind`, `git_url`, `pin`, `commit` and returns the purl string
or `None`. The three rules, measured against real output:

**(1) GitHub git dependency ->
`pkg:github/<owner-lc>/<repo-lc>@<rev>`.** Host detection REUSES the
codebase's single github parser
(`capa.pkg._install._parse_github_owner_repo`), so there is no second
github regex; owner and repo are lowercased (the purl spec
canonicalizes the `github` namespace to lowercase). `<rev>` is the
RESOLVED commit SHA when known (from `capa.lock`), else the declared
pin (tag/rev); with neither, `@<rev>` is omitted.

Measured (dep `logger`, GitHub git, SHA resolved via `capa.lock`):

```
"purl": "pkg:github/acme/logger@ef1c0ffee1234567890abcdef1234567890abcd"
```

**(2) Non-GitHub git dependency ->
`pkg:generic/<name>[@<version>]?vcs_url=git+<url>@<rev>`.** The
`vcs_url` value follows the pip/SPDX form
`git+<transport>://<host>/<path>@<revision>`, percent-encoded. `<rev>`
is the resolved SHA when known, else the pin.

Measured (dep `httpcore`, non-GitHub git, NOT covered by the root
lock, so it carries the pin `v3.0.0`, not a SHA):

```
"purl": "pkg:generic/httpcore@3.0.0?vcs_url=git%2Bhttps:%2F%2Fgit.example.org%2Fnet%2Fhttpcore.git%40v3.0.0"
```

**(3) Path dependency -> `None` (no purl).** A path dependency has no
registry/VCS identity to package-URL; the component carries only
name + version + `capa:source_kind=path` + the root-relative path
("We never fabricate a `pkg:generic` / file purl for it").

Measured (dep `localutil`, path): the component has NO `purl` key; the
`bom-ref` falls back to the deterministic `capa:dep:localutil@9.9.9`
(`DependencyIdentity.bom_ref`).

**A declared but UNRESOLVED dependency still gets a purl (from the
pin), without a version.** Identities are keyed by EDGES (the full
declared set), not only resolved nodes, so a never-vendored git dep is
listed with `resolved=false` and a purl built from the pin. Measured
(`ghost`, github, `rev = "abc123"`, never vendored):

```
"bom-ref": "pkg:github/acme/ghost@abc123",
"purl": "pkg:github/acme/ghost@abc123",
"properties": [ ... {"name":"capa:resolved","value":"false"},
                    {"name":"capa:pin","value":"abc123"} ]
```

No `version` key (an unresolved dep has no `[package].version` to
read) and no `capa:rel_path` (never vendored).

**The lock SHA is applied per SOURCE, not per name.** The root
`capa.lock` is lifted to a `(git_url, pin) -> commit` map and applied
to EVERY edge sharing that source. This is what collapses a
lock-resolved DIAMOND (the direct and the transitive edge of the same
package get the same SHA, hence the same purl, hence dedup to ONE
component). A dependency whose source is NOT in the lock (a
transitive at a URL+pin the root never pinned) keeps its declared
pin: `httpcore`, a top-level git dep outside the lock, carries
`v3.0.0` (pin), not a SHA (a design boundary shared with
[`docs/cra.md`](../docs/cra.md)).

---

## 4. CycloneDX: the emitted shapes

The document is assembled in `build_cyclonedx` (`_cyclonedx.py` line
73). The top shape:

```
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:36a07b24-0d8c-5d7c-9e63-5fa98838d24f",
  "version": 1,
  "metadata": { ... },
  "components": [ ... ],
  "dependencies": [ ... ]
}
```

The `serialNumber` is a deterministic UUIDv5 derived from the display
filename (root-relative) plus the source's sha256, NOT from the
timestamp, so two runs of the same project produce the same serial
(SBOM-diff friendly). The `metadata` block (measured):

```
"metadata": {
  "timestamp": "2023-11-14T22:13:20Z",
  "tools": { "components": [ { "type": "application", "name": "capa",
                               "version": "1.32.0" } ] },
  "component": {
    "bom-ref": "capa:program:main.capa",
    "type": "application",
    "name": "main.capa",
    "version": "1.32.0",
    "supplier": { "name": "capa-build" },
    "licenses": []
  }
}
```

The `timestamp` derives from `SOURCE_DATE_EPOCH` when set (here
`1700000000` -> `2023-11-14T22:13:20Z`), else wall clock. Every
component carries `supplier: {name: capa-build}` and `licenses: []`:
strict validators (`cyclonedx-cli validate --strict`,
Dependency-Track in compliance mode) refuse a component without these
fields, and `licenses: []` is the well-defined "no concluded license"
state CycloneDX permits.

### 4.1 Components: program, functions, capabilities, dependencies

The `components` array has four kinds of entry, distinguished by the
`capa:kind` property:

- **the program**: the `metadata.component` of type `application`;
- **one function** per program function, type `library`, `bom-ref`
  `capa:fn:<file>:<name>` (`capa:kind=function`, section 6);
- **one built-in capability** per capability any function REACHES
  transitively, type `library`, `bom-ref`
  `capa:builtin:<file>:<cap>` (`capa:kind=builtin-capability`),
  synthesized so graph edges can resolve to a real `bom-ref`;
- **one `capa.toml` dependency** per resolved (or
  declared-but-unresolved) dependency, type `library`
  (`capa:kind=dependency`).

The GitHub git dependency, measured in full:

```
{
  "bom-ref": "pkg:github/acme/logger@ef1c0ffee1234567890abcdef1234567890abcd",
  "type": "library",
  "name": "logger",
  "scope": "required",
  "supplier": { "name": "capa-build" },
  "licenses": [],
  "properties": [
    { "name": "capa:kind", "value": "dependency" },
    { "name": "capa:source_kind", "value": "git" },
    { "name": "capa:resolved", "value": "true" },
    { "name": "capa:pin", "value": "v1.2.3" },
    { "name": "capa:commit", "value": "ef1c0ffee1234567890abcdef1234567890abcd" },
    { "name": "capa:rel_path", "value": "vendor/logger" }
  ],
  "version": "1.2.3",
  "purl": "pkg:github/acme/logger@ef1c0ffee1234567890abcdef1234567890abcd"
}
```

The path dependency (`localutil`) has the SAME shape without the
`purl` and `capa:commit` keys, with `capa:source_kind=path` and
`capa:rel_path=../localutil`. The component's `version` and `purl`
keys are emitted ONLY when present: an unresolved dep has no
`version`, a path dep has no `purl`.

### 4.2 The `dependencies` graph

Each "depends on" relation is an edge in `dependencies`. The program
depends on all its functions and reached built-in caps AND on each
top-level `capa.toml` dependency; each function depends on the
capabilities it reaches. Measured:

```
"dependencies": [
  { "ref": "capa:program:main.capa",
    "dependsOn": [
      "capa:builtin:main.capa:Stdio",
      "capa:fn:main.capa:main",
      "capa:dep:localutil@9.9.9",
      "pkg:generic/httpcore@3.0.0?vcs_url=git%2Bhttps:%2F%2Fgit.example.org%2Fnet%2Fhttpcore.git%40v3.0.0",
      "pkg:github/acme/ghost@abc123",
      "pkg:github/acme/logger@ef1c0ffee1234567890abcdef1234567890abcd"
    ] },
  { "ref": "capa:fn:main.capa:main",
    "dependsOn": [ "capa:builtin:main.capa:Stdio" ] }
]
```

The `capa.toml` dependency edges come from the `DependencyGraph` the
same resolution produces; the graph is deduped and sorted to be
byte-reproducible. When some function carries the `@vex` attribute,
the document additionally gains a `vulnerabilities[]` array
(CycloneDX 1.4+), with per-function granularity; in this chapter's
corpus (no `@vex`) the array is absent.

---

## 5. SPDX: the emitted shapes

The document is assembled in `build_spdx` (`_spdx.py` line 107). SPDX
is more RIGID than CycloneDX: there is no free `properties[]` array,
so the metadata travels in `annotations[]` (section 6), and there is
no granularity below `package`, so each function is a package with
`filesAnalyzed: false`. The header, measured:

```
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "main.capa",
  "documentNamespace": "https://capa-language.com/spdx/54643a2c-e7ae-5d41-a47c-e7c3d7249530",
  "creationInfo": {
    "created": "2023-11-14T22:13:20Z",
    "creators": [ "Tool: capa-1.32.0" ]
  },
  "packages": [ ... ],
  "relationships": [ ... ]
}
```

The `documentNamespace` is, like the CycloneDX serial, a
deterministic UUIDv5 URN of name plus source sha256, not of the
timestamp. Each package carries `licenseConcluded` /
`licenseDeclared` / `copyrightText` as `NOASSERTION`:
compliance-grade consumers (OpenChain, strict SPDX validation) refuse
a package without these three fields, and SPDX 2.3 blesses
`NOASSERTION` as the placeholder when the producer determined no
license.

### 5.1 Packages and relationships

The `packages` mirror the CycloneDX components: the program package,
one per reached built-in cap (`SPDXRef-Builtin-...`), one per user
capability (`SPDXRef-Cap-...`), one per function (`SPDXRef-Fn-...`),
and one per `capa.toml` dependency (`SPDXRef-Dep-...`). A
dependency's SPDXID is
`SPDXRef-Dep-<name>-<version-or-'none'>-<8 hex of the bom_ref sha256>`:
the hash suffix makes two distinct-source deps sharing name AND
version deterministically distinct. The GitHub git dependency,
measured:

```
{
  "SPDXID": "SPDXRef-Dep-logger-1.2.3-486da44d",
  "name": "logger",
  "downloadLocation": "NOASSERTION",
  "filesAnalyzed": false,
  "licenseConcluded": "NOASSERTION",
  "licenseDeclared": "NOASSERTION",
  "copyrightText": "NOASSERTION",
  "annotations": [
    { "annotationDate": "2023-11-14T22:13:20Z", "annotationType": "OTHER",
      "annotator": "Tool: capa", "comment": "capa:kind=dependency" },
    { ... "comment": "capa:source_kind=git" },
    { ... "comment": "capa:resolved=true" },
    { ... "comment": "capa:pin=v1.2.3" },
    { ... "comment": "capa:commit=ef1c0ffee1234567890abcdef1234567890abcd" },
    { ... "comment": "capa:rel_path=vendor/logger" }
  ],
  "versionInfo": "1.2.3",
  "externalRefs": [
    { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
      "referenceLocator": "pkg:github/acme/logger@ef1c0ffee1234567890abcdef1234567890abcd" }
  ]
}
```

The purl travels as ONE `externalRefs[]` entry of
`referenceCategory: PACKAGE-MANAGER` / `referenceType: purl`, and
ONLY when present: the `localutil` (path) package has no
`externalRefs` (no purl) but has `versionInfo: "9.9.9"`. `versionInfo`
is emitted only when the record has a version, so an unresolved
dependency (`SPDXRef-Dep-ghost-none-7a41eec4`) goes without it.

Relationships are explicit (`relationships[]`): the document
`DESCRIBES` the program, the program `CONTAINS` each function, and
the authority and dependency edges are `DEPENDS_ON`. Measured:

```
{ "spdxElementId": "SPDXRef-DOCUMENT",          "relationshipType": "DESCRIBES",  "relatedSpdxElement": "SPDXRef-Package-main.capa" }
{ "spdxElementId": "SPDXRef-Package-main.capa", "relationshipType": "CONTAINS",   "relatedSpdxElement": "SPDXRef-Fn-main.capa-main" }
{ "spdxElementId": "SPDXRef-Package-main.capa", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Builtin-main.capa-Stdio" }
{ "spdxElementId": "SPDXRef-Fn-main.capa-main", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Builtin-main.capa-Stdio" }
{ "spdxElementId": "SPDXRef-Package-main.capa", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Dep-logger-1.2.3-486da44d" }
{ "spdxElementId": "SPDXRef-Package-main.capa", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Dep-httpcore-3.0.0-ca150ef6" }
{ "spdxElementId": "SPDXRef-Package-main.capa", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Dep-localutil-9.9.9-4e0a30d2" }
```

**Fail-closed uniqueness guard.** Before emitting, `build_spdx`
verifies all SPDXIDs are distinct: a collision would silently merge
two elements (relationships resolve by SPDXID), so the code RAISES
`ComposeError` instead of emitting a silently wrong document. (NOT
VERIFIED by execution: no SPDXID collision was constructed; read
code, the non-negotiable backstop.)

---

## 6. The capability layer: the honest added value

An ordinary SBOM enumerates components and dependencies. What Capa
adds, and no other SBOM emitter produces by construction, is each
component's AUTHORITY read from the type system: each function
carries, in-band, its DECLARED, TRANSITIVELY REACHABLE and PROVABLY
EXCLUDED capability sets (the four fields of
[29-capability-manifest.md](29-capability-manifest.md)). This travels
as `capa:*` properties in CycloneDX and as `capa:<key>=<value>`
annotations in SPDX, in a namespace that SBOM tooling unaware of Capa
ignores without failing validation. The corpus's `main` function,
measured in CycloneDX:

```
{
  "bom-ref": "capa:fn:main.capa:main",
  "type": "library",
  "name": "main",
  "scope": "required",
  "supplier": { "name": "capa-build" },
  "licenses": [],
  "properties": [
    { "name": "capa:kind", "value": "function" },
    { "name": "capa:pos", "value": "main.capa:1:1" },
    { "name": "capa:return_type", "value": "()" },
    { "name": "capa:has_unsafe", "value": "false" },
    { "name": "capa:is_pub", "value": "false" },
    { "name": "capa:declared_capability", "value": "Stdio" },
    { "name": "capa:transitively_reachable_capability", "value": "Stdio" },
    { "name": "capa:provably_excluded_capability", "value": "Clock" },
    { "name": "capa:provably_excluded_capability", "value": "Db" },
    { "name": "capa:provably_excluded_capability", "value": "Env" },
    { "name": "capa:provably_excluded_capability", "value": "Fs" },
    { "name": "capa:provably_excluded_capability", "value": "Net" },
    { "name": "capa:provably_excluded_capability", "value": "Proc" },
    { "name": "capa:provably_excluded_capability", "value": "Random" },
    { "name": "capa:provably_excluded_capability", "value": "Serve" },
    { "name": "capa:provably_excluded_capability", "value": "Unsafe" },
    { "name": "capa:param", "value": "out: Stdio [cap]" }
  ]
}
```

The SAME content in SPDX, as annotations of the
`SPDXRef-Fn-main.capa-main` package (one `OTHER` /
`annotator: "Tool: capa"` annotation per pair).

The `provably_excluded` set is the strong guarantee: `main` receives
only `Stdio`, so the types PROVE it cannot exercise `Net`, `Fs`,
`Proc`, and so on (the nine exclusions = `CAPABILITY_NAMES` minus
`{Stdio}`). Besides the capability fields, the function-to-capability
membership is ALSO encoded as a graph edge (the CycloneDX `dependsOn`
/ the SPDX `DEPENDS_ON` of sections 4.2/5.1), so graph tooling sees
the authority chain, not just a flat property. A user capability
emits its own component/package with `capa:capability:method` and
`capa:capability:implementor`; the operator-declared grants
(`--preopen`, `--allow-host`) and the compiler-derived argv-to-sink
surface travel as top-level properties/annotations, labelled with
their opposite trust levels (the same pair
[29-capability-manifest.md](29-capability-manifest.md) section 2.2
describes).

JUDGEMENT. This authority layer is the genuine contribution: a
CAPABILITY-ANNOTATED SBOM, where each component's authority falls out
of the analyzer "for free", something another language does not emit
because the authority graph is not in its type system. It is a claim
about what the TYPES prove, not a regulatory-conformity claim
(section 7).

---

## 7. Determinism, and the design boundaries

**Determinism (measured).** With `SOURCE_DATE_EPOCH=1700000000`, two
runs of `--cyclonedx` over the same project gave identical bytes
(same sha256), and likewise `--spdx`. The CycloneDX serial and the
SPDX namespace are deterministic UUIDv5 of name+source, not of the
clock; the timestamp derives from `SOURCE_DATE_EPOCH`. Note: the
SBOMs are printed with `json.dumps(..., indent=2)` (readable), NOT in
the key-sorted canonical form of chapter 29's S1 envelope; the
measured byte stability comes from the builder already sorting lists
and from the deterministic serial/namespace/timestamp.

**Design boundaries** (shared with
[`docs/cra.md`](../docs/cra.md)):

- **A transitive dependency outside the root lock carries the PIN,
  not a SHA.** Measured: `httpcore` carries `capa:pin=v3.0.0` and a
  `...@v3.0.0` purl, no `capa:commit`. The lock resolves per SOURCE
  (section 3), so only sources the root pinned get a SHA.
- **A path dependency gets no purl.** Measured: `localutil` has no
  `purl` key (CycloneDX) / no `externalRefs` (SPDX); it is named by
  name + version + `capa:source_kind=path` + `capa:rel_path`. By
  design: there is no registry/VCS identity to fabricate.
- **SPDX stays at 2.3.** 3.0 is JSON-Lite-shaped and breaks
  compatibility; a DEFERRED model reshape (the identity source
  already anticipates "a future SPDX-3 emitter" as a consumer).
- **The host Python interpreter is NOT a component.** The SBOM
  describes the Capa program and its `capa.toml` dependencies, not
  the toolchain that runs it. (JUDGEMENT from reading the emitters:
  no host-runtime component is synthesized.)
- **Nothing here is "CRA-compliant".** Quoting
  [`docs/cra.md`](../docs/cra.md): "no act exists. There is therefore
  no presumption of conformity to invoke and nothing here can
  honestly be called 'CRA-compliant'." These are valid technical
  SBOMs (CycloneDX 1.6, SPDX 2.3), ingestible by existing tooling;
  the honest differentiator is the capability layer of section 6, not
  a regulatory-conformity claim.

---

## 8. Notes

- **Scope of the measurements.** The pasted outputs come from ONE
  product tree built for the purpose (`app` with four dependencies:
  lock-resolved GitHub git, non-GitHub git outside the lock, path,
  and declared-but-unvendored git), at `8e2c609`, on one machine,
  from a scratch folder with `CAPA_NO_VERIFY=1`. The three purl rules
  and both formats were exercised; this is not a statistical sample
  of projects.
- **MEASURED versus JUDGEMENT.** MEASURED:
  `bomFormat`/`specVersion`/`spdxVersion`/`dataLicense`; the
  component/package/graph/relationship shapes for function, built-in
  cap, and the four dependency classes; the cross-emitter purl
  agreement (50 tests passed at this commit); byte determinism under
  `SOURCE_DATE_EPOCH`; the version constants and cited line numbers.
  The pasted purl strings are literal CLI output. JUDGEMENT: the
  characterization of the capability layer as the genuine
  contribution; the reading that the host interpreter is not a
  component; the docstring citations about why a format choice is
  sound.
- **NOT VERIFIED by execution.** (1) The fail-closed SPDXID
  uniqueness guard: no collision was constructed. (2) The documents
  were not validated against an external strict validator
  (`cyclonedx-cli`, SPDX tooling) in this pass; the compliance-field
  choices are the documented intent of the emitters. (3) The purl
  round-trip through the reference `packageurl` library lives in
  `test_dependency_identity.py` (green in the 50-test run above), not
  exercised separately here.

---

## Links

- [29-capability-manifest.md](29-capability-manifest.md): the
  internal manifest (the four capability fields, composition, the
  authority-UNKNOWN element) both emitters wrap.
- [`docs/packages.md`](../docs/packages.md): the dependency model
  (`capa.toml`, path versus git, `vendor/`, `capa.lock`) that
  `resolve_dependency_identities` walks.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  the operator-declared grants and the compiler-derived argv-to-sink
  surface the SBOMs carry as labelled top-level metadata.
- [25-cli-commands-and-flags.md](25-cli-commands-and-flags.md): the
  CLI surface of `--cyclonedx` / `--spdx`.
- [`docs/cra.md`](../docs/cra.md): the regulatory mapping these SBOMs
  feed, and the shared no-conformity-claim posture.
