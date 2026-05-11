# Capa — TODO / Roadmap

Living inventory of pending work, captured locally so context survives
across sessions. Loosely ordered by impact. Edit freely.

Legend: **P0** = blocking next public milestone · **P1** = high
impact within the next 1–2 milestones · **P2** = nice to have ·
**P3** = future / research-grade · ⏱ = rough effort estimate.

---

## Current focus

Bridge from "working alpha" to "shareable v0.2 alpha". Three pieces:

- [x] **Demo: "Capa would have caught X"** — event-stream (Nov 2018).
  Safe Capa library in `examples/demo_event_stream.capa`; writeup
  with attack-attempt code + analyzer rejections in
  `docs/demo-event-stream.md`; cross-referenced from README.
- [x] **VSCode syntax highlighting** — TextMate grammar covering
  keywords (by category), built-in caps highlighted distinctly,
  string interpolation, numeric literals in all bases, operators
  including `..`, `..=`, `=>`, `?`. Lives in `vscode/`. Install
  manually via symlink/junction; Marketplace publication later.
- [x] **Full website (5 pages)** — `docs/{index,why,tour,start,roadmap}.html`
  + `docs/style.css`. Slim landing with three value-prop cards; "Why
  Capa" makes the case (ambient authority, event-stream, three
  pillars, attenuation, user-defined caps, honest limits); language
  tour in 12 sections; getting-started with full CLI reference;
  honest roadmap with status pills. Dark theme, single accent, no
  JS, no framework, no external fonts. Header is purely typographic
  (a hand-coded SVG logo was attempted and abandoned — bad call,
  see memory). Ready to serve via GitHub Pages when enabled for
  `docs/`.

When the public-readiness items land: tag `v0.2.0-alpha`, flip repo
to public.

---

## WhitePaper promises still open (P1)

- [ ] **Atenuação genérica** — extend `restrict_to` pattern to other
  built-in caps (`Fs.restrict_to(path_prefix)`,
  `Env.restrict_to_keys([...])`, `Clock.restrict_to_after(t)`, etc.)
  ⏱ ~3h each
- [ ] **Visibility (`pub`)** — KW_PUB is parsed but not enforced.
  Waits on a real module system. P2/P3
- [ ] **Native Capa module system** — `import` is parsed but
  analyzer-rejected today. Designing this is substantial work, and
  the practical win is small as long as projects are single-file.
  P3
- [ ] **Refinement types** — explicitly future in the WhitePaper. P3

---

## EBNF declares but not implemented (P2)

- [ ] **Doc comments** (`///`, `/**`) — lexer treats as ordinary
  comments today. Implement preservation + a tiny `capa-doc`
  generator. ⏱ 4-6h
- [ ] **Raw strings** (`r"..."`) — useful for regex and Windows paths.
  ⏱ 1-2h
- [ ] **Named arguments** (`f(name: "Ana", age: 30)`) — EBNF allows
  it, parser may accept; need to verify analyzer maps to parameters
  correctly + add tests. ⏱ 1-2h
- [ ] **Turbofish (`::<T>`)** — EBNF §7.3 mentions; never needed
  because inference has been enough. Only implement if a real case
  comes up. P3

---

## Tooling that moves the adoption needle (P1–P2)

- [ ] **LSP server** (Python, `pygls`) — diagnostics first, then
  hover, then go-to-definition. The single biggest multiplier for
  any new language. ⏱ 1-2 weeks for a useful subset. P1 after the
  demo lands.
- [ ] **`capa-fmt` (formatter)** — canonical, non-configurable
  (gofmt-style). Walks the AST and re-emits. ⏱ 1-2 days for v1.
- [ ] **Package manager** — only meaningful once there's a module
  system. P3
- [ ] **REPL** — deleted earlier. Reimplement when language is
  stable and demand exists. P2
- [ ] **`capa init`** — project scaffolding command. ⏱ 1-2h
- [ ] **Debugger integration** — Python debugger works on the
  transpiled output but maps poorly. Source maps would help. P3

---

## Known bugs / partial features (P1)

- [ ] **Multi-line `match` inside parentheses** — fails because parens
  suppress NEWLINE. Workaround: inline `{ }`, but `f(match x ...)`
  feels natural and doesn't work. ⏱ 1-2h
- [ ] **Block-body lambdas in deep expression contexts** — README
  flags this as a known parsing edge. Verify and either fix or
  document precisely.
- [ ] **Operator `?` uses internal exception** — correct but slower
  than expanded early-return. Optimisation. P2

---

## Code-quality maintenance (P2)

- [ ] **Split `analyzer.py` (2800+ lines)** into
  `analyzer/discipline.py`, `analyzer/inference.py`,
  `analyzer/dispatch.py`, etc. Currently navigable but starting to
  feel large.
- [ ] **Error-message audit** — top 10 most common messages: are
  they precise? Do they suggest fixes? Some are too terse.
- [ ] **Analyzer performance** — no benchmarks. Only worth attacking
  if someone reports slowness.
- [ ] **Test-coverage review** — `coverage.py` run + identify which
  parts of the analyzer are under-tested.

---

## PhD-aligned work (P1, when it makes sense)

Capa as artefact in the SBOM Governance thesis:

- [ ] **SPDX 2.3 parser in Capa** — proves Capa can mex with the
  real SBOM format. Becomes a thesis chapter on representation.
  ⏱ 1 week
- [ ] **CycloneDX 1.5 parser in Capa** — same story.
- [ ] **`capability Provenance` (user-defined)** — capability that
  represents the right to query/verify a piece of supply-chain
  metadata. Demonstrates user-defined caps in a real domain.
- [ ] **Example linking SBOM ↔ capabilities**: a Capa program that
  reads an npm package's SBOM and shows that its declared
  capabilities (network, fs, env) match what the package's
  source-code analysis claims. The "auditable supply chain" pitch.

These are not Capa-the-language work; they're Capa-as-research-vehicle
work. Pick them up alongside the thesis chapters they unlock.

---

## Strategic / governance (P0 once we go public)

- [ ] **`CONTRIBUTING.md`** — how to file an issue, what makes a good
  PR, branch naming, etc.
- [ ] **`CHANGELOG.md`** — start from this `v0.1.0` baseline.
- [ ] **Issue / PR templates** in `.github/`.
- [ ] **`CODE_OF_CONDUCT.md`** — Contributor Covenant is the default.
- [x] **Security policy** — `SECURITY.md` with how to report
  vulnerabilities. Lists in/out-of-scope issues, the GitHub private
  advisory channel, supported versions, disclosure flow.
- [x] **Flip repo to public** — `gh repo edit --visibility public`.
  Tagged `v0.2.0-alpha` first.
- [x] **Repo security hardening** — Dependabot vulnerability alerts +
  security updates, secret scanning + push protection, private
  vulnerability reporting, CodeQL workflow (push + PR + weekly
  cron), `.github/dependabot.yml` for GitHub Actions, explicit
  `permissions: contents: read` on the tests workflow.

---

## Things explicitly NOT planned for v1

For honesty / scope control:

- LLVM backend (Phase 4 of original WhitePaper roadmap; far future)
- Self-hosting (Phase 5; very far future)
- Full async/await (reserved keywords, no implementation)
- Tail-call optimisation
- Garbage collection beyond what CPython provides
- Custom syntax extensions / macros
