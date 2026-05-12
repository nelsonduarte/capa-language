# Capa, TODO / Roadmap

Living inventory of pending work, captured locally so context survives
across sessions. Loosely ordered by impact. Edit freely.

Legend: **P0** = blocking next public milestone · **P1** = high
impact within the next 1-2 milestones · **P2** = nice to have ·
**P3** = future / research-grade · ⏱ = rough effort estimate.

---

## Current focus

Bridge from "working alpha" to "shareable v0.2 alpha". Three pieces:

- [x] **Demo: "Capa would have caught X"**, event-stream (Nov 2018).
  Safe Capa library in `examples/demo_event_stream.capa`; writeup
  with attack-attempt code + analyzer rejections in
  `docs/demo-event-stream.md`; cross-referenced from README.
- [x] **VSCode syntax highlighting**, TextMate grammar covering
  keywords (by category), built-in caps highlighted distinctly,
  string interpolation, numeric literals in all bases, operators
  including `..`, `..=`, `=>`, `?`. Lives in `vscode/`. Install
  manually via symlink/junction; Marketplace publication later.
- [x] **Full website (5 pages)**, `docs/{index,why,tour,start,roadmap}.html`
  + `docs/style.css`. Slim landing with three value-prop cards; "Why
  Capa" makes the case (ambient authority, event-stream, three
  pillars, attenuation, user-defined caps, honest limits); language
  tour in 12 sections; getting-started with full CLI reference;
  honest roadmap with status pills. Dark theme, single accent, no
  JS, no framework, no external fonts. Header is purely typographic
  (a hand-coded SVG logo was attempted and abandoned, bad call,
  see memory). Ready to serve via GitHub Pages when enabled for
  `docs/`.

When the public-readiness items land: tag `v0.2.0-alpha`, flip repo
to public.

---

## WhitePaper promises still open (P1)

- [x] **Atenuação genérica**: every built-in capability has an
  attenuator. `Net.restrict_to(host)`, `Fs.restrict_to(prefix)`,
  `Env.restrict_to_keys([...])`, `Clock.restrict_to_after(t)`,
  and `Random.with_seed(seed)`. The first four monotonically
  narrow authority and are fail-closed on denied access; the
  last has no denied state but produces a deterministic sequence
  whose seed is visible in the manifest's data-flow tracker.
- [ ] **Visibility (`pub`)**, KW_PUB is parsed but not enforced.
  Waits on a real module system. P2/P3
- [ ] **Native Capa module system**, `import` is parsed but
  analyzer-rejected today. Designing this is substantial work, and
  the practical win is small as long as projects are single-file.
  P3
- [ ] **Refinement types**, explicitly future in the WhitePaper. P3

---

## EBNF declares but not implemented (P2)

- [x] **Doc comments** (`///`, `/**`). Lexer emits `DOC_COMMENT`
  tokens with leading-space and Javadoc star-margin stripped;
  parser attaches them to the following `fun` / `type` / `trait` /
  `capability` / `impl` method as the `doc` field; `--doc` runs
  the `capa.docgen` HTML generator. The markdown subset covers
  paragraphs, inline `code` spans, fenced code blocks (with
  optional language tag), and bulleted lists. Plain (non-capability)
  traits get their own section with method signatures and the
  list of implementor types.
- [x] **Raw strings** (`r"..."`), no escape processing and no
  `${}` interpolation; useful for regex and Windows paths. A raw
  string cannot embed `"`; use a regular string with `\"` for that.
- [x] **Named arguments** (`f(name: "Ana", age: 30)`), parser
  accepts an optional `IDENT ":"` prefix on each call argument;
  the analyzer reorders to parameter order before type checking,
  rejects positional-after-named, unknown names, duplicates, and
  arity mismatches; the transpiler emits Python keyword arguments.
  Built-in methods (String, Map, Set, capabilities) reject named
  arguments because their parameter names are not tracked.
- [ ] **Turbofish (`::<T>`)**, EBNF §7.3 mentions; never needed
  because inference has been enough. Only implement if a real case
  comes up. P3

---

## Tooling that moves the adoption needle (P1-P2)

- [ ] **LSP server** (Python, `pygls`), diagnostics first, then
  hover, then go-to-definition. The single biggest multiplier for
  any new language. ⏱ 1-2 weeks for a useful subset. P1 after the
  demo lands.
- [~] **`capa-fmt` (formatter)**, canonical, non-configurable
  (gofmt-style). **v1 (line-level) landed**: CLI flags `--fmt` and
  `--fmt-check` normalise line endings, indentation (tabs to 4
  spaces, partial indents floor to a 4-space multiple), trailing
  whitespace, blank-line clusters (collapse to one), and the final
  newline. Block-comment interiors (`/* ... */` and `/** ... */`)
  are preserved verbatim so Javadoc-style `*` continuation lines
  survive. Idempotent by construction. **Pending (v2)**: intra-line
  canonicalisation (operator spacing, brace placement, expression
  re-emission from the AST) and `//` comment preservation through
  the future AST round-trip.
- [ ] **Package manager**, only meaningful once there's a module
  system. P3
- [ ] **REPL**, deleted earlier. Reimplement when language is
  stable and demand exists. P2
- [x] **`capa init`**, project scaffolding. `python -m capa init [name]`
  creates `main.capa` (a runnable, canonically-formatted starter that
  uses `Stdio` so the capability discipline shows up on line one),
  `README.md`, `.gitignore`, and `.capa-version`. Refuses to overwrite
  a non-empty directory or a path that is a file. The starter passes
  `--check` and `--run` out of the box.
- [ ] **Debugger integration**, Python debugger works on the
  transpiled output but maps poorly. Source maps would help. P3

---

## Known bugs / partial features (P1)

- [ ] **Indent-based `match` inside parentheses**, by design fails
  because parens suppress NEWLINE/INDENT/DEDENT. The braced inline
  form (`match x { P1 -> e1, P2 -> e2, ... }`) does work inside a
  call expression and is the documented way to write a `match` as
  an argument. Reclassified from "bug" to "documented restriction";
  promote to a real fix only if someone proposes a lexer change
  whose blast radius does not eat the indent-based form elsewhere.
- [x] **Block-body lambdas in deep expression contexts**, verified
  and documented as a deliberate restriction. Same root cause as
  indent-form match inside parens: the lexer suppresses
  NEWLINE/INDENT/DEDENT inside `(...)` for implicit line continuation,
  so block-body lambdas there are unreachable by design. The parser
  now emits a targeted error pointing at the recommended workaround
  (bind to `let` first, then pass the binding, or use a
  single-expression body). README, EBNF section on lambdas, and the
  reference page document this precisely.
- [ ] **Operator `?` uses internal exception**, correct but slower
  than expanded early-return. Optimisation. P2

---

## Code-quality maintenance (P2)

- [ ] **Split `analyzer.py` (2800+ lines)** into
  `analyzer/discipline.py`, `analyzer/inference.py`,
  `analyzer/dispatch.py`, etc. Currently navigable but starting to
  feel large.
- [ ] **Error-message audit**, top 10 most common messages: are
  they precise? Do they suggest fixes? Some are too terse.
- [ ] **Analyzer performance**, no benchmarks. Only worth attacking
  if someone reports slowness.
- [ ] **Test-coverage review**, `coverage.py` run + identify which
  parts of the analyzer are under-tested.

---

## PhD-aligned work (P1, when it makes sense)

Capa as artefact in the SBOM Governance thesis:

- [ ] **SPDX 2.3 parser in Capa**, proves Capa can mex with the
  real SBOM format. Becomes a thesis chapter on representation.
  ⏱ 1 week
- [ ] **CycloneDX 1.5 parser in Capa**, same story.
- [ ] **`capability Provenance` (user-defined)**, capability that
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

- [x] **`CONTRIBUTING.md`**, how to file an issue, what makes a good
  PR, dev setup, compiler structure, what kinds of contributions help
  and what does not currently fit.
- [x] **`CHANGELOG.md`**, Keep-a-Changelog format starting at
  `v0.2.0-alpha` (the first tagged release) with an `[Unreleased]`
  section for the post-tag security + governance work.
- [x] **Issue / PR templates** in `.github/`, two YAML issue forms
  (bug, feature) with required fields, a `config.yml` that disables
  blank issues and contact-links to security advisories + discussions,
  plus a `PULL_REQUEST_TEMPLATE.md`.
- [x] **`CODE_OF_CONDUCT.md`**, adopts Contributor Covenant 2.1 by
  reference with maintainer contact for reports.
- [x] **Security policy**, `SECURITY.md` with how to report
  vulnerabilities. Lists in/out-of-scope issues, the GitHub private
  advisory channel, supported versions, disclosure flow.
- [x] **Flip repo to public**, `gh repo edit --visibility public`.
  Tagged `v0.2.0-alpha` first.
- [x] **Repo security hardening**, Dependabot vulnerability alerts +
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
