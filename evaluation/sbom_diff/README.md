# SBOM-diff at scale: capability-aware vs PURL

Quantitative companion to [`docs/empirical_micro.md`](../../docs/empirical_micro.md).
That document shows the mechanism on **one** library; this study
applies the same comparison across **N** real-world-shaped Python
libraries and reports aggregates.

## Headline claim under test

> For libraries that exercise any capability (Fs / Env / Net /
> Proc / Stdio / Clock / Random / Db), a capability-aware Capa
> SBOM is a strict information gain over a PURL-based SBOM
> emitted from the equivalent hand-Python.

"Strict information gain" means: every fact a PURL SBOM
encodes (the set of imported modules that correspond to
capabilities) is recoverable from the Capa SBOM, and the Capa
SBOM additionally reports per-function attribution that the
PURL SBOM cannot.

## Methodology

Each library pair lives in its own sub-directory:

```
evaluation/sbom_diff/<lib>/
  naive.py    # typical hand-Python shape (one signature, conflated authorities)
  capa.capa   # Capa transliteration with per-function capability declarations
  README.md   # what the library does, why it's representative, expected cap surface
```

The harness ([`harness.py`](harness.py)):

1. Runs `capa --cyclonedx <lib>/capa.capa` on each Capa
   transliteration, parsing the resulting per-function
   `capa:declared_capability` properties.
2. Reads `<lib>/naive.py` and extracts top-level imports as a
   PURL-style proxy ("which modules a PURL SBOM would list").
3. Computes per-pair metrics: total functions, functions with
   capability declarations, distinct capability kinds declared,
   PURL-attributed modules, capability kinds inferrable from
   PURLs alone.
4. Emits `results.csv` with one row per pair plus an aggregate
   row.

The summary script ([`summary.py`](summary.py)) consumes
`results.csv` and writes `summary.md` (a Markdown table fit to
paste into the paper's §5) plus a one-page README of
methodology + threats to validity.

## Library selection

The corpus targets the **shape** of capability-using Python
libraries that appear in production codebases:

| Library | Authority surface | Why representative |
|---|---|---|
| `config_loader` | Fs + Env + Net | The 12-factor microservice config pattern, ubiquitous in cloud Python apps. Same code as [`docs/empirical_micro.md`](../../docs/empirical_micro.md)'s headline pair, ported under this harness. |
| `dotenv` | Fs + Env | The python-dotenv pattern: parse a `.env` file and overlay onto the process environment. ~3M downloads/month on PyPI. |
| `slugify` | *(none)* | The python-slugify pattern: pure string transformation, NO capabilities. Asymmetry case: PURL SBOM lists `re` and `unicodedata` from stdlib (capability-bearing modules in general) when the actual function exercises neither. Capa SBOM correctly attributes zero. |

Slices 2-N add additional libraries from a curated PyPI sample
(`python-dotenv`, `python-slugify`, `tabulate`, `humanize`,
`shortuuid`, `pathspec`, `urlparse`, `tomli`, `colorama`,
`textwrap`, a small log forwarder, an HTTP retry decorator, an
ini loader, a path-glob walker, a config-from-environment loader,
a subprocess wrapper, a markdown subset, an email validator, a
basic feed parser subset, a YAML safe-load subset).

Selection criteria:

- Real PyPI library (named, not invented).
- Public API surface fits in ~50-300 LOC of Capa (full
  transliteration would be weeks per library; the core public
  API is what the SBOM-diff claim cares about).
- Spans at least one of the capability axes Capa tracks; pure
  baselines are included as asymmetry cases.

## What this study does NOT claim

1. **The Capa versions are hand-written.** Same caveat as
   [`docs/empirical_micro.md`](../../docs/empirical_micro.md):
   no Python-to-Capa transliteration tool exists. Each pair is
   a faithful representation of the library's public-API
   capability shape, not a feature-by-feature port.
2. **The naive Python is illustrative.** It captures the
   *typical* shape (one signature, conflated authorities) that
   appears in many real codebases, not the best-engineered
   form. Disciplined Python (dependency injection, explicit
   handle-passing) lacks Capa's static guarantee but narrows
   the gap.
3. **Sample size is small relative to PyPI.** The corpus aims
   for 10-20 libraries spanning the capability axes; PyPI has
   hundreds of thousands. The claim is about the *mechanism*'s
   information gain, not statistical representativeness of all
   Python code.

## Reproducing

From the repo root with the venv active:

```
.venv/Scripts/python -m evaluation.sbom_diff.harness
.venv/Scripts/python -m evaluation.sbom_diff.summary
```

`harness.py` writes `results.csv`; `summary.py` reads it and
writes `summary.md`.

## Status

| Slice | Status | Notes |
|---|---|---|
| 1 (scaffold + 3 pairs) | done 2026-05-26 | harness + summary green on `config_loader`, `dotenv`, `slugify` |
| 2-N (corpus expansion) | pending | each slice adds 2-4 library pairs |
| Final (paper figure) | pending | regenerate `summary.md` once N >= 10 |
