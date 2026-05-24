# Evaluation

Reproducible artefacts that back the empirical-evaluation section
(§5) of the Capa paper draft. Everything here is data + scripts,
no compiler code lives in this tree.

Three independent studies, each in its own sub-directory:

- [`fuzz/`](fuzz/) - capability-bypass attack panel. ~160 attack
  programs across 8 categories, each expected to be rejected by
  `capa --check` at static-analysis time. Surfaces soundness
  holes early.
- [`cve/`](cve/) - quantitative CVE-corpus classification. NVD
  2018-2024 slice, N=150, classified into
  `STRUCTURAL_REJECT` / `ATTENUATION_MITIGATED` /
  `OUT_OF_SCOPE_*` / `UNCLEAR` buckets. Reproducible from raw
  feed.
- [`runtime/`](runtime/) - runtime overhead micro+macro benchmarks
  across four backends (Capa --python, Capa --wasm via wasmtime,
  hand-Python, Node.js).

The harness uses a shared helper module
[`shared/runner_utils.py`](shared/runner_utils.py) (subprocess +
timing + CSV emit).

## Reproducing

From the repo root, with the venv active:

```
# fuzz panel (slice 1: one category smoke)
.venv/Scripts/python -m evaluation.fuzz.harness --category cat_fs_traversal

# full fuzz panel (slice 6)
.venv/Scripts/python -m evaluation.fuzz.harness --all

# CVE classification (slices 2-4)
.venv/Scripts/python -m evaluation.cve.download_nvd
.venv/Scripts/python -m evaluation.cve.classify
.venv/Scripts/python -m evaluation.cve.summary

# runtime benchmarks (slice 5)
.venv/Scripts/python -m evaluation.runtime.harness
.venv/Scripts/python -m evaluation.runtime.plot
```

Each command emits a `results.csv` next to itself and (for cve +
runtime) a `results.png` figure. The paper's §5 tables and plots
are produced from these CSVs.

## Status

| Slice | Status | Notes |
|---|---|---|
| 0 (soundness fix) | done 2026-05-24 | capability-forge bug found by slice-1 smoke before slice 1 even completed; fix in commit 67d9878 |
| 1 (scaffold + smoke) | done 2026-05-24 | fuzz harness lives in [`fuzz/`](fuzz/), category `cat_fs_traversal` x 3 attacks 3/3 rejected |
| 2 (NVD download) | done 2026-05-24 | 7 yearly feeds pinned in [`cve/MANIFEST.sha256`](cve/MANIFEST.sha256), 95 MB cache (gitignored) |
| 3 (auto-classify) | done 2026-05-24 | N=150 sample, 4305 candidates filtered; preliminary headline 97.3% Capa-relevant |
| 4 (manual + figures) | figures done 2026-05-24; manual review pending | [`cve/summary.md`](cve/summary.md) + [`cve/summary.png`](cve/summary.png) auto-generated. The manual reviewer pass on `decisions.csv` STRUCTURAL_REJECT / ATTENUATION_MITIGATED rows is the remaining work |
| 5 (runtime baselines) | done 2026-05-24 (Capa --python vs --wasm only) | hand-Python + Node baselines deferred; macro figure in [`runtime/results.png`](runtime/results.png); headline 1.52x Wasm overhead at cold-start macro scale |
| 6 (full fuzz panel) | pending | |
| 7 (paper polish) | pending | |

## Caveats for paper citation

The slice-3 / slice-4 CVE figures are the output of an
**automatic first-pass classifier**, not human review. Any paper
text that cites the 97.3% headline must declare the
single-reviewer + automatic-first-pass status as a
threat-to-validity (see paper §7). The manual review will refine
the load-bearing buckets and is expected to shift the number by
a few percentage points in either direction. Re-run
`python -m evaluation.cve.summary` after any manual edit to
`decisions.csv` to regenerate the figure.
