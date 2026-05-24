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
| 1 (scaffold + smoke) | in progress | this commit |
| 2 (NVD download) | pending | |
| 3 (auto-classify) | pending | |
| 4 (manual + figures) | pending | |
| 5 (runtime baselines) | pending | |
| 6 (full fuzz panel) | pending | |
| 7 (paper polish) | pending | |
