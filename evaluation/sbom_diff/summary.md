# SBOM diff study: capability-aware vs PURL

Capability-aware Capa SBOMs encode strictly more information than PURL SBOMs for libraries that exercise any capability. Every PURL fact (the set of imported modules that map to capability-bearing standard-library surface) is recoverable from the Capa SBOM, and the Capa SBOM additionally reports per-function attribution that the PURL view cannot. The table below shows this across 20 pairs.

## Per-pair results

| Library | Capa functions (pure / with caps / total) | Capa caps declared | Per-fn (fn x cap) bits | Naive Python imports | PURL cap-bearing imports |
|---|---|---|---:|---|---|
| colorama | 8 / 1 / 9 | Stdio | 1 | *(none)* | *(none)* |
| config_loader | 3 / 5 / 8 | Env, Fs, Net, Stdio | 7 | json, os, urllib.request | os, urllib.request |
| csv_parser | 6 / 1 / 7 | Stdio | 1 | *(none)* | *(none)* |
| disk_cache | 3 / 3 / 6 | Clock, Fs, Stdio | 5 | os, time | os, time |
| dotenv | 2 / 4 / 6 | Env, Fs, Stdio | 5 | os | os |
| env_loader | 2 / 3 / 5 | Env, Stdio | 4 | os | os |
| glob_walker | 3 / 2 / 5 | Fs, Stdio | 2 | glob, os | glob, os |
| http_retry | 1 / 4 / 5 | Clock, Net, Stdio | 5 | time, urllib.error, urllib.request | time, urllib.error, urllib.request |
| humanize | 6 / 1 / 7 | Stdio | 1 | *(none)* | *(none)* |
| ini_loader | 3 / 2 / 5 | Fs, Stdio | 2 | *(none)* | *(none)* |
| log_forwarder | 2 / 4 / 6 | Fs, Net, Stdio | 5 | json, urllib.request | urllib.request |
| pathspec | 6 / 1 / 7 | Stdio | 1 | re | *(none)* |
| rate_limiter | 3 / 3 / 6 | Clock, Stdio | 3 | time | time |
| secret_rotator | 2 / 3 / 5 | Clock, Env, Stdio | 5 | os, time | os, time |
| session_token | 4 / 4 / 8 | Clock, Random, Stdio | 5 | secrets, time | secrets, time |
| short_uuid | 2 / 2 / 4 | Random, Stdio | 3 | secrets | secrets |
| slugify | 4 / 1 / 5 | Stdio | 1 | re, unicodedata | *(none)* |
| tabulate | 8 / 1 / 9 | Stdio | 1 | typing | *(none)* |
| textwrap | 3 / 1 / 4 | Stdio | 1 | *(none)* | *(none)* |
| url_fetch | 2 / 3 / 5 | Net, Stdio | 3 | json, urllib.request | urllib.request |
| **TOTAL** | **73 / 49 / 122** | **Clock, Env, Fs, Net, Random, Stdio** | **61** | **glob, json, os, re, secrets, time, typing, unicodedata, urllib.error, urllib.request** | **glob, os, secrets, time, urllib.error, urllib.request** |

## Per-function attribution density

`per_fn_info_bits` counts the number of (function, capability) declarations a Capa SBOM exposes; each such fact is of the form "this specific function exercises this specific capability" and has no counterpart in a PURL SBOM, which only attributes capability surface at the package level. For the current corpus the aggregate is 61 such facts across 20 pairs.

## Asymmetry cases

Two shapes of asymmetry appear in the corpus: (a) PURL lists cap-bearing modules and Capa narrows the attribution by proving some functions in the package are pure, and (b) PURL lists modules that do not carry capabilities at all (over-attribution) and Capa attributes zero authority to the corresponding functions. In both shapes the Capa SBOM proves something the PURL view cannot express.

- `config_loader`: 3 of 8 Capa functions are compiler-verified pure; a PURL SBOM listing `json, os, urllib.request` (of which `os, urllib.request` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `disk_cache`: 3 of 6 Capa functions are compiler-verified pure; a PURL SBOM listing `os, time` (of which `os, time` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `dotenv`: 2 of 6 Capa functions are compiler-verified pure; a PURL SBOM listing `os` (of which `os` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `env_loader`: 2 of 5 Capa functions are compiler-verified pure; a PURL SBOM listing `os` (of which `os` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `glob_walker`: 3 of 5 Capa functions are compiler-verified pure; a PURL SBOM listing `glob, os` (of which `glob, os` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `http_retry`: 1 of 5 Capa functions are compiler-verified pure; a PURL SBOM listing `time, urllib.error, urllib.request` (of which `time, urllib.error, urllib.request` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `log_forwarder`: 2 of 6 Capa functions are compiler-verified pure; a PURL SBOM listing `json, urllib.request` (of which `urllib.request` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `pathspec`: 6 of 7 Capa functions are compiler-verified pure; a PURL SBOM listing `re` over-attributes (none of these imports exercise any capability) while Capa attributes zero authority to 6 of 7 functions.
- `rate_limiter`: 3 of 6 Capa functions are compiler-verified pure; a PURL SBOM listing `time` (of which `time` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `secret_rotator`: 2 of 5 Capa functions are compiler-verified pure; a PURL SBOM listing `os, time` (of which `os, time` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `session_token`: 4 of 8 Capa functions are compiler-verified pure; a PURL SBOM listing `secrets, time` (of which `secrets, time` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `short_uuid`: 2 of 4 Capa functions are compiler-verified pure; a PURL SBOM listing `secrets` (of which `secrets` are cap-bearing) cannot make the pure-vs-impure split per-function.
- `slugify`: 4 of 5 Capa functions are compiler-verified pure; a PURL SBOM listing `re, unicodedata` over-attributes (none of these imports exercise any capability) while Capa attributes zero authority to 4 of 5 functions.
- `tabulate`: 8 of 9 Capa functions are compiler-verified pure; a PURL SBOM listing `typing` over-attributes (none of these imports exercise any capability) while Capa attributes zero authority to 8 of 9 functions.
- `url_fetch`: 2 of 5 Capa functions are compiler-verified pure; a PURL SBOM listing `json, urllib.request` (of which `urllib.request` are cap-bearing) cannot make the pure-vs-impure split per-function.

## What this study does NOT claim

- The Capa versions are hand-written. No Python-to-Capa transliteration tool exists; each pair is a faithful representation of the library's public-API capability shape, not a feature-by-feature port.
- The naive Python is illustrative. It captures the typical shape (one signature, conflated authorities) that appears in many real codebases, not the best-engineered form. Disciplined Python (dependency injection, explicit handle-passing) lacks Capa's static guarantee but narrows the gap.
- Sample size is small relative to PyPI. The corpus aims for 10-20 libraries spanning the capability axes; PyPI has hundreds of thousands. The claim is about the mechanism's information gain, not statistical representativeness of all Python code.

## Reproducibility

Generated by `evaluation/sbom_diff/summary.py` from `evaluation/sbom_diff/results.csv`. To regenerate from raw sources:

    .venv/Scripts/python -m evaluation.sbom_diff.harness
    .venv/Scripts/python -m evaluation.sbom_diff.summary
