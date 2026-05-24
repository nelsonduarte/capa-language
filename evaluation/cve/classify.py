"""Automatic first-pass CVE classification.

Walks the NVD JSON 2.0 yearly feeds (2018-2024) in
``evaluation/cve/cache/``, filters to the capability-relevant CWE
subset + HIGH/CRITICAL CVSS, samples N=150 uniformly without
replacement (deterministic seed), and assigns each surviving CVE
to one of six buckets via CWE + keyword heuristics.

Output: ``evaluation/cve/decisions.csv`` with one row per sampled
CVE. The manual review pass (slice 4) reads this CSV, refines the
``bucket`` column for the load-bearing buckets (STRUCTURAL_REJECT,
ATTENUATION_MITIGATED), and fills the ``reviewer_note`` column.

Reproducibility: seed=20260524, sample size=150. Both are
constants below; changing them invalidates the dataset and any
paper figures derived from it.

The taxonomy:

- ``STRUCTURAL_REJECT``: the exploit needs a capability the
  legitimate function would not have declared. Capa's static
  discipline rejects the call shape, blocking the exploit before
  it can run.
- ``ATTENUATION_MITIGATED``: the capability IS legitimately
  needed, but attenuation (Fs.restrict_to, Net.restrict_to)
  reduces blast radius enough that the exploit cannot reach
  sensitive targets.
- ``OUT_OF_SCOPE_MEMORY``: the bug is a memory-safety / UB issue
  in unsafe code or a C dependency; Capa's capability layer has
  no opinion.
- ``OUT_OF_SCOPE_LOGIC``: the bug is an application-layer
  logic / auth flaw; capabilities don't help here.
- ``OUT_OF_SCOPE_BELOW_LANG``: the bug is in build tooling, a
  linker, a kernel module, or another artefact below the
  language layer.
- ``UNCLEAR``: not enough signal in the NVD entry alone; the
  manual reviewer decides.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import random
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

from evaluation.cve.download_nvd import CACHE_DIR, YEARS

SEED = 20260524
SAMPLE_SIZE = 150

CWE_STRUCTURAL = {
    "CWE-94",   # Code Injection
    "CWE-78",   # OS Command Injection
    "CWE-77",   # Command Injection
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-611",  # XXE (XML External Entity)
    "CWE-918",  # SSRF
    "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-1357", # Reliance on Insufficiently Trustworthy Component
}

CWE_ATTENUATION = {
    "CWE-22",   # Path Traversal
    "CWE-345",  # Insufficient Verification of Data Authenticity
    "CWE-444",  # HTTP Request/Response Smuggling
    "CWE-506",  # Embedded Malicious Code (supply-chain)
    "CWE-494",  # Download of Code Without Integrity Check
}

CWE_FILTER = CWE_STRUCTURAL | CWE_ATTENUATION

MIN_CVSS_SCORE = 7.0  # HIGH + CRITICAL only

# Reference-host filter: at least one URL host must match one of
# these prefixes (or the reference must carry a Patch / Vendor
# Advisory tag). Restricts the sample to bugs in language-level
# packages or first-party services, where Capa's discipline could
# meaningfully apply.
REFERENCE_HOST_MARKERS = (
    "npmjs.com", "pypi.org", "github.com", "rubygems.org",
    "crates.io", "packagist.org", "pkg.go.dev", "nuget.org",
    "ghsa", "go-review.googlesource.com",
)

# Keywords that, if found in the description, override the CWE
# bucket and re-route to a more specific out-of-scope bucket.
# Used by _auto_bucket to catch CVEs that pass the CWE filter on
# paper but are actually memory / logic / below-lang.
RE_MEMORY = re.compile(
    r"\b(buffer overflow|use[- ]after[- ]free|double free|"
    r"heap overflow|stack overflow|out[- ]of[- ]bounds|"
    r"null pointer|memory corruption|integer overflow)\b",
    re.IGNORECASE,
)
RE_LOGIC = re.compile(
    r"\b(authentication bypass|authorization bypass|"
    r"hardcoded credentials|broken access control|"
    r"information disclosure)\b",
    re.IGNORECASE,
)
RE_BELOW_LANG = re.compile(
    r"\b(linux kernel|systemd|openssl|glibc|musl|"
    r"linker|loader|firmware|bootloader|hypervisor)\b",
    re.IGNORECASE,
)


@dataclass
class Decision:
    """One row in decisions.csv."""

    cve_id: str
    year: int
    cvss_score: float
    severity: str
    cwes: str           # comma-separated CWE-IDs
    bucket: str         # one of the six taxonomy strings
    auto_reason: str    # one-line trace of why the bucket was assigned
    description: str    # NVD English description, truncated
    references: str     # pipe-separated URL hosts
    reviewer_note: str  # always empty here; filled by slice 4


def _extract_description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _extract_cwes(cve: dict) -> list[str]:
    out: set[str] = set()
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                out.add(v)
    return sorted(out)


def _extract_cvss(cve: dict) -> tuple[float, str]:
    """Return (score, severity). Prefers CVSS v3.1, falls back to
    v3.0, then v2. Returns (0.0, '') if no metrics present."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            return (
                float(data.get("baseScore", 0.0)),
                str(data.get("baseSeverity", "")),
            )
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        data = metrics["cvssMetricV2"][0].get("cvssData", {})
        score = float(data.get("baseScore", 0.0))
        sev = (
            "HIGH" if score >= 7.0
            else "MEDIUM" if score >= 4.0
            else "LOW"
        )
        return (score, sev)
    return (0.0, "")


def _ref_hosts(cve: dict) -> list[str]:
    """Return the list of unique reference host strings, lowercased."""
    seen: set[str] = set()
    for r in cve.get("references", []):
        url = r.get("url", "")
        # Crude host extraction; good enough for the filter.
        m = re.match(r"https?://([^/]+)/", url)
        if m:
            seen.add(m.group(1).lower())
    return sorted(seen)


def _passes_reference_filter(cve: dict) -> bool:
    hosts = _ref_hosts(cve)
    if not hosts:
        # No references: not necessarily a problem; check tags.
        for r in cve.get("references", []):
            tags = r.get("tags", [])
            if "Patch" in tags or "Vendor Advisory" in tags:
                return True
        return False
    for h in hosts:
        for marker in REFERENCE_HOST_MARKERS:
            if marker in h:
                return True
    return False


def _passes_filter(cve: dict) -> bool:
    cwes = set(_extract_cwes(cve))
    if not (cwes & CWE_FILTER):
        return False
    score, _ = _extract_cvss(cve)
    if score < MIN_CVSS_SCORE:
        return False
    if not _passes_reference_filter(cve):
        return False
    return True


def _auto_bucket(cve: dict) -> tuple[str, str]:
    """Return (bucket, reason). The bucket is one of the six
    taxonomy strings; reason is a one-line trace for the CSV.

    Resolution order:

    1. CWE-decisive structural CWEs (78, 77, 94, 502, 611, 918,
       829, 1357) bind first. These categories' definitions
       already constrain the bug class enough that downstream
       keyword matches on the *consequence* (e.g. "information
       disclosure" as the impact of an XXE) cannot override the
       structural-reject classification. Capa's discipline
       rejects the *means*, regardless of the consequence.
    2. Memory / below-language keyword overrides apply BEFORE the
       attenuation set. If a path-traversal CVE description
       screams 'use-after-free' the right call is memory-bug.
    3. Attenuation CWEs (22, 345, 444, 506, 494) bind last among
       the CWE classifications.
    4. Logic-keyword override is reserved for CVEs that have no
       structural/attenuation CWE but still slipped through some
       reference / CVSS filter; treat them as logic-layer issues.
    """
    desc = _extract_description(cve)
    cwes = set(_extract_cwes(cve))

    structural = cwes & CWE_STRUCTURAL
    attenuated = cwes & CWE_ATTENUATION

    # Structural CWEs bind first: the means-of-attack is the
    # classification, the impact is not. (Pre-tightening, the
    # description-keyword override misrouted CWE-611 XXE entries
    # to OUT_OF_SCOPE_LOGIC because their impact line mentioned
    # 'information disclosure'.)
    if structural and not RE_MEMORY.search(desc) and not RE_BELOW_LANG.search(desc):
        return (
            "STRUCTURAL_REJECT",
            f"CWE match in structural set: {sorted(structural)}",
        )

    if RE_MEMORY.search(desc):
        return ("OUT_OF_SCOPE_MEMORY", "description matches memory-bug keywords")
    if RE_BELOW_LANG.search(desc):
        return ("OUT_OF_SCOPE_BELOW_LANG", "description matches below-language artefact")

    if structural and attenuated:
        # Mixed: prefer the stricter STRUCTURAL_REJECT.
        return (
            "STRUCTURAL_REJECT",
            f"mixed CWEs; structural={sorted(structural)} "
            f"attenuated={sorted(attenuated)}; defaulted to STRUCTURAL_REJECT",
        )
    if attenuated:
        return (
            "ATTENUATION_MITIGATED",
            f"CWE match in attenuation set: {sorted(attenuated)}",
        )

    if RE_LOGIC.search(desc):
        return ("OUT_OF_SCOPE_LOGIC", "description matches logic/auth keywords")
    return ("UNCLEAR", "passed filter but no decisive CWE / keyword match")


def _load_year(year: int) -> list[dict]:
    """Load the CVE list from a yearly NVD gz feed."""
    path = CACHE_DIR / f"nvdcve-2.0-{year}.json.gz"
    with gzip.open(path) as f:
        data = json.load(f)
    return [v["cve"] for v in data.get("vulnerabilities", [])]


def _build_candidates() -> list[tuple[int, dict]]:
    """Walk every year, return (year, cve) for CVEs that pass the
    filter. Stable order: ascending by year, then by id."""
    out: list[tuple[int, dict]] = []
    for year in YEARS:
        cves = _load_year(year)
        kept = [c for c in cves if _passes_filter(c)]
        kept.sort(key=lambda c: c["id"])
        for c in kept:
            out.append((year, c))
    return out


def _sample(
    candidates: list[tuple[int, dict]],
    n: int,
    seed: int,
) -> list[tuple[int, dict]]:
    """Sample ``n`` uniformly without replacement using ``seed``.
    If fewer than ``n`` candidates exist, return all of them."""
    rng = random.Random(seed)
    if len(candidates) <= n:
        return list(candidates)
    return rng.sample(candidates, n)


def classify_all() -> list[Decision]:
    candidates = _build_candidates()
    print(
        f"[classify] {len(candidates)} CVEs pass the filter "
        f"(years {YEARS[0]}-{YEARS[-1]}, "
        f"CVSS >= {MIN_CVSS_SCORE}, CWE in {sorted(CWE_FILTER)})",
        file=sys.stderr,
    )
    sample = _sample(candidates, SAMPLE_SIZE, SEED)
    sample.sort(key=lambda t: t[1]["id"])
    out: list[Decision] = []
    for year, cve in sample:
        bucket, reason = _auto_bucket(cve)
        score, severity = _extract_cvss(cve)
        desc = _extract_description(cve)
        out.append(Decision(
            cve_id=cve["id"],
            year=year,
            cvss_score=score,
            severity=severity,
            cwes=",".join(_extract_cwes(cve)),
            bucket=bucket,
            auto_reason=reason,
            description=desc[:400],
            references="|".join(_ref_hosts(cve)),
            reviewer_note="",
        ))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="CVE classification pass")
    p.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "decisions.csv",
    )
    args = p.parse_args(argv)

    decisions = classify_all()
    counts: dict[str, int] = {}
    for d in decisions:
        counts[d.bucket] = counts.get(d.bucket, 0) + 1

    fieldnames = list(asdict(decisions[0]).keys()) if decisions else []
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in decisions:
            writer.writerow(asdict(d))

    print(f"[classify] wrote {len(decisions)} rows to {args.out}")
    print("[classify] bucket distribution:")
    for bucket in sorted(counts):
        print(f"  {bucket}: {counts[bucket]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
