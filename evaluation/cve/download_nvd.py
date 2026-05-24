"""Download the NVD JSON 2.0 bulk feeds the CVE study slices.

Idempotent: if a yearly feed is already present in
``evaluation/cve/cache/`` AND its SHA256 matches the value in
``MANIFEST.sha256``, the download is skipped. The first run on a
fresh clone populates the MANIFEST with the freshly-computed
checksums and writes them back; subsequent runs verify-only.

Defensive against rate limiting: the NVD bulk feeds are served
without an API key but bare-IP fetches occasionally rate-limit
after the third request. The script sleeps 1.5s between fetches
to stay well under any documented threshold.

Network failure mode: if a fetch fails (404, timeout, partial
content), the script prints the failed URL and exits non-zero
WITHOUT touching the cache. A half-downloaded file would falsify
the dataset, so all-or-nothing is the contract.

Usage:
    python -m evaluation.cve.download_nvd
    python -m evaluation.cve.download_nvd --verify-only
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

YEARS = list(range(2018, 2025))  # 2018-2024 inclusive
NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"

CVE_DIR = Path(__file__).parent
CACHE_DIR = CVE_DIR / "cache"
MANIFEST_PATH = CVE_DIR / "MANIFEST.sha256"

REQUEST_DELAY_S = 1.5
TIMEOUT_S = 60.0


@dataclass
class ManifestEntry:
    """One row in MANIFEST.sha256."""

    sha256: str  # empty string if not yet known
    filename: str
    url: str


def _sha256(path: Path) -> str:
    """SHA256 of a file, streamed to support multi-MB feeds without
    loading them into memory."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_manifest() -> tuple[list[str], dict[str, ManifestEntry]]:
    """Return (preamble_lines, entry_by_filename). Preamble is the
    comment header before the first data line; entry_by_filename
    maps the filename to its ManifestEntry. Entries with an
    unfilled checksum (literal '(sha256)' marker) are kept so the
    download step can populate them."""
    lines = MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
    preamble: list[str] = []
    entries: dict[str, ManifestEntry] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            preamble.append(line)
            continue
        parts = stripped.split(None, 2)
        if len(parts) != 3:
            preamble.append(line)
            continue
        sha, name, url = parts
        if sha == "(sha256)":
            sha = ""
        entries[name] = ManifestEntry(sha256=sha, filename=name, url=url)
    return preamble, entries


def _format_manifest(
    preamble: list[str], entries: dict[str, ManifestEntry],
) -> str:
    """Render the manifest back to disk. Preamble is preserved
    verbatim; entries are sorted by filename for stable diffs.

    Replaces any `# (sha256)  <filename>  <url>` placeholder line
    in the preamble with the populated entry (so the file shape
    matches what a fresh clone sees: a single data line per
    yearly feed, no orphan comments)."""
    populated_lines = [
        f"{e.sha256}  {e.filename}  {e.url}"
        for e in sorted(entries.values(), key=lambda x: x.filename)
    ]
    cleaned_preamble: list[str] = []
    for line in preamble:
        stripped = line.strip()
        is_placeholder = (
            stripped.startswith("# (sha256)")
            and any(name in stripped for name in entries)
        )
        if not is_placeholder:
            cleaned_preamble.append(line)
    return "\n".join(cleaned_preamble + populated_lines) + "\n"


def _download(url: str, dest: Path) -> None:
    """Stream a URL to a local path. Writes to a ``.tmp`` sibling
    and renames on success so a partial fetch never leaves a
    half-file in the cache."""
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    req = urllib.request.Request(
        url,
        headers={
            # Default urllib UA gets rate-limited / 403'd by NVD;
            # advertise as a reproducible-research harness.
            "User-Agent": "capa-evaluation-harness/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
        with tmp.open("wb") as out:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                out.write(chunk)
    tmp.replace(dest)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Download + verify NVD feeds")
    p.add_argument(
        "--verify-only",
        action="store_true",
        help="do not download; only verify existing cache against MANIFEST",
    )
    args = p.parse_args(argv)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    preamble, entries = _parse_manifest()

    # Seed missing entries for years that the manifest does not
    # yet mention. Keeps the script self-bootstrapping if a year
    # is added to YEARS without manifest pre-population.
    for year in YEARS:
        filename = f"nvdcve-2.0-{year}.json.gz"
        if filename not in entries:
            entries[filename] = ManifestEntry(
                sha256="",
                filename=filename,
                url=f"{NVD_BASE}/{filename}",
            )

    manifest_dirty = False
    for year in YEARS:
        filename = f"nvdcve-2.0-{year}.json.gz"
        dest = CACHE_DIR / filename
        entry = entries[filename]

        if dest.exists():
            actual = _sha256(dest)
            if entry.sha256 and actual != entry.sha256:
                print(
                    f"[nvd] checksum mismatch for {filename}: "
                    f"expected {entry.sha256[:12]}.., got {actual[:12]}..; "
                    f"refusing to silently re-download",
                    file=sys.stderr,
                )
                return 2
            if not entry.sha256:
                # Cache present but manifest empty: adopt the cached
                # checksum as the pinned value.
                entry.sha256 = actual
                manifest_dirty = True
                print(f"[nvd] pinned {filename}  sha={actual[:12]}..")
            else:
                print(f"[nvd] {filename}  ok  sha={actual[:12]}..")
            continue

        if args.verify_only:
            print(
                f"[nvd] {filename} MISSING (verify-only mode; "
                f"run without --verify-only to download)",
                file=sys.stderr,
            )
            return 3

        print(f"[nvd] fetching {entry.url}")
        try:
            _download(entry.url, dest)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            print(f"[nvd] FAILED to fetch {entry.url}: {e}", file=sys.stderr)
            return 4
        actual = _sha256(dest)
        if entry.sha256 and actual != entry.sha256:
            print(
                f"[nvd] freshly downloaded {filename} has sha {actual[:12]}.. "
                f"but MANIFEST expected {entry.sha256[:12]}..; refusing",
                file=sys.stderr,
            )
            dest.unlink()
            return 5
        entry.sha256 = actual
        manifest_dirty = True
        print(f"[nvd] downloaded {filename}  sha={actual[:12]}..")
        time.sleep(REQUEST_DELAY_S)

    if manifest_dirty:
        MANIFEST_PATH.write_text(
            _format_manifest(preamble, entries), encoding="utf-8",
        )
        print(f"[nvd] manifest updated: {MANIFEST_PATH}")
    else:
        print("[nvd] manifest unchanged")

    return 0


if __name__ == "__main__":
    sys.exit(main())
