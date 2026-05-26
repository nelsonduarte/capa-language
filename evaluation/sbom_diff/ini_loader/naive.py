"""A naive Python INI/config-file loader, of the shape that
appears in many Python applications that hand-roll a small
config reader instead of pulling in `configparser` (and of the
shape `configparser` and `iniparse` themselves expose to the
caller).

The signature `load_ini(path: str) -> dict[str, dict[str, str]]`
tells the reader nothing about which capabilities are
exercised. A reviewer reading the import block at the top of
the file sees nothing: this loader has no third-party imports
and uses only `open()` from the language builtins. A reviewer
reading the function body finds that the function reads a file
from disk. The CycloneDX SBOM emitted by pip-licenses / syft
for this script would list NOTHING: an empty components array.

The Capa equivalent (see `capa.capa`) splits the same logic
into two functions, each declaring the capabilities it uses
in its parameter list:

  parse_ini_text   : pure
  load_ini         : Fs only

Even in a single-capability library the split matters: the
parser is unit-testable without any filesystem handle, and a
reviewer reading `parse_ini_text`'s signature knows immediately
that it cannot read the disk.

Format choice: lines outside any section are dropped (we do
NOT emit a default `""` section). The first `[name]` line
opens a section; subsequent `key = value` lines accumulate
into the most recent section.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""


def load_ini(path: str) -> dict:
    # Step 1: read the INI file from disk. Exercises Fs.
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return {}

    # Step 2: parse [section] / key = value lines, skipping
    # blanks and `#` / `;` comments.
    out: dict = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            if current not in out:
                out[current] = {}
            continue
        if current is None:
            # Key outside any section: dropped.
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[current][key.strip()] = value.strip()

    return out


# A reviewer auditing this function from the signature alone
# has no way to know that it reads files. The PURL SBOM proxy
# for this file is empty (no third-party imports, no
# capability-bearing stdlib imports either) - yet the function
# still mixes pure parsing logic with file I/O under one name.
# A CVE-style attack that swapped the file-read for a remote
# fetch (adding Net) would not change the signature, and
# crucially would not change the PURL SBOM either: there were
# no imports to list before, so there are no new ones to flag.
# Capa exposes the split structurally.
