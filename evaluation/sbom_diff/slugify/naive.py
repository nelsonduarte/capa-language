"""A naive Python URL slug normaliser, of the shape that appears
in many web Python codebases (python-slugify has ~6M downloads/
month on PyPI; this is the core of its public API).

The signature `slugify(text: str, max_length: int | None = None) -> str`
exercises NO capabilities at all - the function is pure. But a
PURL-based SBOM emitted by syft / pip-licenses for this file
would list `re` and `unicodedata` as imports without any
per-function attribution. The Capa equivalent (see `capa.capa`)
proves that not only the public function but every helper is
purity-verified by the compiler.

This file is the asymmetry case in the SBOM-diff study: pip-
based tooling cannot distinguish "imports a stdlib module" from
"exercises that module's capability surface". Capa can.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import re
import unicodedata


def slugify(text: str, max_length: int | None = None) -> str:
    # Step 1: Unicode-normalise (NFKD) and drop combining marks.
    # Categories starting with "M" are combining marks; stripping
    # them turns "Olá" into "Ola", "café" into "cafe", etc.
    normalised = unicodedata.normalize("NFKD", text)
    stripped = "".join(
        ch for ch in normalised
        if not unicodedata.category(ch).startswith("M")
    )

    # Step 2: lower-case the result.
    lowered = stripped.lower()

    # Step 3: replace any run of non-alphanumeric characters with
    # a single dash. `\W` here would also match underscore as a
    # word character; the slugify convention is letters + digits
    # only, so an explicit class is used.
    dashed = re.sub(r"[^a-z0-9]+", "-", lowered)

    # Step 4: trim leading and trailing dashes that the previous
    # step may have introduced at the string boundaries.
    trimmed = dashed.strip("-")

    # Step 5: optional length cap. The python-slugify convention
    # is to truncate on a word boundary; the simpler form here is
    # a hard cut followed by another dash-trim so we never end on
    # a dangling separator.
    if max_length is not None and len(trimmed) > max_length:
        trimmed = trimmed[:max_length].rstrip("-")

    return trimmed


# A PURL-based SBOM emitted by syft / pip-licenses for this file
# would list `re` and `unicodedata` as imports. Both are stdlib
# modules; neither is actually exercising any authority (no Fs,
# no Env, no Net, no Stdio). The naive SBOM over-attributes: it
# cannot tell that the imports are pure helpers. The Capa
# equivalent declares zero capabilities per function and the
# compiler enforces it.
