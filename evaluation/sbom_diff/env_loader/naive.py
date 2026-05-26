"""A naive Python "settings from environment" loader, of the
shape that appears in almost every cloud-deployed Python
service (Django, Flask, FastAPI, and the dedicated PyPI
libraries `environs`, `python-decouple`, `pydantic-settings`
all expose this pattern as their core public API).

The signature `load_settings(prefix: str = 'APP_', required:
list[str] | None = None) -> dict[str, str]` tells the reader
nothing about which capabilities are exercised. A reviewer
reading the import block at the top of the file sees `os`; a
reviewer reading the function body finds that the function
iterates the whole process environment AND validates the
result. The CycloneDX SBOM emitted by pip-licenses / syft
for this script would list `os` as an import, with no
per-function attribution and no indication that the
validation step is logically pure.

The Capa equivalent (see `capa.capa`) splits the same logic
into three functions, each declaring the capabilities it
uses in its parameter list:

  strip_prefix       : pure
  validate_required  : pure
  load_settings      : Env only

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import os


def _strip_prefix(key: str, prefix: str) -> str:
    # Pure helper. Strip the prefix and lowercase the remainder.
    # No capability use; takes a string, returns a string.
    return key[len(prefix):].lower()


def load_settings(
    prefix: str = "APP_",
    required: list | None = None,
) -> dict:
    # Step 1: iterate os.environ, picking keys that begin with
    # `prefix` and stripping/lowercasing into the result dict.
    # Exercises Env (reads the entire process environment).
    out: dict = {}
    for key, value in os.environ.items():
        if key.startswith(prefix):
            out[_strip_prefix(key, prefix)] = value

    # Step 2: validate that every required key is present in the
    # result. Logically pure - operates on the already-loaded
    # dict and the caller-supplied list - but conflated under
    # the same signature as the Env-reading step above.
    if required is not None:
        for req in required:
            if req not in out:
                raise KeyError(f"missing required setting: {req}")

    return out


# A reviewer auditing this function from the signature alone
# has no way to know that it reads the whole process
# environment, nor that the validation half of the body is
# pure and could be unit-tested with no env access at all.
# The PURL SBOM proxy for this file lists `os` (a
# capability-bearing stdlib module) - a single coarse fact
# attached to the file, not to either of the two distinct
# concerns the function mixes. Capa attributes Env to
# `load_settings` per-function and proves the prefix-stripping
# and required-key validation helpers are pure.
