"""A naive Python short-ID generator, of the shape that appears
in many Python services that mint URL-safe identifiers
(`shortuuid` has ~3M downloads/month on PyPI; `nanoid` is the
other widely-used variant of this pattern). This is the core of
their public API.

The signature `generate(length: int = 22) -> str` tells the
reader nothing about which capabilities are exercised. A reviewer
reading the import block at the top of the file sees `secrets`; a
reviewer reading the function body finds that the function pulls
bytes from the OS CSPRNG to pick characters out of a fixed
alphabet. The CycloneDX SBOM emitted by pip-licenses / syft for
this script would list `secrets` as an import, with no
per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic into
functions, each declaring the capabilities it uses in its
parameter list:

  default_alphabet  : pure
  is_valid_length   : pure
  generate          : Random only

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import secrets

# Default shortuuid alphabet: 57 visually unambiguous characters.
# Excludes `0`, `1`, `O`, `I`, and `l` to avoid the confusions
# that bite users when they read an ID off a screen and type it
# into a form.
DEFAULT_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def validate_length(length: int) -> None:
    # Pure helper. No randomness, no I/O, no globals; the only job
    # is to reject obviously bad inputs before the caller burns
    # CSPRNG draws on them.
    if length < 1:
        raise ValueError(f"length must be >= 1, got {length}")


def generate(length: int = 22) -> str:
    # Step 1: validate the requested length. Pure.
    validate_length(length)

    # Step 2: draw `length` characters from the alphabet using the
    # OS CSPRNG. Exercises Random.
    return "".join(
        secrets.choice(DEFAULT_ALPHABET) for _ in range(length)
    )


# A reviewer auditing this function from the signature alone has
# no way to know that it reads from the OS CSPRNG. The randomness
# is buried in the body. A CVE-style swap that replaced
# `secrets.choice` with a `random.choice` seeded from the current
# time (silently downgrading security) would not change the
# signature; it would not show up in any pip-based SBOM beyond
# swapping one stdlib import for another. The Capa equivalent
# names `Random` per-function and proves the validator + alphabet
# helpers are pure.
