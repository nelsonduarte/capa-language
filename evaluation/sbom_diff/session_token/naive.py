"""A naive Python session-token mint-and-validate pair, of the
shape that appears in essentially every Python web framework's
session layer: `itsdangerous` (the Flask session signer; ~100M
downloads/month on PyPI as a Flask transitive dependency),
`pyjwt` (JWTs sign a payload whose `exp` claim is a unix
timestamp), `flask-login`'s remember-cookie token, and
`django.core.signing`. The exact code is illustrative; the
*pattern* (one function that mints a random token with an expiry
timestamp baked in, one function that parses the suffix and
compares it against the wall clock) is widespread.

The functional shape is a pair:
`generate_token(ttl_seconds: int = 3600) -> str` mints a token
of the form `"<random_id>.<expiry_ts>"`, and
`is_token_valid(token: str) -> bool` parses the suffix and
returns True iff the embedded timestamp is still in the future.
Both signatures hide the fact that the implementation draws from
the OS CSPRNG AND reads the wall clock; even the validator,
which a reviewer might assume is pure parsing, quietly calls
`time.time()`. A reviewer reading the import block at the top of
the file sees `secrets` and `time`; a reviewer reading the
function bodies finds that two of the five functions touch one
authority each. The CycloneDX SBOM emitted by pip-licenses /
syft for this script would list both imports, with no
per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic into
functions, each declaring the capabilities it uses in its
parameter list:

  _format_token   : pure
  _parse_token    : pure
  is_expired      : pure
  _random_id      : Random only
  generate_token  : Random + Clock
  is_token_valid  : Clock only

The pure / impure split matters: the token format, the parser,
and the expiry comparison are all pure functions of (token, now);
the ONLY impure parts are the single `secrets.choice` draws in
`_random_id` and the single `time.time()` reads in
`generate_token` and `is_token_valid`. Capa exposes that
surgically; Python rolls it all into two top-level imports.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import secrets
import time

# Same 57-character visually-unambiguous alphabet as `short_uuid`.
# Excludes `0`, `1`, `O`, `I`, and `l` to avoid the confusions
# that bite users when they read an ID off a screen and type it
# into a form. Conveniently also excludes `.`, so the dotted
# token format is unambiguous to parse.
_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _random_id(length: int = 16) -> str:
    # Draw `length` characters from the alphabet using the OS
    # CSPRNG. Exercises Random; no clock, no I/O.
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def _format_token(rid: str, expiry_ts: int) -> str:
    # Pure: join the random id and the expiry suffix with a `.`.
    return f"{rid}.{expiry_ts}"


def _parse_token(token: str) -> tuple[str, int] | None:
    # Pure: split on the LAST `.` and parse the int suffix.
    # Returns None on any malformed input (no dot, non-int suffix).
    idx = token.rfind(".")
    if idx < 0:
        return None
    rid = token[:idx]
    suffix = token[idx + 1 :]
    try:
        expiry_ts = int(suffix)
    except ValueError:
        return None
    return (rid, expiry_ts)


def generate_token(ttl_seconds: int = 3600) -> str:
    # Step 1: read the wall clock to compute the expiry timestamp.
    # Exercises Clock.
    expiry_ts = int(time.time()) + ttl_seconds

    # Step 2: draw a random id. Exercises Random.
    rid = _random_id()

    # Step 3: format. Pure given (rid, expiry_ts).
    return _format_token(rid, expiry_ts)


def is_token_valid(token: str) -> bool:
    # Step 1: parse the token. Pure.
    parsed = _parse_token(token)
    if parsed is None:
        return False
    _rid, expiry_ts = parsed

    # Step 2: read the wall clock and compare. Exercises Clock.
    return int(time.time()) < expiry_ts


# A reviewer auditing these functions from the signatures alone
# has no way to know that `generate_token` draws from the CSPRNG
# AND reads the wall clock, or that `is_token_valid` reads the
# wall clock; the `str` return type and the `bool` return type
# are silent on authority. A CVE-style swap that replaced
# `secrets.choice` with a `random.choice` seeded from the current
# time (silently downgrading security) or that "fixed" the
# validator by deleting the expiry check (silently disabling
# session expiration) would not change the signature; it would
# not show up in any pip-based SBOM. The PURL SBOM proxy for this
# file lists `secrets` and `time` (both cap-bearing stdlib
# modules) but cannot attribute Random to one function, Clock to
# two, and prove the parser + formatter + expiry comparator are
# pure given an explicit `now`. Capa narrows Random and Clock per-
# function and proves the helpers are pure.
