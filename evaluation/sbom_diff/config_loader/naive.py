"""A naive Python config loader, of the shape that appears in a
typical microservice. The exact code is illustrative; the
*pattern* (one function that conflates Fs + Env + Net under a
single name with no indication in the signature) is widespread.

The point this file makes, alongside `examples/empirical_config.capa`,
is that the Python signature `load_config(path: str) -> dict` tells
the reader nothing about which capabilities the function exercises.
A reviewer reading the import block at the top sees `json`, `os`,
`urllib`. A reviewer reading the function body finds that all three
are exercised on every call. A reviewer reading the CycloneDX SBOM
emitted by pip-licenses / syft for this script gets a list of
top-level imports and no per-function attribution.

The Capa equivalent (see `examples/empirical_config.capa`) splits
the same logic into four functions, each declaring the capabilities
it uses in its parameter list. The CycloneDX SBOM emitted by
`capa --cyclonedx` includes `capa:declared_capability` properties
per function. The diff is the empirical point.

This file is not run by the test suite; it is included only as the
hand-Python comparison artefact for `docs/empirical_micro.md`.
"""

import json
import os
import urllib.request


def load_config(path: str) -> dict:
    # Step 1: read base config from disk. Exercises Fs.
    with open(path, encoding="utf-8") as f:
        config = json.load(f)

    # Step 2: overlay environment-variable overrides. Exercises Env.
    # The pattern is: any env var starting with APP_ overrides the
    # config field with the rest of the name lowercased.
    for key, value in os.environ.items():
        if key.startswith("APP_"):
            field = key[4:].lower()
            config[field] = value

    # Step 3: fetch optional remote feature-flag patch. Exercises
    # Net. If a "flags_url" key was set (by file or env), pull the
    # JSON document at that URL and merge it on top.
    flags_url = config.get("flags_url")
    if flags_url:
        with urllib.request.urlopen(flags_url, timeout=5) as resp:
            patch = json.loads(resp.read().decode("utf-8"))
        config.update(patch)

    return config


# A reviewer auditing this function from the signature alone has
# no way to know that it reads files, reads the environment, AND
# opens the network. All three are buried in the body. A CVE-style
# attack that tampers with this function to also POST the config
# somewhere would not change the signature; it would not show up
# in any pip-based SBOM.
