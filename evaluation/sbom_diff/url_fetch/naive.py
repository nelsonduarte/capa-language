"""A naive Python `fetch a URL and parse the JSON response`
helper, of the shape that appears in essentially every Python
HTTP client SDK and example: `requests.get(url).json()`,
`httpx.get(url).json()`, and the explicit two-step
`urllib.request.urlopen(...) + json.loads(...)` recipe taught in
the stdlib docs. The exact code is illustrative; the *pattern*
(one function that conflates Net + JSON parsing under a single
name with no indication in the signature) is widespread.

The signature `fetch_json(url: str) -> dict` tells the reader
nothing about which capabilities are exercised. A reviewer
reading the import block at the top of the file sees
`urllib.request` and `json`; a reviewer reading the function
body finds that the function opens the network AND parses the
response body AND extracts fields. The CycloneDX SBOM emitted by
pip-licenses / syft for this script would list both imports,
with no per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic into
four functions, each declaring the capabilities it uses in its
parameter list:

  is_https_url    : pure
  extract_field   : pure
  fetch_text      : Net only
  fetch_json      : Net only

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import json
import urllib.request


def is_https_url(url: str) -> bool:
    # Pure: structural check that the URL is HTTPS and has at
    # least some host body after the scheme. No I/O.
    prefix = "https://"
    if not url.startswith(prefix):
        return False
    return len(url) > len(prefix)


def extract_field(data: dict, key: str, default: str = "") -> str:
    # Pure: safely pull a string field out of a parsed JSON
    # object with a typed fallback. No I/O.
    value = data.get(key, default)
    if isinstance(value, str):
        return value
    return default


def fetch_json(url: str) -> dict:
    # Step 1: validate the URL shape before opening anything.
    # Exercises no capability.
    if not is_https_url(url):
        raise ValueError(f"refusing to fetch non-HTTPS URL: {url!r}")

    # Step 2: open the network and read the body. Exercises Net.
    with urllib.request.urlopen(url, timeout=5) as resp:
        body = resp.read().decode("utf-8")

    # Step 3: parse the body as JSON. Pure given the body string;
    # bundled into the same signature as the network call.
    return json.loads(body)


# A reviewer auditing this function from the signature alone has
# no way to know which parts open the network and which are pure
# string manipulation. The PURL SBOM proxy lists `urllib.request`
# and `json` (one cap-bearing); Capa narrows to Net per-function
# and proves the URL validator and field extractor are pure.
