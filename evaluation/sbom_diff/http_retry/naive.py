"""A naive Python `fetch with exponential backoff` helper, of the
shape that appears in essentially every Python HTTP client and
standalone retry library: `urllib3.Retry`, `requests`'
`HTTPAdapter` retry, `tenacity`'s decorator, `backoff`'s
decorator, `httpx`'s transport retries. The exact code is
illustrative; the *pattern* (one function that conflates Net +
Clock under a single name with no indication in the signature)
is widespread.

The signature `fetch_with_retry(url: str, max_retries: int = 3,
base_delay: float = 1.0) -> str` tells the reader nothing about
which capabilities are exercised. A reviewer reading the import
block at the top of the file sees `urllib.request` and `time`;
a reviewer reading the function body finds that the function
opens the network AND sleeps the process. The CycloneDX SBOM
emitted by pip-licenses / syft for this script would list both
imports, with no per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic into
four functions, each declaring the capabilities it uses in its
parameter list:

  compute_backoff_seconds : pure
  fetch_once              : Net only
  wait_backoff            : Clock only
  fetch_with_retry        : Net + Clock

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import time
import urllib.request
from urllib.error import URLError


def fetch_with_retry(
    url: str, max_retries: int = 3, base_delay: float = 1.0
) -> str:
    last_error: Exception | None = None
    for attempt in range(max_retries):
        # Step 1: open the network. Exercises Net.
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return resp.read().decode("utf-8")
        except URLError as exc:
            last_error = exc

        # Step 2: back off before the next attempt. Exercises Clock.
        # Exponential schedule: base_delay, 2*base_delay, 4*base_delay, ...
        delay = base_delay * (2 ** attempt)
        time.sleep(delay)

    # All retries exhausted; re-raise the most recent failure.
    assert last_error is not None
    raise last_error


# A reviewer auditing this function from the signature alone has
# no way to know which functions use the network and which use the
# clock; both are conflated under one signature. A CVE-style attack
# that swapped the urlopen call for an exfiltration POST (still
# Net) or that turned the retry loop into a denial-of-service spin
# (Clock without bound) would not change the signature; it would
# not show up in any pip-based SBOM.
