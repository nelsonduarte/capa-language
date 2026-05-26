"""A naive Python log forwarder, of the shape that appears in
essentially every observability sidecar: the Datadog Agent's
file tailer, Filebeat's harvester, the Splunk Universal
Forwarder, a homegrown Loki / Grafana / Sentry forwarder.
The exact code is illustrative; the *pattern* (one function
that conflates Fs + Net under a single name with no indication
in the signature) is widespread.

The signature `forward_log(path: str, url: str, max_lines: int
= 100) -> int` tells the reader nothing about which capabilities
are exercised. A reviewer reading the import block at the top of
the file sees `json` and `urllib.request`; a reviewer reading
the function body finds that the function reads the disk AND
opens the network. The CycloneDX SBOM emitted by pip-licenses /
syft for this script would list both imports, with no
per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic into
functions that each declare the capabilities they use in their
parameter list:

  escape_for_json : pure
  format_as_json  : pure
  read_tail       : Fs only
  send_lines      : Net only
  forward_log     : Fs + Net

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import json
import urllib.request


def _read_tail(path: str, max_lines: int) -> list[str]:
    # Step 1: read the file from disk. Exercises Fs. A production
    # forwarder would seek from the end for efficiency; the
    # illustrative shape reads the whole file and slices the tail.
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    return lines[-max_lines:]


def _format_as_json(lines: list[str]) -> str:
    # Pure: turn the list into a JSON array literal. Same role as
    # `json.dumps(lines)` does on a homogeneous str list, written
    # out by hand to mirror the Capa version's structure.
    return json.dumps(lines)


def forward_log(path: str, url: str, max_lines: int = 100) -> int:
    # Step 2: read the tail of the log file. Exercises Fs.
    tail = _read_tail(path, max_lines)

    # Step 3: format the tail as a JSON payload. Pure.
    payload = _format_as_json(tail).encode("utf-8")

    # Step 4: POST the payload to the collector URL. Exercises Net.
    # urlopen treats any request with a `data` argument as a POST.
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()

    return len(tail)


# A reviewer auditing this function from the signature alone has
# no way to know that it reads a file AND opens the network; both
# are conflated under one signature. A CVE-style attack that
# swapped the collector URL for an exfiltration endpoint, or that
# widened the file read to include arbitrary paths the caller
# never named, would not change the signature; it would not show
# up in any pip-based SBOM.
