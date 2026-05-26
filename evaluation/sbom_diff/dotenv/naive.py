"""A naive Python `.env` loader, of the shape that appears in
many Python microservices that follow the 12-factor convention
(python-dotenv has ~3M downloads/month on PyPI; this is the
core of its public API).

The signature `load_dotenv(path: str = '.env') -> dict[str, str]`
tells the reader nothing about which capabilities are
exercised. A reviewer reading the import block at the top of
the file sees `os`; a reviewer reading the function body finds
that the function reads a file AND mutates the process
environment. The CycloneDX SBOM emitted by pip-licenses / syft
for this script would list `os` as an import, with no
per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic
into three functions, each declaring the capabilities it
uses in its parameter list:

  parse_env_text   : pure
  read_env_file    : Fs only
  load_dotenv      : Fs + Env

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import os


def load_dotenv(path: str = ".env", override: bool = False) -> dict:
    # Step 1: read the .env file from disk. Exercises Fs.
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return {}

    # Step 2: parse KEY=VALUE lines, skipping blanks and comments.
    parsed: dict = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        # Strip surrounding quotes if present.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        parsed[key] = value

    # Step 3: overlay onto os.environ. Exercises Env.
    for k, v in parsed.items():
        if override or k not in os.environ:
            os.environ[k] = v

    return parsed


# A reviewer auditing this function from the signature alone has
# no way to know that it reads files AND mutates the environment.
# Both are buried in the body. A CVE-style attack that swapped
# the file-read for a remote fetch (adding Net) would not change
# the signature; it would not show up in any pip-based SBOM.
