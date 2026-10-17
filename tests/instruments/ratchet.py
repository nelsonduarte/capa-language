"""The register ratchet as a command: shrink-only against the base register.

    python -m tests.instruments.ratchet --base <file or NONE> --candidate <file>

``NONE`` means the base commit has no register (the first landing): a
BOOTSTRAP, reported as such and accepted. Any other base is compared by
set inclusion (``_register.ratchet``); an added or re-described entry the
candidate does not declare as a REVEAL or a REGENERATION fails the
command. In CI the base is the register of the pushed range's base
commit (the ``before`` sha on a push, the base sha on a pull request),
never ``HEAD~1``: a push of several commits is judged once, against what
was there before the push.
"""

from __future__ import annotations

import argparse
import sys

from tests.instruments._register import load, ratchet


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="shrink-only ratchet of the instrument register")
    ap.add_argument("--base", required=True, help="the base register file, or NONE for a bootstrap")
    ap.add_argument("--candidate", required=True)
    args = ap.parse_args(argv)
    base = None if args.base == "NONE" else load(args.base)
    r = ratchet(base, load(args.candidate))
    print(r.report())
    return 0 if r.green else 1


if __name__ == "__main__":
    sys.exit(main())
