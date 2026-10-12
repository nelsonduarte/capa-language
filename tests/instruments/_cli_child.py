"""The command-line child: runs ``capa`` the way a user does, from a tree.

usage: python -I -X utf8 _cli_child.py <tree> <capa arguments...>

Writes ``QPROV file=<capa.__file__> hash=<whole-package hash COMPUTED
HERE>`` to stderr first, then runs ``capa.cli.main`` with the arguments and
exits with its status. The hash is computed in this process; nothing in
the environment can substitute it.
"""

from __future__ import annotations

import os
import sys


def _main() -> None:
    tree = os.path.abspath(sys.argv[1])
    sys.path.insert(0, tree)
    from tests.instruments._provenance import package_hash, use_tree
    f = use_tree(tree)
    sys.stderr.write("QPROV file=%s hash=%s\n" % (f, package_hash(tree)[0]))
    sys.stderr.flush()
    sys.argv = ["capa"] + sys.argv[2:]
    from capa.cli import main
    rc = main()
    sys.exit(rc if isinstance(rc, int) else 0)


if __name__ == "__main__":
    _main()
