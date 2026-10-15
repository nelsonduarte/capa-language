"""A command-line child that prints a FIXED hash on its provenance line and
then runs ``capa`` as usual. The runner must VOID every row of such a child
(the provenance control of the command-line legs)."""

import os
import sys

tree = os.path.abspath(sys.argv[1])
sys.path.insert(0, tree)
from tests.instruments._provenance import use_tree  # noqa: E402

f = use_tree(tree)
sys.stderr.write("QPROV file=%s hash=%s\n" % (f, "0000feedface0000"))
sys.stderr.flush()
sys.argv = ["capa"] + sys.argv[2:]
from capa.cli import main  # noqa: E402

rc = main()
sys.exit(rc if isinstance(rc, int) else 0)
