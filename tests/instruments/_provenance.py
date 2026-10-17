"""Build identity: ONE place.

The identity of a build is the hash of the WHOLE ``capa`` package: every
file under it, sorted by relative path, bytes with CRLF normalised to LF,
byte-compiled caches excluded. A subtree hash is not an identity (a
discipline deleted in ``typesys.py`` left the analyzer directory's hash
intact), and a checkout and an archive of the same commit differ in line
endings, which the normalisation removes.

Every CHILD process computes this hash itself over the tree it imported
``capa`` from and prints it with ``capa.__file__``; the parent recomputes
it over the tree it asked for and VOIDS every row of a child whose line
differs. No parent ever hands a child the number to print.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

WRONG_TREE_EXIT = 97


def package_hash(tree) -> tuple[str, int]:
    """``(sha256 hex prefix of 16, file count)`` over ``<tree>/capa``."""
    tree = os.path.abspath(str(tree))
    root = os.path.join(tree, "capa")
    items = []
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        for fn in sorted(files):
            if fn.endswith((".pyc", ".pyo")):
                continue
            p = os.path.join(d, fn)
            items.append((os.path.relpath(p, tree).replace(os.sep, "/"), p))
    h = hashlib.sha256()
    for rel, p in sorted(items):
        with open(p, "rb") as fh:
            data = fh.read().replace(b"\r\n", b"\n")
        h.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(data).digest())
    return h.hexdigest()[:16], len(items)


def file_under(path, tree) -> bool:
    try:
        Path(path).resolve().relative_to(Path(tree).resolve())
    except ValueError:
        return False
    return True


def use_tree(tree) -> str:
    """Make ``tree`` the one place this process imports ``capa`` from.

    Puts the tree first on the import path, drops every editable-install
    finder (an editable install of another checkout would otherwise supply
    its ``capa`` whatever the path says), forgets any ``capa`` module
    already imported, imports ``capa`` and refuses (exit 97) unless
    ``capa.__file__`` is under the tree. Returns ``capa.__file__``."""
    tree = os.path.abspath(str(tree))
    sys.meta_path[:] = [
        f for f in sys.meta_path
        if "editable" not in type(f).__module__.lower()
        and "editable" not in repr(f).lower()
    ]
    sys.path[:] = [tree] + [p for p in sys.path if os.path.abspath(p or ".") != tree]
    for name in [m for m in list(sys.modules) if m == "capa" or m.startswith("capa.")]:
        del sys.modules[name]
    import capa
    f = os.path.abspath(capa.__file__)
    if not file_under(f, tree):
        sys.stderr.write("PROV-WRONG-TREE file=%s expected=%s\n" % (f, tree))
        sys.stderr.flush()
        sys.exit(WRONG_TREE_EXIT)
    return f


def provenance_ok(tree=REPO_ROOT) -> bool:
    """True when the ``capa`` imported in THIS process lives under ``tree``."""
    import capa
    return file_under(capa.__file__, tree)
