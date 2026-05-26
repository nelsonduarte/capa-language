"""A naive Python recursive file walker, of the shape that
appears in many Python tools that hand-roll a "find every file
under this root whose name matches" helper instead of pulling
in `glob.glob("**/*.py", recursive=True)`, `pathlib.Path.rglob`,
or the `pathspec` PyPI library (and of the shape those
libraries themselves expose to the caller).

The signature `find_files(root: str, suffix: str = ".py") -> list[str]`
tells the reader nothing about which capabilities are
exercised. A reviewer reading the import block at the top of
the file sees `os` and `glob`; a reviewer reading the function
body finds that the function lists directories and recurses
into subdirectories. The CycloneDX SBOM emitted by pip-licenses
/ syft for this script would list `os` and `glob` (both
capability-bearing stdlib modules) as imports, with no
per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic
into helpers, each declaring the capabilities it uses in its
parameter list:

  matches_suffix   : pure
  basename         : pure
  join_path        : pure
  walk_dir         : Fs only

Even in a single-capability library the split matters: the
matcher and path helpers are unit-testable without any
filesystem handle, and a reviewer reading `walk_dir`'s
signature knows immediately that it is the one place the disk
can be touched.

Behaviour: permission errors during `os.listdir` are silently
skipped (the walker keeps going on the rest of the tree); any
other OSError is allowed to propagate. The naive Python uses
`os.walk`, which has the same skip-on-error default.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import glob
import os


def _matches_suffix(name: str, suffix: str) -> bool:
    # Pure: no filesystem access, just a string predicate.
    return name.endswith(suffix)


def find_files(root: str, suffix: str = ".py") -> list:
    # Walks `root` recursively and returns the full paths of every
    # file whose basename ends with `suffix`. Exercises Fs (both
    # the directory-listing side via `os.walk` and the implicit
    # is-dir check that `os.walk` does under the hood).
    out: list = []
    try:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fname in filenames:
                if _matches_suffix(fname, suffix):
                    out.append(os.path.join(dirpath, fname))
    except PermissionError:
        # Match `os.walk`'s default: skip unreadable subtrees.
        pass
    return out


# A reviewer auditing this function from the signature alone has
# no way to know that it walks the filesystem. The PURL SBOM
# proxy for this file lists `os` and `glob` (both
# capability-bearing stdlib modules) but says nothing about
# which function exercises file I/O - and `_matches_suffix`,
# which is pure, is bundled into the same SBOM row. A CVE-style
# attack that swapped the directory walk for a remote fetch
# (adding Net) would not change the signature and would not
# necessarily change the PURL SBOM either if it reused `os` for
# something else. Capa narrows `Fs` to `walk_dir` per-function
# and proves the matcher and path helpers are pure.
