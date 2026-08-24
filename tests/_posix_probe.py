"""Single source of the symlink-capability predicate shared by the
POSIX-only symlink security guards.

Three guard modules gate load-bearing symlink SECURITY properties on
"can this platform create symlinks":

* ``tests.test_fs_toctou.TestSymlinkSwap`` and
  ``tests.test_db_toctou.TestSymlinkSwap`` -- the post-open handle
  re-validation denies a symlink swapped in after the pre-check.
* ``tests.test_attenuation.TestFsPathCanonicalisation`` -- a symlink
  pointing outside a ``restrict_to`` prefix is denied, one inside is
  allowed.

Each of those once carried its own hand-copied
``not sys.platform.startswith("win")`` predicate. That is the
duplicated-hand-synced-knowledge defect the modularization effort
exists to kill: three copies drift, one set of guards runs while the
others skip unnoticed, and the fail-loud floor
(``tests.test_posix_harness_present``) that keeps them honest cannot
know which "POSIX-capable" it is enforcing. This module is the ONE
definition all of them import, so there is exactly one fact.
"""

import os
import sys


def symlinks_available() -> bool:
    """True when this platform can create symlinks.

    Windows symlink creation needs admin rights in most configurations,
    so the symlink-shaped security guards skip there; the non-symlink
    denial paths still run everywhere."""
    return hasattr(os, "symlink") and not sys.platform.startswith("win")
