"""Static Fs authority-ceiling analysis for the ``--wasi`` mode.

Phase 0 of the Fs migration in ``docs/design/wasi-attenuation.md``:
map ``main``'s Fs CEILING onto the WASI host configuration
(``wasi:filesystem`` preopens) so the component is instantiated with
preopened directory descriptors for ONLY the directories the program
can reach, and nothing else. A preopen is a hard runtime ceiling:
wasmtime denies any path traversal outside a preopened directory and
denies a write through a READ_ONLY preopen, regardless of what the
guest code attempts.

The ceiling is computed from the CIR (after the loader has inlined
imported functions, so every reachable ``fs.*`` call site is visible)
by scanning every ``MethodCall`` whose receiver is an ``Fs``:

- a STRING-LITERAL path argument (``Value(kind="lit_str")``)
  contributes a PREOPEN: the PARENT directory of the literal path
  (the directory wasmtime grants the guest a descriptor for; the Fs
  metadata wrappers then stat / create RELATIVE to that descriptor
  using the path's basename). The derived permission is READ_WRITE
  when the op MUTATES (``mkdir`` / ``write``), READ_ONLY otherwise
  (``exists`` / ``is_dir`` / ``read`` / ``list_dir``).
- any NON-LITERAL path argument (a local / param / computed value)
  makes the ceiling indeterminable at compile time, so it is marked
  NOT CLOSED.

POLICY for a NOT-CLOSED ceiling (a dynamic Fs path): FAIL CLOSED. The
host materialises NO preopens at all, so the component cannot open any
directory. This is TIGHTER than the Env Level-1 fallback (which drops
to ``inherit_env``) because a wrongly-derived preopen is real
filesystem authority, whereas a missing preopen merely denies access.
A program that needs dynamic Fs paths must use the default
``capa:host`` backend (drop ``--wasi``).

Why preopen the PARENT and address relative by basename:

- ``wasi:filesystem`` operates on directory descriptors plus a
  relative path. To ``create-directory-at "X"`` you need a writable
  descriptor for X's PARENT; to ``stat-at "X"`` you stat from the
  parent descriptor. Preopening the parent of every literal path and
  using the basename as the relative argument handles files
  (exists / is_dir / read of ``dir/file``) and directories (mkdir /
  is_dir of ``dir/sub``) uniformly: the preopen is ``dir`` and the
  relative path is ``file`` / ``sub``.

Per-call-site resolution: every literal Fs call records the INDEX of
its preopen in the sorted ceiling list plus the relative path from
that preopen to the target, so the guest WAT wrapper takes
``(preopen_index, rel_ptr, rel_len)`` and never has to string-match
preopen paths at runtime. The host registers the preopens in the same
sorted order, and ``wasi:filesystem/preopens.get-directories`` returns
the descriptors in registration order, so index K on the guest names
directory K on the host.

Nested-preopen COALESCING (correctness, not just optimisation): two
preopens where one is a subdirectory of another MUST NOT both be
registered. wasmtime collapses overlapping preopens, and addressing
the inner one by descriptor index then traps (``unknown handle
index``). So a parent that is nested under another parent in the
ceiling is DROPPED, and its call sites resolve against the OUTERMOST
containing preopen with a multi-segment relative path (e.g. a file
``root/sub/y`` whose own parent ``root/sub`` is nested under ``root``
resolves to the ``root`` preopen with relative ``sub/y``; wasmtime's
``stat-at`` / ``create-directory-at`` accept multi-segment relative
paths). The outermost preopen inherits READ_WRITE if any coalesced
member needed it.

This increment migrates only the METADATA operations (``exists`` /
``is_dir`` / ``mkdir``). ``read`` / ``write`` / ``list_dir`` still
contribute to the ceiling (so the preopen set and its permissions are
complete and honest) but are rejected at compile time in ``--wasi``
mode by ``_validate_wasi_caps``; the same programs compile and run on
the default ``capa:host`` backend.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

from .. import capa_ast as A
from ._lower import Lowerer
from ._nodes import MethodCall, Module
from ._walk import walk_module


# Capability class name whose calls define the Fs preopen ceiling.
_FS_CAP = "Fs"

# Fs methods that take a filesystem PATH as their first argument and so
# contribute a preopen to the ceiling. ``write`` takes (path, content)
# but the path is still arg[0]. ``restrict_to`` takes a prefix string
# that NARROWS authority; it never widens what the program can touch
# beyond the paths it already passes to a privileged op, so it does not
# add a preopen (mirrors how Env.restrict_to_keys does not widen the
# Env ceiling). ``allows`` is a pure query; it likewise touches no new
# path. Both are excluded so the ceiling is exactly the directories the
# program can actually stat / read / write / create.
_FS_PATH_METHODS: frozenset[str] = frozenset({
    "exists", "is_dir", "mkdir", "read", "write", "list_dir",
})

# The subset that MUTATES the filesystem, so its preopen needs
# READ_WRITE rather than READ_ONLY permission.
_FS_MUTATING_METHODS: frozenset[str] = frozenset({"mkdir", "write"})


def _split_parent_base(path: str) -> tuple[str, str]:
    """Split a literal path into (parent_dir, basename) using POSIX
    semantics (forward slashes), the path convention the guest and the
    WASI host both speak. A trailing slash is stripped first so
    ``dir/sub/`` resolves like ``dir/sub``. A path with no directory
    component (a bare ``name``) yields ``(".", name)``: the preopen is
    the current directory and the relative path is the name."""
    normalised = path.rstrip("/")
    if not normalised:
        # Path was "/" (or empty): the parent is "/" and the basename
        # is empty. Addressing the root itself relative to its own
        # descriptor uses ".".
        return ("/", ".")
    parent, base = posixpath.split(normalised)
    if not parent:
        parent = "."
    if not base:
        base = "."
    return (parent, base)


def _is_under(child: str, ancestor: str) -> bool:
    """True when directory ``child`` is ``ancestor`` itself or nested
    under it, by POSIX path-segment containment (so ``/a/b`` is under
    ``/a`` but ``/ab`` is not under ``/a``). Trailing slashes are
    normalised away first."""
    a = ancestor.rstrip("/") or "/"
    c = child.rstrip("/") or "/"
    if a == c:
        return True
    prefix = a if a.endswith("/") else a + "/"
    return c.startswith(prefix)


def _relative_to(path: str, preopen: str) -> str:
    """Return ``path`` expressed RELATIVE to ``preopen`` directory,
    using forward slashes. ``preopen`` must contain ``path``. The
    result is the remainder after the preopen prefix (a multi-segment
    relative path when ``path`` is nested below the preopen), or ``"."``
    when ``path`` IS the preopen directory (addressing a directory
    relative to its own descriptor)."""
    p = path.rstrip("/")
    pre = preopen.rstrip("/") or "/"
    if p == pre:
        return "."
    prefix = pre if pre.endswith("/") else pre + "/"
    if p.startswith(prefix):
        return p[len(prefix):] or "."
    # Should not happen for a path the same ceiling was computed from;
    # fall back to the basename rather than raise here (the caller's
    # resolve_fs_call raises on a genuine mismatch).
    return posixpath.basename(p) or "."


@dataclass(frozen=True)
class FsPreopen:
    """One preopened directory in the Fs ceiling.

    ``host_path`` is the directory wasmtime grants a descriptor for
    (the parent of every literal path that resolved to it).
    ``read_write`` is True when at least one mutating op (``mkdir`` /
    ``write``) targets a path under this directory, so the host
    registers it with READ_WRITE perms; otherwise READ_ONLY."""
    host_path: str
    read_write: bool


@dataclass(frozen=True)
class FsCeiling:
    """The result of the static Fs ceiling analysis.

    ``closed`` is True when every reachable ``fs.*`` path argument is a
    string literal, so ``preopens`` is the exact, complete set of
    directories the program can reach. When ``closed`` is False at
    least one path is computed at runtime; the ceiling CANNOT be
    materialised and the host must FAIL CLOSED (register no preopens),
    so ``preopens`` is empty and the component can open nothing.

    ``preopens`` is ordered (the sorted unique parent directories);
    the index of a directory in this list is the index the guest WAT
    wrappers pass to address that preopen, and the order the host
    registers them in (``get-directories`` returns descriptors in
    registration order)."""
    closed: bool
    preopens: tuple[FsPreopen, ...]

    def index_of(self, host_path: str) -> int:
        """Return the preopen index of ``host_path`` in the ordered
        ceiling, or -1 if absent (a not-closed ceiling has none)."""
        for i, pre in enumerate(self.preopens):
            if pre.host_path == host_path:
                return i
        return -1


def compute_fs_ceiling_from_cir(cir: Module) -> FsCeiling:
    """Scan a lowered CIR module for the Fs preopen ceiling.

    Walks every function and impl-method body (the loader has already
    inlined imported functions into the AST the CIR was lowered from,
    so this covers the whole reachable program) and inspects every
    ``fs.*`` path-bearing call site. See the module docstring for the
    literal / dynamic rule and the parent-preopen derivation."""
    # parent_dir -> needs_read_write (True wins once any mutating op
    # touches it).
    perms: dict[str, bool] = {}
    closed = True
    for _owner, instr in walk_module(cir):
        if not isinstance(instr, MethodCall):
            continue
        cap = instr.cap_used or (instr.receiver.ty or "")
        # ``receiver.ty`` may be a generic head like ``Fs`` directly;
        # capabilities are never parameterised, so a plain compare is
        # enough.
        if cap != _FS_CAP:
            continue
        if instr.method not in _FS_PATH_METHODS:
            continue
        if not instr.args:
            # Defensive: an arity we do not expect cannot be proven
            # literal, so treat it as dynamic (fail-closed).
            closed = False
            continue
        arg = instr.args[0]
        if arg.kind == "lit_str" and isinstance(arg.literal, str):
            parent, _base = _split_parent_base(arg.literal)
            mutating = instr.method in _FS_MUTATING_METHODS
            perms[parent] = perms.get(parent, False) or mutating
        else:
            # A computed / local / param path: the program may touch a
            # directory decided at runtime, so the ceiling cannot be
            # materialised. Fail-closed.
            closed = False
    if not closed:
        return FsCeiling(closed=False, preopens=())
    # Coalesce nested parents: a directory that is nested under another
    # collected parent is folded into that outer one (its perms merged
    # in), so no preopen is a subdirectory of another (which wasmtime
    # collapses, trapping on the inner descriptor index). The OUTERMOST
    # roots survive; each surviving root's READ_WRITE is the OR over
    # every collected parent it now subsumes.
    roots: dict[str, bool] = {}
    for child in sorted(perms):
        # Find the outermost existing root that contains ``child``;
        # if none, ``child`` becomes a new root.
        container = None
        for r in roots:
            if _is_under(child, r):
                container = r
                break
        if container is not None:
            roots[container] = roots[container] or perms[child]
        else:
            # ``child`` may itself be an ancestor of roots already
            # recorded (sorted order means a shorter ancestor can
            # appear after a longer descendant only when they do not
            # share a prefix, but be defensive): absorb any existing
            # root nested under ``child`` into ``child``.
            absorbed_rw = perms[child]
            for r in list(roots):
                if _is_under(r, child):
                    absorbed_rw = absorbed_rw or roots.pop(r)
            roots[child] = absorbed_rw
    preopens = tuple(
        FsPreopen(host_path=p, read_write=roots[p])
        for p in sorted(roots)
    )
    return FsCeiling(closed=True, preopens=preopens)


def resolve_fs_call(
    ceiling: FsCeiling, path_literal: str,
) -> tuple[int, str]:
    """Resolve a literal Fs path to ``(preopen_index, relative_path)``
    against a CLOSED ceiling. The preopen is the (post-coalescing)
    outermost ceiling directory that contains the path; the relative
    path is the remainder from that preopen to the target (a
    multi-segment path when the target is nested below the preopen, or
    ``"."`` when the target IS the preopen directory). Raises
    ``ValueError`` if the ceiling is not closed or no preopen contains
    the path (which never happens for a path the same closed ceiling
    was computed from)."""
    if not ceiling.closed:
        raise ValueError("Fs ceiling is not closed; no preopens")
    parent, _base = _split_parent_base(path_literal)
    # The preopen is the outermost ceiling directory containing the
    # path's parent (== containing the path). After coalescing the
    # ceiling holds only outermost roots, so exactly one contains it.
    for i, pre in enumerate(ceiling.preopens):
        if _is_under(parent, pre.host_path):
            return (i, _relative_to(path_literal, pre.host_path))
    raise ValueError(
        f"Fs path {path_literal!r} parent {parent!r} not in ceiling"
    )


def compute_fs_ceiling(
    module: A.Module, types: dict | None = None,
) -> FsCeiling:
    """Lower ``module`` to CIR and compute its Fs preopen ceiling.

    Convenience wrapper over :func:`compute_fs_ceiling_from_cir` that
    runs the same lowering the Wasm pipeline uses (so the ceiling is
    computed from the exact instruction tree that will be emitted)."""
    cir = Lowerer(types=types or {}).lower_module(module)
    return compute_fs_ceiling_from_cir(cir)
