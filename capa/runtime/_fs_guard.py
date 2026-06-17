"""Post-open handle verification for the ``Fs`` capability.

Closes the read/write TOCTOU window documented since the first
``Fs`` audit: ``Fs.allows()`` resolves the path with
``os.path.realpath`` and checks it against the allowed prefixes,
but a hostile process could swap a symlink between that check and
the ``open()`` syscall, landing the handle outside the sandbox.

The fix implemented here does not try to win the race; it makes
winning it useless. The file is opened first, then the *true* path
of the already-open handle is asked of the OS and re-validated
against the capability's prefixes before any byte is read, written,
or truncated. A swapped symlink changes which file the handle binds
to, but it cannot change what the OS reports for that handle.

True-path resolution per platform (``fd_true_path``):

- Linux: ``os.readlink("/proc/self/fd/<fd>")``.
- macOS / BSDs with ``F_GETPATH``: ``fcntl.fcntl(fd, F_GETPATH)``.
- Windows: ``GetFinalPathNameByHandleW`` on the OS handle obtained
  from the C-runtime fd via ``msvcrt.get_osfhandle``.
- Anything else: ``None``, and the guard explicitly falls back to
  the historical pre-open-check-only behaviour (see ``_verify_fd``)
  rather than breaking ``Fs`` on platforms we cannot test.

Write is the destructive vector: ``open(path, "w")`` truncates at
the syscall, destroying the target before any verification could
run. ``open_verified_write`` therefore opens with
``O_WRONLY | O_CREAT`` (no ``O_TRUNC``), verifies the handle, and
only then truncates. A denied write leaves pre-existing data
outside the sandbox untouched; at worst it leaves behind an empty
file that the swapped link pointed at a path that did not exist
yet (no pre-existing byte is ever modified or truncated).

``O_NOFOLLOW`` is OR-ed into the open flags where the platform
defines it, as defence in depth against final-component symlink
swaps. The correctness of the guard does not depend on it: when
the open fails with the symlink-refused errno the open is retried
without the flag so legitimate in-prefix symlinks keep working,
and the post-open verification remains the actual gate.
"""

from __future__ import annotations

import errno
import os
import sys

try:
    import fcntl as _fcntl
    _F_GETPATH = getattr(_fcntl, "F_GETPATH", None)
except ImportError:  # Windows
    _fcntl = None
    _F_GETPATH = None

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# CPython's built-in open() always opens in binary mode at the CRT
# level on Windows; mirror that for the raw os.open so the fd we
# hand to os.fdopen behaves identically (no CRT-level CRLF
# translation under the Python io layer's own translation).
_O_BINARY = getattr(os, "O_BINARY", 0)

# errnos that mean "O_NOFOLLOW refused a symlink final component".
# POSIX says ELOOP; FreeBSD historically used EMLINK, NetBSD EFTYPE.
_NOFOLLOW_ERRNOS = tuple(
    e for e in (
        errno.ELOOP,
        getattr(errno, "EMLINK", None),
        getattr(errno, "EFTYPE", None),
    ) if e is not None
)


class PostOpenDenied(Exception):
    """The true path of an opened handle failed the capability check.

    Raised by ``open_verified_read`` / ``open_verified_write`` after
    the offending fd has been closed; carries the resolved path for
    diagnostics (callers map this onto their usual deny error and
    must not leak the resolved path to the guest).
    """

    def __init__(self, true_path: str):
        super().__init__(true_path)
        self.true_path = true_path


def _fd_true_path_windows(fd: int) -> str | None:
    """Resolve via ``GetFinalPathNameByHandleW`` (flags=0 means
    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS, i.e. a fully resolved
    long-form drive-letter path)."""
    import ctypes
    import msvcrt

    handle = msvcrt.get_osfhandle(fd)
    kernel32 = ctypes.windll.kernel32
    # First call with a zero-length buffer returns the required
    # size in WCHARs (including the terminating NUL).
    needed = kernel32.GetFinalPathNameByHandleW(
        ctypes.c_void_p(handle), None, 0, 0,
    )
    if needed == 0:
        return None
    buf = ctypes.create_unicode_buffer(needed + 1)
    n = kernel32.GetFinalPathNameByHandleW(
        ctypes.c_void_p(handle), buf, len(buf), 0,
    )
    if n == 0 or n >= len(buf):
        return None
    path = buf.value
    # Strip the NT long-path prefix so the result compares cleanly
    # against os.path.realpath output (which is unprefixed).
    if path.startswith("\\\\?\\UNC\\"):
        path = "\\\\" + path[8:]
    elif path.startswith("\\\\?\\"):
        path = path[4:]
    return path


def fd_true_path(fd: int) -> str | None:
    """Return the OS's canonical path for the open descriptor ``fd``,
    or ``None`` when the platform offers no mechanism.

    The returned path is fully resolved by the kernel (symlink-free)
    and is deliberately NOT passed through ``os.path.realpath``
    again: re-resolving would walk the filesystem a second time and
    reopen the very race this module closes (an attacker could plant
    a symlink at a component of the *resolved* path and make the
    re-resolution land inside the sandbox while the handle points
    outside).
    """
    # Linux (and anything else exposing /proc/self/fd).
    if os.path.isdir("/proc/self/fd"):
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            pass
    # macOS / FreeBSD: F_GETPATH fills a MAXPATHLEN (1024) buffer.
    if _F_GETPATH is not None:
        try:
            raw = _fcntl.fcntl(fd, _F_GETPATH, bytes(1024))
            return raw.split(b"\x00", 1)[0].decode(
                sys.getfilesystemencoding(), "surrogateescape",
            )
        except OSError:
            pass
    if sys.platform == "win32":
        try:
            return _fd_true_path_windows(fd)
        except OSError:
            pass
    return None


def _open_fd(path: str, flags: int) -> int:
    """``os.open`` with ``O_NOFOLLOW`` defence in depth.

    If the final component is a symlink the strict open fails with a
    platform-specific errno; retry without the flag so legitimate
    in-prefix symlinks keep working. The post-open verification in
    ``_verify_fd`` is the real gate either way.
    """
    if _O_NOFOLLOW:
        try:
            return os.open(path, flags | _O_NOFOLLOW)
        except OSError as e:
            if e.errno not in _NOFOLLOW_ERRNOS:
                raise
    return os.open(path, flags)


def _verify_fd(fd: int, verify) -> None:
    """Run ``verify`` on the true path of ``fd``; raise
    ``PostOpenDenied`` on refusal. The caller owns closing ``fd``."""
    true_path = fd_true_path(fd)
    if true_path is None:
        # No handle-path mechanism on this platform (none of
        # /proc/self/fd, F_GETPATH, GetFinalPathNameByHandle).
        # Deliberate fallback to the historical behaviour: the
        # pre-open allows() check already passed, and failing
        # closed here would break Fs entirely on such platforms.
        # The residual race on this path is documented in
        # docs/stdlib.md and the Fs docstring.
        return
    if not verify(true_path):
        raise PostOpenDenied(true_path)


def _fdopen(fd: int, mode: str):
    """``os.fdopen`` that closes ``fd`` if the wrap itself fails
    (e.g. ``IsADirectoryError`` from FileIO on a directory fd)."""
    try:
        return os.fdopen(fd, mode, encoding="utf-8")
    except Exception:
        os.close(fd)
        raise


def verify_path_open(path: str, verify) -> None:
    """Open ``path`` (creating it if absent, like ``sqlite3.connect``),
    confirm the kernel-reported true path of the resulting handle
    satisfies ``verify(true_path) -> bool``, then close the handle.

    Raises ``PostOpenDenied`` (handle closed) when the verification
    refuses. Used by the ``Db`` capability, which cannot apply the
    full ``open_verified_*`` flow because ``sqlite3`` owns its own
    connection fd and never exposes it: the closest analog is to
    open the same path ourselves first, take the kernel's symlink-
    free path for *that* handle, and re-validate it against the
    prefixes before letting SQLite open the (now-resolved) file. The
    ``O_NOFOLLOW`` defence-in-depth and the platform fallback in
    ``_verify_fd`` behave exactly as for the read/write path.

    Residual (documented): a symlink swapped between this verified
    close and SQLite's subsequent open is not caught -- the same
    narrow class of residual the read/write guard accepts on
    platforms without a handle-path mechanism. The window is far
    smaller than the original allows()-to-connect gap and requires
    re-winning the race a second time.
    """
    fd = _open_fd(path, os.O_RDONLY | os.O_CREAT | _O_BINARY)
    try:
        _verify_fd(fd, verify)
    finally:
        os.close(fd)


def open_verified_read(path: str, verify):
    """Open ``path`` for reading; verify the handle's true path with
    ``verify(true_path) -> bool`` before returning the (text-mode,
    UTF-8) file object. Raises ``PostOpenDenied`` (fd closed) when
    the verification refuses, or ``OSError`` as a plain open would.
    """
    fd = _open_fd(path, os.O_RDONLY | _O_BINARY)
    try:
        _verify_fd(fd, verify)
    except BaseException:
        os.close(fd)
        raise
    return _fdopen(fd, "r")


def open_verified_write(path: str, verify):
    """Open ``path`` for writing WITHOUT truncating, verify the
    handle's true path, and only then truncate. Returns a text-mode
    UTF-8 file object positioned at offset 0 of a now-empty file,
    so callers observe exactly the semantics of ``open(path, "w")``.

    Raises ``PostOpenDenied`` (fd closed, target untouched) when the
    verification refuses, or ``OSError`` as a plain open would.
    """
    fd = _open_fd(path, os.O_WRONLY | os.O_CREAT | _O_BINARY)
    try:
        _verify_fd(fd, verify)
        os.ftruncate(fd, 0)
    except BaseException:
        os.close(fd)
        raise
    return _fdopen(fd, "w")
