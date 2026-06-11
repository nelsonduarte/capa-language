"""The ``panic`` builtin: deliberate, loud program abort.

``panic(message)`` is Capa's only sanctioned way for a program to
terminate with a non-zero exit code. It is NOT an exception: there
is no unwinding and no catch. The contract, identical on every
backend, is

- ``panic: <message>`` is written to stderr (one line),
- nothing is written to stdout,
- the process exits non-zero (1 on the Python backend; the Wasm
  backends trap, which the CLI / ``capa test`` translate to a
  non-zero exit).

On this (Python) backend the abort is carried by ``SystemExit(1)``,
which the CLI's ``--run`` handler propagates as the process exit
code without printing a traceback; running the transpiled module
directly under ``python`` exits 1 the same way. The Wasm emitter
compiles ``panic`` to a ``capa:host/panic`` import (the host writes
the message to stderr) followed by ``unreachable``.

``capa test`` builds on this: a test file fails by calling
``panic`` on its failing path (see docs/testing.md).
"""

from __future__ import annotations

import sys


def panic(message):
    """Abort the program: ``panic: <message>`` to stderr, exit 1.

    stdout is flushed first so output the program already produced
    is not reordered past the panic message when both streams go to
    the same terminal or log file.
    """
    try:
        sys.stdout.flush()
    except Exception:
        pass
    sys.stderr.write(f"panic: {message}\n")
    try:
        sys.stderr.flush()
    except Exception:
        pass
    raise SystemExit(1)
