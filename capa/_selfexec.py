"""How this compiler re-invokes ITSELF as a child process.

Two commands spawn a fresh ``capa`` to run a program: ``capa test``
(one child per test file) and ``capa --watch`` (one child per rerun).
Both built ``[sys.executable, "-m", "capa", ...]``, which is correct
only while ``sys.executable`` is a Python interpreter.

Inside a PyInstaller bundle it is not: ``sys.executable`` IS the
frozen ``capa`` binary, and that binary does not accept ``-m``. Every
child died with ``error: unrecognized arguments: -m <file>`` before
parsing anything, so under every released binary ``capa test``
reported every test as failed. ``--check`` and ``--run`` were
unaffected because they never spawn anything, which is exactly why the
binary smoke test never saw it.

The fix is to ask what ``sys.executable`` IS. Frozen, it takes the
compiler's own arguments directly (``capa --run x.capa``); unfrozen,
it is an interpreter and needs ``-m capa`` to reach the same CLI.
Both forms land in ``capa.cli.main`` with identical arguments from
that point on, so callers build only the tail.

WHY THESE TWO KEEP A CHILD PROCESS, when ``--run`` deliberately went
in-process (see the historical note in ``capa.cli``). What ``--run``
had to execute was arbitrary TRANSPILED PYTHON, which a frozen binary
genuinely cannot do: it is not a general interpreter. What these two
have to execute is ``capa --run <file>``, which the frozen binary runs
natively. Here the separate process is not a workaround for freezing,
it is the feature being bought:

  * **Isolation.** Module-level state, a mutated recursion limit, a
    loaded wasmtime instance, an exhausted file handle: none of it
    reaches the next test file or the next rerun. A test runner whose
    tests share an interpreter is a test runner whose results depend
    on their order.
  * **Survivable crashes.** A test that traps in Wasm, segfaults a
    C extension or calls ``os._exit`` costs one exit code, not the
    whole run. In-process, the first such test would take the runner
    down and every later test would go unreported.
  * **Honest capture.** Output written by grandchildren (the ``Proc``
    capability spawns real processes) reaches the report, because the
    pipe is inherited at the file-descriptor level. An in-process
    ``redirect_stdout`` sees only what Python itself writes.

So the shape was right; only the command was wrong.

The child's environment is inherited unchanged (apart from what the
caller adds). Under a onefile bundle that includes PyInstaller's own
``_PYI_*`` bookkeeping and, on Linux, the loader path pointing at the
extracted bundle, which is precisely the environment the onefile
bootloader hands to a re-execution of itself. Scrubbing half of it
would be the risk, not inheriting it.
"""

from __future__ import annotations

import sys
from typing import Sequence


def is_frozen() -> bool:
    """True when running inside a PyInstaller-bundled ``capa``, where
    ``sys.executable`` is the compiler binary rather than a Python
    interpreter. ``sys.frozen`` is the attribute PyInstaller injects;
    other freezers set it too, and every one of them shares the
    property that matters here."""
    return bool(getattr(sys, "frozen", False))


def capa_child_command(args: Sequence[str]) -> list[str]:
    """The argv that runs a fresh ``capa`` with ``args``, in whichever
    form this process happens to have been started.

    ``capa_child_command(["--run", "x.capa"])`` yields
    ``[<python>, "-m", "capa", "--run", "x.capa"]`` from a source
    checkout or a pip install, and ``[<capa binary>, "--run",
    "x.capa"]`` from a released binary."""
    if is_frozen():
        return [sys.executable, *args]
    return [sys.executable, "-m", "capa", *args]
