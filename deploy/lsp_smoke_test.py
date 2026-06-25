#!/usr/bin/env python3
"""Smoke-test a built `capa` binary's bundled LSP server.

Run as::

    python deploy/lsp_smoke_test.py dist/capa        # Linux / macOS
    python deploy/lsp_smoke_test.py dist/capa.exe    # Windows

It launches ``<binary> lsp``, sends a single LSP ``initialize`` request
over stdio (framed with ``Content-Length``), and checks that the server
replies with a JSON-RPC ``result``. A binary that was built without the
LSP stack falls into the "pygls is required" path and exits with code 2
before printing anything; this test catches that regression.

Driven from the runner's own Python (not the bundled interpreter) so the
exact same script runs identically on the three release platforms,
sidestepping shell-quoting differences between bash and PowerShell.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: lsp_smoke_test.py <path-to-capa-binary>", file=sys.stderr)
        return 64  # EX_USAGE

    # Resolve to an absolute path. On Windows, CreateProcess does not look up
    # a relative command name like ``dist/capa.exe`` against the working
    # directory (it searches PATH instead), so a bare relative path fails
    # with WinError 2. An absolute path works the same everywhere.
    binary = os.path.abspath(argv[1])
    if not os.path.isfile(binary):
        print(f"LSP smoke test FAILED: binary not found: {binary}", file=sys.stderr)
        return 1

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": None,
                "rootUri": None,
                "capabilities": {},
            },
        }
    )
    request = f"Content-Length: {len(body)}\r\n\r\n{body}".encode("utf-8")

    try:
        completed = subprocess.run(
            [binary, "lsp"],
            input=request,
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        print(
            "LSP smoke test FAILED: server did not respond within 30s.",
            file=sys.stderr,
        )
        return 1

    stdout = completed.stdout
    stderr = completed.stderr.decode("utf-8", errors="replace")

    # The "pygls not installed" path exits 2 with no LSP output. Anything
    # other than a JSON-RPC result on stdout means the bundle is broken.
    if completed.returncode == 2 and b'"result"' not in stdout:
        print(
            "LSP smoke test FAILED: binary fell into the pygls-missing path "
            f"(exit 2). The LSP stack was not bundled.\nstderr:\n{stderr}",
            file=sys.stderr,
        )
        return 1

    if b'"result"' not in stdout or b"capabilities" not in stdout:
        print(
            "LSP smoke test FAILED: no initialize result received.\n"
            f"exit code: {completed.returncode}\n"
            f"stdout (first 400 bytes): {stdout[:400]!r}\n"
            f"stderr:\n{stderr}",
            file=sys.stderr,
        )
        return 1

    print(
        "LSP smoke test OK: bundled `capa lsp` answered initialize "
        f"({len(stdout)} bytes on stdout)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
