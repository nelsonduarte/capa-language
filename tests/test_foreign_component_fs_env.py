"""Feature #4 F3: POSITIVE runtime dispatch of a typed foreign-component
call granted an ATTENUATED ``Fs`` / ``Env`` through the host-mediated
``capa:host/fs`` / ``capa:host/env`` closures.

F2a/F2b/F2c proved the SANDBOX (which caps a child can reach, and the
scalar / String / aggregate value marshalling) using ``Net`` -- but the
only cap method those fixtures ever call is ``allows`` (a bool query).
The privileged, value-returning closures ``fs.read``
(``result<string, io-error>``) and ``env.get`` (``option<string>``) were
coded in ``capa.runtime._foreign`` (``_bind_fs`` / ``_bind_env``) and
enforced with ``fs.allows(path)`` / ``env.allows(name)``, but had NO
positive runtime test -- only negative deny-path coverage. This module
adds that positive coverage end to end:

- ``fs_read_child.wasm``: imports ``capa:host/fs`` (``read`` +
  ``restrict-to``). Exports ``read-it(path) -> string`` returning the Ok
  file contents or the literal ``"ERR"`` on the Err arm, and
  ``widen-read(path)`` which first calls ``restrict-to`` (a host no-op)
  then reads -- proving the guest cannot widen its grant.
- ``env_get_child.wasm``: imports ``capa:host/env`` (``get``). Exports
  ``get-env(name) -> string`` returning the Some value or the literal
  ``"MISSING"`` on None (a denied key is indistinguishable from an unset
  one, per the Env contract).

Both children run in a BARE store under the restricted linker: the only
way they touch the filesystem / environment is the granted
``capa:host/<cap>`` closure, which enforces the caller's attenuation.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa.cli import _wasm_tooling_available, main

_FIXTURES = Path(__file__).parent / "fixtures" / "foreign"


def _run_cli(argv, cwd):
    out, err = io.StringIO(), io.StringIO()
    patches = [
        mock.patch.object(sys, "argv", ["capa"] + list(argv)),
        mock.patch.object(sys, "stdout", out),
        mock.patch.object(sys, "stderr", err),
    ]
    original = os.getcwd()
    try:
        os.chdir(str(cwd))
        for p in patches:
            p.start()
        try:
            rc = main()
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        return rc, out.getvalue(), err.getvalue()
    finally:
        for p in reversed(patches):
            p.stop()
        os.chdir(original)


def _write(td: str, name: str, source: str) -> Path:
    p = Path(td) / name
    p.write_text(source, encoding="utf-8")
    return p


# Fs granted attenuated to the "sandbox" subdir: an in-prefix read returns
# the exact file contents; an out-of-prefix read is denied ("ERR"); a
# guest widen attempt (restrict-to, a host no-op) cannot escape the grant.
_FS_PROG = (
    'extern component Reader from "fs_read_child.wasm"\n'
    "    fun read_it(fs: Fs, path: String) -> String\n"
    "    fun widen_read(fs: Fs, path: String) -> String\n"
    "\n"
    "fun main(fs: Fs, stdio: Stdio)\n"
    '    let safe = fs.restrict_to("sandbox")\n'
    '    stdio.println("in=${Reader.read_it(safe, "sandbox/data.txt")}")\n'
    '    stdio.println("out=${Reader.read_it(safe, "secret.txt")}")\n'
    '    stdio.println("widen=${Reader.widen_read(safe, "secret.txt")}")\n'
)

# The fs child imports capa:host/fs but this method grants NO cap: the
# structural cap-set deny must fire at instantiation.
_FS_UNGRANTED_PROG = (
    'extern component Reader from "fs_read_child.wasm"\n'
    "    fun read_it(path: String) -> String\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    '    stdio.println("r=${Reader.read_it("sandbox/data.txt")}")\n'
)

# Env granted attenuated to a single key: a permitted key returns its
# value; a non-permitted key is denied (looks unset -> "MISSING").
_ENV_PROG = (
    'extern component Getter from "env_get_child.wasm"\n'
    "    fun get_env(env: Env, key: String) -> String\n"
    "\n"
    "fun main(env: Env, stdio: Stdio)\n"
    '    let safe = env.restrict_to_keys(["CAPA_FFI_ALLOWED"])\n'
    '    stdio.println("ok=${Getter.get_env(safe, "CAPA_FFI_ALLOWED")}")\n'
    '    stdio.println("deny=${Getter.get_env(safe, "CAPA_FFI_SECRET")}")\n'
)

# The env child imports capa:host/env but this method grants NO cap: the
# structural cap-set deny must fire at instantiation.
_ENV_UNGRANTED_PROG = (
    'extern component Getter from "env_get_child.wasm"\n'
    "    fun get_env(key: String) -> String\n"
    "\n"
    "fun main(stdio: Stdio)\n"
    '    stdio.println("r=${Getter.get_env("CAPA_FFI_ALLOWED")}")\n'
)


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignFsRuntime(unittest.TestCase):
    def _prep(self, td):
        sandbox = Path(td) / "sandbox"
        sandbox.mkdir()
        # No trailing newline: assert the exact bytes cross the boundary.
        (sandbox / "data.txt").write_text("INSIDE-OK", encoding="utf-8")
        (Path(td) / "secret.txt").write_text("SECRET", encoding="utf-8")
        shutil.copy(_FIXTURES / "fs_read_child.wasm", Path(td) / "fs_read_child.wasm")

    def test_fs_read_in_prefix_out_prefix_and_widen(self):
        # In-prefix read returns the EXACT file bytes; out-of-prefix read
        # is denied by the host closure's fs.allows(path) check (the child
        # gets "ERR", the host never reads the file); a guest restrict-to
        # cannot widen the grant (widen-read of the out-of-prefix path is
        # still denied).
        with tempfile.TemporaryDirectory() as td:
            self._prep(td)
            p = _write(td, "prog.capa", _FS_PROG)
            rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("in=INSIDE-OK", out)
            self.assertIn("out=ERR", out)
            self.assertIn("widen=ERR", out)
            # The out-of-prefix secret bytes never crossed the boundary.
            self.assertNotIn("SECRET", out)

    def test_fs_ungranted_cap_denied_at_instantiation(self):
        # SECURITY REGRESSION CHECK: the structural cap-set deny fires on
        # the Fs path -- the child imports capa:host/fs but the method
        # grants no cap, so instantiation is denied.
        with tempfile.TemporaryDirectory() as td:
            self._prep(td)
            p = _write(td, "prog.capa", _FS_UNGRANTED_PROG)
            rc, _out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("instantiation denied", err)
            self.assertIn("capa:host/fs", err)


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignEnvRuntime(unittest.TestCase):
    def _prep(self, td):
        shutil.copy(_FIXTURES / "env_get_child.wasm", Path(td) / "env_get_child.wasm")

    def test_env_get_permitted_and_denied(self):
        # A permitted key returns its exact value; a non-permitted key is
        # denied by the host closure's env.allows(name) check and reads as
        # unset ("MISSING") -- the value never crosses the boundary.
        with tempfile.TemporaryDirectory() as td:
            self._prep(td)
            p = _write(td, "prog.capa", _ENV_PROG)
            with mock.patch.dict(
                os.environ,
                {
                    "CAPA_FFI_ALLOWED": "allowed-value",
                    "CAPA_FFI_SECRET": "secret-value",
                },
            ):
                rc, out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 0, err)
            self.assertIn("ok=allowed-value", out)
            self.assertIn("deny=MISSING", out)
            self.assertNotIn("secret-value", out)

    def test_env_ungranted_cap_denied_at_instantiation(self):
        # SECURITY REGRESSION CHECK: the structural cap-set deny fires on
        # the Env path too.
        with tempfile.TemporaryDirectory() as td:
            self._prep(td)
            p = _write(td, "prog.capa", _ENV_UNGRANTED_PROG)
            rc, _out, err = _run_cli(["--wasm", "--run", str(p)], cwd=td)
            self.assertEqual(rc, 1)
            self.assertIn("instantiation denied", err)
            self.assertIn("capa:host/env", err)


if __name__ == "__main__":
    unittest.main()
