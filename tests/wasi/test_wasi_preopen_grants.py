"""``--wasi`` filesystem preopens: every registration site grants exactly the
access its source declares.

The WASI host registers a preopen at four sites:

1. a derived ceiling directory that exists, read-only;
2. a derived ceiling directory that exists, read-write;
3. a derived ceiling directory that does NOT exist, registered against an
   empty placeholder, always read-only;
4. the operator ``--preopen`` grant, read-only or read-write as declared.

All four go through one helper that takes the read-write flag explicitly,
with no default (the binding's own parameter defaults to read-write). The
first class records what each site asks the binding for; the second runs
real programs and checks the binding enforces it.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest

from capa import Lexer, Parser, analyze

try:
    import wasmtime
    import wasmtime.component  # noqa: F401
except ImportError:  # pragma: no cover - the [wasm] extra is absent
    wasmtime = None

_HAVE_WASI = wasmtime is not None and hasattr(wasmtime, "WasiConfig")
_HAVE_WASM_TOOLS = shutil.which("wasm-tools") is not None


class _RecordingWasiConfig:
    """Stands in for ``wasmtime.WasiConfig`` and records each preopen."""

    def __init__(self):
        self.calls: list[tuple[str, str, bool]] = []

    def preopen_dir(self, path, guest_path, fs_mutable):
        self.calls.append((path, guest_path, fs_mutable))


@unittest.skipUnless(_HAVE_WASI, "wasmtime with WASI not installed")
class TestPreopenSites(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.mkdtemp(prefix="capa-preopen-sites-")
        self.ro = os.path.join(self._td, "ro")
        self.rw = os.path.join(self._td, "rw")
        self.absent = os.path.join(self._td, "absent")
        self.op = os.path.join(self._td, "op")
        for d in (self.ro, self.rw, self.op):
            os.makedirs(d)

    def tearDown(self):
        shutil.rmtree(self._td, ignore_errors=True)

    def _record(self, *, operator):
        from capa.ir import FsCeiling, FsPreopen
        from capa.runtime._wasm_component_host import WasmComponentHost
        ceiling = FsCeiling(closed=True, preopens=(
            FsPreopen(host_path=self.ro, read_write=False),
            FsPreopen(host_path=self.rw, read_write=True),
            FsPreopen(host_path=self.absent, read_write=True),
        ))
        host = WasmComponentHost(
            wasi=False, fs_ceiling=ceiling, fs_operator_preopen=operator,
        )
        cfg = _RecordingWasiConfig()
        host._apply_fs_preopens(cfg)
        return cfg.calls

    def test_each_site_passes_the_declared_access(self):
        for op_rw in (False, True):
            with self.subTest(operator_read_write=op_rw):
                calls = self._record(operator=(self.op, op_rw))
                self.assertEqual(len(calls), 4, calls)
                by_guest = {g: (p, m) for p, g, m in calls}
                self.assertEqual(by_guest["/capa-preopen-0"], (self.ro, False))
                self.assertEqual(by_guest["/capa-preopen-1"], (self.rw, True))
                placeholder, mutable = by_guest["/capa-preopen-2"]
                self.assertNotEqual(placeholder, self.absent)
                self.assertIs(mutable, False)
                self.assertEqual(
                    by_guest["/capa-preopen-3"], (self.op, op_rw),
                )
                for _p, _g, m in calls:
                    self.assertIs(type(m), bool)

    def test_helper_takes_the_flag_explicitly(self):
        from capa.runtime._wasm_component_host import _preopen
        cfg = _RecordingWasiConfig()
        with self.assertRaises(TypeError):
            _preopen(cfg, self.ro, "/g")
        for bad in (None, 0, 1, "ro", "rw"):
            with self.subTest(read_write=bad):
                with self.assertRaises(TypeError):
                    _preopen(cfg, self.ro, "/g", read_write=bad)
        self.assertEqual(cfg.calls, [])


def _analyze(src: str):
    module = Parser(Lexer(src).lex(), source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module, result


def _component(src: str, *, dynamic: bool) -> bytes:
    from capa.cli import _wrap_as_component
    from capa.ir import compile_wasm, compile_wit
    module, result = _analyze(src)
    extra = {"wasi_dynamic_fs": True} if dynamic else {}
    core = compile_wasm(module, types=result.types, wasi=True, **extra)
    wit = compile_wit(module, types=result.types, wasi=True)
    return _wrap_as_component(core, wit, wasi=True)


def _run(host, comp) -> str:
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    try:
        host.run_main(comp)
    finally:
        sys.stdout, sys.stderr = saved
    return host.captured_stdout().decode("utf-8", errors="surrogatepass")


_DYNAMIC_WRITE = (
    "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
    "    match env.args().get(0)\n"
    "        Some(p) ->\n"
    "            match fs.write(p, \"x\")\n"
    "                Ok(u) -> stdio.println(\"W=ok\")\n"
    "                Err(e) -> stdio.println(\"W=err\")\n"
    "        None -> stdio.println(\"NOARG\")\n"
)


def _literal_write(path: str) -> str:
    p = path.replace("\\", "/")
    return (
        "fun main(fs: Fs, stdio: Stdio)\n"
        f"    match fs.write(\"{p}\", \"x\")\n"
        "        Ok(u) -> stdio.println(\"W=ok\")\n"
        "        Err(e) -> stdio.println(\"W=err\")\n"
    )


@unittest.skipUnless(
    _HAVE_WASI and _HAVE_WASM_TOOLS, "wasm-tools / wasmtime WASI missing",
)
class TestPreopenAccessEnforced(unittest.TestCase):
    """The binding enforces the access each site registered."""

    def setUp(self):
        self._td = tempfile.mkdtemp(prefix="capa-preopen-e2e-")

    def tearDown(self):
        shutil.rmtree(self._td, ignore_errors=True)

    def _dir(self, name):
        d = os.path.join(self._td, name)
        os.makedirs(d)
        return d

    def _derived(self, directory, read_write):
        from capa.ir import FsCeiling, FsPreopen
        from capa.runtime._wasm_component_host import WasmComponentHost
        target = os.path.join(directory, "f.txt")
        host = WasmComponentHost(wasi=True, fs_ceiling=FsCeiling(
            closed=True,
            preopens=(FsPreopen(host_path=directory, read_write=read_write),),
        ))
        return _run(host, _component(_literal_write(target), dynamic=False))

    def _operator(self, directory, read_write):
        from capa.runtime._wasm_component_host import WasmComponentHost
        host = WasmComponentHost(
            args=("f.txt",), wasi=True,
            fs_operator_preopen=(directory, read_write),
        )
        return _run(host, _component(_DYNAMIC_WRITE, dynamic=True))

    def test_derived_read_only_denies_a_write(self):
        d = self._dir("dro")
        self.assertEqual(self._derived(d, False), "W=err\n")
        self.assertFalse(os.path.exists(os.path.join(d, "f.txt")))

    def test_derived_read_write_allows_a_write(self):
        d = self._dir("drw")
        self.assertEqual(self._derived(d, True), "W=ok\n")
        self.assertTrue(os.path.exists(os.path.join(d, "f.txt")))

    def test_absent_directory_placeholder_denies_a_write(self):
        # The ceiling asks for read-write on a directory that does not
        # exist on the host; the placeholder that keeps the slot aligned
        # must still refuse the write.
        absent = os.path.join(self._td, "never-created")
        self.assertEqual(self._derived(absent, True), "W=err\n")
        self.assertFalse(os.path.exists(absent))

    def test_operator_read_only_denies_a_write(self):
        d = self._dir("oro")
        self.assertEqual(self._operator(d, False), "W=err\n")
        self.assertFalse(os.path.exists(os.path.join(d, "f.txt")))

    def test_operator_read_write_allows_a_write(self):
        d = self._dir("orw")
        self.assertEqual(self._operator(d, True), "W=ok\n")
        self.assertTrue(os.path.exists(os.path.join(d, "f.txt")))


if __name__ == "__main__":
    unittest.main()
