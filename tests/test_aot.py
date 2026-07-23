"""Tests for ahead-of-time (AOT) artifacts: ``capa build --release``
+ ``capa run-aot`` (roadmap P1).

Two layers:
  * unit tests of ``capa.runtime._aot`` (container format: build, parse,
    load, version-mismatch, bad-magic) -- some need wasmtime to build a
    real serialized module, gated with skipUnless.
  * CLI end-to-end (build -> run-aot) with output parity against the
    JIT ``--run --wasm`` path -- gated on the full wasm toolchain.
"""

import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa import Lexer, Parser, analyze
from capa.ir import compile_wasm
from capa.runtime import _aot


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _has_wasmtime() -> bool:
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False


_FULL_WASM = _has_wasm_tools() and _has_wasmtime()


def _wasm_blob(src: str, filename: str = "t.capa") -> bytes:
    module = Parser(Lexer(src).lex(), source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return compile_wasm(module, types=result.types, filename=filename)


_HELLO = 'fun main(stdio: Stdio)\n    stdio.println("hi")\n'


class TestAotContainerFormat(unittest.TestCase):
    """Container parsing: these don't need wasmtime (they exercise the
    pure header/magic/version logic on hand-built blobs)."""

    def _make_container(self, header_json: bytes, cwasm: bytes) -> bytes:
        return b"".join([
            b"CPAO",
            struct.pack("<I", _aot._FORMAT_VERSION),
            struct.pack("<I", len(header_json)),
            header_json,
            cwasm,
        ])

    def test_parse_round_trip(self):
        body = self._make_container(b'{"wasmtime_version":"x"}', b"CWASMBYTES")
        header, cwasm = _aot.parse_aot(body)
        self.assertEqual(header["wasmtime_version"], "x")
        self.assertEqual(cwasm, b"CWASMBYTES")

    def test_bad_magic_rejected(self):
        with self.assertRaises(_aot.AotError) as ctx:
            _aot.parse_aot(b"NOPE" + b"\x00" * 20)
        self.assertIn("bad magic", str(ctx.exception))

    def test_unknown_format_version_rejected(self):
        body = b"CPAO" + struct.pack("<I", 999) + struct.pack("<I", 2) + b"{}"
        with self.assertRaises(_aot.AotError) as ctx:
            _aot.parse_aot(body)
        self.assertIn("format version", str(ctx.exception))

    def test_format_version_1_refused_not_read(self):
        # Container format 1 carried ``main_param_names``, which drove
        # the name-matching root-handle binding (unrecognised name ->
        # Fs root). Reading such a header with today's loader would
        # find no ``main_cap_types`` and refuse anyway, but the version
        # check must fire FIRST so the operator is told to rebuild
        # rather than shown a binding diagnostic about a stale field.
        header = b'{"main_param_names": ["fs"]}'
        body = (
            b"CPAO" + struct.pack("<I", 1)
            + struct.pack("<I", len(header)) + header
        )
        with self.assertRaises(_aot.AotError) as ctx:
            _aot.parse_aot(body)
        self.assertIn("format version 1", str(ctx.exception))
        self.assertIn("rebuild", str(ctx.exception))

    def test_truncated_header_rejected(self):
        # header_len claims 100 bytes but only 2 follow.
        body = (
            b"CPAO" + struct.pack("<I", _aot._FORMAT_VERSION)
            + struct.pack("<I", 100) + b"{}"
        )
        with self.assertRaises(_aot.AotError) as ctx:
            _aot.parse_aot(body)
        self.assertIn("truncated", str(ctx.exception))

    def test_aot_main_cap_types_helper(self):
        self.assertEqual(
            _aot.aot_main_cap_types({"main_cap_types": ["fs", "net"]}),
            ["fs", "net"],
        )
        # A header with no binding yields None, NOT an empty list: the
        # host must be able to tell "declares no cap slots" from
        # "declares nothing", and only the latter is a refusal.
        self.assertIsNone(_aot.aot_main_cap_types({}))
        self.assertEqual(_aot.aot_main_cap_types({"main_cap_types": []}), [])
        self.assertIsNone(_aot.aot_main_cap_types({"main_cap_types": "bad"}))
        self.assertIsNone(
            _aot.aot_main_cap_types({"main_cap_types": ["fs", 7]})
        )


@unittest.skipUnless(_FULL_WASM, "wasm toolchain not installed")
class TestAotBuildLoad(unittest.TestCase):
    """build_aot + load_aot against a real serialized module."""

    def test_build_then_load_round_trips(self):
        blob = _wasm_blob(_HELLO)
        artifact = _aot.build_aot(blob, capa_version="9.9.9")
        self.assertEqual(artifact[:4], b"CPAO")
        header, cwasm = _aot.parse_aot(artifact)
        self.assertEqual(header["capa_version"], "9.9.9")
        self.assertIn("wasmtime_version", header)
        # The cwasm is wasmtime's serialized form, NOT a .wasm.
        self.assertNotEqual(cwasm[:4], b"\x00asm")
        # load_aot deserializes it back into a Module.
        module, hdr2 = _aot.load_aot(artifact)
        self.assertIsNotNone(module)
        self.assertEqual(hdr2["capa_version"], "9.9.9")

    def test_main_cap_types_captured(self):
        # A main with cap params: the declared cap TYPES must be
        # captured at build time (the serialized cwasm has no export
        # names, so this is the only place run-aot can recover the
        # cap->slot binding).
        src = (
            "fun use_fs(fs: Fs) -> Bool\n"
            '    match fs.read("/nope_xyz")\n'
            "        Ok(c) -> return true\n"
            "        Err(_) -> return false\n"
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = use_fs(fs.restrict_to(\"/tmp/\"))\n"
            '    stdio.println("${r}")\n'
        )
        blob = _wasm_blob(src)
        artifact = _aot.build_aot(blob, capa_version="t")
        header, _ = _aot.parse_aot(artifact)
        # main's params are (stdio erased, fs kept) -> the i32 slot is fs.
        self.assertEqual(header["main_cap_types"], ["fs"])
        self.assertNotIn("main_param_names", header)

    def test_version_mismatch_fails_closed(self):
        # An artifact stamped with a different wasmtime version must be
        # refused (deserializing a mismatched cwasm is unsafe).
        blob = _wasm_blob(_HELLO)
        artifact = _aot.build_aot(blob, capa_version="t")
        header, cwasm = _aot.parse_aot(artifact)
        import json
        header["wasmtime_version"] = "0.0.0-not-this"
        forged = b"".join([
            b"CPAO", struct.pack("<I", _aot._FORMAT_VERSION),
            struct.pack("<I", len(json.dumps(header).encode())),
            json.dumps(header).encode(), cwasm,
        ])
        with self.assertRaises(_aot.AotError) as ctx:
            _aot.load_aot(forged)
        self.assertIn("wasmtime", str(ctx.exception).lower())


@unittest.skipUnless(_FULL_WASM, "wasm toolchain not installed")
class TestAotCli(unittest.TestCase):
    """End-to-end ``capa build`` -> ``capa run-aot`` via subprocess,
    with output parity against ``--run --wasm``."""

    def _run(self, argv, **kw):
        return subprocess.run(
            [sys.executable, "-m", "capa.cli", *argv],
            capture_output=True, text=True, encoding="utf-8", **kw,
        )

    def test_build_and_run_aot_matches_jit(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "p.capa"
            src.write_text(
                'fun main(stdio: Stdio)\n'
                '    let x = 21 + 21\n'
                '    stdio.println("answer=${x}")\n',
                encoding="utf-8",
            )
            jit = self._run(["--run", "--wasm", str(src)])
            self.assertEqual(jit.returncode, 0, jit.stderr)

            out = Path(td) / "p.cwasm"
            build = self._run(
                ["build", "--release", str(src), "-o", str(out)]
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertTrue(out.exists())

            aot = self._run(["run-aot", str(out)])
            self.assertEqual(aot.returncode, 0, aot.stderr)
            self.assertEqual(aot.stdout, jit.stdout)
            self.assertIn("answer=42", aot.stdout)

    def test_default_output_path(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "prog.capa"
            src.write_text(_HELLO, encoding="utf-8")
            build = self._run(["build", "--release", str(src)])
            self.assertEqual(build.returncode, 0, build.stderr)
            self.assertTrue((Path(td) / "prog.cwasm").exists())

    def test_run_aot_bad_file_clean_error(self):
        with tempfile.TemporaryDirectory() as td:
            junk = Path(td) / "junk.cwasm"
            junk.write_bytes(b"not an aot artifact at all")
            r = self._run(["run-aot", str(junk)])
            self.assertEqual(r.returncode, 2, r.stdout)
            self.assertIn("bad magic", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_build_rejects_analysis_error(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "bad.capa"
            # net declared but unused -> analyzer error.
            src.write_text(
                "fun main(stdio: Stdio, net: Net)\n"
                '    stdio.println("hi")\n',
                encoding="utf-8",
            )
            r = self._run(["build", "--release", str(src)])
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertFalse((Path(td) / "bad.cwasm").exists())


if __name__ == "__main__":
    unittest.main()
