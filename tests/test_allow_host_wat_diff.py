"""Phase B0 (part 2): the DIFFERENTIAL WAT-vs-Python oracle for the runtime
Net URL extractor.

The security core of the ``--allow-host`` dynamic path: the guest-side WAT
extractor (``$Net_url_extract``) must produce EXACTLY the same
``(host, is_https, authority, path)`` as its Python executable spec
(:func:`capa.ir._net_host.extract_url_parts`) for every URL in the
adversarial corpus. A divergence would mean the host the guest VERIFIES
against the allowlist differs from what the reference (and thus the review /
SBOM reasoning) believes -- a bypass. This harness assembles a minimal core
module carrying the real emitted extractor, runs it on wasmtime, and asserts
byte-for-byte agreement.
"""

import shutil
import subprocess
import unittest

from capa.ir._net_host import extract_url_parts
from tests.test_allow_host_oracle import ADVERSARIAL_URL_CORPUS


def _has_tooling() -> bool:
    if shutil.which("wasm-tools") is None:
        return False
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return False
    return True


def _extractor_wat() -> str:
    """The real emitted extractor helpers ($is_url_ws / $ascii_lc /
    $Net_url_extract), pulled straight from the WasmEmitter so the harness
    tests the SAME code the compiler emits (not a copy)."""
    from capa.ir._emit_wasm import WasmEmitter
    em = WasmEmitter(wasi=True)
    em._emit_wasi_is_url_ws_helper()
    em._emit_wasi_net_url_extract_helper()
    return "\n".join(em._lines)


# Memory layout for the harness (generous, page-aligned regions).
_URL_AT = 1024
_SCRATCH_AT = 16384
_OUT_AT = 131072  # in page 2 (module declares 4 pages)


def _module_wat() -> str:
    return (
        "(module\n"
        "  (memory (export \"memory\") 4)\n"
        f"{_extractor_wat()}\n"
        "  (func (export \"extract\")\n"
        "      (param $u i32) (param $ul i32) (param $s i32) (param $o i32)\n"
        "      (result i32)\n"
        "    (call $Net_url_extract (local.get $u) (local.get $ul)\n"
        "      (local.get $s) (local.get $o)))\n"
        ")\n"
    )


def _assemble(wat: str) -> bytes:
    proc = subprocess.run(
        ["wasm-tools", "parse", "-"],
        input=wat.encode("utf-8"),
        capture_output=True, check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            "wasm-tools parse failed:\n"
            + proc.stderr.decode("utf-8", "replace")
            + "\n--- WAT ---\n" + wat
        )
    return proc.stdout


@unittest.skipUnless(_has_tooling(), "wasm-tools and/or wasmtime-py not installed")
class DifferentialUrlExtractor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import wasmtime
        cls.wasmtime = wasmtime
        blob = _assemble(_module_wat())
        cls.engine = wasmtime.Engine()
        cls.module = wasmtime.Module(cls.engine, blob)

    def _run(self, url: str):
        wasmtime = self.wasmtime
        store = wasmtime.Store(self.engine)
        inst = wasmtime.Instance(store, self.module, [])
        exp = inst.exports(store)
        mem = exp["memory"]
        extract = exp["extract"]
        raw = url.encode("utf-8", "surrogatepass")
        mem.write(store, raw, _URL_AT)
        rc = extract(store, _URL_AT, len(raw), _SCRATCH_AT, _OUT_AT)

        def _i32(off):
            b = mem.read(store, _OUT_AT + off, _OUT_AT + off + 4)
            return int.from_bytes(b, "little", signed=False)

        if rc == 0:
            return ("", None, "", "")  # fail-closed sentinel
        host_ptr, host_len = _i32(0), _i32(4)
        is_https = _i32(8)
        auth_ptr, auth_len = _i32(12), _i32(16)
        path_ptr, path_len = _i32(20), _i32(24)

        def _s(ptr, ln):
            if ln == 0:
                return ""
            return mem.read(store, ptr, ptr + ln).decode("utf-8", "surrogatepass")

        return (
            _s(host_ptr, host_len),
            bool(is_https),
            _s(auth_ptr, auth_len),
            _s(path_ptr, path_len),
        )

    def test_wat_matches_python_reference_over_corpus(self):
        mismatches = []
        for url in ADVERSARIAL_URL_CORPUS:
            py = extract_url_parts(url)
            wat = self._run(url)
            py_deny = (py[0] == "")
            wat_deny = (wat[0] == "")
            if py_deny and wat_deny:
                continue  # both fail-closed: agree (deny is safe)
            # Neither denied (or one did): require full byte agreement on the
            # admitted parts. is_https/authority/path only meaningful when
            # admitted.
            if py_deny != wat_deny:
                mismatches.append(
                    f"{url!r}: DENY divergence py_deny={py_deny} wat_deny={wat_deny}"
                    f" (py={py} wat={wat})"
                )
                continue
            if (wat[0], wat[1], wat[2], wat[3]) != (py[0], py[1], py[2], py[3]):
                mismatches.append(f"{url!r}: py={py} wat={wat}")
        self.assertEqual(mismatches, [], "WAT/Python extractor diverged:\n" + "\n".join(mismatches))

    def test_verified_host_is_authority_prefix(self):
        # The ironclad invariant, re-checked on the REAL WAT output: when
        # admitted, the authority the guest sends to wasi:http begins with
        # exactly the host it verified (no second parser can disagree).
        for url in ADVERSARIAL_URL_CORPUS:
            host, is_https, authority, path = self._run(url)
            if host == "":
                continue
            self.assertTrue(
                authority == host or authority.startswith(host + ":"),
                f"{url!r}: authority {authority!r} not built from host {host!r}",
            )


if __name__ == "__main__":
    unittest.main()
