# pyright: reportCallIssue=none
#
# wasmtime-py types ``instance.exports(store)[name]`` as a union
# ``Func | Global | Memory | Table | SharedMemory``. Every call site
# in this module passes the resulting export through ``(...)``, so
# Pyright flags each non-callable variant of the union. We know the
# relevant export is a Func because the WAT we emit always declares it
# as one; silencing ``reportCallIssue`` for the whole module is the
# smallest fix that does not bury the test code in per-line type-ignore
# noise. Real "not callable" errors are still caught at runtime by
# ``python -m unittest``.
"""WebAssembly backend: strings (locals, methods, split, IoError format
strings, and global string constants).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import compile_wasm


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStringLocals(unittest.TestCase):
    """Phase 6D-1: String values backed by a (ptr, len) i32 pair.
    A String local declares two Wasm locals (``$name_ptr`` /
    ``$name_len``); String params expand to two i32 params at the
    function signature. String literals and locals can be passed
    interchangeably to capability methods and user functions."""

    def _run_capturing_stdout(self, src: str) -> tuple[str, str]:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out, err = io.StringIO(), io.StringIO()
        saved_out, saved_err = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            host.run_main(blob)
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
        return out.getvalue(), err.getvalue()

    def test_string_local_used_in_println(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    let msg = \"hello from a local\"\n"
            "    stdio.println(msg)\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "hello from a local\n")

    def test_string_param_in_user_function(self):
        src = (
            "fun say(stdio: Stdio, msg: String)\n"
            "    stdio.println(msg)\n"
            "fun main(stdio: Stdio)\n"
            "    say(stdio, \"forwarded literal\")\n"
            "    let s = \"forwarded local\"\n"
            "    say(stdio, s)\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(
            out,
            "forwarded literal\nforwarded local\n",
        )

    def test_string_reassign_to_local(self):
        src = (
            "fun main(stdio: Stdio)\n"
            "    var msg = \"first\"\n"
            "    stdio.println(msg)\n"
            "    msg = \"second\"\n"
            "    stdio.println(msg)\n"
        )
        out, _ = self._run_capturing_stdout(src)
        self.assertEqual(out, "first\nsecond\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStringMethods(unittest.TestCase):
    """Phase 6D-4: String methods backed by (ptr, len) pair
    semantics. Read-only methods (length, contains, starts_with,
    ends_with, is_empty) compute over the receiver bytes without
    allocating. Transforming methods (substring, to_upper,
    to_lower, trim) allocate fresh buffers via ``$alloc`` and
    return new (ptr, len) pairs. String returns use Wasm 2.0
    multi-value ``(result i32 i32)``."""

    def _instantiate(self, src: str):
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return store, instance.exports(store)

    def _read_string(self, store, exports, name: str) -> str:
        """Call a no-arg function returning String (multi-value
        i32 ptr, i32 len) and decode the result via the module's
        exported memory. wasmtime maps multi-value to a tuple."""
        result = exports[name](store)
        ptr, length = result
        data = exports["memory"].read(store, ptr, ptr + length)
        return bytes(data).decode("utf-8")

    def test_length_and_is_empty(self):
        src = (
            "fun len_hello() -> Int\n"
            "    return \"hello\".length()\n"
            "fun empty1() -> Bool\n"
            "    return \"\".is_empty()\n"
            "fun empty2() -> Bool\n"
            "    return \"x\".is_empty()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["len_hello"](store), 5)
        self.assertEqual(exp["empty1"](store), 1)
        self.assertEqual(exp["empty2"](store), 0)

    def test_starts_with(self):
        src = (
            "fun yes() -> Bool\n"
            "    return \"hello world\".starts_with(\"hello\")\n"
            "fun no_mismatch() -> Bool\n"
            "    return \"hello world\".starts_with(\"world\")\n"
            "fun no_longer_than_self() -> Bool\n"
            "    return \"hi\".starts_with(\"hello\")\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["yes"](store), 1)
        self.assertEqual(exp["no_mismatch"](store), 0)
        self.assertEqual(exp["no_longer_than_self"](store), 0)

    def test_ends_with(self):
        src = (
            "fun yes() -> Bool\n"
            "    return \"hello world\".ends_with(\"world\")\n"
            "fun no_mismatch() -> Bool\n"
            "    return \"hello world\".ends_with(\"hello\")\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["yes"](store), 1)
        self.assertEqual(exp["no_mismatch"](store), 0)

    def test_contains(self):
        src = (
            "fun mid() -> Bool\n"
            "    return \"hello world\".contains(\"o w\")\n"
            "fun start() -> Bool\n"
            "    return \"hello world\".contains(\"hello\")\n"
            "fun end() -> Bool\n"
            "    return \"hello world\".contains(\"world\")\n"
            "fun missing() -> Bool\n"
            "    return \"hello world\".contains(\"xyz\")\n"
            "fun empty_needle() -> Bool\n"
            "    return \"hello\".contains(\"\")\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(exp["mid"](store), 1)
        self.assertEqual(exp["start"](store), 1)
        self.assertEqual(exp["end"](store), 1)
        self.assertEqual(exp["missing"](store), 0)
        self.assertEqual(exp["empty_needle"](store), 1)

    def test_substring(self):
        src = (
            "fun mid() -> String\n"
            "    return \"hello world\".substring(6, 11)\n"
            "fun empty() -> String\n"
            "    return \"hello\".substring(2, 2)\n"
            "fun whole() -> String\n"
            "    return \"abc\".substring(0, 3)\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(self._read_string(store, exp, "mid"), "world")
        self.assertEqual(self._read_string(store, exp, "empty"), "")
        self.assertEqual(self._read_string(store, exp, "whole"), "abc")

    def test_to_upper_and_to_lower(self):
        src = (
            "fun upper() -> String\n"
            "    return \"hello world\".to_upper()\n"
            "fun lower() -> String\n"
            "    return \"HELLO WORLD\".to_lower()\n"
            "fun mixed() -> String\n"
            "    return \"Hello, World!\".to_upper()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(self._read_string(store, exp, "upper"), "HELLO WORLD")
        self.assertEqual(self._read_string(store, exp, "lower"), "hello world")
        self.assertEqual(self._read_string(store, exp, "mixed"), "HELLO, WORLD!")

    def test_to_upper_lower_ascii_only_non_ascii_intact(self):
        # to_upper / to_lower are ASCII-only by design: only A-Z <-> a-z
        # fold, every other code point passes through untouched. This
        # mirrors the Python backend (which routes through
        # _capa_to_upper / _capa_to_lower for byte-identical parity).
        # The accented "é", Greek, Cyrillic, and the emoji must survive
        # unchanged; only the surrounding ASCII letters change case.
        src = (
            "fun u_accent() -> String\n"
            "    return \"café\".to_upper()\n"
            "fun l_accent() -> String\n"
            "    return \"CAFÉx\".to_lower()\n"
            "fun greek() -> String\n"
            "    return \"Ελλ\".to_upper()\n"
            "fun emoji() -> String\n"
            "    return \"a\U0001F600B\".to_upper()\n"
        )
        store, exp = self._instantiate(src)
        # "café" -> "CAFé": the é is unchanged (Python's full-Unicode
        # .upper() would have produced "CAFÉ"; ASCII-only does not).
        self.assertEqual(self._read_string(store, exp, "u_accent"), "CAFé")
        # "CAFÉx" -> "cafÉx": only the ASCII x lowers; the É is intact.
        self.assertEqual(self._read_string(store, exp, "l_accent"), "cafÉx")
        # Greek letters have no ASCII fold, so they pass through.
        self.assertEqual(self._read_string(store, exp, "greek"), "Ελλ")
        # Emoji is a 4-byte code point; its bytes are never folded.
        # The surrounding ASCII letters do fold: "a😀B" -> "A😀B".
        self.assertEqual(self._read_string(store, exp, "emoji"), "A\U0001F600B")

    def test_trim_variants(self):
        src = (
            "fun both() -> String\n"
            "    return \"  spaced  \".trim()\n"
            "fun left() -> String\n"
            "    return \"  spaced  \".trim_start()\n"
            "fun right() -> String\n"
            "    return \"  spaced  \".trim_end()\n"
            "fun mixed_ws() -> String\n"
            "    return \"\\t\\n  hi  \\r\\n\".trim()\n"
            "fun no_trim_needed() -> String\n"
            "    return \"abc\".trim()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(self._read_string(store, exp, "both"), "spaced")
        self.assertEqual(self._read_string(store, exp, "left"), "spaced  ")
        self.assertEqual(self._read_string(store, exp, "right"), "  spaced")
        self.assertEqual(self._read_string(store, exp, "mixed_ws"), "hi")
        self.assertEqual(self._read_string(store, exp, "no_trim_needed"), "abc")

    def test_string_method_chaining(self):
        # Verify that the result of one string method can be the
        # receiver of another. Locals carry the (ptr, len) pair so
        # this works without explicit temp variables.
        src = (
            "fun pipeline() -> String\n"
            "    let s = \"  Hello, World!  \"\n"
            "    let t = s.trim()\n"
            "    return t.to_upper()\n"
        )
        store, exp = self._instantiate(src)
        self.assertEqual(
            self._read_string(store, exp, "pipeline"),
            "HELLO, WORLD!",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmStringSplit(unittest.TestCase):
    """Phase 6H: String.split(sep) -> List<String>. Also exercises
    the List<String> baseline (literal + index + iter) that the same
    change unlocks. The multi-character separator tests (2026-07)
    pin the substring-split semantics of Python's ``str.split``:
    cut at each NON-overlapping occurrence of the FULL separator,
    left to right. Pre-fix the Wasm backend compared only the first
    byte of the separator, so ``"a}}b".split("}}")`` cut at every
    ``}`` and inserted spurious empty chunks."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_list_string_literal_and_index(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = ["alpha", "beta", "gamma"]\n'
            '    stdio.println(xs[0])\n'
            '    stdio.println(xs[2])\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "alpha\ngamma\n")

    def test_list_string_for_iteration(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let xs = ["one", "two", "three"]\n'
            '    for s in xs\n'
            '        stdio.println(s)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "one\ntwo\nthree\n",
        )

    def test_split_simple(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "a,b,c".split(",")\n'
            '    stdio.println("n=${parts.length()}")\n'
            '    stdio.println(parts[0])\n'
            '    stdio.println(parts[1])\n'
            '    stdio.println(parts[2])\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=3\na\nb\nc\n",
        )

    def test_split_no_separator_found(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "abc".split(",")\n'
            '    stdio.println("n=${parts.length()}")\n'
            '    stdio.println(parts[0])\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=1\nabc\n",
        )

    def test_split_trailing_separator(self):
        # "a,,c" produces 3 elements with the middle one empty.
        src = (
            'fun main(stdio: Stdio)\n'
            '    let parts = "a,,c".split(",")\n'
            '    stdio.println("n=${parts.length()}")\n'
            '    stdio.println("mid_empty=${parts[1].is_empty()}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=3\nmid_empty=true\n",
        )

    def test_split_dotted_path(self):
        # policy-eval pattern: a.b.c -> ["a", "b", "c"]
        src = (
            'fun main(stdio: Stdio)\n'
            '    let segs = "config.encryption.enabled".split(".")\n'
            '    for s in segs\n'
            '        stdio.println(s)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "config\nencryption\nenabled\n",
        )

    def _split_stdout(self, receiver: str, sep: str) -> str:
        """Compile-and-run helper for the multi-char separator
        matrix: prints the element count then each part wrapped in
        angle brackets so empty chunks are visible in the exact
        stdout assertion."""
        src = (
            'fun main(stdio: Stdio)\n'
            f'    let parts = "{receiver}".split("{sep}")\n'
            '    stdio.println("n=${parts.length()}")\n'
            '    for p in parts\n'
            '        stdio.println("<${p}>")\n'
        )
        return self._run_capturing_stdout(src)

    def test_split_multichar_basic(self):
        # The original parity bug: the pre-fix byte-at-a-time scan
        # produced n=5 with empty chunks between the two `}` bytes.
        self.assertEqual(
            self._split_stdout("a}}b}}c", "}}"),
            "n=3\n<a>\n<b>\n<c>\n",
        )

    def test_split_multichar_leading_separator(self):
        # Python: "}}a".split("}}") == ["", "a"]
        self.assertEqual(
            self._split_stdout("}}a", "}}"), "n=2\n<>\n<a>\n",
        )

    def test_split_multichar_trailing_separator(self):
        # Python: "a}}".split("}}") == ["a", ""]
        self.assertEqual(
            self._split_stdout("a}}", "}}"), "n=2\n<a>\n<>\n",
        )

    def test_split_multichar_adjacent_separators(self):
        # Python: "a}}}}b".split("}}") == ["a", "", "b"]
        self.assertEqual(
            self._split_stdout("a}}}}b", "}}"), "n=3\n<a>\n<>\n<b>\n",
        )

    def test_split_multichar_absent_separator(self):
        # Python: "abc".split("}}") == ["abc"]
        self.assertEqual(
            self._split_stdout("abc", "}}"), "n=1\n<abc>\n",
        )

    def test_split_multichar_overlapping_occurrences(self):
        # Non-overlapping, left to right, same as Python:
        # "aaa".split("aa") == ["", "a"] (the match at offset 0
        # consumes both bytes; the match at offset 1 never fires).
        self.assertEqual(
            self._split_stdout("aaa", "aa"), "n=2\n<>\n<a>\n",
        )

    def test_split_separator_longer_than_receiver(self):
        # Python: "ab".split("abc") == ["ab"]
        self.assertEqual(
            self._split_stdout("ab", "abc"), "n=1\n<ab>\n",
        )

    def test_split_receiver_equals_separator(self):
        # Python: "}}".split("}}") == ["", ""]
        self.assertEqual(
            self._split_stdout("}}", "}}"), "n=2\n<>\n<>\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmIoErrorFormatStr(unittest.TestCase):
    """``${io}`` where ``io: IoError`` used to fail the Wasm
    backend with ``Phase 6F: FormatStr value of type 'IoError'
    not supported (Int / Bool / String only)``. Python tolerated
    it via ``__str__``. The 2026-05-27 fix special-cases IoError
    in ``_emit_format_part_stash`` to read the ``message`` field
    (a String at offset 0 of the 16-byte IoError record).

    General struct-to-string codegen for arbitrary user types
    is a separate (still open) P1 item; the cheap IoError
    special-case lands now because it unblocks the showcase's
    common ``stdio.eprintln("read error: ${io}")`` pattern."""

    def _run_capturing_stderr(self, src: str) -> str:
        # IoError interpolation flows through ``stdio.eprintln``
        # in the typical pattern; capture stderr to assert the
        # message renders correctly. The actual error path uses
        # fs.read on a non-existent file which returns an
        # IoError carrying a real OS message.
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_err = sys.stderr
        sys.stderr = out
        try:
            host.run_main(blob)
        finally:
            sys.stderr = saved_err
        return out.getvalue()

    def test_io_error_interpolated_via_eprintln(self):
        # Trigger a real IoError via fs.read on a missing path,
        # match the Err, interpolate the IoError into a stderr
        # message. The exact OS message varies, so we only
        # assert the prefix + non-empty suffix.
        src = (
            'fun main(stdio: Stdio, fs: Fs)\n'
            '    match fs.read("/does/not/exist/at/all")\n'
            '        Ok(_)  -> stdio.println("unexpected ok")\n'
            '        Err(e) -> stdio.eprintln("read error: ${e}")\n'
        )
        out = self._run_capturing_stderr(src)
        self.assertTrue(
            out.startswith("read error: "),
            f"unexpected stderr: {out!r}",
        )
        self.assertGreater(
            len(out.strip()), len("read error: "),
            "IoError message should be non-empty",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmGlobalStringConst(unittest.TestCase):
    """Top-level ``pub const NAME: String = "..."`` referenced from
    a function body used to fail the Wasm backend with either
    ``cannot push string Value of kind 'global' as (ptr, len)``
    (interpolation site) or ``cannot bind String dst ... from
    value Value(kind='global', ...)`` (let-binding site).

    Root cause was two-fold: (1) ``_push_string_value_as_ptr_len``
    and ``_emit_string_assign`` had no ``global`` case; (2) even
    if they had, the constant's UTF-8 bytes were never interned
    in the data segment (the discovery pass walks function
    bodies only, never ConstDecl) so the recursion would push
    offset=0 -- the data segment's start, not the constant's
    location.

    Fix landed 2026-05-27: pre-intern every String-typed
    top-level constant at module-emit init, and add the
    ``global`` branch in both push / assign helpers. Tests
    pin both code paths."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_const_string_interpolated_via_push(self):
        # Exercises ``_push_string_value_as_ptr_len``'s new
        # global branch -- the format-string lowering pushes
        # the value as (ptr, len) into the format buffer.
        src = (
            'pub const SCHEMA: String = "1.0"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println("schema=${SCHEMA}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "schema=1.0\n",
        )

    def test_const_string_let_bound_then_used(self):
        # Exercises ``_emit_string_assign``'s new global branch
        # -- the let copies the constant into a String local
        # (${dst}_ptr / ${dst}_len), then println reads from
        # the local.
        src = (
            'pub const GREETING: String = "hello"\n'
            'fun main(stdio: Stdio)\n'
            '    let g = GREETING\n'
            '    stdio.println(g)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "hello\n",
        )

    def test_const_string_passed_as_arg(self):
        # The arg push path also routes through
        # _push_string_value_as_ptr_len for String params.
        src = (
            'pub const NAME: String = "world"\n'
            'fun greet(stdio: Stdio, name: String)\n'
            '    stdio.println("hi ${name}")\n'
            'fun main(stdio: Stdio)\n'
            '    greet(stdio, NAME)\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "hi world\n",
        )
