"""Analyzer tests: stdio, parse functions, ranges, numeric conversions, json (and helpers),
option/result methods, functional combinators, io-error read-only, and
internal-builtin rejection.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from capa import Lexer, Parser, analyze

from tests.analyzer._helpers import check, errors_of


class TestStdioMethods(unittest.TestCase):
    """Stdio now has typed methods: print, println, eprintln,
    read_line. The checker catches wrong types that previously passed
    as TyUnknown."""

    def test_println_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(123)\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_read_line_returns_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = stdio.read_line()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, IoError>",
        )

    def test_read_line_no_args(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let r = stdio.read_line(\"oops\")\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expected 0 arguments, got 1" in m for m in msgs)
        )


class TestParseFunctions(unittest.TestCase):
    """parse_int and parse_float convert String to Option<Int|Float>."""

    def test_parse_int_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(\"42\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_n = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_n.value)]), "Option<Int>")

    def test_parse_int_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )


class TestRangeExpressions(unittest.TestCase):
    """Range expressions: `a..b` (exclusive) and `a..=b` (inclusive).
    Endpoints must be Int; the result has type Range<Int> (a lazy
    iterable distinct from List<Int>; ``to_list()`` materialises
    when the full List method surface is needed)."""

    def test_exclusive_range_is_range_int(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = 0..10\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_xs = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_xs.value)]), "Range<Int>"
        )

    def test_inclusive_range_is_range_int(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = 1..=5\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_xs = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_xs.value)]), "Range<Int>"
        )

    def test_range_with_arithmetic_endpoints(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let n = 5\n"
            "    let xs = (n - 1)..(n * 2)\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_range_with_float_left_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = 1.0..10\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(
            any("requires Int endpoints" in m and "left side" in m for m in msgs),
            msgs,
        )

    def test_range_with_string_right_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = 0..\"ten\"\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(
            any("requires Int endpoints" in m and "right side" in m for m in msgs),
            msgs,
        )

    def test_range_to_list_chains_with_list_methods(self):
        # Range's API surface is intentionally minimal (length,
        # contains, is_empty, to_list). Users that want the full
        # List API call `.to_list()` first; the materialisation
        # is then explicit in the source rather than hidden.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let evens = (0..10).to_list().filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    stdio.println(\"${evens.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_range_filter_directly_typechecks(self):
        # The teaching material's exact example: a Range carries the
        # List transform methods, so direct `.filter` on a range
        # type-checks and yields `List<Int>` (the same type as
        # `(0..10).to_list().filter(...)`). Both backends desugar
        # through `.to_list()`.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let evens = (0..10).filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    stdio.println(\"${evens.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_evens = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_evens.value)]), "List<Int>")

    def test_range_transform_methods_typecheck(self):
        # map / fold / first / get carry the same signatures as their
        # List homonyms: map -> List<U>, fold -> the accumulator, the
        # indexed queries -> Option<T>.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let squares = (0..5).map(fun (x: Int) -> Int => x * x)\n"
            "    let total = (1..=5).fold(0, fun (a: Int, x: Int) -> Int => a + x)\n"
            "    let head = (0..5).first()\n"
            "    let at = (0..5).get(2)\n"
            "    stdio.println(\"${squares.length()} ${total}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        stmts = module.items[0].body.stmts
        self.assertEqual(ty_str(result.types[id(stmts[0].value)]), "List<Int>")
        self.assertEqual(ty_str(result.types[id(stmts[1].value)]), "Int")
        self.assertEqual(ty_str(result.types[id(stmts[2].value)]), "Option<Int>")
        self.assertEqual(ty_str(result.types[id(stmts[3].value)]), "Option<Int>")


class TestNumericConversions(unittest.TestCase):
    """to_float(Int) -> Float and to_int(Float) -> Int are the explicit
    bridges between numeric types (Capa has no implicit coercion)."""

    def test_to_float_typechecks(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x: Int = 5\n"
            "    let y = to_float(x)\n"
            "    stdio.println(\"${y}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_y = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_y.value)]), "Float")

    def test_to_float_unblocks_int_to_float_division(self):
        # The motivating use case: Float / Int is a type error, but
        # Float / to_float(Int) is well-typed.
        r = check(
            "fun avg(sum: Float, count: Int) -> Float\n"
            "    return sum / to_float(count)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_to_int_typechecks(self):
        r = check(
            "fun f() -> Int\n"
            "    return to_int(3.7)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_to_float_rejects_non_int(self):
        msgs = errors_of(
            "fun f() -> Float\n"
            "    return to_float(3.14)\n"
        )
        self.assertTrue(
            any("expects Int, got Float" in m for m in msgs),
            msgs,
        )

    def test_to_int_rejects_non_float(self):
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return to_int(42)\n"
        )
        self.assertTrue(
            any("expects Float, got Int" in m for m in msgs),
            msgs,
        )


class TestJson(unittest.TestCase):
    """JsonValue is a built-in sum type with 6 variants. parse_json and
    to_json are built-in functions."""

    def test_parse_json_returns_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = parse_json(\"{}\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<JsonValue, String>",
        )

    def test_match_all_json_variants(self):
        r = check(
            "fun describe(j: JsonValue) -> String\n"
            "    return match j\n"
            "        JNull -> \"null\"\n"
            "        JBool(b) -> \"bool\"\n"
            "        JNum(n) -> \"num\"\n"
            "        JStr(s) -> \"str\"\n"
            "        JArr(xs) -> \"arr\"\n"
            "        JObj(m) -> \"obj\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_non_exhaustive_json_match_rejected(self):
        msgs = errors_of(
            "fun describe(j: JsonValue) -> String\n"
            "    return match j\n"
            "        JNull -> \"null\"\n"
            "        JBool(b) -> \"bool\"\n"
        )
        self.assertTrue(
            any("missing variants" in m and "JArr" in m and "JObj" in m
                for m in msgs)
        )

    def test_jstr_payload_is_string(self):
        # In match against JStr(s), s should be String.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(\"hello\")\n"
            "    match v\n"
            "        JStr(s) -> stdio.println(s.to_upper())\n"
            "        _ -> stdio.println(\"\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_jstr_with_int_rejected(self):
        # JStr expects String in the payload.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("String" in m for m in msgs)
        )

    def test_to_json_returns_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = to_json(JNull)\n"
            "    stdio.println(s)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_s.value)]), "String")


class TestJsonHelpers(unittest.TestCase):
    """Methods as_string, as_num, etc. on JsonValue avoid boilerplate."""

    def test_as_string_returns_option_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(\"x\")\n"
            "    let s = v.as_string()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_s.value)]),
            "Option<String>",
        )

    def test_is_null_returns_bool(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let v = JNull\n"
            "    let b = v.is_null()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_b = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_b.value)]), "Bool")


class TestOptionResultMethods(unittest.TestCase):
    """Option and Result have is_some/is_none/is_ok/is_err/unwrap_or."""

    def test_option_is_some(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(42)\n"
            "    if o.is_some()\n"
            "        stdio.println(\"some\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_option_unwrap_or(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let n = o.unwrap_or(0)\n"
            "    stdio.println(\"${n}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_n = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_n.value)]), "Int")

    def test_option_unwrap_or_wrong_type_rejected(self):
        # unwrap_or<T>(default: T), default must have the same T as Option<T>.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let n = o.unwrap_or(\"oops\")\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_result_is_ok(self):
        r = check(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\")\n"
            "    if r.is_ok()\n"
            "        stdio.println(\"ok\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestFunctionalCombinators(unittest.TestCase):
    """map, and_then, ok_or, map_err on Option/Result."""

    def test_option_map_changes_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(\"42\")\n"
            "    let s = n.map(fun (x: Int) -> String => \"n\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_s.value)]),
            "Option<String>",
        )

    def test_option_ok_or_to_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = parse_int(\"42\").ok_or(\"bad\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<Int, String>",
        )

    def test_result_map_err_changes_error_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\").map_err(fun (e: IoError) -> Int => 1)\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, Int>",
        )

    def test_option_filter_returns_option_t(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(7)\n"
            "    let f = o.filter(fun (x: Int) -> Bool => x > 5)\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_f = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_f.value)]),
            "Option<Int>",
        )

    def test_option_filter_rejects_non_bool_predicate(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(7)\n"
            "    let f = o.filter(fun (x: Int) -> Int => x + 1)\n"
        )
        self.assertTrue(any("Bool" in m for m in msgs), msgs)

    def test_option_or_else_returns_option_t(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let r = o.or_else(fun () -> Option<Int> => Some(42))\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Option<Int>",
        )

    def test_result_or_else_can_change_error_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\").or_else(\n"
            "        fun (e: IoError) -> Result<String, Int> => Err(1)\n"
            "    )\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, Int>",
        )

    def test_result_ok_to_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Ok(7)\n"
            "    let o = r.ok()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_o = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_o.value)]),
            "Option<Int>",
        )

    def test_result_err_to_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Err(\"boom\")\n"
            "    let o = r.err()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_o = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_o.value)]),
            "Option<String>",
        )


class TestBuiltinIoErrorReadOnly(unittest.TestCase):
    """The builtin ``IoError``'s fields are readable but not
    writable: the Python runtime backs the value with a frozen
    dataclass (a write raises FrozenInstanceError at runtime) while
    the Wasm backend would silently store through the record
    pointer, a silent backend divergence. The analyzer rejects the
    write at compile time. A USER-declared ``type IoError`` shadows
    the builtin and keeps ordinary mutable-struct semantics."""

    def test_write_to_builtin_ioerror_field_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let e = IoError(\"x\")\n"
            "    e.message = \"y\"\n"
            "    stdio.println(\"${e.message}\")\n"
        )
        self.assertTrue(
            any("built-in 'IoError'" in m and "read-only" in m
                for m in msgs),
            msgs,
        )

    def test_augmented_write_to_builtin_ioerror_field_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let e = IoError(\"x\")\n"
            "    e.message += \"y\"\n"
            "    stdio.println(\"${e.message}\")\n"
        )
        self.assertTrue(
            any("built-in 'IoError'" in m and "read-only" in m
                for m in msgs),
            msgs,
        )

    def test_write_via_err_pattern_binder_rejected(self):
        msgs = errors_of(
            "fun fail() -> Result<Int, IoError>\n"
            "    return Err(IoError(\"boom\"))\n"
            "fun main(stdio: Stdio)\n"
            "    match fail()\n"
            "        Ok(n) -> stdio.println(\"ok ${n}\")\n"
            "        Err(e) ->\n"
            "            e.cause = \"later\"\n"
            "            stdio.println(\"err\")\n"
        )
        self.assertTrue(
            any("built-in 'IoError'" in m and "read-only" in m
                for m in msgs),
            msgs,
        )

    def test_read_of_builtin_ioerror_fields_still_allowed(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let e = IoError(\"boom\", \"root\")\n"
            "    stdio.println(\"${e.message}: ${e.cause}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_user_declared_ioerror_struct_stays_mutable(self):
        r = check(
            "type IoError { message: String, cause: String }\n"
            "fun main(stdio: Stdio)\n"
            "    var e = IoError { message: \"x\", cause: \"\" }\n"
            "    e.message = \"y\"\n"
            "    stdio.println(\"${e.message}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestInternalBuiltinRejection(unittest.TestCase):
    """Underscore-prefixed builtin functions (``_capa_chr``) are
    compiler-internal plumbing for the bundled JSON parser
    (``capa/ir/_builtin_json.capa``), not language surface. They
    became reachable from user code when ``_capa_chr`` landed in
    ``FREE_FUNCTIONS`` (2026-06-10); the analyzer now rejects user
    calls and bare references with a clear message. The bundled
    source itself is analyzed with ``internal=True`` and keeps
    access (pinned here by loading its IR)."""

    def test_user_call_to_capa_chr_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(_capa_chr(65))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_bare_reference_to_capa_chr_is_rejected(self):
        # Aliasing would smuggle the builtin past the call check.
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let f = _capa_chr\n"
            "    stdio.println(f(65))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_user_call_to_capa_str_span_is_rejected(self):
        # _capa_str_span (perf/wasm-json-span) is the same kind of
        # internal-only plumbing as _capa_chr: the bundled parser uses
        # it for O(1) value extraction, user code must not reach it.
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    var cs: List<String> = []\n"
            '    cs.push("a")\n'
            "    stdio.println(_capa_str_span(cs, 0, 1))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_user_underscore_function_still_callable(self):
        # A user-defined function that happens to start with ``_``
        # has a real source position (never BUILTIN_POS) and stays
        # callable.
        r = check(
            "fun _helper() -> Int\n"
            "    return 7\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${_helper()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_bundled_json_parser_keeps_internal_access(self):
        # The bundled parser calls _capa_chr to decode \uXXXX; its
        # loader analyzes with internal=True. Re-analyze the shipped
        # source both ways: internal=True must be clean, and the
        # user-mode analysis of the same source must trip the
        # rejection (proving the gate actually guards _capa_chr).
        from capa.ir._builtin_json import _BUNDLED_SOURCE_PATH
        source = _BUNDLED_SOURCE_PATH.read_text(encoding="utf-8")
        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        internal = analyze(module, source=source, internal=True)
        self.assertEqual([e.message for e in internal.errors], [])
        # Fresh parse for the user-mode run so the two analyses
        # cannot share AST-keyed state.
        module2 = Parser(
            Lexer(source).lex(), source=source,
        ).parse_module()
        as_user = analyze(module2, source=source)
        self.assertTrue(
            any(
                "internal compiler builtin" in e.message
                for e in as_user.errors
            ),
            [e.message for e in as_user.errors],
        )


if __name__ == "__main__":
    unittest.main()
