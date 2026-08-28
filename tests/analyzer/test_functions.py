"""Analyzer tests: method dispatch, trait impls, method chaining, lambdas and lambda param
inference, and callability rejections.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from capa import Lexer, Parser, analyze

from tests.analyzer._helpers import check, errors_of


class TestMethodDispatch(unittest.TestCase):
    """The analyzer does real dispatch of calls to methods defined in
    impl blocks, checking arity, argument types and returning the
    return type with substitution of receiver type params."""

    def test_method_returns_field_type(self):
        # extrair() returns the field type, with T substituted by the
        # concrete type of the receiver.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "type Caixa<T> { valor: T }\n"
            "impl Caixa<T>\n"
            "    fun extrair(self) -> T\n"
            "        return self.valor\n"
            "fun f() -> Int\n"
            "    let c = Caixa { valor: 42 }\n"
            "    return c.extrair()\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        # The expression c.extrair() should have type Int.
        ret_stmt = module.items[2].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(ret_stmt.value)]), "Int")

    def test_unknown_method_rejected(self):
        msgs = errors_of(
            "type Ponto { x: Float, y: Float }\n"
            "impl Ponto\n"
            "    fun distancia(self) -> Float\n"
            "        return self.x\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Ponto { x: 1.0, y: 2.0 }\n"
            "    let v = p.metodo_inexistente()\n"
        )
        self.assertTrue(
            any("has no method 'metodo_inexistente'" in m for m in msgs)
        )

    def test_method_arity_mismatch_rejected(self):
        msgs = errors_of(
            "type Ponto { x: Float, y: Float }\n"
            "impl Ponto\n"
            "    fun get_x(self) -> Float\n"
            "        return self.x\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Ponto { x: 1.0, y: 2.0 }\n"
            "    let v = p.get_x(99)\n"
        )
        self.assertTrue(
            any("expected 0 arguments, got 1" in m for m in msgs)
        )

    def test_method_arg_type_mismatch_rejected(self):
        msgs = errors_of(
            "type Caixa<T> { valor: T }\n"
            "impl Caixa<T>\n"
            "    fun substituir(self, novo: T) -> Caixa<T>\n"
            "        return Caixa { valor: novo }\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Caixa { valor: 42 }\n"
            "    let r = c.substituir(\"texto\")\n"
        )
        # T was inferred as Int from the receiver; "texto" is String.
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_self_returning_method(self):
        # A method that returns Self should resolve to the receiver type.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "type Contador { v: Int }\n"
            "impl Contador\n"
            "    fun incrementar(self) -> Self\n"
            "        return Contador { v: self.v + 1 }\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Contador { v: 0 }\n"
            "    let novo = c.incrementar()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_stmt = module.items[2].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_stmt.value)]), "Contador")

    def test_method_on_capability_passes(self):
        # Capabilities don't have impl in Capa code, calls to their
        # methods should continue to be accepted as TyUnknown.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "    stdio.eprintln(\"y\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestLambdas(unittest.TestCase):
    """Closures: ``fun (params) -> Ret => body``. For v0, body is
    always a single expression."""

    def test_lambda_typed_as_function(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let f = fun (x: Int) -> Int => x * 2\n"
            "    stdio.println(\"${f(21)}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_stmt = module.items[0].body.stmts[0]
        ty = ty_str(result.types[id(let_stmt.value)])
        # The exact textual representation depends on ty_str for TyFun;
        # verify that it contains Int → Int (in some format).
        self.assertIn("Int", ty)

    def test_lambda_return_type_mismatch_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let mau = fun (x: Int) -> Int => \"not int\"\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("lambda body has type String" in m for m in msgs)
        )

    def test_lambda_in_let(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let id = fun (x: Int) -> Int => x\n"
            "    stdio.println(\"${id(42)}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Function types and higher-order -------

    def test_function_type_in_param(self):
        r = check(
            "fun aplicar(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main(stdio: Stdio)\n"
            "    let dobro = fun (x: Int) -> Int => x * 2\n"
            "    let n = aplicar(dobro, 21)\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_function_type_two_params(self):
        r = check(
            "fun aplicar2(g: Fun(Int, Int) -> Int, a: Int, b: Int) -> Int\n"
            "    return g(a, b)\n"
            "fun main(stdio: Stdio)\n"
            "    let s = aplicar2(fun (a: Int, b: Int) -> Int => a + b, 3, 4)\n"
            "    stdio.println(\"${s}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_function_type_signature_mismatch_rejected(self):
        msgs = errors_of(
            "fun aplicar(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main(stdio: Stdio)\n"
            "    let r = aplicar(fun (x: Int) -> String => \"x\", 5)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects fun(Int) -> Int" in m for m in msgs),
            f"got: {msgs}",
        )

    # ------- Capability capture in closures -------

    def test_closure_capture_borrow_ok(self):
        # Capturing a cap and borrowing it is allowed.
        r = check(
            "fun emprestar(stdio: Stdio) -> Int\n"
            "    stdio.println(\"x\")\n"
            "    return 1\n"
            "fun main(stdio: Stdio)\n"
            "    let log = fun (x: Int) -> Int => emprestar(stdio) + x\n"
            "    let _r = log(1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_closure_capture_consume_rejected(self):
        # Capturing a cap and trying to consume it is an error: the closure
        # may be called multiple times.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio) -> Int\n"
            "    stdio.println(\"x\")\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let bad = fun (x: Int) -> Int => adoptar(stdio) + x\n"
            "    let _r = bad(1)\n"
        )
        self.assertTrue(
            any(
                "cannot consume capability 'stdio' captured from enclosing scope"
                in m for m in msgs
            )
        )

    def test_closure_consumes_own_param_ok(self):
        # Cap-as-param of the closure itself can be consumed, each
        # invocation receives its own.
        r = check(
            "fun adoptar(consume stdio: Stdio) -> Int\n"
            "    stdio.println(\"x\")\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let consumer = fun (s: Stdio) -> Int => adoptar(s)\n"
            "    let _r = consumer(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Block-body lambdas -------

    def test_block_body_lambda(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let log = fun (x: Int) -> Int =>\n"
            "        stdio.println(\"got ${x}\")\n"
            "        return x * 10\n"
            "    let _r = log(3)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_block_body_lambda_return_type_check(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let mau = fun (x: Int) -> Int =>\n"
            "        stdio.println(\"x\")\n"
            "        return \"string\"\n"
            "    stdio.println(\"never\")\n"
        )
        self.assertTrue(
            any("expected Int, got String" in m for m in msgs)
        )

    def test_block_body_capture_consume_rejected(self):
        # Capture analysis also applies in block-body lambdas.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio) -> Int\n"
            "    stdio.println(\"x\")\n"
            "    return 0\n"
            "fun main(stdio: Stdio)\n"
            "    let bad = fun (x: Int) -> Int =>\n"
            "        stdio.println(\"step\")\n"
            "        return adoptar(stdio) + x\n"
            "    let _r = bad(1)\n"
        )
        self.assertTrue(
            any(
                "cannot consume capability 'stdio' captured" in m
                for m in msgs
            )
        )

    # ------- break / continue cannot cross a lambda (BUG #8) -------
    #
    # A ``break`` / ``continue`` inside a lambda body cannot cross the
    # lambda's function boundary: the enclosing loop is not visible, so
    # both backends fail at codegen (Python SyntaxError, Wasm "break
    # outside of a loop"). The analyzer must reject it; a break /
    # continue directly inside a real loop must still be accepted.

    def test_break_in_lambda_inside_loop_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    for i in 0..3\n"
            "        let f = fun () -> Unit =>\n"
            "            if i == 1\n"
            "                break\n"
            "        f()\n"
        )
        self.assertTrue(
            any("break outside of a loop" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_continue_in_lambda_inside_loop_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    for i in 0..3\n"
            "        let f = fun () -> Unit =>\n"
            "            if i == 1\n"
            "                continue\n"
            "        f()\n"
        )
        self.assertTrue(
            any("continue outside of a loop" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_break_directly_in_loop_ok(self):
        # Control: break / continue directly inside a real loop body
        # (no lambda in between) must still be accepted.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    for i in 0..3\n"
            "        if i == 1\n"
            "            break\n"
            "        if i == 2\n"
            "            continue\n"
            '        stdio.println("${i}")\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_break_outside_loop_rejected(self):
        # A break at function top level (no enclosing loop) is also an
        # error -- the loop-depth tracking covers this case too.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    break\n"
        )
        self.assertTrue(
            any("break outside of a loop" in m for m in msgs),
            f"got: {msgs}",
        )


class TestTraitImpl(unittest.TestCase):
    """Trait impls are fully checked: presence and signatures of
    methods.
    """

    def test_correct_impl_ok(self):
        r = check(
            "trait Mostravel\n"
            "    fun mostrar(self) -> String\n"
            "type Pessoa { nome: String }\n"
            "impl Mostravel for Pessoa\n"
            "    fun mostrar(self) -> String\n"
            "        return self.nome\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_missing_method_rejected(self):
        msgs = errors_of(
            "trait Comparavel\n"
            "    fun comparar(self, outro: Self) -> Int\n"
            "    fun aux(self) -> Bool\n"
            "type X { x: Int }\n"
            "impl Comparavel for X\n"
            "    fun comparar(self, outro: Self) -> Int\n"
            "        return 0\n"
        )
        self.assertTrue(
            any("missing methods: aux" in m for m in msgs)
        )

    def test_wrong_signature_return_type_rejected(self):
        msgs = errors_of(
            "trait Mostravel\n"
            "    fun mostrar(self) -> String\n"
            "type N { v: Int }\n"
            "impl Mostravel for N\n"
            "    fun mostrar(self) -> Int\n"
            "        return self.v\n"
        )
        self.assertTrue(
            any(
                "expected signature fun() -> String, got fun() -> Int" in m
                for m in msgs
            ),
            f"got: {msgs}",
        )

    def test_wrong_signature_param_type_rejected(self):
        msgs = errors_of(
            "trait Adicionavel\n"
            "    fun adicionar(self, x: Int) -> Int\n"
            "type N { v: Int }\n"
            "impl Adicionavel for N\n"
            "    fun adicionar(self, x: String) -> Int\n"
            "        return self.v\n"
        )
        self.assertTrue(
            any("expected signature" in m for m in msgs)
        )

    def test_self_in_trait_signature_resolved(self):
        # Self in the trait signature should resolve to the impl type.
        r = check(
            "trait Clonavel\n"
            "    fun clonar(self) -> Self\n"
            "type Caixa { v: Int }\n"
            "impl Clonavel for Caixa\n"
            "    fun clonar(self) -> Self\n"
            "        return Caixa { v: self.v }\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_extra_methods_allowed(self):
        # Methods not declared in the trait are allowed as helpers.
        r = check(
            "trait Mostravel\n"
            "    fun mostrar(self) -> String\n"
            "type N { v: Int }\n"
            "impl Mostravel for N\n"
            "    fun mostrar(self) -> String\n"
            '        return "ok"\n'
            "    fun helper(self) -> Int\n"
            "        return self.v\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestMethodChaining(unittest.TestCase):
    """When a line starts with '.', the lexer suppresses the previous
    NEWLINE/INDENT, allowing chaining of methods across multiple lines."""

    def test_simple_chain_two_lines(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let r = xs\n"
            "        .filter(fun (x: Int) -> Bool => x > 1)\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_chain_three_methods(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3, 4]\n"
            "    let n = xs\n"
            "        .filter(fun (x: Int) -> Bool => x > 1)\n"
            "        .map(fun (x: Int) -> Int => x * 2)\n"
            "        .fold(0, fun (a: Int, x: Int) -> Int => a + x)\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_field_access_multi_line(self):
        # Chaining also with field access (not just methods).
        r = check(
            "type P { nome: String }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = P { nome: \"Ana\" }\n"
            "    let n = p\n"
            "        .nome\n"
            "    stdio.println(n)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_chain_with_inline_comment(self):
        # Comments between chain methods should be tolerated.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let r = xs\n"
            "        // filter\n"
            "        .filter(fun (x: Int) -> Bool => x > 1)\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestMethodWithoutSelfNotCallable(unittest.TestCase):
    """A user-defined impl method that does not take ``self`` as its
    first parameter cannot be called via ``receiver.method()``: the
    runtime would pass the receiver as the first positional argument
    and Python raises ``TypeError: ... takes 0 positional arguments
    but 1 was given``. The analyser rejects the call site at compile
    time.

    Built-in capability methods (``stdio.println``) and built-in
    type methods (``json.as_object``, ``xs.length``) are not subject
    to the check: they are registered at the BUILTIN_POS sentinel
    and dispatch through a different runtime path."""

    def test_call_user_method_without_self_is_rejected(self):
        errs = errors_of(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun get() -> Int\n"
            "        return 42\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Counter { v: 5 }\n"
            "    stdio.println(\"${c.get()}\")\n"
        )
        self.assertTrue(
            any("Counter.'get'" in e and "no 'self'" in e for e in errs),
            errs,
        )

    def test_static_method_declaration_still_accepted(self):
        # A "static" method (no self) is allowed at the impl level;
        # only the dot call is rejected. The user may keep the
        # method as a constructor-style helper even though there is
        # no public call syntax for it yet.
        r = check(
            "type Ponto { x: Float, y: Float }\n"
            "impl Ponto\n"
            "    fun zero() -> Ponto\n"
            "        return Ponto { x: 0.0, y: 0.0 }\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_user_method_with_self_still_accepted(self):
        # Regression guard against a prior failed attempt where the
        # check fired on every user impl method because ``param_names``
        # strips ``self``. With ``has_self`` stored on the symbol the
        # legitimate case stays accepted.
        r = check(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun valor(self) -> Int\n"
            "        return self.v\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Counter { v: 7 }\n"
            "    stdio.println(\"${c.valor()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_builtin_capability_method_still_callable(self):
        # Regression guard against a prior failed attempt that broke
        # every built-in capability method. ``stdio.println`` lives
        # in capa/builtins.py at BUILTIN_POS; the check is gated on
        # ``type_sym.pos != BUILTIN_POS`` and so leaves it alone.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"ok\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_builtin_jsonvalue_method_still_callable(self):
        # Regression guard against a prior failed attempt that broke
        # JsonValue methods because JsonValue is TYPE_SUM but its
        # methods are built-in. JsonValue.as_object lives at
        # BUILTIN_POS so the check leaves it alone.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    match parse_json(\"{}\")\n"
            "        Ok(j) ->\n"
            "            match j.as_object()\n"
            "                Some(_) -> stdio.println(\"object\")\n"
            "                None    -> stdio.println(\"other\")\n"
            "        Err(_) -> stdio.println(\"parse error\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestLambdaParamInference(unittest.TestCase):
    """Lambda parameter / return-type inference from the expected
    ``Fun(..)`` type of a higher-order-function argument slot."""

    def _main(self, body: str) -> str:
        lines = "".join(f"    {ln}\n" for ln in body.strip().splitlines())
        return f"fun main(stdio: Stdio)\n{lines}"

    def test_map_infers_param_and_return(self):
        r = check(self._main(
            "let xs = [1, 2, 3]\n"
            "let d = xs.map(fun (x) => x * 2)\n"
            "stdio.println(\"${d[0]}\")"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_filter_infers_bool_predicate(self):
        r = check(self._main(
            "let xs = [1, 2, 3, 4]\n"
            "let e = xs.filter(fun (x) => x % 2 == 0)\n"
            "stdio.println(\"${e.length()}\")"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_fold_infers_both_params(self):
        r = check(self._main(
            "let xs = [1, 2, 3]\n"
            "let t = xs.fold(0, fun (acc, x) => acc + x)\n"
            "stdio.println(\"${t}\")"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_mixed_typed_and_inferred_param(self):
        r = check(self._main(
            "let xs = [1, 2, 3]\n"
            "let t = xs.fold(0, fun (acc, x: Int) => acc + x)\n"
            "stdio.println(\"${t}\")"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_struct_element_param_inferred(self):
        src = (
            "type P { x: Int, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let ps = [P { x: 1, y: 2 }]\n"
            "    let xs = ps.map(fun (p) => p.x + p.y)\n"
            "    stdio.println(\"${xs[0]}\")\n"
        )
        r = check(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_user_defined_hof_infers_param(self):
        src = (
            "fun apply(f: Fun(Int) -> Int, n: Int) -> Int\n"
            "    return f(n)\n"
            "fun main(stdio: Stdio)\n"
            "    let r = apply(fun (x) => x * 3, 4)\n"
            "    stdio.println(\"${r}\")\n"
        )
        r = check(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_no_context_is_clear_error(self):
        r = check(self._main(
            "let f = fun (x) => x + 1\n"
            "stdio.println(\"hi\")"
        ))
        self.assertFalse(r.ok)
        self.assertTrue(
            any("cannot infer the type" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )

    def test_explicit_annotation_override_unaffected(self):
        r = check(self._main(
            "let xs = [1, 2, 3]\n"
            "let d = xs.map(fun (x: Int) -> Int => x * 2)\n"
            "stdio.println(\"${d[0]}\")"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_typed_param_no_return_still_works(self):
        # Pre-existing behaviour: an annotated parameter with an
        # omitted return type infers the return from the body without
        # needing higher-order context.
        r = check(self._main(
            "let xs = [1, 2, 3]\n"
            "let d = xs.map(fun (x: Int) => x * 2)\n"
            "stdio.println(\"${d[0]}\")"
        ))
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_inferred_param_type_written_back_into_ast(self):
        # The analyzer fills the omitted parameter / return annotations
        # back into the AST so the IR lowerer produces the same CIR as
        # a hand-annotated lambda.
        from capa import ast as A
        src = self._main(
            "let xs = [1, 2, 3]\n"
            "let d = xs.map(fun (x) => x * 2)\n"
            "stdio.println(\"${d[0]}\")"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        r = analyze(module, source=src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        lambdas = []

        def walk(node):
            if isinstance(node, A.LambdaExpr):
                lambdas.append(node)
            for v in vars(node).values():
                if isinstance(v, A.Node):
                    walk(v)
                elif isinstance(v, list):
                    for it in v:
                        if isinstance(it, A.Node):
                            walk(it)

        for item in module.items:
            walk(item)
        self.assertEqual(len(lambdas), 1)
        lam = lambdas[0]
        self.assertIsNotNone(lam.params[0].type_expr)
        self.assertEqual(lam.params[0].type_expr.name, "Int")
        self.assertIsNotNone(lam.return_type)
        self.assertEqual(lam.return_type.name, "Int")


if __name__ == "__main__":
    unittest.main()
