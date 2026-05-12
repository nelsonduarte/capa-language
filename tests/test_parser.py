"""Unit tests for the Capa parser.

Coverage: each relevant syntactic construct in isolation, plus some
small programs that exercise multiple constructs together.
Also includes tests for error messages and particular rules
(non-associative comparisons, valid assignment target, etc.).
"""

import unittest

from capa import Lexer, Parser, ParserError, LexerError
from capa import ast as A


def parse(source: str) -> A.Module:
    tokens = Lexer(source).lex()
    return Parser(tokens, source=source).parse_module()


def parse_expr(source: str) -> A.Expr:
    """For expression-focused tests: wraps the expression in an ExprStmt
    inside a main function, parses, and returns just the expression."""
    full = f"fun _t()\n    {source}\n"
    module = parse(full)
    fn = module.items[0]
    assert isinstance(fn, A.FunDecl)
    stmt = fn.body.stmts[0]
    assert isinstance(stmt, A.ExprStmt)
    return stmt.expr


# =============================================================
# Imports
# =============================================================

class TestImports(unittest.TestCase):
    def test_simple_import(self):
        m = parse("import json\n")
        self.assertEqual(len(m.items), 1)
        imp = m.items[0]
        self.assertIsInstance(imp, A.Import)
        self.assertEqual(imp.path, ["json"])
        self.assertIsNone(imp.alias)

    def test_import_with_alias(self):
        m = parse("import datetime as dt\n")
        imp = m.items[0]
        self.assertEqual(imp.path, ["datetime"])
        self.assertEqual(imp.alias, "dt")

    def test_dotted_import(self):
        m = parse("import std.collections\n")
        imp = m.items[0]
        self.assertEqual(imp.path, ["std", "collections"])

    def test_multiple_imports(self):
        m = parse("import a\nimport b\nimport c\n")
        self.assertEqual(len(m.items), 3)


# =============================================================
# Const
# =============================================================

class TestConst(unittest.TestCase):
    def test_simple_const(self):
        m = parse('const PI: Float = 3.14\n')
        c = m.items[0]
        self.assertIsInstance(c, A.ConstDecl)
        self.assertEqual(c.name, "PI")
        self.assertIsInstance(c.type_expr, A.TypeName)
        self.assertEqual(c.type_expr.name, "Float")
        self.assertIsInstance(c.value, A.FloatLit)

    def test_pub_const(self):
        m = parse('pub const MAX: Int = 100\n')
        c = m.items[0]
        self.assertTrue(c.is_pub)


# =============================================================
# Type declarations
# =============================================================

class TestTypeDecls(unittest.TestCase):
    def test_struct(self):
        m = parse("type Ponto { x: Float, y: Float }\n")
        t = m.items[0]
        self.assertIsInstance(t, A.TypeStruct)
        self.assertEqual(t.name, "Ponto")
        self.assertEqual(len(t.fields), 2)
        self.assertEqual(t.fields[0].name, "x")
        self.assertEqual(t.fields[1].name, "y")

    def test_struct_multiline(self):
        m = parse("type Ponto {\n    x: Float,\n    y: Float\n}\n")
        t = m.items[0]
        self.assertEqual(len(t.fields), 2)

    def test_struct_with_generics(self):
        m = parse("type Par<A, B> { primeiro: A, segundo: B }\n")
        t = m.items[0]
        self.assertEqual(t.type_params, ["A", "B"])

    def test_sum_type(self):
        m = parse("type Cor =\n    Vermelho\n    Verde\n    Azul\n")
        t = m.items[0]
        self.assertIsInstance(t, A.TypeSum)
        self.assertEqual(t.name, "Cor")
        self.assertEqual(len(t.variants), 3)
        self.assertEqual([v.name for v in t.variants],
                         ["Vermelho", "Verde", "Azul"])

    def test_sum_with_payload(self):
        m = parse("type Option<T> =\n    Some(T)\n    None\n")
        t = m.items[0]
        self.assertEqual(t.type_params, ["T"])
        self.assertIsNotNone(t.variants[0].payload)
        self.assertIsNone(t.variants[1].payload)


# =============================================================
# Trait and impl
# =============================================================

class TestTraits(unittest.TestCase):
    def test_simple_trait(self):
        m = parse(
            "trait Imprimivel\n"
            "    fun imprimir(self) -> String\n"
        )
        t = m.items[0]
        self.assertIsInstance(t, A.TraitDecl)
        self.assertEqual(len(t.methods), 1)
        sig = t.methods[0]
        self.assertEqual(sig.name, "imprimir")
        self.assertEqual(sig.params[0].name, "self")
        self.assertIsNone(sig.params[0].type_expr)

    def test_inherent_impl(self):
        m = parse(
            "impl Ponto\n"
            "    fun distancia(self) -> Float\n"
            "        return 0.0\n"
        )
        i = m.items[0]
        self.assertIsInstance(i, A.ImplBlock)
        self.assertIsNone(i.trait_name)
        self.assertEqual(i.type_name, "Ponto")
        self.assertEqual(len(i.methods), 1)

    def test_trait_impl(self):
        m = parse(
            "impl Imprimivel for Ponto\n"
            "    fun imprimir(self) -> String\n"
            "        return \"Ponto\"\n"
        )
        i = m.items[0]
        self.assertEqual(i.trait_name, "Imprimivel")
        self.assertEqual(i.type_name, "Ponto")


# =============================================================
# Functions
# =============================================================

class TestFunctions(unittest.TestCase):
    def test_simple_function(self):
        m = parse("fun id(x: Int) -> Int\n    return x\n")
        f = m.items[0]
        self.assertIsInstance(f, A.FunDecl)
        self.assertEqual(f.name, "id")
        self.assertEqual(len(f.params), 1)
        self.assertEqual(f.params[0].name, "x")

    def test_function_no_return_type(self):
        m = parse("fun saudar(nome: String)\n    return\n")
        f = m.items[0]
        self.assertIsNone(f.return_type)

    def test_function_with_generics(self):
        m = parse("fun primeiro<T>(xs: List<T>) -> T\n    return xs[0]\n")
        f = m.items[0]
        self.assertEqual(f.type_params, ["T"])

    def test_function_returning_self(self):
        m = parse(
            "impl Ponto\n"
            "    fun clone(self) -> Self\n"
            "        return self\n"
        )
        impl = m.items[0]
        ret = impl.methods[0].return_type
        self.assertIsInstance(ret, A.TypeName)
        self.assertEqual(ret.name, "Self")


# =============================================================
# Statements
# =============================================================

class TestStatements(unittest.TestCase):
    def test_let(self):
        m = parse("fun f()\n    let x = 1\n")
        body = m.items[0].body.stmts
        self.assertIsInstance(body[0], A.LetStmt)
        self.assertIsInstance(body[0].pattern, A.IdentPat)
        self.assertEqual(body[0].pattern.name, "x")

    def test_let_with_type(self):
        m = parse("fun f()\n    let x: Int = 1\n")
        let = m.items[0].body.stmts[0]
        self.assertIsNotNone(let.type_expr)

    def test_var(self):
        m = parse("fun f()\n    var i = 0\n")
        var = m.items[0].body.stmts[0]
        self.assertIsInstance(var, A.VarStmt)
        self.assertEqual(var.name, "i")

    def test_assign(self):
        m = parse("fun f()\n    var i = 0\n    i = 1\n")
        s = m.items[0].body.stmts[1]
        self.assertIsInstance(s, A.AssignStmt)
        self.assertEqual(s.op, "=")

    def test_compound_assign(self):
        m = parse("fun f()\n    var i = 0\n    i += 5\n")
        s = m.items[0].body.stmts[1]
        self.assertEqual(s.op, "+=")

    def test_if(self):
        m = parse("fun f()\n    if x > 0\n        return 1\n")
        s = m.items[0].body.stmts[0]
        self.assertIsInstance(s, A.IfStmt)

    def test_if_elif_else(self):
        m = parse(
            "fun f()\n"
            "    if x > 0\n"
            "        return 1\n"
            "    elif x < 0\n"
            "        return -1\n"
            "    else\n"
            "        return 0\n"
        )
        s = m.items[0].body.stmts[0]
        self.assertEqual(len(s.elif_arms), 1)
        self.assertIsNotNone(s.else_block)

    def test_while(self):
        m = parse("fun f()\n    while x > 0\n        x -= 1\n")
        s = m.items[0].body.stmts[0]
        self.assertIsInstance(s, A.WhileStmt)

    def test_for(self):
        m = parse("fun f()\n    for x in xs\n        consumir(x)\n")
        s = m.items[0].body.stmts[0]
        self.assertIsInstance(s, A.ForStmt)

    def test_match(self):
        m = parse(
            "fun classify(c: Cor) -> String\n"
            "    match c\n"
            "        Vermelho -> \"quente\"\n"
            "        Azul -> \"frio\"\n"
            "        _ -> \"outro\"\n"
        )
        stmt = m.items[0].body.stmts[0]
        # Match in statement position is ExprStmt(MatchExpr).
        self.assertIsInstance(stmt, A.ExprStmt)
        self.assertIsInstance(stmt.expr, A.MatchExpr)
        self.assertEqual(len(stmt.expr.arms), 3)

    def test_match_with_guard(self):
        m = parse(
            "fun f(x: Int)\n"
            "    match x\n"
            "        n if n > 0 -> \"positivo\"\n"
            "        _ -> \"outro\"\n"
        )
        stmt = m.items[0].body.stmts[0]
        self.assertIsInstance(stmt, A.ExprStmt)
        self.assertIsInstance(stmt.expr, A.MatchExpr)
        self.assertIsNotNone(stmt.expr.arms[0].guard)

    def test_break_continue(self):
        m = parse(
            "fun f()\n"
            "    while true\n"
            "        break\n"
            "        continue\n"
        )
        body = m.items[0].body.stmts[0].body.stmts
        self.assertIsInstance(body[0], A.BreakStmt)
        self.assertIsInstance(body[1], A.ContinueStmt)

    def test_assignment_to_field(self):
        m = parse("fun f()\n    p.x = 1\n")
        s = m.items[0].body.stmts[0]
        self.assertIsInstance(s, A.AssignStmt)
        self.assertIsInstance(s.target, A.FieldAccess)


# =============================================================
# Expressions
# =============================================================

class TestExpressions(unittest.TestCase):
    def test_literals(self):
        self.assertIsInstance(parse_expr("42"), A.IntLit)
        self.assertIsInstance(parse_expr("3.14"), A.FloatLit)
        self.assertIsInstance(parse_expr('"hello"'), A.StringLit)
        self.assertIsInstance(parse_expr("'a'"), A.CharLit)
        self.assertIsInstance(parse_expr("true"), A.BoolLit)
        self.assertIsInstance(parse_expr("()"), A.UnitLit)

    def test_arithmetic_precedence(self):
        # 1 + 2 * 3 = BinOp(+, 1, BinOp(*, 2, 3))
        e = parse_expr("1 + 2 * 3")
        self.assertIsInstance(e, A.BinOp)
        self.assertEqual(e.op, "+")
        self.assertIsInstance(e.right, A.BinOp)
        self.assertEqual(e.right.op, "*")

    def test_left_associativity(self):
        # 1 - 2 - 3 = BinOp(-, BinOp(-, 1, 2), 3)
        e = parse_expr("1 - 2 - 3")
        self.assertEqual(e.op, "-")
        self.assertIsInstance(e.left, A.BinOp)
        self.assertEqual(e.left.op, "-")

    def test_unary_minus(self):
        e = parse_expr("-x")
        self.assertIsInstance(e, A.UnaryOp)
        self.assertEqual(e.op, "-")

    def test_logical_ops(self):
        e = parse_expr("a and b or c")
        # 'or' has lower precedence: (a and b) or c
        self.assertEqual(e.op, "or")
        self.assertEqual(e.left.op, "and")

    def test_not(self):
        e = parse_expr("not x")
        self.assertIsInstance(e, A.UnaryOp)
        self.assertEqual(e.op, "not")

    def test_comparison_non_associative(self):
        with self.assertRaises(ParserError) as ctx:
            parse_expr("1 < x < 10")
        self.assertIn("non-associative", str(ctx.exception))

    def test_function_call(self):
        e = parse_expr("f(1, 2, 3)")
        self.assertIsInstance(e, A.Call)
        self.assertEqual(len(e.args), 3)
        # All-positional: arg_names should be all None.
        self.assertEqual(e.arg_names, [None, None, None])

    def test_call_with_named_arguments(self):
        e = parse_expr('f(1, name: "Ana", age: 30)')
        self.assertIsInstance(e, A.Call)
        self.assertEqual(len(e.args), 3)
        self.assertEqual(e.arg_names, [None, "name", "age"])
        self.assertIsInstance(e.args[0], A.IntLit)
        self.assertIsInstance(e.args[1], A.StringLit)
        self.assertIsInstance(e.args[2], A.IntLit)

    def test_method_call(self):
        e = parse_expr("obj.metodo(x)")
        self.assertIsInstance(e, A.MethodCall)
        self.assertEqual(e.method, "metodo")
        self.assertEqual(e.arg_names, [None])

    def test_method_call_with_named_arguments(self):
        e = parse_expr("p.move(dx: 1, dy: 2)")
        self.assertIsInstance(e, A.MethodCall)
        self.assertEqual(e.method, "move")
        self.assertEqual(e.arg_names, ["dx", "dy"])

    def test_field_access(self):
        e = parse_expr("p.x")
        self.assertIsInstance(e, A.FieldAccess)
        self.assertEqual(e.field_name, "x")

    def test_index(self):
        e = parse_expr("xs[0]")
        self.assertIsInstance(e, A.Index)

    def test_try(self):
        e = parse_expr("ler()?")
        self.assertIsInstance(e, A.Try)

    def test_chained_postfix(self):
        # obj.field[0].method()?
        e = parse_expr("obj.campo[0].metodo()?")
        self.assertIsInstance(e, A.Try)
        self.assertIsInstance(e.expr, A.MethodCall)

    def test_struct_literal(self):
        e = parse_expr("Ponto { x: 1.0, y: 2.0 }")
        self.assertIsInstance(e, A.StructLit)
        self.assertEqual(e.type_name, "Ponto")
        self.assertEqual(len(e.fields), 2)

    def test_list_literal(self):
        e = parse_expr("[1, 2, 3]")
        self.assertIsInstance(e, A.ListLit)
        self.assertEqual(len(e.elements), 3)

    def test_empty_list(self):
        e = parse_expr("[]")
        self.assertEqual(len(e.elements), 0)

    def test_paren_expression(self):
        e = parse_expr("(1 + 2)")
        # Parentheses group but don't create their own node.
        self.assertIsInstance(e, A.BinOp)

    def test_tuple(self):
        e = parse_expr("(1, 2)")
        self.assertIsInstance(e, A.TupleLit)
        self.assertEqual(len(e.elements), 2)


# =============================================================
# Complete programs (smoke tests)
# =============================================================

class TestCompletePrograms(unittest.TestCase):
    def test_hello_world(self):
        src = (
            'fun main(stdio: Stdio)\n'
            '    stdio.print("Olá, mundo!")\n'
        )
        m = parse(src)
        self.assertEqual(len(m.items), 1)

    def test_canonical_example(self):
        """Exercises: type sum, type struct, trait, impl, fun, guarded match,
        ?, struct lit, list lit, for."""
        with open("examples/tasks.capa", encoding="utf-8") as f:
            src = f.read()
        m = parse(src)
        # 8 items: type sum, type struct, trait, 2 helper funs, impl,
        # classify_urgency fun, main fun.
        self.assertEqual(len(m.items), 8)

    def test_basics_example(self):
        with open("examples/basics.capa", encoding="utf-8") as f:
            src = f.read()
        m = parse(src)
        self.assertGreater(len(m.items), 0)


# =============================================================
# Errors
# =============================================================

class TestErrors(unittest.TestCase):
    def test_missing_function_body(self):
        with self.assertRaises(ParserError):
            parse("fun f()\n")

    def test_invalid_assignment_target(self):
        with self.assertRaises(ParserError) as ctx:
            parse("fun f()\n    1 + 1 = 2\n")
        self.assertIn("invalid assignment target", str(ctx.exception))

    def test_unexpected_token(self):
        # `let` without pattern is a parser error (not a lexer error).
        with self.assertRaises(ParserError):
            parse("fun f()\n    let = 1\n")

    def test_pub_before_import_rejected(self):
        with self.assertRaises(ParserError):
            parse("pub import json\n")


# =============================================================
# Documented restrictions (block-body inside parentheses)
# =============================================================

class TestBlockBodyInParensRestriction(unittest.TestCase):
    """Inside ``(...)`` the lexer suppresses NEWLINE/INDENT/DEDENT
    for implicit line continuation. Constructs whose body shape
    relies on those layout tokens (block-body lambdas, indent-form
    match) are unreachable there by design. The parser should
    surface a clear, actionable error rather than a generic
    "expected expression"."""

    def test_block_body_lambda_inside_parens_has_targeted_error(self):
        src = (
            "fun apply(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main()\n"
            "    let _ = apply(fun (x: Int) -> Int =>\n"
            "        let y = x + 1\n"
            "        return y\n"
            "    , 5)\n"
        )
        with self.assertRaises(ParserError) as ctx:
            parse(src)
        msg = str(ctx.exception)
        self.assertIn("block-body lambda", msg)
        self.assertIn("inside parentheses", msg)
        # The error should mention the recommended workaround.
        self.assertTrue(
            "let" in msg or "single-expression" in msg, msg,
        )

    def test_let_bound_block_body_lambda_then_pass_works(self):
        # The documented workaround: bind the lambda to a let, pass
        # the binding through the call. Must parse cleanly.
        src = (
            "fun apply(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main()\n"
            "    let body = fun (x: Int) -> Int =>\n"
            "        let y = x + 1\n"
            "        return y * 10\n"
            "    let _ = apply(body, 5)\n"
        )
        m = parse(src)
        self.assertEqual(len(m.items), 2)

    def test_single_expression_lambda_inside_parens_still_works(self):
        # Single-expression lambdas inside parens must remain
        # unaffected by the targeted block-body diagnostic.
        src = (
            "fun apply(f: Fun(Int) -> Int, x: Int) -> Int\n"
            "    return f(x)\n"
            "fun main()\n"
            "    let _ = apply(fun (x: Int) -> Int => x * 2, 5)\n"
        )
        m = parse(src)
        self.assertEqual(len(m.items), 2)


if __name__ == "__main__":
    unittest.main()
