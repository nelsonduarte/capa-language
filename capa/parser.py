"""Recursive descent parser for the Capa language.

Implements the grammar defined in the EBNF document (chapter 5). The
strategy is pure recursive descent, with precedence climbing for binary
expressions. The lexer handles significant indentation: the parser only
consumes NEWLINE / INDENT / DEDENT as structural tokens.

Design decisions:
- Errors are detected as early as possible and propagated with precise
  position info.
- The self._error function produces a ParserError with caret-style
  formatting.
- For statements vs expressions, the rule is clear: if/while/for/match
  are statements (not expressions). Only expressions may appear where
  an expression is expected.
- Comparison operators are parsed as NON-associative: 1 < x < 10 is a
  syntax error.

Known limitations (v1.0):
- Lambdas (fun (x: T) => expr) are not yet implemented.
- Range expressions (a..b) are not yet implemented.
- Where clauses are not supported.
- Or-patterns (a | b) are not supported.
"""

from __future__ import annotations

from typing import Optional

from . import capa_ast as A
from .errors import LexerError
from .tokens import KEYWORDS, Pos, Token, TokenKind as T


class ParserError(LexerError):
    """Error detected by the parser. Reuses LexerError's formatting."""
    pass


# Token sets used in parser decisions.
_ASSIGN_OPS = {
    T.EQ:        "=",
    T.PLUS_EQ:   "+=",
    T.MINUS_EQ:  "-=",
    T.STAR_EQ:   "*=",
    T.SLASH_EQ:  "/=",
    T.PERCENT_EQ: "%=",
}

_COMPARISON_OPS = {
    T.EQ_EQ:  "==",
    T.BANG_EQ: "!=",
    T.LT:     "<",
    T.LT_EQ:  "<=",
    T.GT:     ">",
    T.GT_EQ:  ">=",
}

_ADDITIVE_OPS = {T.PLUS: "+", T.MINUS: "-"}
_MULTIPLICATIVE_OPS = {T.STAR: "*", T.SLASH: "/", T.PERCENT: "%"}


class Parser:
    """Recursive descent parser.

    Usage:
        from capa import Lexer, Parser
        tokens = Lexer(source).lex()
        ast = Parser(tokens, source=source, filename="x.capa").parse_module()
    """

    def __init__(
        self,
        tokens: list[Token],
        source: str = "",
        filename: str = "<input>",
    ):
        self.tokens = tokens
        self.idx = 0
        self.source = source
        self.filename = filename
        # When True, suppresses the "PascalCase IDENT followed by `{`"
        # heuristic that parses a struct literal. Used while parsing the
        # scrutinee of `match`, so `match SomeVariant { ... }` is read as
        # inline match arms rather than `match (SomeVariant { ... })`.
        # To use a struct literal as scrutinee, wrap it in parentheses.
        self._no_struct_lit = False

    def _build_string_lit(self, value: str, pos) -> A.Expr:
        """Builds a string literal. If it contains ``${...}``, returns
        an ``InterpolatedString`` with each interpolation parsed as a
        Capa expression. Otherwise, returns a plain ``StringLit``.

        ``$$`` is a literal escape for ``$``. Literal text and
        expressions alternate inside ``parts``.
        """
        if "${" not in value:
            return A.StringLit(pos=pos, value=value)
        parts: list = []
        buf: list[str] = []
        i = 0
        while i < len(value):
            c = value[i]
            if c == "$" and i + 1 < len(value) and value[i + 1] == "$":
                # Literal $ escape.
                buf.append("$")
                i += 2
                continue
            if c == "$" and i + 1 < len(value) and value[i + 1] == "{":
                # End accumulated literal text.
                parts.append("".join(buf))
                buf.clear()
                # Find the matching `}`, counting depth (to support
                # `${ {x: 1} }` in the future, although today such
                # cases are uncommon).
                depth = 1
                j = i + 2
                while j < len(value) and depth > 0:
                    if value[j] == "{":
                        depth += 1
                    elif value[j] == "}":
                        depth -= 1
                    if depth > 0:
                        j += 1
                if depth != 0:
                    raise self._error(
                        f"unterminated interpolation in string literal: {value!r}"
                    )
                expr_text = value[i + 2 : j]
                # Mini-lex + mini-parse of the expression. Reuses the
                # same lexer/parser on the raw source.
                expr = self._parse_interpolation(expr_text, pos)
                parts.append(expr)
                i = j + 1
                continue
            buf.append(c)
            i += 1
        # Remaining text after the last interpolation.
        parts.append("".join(buf))
        return A.InterpolatedString(pos=pos, parts=parts)

    def _parse_interpolation(self, expr_text: str, pos) -> A.Expr:
        """Parses ``expr_text`` (the content between ``${`` and ``}``)
        as a Capa expression.

        Creates a local Lexer and Parser for the sub-string. On error,
        propagates as a ParserError with the original literal's
        position (fine-grained reporting inside the interpolation
        would be possible but requires offset arithmetic, a future
        improvement).
        """
        from .lexer import Lexer
        try:
            sub_tokens = Lexer(expr_text, filename=self.filename).lex()
            sub_parser = Parser(
                sub_tokens, source=expr_text, filename=self.filename,
            )
            expr = sub_parser._parse_expr()
        except (LexerError, ParserError) as e:
            # Re-raise as an error of the outer literal, with position.
            raise self._error(
                f"error parsing interpolation: {e.message}"
            )
        return expr

    # ===========================================================
    # Cursor helpers
    # ===========================================================

    def _peek(self, n: int = 0) -> Token:
        i = self.idx + n
        if i >= len(self.tokens):
            return self.tokens[-1]  # EOF
        return self.tokens[i]

    def _at_end(self) -> bool:
        return self._peek().kind == T.EOF

    def _advance(self) -> Token:
        t = self.tokens[self.idx]
        if not self._at_end():
            self.idx += 1
        return t

    def _check(self, *kinds: T) -> bool:
        return self._peek().kind in kinds

    def _match(self, *kinds: T) -> Optional[Token]:
        if self._peek().kind in kinds:
            return self._advance()
        return None

    def _expect(self, kind: T, message: str) -> Token:
        if self._peek().kind == kind:
            return self._advance()
        got = self._peek()
        raise self._error(
            f"{message}; got {got.kind.name}"
            + (f" {got.text!r}" if got.text else ""),
            got,
        )

    def _error(self, message: str, tok: Optional[Token] = None) -> ParserError:
        tok = tok or self._peek()
        return ParserError(message, tok.start, self.source, self.filename)

    def _skip_newlines(self) -> None:
        while self._check(T.NEWLINE):
            self._advance()

    # ===========================================================
    # Main entry point
    # ===========================================================

    def parse_module(self) -> A.Module:
        start = self._peek().start
        self._skip_newlines()
        items: list[A.Item] = []
        while not self._at_end():
            items.append(self._parse_item())
            self._skip_newlines()
        return A.Module(pos=start, items=items)

    # ===========================================================
    # Top-level items
    # ===========================================================

    def _parse_item(self) -> A.Item:
        # Optional `pub` modifier
        is_pub = bool(self._match(T.KW_PUB))

        if self._check(T.KW_IMPORT):
            if is_pub:
                raise self._error("'pub' is not valid before 'import'")
            return self._parse_import()
        if self._check(T.KW_CONST):
            return self._parse_const(is_pub)
        if self._check(T.KW_TYPE):
            return self._parse_type_decl(is_pub)
        if self._check(T.KW_TRAIT):
            return self._parse_trait_decl(is_pub)
        if self._check(T.KW_CAPABILITY):
            return self._parse_capability_decl(is_pub)
        if self._check(T.KW_IMPL):
            if is_pub:
                raise self._error("'pub' is not valid before 'impl'")
            return self._parse_impl()
        if self._check(T.KW_FUN):
            return self._parse_fun_decl(is_pub)
        raise self._error(
            f"expected top-level declaration "
            f"(import / const / type / trait / capability / impl / fun), "
            f"got {self._peek().kind.name}"
        )

    # -------- import --------

    def _parse_import(self) -> A.Import:
        start = self._peek().start
        self._expect(T.KW_IMPORT, "expected 'import'")
        path = [self._expect(T.IDENT, "expected module name").text]
        while self._match(T.DOT):
            path.append(
                self._expect(T.IDENT, "expected identifier after '.'").text
            )
        alias: Optional[str] = None
        if self._match(T.KW_AS):
            alias = self._expect(T.IDENT, "expected alias name").text
        self._expect_eos("after import declaration")
        return A.Import(pos=start, path=path, alias=alias)

    # -------- const --------

    def _parse_const(self, is_pub: bool) -> A.ConstDecl:
        start = self._peek().start
        self._expect(T.KW_CONST, "expected 'const'")
        name = self._expect(T.IDENT, "expected constant name").text
        self._expect(T.COLON, "expected ':' after constant name")
        type_expr = self._parse_type()
        self._expect(T.EQ, "expected '=' in constant declaration")
        value = self._parse_expr()
        self._expect_eos("after constant declaration")
        return A.ConstDecl(
            pos=start,
            name=name,
            type_expr=type_expr,
            value=value,
            is_pub=is_pub,
        )

    # -------- type --------

    def _parse_type_decl(self, is_pub: bool) -> A.Item:
        start = self._peek().start
        self._expect(T.KW_TYPE, "expected 'type'")
        name = self._expect(T.IDENT, "expected type name").text
        type_params = self._parse_type_params_opt()

        if self._match(T.LBRACE):
            # Struct: type Name { fields }
            fields = self._parse_struct_fields()
            self._expect_eos("after struct declaration")
            return A.TypeStruct(
                pos=start,
                name=name,
                type_params=type_params,
                fields=fields,
                is_pub=is_pub,
            )
        if self._match(T.EQ):
            # Sum type: type Name = INDENT variants DEDENT
            self._expect(T.NEWLINE, "expected newline after '=' in sum type")
            self._expect(T.INDENT, "expected indented variants for sum type")
            variants: list[A.Variant] = []
            while not self._check(T.DEDENT) and not self._at_end():
                variants.append(self._parse_variant())
                self._skip_newlines()
            self._expect(T.DEDENT, "expected dedent at end of sum type")
            if not variants:
                raise self._error("sum type must have at least one variant")
            return A.TypeSum(
                pos=start,
                name=name,
                type_params=type_params,
                variants=variants,
                is_pub=is_pub,
            )
        raise self._error("expected '{' (struct) or '=' (sum) in type declaration")

    def _parse_struct_fields(self) -> list[A.Field]:
        """Inside { ... }, separated by commas, with optional newlines."""
        fields: list[A.Field] = []
        self._skip_newlines()
        while not self._check(T.RBRACE):
            fpos = self._peek().start
            fname = self._expect(T.IDENT, "expected field name").text
            self._expect(T.COLON, "expected ':' after field name")
            ftype = self._parse_type()
            fields.append(A.Field(pos=fpos, name=fname, type_expr=ftype))
            self._skip_newlines()
            if self._match(T.COMMA):
                self._skip_newlines()
                continue
            break
        self._expect(T.RBRACE, "expected '}' to close struct")
        return fields

    def _parse_variant(self) -> A.Variant:
        vpos = self._peek().start
        vname = self._expect(T.IDENT, "expected variant name").text
        payload: Optional[A.TypeExpr] = None
        if self._match(T.LPAREN):
            payload = self._parse_type()
            self._expect(T.RPAREN, "expected ')' after variant payload type")
        return A.Variant(pos=vpos, name=vname, payload=payload)

    # -------- trait --------

    def _parse_trait_decl(self, is_pub: bool) -> A.TraitDecl:
        return self._parse_trait_or_capability(is_pub, is_capability=False)

    def _parse_capability_decl(self, is_pub: bool) -> A.TraitDecl:
        """A user-defined capability. Syntactically identical to a trait;
        semantically, the analyzer treats the declared name as a
        capability and subjects it (and types that implement it) to the
        capability discipline. See WhitePaper §4.6.
        """
        return self._parse_trait_or_capability(is_pub, is_capability=True)

    def _parse_trait_or_capability(
        self, is_pub: bool, is_capability: bool,
    ) -> A.TraitDecl:
        start = self._peek().start
        keyword = T.KW_CAPABILITY if is_capability else T.KW_TRAIT
        word = "capability" if is_capability else "trait"
        self._expect(keyword, f"expected '{word}'")
        name = self._expect(T.IDENT, f"expected {word} name").text
        type_params = self._parse_type_params_opt()
        self._expect(T.NEWLINE, f"expected newline after {word} header")
        self._expect(T.INDENT, "expected indented method signatures")
        methods: list[A.MethodSig] = []
        while not self._check(T.DEDENT) and not self._at_end():
            methods.append(self._parse_method_sig())
            self._skip_newlines()
        self._expect(T.DEDENT, f"expected dedent at end of {word} body")
        return A.TraitDecl(
            pos=start,
            name=name,
            type_params=type_params,
            methods=methods,
            is_pub=is_pub,
            is_capability=is_capability,
        )

    def _parse_method_sig(self) -> A.MethodSig:
        start = self._peek().start
        self._expect(T.KW_FUN, "expected 'fun' in method signature")
        name = self._expect(T.IDENT, "expected method name").text
        type_params = self._parse_type_params_opt()
        self._expect(T.LPAREN, "expected '(' for parameter list")
        params = self._parse_params()
        self._expect(T.RPAREN, "expected ')' to close parameter list")
        return_type: Optional[A.TypeExpr] = None
        if self._match(T.ARROW):
            return_type = self._parse_type()
        self._expect_eos("after method signature")
        return A.MethodSig(
            pos=start,
            name=name,
            type_params=type_params,
            params=params,
            return_type=return_type,
        )

    # -------- impl --------

    def _parse_impl(self) -> A.ImplBlock:
        start = self._peek().start
        self._expect(T.KW_IMPL, "expected 'impl'")
        # Can be:
        #   impl Type<...>                      -> inherent impl
        #   impl Trait for Type<...>            -> trait impl
        first_name = self._expect(T.IDENT, "expected type or trait name").text
        first_args: list[A.TypeExpr] = []
        if self._check(T.LT):
            first_args = self._parse_type_args()
        if self._match(T.KW_FOR):
            trait_name: Optional[str] = first_name
            if first_args:
                # Traits with generic arguments are not currently supported.
                raise self._error(
                    "generic trait references in impl are not yet supported"
                )
            type_name = self._expect(T.IDENT, "expected target type name").text
            type_args: list[A.TypeExpr] = []
            if self._check(T.LT):
                type_args = self._parse_type_args()
        else:
            trait_name = None
            type_name = first_name
            type_args = first_args
        self._expect(T.NEWLINE, "expected newline after impl header")
        self._expect(T.INDENT, "expected indented method definitions")
        methods: list[A.FunDecl] = []
        while not self._check(T.DEDENT) and not self._at_end():
            # Methods inside impl can have `pub`.
            is_pub = bool(self._match(T.KW_PUB))
            methods.append(self._parse_fun_decl(is_pub))
            self._skip_newlines()
        self._expect(T.DEDENT, "expected dedent at end of impl block")
        return A.ImplBlock(
            pos=start,
            trait_name=trait_name,
            type_name=type_name,
            type_args=type_args,
            methods=methods,
        )

    # -------- fun --------

    def _parse_fun_decl(self, is_pub: bool) -> A.FunDecl:
        start = self._peek().start
        self._expect(T.KW_FUN, "expected 'fun'")
        name = self._expect(T.IDENT, "expected function name").text
        type_params = self._parse_type_params_opt()
        self._expect(T.LPAREN, "expected '(' for parameter list")
        params = self._parse_params()
        self._expect(T.RPAREN, "expected ')' to close parameter list")
        return_type: Optional[A.TypeExpr] = None
        if self._match(T.ARROW):
            return_type = self._parse_type()
        body = self._parse_block()
        return A.FunDecl(
            pos=start,
            name=name,
            type_params=type_params,
            params=params,
            return_type=return_type,
            body=body,
            is_pub=is_pub,
        )

    def _parse_type_params_opt(self) -> list[str]:
        if not self._match(T.LT):
            return []
        params: list[str] = []
        params.append(self._expect(T.IDENT, "expected type parameter name").text)
        while self._match(T.COMMA):
            params.append(
                self._expect(T.IDENT, "expected type parameter name").text
            )
        self._expect(T.GT, "expected '>' to close type parameter list")
        return params

    def _parse_params(self) -> list[A.Param]:
        params: list[A.Param] = []
        if self._check(T.RPAREN):
            return params
        params.append(self._parse_param())
        while self._match(T.COMMA):
            params.append(self._parse_param())
        return params

    def _parse_param(self) -> A.Param:
        ppos = self._peek().start
        # `self` is a special case: no type.
        if self._match(T.KW_SELF):
            return A.Param(pos=ppos, name="self", type_expr=None)
        # Optional `consume`: marks the parameter as consuming (transfers
        # ownership of the passed capability).
        consuming = bool(self._match(T.KW_CONSUME))
        name = self._expect(T.IDENT, "expected parameter name").text
        self._expect(T.COLON, f"expected ':' after parameter name {name!r}")
        type_expr = self._parse_type()
        return A.Param(
            pos=ppos, name=name, type_expr=type_expr, consuming=consuming,
        )

    # ===========================================================
    # Types
    # ===========================================================

    def _parse_type(self) -> A.TypeExpr:
        # Special case: () = UnitType
        if self._check(T.LPAREN):
            start = self._peek().start
            save = self.idx
            self._advance()
            if self._match(T.RPAREN):
                return A.UnitType(pos=start)
            # Tuple of types (T, U, V) - restore and parse
            self.idx = save
            return self._parse_tuple_or_paren_type()
        # Named type, with possible generic args. Also accepts Self.
        start = self._peek().start
        if self._check(T.KW_BIG_SELF):
            self._advance()
            name = "Self"
        else:
            name = self._expect(T.IDENT, "expected type name").text
        # Function type: 'Fun' followed by '('. Syntax:
        #   Fun(T1, T2, ...) -> Ret
        # Ambiguity with the outer function's return type: to return
        # a function, wrap it in parentheses or a tuple:
        # '(Fun(Int) -> Int)'.
        if name == "Fun" and self._check(T.LPAREN):
            self._advance()
            param_types: list[A.TypeExpr] = []
            if not self._check(T.RPAREN):
                param_types.append(self._parse_type())
                while self._match(T.COMMA):
                    param_types.append(self._parse_type())
            self._expect(T.RPAREN, "expected ')' to close 'Fun(...)'")
            self._expect(T.ARROW, "expected '->' after 'Fun(...)'")
            ret = self._parse_type()
            return A.FunType(pos=start, param_types=param_types, return_type=ret)
        args: list[A.TypeExpr] = []
        if self._check(T.LT):
            args = self._parse_type_args()
        return A.TypeName(pos=start, name=name, args=args)

    def _parse_tuple_or_paren_type(self) -> A.TypeExpr:
        start = self._peek().start
        self._expect(T.LPAREN, "expected '('")
        first = self._parse_type()
        if self._match(T.COMMA):
            elements = [first]
            while not self._check(T.RPAREN):
                elements.append(self._parse_type())
                if not self._match(T.COMMA):
                    break
            self._expect(T.RPAREN, "expected ')' to close tuple type")
            return A.TupleType(pos=start, elements=elements)
        self._expect(T.RPAREN, "expected ')' or ',' in type")
        return first

    def _parse_type_args(self) -> list[A.TypeExpr]:
        self._expect(T.LT, "expected '<'")
        args = [self._parse_type()]
        while self._match(T.COMMA):
            args.append(self._parse_type())
        self._expect(T.GT, "expected '>' to close type argument list")
        return args

    # ===========================================================
    # Statements and Block
    # ===========================================================

    def _parse_block(self) -> A.Block:
        """NEWLINE INDENT stmt+ DEDENT"""
        start = self._peek().start
        self._expect(T.NEWLINE, "expected newline before block")
        self._expect(T.INDENT, "expected indented block")
        stmts: list[A.Stmt] = []
        while not self._check(T.DEDENT) and not self._at_end():
            stmts.append(self._parse_stmt())
            self._skip_newlines()
        self._expect(T.DEDENT, "expected dedent at end of block")
        return A.Block(pos=start, stmts=stmts)

    def _parse_stmt(self) -> A.Stmt:
        if self._check(T.KW_LET):
            return self._parse_let_stmt()
        if self._check(T.KW_VAR):
            return self._parse_var_stmt()
        if self._check(T.KW_IF):
            return self._parse_if_stmt()
        if self._check(T.KW_WHILE):
            return self._parse_while_stmt()
        if self._check(T.KW_FOR):
            return self._parse_for_stmt()
        if self._check(T.KW_MATCH):
            start = self._peek().start
            expr = self._parse_match_expr()
            return A.ExprStmt(pos=start, expr=expr)
        if self._check(T.KW_RETURN):
            return self._parse_return_stmt()
        if self._check(T.KW_BREAK):
            start = self._advance().start
            self._expect_eos("after 'break'")
            return A.BreakStmt(pos=start)
        if self._check(T.KW_CONTINUE):
            start = self._advance().start
            self._expect_eos("after 'continue'")
            return A.ContinueStmt(pos=start)
        # Expression or assignment
        return self._parse_expr_or_assign_stmt()

    def _parse_let_stmt(self) -> A.LetStmt:
        start = self._peek().start
        self._expect(T.KW_LET, "expected 'let'")
        pattern = self._parse_pattern()
        type_expr: Optional[A.TypeExpr] = None
        if self._match(T.COLON):
            type_expr = self._parse_type()
        self._expect(T.EQ, "expected '=' in let binding")
        value = self._parse_expr()
        self._expect_eos("after let binding")
        return A.LetStmt(
            pos=start, pattern=pattern, type_expr=type_expr, value=value
        )

    def _parse_var_stmt(self) -> A.VarStmt:
        start = self._peek().start
        self._expect(T.KW_VAR, "expected 'var'")
        name = self._expect(T.IDENT, "expected variable name").text
        type_expr: Optional[A.TypeExpr] = None
        if self._match(T.COLON):
            type_expr = self._parse_type()
        self._expect(T.EQ, "expected '=' in var declaration")
        value = self._parse_expr()
        self._expect_eos("after var declaration")
        return A.VarStmt(pos=start, name=name, type_expr=type_expr, value=value)

    def _parse_if_stmt(self) -> A.IfStmt:
        start = self._peek().start
        self._expect(T.KW_IF, "expected 'if'")
        cond = self._parse_expr()
        then_block = self._parse_block()
        elif_arms: list[tuple[A.Expr, A.Block]] = []
        else_block: Optional[A.Block] = None
        # elif/else are only recognized immediately after the if's block;
        # the block parser has already consumed the DEDENT, so we are
        # already at the right level.
        while self._check(T.KW_ELIF):
            self._advance()
            elif_cond = self._parse_expr()
            elif_block = self._parse_block()
            elif_arms.append((elif_cond, elif_block))
        if self._match(T.KW_ELSE):
            else_block = self._parse_block()
        return A.IfStmt(
            pos=start,
            cond=cond,
            then_block=then_block,
            elif_arms=elif_arms,
            else_block=else_block,
        )

    def _parse_while_stmt(self) -> A.WhileStmt:
        start = self._peek().start
        self._expect(T.KW_WHILE, "expected 'while'")
        cond = self._parse_expr()
        body = self._parse_block()
        return A.WhileStmt(pos=start, cond=cond, body=body)

    def _parse_for_stmt(self) -> A.ForStmt:
        start = self._peek().start
        self._expect(T.KW_FOR, "expected 'for'")
        pattern = self._parse_pattern()
        self._expect(T.KW_IN, "expected 'in' in for loop")
        it = self._parse_expr()
        body = self._parse_block()
        return A.ForStmt(pos=start, pattern=pattern, iter=it, body=body)

    def _parse_lambda_expr(self) -> A.LambdaExpr:
        """Parses ``fun (params) -> Ret => body``. Body is a single
        expression or an indented block. Return type is optional.

        Block body: if ``=>`` is followed by NEWLINE, parses as a block
        (NEWLINE INDENT stmts DEDENT) - useful for lambdas with multiple
        statements, explicit returns, etc.
        """
        start = self._peek().start
        self._expect(T.KW_FUN, "expected 'fun'")
        self._expect(T.LPAREN, "expected '(' for lambda parameters")
        params: list[A.Param] = []
        if not self._check(T.RPAREN):
            params.append(self._parse_param())
            while self._match(T.COMMA):
                params.append(self._parse_param())
        self._expect(T.RPAREN, "expected ')' after lambda parameters")
        return_type: Optional[A.TypeExpr] = None
        if self._match(T.ARROW):
            return_type = self._parse_type()
        self._expect(T.FAT_ARROW, "expected '=>' before lambda body")
        # Block body: NEWLINE followed by INDENT.
        # Single-expr body: everything else.
        body: A.Expr | A.Block
        if self._check(T.NEWLINE):
            body = self._parse_block()
        else:
            body = self._parse_expr()
        return A.LambdaExpr(
            pos=start, params=params, return_type=return_type, body=body,
        )

    def _parse_match_expr(self) -> A.MatchExpr:
        start = self._peek().start
        self._expect(T.KW_MATCH, "expected 'match'")
        # Suppress the struct-literal heuristic while reading the
        # scrutinee, so that `match X { ... }` parses as an inline match
        # rather than `match (X { ... })`. Wrap the scrutinee in parens
        # if you really want a struct literal there.
        prev = self._no_struct_lit
        self._no_struct_lit = True
        try:
            scrutinee = self._parse_expr()
        finally:
            self._no_struct_lit = prev

        # Inline form: `match s { p -> e [, p -> e ]* [,] }`
        if self._check(T.LBRACE):
            return self._parse_match_inline_arms(start, scrutinee)

        # Multi-line form: NEWLINE INDENT arms DEDENT
        self._expect(
            T.NEWLINE,
            "expected newline or '{' after match scrutinee",
        )
        self._expect(T.INDENT, "expected indented match arms")
        arms: list[A.MatchArm] = []
        while not self._check(T.DEDENT) and not self._at_end():
            arms.append(self._parse_match_arm())
            self._skip_newlines()
        self._expect(T.DEDENT, "expected dedent at end of match")
        if not arms:
            raise self._error("match must have at least one arm")
        return A.MatchExpr(pos=start, scrutinee=scrutinee, arms=arms)

    def _parse_match_inline_arms(
        self, start, scrutinee: A.Expr,
    ) -> A.MatchExpr:
        """Parses inline match arms: ``{ p -> e, p -> e [, ...] }``.

        Each arm body is a single expression (no block bodies in the
        inline form). Or-patterns and guards are supported.
        """
        self._expect(T.LBRACE, "expected '{' for inline match arms")
        arms: list[A.MatchArm] = []
        if not self._check(T.RBRACE):
            arms.append(self._parse_inline_match_arm())
            while self._match(T.COMMA):
                if self._check(T.RBRACE):  # trailing comma
                    break
                arms.append(self._parse_inline_match_arm())
        self._expect(T.RBRACE, "expected '}' to close inline match arms")
        if not arms:
            raise self._error("inline match must have at least one arm")
        return A.MatchExpr(pos=start, scrutinee=scrutinee, arms=arms)

    def _parse_inline_match_arm(self) -> A.MatchArm:
        """Parses one arm of an inline match: ``pat [if guard] -> expr``.

        Or-patterns (``a | b | c``) are accepted at the arm level.
        """
        start = self._peek().start
        pattern = self._parse_pattern(in_match=True)
        if self._check(T.PIPE):
            alternatives: list[A.Pattern] = [pattern]
            while self._match(T.PIPE):
                alternatives.append(self._parse_pattern(in_match=True))
            pattern = A.OrPat(pos=start, alternatives=alternatives)
        guard: Optional[A.Expr] = None
        if self._match(T.KW_IF):
            guard = self._parse_expr()
        self._expect(T.ARROW, "expected '->' in inline match arm")
        body = self._parse_expr()
        return A.MatchArm(pos=start, pattern=pattern, guard=guard, body=body)

    def _parse_match_arm(self) -> A.MatchArm:
        start = self._peek().start
        pattern = self._parse_pattern(in_match=True)
        # Or-patterns: ``pat1 | pat2 | ...``. We keep parsing while we
        # see PIPE. This is only interpreted as an or-pattern in match
        # context (not in let/for/var).
        if self._check(T.PIPE):
            alternatives: list[A.Pattern] = [pattern]
            while self._match(T.PIPE):
                alternatives.append(self._parse_pattern(in_match=True))
            pattern = A.OrPat(pos=start, alternatives=alternatives)
        guard: Optional[A.Expr] = None
        if self._match(T.KW_IF):
            guard = self._parse_expr()
        self._expect(T.ARROW, "expected '->' in match arm")
        # Body: can be a single expression (terminated by NEWLINE), or an
        # indented block (NEWLINE INDENT stmts DEDENT).
        if self._check(T.NEWLINE):
            body: A.Block | A.Expr = self._parse_block()
        else:
            body = self._parse_expr()
            self._expect_eos("after match arm body")
        return A.MatchArm(pos=start, pattern=pattern, guard=guard, body=body)

    def _parse_return_stmt(self) -> A.ReturnStmt:
        start = self._peek().start
        self._expect(T.KW_RETURN, "expected 'return'")
        value: Optional[A.Expr] = None
        if not self._check(T.NEWLINE) and not self._at_end():
            value = self._parse_expr()
        self._expect_eos("after return statement")
        return A.ReturnStmt(pos=start, value=value)

    def _parse_expr_or_assign_stmt(self) -> A.Stmt:
        start = self._peek().start
        expr = self._parse_expr()
        if self._peek().kind in _ASSIGN_OPS:
            op_tok = self._advance()
            op = _ASSIGN_OPS[op_tok.kind]
            value = self._parse_expr()
            self._expect_eos(f"after assignment '{op}'")
            # Validate: target can only be an ident, field access, or index.
            if not isinstance(expr, (A.Ident, A.FieldAccess, A.Index)):
                raise self._error(
                    "invalid assignment target (must be name, field, or index)",
                    self.tokens[self.idx - 1] if self.idx > 0 else None,
                )
            return A.AssignStmt(pos=start, target=expr, op=op, value=value)
        self._expect_eos("after expression statement")
        return A.ExprStmt(pos=start, expr=expr)

    def _expect_eos(self, where: str) -> None:
        """End-of-statement: NEWLINE or EOF."""
        if self._check(T.NEWLINE):
            self._advance()
            return
        if self._at_end():
            return
        # In some cases, end-of-block (DEDENT) also counts as an
        # implicit end of statement - but the lexer emits NEWLINE
        # before DEDENT.
        if self._check(T.DEDENT):
            return
        # If the last consumed token was a NEWLINE or DEDENT, the
        # logical line has already ended - this typically happens when
        # a complex expression (match-expr) ends with a DEDENT that
        # closes its own block. We do not need to require another
        # NEWLINE.
        if self.idx > 0 and self.tokens[self.idx - 1].kind in (
            T.NEWLINE, T.DEDENT,
        ):
            return
        raise self._error(f"expected newline {where}")

    # ===========================================================
    # Patterns
    # ===========================================================

    def _parse_pattern(self, in_match: bool = False) -> A.Pattern:
        """Parses a pattern.

        In ``match`` context (in_match=True), identifiers that begin with
        an uppercase letter are treated as variants (PascalCase
        convention). In ``let``/``for``/``var`` context (in_match=False),
        a bare Ident is always a binding, regardless of capitalization -
        it is syntactically impossible to "destructure" a variant in
        let/for without an argument.

        Tuples: ``(pat1, pat2, ...)`` are destructured into ``TuplePat``.
        ``()`` is the pattern for Unit (zero elements). ``(p,)`` is a
        single-element tuple (trailing comma required to distinguish
        from grouping).
        """
        start = self._peek().start
        # _ is wildcard
        if self._match(T.UNDERSCORE):
            return A.WildcardPat(pos=start)
        # Tuple / grouping / unit
        if self._match(T.LPAREN):
            # ()  - empty TuplePat (matches Unit)
            if self._match(T.RPAREN):
                return A.TuplePat(pos=start, elements=[])
            first = self._parse_pattern(in_match=in_match)
            # (pat,) or (pat, pat, ...)
            if self._match(T.COMMA):
                elements = [first]
                # (pat,) - 1-tuple, with trailing comma
                if not self._check(T.RPAREN):
                    elements.append(self._parse_pattern(in_match=in_match))
                    while self._match(T.COMMA):
                        if self._check(T.RPAREN):
                            break
                        elements.append(self._parse_pattern(in_match=in_match))
                self._expect(T.RPAREN, "expected ')' to close tuple pattern")
                return A.TuplePat(pos=start, elements=elements)
            # (pat) - just grouping, returns the inner pattern
            self._expect(T.RPAREN, "expected ')' to close pattern")
            return first
        # Literals
        if self._check(T.INT_LIT, T.FLOAT_LIT, T.STRING_LIT, T.CHAR_LIT,
                       T.KW_TRUE, T.KW_FALSE):
            value = self._parse_primary_literal()
            return A.LiteralPat(pos=start, value=value)
        # Identifier: can be a simple binding, a variant, or a struct pattern.
        if self._check(T.IDENT):
            name = self._advance().text
            # Variant with payload: Name ( pattern )
            if self._match(T.LPAREN):
                payload = self._parse_pattern(in_match=in_match)
                self._expect(T.RPAREN, "expected ')' after variant payload")
                return A.VariantPat(pos=start, name=name, payload=payload)
            # Struct pattern: Name { ... }
            if self._match(T.LBRACE):
                fields = self._parse_struct_pattern_fields(in_match=in_match)
                return A.StructPat(pos=start, type_name=name, fields=fields)
            # No args/braces: PascalCase heuristic only in match context.
            if in_match and name and name[0].isupper():
                return A.VariantPat(pos=start, name=name, payload=None)
            return A.IdentPat(pos=start, name=name)
        raise self._error(f"expected pattern, got {self._peek().kind.name}")

    def _parse_struct_pattern_fields(
        self, in_match: bool = False,
    ) -> list[tuple[str, Optional[A.Pattern]]]:
        fields: list[tuple[str, Optional[A.Pattern]]] = []
        self._skip_newlines()
        while not self._check(T.RBRACE):
            fname = self._expect(
                T.IDENT, "expected field name in struct pattern"
            ).text
            sub: Optional[A.Pattern] = None
            if self._match(T.COLON):
                sub = self._parse_pattern(in_match=in_match)
            fields.append((fname, sub))
            self._skip_newlines()
            if self._match(T.COMMA):
                self._skip_newlines()
                continue
            break
        self._expect(T.RBRACE, "expected '}' to close struct pattern")
        return fields

    def _parse_primary_literal(self) -> A.Expr:
        """Just a literal, used in literal patterns."""
        tok = self._advance()
        if tok.kind == T.INT_LIT:
            return A.IntLit(pos=tok.start, value=tok.value)
        if tok.kind == T.FLOAT_LIT:
            return A.FloatLit(pos=tok.start, value=tok.value)
        if tok.kind == T.STRING_LIT:
            return self._build_string_lit(tok.value, tok.start)
        if tok.kind == T.CHAR_LIT:
            return A.CharLit(pos=tok.start, value=tok.value)
        if tok.kind == T.KW_TRUE:
            return A.BoolLit(pos=tok.start, value=True)
        if tok.kind == T.KW_FALSE:
            return A.BoolLit(pos=tok.start, value=False)
        raise self._error(f"expected literal, got {tok.kind.name}")

    # ===========================================================
    # Expressions - precedence climbing
    # ===========================================================

    def _parse_expr(self) -> A.Expr:
        # if-expression: ``if cond then e1 else e2``. The ``then`` is
        # the discriminator - without it, ``if`` is a statement
        # elsewhere in the parser and this path is not taken.
        if self._check(T.KW_IF):
            return self._parse_if_expr()
        # match was already parsed as an expression via _parse_match_expr
        # when it appears on the RHS of let/var/return; this branch is
        # reached if the user writes `let x = match e ...`.
        if self._check(T.KW_MATCH):
            return self._parse_match_expr()
        return self._parse_or()

    def _parse_if_expr(self) -> A.Expr:
        """Parses ``if cond then e1 else e2`` as an IfExpr.

        Note: ``then`` is required in expression form. Without ``then``,
        ``if`` is interpreted as a statement (parsed in another path).
        """
        start = self._expect(T.KW_IF, "expected 'if'").start
        cond = self._parse_or()
        self._expect(T.KW_THEN, "expected 'then' in if-expression")
        then_expr = self._parse_expr()
        self._expect(T.KW_ELSE, "expected 'else' in if-expression")
        else_expr = self._parse_expr()
        return A.IfExpr(
            pos=start, cond=cond,
            then_expr=then_expr, else_expr=else_expr,
        )

    def _parse_or(self) -> A.Expr:
        left = self._parse_and()
        while self._match(T.KW_OR):
            right = self._parse_and()
            left = A.BinOp(pos=left.pos, op="or", left=left, right=right)
        return left

    def _parse_and(self) -> A.Expr:
        left = self._parse_not()
        while self._match(T.KW_AND):
            right = self._parse_not()
            left = A.BinOp(pos=left.pos, op="and", left=left, right=right)
        return left

    def _parse_not(self) -> A.Expr:
        if self._check(T.KW_NOT):
            start = self._advance().start
            operand = self._parse_not()
            return A.UnaryOp(pos=start, op="not", operand=operand)
        return self._parse_comparison()

    def _parse_comparison(self) -> A.Expr:
        left = self._parse_range()
        if self._peek().kind in _COMPARISON_OPS:
            op_tok = self._advance()
            op = _COMPARISON_OPS[op_tok.kind]
            right = self._parse_range()
            # Non-associative: reject if another comparison operator follows.
            if self._peek().kind in _COMPARISON_OPS:
                next_tok = self._peek()
                raise self._error(
                    "comparison operators are non-associative; "
                    "use parentheses or boolean operators to combine",
                    next_tok,
                )
            return A.BinOp(pos=left.pos, op=op, left=left, right=right)
        return left

    def _parse_range(self) -> A.Expr:
        """Range expression: ``start..end`` (exclusive) or
        ``start..=end`` (inclusive). Non-associative — chained ranges
        like ``a..b..c`` are not allowed and would be a syntax error.
        Sits between comparison and addition in the precedence ladder,
        so ``1+2..5+3`` parses as ``(1+2)..(5+3)``.
        """
        left = self._parse_additive()
        if self._check(T.DOT_DOT):
            start_tok = self._advance()
            end = self._parse_additive()
            return A.RangeExpr(
                pos=start_tok.start, start=left, end=end, inclusive=False,
            )
        if self._check(T.DOT_DOT_EQ):
            start_tok = self._advance()
            end = self._parse_additive()
            return A.RangeExpr(
                pos=start_tok.start, start=left, end=end, inclusive=True,
            )
        return left

    def _parse_additive(self) -> A.Expr:
        left = self._parse_multiplicative()
        while self._peek().kind in _ADDITIVE_OPS:
            op_tok = self._advance()
            op = _ADDITIVE_OPS[op_tok.kind]
            right = self._parse_multiplicative()
            left = A.BinOp(pos=left.pos, op=op, left=left, right=right)
        return left

    def _parse_multiplicative(self) -> A.Expr:
        left = self._parse_unary()
        while self._peek().kind in _MULTIPLICATIVE_OPS:
            op_tok = self._advance()
            op = _MULTIPLICATIVE_OPS[op_tok.kind]
            right = self._parse_unary()
            left = A.BinOp(pos=left.pos, op=op, left=left, right=right)
        return left

    def _parse_unary(self) -> A.Expr:
        if self._check(T.MINUS):
            start = self._advance().start
            operand = self._parse_unary()
            return A.UnaryOp(pos=start, op="-", operand=operand)
        return self._parse_postfix()

    def _parse_postfix(self) -> A.Expr:
        expr = self._parse_primary()
        while True:
            if self._match(T.DOT):
                name_tok = self._expect(T.IDENT, "expected field or method name")
                # Method call if followed by '(' or turbofish '::<'.
                if self._check(T.LPAREN):
                    args = self._parse_call_args()
                    expr = A.MethodCall(
                        pos=expr.pos,
                        receiver=expr,
                        method=name_tok.text,
                        args=args,
                    )
                else:
                    expr = A.FieldAccess(
                        pos=expr.pos, receiver=expr, field_name=name_tok.text
                    )
                continue
            if self._check(T.LPAREN):
                # Function call
                args = self._parse_call_args()
                expr = A.Call(pos=expr.pos, callee=expr, args=args)
                continue
            if self._check(T.LBRACKET):
                self._advance()
                idx = self._parse_expr()
                self._expect(T.RBRACKET, "expected ']' after index expression")
                expr = A.Index(pos=expr.pos, receiver=expr, index=idx)
                continue
            if self._match(T.QUESTION):
                expr = A.Try(pos=expr.pos, expr=expr)
                continue
            break
        return expr

    def _parse_call_args(self) -> list[A.Expr]:
        self._expect(T.LPAREN, "expected '('")
        args: list[A.Expr] = []
        if not self._check(T.RPAREN):
            args.append(self._parse_expr())
            while self._match(T.COMMA):
                if self._check(T.RPAREN):  # trailing comma
                    break
                args.append(self._parse_expr())
        self._expect(T.RPAREN, "expected ')' to close call argument list")
        return args

    def _parse_primary(self) -> A.Expr:
        tok = self._peek()

        if tok.kind == T.INT_LIT:
            self._advance()
            return A.IntLit(pos=tok.start, value=tok.value)
        if tok.kind == T.FLOAT_LIT:
            self._advance()
            return A.FloatLit(pos=tok.start, value=tok.value)
        if tok.kind == T.STRING_LIT:
            self._advance()
            return self._build_string_lit(tok.value, tok.start)
        if tok.kind == T.CHAR_LIT:
            self._advance()
            return A.CharLit(pos=tok.start, value=tok.value)
        if tok.kind == T.KW_TRUE:
            self._advance()
            return A.BoolLit(pos=tok.start, value=True)
        if tok.kind == T.KW_FALSE:
            self._advance()
            return A.BoolLit(pos=tok.start, value=False)

        if tok.kind == T.LPAREN:
            return self._parse_paren_or_tuple()

        if tok.kind == T.LBRACKET:
            return self._parse_list_literal()

        if tok.kind == T.IDENT:
            return self._parse_ident_or_struct_lit()

        if tok.kind == T.KW_SELF:
            self._advance()
            return A.Ident(pos=tok.start, name="self")

        if tok.kind == T.KW_MATCH:
            return self._parse_match_expr()

        if tok.kind == T.KW_FUN:
            return self._parse_lambda_expr()

        raise self._error(
            f"expected expression, got {tok.kind.name}"
            + (f" {tok.text!r}" if tok.text else "")
        )

    def _parse_paren_or_tuple(self) -> A.Expr:
        start = self._peek().start
        self._expect(T.LPAREN, "expected '('")
        # () = unit
        if self._match(T.RPAREN):
            return A.UnitLit(pos=start)
        first = self._parse_expr()
        if self._match(T.COMMA):
            elements = [first]
            while not self._check(T.RPAREN):
                elements.append(self._parse_expr())
                if not self._match(T.COMMA):
                    break
            self._expect(T.RPAREN, "expected ')' to close tuple")
            return A.TupleLit(pos=start, elements=elements)
        self._expect(T.RPAREN, "expected ')' or ',' in parenthesized expression")
        return first

    def _parse_list_literal(self) -> A.ListLit:
        start = self._peek().start
        self._expect(T.LBRACKET, "expected '['")
        elements: list[A.Expr] = []
        self._skip_newlines()
        if not self._check(T.RBRACKET):
            elements.append(self._parse_expr())
            self._skip_newlines()
            while self._match(T.COMMA):
                self._skip_newlines()
                if self._check(T.RBRACKET):
                    break
                elements.append(self._parse_expr())
                self._skip_newlines()
        self._expect(T.RBRACKET, "expected ']' to close list literal")
        return A.ListLit(pos=start, elements=elements)

    def _parse_ident_or_struct_lit(self) -> A.Expr:
        """Identifier, possibly followed by '{' (struct literal).

        The heuristic: if it is an IDENT directly followed by '{' (with
        no newline between them), treat it as a struct literal.
        Otherwise, it is a plain reference. We use the PascalCase
        heuristic as additional confirmation to avoid ambiguity in
        statements like `if x { ... }` (not Capa, but avoids surprises).

        The ``_no_struct_lit`` flag overrides the heuristic — used when
        parsing the scrutinee of ``match`` so that ``match X { ... }``
        is the inline-arm form, not a struct literal as the scrutinee.
        """
        tok = self._advance()
        # Struct literal: Type { field: value, ... }
        # Convention: name starts with an uppercase letter.
        if (
            tok.text and tok.text[0].isupper()
            and self._check(T.LBRACE)
            and not self._no_struct_lit
        ):
            self._advance()  # {
            fields = self._parse_struct_lit_fields()
            return A.StructLit(
                pos=tok.start,
                type_name=tok.text,
                fields=fields,
            )
        return A.Ident(pos=tok.start, name=tok.text)

    def _parse_struct_lit_fields(self) -> list[tuple[str, A.Expr]]:
        fields: list[tuple[str, A.Expr]] = []
        self._skip_newlines()
        while not self._check(T.RBRACE):
            fname = self._expect(T.IDENT, "expected field name").text
            self._expect(T.COLON, "expected ':' in struct literal field")
            value = self._parse_expr()
            fields.append((fname, value))
            self._skip_newlines()
            if self._match(T.COMMA):
                self._skip_newlines()
                continue
            break
        self._expect(T.RBRACE, "expected '}' to close struct literal")
        return fields
