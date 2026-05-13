"""Top-level item parsing mixin.

Owns everything below the module entry point: each top-level
declaration plus the helpers they share.

- ``_parse_item``: dispatch between ``import`` / ``const`` /
  ``type`` / ``trait`` / ``capability`` / ``impl`` / ``fun``,
  applying the ``pub`` / attribute / doc-comment rules.
- Doc comments: ``_consume_doc_comments_opt`` concatenates
  consecutive ``///`` lines.
- Attributes: ``_parse_attributes_opt`` / ``_parse_attribute`` /
  ``_parse_attribute_arg`` parse ``@name(key: "value", ...)``
  lines. The parser is permissive about names; the analyzer
  validates them against ``_ATTRIBUTE_SCHEMA``.
- Declarations: ``_parse_import``, ``_parse_const``,
  ``_parse_type_decl`` (handles both struct and sum forms),
  ``_parse_struct_fields``, ``_parse_variant``,
  ``_parse_trait_decl``, ``_parse_capability_decl``,
  ``_parse_trait_or_capability``, ``_parse_method_sig``,
  ``_parse_impl``, ``_parse_fun_decl``.
- Helpers: ``_parse_type_params_opt``, ``_parse_params``,
  ``_parse_param``.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..tokens import TokenKind as T


class _ItemsMixin:
    def _parse_item(self) -> A.Item:
        # Doc comments (/// or /**) attach to the next declaration if
        # it accepts them (fun, type, trait, capability). They are
        # collected here so that attribute and `pub` parsing below
        # can stay simple.
        doc = self._consume_doc_comments_opt()

        # Optional attributes (@name(...)). v1 supports them only on `fun`;
        # presence on any other top-level construct is an explicit error.
        attributes = self._parse_attributes_opt()

        # Optional `pub` modifier
        is_pub = bool(self._match(T.KW_PUB))

        if self._check(T.KW_IMPORT):
            if is_pub:
                raise self._error("'pub' is not valid before 'import'")
            if attributes:
                raise self._error("attributes are not valid on 'import'")
            if doc:
                raise self._error("doc comments are not valid on 'import'")
            return self._parse_import()
        if self._check(T.KW_CONST):
            if attributes:
                raise self._error(
                    "attributes are not valid on 'const' "
                    "(v1 supports them on 'fun' only)"
                )
            if doc:
                raise self._error(
                    "doc comments are not valid on 'const' "
                    "(v1 supports them on fun / type / trait / capability)"
                )
            return self._parse_const(is_pub)
        if self._check(T.KW_TYPE):
            if attributes:
                raise self._error(
                    "attributes are not valid on 'type' "
                    "(v1 supports them on 'fun' only)"
                )
            return self._parse_type_decl(is_pub, doc=doc)
        if self._check(T.KW_TRAIT):
            if attributes:
                raise self._error(
                    "attributes are not valid on 'trait' "
                    "(v1 supports them on 'fun' only)"
                )
            return self._parse_trait_decl(is_pub, doc=doc)
        if self._check(T.KW_CAPABILITY):
            if attributes:
                raise self._error(
                    "attributes are not valid on 'capability' "
                    "(v1 supports them on 'fun' only)"
                )
            return self._parse_capability_decl(is_pub, doc=doc)
        if self._check(T.KW_IMPL):
            if is_pub:
                raise self._error("'pub' is not valid before 'impl'")
            if attributes:
                raise self._error(
                    "attributes are not valid on 'impl' "
                    "(v1 supports them on 'fun' only)"
                )
            if doc:
                raise self._error(
                    "doc comments are not valid on 'impl' "
                    "(attach to its methods instead)"
                )
            return self._parse_impl()
        if self._check(T.KW_FUN):
            return self._parse_fun_decl(is_pub, attributes=attributes, doc=doc)
        raise self._error(
            f"expected top-level declaration "
            f"(import / const / type / trait / capability / impl / fun), "
            f"got {self._peek().kind.name}"
        )

    # -------- doc comments (/// and /** */) --------

    def _consume_doc_comments_opt(self) -> Optional[str]:
        """Consume any DOC_COMMENT tokens at the current position and
        return their concatenated text, or None if there are none.

        Consecutive ``///`` lines are joined with newlines; intervening
        NEWLINE tokens between them are absorbed silently so that

            /// line one
            /// line two
            fun f()

        produces ``"line one\\nline two"``. A single ``/** ... */``
        block already carries multi-line content in its value, so it
        is appended as-is.
        """
        parts: list[str] = []
        # We may be after newlines from a previous item; skip them first.
        self._skip_newlines()
        while self._check(T.DOC_COMMENT):
            tok = self._advance()
            parts.append(tok.value)
            # Allow a single NEWLINE between consecutive doc tokens.
            while self._check(T.NEWLINE):
                self._advance()
        if not parts:
            return None
        return "\n".join(parts)

    # -------- attributes (@name(key: "value", ...)) --------

    def _parse_attributes_opt(self) -> list[A.Attribute]:
        """Parse zero or more attribute lines (``@name(key: "value", ...)``).

        Each attribute is followed by its own newline. Stacking is
        allowed:

            @security(cve: "CVE-2024-12345", severity: "high")
            @audited(date: "2026-05-11", by: "Nelson Duarte")
            fun verify_token(stdio: Stdio, token: String) -> Bool
                ...

        The analyzer is responsible for validating attribute names and
        the shape of their argument lists; the parser is permissive
        about the name but requires string-literal values.
        """
        attributes: list[A.Attribute] = []
        while self._check(T.AT):
            attributes.append(self._parse_attribute())
            self._skip_newlines()
        return attributes

    def _parse_attribute(self) -> A.Attribute:
        start = self._peek().start
        self._expect(T.AT, "expected '@' to begin attribute")
        name_tok = self._expect(T.IDENT, "expected attribute name after '@'")
        self._expect(T.LPAREN, f"expected '(' after attribute '@{name_tok.text}'")
        args: list[tuple[str, str]] = []
        if not self._check(T.RPAREN):
            args.append(self._parse_attribute_arg())
            while self._match(T.COMMA):
                if self._check(T.RPAREN):
                    # Trailing comma is permitted.
                    break
                args.append(self._parse_attribute_arg())
        self._expect(T.RPAREN, "expected ')' to close attribute arguments")
        self._expect_eos(f"after '@{name_tok.text}' attribute")
        return A.Attribute(pos=start, name=name_tok.text, args=args)

    def _parse_attribute_arg(self) -> tuple[str, str]:
        """Parse ``key: "value"`` inside an attribute's argument list.

        v1 restricts values to string literals so that attributes are
        statically inspectable without running expression evaluation.
        """
        key_tok = self._expect(T.IDENT, "expected attribute argument name")
        self._expect(T.COLON, f"expected ':' after attribute key '{key_tok.text}'")
        val_tok = self._expect(
            T.STRING_LIT,
            f"attribute argument '{key_tok.text}' must be a string literal",
        )
        return (key_tok.text, val_tok.value)

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
        name_tok = self._expect(T.IDENT, "expected constant name")
        self._expect(T.COLON, "expected ':' after constant name")
        type_expr = self._parse_type()
        self._expect(T.EQ, "expected '=' in constant declaration")
        value = self._parse_expr()
        self._expect_eos("after constant declaration")
        return A.ConstDecl(
            pos=start,
            name=name_tok.text,
            name_pos=name_tok.start,
            type_expr=type_expr,
            value=value,
            is_pub=is_pub,
        )

    # -------- type --------

    def _parse_type_decl(
        self,
        is_pub: bool,
        *,
        doc: Optional[str] = None,
    ) -> A.Item:
        start = self._peek().start
        self._expect(T.KW_TYPE, "expected 'type'")
        name_tok = self._expect(T.IDENT, "expected type name")
        name = name_tok.text
        name_pos = name_tok.start
        type_params = self._parse_type_params_opt()

        if self._match(T.LBRACE):
            # Struct: type Name { fields }
            fields = self._parse_struct_fields()
            self._expect_eos("after struct declaration")
            return A.TypeStruct(
                pos=start,
                name=name,
                name_pos=name_pos,
                type_params=type_params,
                fields=fields,
                is_pub=is_pub,
                doc=doc,
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
                name_pos=name_pos,
                type_params=type_params,
                variants=variants,
                is_pub=is_pub,
                doc=doc,
            )
        raise self._error("expected '{' (struct) or '=' (sum) in type declaration")

    def _parse_struct_fields(self) -> list[A.Field]:
        """Inside { ... }, separated by commas, with optional newlines."""
        fields: list[A.Field] = []
        self._skip_newlines()
        while not self._check(T.RBRACE):
            fname_tok = self._expect(T.IDENT, "expected field name")
            self._expect(T.COLON, "expected ':' after field name")
            ftype = self._parse_type()
            fields.append(A.Field(
                pos=fname_tok.start,
                name=fname_tok.text,
                name_pos=fname_tok.start,
                type_expr=ftype,
            ))
            self._skip_newlines()
            if self._match(T.COMMA):
                self._skip_newlines()
                continue
            break
        self._expect(T.RBRACE, "expected '}' to close struct")
        return fields

    def _parse_variant(self) -> A.Variant:
        vname_tok = self._expect(T.IDENT, "expected variant name")
        payload: Optional[A.TypeExpr] = None
        if self._match(T.LPAREN):
            payload = self._parse_type()
            self._expect(T.RPAREN, "expected ')' after variant payload type")
        return A.Variant(
            pos=vname_tok.start,
            name=vname_tok.text,
            name_pos=vname_tok.start,
            payload=payload,
        )

    # -------- trait --------

    def _parse_trait_decl(
        self,
        is_pub: bool,
        *,
        doc: Optional[str] = None,
    ) -> A.TraitDecl:
        return self._parse_trait_or_capability(
            is_pub, is_capability=False, doc=doc,
        )

    def _parse_capability_decl(
        self,
        is_pub: bool,
        *,
        doc: Optional[str] = None,
    ) -> A.TraitDecl:
        """A user-defined capability. Syntactically identical to a trait;
        semantically, the analyzer treats the declared name as a
        capability and subjects it (and types that implement it) to the
        capability discipline. See WhitePaper §4.6.
        """
        return self._parse_trait_or_capability(
            is_pub, is_capability=True, doc=doc,
        )

    def _parse_trait_or_capability(
        self,
        is_pub: bool,
        is_capability: bool,
        *,
        doc: Optional[str] = None,
    ) -> A.TraitDecl:
        start = self._peek().start
        keyword = T.KW_CAPABILITY if is_capability else T.KW_TRAIT
        word = "capability" if is_capability else "trait"
        self._expect(keyword, f"expected '{word}'")
        name_tok = self._expect(T.IDENT, f"expected {word} name")
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
            name=name_tok.text,
            name_pos=name_tok.start,
            type_params=type_params,
            methods=methods,
            is_pub=is_pub,
            is_capability=is_capability,
            doc=doc,
        )

    def _parse_method_sig(self) -> A.MethodSig:
        start = self._peek().start
        self._expect(T.KW_FUN, "expected 'fun' in method signature")
        name_tok = self._expect(T.IDENT, "expected method name")
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
            name=name_tok.text,
            name_pos=name_tok.start,
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
            # Methods inside impl can have doc comments, attributes and `pub`.
            doc = self._consume_doc_comments_opt()
            attributes = self._parse_attributes_opt()
            is_pub = bool(self._match(T.KW_PUB))
            methods.append(
                self._parse_fun_decl(is_pub, attributes=attributes, doc=doc)
            )
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

    def _parse_fun_decl(
        self,
        is_pub: bool,
        attributes: Optional[list[A.Attribute]] = None,
        *,
        doc: Optional[str] = None,
    ) -> A.FunDecl:
        if attributes is None:
            attributes = []
        # If attributes were collected upstream, point the FunDecl at the
        # first attribute's line so IDE tooling navigates to the start of
        # the whole annotated block, not just the `fun` keyword.
        start = attributes[0].pos if attributes else self._peek().start
        self._expect(T.KW_FUN, "expected 'fun'")
        name_tok = self._expect(T.IDENT, "expected function name")
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
            name=name_tok.text,
            name_pos=name_tok.start,
            type_params=type_params,
            params=params,
            return_type=return_type,
            body=body,
            is_pub=is_pub,
            attributes=attributes,
            doc=doc,
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
            return A.Param(pos=ppos, name="self", name_pos=ppos, type_expr=None)
        # Optional `consume`: marks the parameter as consuming (transfers
        # ownership of the passed capability).
        consuming = bool(self._match(T.KW_CONSUME))
        name_tok = self._expect(T.IDENT, "expected parameter name")
        name = name_tok.text
        self._expect(T.COLON, f"expected ':' after parameter name {name!r}")
        type_expr = self._parse_type()
        return A.Param(
            pos=ppos, name=name, name_pos=name_tok.start,
            type_expr=type_expr, consuming=consuming,
        )
