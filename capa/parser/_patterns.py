"""Pattern-parsing mixin.

Handles the grammar for :class:`A.Pattern` nodes: wildcards,
tuples, literals, ident bindings, variant patterns, and struct
patterns. Also exposes ``_parse_primary_literal``, used both inside
patterns (literal arms) and indirectly by the expression mixin
through the primary-expression dispatch.

The ``in_match`` flag flips one heuristic: in match arms, a
PascalCase identifier with no payload is treated as a variant; in
``let`` / ``var`` / ``for`` contexts it is always a binding. See
:meth:`_parse_pattern` for the rationale.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..tokens import TokenKind as T


class _PatternsMixin:
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
            return self._build_string_lit(tok.value, tok.start, tok.interp_positions)
        if tok.kind == T.CHAR_LIT:
            return A.CharLit(pos=tok.start, value=tok.value)
        if tok.kind == T.KW_TRUE:
            return A.BoolLit(pos=tok.start, value=True)
        if tok.kind == T.KW_FALSE:
            return A.BoolLit(pos=tok.start, value=False)
        raise self._error(f"expected literal, got {tok.kind.name}")
