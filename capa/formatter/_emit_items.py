"""Top-level item emission for the AST pretty-printer.

Handles ``Module`` plus the seven ``Item`` shapes:

- :class:`Import`
- :class:`ConstDecl`
- :class:`TypeStruct`
- :class:`TypeSum`
- :class:`TraitDecl` (and ``capability``)
- :class:`ImplBlock`
- :class:`FunDecl`

Each ``_emit_*`` method emits the canonical Capa surface form for
that node, consulting the optional CommentMap through the
``_emit_leading`` / ``_emit_trailing_header`` hooks defined on
:class:`_Emitter`.

The mixin is intentionally thin: the heavy lifting (statements,
expressions, type expressions) is delegated to the other two
mixins.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A

from ._emit_exprs import _param_modifier_prefix


class _ItemsEmitterMixin:
    # ------------------------------------------------------------
    # Module entry
    # ------------------------------------------------------------
    def emit_module(self, module: A.Module) -> None:
        """Emit a whole module: leading comments, every item with one
        blank line between, trailing comments.

        If ``module`` has any ``leading`` comments AND any items,
        emit a blank line between the comment block and the first
        item. This separates a file-header comment block from the
        item it precedes, matching the canonical Capa style where
        file headers sit one blank line above the first item.
        Comments classified as ``leading`` on an item itself (the
        much more common case for narrative comments adjacent to a
        function definition) are emitted inside :meth:`_emit_item`
        WITHOUT the separator, so the section-divider-wrapped
        block

            // =====
            // body
            // =====
            fun foo

        re-emits intact.
        """
        att_module = self._attached(module)
        has_module_leading = (
            att_module is not None
            and bool(getattr(att_module, "leading", []) or [])
        )
        self._emit_leading(module)
        first = True
        for item in module.items:
            if first and has_module_leading:
                # Blank line between file header and first item.
                self._newline()
            elif not first:
                # One blank line between every top-level item.
                self._newline()
            self._emit_item(item)
            first = False
        # Module-level trailing (floating) comments after the last item.
        att = self._attached(module)
        if att is not None:
            trailing = getattr(att, "trailing", []) or []
            for c in trailing:
                self._newline()
                self._indent()
                self._write(c.text)
                self._newline()

    def _emit_item(self, item: A.Item) -> None:
        self._emit_leading(item)
        # Canonical separation between a leading-comment block (a
        # section divider like ``// =====`` is the typical case) and
        # the item's own ``///`` doc block: insert one blank line so
        # the visual ranking ``section header > item doc > item``
        # survives the round-trip. The AST does not record the doc
        # comment's source line, so we always insert the blank when
        # both blocks are non-empty rather than gating on the
        # original spacing.
        if self._has_leading(item) and _item_doc(item):
            self._newline()
        if isinstance(item, A.Import):
            self._emit_import(item)
        elif isinstance(item, A.ConstDecl):
            self._emit_const(item)
        elif isinstance(item, A.TypeStruct):
            self._emit_type_struct(item)
        elif isinstance(item, A.TypeSum):
            self._emit_type_sum(item)
        elif isinstance(item, A.TraitDecl):
            self._emit_trait(item)
        elif isinstance(item, A.ImplBlock):
            self._emit_impl(item)
        elif isinstance(item, A.FunDecl):
            self._emit_fun(item)
        else:
            raise AssertionError(
                f"unsupported top-level item: {type(item).__name__}"
            )

    def _has_leading(self, node: A.Node) -> bool:
        att = self._attached(node)
        if att is None:
            return False
        return bool(getattr(att, "leading", []) or [])

    # ------------------------------------------------------------
    # Doc comments / attributes / pub
    # ------------------------------------------------------------
    def _emit_doc(self, doc: Optional[str]) -> None:
        """Emit a multi-line doc string as one ``/// line`` per line.

        The ``/** */`` block form is intentionally normalised to the
        line form; we do not try to reconstruct the original spelling.
        """
        if not doc:
            return
        for line in doc.split("\n"):
            self._indent()
            # Avoid double space after ``///`` for blank doc lines.
            if line:
                self._write(f"/// {line}")
            else:
                self._write("///")
            self._newline()

    def _emit_attributes(self, attrs: list[A.Attribute]) -> None:
        for a in attrs:
            self._indent()
            self._write(f"@{a.name}(")
            parts = [f'{k}: "{_escape_string(v)}"' for (k, v) in a.args]
            self._write(", ".join(parts))
            self._write(")")
            self._newline()

    def _pub_prefix(self, is_pub: bool) -> str:
        return "pub " if is_pub else ""

    # ------------------------------------------------------------
    # Import
    # ------------------------------------------------------------
    def _emit_import(self, imp: A.Import) -> None:
        self._indent()
        path = ".".join(imp.path)
        if imp.selectors is not None:
            parts = [
                f"{name} as {alias}" if alias is not None else name
                for (name, alias) in imp.selectors
            ]
            self._write(f"import {path} ({', '.join(parts)})")
        elif imp.alias is not None:
            self._write(f"import {path} as {imp.alias}")
        else:
            self._write(f"import {path}")
        self._emit_trailing(imp)
        self._newline()

    # ------------------------------------------------------------
    # Const
    # ------------------------------------------------------------
    def _emit_const(self, c: A.ConstDecl) -> None:
        self._indent()
        self._write(self._pub_prefix(c.is_pub))
        self._write(f"const {c.name}: ")
        self._write(self._emit_type(c.type_expr))
        self._write(" = ")
        self._write(self._emit_expr(c.value))
        self._emit_trailing(c)
        self._newline()

    # ------------------------------------------------------------
    # Struct type
    # ------------------------------------------------------------
    def _emit_type_struct(self, t: A.TypeStruct) -> None:
        self._emit_doc(t.doc)
        self._indent()
        self._write(self._pub_prefix(t.is_pub))
        self._write(f"type {t.name}")
        self._write(_type_params_str(t.type_params))
        self._write(" {")
        if not t.fields:
            self._write("}")
            self._emit_trailing_header(t)
            self._newline()
            return
        self._emit_trailing_header(t)
        self._newline()
        # One field per line, indented one level, comma-separated.
        self._push_indent()
        for i, fld in enumerate(t.fields):
            self._indent()
            self._write(f"{fld.name}: {self._emit_type(fld.type_expr)}")
            if i < len(t.fields) - 1:
                self._write(",")
            self._newline()
        self._pop_indent()
        self._indent()
        self._write("}")
        self._newline()

    # ------------------------------------------------------------
    # Sum type
    # ------------------------------------------------------------
    def _emit_type_sum(self, t: A.TypeSum) -> None:
        self._emit_doc(t.doc)
        self._indent()
        self._write(self._pub_prefix(t.is_pub))
        self._write(f"type {t.name}")
        self._write(_type_params_str(t.type_params))
        self._write(" =")
        self._emit_trailing_header(t)
        self._newline()
        self._push_indent()
        for v in t.variants:
            self._indent()
            self._write(v.name)
            if v.payloads:
                payloads = ", ".join(self._emit_type(p) for p in v.payloads)
                self._write(f"({payloads})")
            self._newline()
        self._pop_indent()

    # ------------------------------------------------------------
    # Trait / capability
    # ------------------------------------------------------------
    def _emit_trait(self, t: A.TraitDecl) -> None:
        self._emit_doc(t.doc)
        self._indent()
        self._write(self._pub_prefix(t.is_pub))
        keyword = "capability" if t.is_capability else "trait"
        self._write(f"{keyword} {t.name}")
        self._write(_type_params_str(t.type_params))
        self._emit_trailing_header(t)
        self._newline()
        self._push_indent()
        if not t.methods:
            # Empty trait body: the parser requires INDENT/DEDENT, so
            # there is no representable empty trait. This branch
            # exists for defence in depth; a synthetic AST with an
            # empty methods list would emit nothing, which would not
            # re-parse. Callers should avoid constructing one.
            pass
        for m in t.methods:
            self._emit_method_sig(m)
        self._pop_indent()

    def _emit_method_sig(self, m: A.MethodSig) -> None:
        self._indent()
        self._write(f"fun {m.name}")
        self._write(_type_params_str(m.type_params))
        self._write("(")
        self._write(self._emit_params(m.params))
        self._write(")")
        if m.return_type is not None:
            self._write(f" -> {self._emit_type(m.return_type)}")
        # Declared capability bound (``uses [...]``): preserve it verbatim
        # rather than drop it on a reformat. ``None`` means no clause.
        if m.uses is not None:
            self._write(f" uses [{', '.join(m.uses)}]")
        self._newline()

    # ------------------------------------------------------------
    # Impl
    # ------------------------------------------------------------
    def _emit_impl(self, impl: A.ImplBlock) -> None:
        self._indent()
        if impl.trait_name is not None:
            head = f"impl {impl.trait_name} for {impl.type_name}"
        else:
            head = f"impl {impl.type_name}"
        if impl.type_args:
            head += "<" + ", ".join(
                self._emit_type(t) for t in impl.type_args
            ) + ">"
        self._write(head)
        self._emit_trailing_header(impl)
        self._newline()
        self._push_indent()
        first = True
        for m in impl.methods:
            if not first:
                self._newline()
            self._emit_leading(m)
            self._emit_fun(m)
            first = False
        self._pop_indent()

    # ------------------------------------------------------------
    # Function declarations
    # ------------------------------------------------------------
    def _emit_fun(self, fn: A.FunDecl) -> None:
        self._emit_doc(fn.doc)
        self._emit_attributes(fn.attributes)
        self._indent()
        self._write(self._pub_prefix(fn.is_pub))
        self._write(f"fun {fn.name}")
        self._write(_type_params_str(fn.type_params))
        # Decide between single-line and multi-line parameter list.
        # Single-line is canonical for short signatures; the example
        # corpus uses multi-line only when the source already had
        # the parameters broken across lines. The AST does not
        # preserve that, so we always emit single-line - matching
        # the dominant style in examples/ and evaluation/.
        self._write("(")
        self._write(self._emit_params(fn.params))
        self._write(")")
        if fn.return_type is not None:
            self._write(f" -> {self._emit_type(fn.return_type)}")
        self._emit_trailing_header(fn)
        self._newline()
        # Body: one INDENT level deeper than the header.
        self._push_indent()
        self._emit_block_body(fn.body)
        self._pop_indent()

    def _emit_params(self, params: list[A.Param]) -> str:
        out = []
        for p in params:
            if p.name == "self" and p.type_expr is None:
                out.append("self")
                continue
            prefix = _param_modifier_prefix(p)
            if p.type_expr is None:
                # Defensive: not expected for non-self parameters,
                # but emit a bare name rather than crashing.
                out.append(f"{prefix}{p.name}")
            else:
                out.append(
                    f"{prefix}{p.name}: {self._emit_type(p.type_expr)}"
                )
        return ", ".join(out)


# ----------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------
def _item_doc(item: A.Item) -> Optional[str]:
    """Return the doc string carried on ``item`` (None if the item
    kind has no doc field, or the field is empty / None).

    Only ``fun``, ``type``, ``trait`` and ``capability`` declarations
    are doc-bearing in the surface language; ``import``, ``const``
    and ``impl`` are not. Mirrors the parser's accept-set in
    :class:`_ItemsMixin._parse_item`.
    """
    doc = getattr(item, "doc", None)
    if doc:
        return doc
    return None


def _type_params_str(params: list[str]) -> str:
    if not params:
        return ""
    return "<" + ", ".join(params) + ">"


def _escape_string(s: str) -> str:
    """Escape a Python string for inclusion in a Capa double-quoted literal.

    Used by attribute argument values (which are required to be
    string literals). Mirrors the rules in ``_emit_exprs._emit_string_lit``
    but kept here as a small helper so the items mixin does not
    need to import from the expressions mixin.
    """
    out: list[str] = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\0":
            out.append("\\0")
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            out.append(f"\\u{{{ord(ch):x}}}")
        else:
            out.append(ch)
    return "".join(out)
