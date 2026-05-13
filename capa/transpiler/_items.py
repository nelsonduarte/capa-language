"""Top-level item emission mixin.

Owns the AST -> Python translation for the seven ``Item`` shapes
(``import`` / ``const`` / ``type`` struct / ``type`` sum /
``trait`` / ``impl`` / ``fun``) plus the ``main`` bootstrap.

- ``_emit_item``: dispatcher over the item kinds.
- ``_emit_import``: emits a comment, never a real Python ``import``
  (the analyzer rejects ``import`` in v1; this is defence in
  depth).
- ``_emit_struct`` / ``_emit_sum`` / ``_emit_trait`` /
  ``_emit_impl``: type machinery, mapping Capa types to ``@dataclass``
  and ABC-style classes.
- ``_emit_fun``: function definitions, applying ``@_capa_wrap``
  when the body uses ``?``.
- ``_emit_main_bootstrap`` / ``_capability_for_param``: produce
  the ``if __name__ == "__main__":`` block that instantiates
  capabilities and calls ``main``.
"""

from __future__ import annotations

from .. import capa_ast as A


class _ItemsMixin:
    def _emit_item(self, item: A.Item) -> None:
        from . import TranspilerError
        if isinstance(item, A.Import):
            self._emit_import(item)
        elif isinstance(item, A.ConstDecl):
            self._emit_const(item)
        elif isinstance(item, A.TypeStruct):
            self._emit_struct(item)
        elif isinstance(item, A.TypeSum):
            self._emit_sum(item)
        elif isinstance(item, A.TraitDecl):
            self._emit_trait(item)
        elif isinstance(item, A.ImplBlock):
            self._emit_impl(item)
        elif isinstance(item, A.FunDecl):
            self._emit_fun(item)
        else:
            raise TranspilerError(f"unsupported top-level item: {type(item).__name__}")

    def _emit_import(self, imp: A.Import) -> None:
        # Defense in depth: the analyzer rejects `import` in v1, so in
        # complete pipelines this function is never called with a valid
        # module. If we get here (e.g., direct transpilation without
        # going through the analyzer), we emit only a comment, *never*
        # a Python `import` - that would be the hole the analyzer is
        # closing.
        path = ".".join(imp.path)
        alias = f" as {imp.alias}" if imp.alias else ""
        self.em.write(
            f"# capa: 'import {path}{alias}' rejected, "
            f"use py_import(unsafe, ...) instead"
        )

    def _emit_const(self, c: A.ConstDecl) -> None:
        value_code = self._emit_expr(c.value)
        self.em.write(f"{c.name} = {value_code}")

    def _emit_struct(self, t: A.TypeStruct) -> None:
        from . import _safe_ident
        self.em.write("@dataclass")
        if t.fields:
            self.em.write(f"class {t.name}:")
            self.em.indent()
            for fld in t.fields:
                self.em.write(f"{_safe_ident(fld.name)}: object")
            self.em.dedent()
        else:
            self.em.write(f"class {t.name}:")
            self.em.indent()
            self.em.write("pass")
            self.em.dedent()

    def _emit_sum(self, t: A.TypeSum) -> None:
        # For each variant: a class.
        # - Without payload: empty class, instantiated as Variant().
        # - With payload: dataclass with `value` field.
        for v in t.variants:
            if v.payload is None:
                self.em.write(f"class {v.name}:")
                self.em.indent()
                self.em.write("pass")
                self.em.dedent()
            else:
                self.em.write("@dataclass")
                self.em.write(f"class {v.name}:")
                self.em.indent()
                self.em.write("value: object")
                self.em.dedent()
            self.em.blank()
        # Type alias for the sum type. Useful in type hints, optional at runtime.
        if t.variants:
            union = " | ".join(v.name for v in t.variants)
            self.em.write(f"{t.name} = {union}")

    def _emit_trait(self, t: A.TraitDecl) -> None:
        from . import _safe_ident
        # Generate a Protocol-like: simple class without implementation. The
        # impls that register this trait inherit from `_Trait_<Name>`. The
        # method is only declared (with `...`).
        self.em.write(f"class _Trait_{t.name}:")
        self.em.indent()
        if not t.methods:
            self.em.write("pass")
        else:
            for m in t.methods:
                params = ", ".join(_safe_ident(p.name) for p in m.params)
                self.em.write(f"def {_safe_ident(m.name)}({params}):")
                self.em.indent()
                self.em.write("raise NotImplementedError")
                self.em.dedent()
        self.em.dedent()
        # Alias for use in annotations (not used at runtime).
        self.em.write(f"{t.name} = _Trait_{t.name}")

    def _emit_impl(self, impl: A.ImplBlock) -> None:
        from . import _safe_ident, _uses_try
        # In Python, methods are added directly to the target class.
        # For trait impls, we could optionally inject the inheritance,
        # but that would involve modifying the existing declaration.
        # Instead, we just add the methods. The trait/impl relationship
        # is semantic in Capa and statically checked - at runtime, it
        # is enough that the methods exist.
        target = impl.type_name
        for m in impl.methods:
            params = ", ".join(_safe_ident(p.name) for p in m.params)
            if _uses_try(m.body):
                self.em.write("@_capa_wrap")
            self.em.write(f"def _{target}_{m.name}({params}):")
            self.em.indent()
            self._emit_block_body(m.body)
            self.em.dedent()
            self.em.write(f"{target}.{_safe_ident(m.name)} = _{target}_{m.name}")
            self.em.blank()

    def _emit_fun(self, fn: A.FunDecl) -> None:
        from . import _safe_ident, _uses_try
        params = ", ".join(_safe_ident(p.name) for p in fn.params)
        self._fun_stack.append(fn.name)
        # If the function uses `?`, it needs the decorator that catches
        # the internal exception used for propagation.
        if _uses_try(fn.body):
            self.em.write("@_capa_wrap")
        self.em.write(f"def {_safe_ident(fn.name)}({params}):")
        self.em.indent()
        self._emit_block_body(fn.body)
        self.em.dedent()
        self._fun_stack.pop()

    def _emit_main_bootstrap(self, main_decl: A.FunDecl) -> None:
        """Generates the ``if __name__ == "__main__":`` block that
        instantiates capabilities and calls ``main(...)``."""
        self.em.blank()
        self.em.write('if __name__ == "__main__":')
        self.em.indent()
        # Resolve each parameter to a capability instance.
        args = []
        for p in main_decl.params:
            cap_name = self._capability_for_param(p)
            args.append(f"{cap_name}()")
        if args:
            self.em.write(f"main({', '.join(args)})")
        else:
            self.em.write("main()")
        self.em.dedent()

    def _capability_for_param(self, p: A.Param) -> str:
        """Returns the name of the capability class that parameterizes
        ``p``, based on the type annotation."""
        te = p.type_expr
        if isinstance(te, A.TypeName):
            return te.name
        # Fallback - we assume Stdio just so something happens.
        return "Stdio"
