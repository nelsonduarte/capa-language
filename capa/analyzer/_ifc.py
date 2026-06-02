"""Information-flow label propagation (roadmap S2.3).

Runs alongside type checking: every expression, after it is typed in
``_check_expr``, is also given a security label stored in
``self._expr_labels[id(e)]``. The label is the join (lattice ⊔) of the
labels of the sub-expressions that flow into it -- so a derived value
is ``secret`` iff some operand it depends on is ``secret``. Variable
references take their label from the binding's ``Symbol.label`` (set
from a ``@secret`` / ``@public`` annotation when the binding was
declared).

This slice only PROPAGATES labels. Enforcement (a ``secret`` value
reaching a ``public`` sink) and the source-cap labelling
(``env.get`` -> secret) land in later S2 slices; until then the
labels are computed but no flow is rejected, so behaviour is
unchanged.

Children are always visited before their parent (``_check_expr``
recurses into operands first), so when ``_label_of_expr`` runs for a
parent the children's labels are already in ``self._expr_labels``.
"""

from __future__ import annotations

from .. import capa_ast as A
from .. import _labels as L


class _IfcMixin:
    def _label_expr(self, e: A.Expr) -> str:
        """Compute and record the security label of ``e`` from its
        already-labelled children, returning it. Called by
        ``_check_expr`` right after typing, so child labels are
        present. The result is stored in ``self._expr_labels``."""
        label = self._compute_label(e)
        self._expr_labels[id(e)] = label
        return label

    def _label_of(self, e: A.Expr) -> str:
        """The recorded label of an already-visited expression, or
        PUBLIC if it has none (e.g. a node the walk doesn't label)."""
        return self._expr_labels.get(id(e), L.PUBLIC)

    def _join_decl_and_value_label(self, decl_label, value: A.Expr) -> str:
        """The label a binding receives: the join of an explicit
        ``@secret``/``@public`` annotation (``decl_label``, may be
        ``None``) and the label already computed for its RHS value.
        So ``let x: @secret Int = 1`` is secret by annotation, and
        ``let y = secret_x`` is secret by flow -- both surface here."""
        return L.join(decl_label, self._label_of(value))

    def _label_binding(self, name: str, decl_label, value: A.Expr) -> None:
        """Set the IFC label on the in-scope ``Symbol`` for ``name``
        to the join of its annotation and its RHS value's label.
        Used by ``_check_let`` after the pattern is bound."""
        sym = self.scope.lookup_local(name)
        if sym is not None:
            sym.label = self._join_decl_and_value_label(decl_label, value)

    def _compute_label(self, e: A.Expr) -> str:
        # Literals are public.
        if isinstance(e, (
            A.IntLit, A.FloatLit, A.StringLit, A.CharLit,
            A.BoolLit, A.UnitLit,
        )):
            return L.PUBLIC

        # A name carries its binding's label.
        if isinstance(e, A.Ident):
            sym = self.bindings.get(id(e))
            if sym is not None and getattr(sym, "label", None):
                return L.normalize(sym.label)
            return L.PUBLIC

        # Derived values join the labels of every operand that flows
        # into them. Interpolation is a flow: ``"${secret}"`` is
        # secret, the classic logging-leak shape.
        if isinstance(e, A.InterpolatedString):
            return L.join_all(
                self._label_of(p) for p in e.parts
                if not isinstance(p, str)
            )
        if isinstance(e, A.BinOp):
            return L.join(self._label_of(e.left), self._label_of(e.right))
        if isinstance(e, A.UnaryOp):
            return self._label_of(e.operand)
        if isinstance(e, A.Try):
            # ``x?`` unwraps; the payload keeps the taint of x.
            return self._label_of(e.expr)
        if isinstance(e, A.Index):
            # An element drawn from a tainted container is tainted.
            return L.join(self._label_of(e.receiver), self._label_of(e.index))
        if isinstance(e, A.FieldAccess):
            # Conservative: a field read inherits the receiver's label.
            # (Per-field labels are a v2 refinement.)
            return self._label_of(e.receiver)

        # Calls / method-calls get their label from the callee's
        # declared return label + the join of argument labels, handled
        # where the call is type-checked (so the source-cap labelling
        # and declassify can hook in). Until those slices land, a call
        # result is the join of its argument labels (a pure function of
        # tainted inputs is tainted) -- a safe default.
        if isinstance(e, A.Call):
            return L.join_all(self._label_of(a) for a in e.args)
        if isinstance(e, A.MethodCall):
            return L.join(
                self._label_of(e.receiver),
                L.join_all(self._label_of(a) for a in e.args),
            )

        # Anything else (lambda, struct lit, list/map/set lit, match
        # expr, ...) is public by default in this slice; richer
        # propagation through those forms is a follow-up.
        return L.PUBLIC
