"""Information-flow label propagation (roadmap S2.3).

Runs alongside type checking: every expression, after it is typed in
``_check_expr``, is also given a security label stored in
``self._expr_labels[id(e)]``. The label is the join (lattice ⊔) of the
labels of the sub-expressions that flow into it -- so a derived value
is ``secret`` iff some operand it depends on is ``secret``. Variable
references take their label from the binding's ``Symbol.label`` (set
from a ``@secret`` / ``@public`` annotation when the binding was
declared).

Label propagation (S2.3) computes the labels; sink enforcement
(S2.4, ``_check_ifc_sink``) reports when a ``secret`` value reaches a
public-exfiltration sink (Stdio.println, Net.post, Fs.write, ...).
Warn-then-enforce: a non-fatal warning by default, a hard error under
``@strict_ifc``. The source-cap labelling (``env.get`` -> secret),
``declassify`` + SBOM, and implicit (control-flow) leaks land in
later S2 slices.

Children are always visited before their parent (``_check_expr``
recurses into operands first), so when ``_label_of_expr`` runs for a
parent the children's labels are already in ``self._expr_labels``.
"""

from __future__ import annotations

from .. import capa_ast as A
from .. import _labels as L


# Built-in capability methods that exfiltrate data out of the program
# -- the public sinks. A ``@secret`` value reaching any of these
# argument positions is an information-flow violation unless it was
# declassified. Keyed by ``(CapName, method)`` -> the set of 0-based
# argument indices that are sinks. Roadmap S2.4.
#
# Receiver-only / pure-query methods (allows, exists, read, get from
# Env, now_secs, ...) are NOT sinks: they bring data IN or inspect,
# they don't send it out. ``restrict_to*`` take a config string, not
# user data. The path argument of fs.write is included (a secret
# written to an attacker-chosen path is still disclosure), as is the
# URL of net.get/post (a secret in a URL leaks via the request line /
# server logs).
_PUBLIC_SINKS: dict[tuple[str, str], set[int]] = {
    ("Stdio", "print"):    {0},
    ("Stdio", "println"):  {0},
    ("Stdio", "eprintln"): {0},
    ("Net", "get"):        {0},
    ("Net", "post"):       {0, 1},
    ("Fs", "write"):       {0, 1},
    ("Db", "exec"):        {0, 1},
    ("Db", "query"):       {0, 1},
}


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

    # ---- sink enforcement (roadmap S2.4) -------------------------

    def _check_ifc_sink(self, e: A.MethodCall, recv_ty) -> None:
        """If ``e`` calls a public-sink capability method with a
        ``@secret`` argument in a sink position, report a flow
        violation. Warn-then-enforce: a warning by default (so
        existing unlabelled code is unaffected and labelled code
        surfaces the disclosure), a hard error when the enclosing
        function opted into ``@strict_ifc``.

        The arguments were just typed by ``_check_method_call``, so
        their labels are already in ``self._expr_labels``."""
        if not isinstance(recv_ty, A.TypeName) and not _is_ty_name(recv_ty):
            return
        cap_name = getattr(recv_ty, "name", None)
        if cap_name is None:
            return
        sink_args = _PUBLIC_SINKS.get((cap_name, e.method))
        if not sink_args:
            return
        for idx in sorted(sink_args):
            if idx >= len(e.args):
                continue
            arg = e.args[idx]
            if L.normalize(self._label_of(arg)) != L.SECRET:
                continue
            msg = (
                f"information-flow: a @secret value reaches "
                f"{cap_name}.{e.method} (argument {idx + 1}), a public "
                f"sink that sends data out of the program. Route it "
                f"through declassify(value, reason: \"...\") if this "
                f"disclosure is intended."
            )
            if getattr(self, "_strict_ifc", False):
                self._err(msg, arg.pos)
            else:
                self._warn_ifc(msg, arg.pos)

    def _warn_ifc(self, message: str, pos) -> None:
        """Record a non-fatal IFC warning (does not affect ``ok``).
        Mirrors ``_err`` but routes to ``self.warnings``."""
        from . import AnalysisError
        src = self.source
        fname = self.filename
        if pos.filename and pos.filename in self.sources:
            src = self.sources[pos.filename]
            fname = pos.filename
        self.warnings.append(AnalysisError(message, pos, src, fname))


def _is_ty_name(ty) -> bool:
    """True if ``ty`` is a TyName (the analyzer's resolved type), not
    the AST TypeName. Kept tolerant so the sink check works whether
    the receiver type is the resolved TyName or anything carrying a
    ``.name``."""
    return type(ty).__name__ == "TyName"
