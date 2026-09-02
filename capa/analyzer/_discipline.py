"""Capability discipline mixin.

The Capa core: capabilities cannot be hidden in data structures,
returned by ordinary functions, bound to ``let``/``var``, or
aliased within a single call. These methods enforce those rules
and the use-after-``consume`` flow analysis that supports them.

The mixin assumes ``self`` has the analyzer state set up by
``Analyzer.__init__``: ``scope`` / ``global_scope`` / ``errors``,
``_consumed`` (set of capability names consumed so far in the
current flow), ``_lambda_local_names_stack`` (frames of local
names per nested lambda), plus the ``_err`` helper for reporting.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..tokens import Pos
from ..typesys import (
    CAPABILITY_NAMES, Ty, TyFun, TyName, TyTuple, compatible,
)


class _DisciplineMixin:
    def _mark_consumed_args(
        self, args: list[A.Expr], consuming_flags: list[bool],
    ) -> None:
        """For each capability-source arg whose ``consuming`` flag
        is True, mark the canonical dotted path as consumed.
        Called after evaluating the args so the use of those refs
        in the args themselves (the first occurrence) does not
        trigger the use-after-consume error.

        Two argument shapes resolve to a capability source:
        bare ``Ident`` and Ident-rooted ``FieldAccess`` chains
        (``box.cap``, ``outer.inner.cap``). Pre-2026-05-25 only
        ``Ident`` was tracked, so ``consume_one(box.cap)`` followed
        by ``box.cap.use()`` slipped past the analyzer (audit hole
        D). The canonical path comes from ``_path_of`` for the
        FieldAccess case; ``_consumed`` stores dotted paths so the
        same key is compared against ``_check_ident`` and the
        FieldAccess use-site check.

        Capture inside a lambda: if the consumed root name does
        not belong to the local parameters (or to enclosing
        lambdas that contain us), it is a captured cap, and
        consuming a captured cap is an error because the lambda
        may be invoked multiple times.
        """
        for arg, consuming in zip(args, consuming_flags):
            if not consuming:
                continue
            # Roadmap S1: a ``consume`` param discharges a linear obligation.
            # An OWNED linear identifier or a linear FIELD place
            # (``close(h)`` / ``close(s.conn)``) is moved out through the ONE
            # move seam shared with the aggregate-pack sites; a BORROWED value
            # consumed here is a transfer the callee may not make (the caller
            # still owns it) and routes into the shared transfer guard.
            if self._move_transfer_operand(arg, arg.pos):
                continue
            path = self._consumable_cap_path(arg)
            if path is None:
                continue
            root = path.split(".", 1)[0]
            if self._lambda_local_names_stack:
                is_local_to_some_lambda = any(
                    root in frame
                    for frame in self._lambda_local_names_stack
                )
                if not is_local_to_some_lambda:
                    self._err(
                        f"cannot consume capability {path!r} "
                        f"captured from enclosing scope; closures may "
                        f"be invoked multiple times, but a capability "
                        f"can only be consumed once",
                        arg.pos,
                    )
                    continue
            self._consumed.add(path)

    def _reject_linear_capture(
        self, root: str, pos: Pos, place: Optional[str] = None,
    ) -> bool:
        """True (and reports) iff ``root`` names a linear/typestate value
        CAPTURED from an enclosing scope while a lambda body is being
        checked: moving it out (consume / pack / field-move) is unsound
        because the closure may be invoked more than once, but a
        single-owner value can be moved only once. ``place`` is the dotted
        field path when the move is a field (``s.conn``), else ``None``.
        False when not inside a lambda, or ``root`` is local to some
        enclosing lambda frame."""
        if not self._lambda_local_names_stack:
            return False
        if any(root in frame for frame in self._lambda_local_names_stack):
            return False
        what = place if place is not None else root
        self._err(
            f"cannot consume linear value {what!r} captured from enclosing "
            f"scope; closures may be invoked multiple times, but a "
            f"`linear type` / typestate value can only be consumed once",
            pos,
        )
        return True

    def _move_linear_operand(
        self, expr: A.Expr, pos: Optional[Pos] = None,
    ) -> bool:
        """THE single seam that MOVES a bare OWNED linear/typestate value or
        an owned linear FIELD out at ``expr`` -- discharging the ident's
        obligation (it has been consumed / packed and is single-owner
        elsewhere) or poisoning the field path. Shared by the consume-arg
        path (``_mark_consumed_args``), the struct literal, and the
        typestate-``new`` literal, so a value packed into an aggregate is
        move-tracked exactly as one passed to a ``consume`` parameter.

        Returns True iff ``expr`` named a live OWNED linear operand (or a
        linear field place) and was handled -- so a caller can stop further
        processing -- and False for a non-linear / fresh / borrowed-bare-
        identifier expression (each caller applies its own borrowed reject
        with the right wording; a borrowed FIELD is rejected in place by
        ``_linear_move_field``). Moving a value CAPTURED into a lambda is
        rejected via ``_reject_linear_capture``.

        E3: a ``Call`` / ``MethodCall`` operand whose result LAUNDERS a
        linear/typestate argument (a generic identity / passthrough return)
        is routed through the ONE origin-resolution seam
        (``_call_result_alias_args``), and each aliased argument is moved
        back through THIS seam -- so ``close(id(c))`` / ``Box { f: id(c) }``
        move ``c`` exactly as ``close(c)`` would, and a chained ``id(id(c))``
        recurses. A fresh factory call moves nothing; a fail-closed reject is
        raised in place by the seam."""
        if isinstance(expr, (A.Call, A.MethodCall)):
            for origin_arg in self._call_result_alias_args(expr):
                # A laundering call hands its argument on exactly as a
                # ``return`` / ``consume`` argument does, so the argument is a
                # TRANSFER operand: route it through the one transfer seam,
                # which moves an owned operand and applies the shared
                # borrowed reject on the RESOLVED place. Deciding the
                # borrowed half here on ``isinstance(arg, Ident)`` and
                # ``arg.name`` instead would be a second copy of that rule,
                # and both alias spellings would slip past it -- so
                # ``return id(if c then b else b)`` on a borrowed ``b`` would
                # launder what ``return id(b)`` rejects.
                self._move_transfer_operand(origin_arg, origin_arg.pos)
            return True
        if self._reject_selection_operand(expr):
            return True
        if isinstance(expr, (A.IfExpr, A.MatchExpr)):
            out = self._selection_place.get(id(expr))
            if out is not None and out[0] == "place":
                # Every arm hands over the SAME place: the selection IS that
                # place, so move it exactly once through this seam.
                return self._move_linear_place(out[1], out[2], pos or expr.pos)
            # Fresh (or a non-obligation selection): nothing existing moves.
            return False
        place = self._path_of(expr)
        if place is None:
            return False
        return self._move_linear_place(
            place, self._operand_leaf_ty(expr), pos or expr.pos,
        )

    def _operand_leaf_ty(self, expr: A.Expr):
        """The type of the value a place-denoting operand yields. Taken from
        the recorded expression type, falling back to the binding's declared
        type for a bare identifier the walk has not typed."""
        ty = self.types.get(id(expr))
        if ty is None and isinstance(expr, A.Ident):
            sym = self.scope.lookup(expr.name)
            ty = sym.ty if sym is not None else None
        return ty

    def _move_linear_place(self, place: str, ty, pos) -> bool:
        """Move the obligation held at the canonical ``place`` out. THE one
        body behind every operand shape: a whole-value place discharges its
        name; a FIELD place moves its linear leaf subtree out through the one
        field-projection mover. Splitting on the PLACE -- not on the operand's
        syntax -- is what lets a match-arm binder that VIEWS a carrier field
        (``match b { Box { c: inner } -> close(inner) }``) move exactly the
        field it names, with no per-shape branch."""
        if "." not in place:
            if place not in self._live_linear:
                # A spent HUSK (all linear fields moved out, popped from the
                # live set) cannot be whole-consumed / re-packed again -- that
                # re-transfers an already-moved field (double-free).
                return self._reject_husk_reconsume(place, pos)
            if self._reject_linear_capture(place, pos):
                return True
            self._linear_discharge(place, pos)
            return True
        # A field projection is moved out through the ONE field-projection
        # mover, driven by the leaf-set enumerator: a bare leaf moves its
        # one place, a CARRIER field moves its whole subtree. This single
        # widening sweeps in every caller of this seam (consume-arg, the
        # struct-literal + typestate-``new`` packs, and the field-store RHS).
        if not self._linear_leaves_of(place, ty):
            return False
        root = place.split(".", 1)[0]
        if self._reject_linear_capture(root, pos, place=place):
            return True
        self._move_leaves_of(place, ty, pos)
        return True

    # ---- fail-closed reject of an unresolvable selection ----------------

    def _reject_selection_operand(self, expr: A.Expr) -> bool:
        """True (and reports once) iff ``expr`` is, or projects off, an
        ``if`` / ``match`` selection the classifier could not resolve to a
        single place or to a fresh value. This is the ONE site the fail-closed
        verdict is reported at, because a move position is the only place
        where silently losing the obligation is unsound: a mere READ of an
        unresolvable selection stays legal."""
        root = (
            expr if isinstance(expr, (A.IfExpr, A.MatchExpr))
            else self._selection_root_of(expr)
        )
        if root is None:
            return False
        out = self._selection_place.get(id(root))
        if out is None or out[0] != "reject":
            return False
        if id(root) in self._linear_conditional_reported:
            return True
        self._linear_conditional_reported.add(id(root))
        self._err(
            "a linear/typestate value cannot be selected through a "
            "conditional / match expression; bind it directly (e.g. "
            "`let x = ...` in each branch) or open a fresh value per branch, "
            "so each resource has a single owner",
            root.pos,
        )
        return True

    # ---- the ONE selection classifier ----------------------------------

    def _classify_selection_value(self, e) -> tuple:
        """Classify ONE arm value of a linear/typestate selection, WHILE its
        scope is live, as ``("place", expr)`` / ``("fresh",)`` /
        ``("reject",)``.

        A place is anything ``_path_of`` resolves -- an identifier, a field
        projection, a pattern-binding VIEW, or a nested selection already
        classified -- so the arm binder and the nested wrapper need no second
        mechanism here. FRESHNESS of a call is decided by the ONE acceptance
        rule sibling A already applies to a call at a move position (provably
        fresh, or un-summarisable with no live-obligation argument), so a call
        does not change verdict merely by being wrapped in a conditional.
        Everything else fails CLOSED."""
        if isinstance(e, (A.IntLit, A.StringLit, A.BoolLit, A.FloatLit,
                          A.CharLit, A.UnitLit, A.StructLit, A.Become)):
            return ("fresh",)
        if isinstance(e, (A.Call, A.MethodCall)):
            if self._provably_fresh(e):
                return ("fresh",)
            _key, unresolved = self._e3_callee_key(e)
            if unresolved and not self._e3_backstop_fires(e):
                return ("fresh",)
            return ("reject",)
        if isinstance(e, (A.IfExpr, A.MatchExpr)):
            return self._selection_place.get(id(e), ("reject",))
        place = self._path_of(e)
        if place is None:
            return ("reject",)
        # The RESOLVED PLACE and its type, not the arm's node: the arm may
        # spell a pattern-binding VIEW (``v.c``) that only resolves while the
        # arm's aliases are live, and the move position that consumes the
        # selection runs after the arm scope has been popped. Carrying the
        # answer, rather than something that must be re-resolved later, is
        # what makes the fact stable.
        return ("place", place, self._operand_leaf_ty(e))

    @staticmethod
    def _combine_selection(parts: list) -> tuple:
        """Combine the arm classifications of ONE selection into its outcome.

        Fail-closed by construction, and deliberately ONE function: collapsing
        same-place arms and deciding the verdict were split in an earlier
        build, and the halves disagreed -- ``if flag then a else b`` resolved
        to the FIRST place and shipped a real double-free. Deduplication and
        the verdict now share a body, so the rule cannot be half-applied.

        - no arms at all, or any arm the classifier could not resolve: REJECT;
        - arms naming MORE THAN ONE distinct place: REJECT, because which
          obligation moves would depend on the runtime branch;
        - a MIX of an existing place and a fresh value: REJECT, because one
          branch would move an obligation and the other would not;
        - every arm fresh: FRESH, nothing existing moves;
        - every arm naming the SAME place: that place, moved exactly once."""
        if not parts:
            return ("reject",)
        if any(p[0] == "reject" for p in parts):
            return ("reject",)
        places: dict = {}
        for p in parts:
            if p[0] == "place":
                places.setdefault(p[1], p)
        if not places:
            return ("fresh",)
        if len(places) > 1:
            return ("reject",)
        if any(p[0] != "place" for p in parts):
            return ("reject",)
        return next(iter(places.values()))

    def _record_selection(self, node, ty, parts: list) -> None:
        """Record the selection outcome for ``node``. Gated on the ONE
        obligation predicate, so a selection over a String / Int / plain
        struct records nothing and costs nothing."""
        if not self._owned_obligation(ty):
            return
        self._selection_place[id(node)] = self._combine_selection(parts)

    def _substitute_self(self, ty: Ty, self_ty: Ty) -> Ty:
        """Substitute ``TyName('Self')`` in ``ty`` with ``self_ty``.
        Used to resolve trait method signatures in the context of
        a concrete impl."""
        if isinstance(ty, TyName):
            if ty.name == "Self":
                return self_ty
            if ty.args:
                new_args = tuple(self._substitute_self(a, self_ty) for a in ty.args)
                return TyName(ty.name, new_args)
            return ty
        if isinstance(ty, TyTuple):
            return TyTuple(tuple(
                self._substitute_self(e, self_ty) for e in ty.elements
            ))
        if isinstance(ty, TyFun):
            return TyFun(
                tuple(self._substitute_self(p, self_ty) for p in ty.params),
                self._substitute_self(ty.ret, self_ty),
            )
        return ty

    def _is_capability_ident(self, expr: A.Expr) -> Optional[str]:
        """Canonical path string for capability-source expressions.

        Two shapes resolve to a capability source:

        - bare ``Ident`` bound to a capability in scope;
        - Ident-rooted ``FieldAccess`` chain whose final type is
          a capability (``box.cap``, ``outer.inner.cap``).

        Returns the dotted path so the aliasing check can compare
        equal references; returns ``None`` for anything else.

        Pre-2026-05-24 only matched ``CAPABILITY_NAMES`` (built-in
        set), letting user-defined caps escape the non-aliasing
        rule. The 2026-05-25 audit found a deeper hole: bare-Ident
        matching missed ``f(box.cap, box.cap)`` because both args
        are ``FieldAccess`` nodes, so the dict-keyed aliasing
        check saw two distinct entries.
        """
        if isinstance(expr, A.Ident):
            sym = self.scope.lookup(expr.name)
            if sym is None or sym.ty is None:
                return None
            if self._ty_is_capability(sym.ty):
                return expr.name
            return None
        if isinstance(expr, A.FieldAccess):
            path = self._path_of(expr)
            if path is None:
                return None
            ty = self.types.get(id(expr))
            if ty is None or not self._ty_is_capability(ty):
                return None
            return path
        return None

    def _consumable_cap_path(self, expr: A.Expr) -> Optional[str]:
        """Canonical dotted path for a ``consume``-position argument
        that names a capability SOURCE: a bare capability, OR a
        cap-bearing struct (a value whose type reaches a capability via
        :meth:`_contains_any_capability`).

        This widens :meth:`_is_capability_ident` -- which recognises
        only a bare / field-accessed built-in or user capability -- so a
        struct that carries a cap (``m: SmtpMailer``) is also a
        consumable source. That closes audit hole B-F2: ``dispose(m)``
        followed by ``m.send(..)`` on a struct cap is now use-after-
        consume, exactly as a directly-typed cap already was.

        Used ONLY on the consume path (:meth:`_mark_consumed_args`); the
        aliasing and structural checks keep the narrower
        ``_ty_is_capability`` predicate, because a cap-bearing struct
        stays droppable and is not linear-by-containment. Two shapes
        resolve: a bare ``Ident`` and an Ident-rooted ``FieldAccess``
        chain, keyed by :meth:`_path_of` so the recorded key matches the
        later use-site check."""
        if isinstance(expr, A.Ident):
            sym = self.scope.lookup(expr.name)
            if sym is None or sym.ty is None:
                return None
            if self._contains_any_capability(sym.ty) is not None:
                return expr.name
            return None
        if isinstance(expr, A.FieldAccess):
            path = self._path_of(expr)
            if path is None:
                return None
            ty = self.types.get(id(expr))
            if ty is None or self._contains_any_capability(ty) is None:
                return None
            return path
        return None

    def _path_of(self, expr: A.Expr) -> Optional[str]:
        """Canonical dotted-path string for a place-denoting expression
        (``a``, ``a.b``, ``a.b.c``). Returns ``None`` for any shape that does
        not denote an existing place, so the aliasing check stays conservative
        on non-static paths (calls, indices, ...).

        THE one place the two binding-time facts are resolved, so every
        place-keyed operation inherits them instead of re-deriving them:

        - an identifier bound by a PATTERN as a VIEW of an existing place (a
          ``match`` arm binder) resolves to that place (``_linear_alias``), so
          consuming / projecting / re-reading the binder is the same operation
          on the scrutinee it names;
        - an ``if`` / ``match`` EXPRESSION whose arms all hand over the SAME
          place resolves to that place (``_selection_place``), so a projection
          off a selection (``(if c then o else o).inner``) is an ordinary
          field path and every FieldAccess site closes at once.

        A selection classified fresh or fail-closed has NO place and yields
        ``None``; the fail-closed REJECT is reported at the move seam, which
        is the only site where losing the value is unsound."""
        if isinstance(expr, A.Ident):
            return self._linear_alias_root(expr.name)
        if isinstance(expr, A.FieldAccess):
            base = self._path_of(expr.receiver)
            if base is None:
                return None
            return f"{base}.{expr.field_name}"
        if isinstance(expr, (A.IfExpr, A.MatchExpr)):
            out = self._selection_place.get(id(expr))
            if out is not None and out[0] == "place":
                return out[1]
            return None
        return None

    def _linear_alias_root(self, name: str) -> str:
        """Resolve a pattern-binding VIEW name to the canonical place it
        denotes, following a chain of views (an arm binder of an arm binder)
        to a fixed point. Cycle-guarded, and the identity for every name that
        is not a view -- which is every name in a program with no pattern
        binding over an owned obligation, so this is invisible until the
        binding seam records something."""
        seen: set = set()
        while name in self._linear_alias and name not in seen:
            seen.add(name)
            name = self._linear_alias[name]
        return name

    def _selection_root_of(self, expr: A.Expr):
        """The ``if`` / ``match`` node at the root of a (possibly empty) chain
        of field projections, or ``None``. ``(if c then o else o).inner.fd``
        roots at the ``if``; ``o.inner`` roots at nothing."""
        while isinstance(expr, A.FieldAccess):
            expr = expr.receiver
        return expr if isinstance(expr, (A.IfExpr, A.MatchExpr)) else None

    def _ty_is_capability(self, ty: Ty) -> bool:
        """True iff ``ty`` is a built-in or user-declared
        capability name. Cap-bearing structs are not treated as
        capabilities themselves at this layer; their fields are
        what the aliasing check walks into."""
        if not isinstance(ty, TyName):
            return False
        if ty.name in CAPABILITY_NAMES:
            return True
        sym = self.global_scope.lookup(ty.name)
        if sym is None:
            return False
        from . import SymbolKind
        return sym.kind == SymbolKind.CAPABILITY

    def _check_no_aliasing(self, slots: list[tuple[A.Expr, str]]) -> None:
        """Check that no capability appears twice in ``slots``.

        ``slots`` is a list of ``(expr, role)`` pairs where role
        is a description (``"receiver"``, ``"argument 2"``) for
        the error message. Each slot represents a position in a
        call where a capability could be passed. Aliasing a cap
        within a single call violates the single-flow property
        that gives Capa signatures their meaning.
        """
        seen: dict[str, str] = {}  # name -> first role where it appeared
        for expr, role in slots:
            name = self._is_capability_ident(expr)
            if name is None:
                continue
            if name in seen:
                self._err(
                    f"capability {name!r} appears as {role} but was already "
                    f"used as {seen[name]} of the same call; capabilities "
                    f"cannot be aliased (each call uses each capability at "
                    f"most once)",
                    expr.pos,
                )
            else:
                seen[name] = role

    def _check_no_capability(self, ty: Ty, pos: Pos, context: str) -> None:
        """Enforce the structural capability discipline: caps
        cannot be hidden in data structures, returned by ordinary
        functions, or bound to local / constant slots.
        Recognises both built-in capabilities and user-defined
        ones (declared with the ``capability`` keyword)."""
        cap = self._contains_any_capability(ty)
        if cap is None:
            return
        self._err(
            f"capability {cap.name!r} cannot appear in {context}; "
            f"capabilities only flow through function parameters",
            pos,
        )

    def _reject_cap_leak_via_substitution(
        self,
        pre_ty: Ty,
        post_ty: Ty,
        callee_label: str,
        pos: Pos,
        *,
        slot: str,
    ) -> None:
        """Fire when generic-parameter substitution puts a
        capability where the unsubstituted form had none.

        Hole C from the 2026-05-25 audit: a generic function whose
        signature uses a type variable ``T`` doesn't declare any
        capability, but the call site that substitutes ``T = Stdio``
        smuggles the capability through. The structural check
        ``_check_no_capability`` only runs against the function's
        own declaration body (where ``T`` is opaque), so without
        this post-instantiation re-check the leak goes silent.

        ``pre_ty`` is the parameter or return type as declared;
        ``post_ty`` is the substituted version. If a capability
        appears in ``post_ty`` and *not* in ``pre_ty``, it came
        from a TyVar substitution and the call is rejected.
        """
        post_cap = self._contains_any_capability(post_ty)
        if post_cap is None:
            return
        pre_cap = self._contains_any_capability(pre_ty)
        if pre_cap is not None:
            # The declared signature already names a capability at
            # this slot; substitution preserving it is the legitimate
            # flow (``fun use(s: Stdio)`` called with ``stdio``).
            return
        self._err(
            f"call to {callee_label}: {slot} substitutes capability "
            f"{post_cap.name!r} into a generic type parameter; the "
            f"function's signature does not declare it as a capability "
            f"flow (capabilities must appear by name in the signature)",
            pos,
        )

    def _contains_any_capability(self, ty: Ty) -> Optional[TyName]:
        """Recursive walk that returns the first capability found
        in ``ty``. Three kinds count:

        - built-in caps (``Stdio``, ``Net``, ...), in
          ``CAPABILITY_NAMES``;
        - user-defined caps (Symbol with ``kind=CAPABILITY``);
        - cap-bearing structs (a ``TYPE_STRUCT`` Symbol whose
          ``implements`` set contains at least one user-defined
          capability).
        """
        if isinstance(ty, TyName):
            if ty.name in CAPABILITY_NAMES:
                return ty
            sym = self.global_scope.lookup(ty.name)
            if sym is not None:
                from . import SymbolKind   # late to avoid cycles
                if sym.kind == SymbolKind.CAPABILITY:
                    return ty
                if (
                    sym.kind == SymbolKind.TYPE_STRUCT
                    and any(self._is_user_capability(t) for t in sym.implements)
                ):
                    return ty
            for a in ty.args:
                found = self._contains_any_capability(a)
                if found is not None:
                    return found
        if isinstance(ty, TyTuple):
            for elem in ty.elements:
                found = self._contains_any_capability(elem)
                if found is not None:
                    return found
        return None

    def _cap_in_container(self, ty: Ty) -> Optional[TyName]:
        """First capability that appears BY NAME below a container in
        ``ty``.

        A capability may flow only as a bare, top-level value (a
        direct function parameter). This predicate returns the first
        capability whose type NAME is reachable STRICTLY BELOW the
        top-level type head -- a list / set / map element, a tuple
        member, or any generic argument, at any nesting depth -- which
        is exactly a capability packed into a container by name.

        A BARE capability (``Stdio``) or a cap-bearing struct value
        (``SmtpMailer``) at the TOP level is deliberately NOT flagged:
        those are the legitimate flows (a top-level parameter, a
        factory result, a cap-bearing struct passed as a value). Only
        the nested form is a violation.

        Scope of the check. This is a TYPE-NAME reachability test, so
        it finds authority only where a capability appears BY NAME in
        the value's type. Like :func:`capa.typesys.contains_capability`
        it does NOT descend a ``TyFun``: a capability appearing as the
        parameter of a stored closure is a signature, not storage, so
        ``List<Fun(Stdio) -> Int>`` is not a capability container.
        Consequently authority CAPTURED inside a closure is NOT covered
        here: a thunk that closes over a live capability has a
        signature such as ``Fun() -> Unit`` that does not name the
        capability, so a ``List<Fun() -> Unit>`` of capturing thunks
        carries the authority without this detector seeing it. That is
        a separate, known capability-accounting limitation, not a
        soundness hole this detector is meant to close: the
        ``--check-capabilities`` ceiling still fails closed on any
        ``Fun`` in a signature, so the captured authority cannot be
        under-reported past that gate.

        The nested walk reuses :meth:`_contains_any_capability`, so
        built-in caps, user-defined caps, and cap-bearing structs all
        count once they sit below a container layer. The type is
        resolved against ``_ty_subs`` first, so a container whose
        element was only pinned by inference is judged on its real
        element type.
        """
        ty = self._resolve_ty(ty)
        if isinstance(ty, TyName):
            for a in ty.args:
                found = self._contains_any_capability(a)
                if found is not None:
                    return found
            return None
        if isinstance(ty, TyTuple):
            for elem in ty.elements:
                found = self._contains_any_capability(elem)
                if found is not None:
                    return found
        return None

    def _check_no_cap_container(self, ty: Ty, pos: Pos, context: str) -> None:
        """Reject a type that packs a capability inside a container in
        ``context`` (see :meth:`_cap_in_container`). Used at the entry
        gates -- a function parameter / return whose type nests a
        capability inside a list / set / map / tuple -- for an early,
        precise diagnostic."""
        cap = self._cap_in_container(ty)
        if cap is None:
            return
        self._err(
            f"capability {cap.name!r} cannot appear in {context}; a "
            f"capability may only flow as a bare, top-level value (a "
            f"direct function parameter), never packed inside a list, "
            f"set, map, or tuple",
            pos,
        )

    def _is_user_capability(self, name: str) -> bool:
        """True iff ``name`` resolves to a user-defined
        capability (a Symbol whose kind is CAPABILITY but whose
        name is not in the built-in set). User-defined caps are
        subject to most of the same rules as built-ins, with two
        relaxations: they can be the return type of a regular
        function (factories produce fresh instances), and they
        can wrap built-in capabilities as struct fields when the
        struct implements a user-defined cap."""
        if name in CAPABILITY_NAMES:
            return False
        from . import SymbolKind
        sym = self.global_scope.lookup(name)
        return sym is not None and sym.kind == SymbolKind.CAPABILITY

    def _contains_builtin_capability(self, ty: Ty) -> Optional[TyName]:
        """Like ``_contains_any_capability`` but flags only
        **built-in** capabilities (Stdio, Fs, Net, Env, ...).
        Used by call sites that legitimately let user-defined
        caps flow through."""
        if isinstance(ty, TyName):
            if ty.name in CAPABILITY_NAMES:
                return ty
            for a in ty.args:
                found = self._contains_builtin_capability(a)
                if found is not None:
                    return found
        if isinstance(ty, TyTuple):
            for elem in ty.elements:
                found = self._contains_builtin_capability(elem)
                if found is not None:
                    return found
        return None

    def _contains_unsafe(self, ty: Ty) -> Optional[TyName]:
        """Recursive walk returning the first ``Unsafe`` mention in
        ``ty`` (head TyName, tuple element, or generic argument).
        ``Unsafe`` is the FFI escape hatch, never an attenuable
        built-in cap, so it is rejected even where the cap-bearing
        relaxation lets the attenuable caps (Fs/Net/Db/Proc/Env/
        Clock/Random) be encapsulated in a struct field (audit
        2026-06-17 C5)."""
        if isinstance(ty, TyName):
            if ty.name == "Unsafe":
                return ty
            for a in ty.args:
                found = self._contains_unsafe(a)
                if found is not None:
                    return found
        if isinstance(ty, TyTuple):
            for elem in ty.elements:
                found = self._contains_unsafe(elem)
                if found is not None:
                    return found
        return None

    def _check_no_unsafe_field(self, ty: Ty, pos: Pos, context: str) -> None:
        """Reject an ``Unsafe`` anywhere in ``ty``. Used for fields of
        a cap-bearing struct, which otherwise skip
        :meth:`_check_no_capability` so they can encapsulate
        attenuable built-in caps; ``Unsafe`` must not slip through
        that relaxation (audit 2026-06-17 C5)."""
        cap = self._contains_unsafe(ty)
        if cap is None:
            return
        self._err(
            f"capability 'Unsafe' cannot appear in {context}, even "
            f"in a capability-bearing struct; Unsafe is the FFI escape "
            f"hatch, not an attenuable built-in capability",
            pos,
        )

    def _check_no_builtin_capability(
        self, ty: Ty, pos: Pos, context: str,
    ) -> None:
        """Variant of :meth:`_check_no_capability` that only
        rejects **built-in** capabilities. Used at sites that
        legitimately accept user-defined ones (the return type
        of a factory function, for instance)."""
        cap = self._contains_builtin_capability(ty)
        if cap is None:
            return
        self._err(
            f"capability {cap.name!r} cannot appear in {context}; "
            f"built-in capabilities only flow through function parameters",
            pos,
        )

    def _compatible_with_impls(self, expected: Ty, actual: Ty) -> bool:
        """Like :func:`capa.typesys.compatible` plus nominal
        subtyping via trait / capability implementations.

        When the expected type is a trait or user-defined
        capability, and the actual type is a struct / sum whose
        Symbol records an ``impl`` of that trait / capability,
        the two are compatible (the concrete type is a valid
        implementor).
        """
        if compatible(expected, actual):
            return True
        if isinstance(expected, TyName) and isinstance(actual, TyName):
            from . import SymbolKind
            exp_sym = self.global_scope.lookup(expected.name)
            act_sym = self.global_scope.lookup(actual.name)
            if (
                exp_sym is not None and act_sym is not None
                and exp_sym.kind in (SymbolKind.TRAIT, SymbolKind.CAPABILITY)
                and expected.name in act_sym.implements
            ):
                return True
        return False

    def _assignable(self, expected: Ty, actual: Ty, expr: A.Expr) -> bool:
        """Assignment-direction compatibility for a value flowing into a
        declared slot (a ``let``/``var``/assignment target, a struct or
        typestate field, a function or method argument).

        It is :meth:`_compatible_with_impls` plus the one narrow
        ``String``-into-``Char`` relaxation that needs the expression to
        be sound: a Capa ``Char`` is exactly one code point, so a general
        ``String`` is rejected where a ``Char`` is expected, but a
        provably one-code-point string *literal* (a ``StringLit`` of
        length one) is accepted -- so ``let c: Char = "a"`` stays OK while
        ``let c: Char = "abc"`` and ``let c: Char = someStringVar`` are
        rejected. The other direction (a ``Char`` where a ``String`` is
        expected) is handled unconditionally by ``compatible`` itself,
        since a one-code-point ``Char`` is always a valid ``String``.

        A value flowing into a declared slot is also the moment a
        container CREATED EMPTY and UNANNOTATED has its element type
        fixed. Both types are resolved against ``_ty_subs`` first, so a
        variable pinned by an EARLIER handoff (or populate) is now judged
        on its real element type -- this is what surfaces the launder at a
        later, incompatible read. Once the value is found assignable, the
        still-open element variables it carries are pinned to the
        destination's concrete element type (:meth:`_pin_flexible`), so
        every subsequent use of the original binding is checked against it.
        """
        expected = self._resolve_ty(expected)
        actual = self._resolve_ty(actual)
        if self._compatible_with_impls(expected, actual):
            self._pin_flexible(expected, actual)
            return True
        if (
            isinstance(expected, TyName)
            and expected.name == "Char" and not expected.args
            and isinstance(actual, TyName)
            and actual.name == "String" and not actual.args
            and expected.state == actual.state
            and isinstance(expr, A.StringLit)
            and len(expr.value) == 1
        ):
            return True
        return False
