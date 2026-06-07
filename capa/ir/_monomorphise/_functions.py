"""Function cloning + body substitution: turn one generic
``N.Function`` into a monomorphic clone under a concrete
type-parameter substitution.
"""

from __future__ import annotations

from .. import _nodes as N
from ._typestr import (
    _substitute_locals,
    _substitute_node,
    _substitute_ty,
)


# ============================================================
# Function cloning + body substitution
# ============================================================


def _specialise_function(
    fn: N.Function, subst: dict[str, str], mangled_name: str,
) -> N.Function:
    """Clone ``fn`` with all ``type_params`` substituted to their
    concrete types. Returns a new Function with empty
    ``type_params`` (it is now monomorphic), the mangled name,
    substituted params / return type / locals / body. Pure: does
    not touch the input."""
    new_params = [
        N.Param(
            name=p.name,
            ty=_substitute_ty(p.ty, subst),
            is_capability=p.is_capability,
        )
        for p in fn.params
    ]
    new_return_type = _substitute_ty(fn.return_type, subst)
    new_locals = _substitute_locals(fn.locals, subst)
    new_body = [_substitute_node(instr, subst) for instr in fn.body]
    return N.Function(
        name=mangled_name,
        params=new_params,
        return_type=new_return_type,
        declared_caps=list(fn.declared_caps),
        body=new_body,
        locals=new_locals,
        type_params=[],
    )
