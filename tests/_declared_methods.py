"""Single source of "the method names declared on an owner" for the guards
over ``capa.builtins.METHODS``.

``METHODS`` maps an owner to a list of ``(name, type, type_params)``
entries. The guards that check the declared surface against its
implementations (tests/test_builtin_pairs.py,
tests/test_ifc_tables_declared.py, tests/test_method_emit_agreement.py,
tests/test_stdlib_characterization.py) need only the names, and each
once unpacked the entry shape for itself, three of them in a helper of
the same name: a change to the entry shape would have had to be made
four times, and a copy taught differently would have guarded a
different surface. This module is the one place a NAME reader unpacks
the entry. A reader that also needs the type (the arity table in
tests/test_method_emit_agreement.py) still reads the entry itself; this
module does not cover it.

Not a test module: its name does not match the test*.py discovery
pattern, so unittest discovery and pytest never collect it.
"""

from __future__ import annotations

from capa.builtins import METHODS


def declared_methods(owner: str) -> tuple[str, ...]:
    """The method names ``METHODS`` declares on ``owner``, in declaration
    order; empty for an owner it does not know."""
    return tuple(name for (name, _ty, _type_params) in METHODS.get(owner, []))
