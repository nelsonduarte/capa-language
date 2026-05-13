"""capa.manifest, capability manifest builder.

Walks an analysed Capa module and emits a JSON-serialisable dict
describing, for every top-level function and impl-method:

- signature (params with types, return type)
- declared capabilities (the ones in the signature)
- whether the function crosses the ``Unsafe`` boundary
- attached attributes (``@security``, ``@deprecated``, ``@audited``)

Plus, at the module level: the user-defined capability declarations
and their implementors, and a summary count.

Designed as a CRA-aligned audit artefact. Other languages cannot
emit this because the authority graph is not in their type system;
in Capa, it falls out of the analyser for free.

The manifest format is versioned via ``SCHEMA_VERSION``. Consumers
should refuse to read manifests with a schema version they do not
recognise.

The package is split internally:

- :mod:`._strings` - AST -> short source-like text used for the
  ``args`` field on call records, plus ``_ty_text`` for types.
- :mod:`._flow` - intra-function tracking of ``restrict_to``-style
  attenuation chains (the ``args_flow`` field).
- :mod:`._calls` - call-site extraction (``_collect_calls``).
- :mod:`._funrec` - top-level ``build_manifest`` and per-function
  record assembly.
- :mod:`._cyclonedx` - CycloneDX 1.5 SBOM wrapper around the
  internal manifest (``build_cyclonedx``).
"""

from __future__ import annotations

from ._cyclonedx import CYCLONEDX_SPEC_VERSION, build_cyclonedx
from ._funrec import SCHEMA_VERSION, build_manifest
from ._strings import _ty_text


__all__ = [
    "SCHEMA_VERSION",
    "CYCLONEDX_SPEC_VERSION",
    "build_manifest",
    "build_cyclonedx",
]
