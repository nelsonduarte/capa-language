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
- :mod:`._spdx` - SPDX 2.3 SBOM wrapper around the internal
  manifest (``build_spdx``); the Linux Foundation companion to
  the OWASP-flavoured CycloneDX output.
"""

from __future__ import annotations

from ._cyclonedx import CYCLONEDX_SPEC_VERSION, build_cyclonedx
from ._funrec import SCHEMA_VERSION, build_manifest
from ._provenance import (
    CAPA_BUILD_TYPE, CAPA_BUILDER_ID, SLSA_PREDICATE_TYPE,
    build_provenance,
)
from ._spdx import SPDX_SPEC_VERSION, build_spdx
from ._strings import _ty_text
from ._vex import build_vex_document, build_vex_entries


__all__ = [
    "SCHEMA_VERSION",
    "CYCLONEDX_SPEC_VERSION",
    "SPDX_SPEC_VERSION",
    "CAPA_BUILD_TYPE",
    "CAPA_BUILDER_ID",
    "SLSA_PREDICATE_TYPE",
    "build_manifest",
    "build_cyclonedx",
    "build_spdx",
    "build_vex_document",
    "build_vex_entries",
    "build_provenance",
]
