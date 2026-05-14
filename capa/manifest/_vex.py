"""VEX (Vulnerability Exploitability eXchange) emission.

CycloneDX 1.4+ VEX format. Walks the manifest for ``@vex`` attribute
declarations on functions and emits the corresponding
``vulnerabilities[]`` entries, one per ``@vex`` annotation. Each
entry's ``affects[]`` points to the specific *function* the
declaration was attached to, giving Capa a property no other
language has today: **per-function VEX granularity**.

Standard VEX says "CVE-X affects package Y, but our usage is/isn't
exploitable, justification Z". Per-function VEX refines that to
"CVE-X is not exploitable in function F because F does not declare
the capability the exploit needs". Whether a downstream consumer
(Dependency-Track, Anchore, Grype) treats per-function refs as
first-class or as opaque component refs is up to the consumer; the
CycloneDX schema is permissive enough that either works.

VEX vocabulary (CycloneDX 1.5):

  - ``state``: not_affected | affected | fixed | in_triage |
    false_positive | exploitable | resolved | resolved_with_pedigree
  - ``justification`` (required when state=not_affected):
    code_not_present | code_not_reachable | requires_configuration |
    requires_dependency | requires_environment |
    protected_by_compiler | protected_at_runtime |
    protected_at_perimeter | protected_by_mitigating_control

The capability-typed natural fit: **code_not_reachable** with a
detail like "function F declares no Net, the exploit's network
sink cannot be reached from this entry point".
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Optional

from .. import capa_ast as A

from ._funrec import build_manifest


# CycloneDX VEX vocabulary, used for soft validation (warning, not
# error). Strict validation is the consumer's job; we just nudge.
_KNOWN_STATES = {
    "not_affected", "affected", "fixed", "in_triage",
    "false_positive", "exploitable", "resolved",
    "resolved_with_pedigree",
}

_KNOWN_JUSTIFICATIONS = {
    "code_not_present", "code_not_reachable", "requires_configuration",
    "requires_dependency", "requires_environment",
    "protected_by_compiler", "protected_at_runtime",
    "protected_at_perimeter", "protected_by_mitigating_control",
}


def build_vex_entries(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Walk the module's @vex attributes and produce CycloneDX
    vulnerability entries.

    Returns a list ready to drop into the top-level
    ``vulnerabilities[]`` of a CycloneDX 1.5 document. Empty list if
    no function carries a @vex attribute.
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    inner = build_manifest(module, filename=filename, capa_version=capa_version)
    bom_basename = os.path.basename(filename) or filename

    entries: list[dict[str, Any]] = []

    for fn in inner["functions"]:
        if fn["container"]:
            qualname = f"{fn['container']}::{fn['name']}"
        else:
            qualname = fn["name"]
        fn_ref = f"capa:fn:{bom_basename}:{qualname}"

        for attr in fn["attributes"]:
            if attr["name"] != "vex":
                continue
            args = attr["args"]
            cve = args.get("cve") or "UNKNOWN"
            state = args.get("status") or "in_triage"
            analysis: dict[str, Any] = {"state": state}
            if "justification" in args:
                analysis["justification"] = args["justification"]
            if "detail" in args:
                analysis["detail"] = args["detail"]
            analysis["firstIssued"] = timestamp
            entries.append({
                "bom-ref": f"capa:vex:{bom_basename}:{qualname}:{cve}",
                "id": cve,
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve}"},
                "analysis": analysis,
                "affects": [{"ref": fn_ref}],
            })

    return entries


def build_vex_document(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> dict[str, Any]:
    """Build a standalone CycloneDX 1.5 VEX-only document.

    Same envelope as the full SBOM but the ``components`` list is
    minimal (just the program) and the ``vulnerabilities`` list
    carries the VEX entries. For consumers that want VEX
    separately from the SBOM (CSAF-style workflow).
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    bom_basename = os.path.basename(filename) or filename
    entries = build_vex_entries(
        module,
        filename=filename,
        capa_version=capa_version,
        timestamp=timestamp,
    )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {"type": "application", "name": "capa", "version": capa_version}
                ]
            },
            "component": {
                "bom-ref": f"capa:program:{bom_basename}",
                "type": "application",
                "name": bom_basename,
                "version": capa_version,
            },
        },
        "vulnerabilities": entries,
    }
