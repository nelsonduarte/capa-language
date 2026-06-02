"""Information-flow runtime primitives (roadmap S2.5).

``declassify(value, reason)`` is the single auditable bridge from a
``@secret`` value to a ``@public`` one. At runtime it is the identity
function: it returns ``value`` unchanged. Its entire purpose is at
compile time -- the analyzer relabels the result ``@public`` and the
SBOM records every call site together with its ``reason`` string, so a
regulator can read off exactly where, and why, the program lets secret
data cross to a public sink. The ``reason`` argument is required to be a
string literal (enforced by the analyzer) precisely so the manifest can
record it verbatim.
"""

from __future__ import annotations


def declassify(value, reason):
    """Return ``value`` unchanged. The security relabelling and the
    SBOM audit record happen at compile time; at runtime this is a
    no-op identity so the value flows through with zero overhead."""
    return value
