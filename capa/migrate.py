"""capa/migrate.py, gradual-hardening progress reporting for ``capa migrate``.

Capa's Python interop is one-way through the ``Unsafe`` capability:
``py_import(unsafe, name)`` and ``py_invoke(unsafe, callable, args)`` are
the only operations that consume an ``Unsafe`` token, and both return
``Unknown``. The recommended way to adopt Capa on top of an existing
Python codebase is *gradual hardening*: start with everything behind
``Unsafe`` (a thin bridge to the Python original), then migrate one
function at a time to typed Capa until no ``Unsafe`` remains. The shipped
``examples/migrate_logfetcher_step{1,2,3}_*.capa`` demo and
``docs/migration.md`` walk through exactly that.

This module answers the two questions a developer mid-migration keeps
asking: *how far along am I*, and *which ``Unsafe`` can I drop next*. It
reuses :func:`capa.manifest.build_manifest` rather than re-walking the AST,
so the progress report is computed from the same per-function records that
back the SBOM (``has_unsafe``, ``params``, ``calls``).

Public API:

``migrate_report(module, *, filename="<input>") -> dict``
    A JSON-serialisable report (see :func:`migrate_report` for the shape).

``render_report(report) -> str``
    A human-readable rendering of that report for the terminal.
"""

from __future__ import annotations

from typing import Any

from .manifest import build_manifest


# The only builtins that consume an ``Unsafe`` token. A function whose
# Unsafe is genuinely exercised must, directly or transitively, reach one
# of these.
_BRIDGE_CALLS = ("py_import", "py_invoke")


def _unsafe_param_names(fn: dict[str, Any]) -> list[str]:
    """Names of the function's ``Unsafe``-typed parameters.

    Uses the manifest param records, whose ``type`` is the rendered type
    text; the root type name is the first identifier-ish token.
    """
    names: list[str] = []
    for p in fn["params"]:
        ty = p.get("type") or ""
        # Root type name: strip any generic/qualified tail so e.g.
        # "Unsafe" matches but a hypothetical "UnsafeThing" does not.
        root = ty.split("<", 1)[0].split(".", 1)[0].strip()
        if root == "Unsafe":
            names.append(p["name"])
    return names


def _bridge_call_count(fn: dict[str, Any]) -> int:
    """Number of direct ``py_import`` / ``py_invoke`` call sites."""
    return sum(1 for c in fn["calls"] if c["callee"] in _BRIDGE_CALLS)


def _forwards_unsafe(fn: dict[str, Any], unsafe_names: list[str]) -> bool:
    """Whether any ``Unsafe`` parameter is passed as a call argument.

    Conservative on purpose: an ``Unsafe`` name appearing anywhere in an
    argument expression (as a whole token) counts as "forwarded", so we
    never declare a still-needed ``Unsafe`` removable.
    """
    if not unsafe_names:
        return False
    targets = set(unsafe_names)
    for call in fn["calls"]:
        for arg in call["args"]:
            # Argument expressions are source-like stringifications.
            # Tokenise on non-identifier characters and look for an
            # exact match against an Unsafe parameter name.
            for tok in _identifier_tokens(arg):
                if tok in targets:
                    return True
    return False


def _identifier_tokens(text: str) -> list[str]:
    """Split a stringified expression into identifier-like tokens."""
    tokens: list[str] = []
    cur: list[str] = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            cur.append(ch)
        elif cur:
            tokens.append("".join(cur))
            cur = []
    if cur:
        tokens.append("".join(cur))
    return tokens


def _is_removable(fn: dict[str, Any], unsafe_names: list[str]) -> bool:
    """Whether the function declares ``Unsafe`` it never actually uses.

    True when the function has an ``Unsafe`` parameter but (1) never calls
    a bridge builtin and (2) never forwards the token to another call. In
    that case the ``Unsafe`` parameter is dead weight and can be dropped
    from the signature. Intentionally conservative (no transitive
    call-graph analysis): it never wrongly flags a needed ``Unsafe``, it
    only under-reports.

    Note that the analyser already rejects a capability parameter that is
    referenced nowhere ("declared but never used; prefix with '_' to
    silence"), so the live target of this check is the param that was
    silenced with a leading underscore and is now genuinely dead, e.g.
    after the last ``py_invoke`` was migrated away but the ``_u: Unsafe``
    was left in the signature.
    """
    if not unsafe_names:
        return False
    if _bridge_call_count(fn) > 0:
        return False
    return not _forwards_unsafe(fn, unsafe_names)


def migrate_report(module, *, filename: str = "<input>") -> dict[str, Any]:
    """Build a gradual-hardening progress report for an analysed module.

    Returns a JSON-serialisable dict::

        {
          "file": "<path>",
          "summary": {
            "total_functions": int,
            "functions_using_unsafe": int,
            "functions_removable_unsafe": int,
            "percent_unsafe_free": int  # 0..100
          },
          "removable": [ {source_name, pos, param_name}, ... ],
          "next_candidates": [ {source_name, pos, bridge_call_count}, ... ]
        }

    ``removable`` lists functions whose ``Unsafe`` can be dropped now.
    ``next_candidates`` ranks the functions that still genuinely use
    ``Unsafe`` by how few bridge calls they make (cheapest to harden
    first), ties broken by source position.
    """
    manifest = build_manifest(module, filename=filename)
    functions = manifest["functions"]
    total = len(functions)

    using_unsafe: list[dict[str, Any]] = []
    removable: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    for fn in functions:
        if not fn["has_unsafe"]:
            continue
        unsafe_names = _unsafe_param_names(fn)
        using_unsafe.append(fn)
        if _is_removable(fn, unsafe_names):
            removable.append({
                "source_name": fn["source_name"],
                "pos": fn["pos"],
                # An impl method can declare Unsafe via ``self`` rather
                # than a named parameter; report the first param name or
                # None so the caller can phrase the hint accordingly.
                "param_name": unsafe_names[0] if unsafe_names else None,
            })
        else:
            candidates.append({
                "source_name": fn["source_name"],
                "pos": fn["pos"],
                "bridge_call_count": _bridge_call_count(fn),
            })

    candidates.sort(key=lambda c: (c["bridge_call_count"], c["pos"]))

    n_using = len(using_unsafe)
    if total == 0:
        percent = 100
    else:
        percent = round((total - n_using) / total * 100)

    return {
        "file": filename,
        "summary": {
            "total_functions": total,
            "functions_using_unsafe": n_using,
            "functions_removable_unsafe": len(removable),
            "percent_unsafe_free": percent,
        },
        "removable": removable,
        "next_candidates": candidates,
    }


def _progress_bar(percent: int, width: int = 24) -> str:
    """A simple ``[####----]`` bar for the given percentage."""
    filled = round(percent / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def render_report(report: dict[str, Any]) -> str:
    """Render a :func:`migrate_report` result for the terminal."""
    s = report["summary"]
    total = s["total_functions"]
    using = s["functions_using_unsafe"]
    free = total - using
    percent = s["percent_unsafe_free"]

    lines: list[str] = []
    lines.append(f"Migration progress for {report['file']}")
    lines.append(f"  {_progress_bar(percent)} {percent}% Unsafe-free")
    lines.append(
        f"  {free}/{total} function(s) are Unsafe-free; "
        f"{using} still use Unsafe."
    )

    if total == 0:
        lines.append("")
        lines.append("No functions found.")
        return "\n".join(lines)

    if using == 0:
        lines.append("")
        lines.append("Done: this module is fully hardened, no Unsafe remains.")
        return "\n".join(lines)

    removable = report["removable"]
    if removable:
        lines.append("")
        lines.append(
            f"These {len(removable)} function(s) can drop Unsafe now "
            "(it is declared but never exercised):"
        )
        for r in removable:
            param = f" (param `{r['param_name']}`)" if r["param_name"] else ""
            lines.append(f"  - {r['source_name']}{param}  {r['pos']}")

    candidates = report["next_candidates"]
    if candidates:
        lines.append("")
        lines.append("Next, consider hardening (fewest bridge calls first):")
        for c in candidates:
            n = c["bridge_call_count"]
            calls = f"{n} bridge call{'s' if n != 1 else ''}"
            lines.append(f"  - {c['source_name']}  {c['pos']}  ({calls})")

    return "\n".join(lines)
