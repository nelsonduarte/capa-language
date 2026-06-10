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
asking: *how far along am I*, and *which ``Unsafe`` can I drop next*. In
a multi-file project the report also breaks the progress down per source
file and recommends the next file to harden (slice 3; see
:func:`migrate_report` for the ranking criterion). It
reuses :func:`capa.manifest.build_manifest` rather than re-walking the AST,
so the progress report is computed from the same per-function records that
back the SBOM (``has_unsafe``, ``params``, ``calls``).

Removable-``Unsafe`` detection is transitive over the module call graph
(slice 2): an ``Unsafe`` parameter whose token only ever flows to
functions that can never reach a bridge call counts as removable too,
not just the token that is referenced nowhere. The analysis is
deliberately conservative; see :func:`_compute_reach` for the exact
rules. It can under-report (miss a removable ``Unsafe``) but never
flags an ``Unsafe`` that is genuinely needed.

Public API:

``migrate_report(module, *, filename="<input>") -> dict``
    A JSON-serialisable report (see :func:`migrate_report` for the shape).

``render_report(report) -> str``
    A human-readable rendering of that report for the terminal.

``find_dead_unsafe(module, *, filename="<input>") -> list[DeadUnsafe]``
    The removable verdicts as per-parameter entries with source
    positions. Single source of truth for the analyzer's dead-Unsafe
    warning (surfaced by the CLI and the LSP); ``migrate_report``
    renders the same verdicts per function.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import capa_ast as A
from .manifest import build_manifest, display_filename
from .manifest._reachability import (
    _caps_via_type,
    _type_mentions_any,
    compute_reachability,
)
from .manifest._strings import _root_type_name
from .tokens import Pos


# The only builtins that consume an ``Unsafe`` token. A function whose
# Unsafe is genuinely exercised must, directly or transitively, reach one
# of these.
_BRIDGE_CALLS = ("py_import", "py_invoke")

# A callee we can resolve against the module's top-level functions must
# be a plain identifier (method calls stringify as ``recv.method`` and
# never match).
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

# ``_stringify_expr`` renders an AST node it does not know as
# ``<NodeName>``. Such an argument may hide a token mention, so it is
# treated as opaque (see ``_arg_may_carry``).
_HIDDEN_NODE_RE = re.compile(r"<[A-Za-z_]\w*>")


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


def _arg_may_carry(arg: str, targets: set[str]) -> bool:
    """Whether a stringified call argument may carry an ``Unsafe`` token.

    Argument expressions are source-like stringifications produced by
    the manifest builder. Three rules, conservative on purpose:

    - A pure string literal cannot carry a capability: interpolation
      slots render as ``${...}`` but whatever executes inside them is
      recorded as its own call record, and the resulting value is a
      String. Exempt before the elision check below so ordinary
      logging calls do not poison the analysis.
    - Any ``targets`` name appearing as a whole token counts as a
      potential carry.
    - An *elided* rendering may hide a token mention, so it counts
      too: lambdas render as ``fun(...) => ...`` (a capture is
      invisible), if/match expressions elide their arms, arguments
      longer than the manifest cap truncate to ``...``, and unknown
      node kinds render as ``<NodeName>``.
    """
    if len(arg) >= 2 and arg.startswith('"') and arg.endswith('"'):
        return False
    if any(tok in targets for tok in _identifier_tokens(arg)):
        return True
    if "..." in arg:
        return True
    return _HIDDEN_NODE_RE.search(arg) is not None


# ===========================================================
# Module call graph
# ===========================================================


def _collect_bound_names(node, out: set[str]) -> None:
    """Collect every name a function body can bind (or rebind) locally.

    Capa functions are first-class values: a body can ``let``/``var``
    bind a reference to one function under the *name of another* and
    call through it, so a callee name that the body also binds cannot
    be resolved against the module's top-level functions. The binding
    forms are:

    - ``let`` patterns and ``for`` patterns and ``match`` arm patterns
      (every ``IdentPat`` is a binding occurrence);
    - struct-pattern shorthand fields: ``P { name }`` binds ``name``
      with NO ``IdentPat`` node at all -- the parser records the field
      as ``(name, None)`` (see ``_parse_struct_pattern_fields``), so
      the field name must be collected from the ``StructPat`` itself.
      The explicit form ``P { field: pat }`` carries its bindings
      inside ``pat`` and is covered by the generic walk;
    - ``var`` declarations;
    - plain-identifier assignment targets (a rebinding of a param or
      outer ``var``);
    - lambda parameters (call records inside a lambda body land in the
      same per-function call list).

    The walk mirrors the manifest's generic traversal so it sees the
    same nesting the call records were collected from.
    """
    if node is None:
        return
    if isinstance(node, A.IdentPat):
        out.add(node.name)
        return
    if isinstance(node, A.StructPat):
        for fname, sub in node.fields:
            if sub is None:
                out.add(fname)
    elif isinstance(node, A.VarStmt):
        out.add(node.name)
    elif isinstance(node, A.AssignStmt):
        if isinstance(node.target, A.Ident):
            out.add(node.target.name)
    elif isinstance(node, A.LambdaExpr):
        for p in node.params:
            out.add(p.name)
    if isinstance(node, A.Node):
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            v = getattr(node, f.name)
            if isinstance(v, A.Node):
                _collect_bound_names(v, out)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, A.Node):
                        _collect_bound_names(item, out)
                    elif isinstance(item, tuple):
                        # struct-pattern fields, elif arms, etc.
                        for it in item:
                            if isinstance(it, A.Node):
                                _collect_bound_names(it, out)


@dataclass(kw_only=True)
class _CallGraph:
    """Resolution context for the transitive removable analysis.

    ``by_name`` maps each top-level function's loader-time identifier
    to its ``(manifest record, FunDecl)`` pair; impl methods are never
    callable by bare name, so they stay out. ``reachable`` /
    ``unprovable`` come from the manifest's per-type capability
    reachability fixpoint and answer "can this type smuggle Unsafe".
    ``memo`` caches reach results; a result computed under a non-empty
    cycle stack may be conservatively True, which only ever
    under-reports removability. ``bound_memo`` caches each function's
    locally-bound name set (see :func:`_collect_bound_names`), computed
    lazily because it is only needed when a token-carrying call
    resolves to a top-level name.
    """
    by_name: dict[str, tuple[dict[str, Any], A.FunDecl]]
    ambiguous: set[str]
    reachable: dict[str, set[str]]
    unprovable: set[str]
    memo: dict[tuple[str, Optional[str]], bool] = field(default_factory=dict)
    bound_memo: dict[tuple[str, Optional[str]], frozenset[str]] = field(
        default_factory=dict,
    )


def _body_bound_names(
    rec: dict[str, Any], decl: A.FunDecl, graph: _CallGraph,
) -> frozenset[str]:
    """The (cached) set of names ``decl``'s body binds locally."""
    key = (rec["name"], rec["container"])
    cached = graph.bound_memo.get(key)
    if cached is None:
        names: set[str] = set()
        _collect_bound_names(decl.body, names)
        cached = frozenset(names)
        graph.bound_memo[key] = cached
    return cached


def _build_graph(
    module: A.Module, functions: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], A.FunDecl]], _CallGraph]:
    """Pair manifest records with their FunDecl nodes and build the
    resolution context.

    The decl walk mirrors ``build_manifest`` exactly (top-level
    ``FunDecl`` items in order, then each ``ImplBlock``'s methods), so
    the two lists zip positionally.
    """
    decls: list[A.FunDecl] = []
    for item in module.items:
        if isinstance(item, A.FunDecl):
            decls.append(item)
        elif isinstance(item, A.ImplBlock):
            decls.extend(item.methods)
    if len(decls) != len(functions):  # pragma: no cover - defensive
        raise RuntimeError(
            "capa.migrate: manifest/AST function walk mismatch"
        )
    pairs = list(zip(functions, decls))

    # Per-type Unsafe reachability, in the loader-time (mangled)
    # namespace so it lines up with TypeName/container names.
    user_caps = {
        item.name for item in module.items
        if isinstance(item, A.TraitDecl) and item.is_capability
    }
    reachable, unprovable = compute_reachability(
        module, user_cap_names=user_caps,
    )

    by_name: dict[str, tuple[dict[str, Any], A.FunDecl]] = {}
    ambiguous: set[str] = set()
    for rec, decl in pairs:
        if rec["container"] is not None:
            continue
        name = rec["name"]
        if name in by_name or name in ambiguous:
            # Duplicate top-level names should not analyse cleanly,
            # but if they do, refuse to resolve them at all.
            ambiguous.add(name)
            by_name.pop(name, None)
            continue
        by_name[name] = (rec, decl)
    graph = _CallGraph(
        by_name=by_name, ambiguous=ambiguous,
        reachable=reachable, unprovable=unprovable,
    )
    return pairs, graph


def _signature_poison(
    decl: A.FunDecl, container: Optional[str], graph: _CallGraph,
) -> bool:
    """Whether ``Unsafe`` can flow through this signature in a way the
    textual call-record analysis cannot track.

    A token is trackable only as a plain ``Unsafe``-rooted parameter
    name. Everything else that could carry one poisons the function:

    - a non-``Unsafe``-rooted param whose type reaches ``Unsafe``
      (cap-bearing struct, user cap with an Unsafe-wrapping impl,
      tuple/generic embedding ``Unsafe``);
    - any ``Fun(...)`` in the signature (a closure can capture a
      token invisibly);
    - a return type that reaches ``Unsafe`` (a factory can embed the
      received token in its result);
    - an impl-method container whose type reaches ``Unsafe`` via
      ``self``.
    """
    def _bad(texpr: Optional[A.TypeExpr]) -> bool:
        caps, has_fun = _caps_via_type(texpr, graph.reachable)
        if "Unsafe" in caps or has_fun:
            return True
        return _type_mentions_any(texpr, graph.unprovable)

    for p in decl.params:
        if p.name == "self":
            continue
        if _root_type_name(p.type_expr) == "Unsafe":
            continue  # a plain token param, tracked by name
        if _bad(p.type_expr):
            return True
    if _bad(decl.return_type):
        return True
    if container is not None:
        if "Unsafe" in graph.reachable.get(container, set()):
            return True
        if container in graph.unprovable:
            return True
    return False


def _token_callees(
    rec: dict[str, Any], decl: A.FunDecl, targets: set[str],
    graph: _CallGraph,
) -> Optional[list[str]]:
    """Resolve every call that may carry one of ``targets``.

    Returns the loader-time names of the resolved top-level callees,
    or None when any token-carrying call cannot be resolved (method
    call, callback parameter, locally bound or rebindable name,
    unknown or ambiguous name): the token then escapes our sight and
    the function must count as using it.

    The locally-bound guard matters because functions are first-class:
    a body can shadow a top-level function's name with a ``let``/``var``
    binding to a *different* function and call through it, so a callee
    name the body also binds must not resolve to the homonymous
    top-level declaration.
    """
    out: list[str] = []
    param_names = {p["name"] for p in rec["params"]}
    for call in rec["calls"]:
        if not any(_arg_may_carry(a, targets) for a in call["args"]):
            continue
        callee = call["callee"]
        if callee in _BRIDGE_CALLS:
            return None  # the token feeds a bridge directly
        if call["kind"] != "fn" or _IDENT_RE.fullmatch(callee) is None:
            return None  # method call / computed callee
        if callee in param_names:
            return None  # callback parameter, body unknown
        if callee in graph.ambiguous or callee not in graph.by_name:
            return None  # builtin / unknown / ambiguous
        if callee in _body_bound_names(rec, decl, graph):
            return None  # may be shadowed by a local binding
        out.append(callee)
    return out


def _reaches_bridge(
    rec: dict[str, Any], decl: A.FunDecl, graph: _CallGraph,
    stack: frozenset[tuple[str, Optional[str]]],
) -> bool:
    """Whether a token handed to this function can reach a bridge call,
    directly or transitively. Cycles resolve to True (conservative)."""
    key = (rec["name"], rec["container"])
    if key in stack:
        return True
    cached = graph.memo.get(key)
    if cached is not None:
        return cached
    result = _compute_reach(rec, decl, graph, stack | {key})
    graph.memo[key] = result
    return result


def _compute_reach(
    rec: dict[str, Any], decl: A.FunDecl, graph: _CallGraph,
    stack: frozenset[tuple[str, Optional[str]]],
) -> bool:
    """The reach rules behind :func:`_reaches_bridge`.

    Sound under the analyzer's capability discipline: an ``Unsafe``
    token cannot be aliased (no expression produces an ``Unsafe``
    value), cannot be let/var-bound, and only moves through call
    arguments, closure captures, or cap-bearing struct/impl types.
    The first route is tracked textually via the manifest call
    records; the other two are poisoned wholesale by
    :func:`_signature_poison` and the opaque-argument rule in
    :func:`_arg_may_carry`. Function *references*, unlike tokens, can
    be locally bound under any name, so callee names the body also
    binds refuse to resolve (see :func:`_token_callees`).
    """
    if _bridge_call_count(rec) > 0:
        return True
    if _signature_poison(decl, rec["container"], graph):
        return True
    targets = set(_unsafe_param_names(rec))
    if not targets:
        # No trackable token can enter this function, and Unsafe
        # cannot be minted: it cannot reach a bridge on our behalf.
        return False
    callees = _token_callees(rec, decl, targets, graph)
    if callees is None:
        return True
    for name in callees:
        crec, cdecl = graph.by_name[name]
        if _reaches_bridge(crec, cdecl, graph, stack):
            return True
    return False


def _removability(
    rec: dict[str, Any], decl: A.FunDecl, graph: _CallGraph,
) -> tuple[bool, list[str]]:
    """Whether the function's ``Unsafe`` parameter(s) can be dropped.

    Returns ``(removable, depends_on)``. ``depends_on`` names the
    functions the token is still forwarded to (all proven unable to
    reach a bridge); empty when the token is referenced nowhere. A
    non-empty list means the removal is transitive: the call sites
    forwarding the token (and any dead ``Unsafe`` in those callees)
    have to be cleaned up first.

    The analyser already rejects a capability parameter that is
    referenced nowhere ("declared but never used; prefix with '_' to
    silence"), so the direct case here is the param that was silenced
    with a leading underscore and is now genuinely dead, e.g. after
    the last ``py_invoke`` was migrated away but the ``_u: Unsafe``
    was left in the signature.
    """
    targets = _unsafe_param_names(rec)
    if not targets:
        return False, []
    if _reaches_bridge(rec, decl, graph, frozenset()):
        return False, []
    callees = _token_callees(rec, decl, set(targets), graph) or []
    depends = sorted({graph.by_name[n][0]["source_name"] for n in callees})
    return True, depends


# ===========================================================
# Dead-Unsafe entries (analyzer warning surface)
# ===========================================================


@dataclass(kw_only=True)
class DeadUnsafe:
    """One removable ``Unsafe`` parameter, with its source position.

    ``transitive`` is True when the token is still forwarded to other
    functions (all proven unable to reach a bridge call); those callees
    are listed in ``depends_on`` and their call sites have to lose the
    argument before this parameter can go.
    """
    source_name: str
    param_name: str
    pos: Pos
    transitive: bool
    depends_on: list[str]


def _any_unsafe_param(module: A.Module) -> bool:
    """Cheap pre-check: does any function declare an ``Unsafe``-rooted
    parameter? Only those can ever be removable, so callers (notably
    the analyzer, which runs on every compile and keystroke) skip the
    manifest walk entirely for the common Unsafe-free program."""
    def _has(fn: A.FunDecl) -> bool:
        return any(
            _root_type_name(p.type_expr) == "Unsafe" for p in fn.params
        )
    for item in module.items:
        if isinstance(item, A.FunDecl) and _has(item):
            return True
        if isinstance(item, A.ImplBlock) and any(_has(m) for m in item.methods):
            return True
    return False


def find_dead_unsafe(
    module: A.Module, *, filename: str = "<input>",
) -> list[DeadUnsafe]:
    """Return every removable ``Unsafe`` parameter of the module.

    This is the single source of truth behind the analyzer's
    dead-Unsafe warning; :func:`migrate_report` applies the same
    verdicts (via the shared :func:`_removability`) at function
    granularity. One entry per parameter: a function with several
    dead tokens yields several entries, each positioned at the
    parameter name.
    """
    if not _any_unsafe_param(module):
        return []
    manifest = build_manifest(module, filename=filename)
    pairs, graph = _build_graph(module, manifest["functions"])
    out: list[DeadUnsafe] = []
    for rec, decl in pairs:
        if not rec["has_unsafe"]:
            continue
        is_removable, depends_on = _removability(rec, decl, graph)
        if not is_removable:
            continue
        for name in _unsafe_param_names(rec):
            pos = decl.pos
            for p in decl.params:
                if p.name == name:
                    pos = p.name_pos or p.pos
                    break
            out.append(DeadUnsafe(
                source_name=rec["source_name"],
                param_name=name,
                pos=pos,
                transitive=bool(depends_on),
                depends_on=depends_on,
            ))
    return out


# ===========================================================
# Report
# ===========================================================


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
          "removable": [
            {source_name, pos, param_name, transitive, depends_on},
            ...
          ],
          "next_candidates": [ {source_name, pos, bridge_call_count}, ... ],
          "files": [  # slice 3: per-source-file breakdown
            {
              "file": "<path>",
              "total_functions": int,
              "functions_using_unsafe": int,
              "functions_removable_unsafe": int,
              "percent_unsafe_free": int  # 0..100
            },
            ...
          ],
          "file_ranking": [ "<path>", ... ]
        }

    ``removable`` lists functions whose ``Unsafe`` can be dropped now.
    ``transitive`` is True when the token is still forwarded to other
    functions (none of which can reach a bridge call); ``depends_on``
    names those callees, whose call sites have to lose the argument
    first. ``next_candidates`` ranks the functions that still genuinely
    use ``Unsafe`` by how few bridge calls they make (cheapest to
    harden first), ties broken by source position.

    ``files`` decomposes the same counts by the source file each
    function was *declared* in (the loader lexes every imported module
    under its own path, so a linked multi-file program groups
    correctly), listed in the declaration order of the linked program
    (imports in load order, then the root file). The program-wide
    ``summary`` keeps covering the whole linked program, exactly as
    before slice 3.

    ``file_ranking`` recommends the next file to harden, least
    remaining cost first: files already Unsafe-free are omitted, the
    rest sort by ascending number of functions *genuinely* using
    ``Unsafe`` (still-using minus removable: a removable ``Unsafe`` is
    nearly free to drop, so it must not count against a file), ties
    broken by ascending removable count, then declaration order.
    """
    manifest = build_manifest(module, filename=filename)
    functions = manifest["functions"]
    pairs, graph = _build_graph(module, functions)
    total = len(functions)

    using_unsafe: list[dict[str, Any]] = []
    removable: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    # Per-file aggregation, keyed by the file prefix of the manifest's
    # per-function ``pos`` ("<file>:<line>:<col>"): the same string the
    # report's removable / next_candidates entries display, so the
    # breakdown and the per-entry positions can never disagree on
    # which file a function belongs to. Insertion order is declaration
    # order.
    file_order: list[str] = []
    file_stats: dict[str, dict[str, int]] = {}

    for rec, decl in pairs:
        fname = rec["pos"].rsplit(":", 2)[0]
        stats = file_stats.get(fname)
        if stats is None:
            stats = {"total": 0, "using": 0, "removable": 0}
            file_stats[fname] = stats
            file_order.append(fname)
        stats["total"] += 1
        if not rec["has_unsafe"]:
            continue
        unsafe_names = _unsafe_param_names(rec)
        using_unsafe.append(rec)
        stats["using"] += 1
        is_removable, depends_on = _removability(rec, decl, graph)
        if is_removable:
            stats["removable"] += 1
            removable.append({
                "source_name": rec["source_name"],
                "pos": rec["pos"],
                # An impl method can declare Unsafe via ``self`` rather
                # than a named parameter; report the first param name or
                # None so the caller can phrase the hint accordingly.
                "param_name": unsafe_names[0] if unsafe_names else None,
                "transitive": bool(depends_on),
                "depends_on": depends_on,
            })
        else:
            candidates.append({
                "source_name": rec["source_name"],
                "pos": rec["pos"],
                "bridge_call_count": _bridge_call_count(rec),
            })

    candidates.sort(key=lambda c: (c["bridge_call_count"], c["pos"]))

    n_using = len(using_unsafe)
    if total == 0:
        percent = 100
    else:
        percent = round((total - n_using) / total * 100)

    files: list[dict[str, Any]] = []
    for fname in file_order:
        st = file_stats[fname]
        files.append({
            "file": fname,
            "total_functions": st["total"],
            "functions_using_unsafe": st["using"],
            "functions_removable_unsafe": st["removable"],
            "percent_unsafe_free": round(
                (st["total"] - st["using"]) / st["total"] * 100
            ),
        })
    # Least remaining cost first: clean files are done and stay out;
    # the rest sort by how few functions GENUINELY use Unsafe (a
    # removable Unsafe is nearly free to drop, so a file whose only
    # remaining Unsafe is dead outranks one with a real bridge), ties
    # broken by ascending removable count. The sort is stable, so
    # remaining ties keep declaration order.
    file_ranking = [
        e["file"]
        for e in sorted(
            (e for e in files if e["functions_using_unsafe"] > 0),
            key=lambda e: (
                e["functions_using_unsafe"]
                - e["functions_removable_unsafe"],
                e["functions_removable_unsafe"],
            ),
        )
    ]

    return {
        # Display form (the root file's basename), matching the
        # root-relative POSIX form of every per-entry / per-file
        # ``pos`` below; the raw CLI argument would echo the
        # invocation style (native separators, possibly an absolute
        # path) into both the JSON and the rendered header.
        "file": display_filename(filename),
        "summary": {
            "total_functions": total,
            "functions_using_unsafe": n_using,
            "functions_removable_unsafe": len(removable),
            "percent_unsafe_free": percent,
        },
        "removable": removable,
        "next_candidates": candidates,
        "files": files,
        "file_ranking": file_ranking,
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

    # Per-file breakdown, only when the program actually spans several
    # files: a single-file report renders exactly as it always has.
    # Defensive .get(): a report serialised before slice 3 (stored
    # JSON re-fed to the renderer) has no files / file_ranking keys
    # and must still render.
    files = report.get("files") or []
    if len(files) > 1:
        lines.append("")
        lines.append("Per-file progress:")
        for e in files:
            f_total = e["total_functions"]
            f_free = f_total - e["functions_using_unsafe"]
            line = (
                f"  - {e['file']}  {e['percent_unsafe_free']}% "
                f"Unsafe-free ({f_free}/{f_total})"
            )
            n_rem = e["functions_removable_unsafe"]
            if n_rem:
                line += f", {n_rem} removable Unsafe"
            lines.append(line)
        ranking = report.get("file_ranking") or []
        if ranking:
            nxt = next(e for e in files if e["file"] == ranking[0])
            genuine = (
                nxt["functions_using_unsafe"]
                - nxt["functions_removable_unsafe"]
            )
            n_rem = nxt["functions_removable_unsafe"]
            if genuine == 0:
                # Ranked file with zero genuine Unsafe: everything
                # left is removable, so say that naturally instead
                # of "0 functions genuinely using Unsafe".
                detail = (
                    f"only removable Unsafe left, in "
                    f"{n_rem} function{'s' if n_rem != 1 else ''}"
                )
            else:
                detail = (
                    f"{genuine} function{'s' if genuine != 1 else ''} "
                    "genuinely using Unsafe"
                )
                if n_rem:
                    detail += f", {n_rem} removable"
            lines.append(
                f"  Next file to harden: {nxt['file']} "
                f"({detail}; files with the least genuine Unsafe "
                "come first, already-clean files are done)"
            )

    removable = report["removable"]
    if removable:
        lines.append("")
        lines.append(
            f"These {len(removable)} function(s) can drop Unsafe now "
            "(the token never reaches py_import/py_invoke):"
        )
        for r in removable:
            param = f" (param `{r['param_name']}`)" if r["param_name"] else ""
            lines.append(f"  - {r['source_name']}{param}  {r['pos']}")
            if r.get("depends_on"):
                deps = ", ".join(r["depends_on"])
                lines.append(
                    f"      transitive: still forwarded to {deps}; drop "
                    f"the dead Unsafe there and the forwarding argument "
                    f"first, then this parameter"
                )

    candidates = report["next_candidates"]
    if candidates:
        lines.append("")
        lines.append("Next, consider hardening (fewest bridge calls first):")
        for c in candidates:
            n = c["bridge_call_count"]
            calls = f"{n} bridge call{'s' if n != 1 else ''}"
            lines.append(f"  - {c['source_name']}  {c['pos']}  ({calls})")

    return "\n".join(lines)
