"""Soundness harness for the ``--wasi`` path-arg surface (Layer 1,
:mod:`capa.ir._wasi_path_arg_surface`).

The surface PROVES which ``argv`` (``env.args()``) elements reach which
Fs / Net / Env sinks, read or write. It is an auditable, by-construction
fact, so it must be a CORRECT OVER-APPROXIMATION of the true argv -> sink
boundary. For every program the GROUND TRUTH is the EXACT set of facts a
careful manual read finds: which argv elements genuinely reach which
sink, with what access, and whether the index is statically determinate.

Two soundness obligations, checked per program:

* COVER (never omit): every ground-truth argv -> sink fact is COVERED by
  the analysis -- either by the same concrete index, or by an
  ``argv[*]`` (ANY) fact of the same cap / method / access (a sound
  conservative widening). A ground-truth fact with no covering analysis
  fact is an OMISSION (fail-closed violated) and fails the harness.

* NEVER-NARROWER (never invent precision): every analysis fact with a
  CONCRETE index must correspond to a ground-truth fact that genuinely
  has that concrete index (same cap / method / access). A concrete index
  the ground truth does not support -- or a concrete index where the
  truth is only ``ANY`` -- is the analysis claiming a NARROWER surface
  than proved, and fails the harness.

(The analysis MAY report ``argv[*]`` where the ground truth is a
concrete index: that only WIDENS the surface, never narrows it, and is
allowed. It MAY NOT report a concrete index where the truth is ``*``.)
"""

from __future__ import annotations

import unittest
from dataclasses import dataclass

from capa import Lexer, Parser
from capa.ir._wasi_path_arg_surface import (
    compute_path_arg_surface, ANY_INDEX, FS_CAP, NET_CAP, ENV_CAP,
)


@dataclass(frozen=True)
class G:
    """A ground-truth argv -> sink fact. ``index`` is an int when a
    careful read proves a single concrete argv element reaches the sink,
    or ``ANY_INDEX`` when an argv element reaches it but which one is not
    statically determinate."""

    index: object
    cap: str
    method: str
    access: str


_CORPUS: list[tuple[str, str, list]] = []


def _case(name: str, src: str, truth: list) -> None:
    _CORPUS.append((name, src, truth))


# --- no argv at all: empty surface.
_case(
    "no_argv",
    """
fun main(fs: Fs)
    let _ = match fs.read("data.json") { Err(_) -> "", Ok(s) -> s }
""",
    [],
)

# --- argv read but never reaches a sink: empty surface.
_case(
    "argv_unused_at_sink",
    """
fun main(fs: Fs, env: Env)
    let args = env.args()
    let n = args.len()
    let _ = match fs.read("static.json") { Err(_) -> "", Ok(s) -> s }
""",
    [],
)

# --- the MOTIVATING case: argv[0] -> Fs.read, proved concrete index.
_case(
    "argv_get0_to_read",
    """
fun main(fs: Fs, env: Env)
    let args = env.args()
    let path = match args.get(0) { None -> "", Some(p) -> p }
    let _ = match fs.read(path) { Err(_) -> "", Ok(s) -> s }
""",
    [G(0, FS_CAP, "read", "read")],
)

# --- argv first() -> index 0.
_case(
    "argv_first_to_read",
    """
fun main(fs: Fs, env: Env)
    let p = match env.args().first() { None -> "", Some(x) -> x }
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    [G(0, FS_CAP, "read", "read")],
)

# --- argv indexing args[1] -> index 1.
_case(
    "argv_index1_to_write",
    """
fun main(fs: Fs, env: Env)
    let args = env.args()
    let out = args[1]
    let _ = fs.write(out, "body")
""",
    [G(1, FS_CAP, "write", "write")],
)

# --- argv routed through a helper to fs.write: ANY index (the slot in
# the sink's frame is a parameter, not a direct argv index).
_case(
    "argv_through_helper_write",
    """
fun save(fs: Fs, path: String)
    let _ = fs.write(path, "x")
fun main(fs: Fs, env: Env)
    let out = match env.args().get(2) { None -> "out", Some(p) -> p }
    save(fs, out)
""",
    [G(2, FS_CAP, "write", "write")],
)

# --- argv routed through a STRUCT FIELD then interpolation to a sink:
# the index is lost (ANY), but the arg still reaches the sink, so the
# fact must NOT be omitted.
_case(
    "argv_through_struct_and_interp",
    """
type Opts { out_dir: String }
fun main(fs: Fs, env: Env)
    let dir = match env.args().get(0) { None -> ".", Some(d) -> d }
    let opts = Opts { out_dir: dir }
    let path = "${opts.out_dir}/report.json"
    let _ = fs.write(path, "x")
""",
    [G(ANY_INDEX, FS_CAP, "write", "write")],
)

# --- argv element reaches BOTH a read and a write sink.
_case(
    "argv_read_and_write",
    """
fun main(fs: Fs, env: Env)
    let args = env.args()
    let inp = match args.get(0) { None -> "", Some(p) -> p }
    let outp = match args.get(1) { None -> "", Some(p) -> p }
    let _ = match fs.read(inp) { Err(_) -> "", Ok(s) -> s }
    let _ = fs.write(outp, "x")
""",
    [G(0, FS_CAP, "read", "read"), G(1, FS_CAP, "write", "write")],
)

# --- argv -> Net.get (read) and Net.post (write).
_case(
    "argv_to_net",
    """
fun main(net: Net, env: Env)
    let url = match env.args().get(0) { None -> "", Some(u) -> u }
    let _ = match net.get(url) { Err(_) -> "", Ok(s) -> s }
    let _ = match net.post(url, "body") { Err(_) -> "", Ok(s) -> s }
""",
    [G(0, NET_CAP, "get", "read"), G(0, NET_CAP, "post", "write")],
)

# --- argv -> Env.get (the env KEY itself comes from argv).
_case(
    "argv_to_env_get",
    """
fun main(env: Env)
    let key = match env.args().get(0) { None -> "", Some(k) -> k }
    let _ = match env.get(key) { None -> "", Some(v) -> v }
""",
    [G(0, ENV_CAP, "get", "read")],
)

# --- a computed index (loop variable) over argv -> ANY index, must be
# reported (the arg reaches the sink) but never as a concrete index.
_case(
    "argv_computed_index",
    """
fun main(fs: Fs, env: Env, i: Int)
    let args = env.args()
    let p = args[i]
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- a static literal path next to an argv path: ONLY the argv path is
# in the surface (the literal is not argv-derived).
_case(
    "mixed_literal_and_argv",
    """
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = match fs.read("static.json") { Err(_) -> "", Ok(s) -> s }
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    [G(0, FS_CAP, "read", "read")],
)

# --- argv flows through a multi-frame helper chain (main -> a -> b ->
# sink): ANY index, must be reported.
_case(
    "argv_multi_frame_chain",
    """
fun b(fs: Fs, path: String)
    let _ = match fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun a(fs: Fs, path: String)
    b(fs, path)
fun main(fs: Fs, env: Env)
    let p = match env.args().get(3) { None -> "", Some(x) -> x }
    a(fs, p)
""",
    [G(3, FS_CAP, "read", "read")],
)

# --- argv returned from a helper, then fed to a sink in the caller.
_case(
    "argv_returned_from_helper",
    """
fun first_arg(env: Env) -> String
    return match env.args().get(0) { None -> "", Some(x) -> x }
fun main(fs: Fs, env: Env)
    let p = first_arg(env)
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- mkdir from argv is a WRITE access.
_case(
    "argv_mkdir_is_write",
    """
fun main(fs: Fs, env: Env)
    let d = match env.args().get(0) { None -> ".", Some(x) -> x }
    let _ = fs.mkdir(d)
""",
    [G(0, FS_CAP, "mkdir", "write")],
)

# --- argv reaches a built-in Fs sink whose RECEIVER is a struct FIELD
# (``self.fs.read`` in an impl), routed through the wrapping cap method:
# the surface must NOT omit it (the const-prop treats it as DYNAMIC, but
# omitting an argv-reaching sink is unsound for the surface). Mirrors the
# capa_showcase ``ReadOnlyFsImpl { fs: Fs }`` shape.
_case(
    "argv_to_field_stored_cap",
    """
type RoFs { fs: Fs }
impl RoFs
    fun read(self, path: String) -> String
        return match self.fs.read(path) { Err(_) -> "", Ok(s) -> s }
fun main(env: Env, fs: Fs)
    let ro = RoFs { fs: fs }
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = ro.read(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- argv reaches a sink whose receiver is a LOCAL aliasing a cap param
# (``let g = fs; g.read(p)``): recognised, not omitted.
_case(
    "argv_to_cap_local_alias",
    """
fun main(env: Env, fs: Fs)
    let g = fs
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = match g.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    [G(0, FS_CAP, "read", "read")],
)

# --- argv via for-loop binding reaches a sink -> ANY index.
_case(
    "argv_for_loop",
    """
fun main(fs: Fs, env: Env)
    for arg in env.args()
        let _ = match fs.read(arg) { Err(_) -> "", Ok(s) -> s }
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- LAMBDA-BODY SINK (regression: pre-fix ``_child_exprs`` never visited
# a lambda body, so this sink was OMITTED and the surface falsely said no
# argv reaches a sink). The argv LIST is mapped through a closure whose
# body reads each element -> argv reaches fs.read (ANY index: a higher-
# order element binding, not a single static index).
_case(
    "argv_map_lambda_read",
    """
fun main(fs: Fs, env: Env)
    let args = env.args()
    let _ = args.map(fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s })
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- 0-arg lambda CAPTURING an argv-bound name, then called: the captured
# ``p`` is the concrete argv[0], and the sink lives in the closure body
# (pre-fix: omitted because the body was never walked).
_case(
    "argv_lambda_zero_arg_capture",
    """
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let go = fun () => match fs.read(p) { Err(_) -> "", Ok(s) -> s }
    let _ = go()
""",
    [G(0, FS_CAP, "read", "read")],
)

# --- a NAMED closure called with an argv-tainted argument: the taint flows
# to the lambda parameter and the body's sink must be reported (pre-fix:
# omitted; index is ANY since the slot is a closure parameter).
_case(
    "argv_named_lambda_called",
    """
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let rd = fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
    let _ = rd(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- a NAMED closure passed BY NAME to a higher-order over argv
# (``let rd = fun (a) => ...; args.map(rd)``). Pre-fix the higher-order
# branch only tainted INLINE LambdaExpr args, so a closure referenced by
# name was omitted and the surface falsely reported EMPTY. Each argv
# element is bound to ``rd``'s parameter -> ANY index.
_case(
    "argv_named_closure_to_higher_order",
    """
fun main(fs: Fs, env: Env)
    let rd = fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
    let _ = env.args().map(rd)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE (A-i): a closure passed to a GENERIC helper that invokes it
# (``apply(fun (a) => ..., p)``), with an argv-tainted value also passed.
# The surface cannot follow where ``apply`` binds the closure's param, so
# to stay never-omit it reports the body's param sink at ``argv[*]``.
# (Pre-fix: omitted -- the lambda was neither an argv higher-order arg nor
# a name called directly with argv, so its param stayed untainted.)
_case(
    "argv_escape_to_helper_apply",
    """
fun apply(f: Fun(String) -> String, x: String) -> String
    return f(x)
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = apply(fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s }, p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE (A-ii): a closure RETURNED from a function, then invoked with
# argv in the caller. The closure escapes ``make``'s frame; its param is
# bound by an unknown caller (here argv), so the body's sink is reported
# conservatively at ``argv[*]``. (Pre-fix: omitted.)
_case(
    "argv_escape_returned_lambda",
    """
fun make(fs: Fs) -> Fun(String) -> String
    return fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
fun main(fs: Fs, env: Env)
    let rd = make(fs)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = rd(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE (A-iii): a closure STORED in a struct field, then invoked with
# argv. Stored in an aggregate the closure outlives the frame; its param is
# bound later (here from argv), so the body's sink is reported at
# ``argv[*]``. (Pre-fix: omitted.)
_case(
    "argv_escape_field_stored_lambda",
    """
type Box { f: Fun(String) -> String }
fun main(fs: Fs, env: Env)
    let g = fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
    let b = Box { f: g }
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = (b.f)(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE precision guard: a closure stored in a LIST whose body reads a
# STATIC literal (NOT its param). The escape taints the param, but the sink
# slot is the literal, so NO false argv fact is produced. Confirms the
# escape widening only fires through the param.
_case(
    "escape_lambda_static_sink_no_fact",
    """
type Box { f: Fun(String) -> String }
fun main(fs: Fs)
    let _ = [fun (a) => match fs.read("static.json") { Err(_) -> "", Ok(s) -> s }]
""",
    [],
)

# --- ESCAPE through a RETURNED MATCH ARM (sound-by-construction): a closure
# produced inline as an arm of a ``match`` that is RETURNED escapes the
# frame. Pre-fix ``lam_of`` only descended a bare lambda or a name bound
# DIRECTLY to one, so a lambda nested in a returned match arm was OMITTED and
# the surface falsely reported EMPTY. The general rule descends into match
# arms and reports the param sink at ``argv[*]``.
_case(
    "argv_escape_returned_match_arm_lambda",
    """
fun make(fs: Fs, mode: String) -> Fun(String) -> String
    return match mode { _ -> fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s } }
fun main(fs: Fs, env: Env, mode: String)
    let rd = make(fs, mode)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = rd(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE through a RETURNED IF ARM: a closure produced as a branch of a
# returned ``if`` expression escapes the frame. Pre-fix: omitted (the
# IfExpr branch was never descended). Reported at ``argv[*]``.
_case(
    "argv_escape_returned_if_arm_lambda",
    """
fun make(fs: Fs, flag: Bool) -> Fun(String) -> String
    return if flag then fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s } else fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
fun main(fs: Fs, env: Env, flag: Bool)
    let rd = make(fs, flag)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = rd(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE via a name bound to a MATCH that is then returned
# (``let g = match { ... lambda ... }; return g``). Pre-fix the name ``g``
# was not recognised as holding a lambda (only a name bound DIRECTLY to a
# LambdaExpr was), so the returned closure was OMITTED. The general rule
# resolves ``g`` to the wrapped closure and reports at ``argv[*]``.
_case(
    "argv_escape_let_match_then_returned",
    """
fun make(fs: Fs, mode: String) -> Fun(String) -> String
    let g = match mode { _ -> fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s } }
    return g
fun main(fs: Fs, env: Env, mode: String)
    let rd = make(fs, mode)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = rd(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE via a closure stored as a MAP element, where the closure is
# reached only THROUGH A NAME bound to a returned match (``let g = match {
# ... fun ... }; Map.new().insert("k", g)``). Pre-fix the map-stored closure
# behind a name bound to a WRAPPED value was OMITTED (the name was not
# recognised as holding a lambda). The general rule resolves ``g`` to the
# wrapped closure stored in the map and reports at ``argv[*]``.
_case(
    "argv_escape_map_element_named_wrapped_lambda",
    """
fun make(fs: Fs, mode: String) -> Map<String, Fun(String) -> String>
    let g = match mode { _ -> fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s } }
    return Map.new().insert("k", g)
fun main(fs: Fs, env: Env, mode: String)
    let _ = make(fs, mode)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE via a closure nested in a RETURNED NESTED STRUCT where the
# closure is reached only THROUGH A NAME bound to a returned ``if`` arm
# (``let g = if .. then fun .. else fun ..; Outer { inner: Inner { f: g } }``).
# Pre-fix: omitted (the name ``g`` bound to an IfExpr was not seen to hold a
# lambda). The general rule descends the if arms behind the name and reports
# at ``argv[*]`` two aggregate levels deep.
_case(
    "argv_escape_nested_struct_named_wrapped_lambda",
    """
type Inner { f: Fun(String) -> String }
type Outer { inner: Inner }
fun make(fs: Fs, flag: Bool) -> Outer
    let g = if flag then fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s } else fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
    return Outer { inner: Inner { f: g } }
fun main(fs: Fs, env: Env, flag: Bool)
    let _ = make(fs, flag)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE via a closure wrapped in ``Some(...)`` and returned, where the
# closure is reached only THROUGH A NAME bound to a returned match
# (``let g = match { ... fun ... }; return Some(g)``). Pre-fix: omitted (the
# name ``g`` inside the variant constructor was not seen to hold a lambda).
# The general rule resolves ``g`` inside the wrapper and reports at
# ``argv[*]``.
_case(
    "argv_escape_some_wrapped_named_lambda",
    """
fun make(fs: Fs, mode: String) -> Option<Fun(String) -> String>
    let g = match mode { _ -> fun (a) => match fs.read(a) { Err(_) -> "", Ok(s) -> s } }
    return Some(g)
fun main(fs: Fs, env: Env, mode: String)
    let _ = make(fs, mode)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- ESCAPE precision guard (sound-by-construction, no over-fire): a closure
# nested in a RETURNED match arm whose body reads a STATIC literal (NOT its
# param). The general escape rule taints the param, but the sink slot is the
# literal, so NO false argv fact is produced -- the widening fires through the
# param only, even through the new wrapping descent.
_case(
    "escape_returned_match_arm_static_sink_no_fact",
    """
fun make(fs: Fs, mode: String) -> Fun(String) -> String
    return match mode { _ -> fun (a) => match fs.read("static.json") { Err(_) -> "", Ok(s) -> s } }
fun main(fs: Fs)
    let _ = make(fs, "x")
""",
    [],
)

# --- a BLOCK-BODY lambda (multi-statement) called with an argv-tainted
# argument: the body's sink, reached only by walking the block, must be
# reported (pre-fix: omitted).
_case(
    "argv_block_body_lambda",
    """
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let rd = fun (a) =>
        let r = match fs.read(a) { Err(_) -> "", Ok(s) -> s }
        return r
    let _ = rd(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- a lambda over a NON-argv collection whose body reads a STATIC literal
# path: no argv reaches the sink, so the surface must stay empty (guards
# the lambda-param taint from over-firing into a false fact).
_case(
    "nonargv_lambda_no_fact",
    """
fun main(fs: Fs, nums: List<Int>)
    let _ = nums.map(fun (n) => match fs.read("static.json") { Err(_) -> "", Ok(s) -> s })
""",
    [],
)

# --- REASSIGNED argv index (regression: pre-fix ``_index_provenance``
# ignored ``AssignStmt`` and reported the FIRST binding's index, so this
# falsely claimed ``argv[0]`` while the live value is ``argv[1]``). A
# reassigned argv-index name must collapse to ANY (never narrower than the
# real element).
_case(
    "argv_reassigned_index",
    """
fun main(fs: Fs, env: Env)
    var p = match env.args().get(0) { None -> "", Some(x) -> x }
    p = match env.args().get(1) { None -> "", Some(x) -> x }
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- mirror of the reassignment (0 after 1): still ANY, never the
# first-binding's narrower index.
_case(
    "argv_reassigned_index_mirror",
    """
fun main(fs: Fs, env: Env)
    var p = match env.args().get(1) { None -> "", Some(x) -> x }
    p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- SCOPE-OMISSION CLASS (R5): a NAMED closure bound INSIDE another
# lambda's body, passed BY NAME to a higher-order over argv
# (``let outer = fun (b) =>\\n let rd = fun (a) => fs.read(a)\\n
# args().map(rd)``). Pre-fix the statement-level helpers (``_all_stmts``,
# ``_lambda_name_bindings``, the application sweep) never descended into a
# lambda BODY, so the ``let rd = ...`` binding and the ``args().map(rd)``
# application inside ``outer`` were invisible and the surface falsely
# reported EMPTY. Each argv element binds ``rd``'s param -> ANY index.
_case(
    "argv_named_nested_closure_higher_order",
    """
fun main(fs: Fs, env: Env)
    let outer = fun (b: Int) -> Int =>
        let rd = fun (a: String) -> String => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
        let _ = env.args().map(rd)
        return b
    let _ = outer(0)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- SCOPE-OMISSION CLASS (R1): a NAMED closure bound INSIDE another
# lambda's body, APPLIED with an argv-tainted argument inside that same
# body (``let rd = fun (a) => ...; let p = args.get(0); rd(p)``). Pre-fix:
# omitted (the binding and the application lived in a lambda sub-scope the
# statement helpers never entered). ANY index (slot is a closure param).
_case(
    "argv_named_nested_closure_applied",
    """
fun main(fs: Fs, env: Env)
    let outer = fun (b: Int) -> Int =>
        let rd = fun (a: String) -> String => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
        let p = match env.args().get(0) { None -> "", Some(x) -> x }
        let _ = rd(p)
        return b
    let _ = outer(0)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- SCOPE-OMISSION CLASS, DEEPER NESTING: a named closure three lambda
# levels deep, mapped over argv from the innermost frame. Confirms the
# statement-level descent recurses through ARBITRARY lambda nesting, not
# just one level.
_case(
    "argv_named_closure_triple_nested",
    """
fun main(fs: Fs, env: Env)
    let a1 = fun (x: Int) -> Int =>
        let a2 = fun (y: Int) -> Int =>
            let rd = fun (a: String) -> String => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
            let _ = env.args().map(rd)
            return y
        let _ = a2(0)
        return x
    let _ = a1(0)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- SCOPE-OMISSION CLASS, named-nested bound to a MATCH inside a lambda
# body: the named closure is reached through a ``match`` wrapper, itself
# bound inside ``outer``'s body, then mapped over argv. Confirms the
# descent composes with the existing wrapping descent (``lams_reachable``).
_case(
    "argv_named_nested_closure_via_match",
    """
fun main(fs: Fs, env: Env)
    let outer = fun (b: Int) -> Int =>
        let rd = match b { _ -> fun (a: String) -> String => match fs.read(a) { Err(_) -> "", Ok(s) -> s } }
        let _ = env.args().map(rd)
        return b
    let _ = outer(0)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- SCOPE precision guard (no scope confusion): a NESTED lambda whose
# OWN ``return`` yields an argv value, while the ENCLOSING function returns
# a non-argv Int and the only sink reads a STATIC literal. The nested
# lambda's ``return`` must NOT be attributed to the enclosing frame (that
# would taint ``helper``'s return and could over-report), and no argv
# reaches a sink, so the surface must stay EMPTY. Guards the statement
# descent from leaking a lambda's return into its enclosing frame.
_case(
    "nested_lambda_return_not_outer_frame_no_fact",
    """
fun helper(env: Env) -> Int
    let f = fun (x: Int) -> String =>
        let p = match env.args().get(0) { None -> "", Some(v) -> v }
        return p
    let _ = f(0)
    return 5
fun main(fs: Fs, env: Env)
    let n = helper(env)
    let _ = match fs.read("static.json") { Err(_) -> "", Ok(s) -> s }
""",
    [],
)

# --- SCOPE-OMISSION CLASS (match-arm BLOCK body): a named closure bound and
# APPLIED with an argv-tainted value INSIDE a multi-line ``match`` arm's
# ``Block`` body. Pre-fix the statement-level traversal descended into
# if/while/for blocks and lambda bodies but NOT into a match-arm block (it
# lives at the expression level), so the ``let rd = ...`` binding and the
# ``rd(p)`` application inside the arm were invisible and the surface falsely
# reported EMPTY. ANY index (slot is a closure parameter).
_case(
    "argv_match_arm_block_named_closure_applied",
    """
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    match env.args()
        _ ->
            let rd = fun (a: String) -> String => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
            let _ = rd(p)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- SCOPE-OMISSION CLASS (match-arm BLOCK body, higher-order): a named
# closure bound inside a match-arm block, passed BY NAME to a higher-order
# over argv (``args().map(rd)``) within that same arm block. Pre-fix:
# omitted (the arm-block binding + application were never traversed). ANY.
_case(
    "argv_match_arm_block_map_named_closure",
    """
fun main(fs: Fs, env: Env)
    match env.args()
        _ ->
            let rd = fun (a: String) -> String => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
            let _ = env.args().map(rd)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- SCOPE-OMISSION CLASS (match-arm BLOCK inside a LAMBDA body): a named
# closure bound inside a match-arm block that is ITSELF inside another
# lambda's body, mapped over argv. Confirms the same-frame match-arm descent
# composes with the cross-frame lambda descent (the arm block belongs to the
# lambda's frame, and its binding/application are reached). Pre-fix: omitted.
_case(
    "argv_match_arm_block_inside_lambda",
    """
fun main(fs: Fs, env: Env)
    let outer = fun (b: Int) -> Int =>
        match b
            _ ->
                let rd = fun (a: String) -> String => match fs.read(a) { Err(_) -> "", Ok(s) -> s }
                let _ = env.args().map(rd)
        return b
    let _ = outer(0)
""",
    [G(ANY_INDEX, FS_CAP, "read", "read")],
)

# --- SCOPE-OMISSION CLASS (IF-STATEMENT block inside a match-arm block):
# a sink whose argv-tainted slot lives inside an ``if`` block that is itself
# inside a match-arm block -- two same-frame sub-scopes deep. Confirms the
# traversal composes control-flow and match-arm descent. Pre-fix: omitted.
_case(
    "argv_if_block_inside_match_arm_block",
    """
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    match env.args()
        _ ->
            if true
                let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
""",
    [G(0, FS_CAP, "read", "read")],
)

# --- SCOPE precision guard (match-arm block, no over-fire): a named closure
# bound inside a match-arm block whose body reads a STATIC literal (NOT argv).
# The descent reaches the binding but the sink slot is a literal, so NO false
# argv fact is produced -- confirms the match-arm descent does not over-report.
_case(
    "match_arm_block_static_sink_no_fact",
    """
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    match env.args()
        _ ->
            let _ = match fs.read("static.json") { Err(_) -> "", Ok(s) -> s }
""",
    [],
)


def _covers(analysis_facts, g: G) -> bool:
    """A ground-truth fact ``g`` is covered when some analysis fact has
    the same cap / method / access AND an index that is either exactly
    ``g.index`` or ``ANY_INDEX`` (a sound widening)."""
    for f in analysis_facts:
        if f.cap == g.cap and f.method == g.method and f.access == g.access:
            if f.arg_index is ANY_INDEX or f.arg_index == g.index:
                return True
    return False


def _concrete_supported(g_list, f) -> bool:
    """An analysis fact ``f`` with a CONCRETE index must match a ground
    truth fact that genuinely has THAT concrete index (same cap / method
    / access). A concrete index against an ``ANY`` ground truth, or no
    matching truth at all, is the analysis narrowing the surface."""
    for g in g_list:
        if g.cap == f.cap and g.method == f.method and g.access == f.access \
                and g.index == f.arg_index:
            return True
    return False


class TestPathArgSurfaceSoundness(unittest.TestCase):
    def _surface(self, src: str):
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        return compute_path_arg_surface(module).facts

    def test_corpus_is_sound(self) -> None:
        failures: list[str] = []
        for name, src, truth in _CORPUS:
            facts = self._surface(src)
            # COVER: every ground-truth fact must be covered.
            for g in truth:
                if not _covers(facts, g):
                    failures.append(
                        f"{name}: OMISSION -- ground truth {g} not covered "
                        f"by analysis {[ _fmt(f) for f in facts ]}"
                    )
            # NEVER-NARROWER: a concrete analysis index must be backed by
            # the ground truth.
            for f in facts:
                if f.arg_index is not ANY_INDEX and \
                        not _concrete_supported(truth, f):
                    failures.append(
                        f"{name}: NARROWER -- analysis claims {_fmt(f)} but "
                        f"ground truth does not support that concrete index"
                    )
        if failures:
            self.fail(
                "path-arg surface soundness violations:\n  "
                + "\n  ".join(failures)
            )

    def test_motivating_case_proves_concrete_index(self) -> None:
        facts = self._surface(
            """
fun main(fs: Fs, env: Env)
    let p = match env.args().get(0) { None -> "", Some(x) -> x }
    let _ = match fs.read(p) { Err(_) -> "", Ok(s) -> s }
"""
        )
        self.assertEqual(len(facts), 1)
        (f,) = facts
        self.assertEqual(f.arg_index, 0)
        self.assertEqual(f.cap, FS_CAP)
        self.assertEqual(f.access, "read")


def _fmt(f) -> str:
    idx = "*" if f.arg_index is ANY_INDEX else f.arg_index
    return f"argv[{idx}]->{f.cap}.{f.method}/{f.access}"


if __name__ == "__main__":
    unittest.main()
