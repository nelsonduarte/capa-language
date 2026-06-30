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
