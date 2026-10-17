"""Benign Wasm probes, one per engine feature decision.

Shared by the engine-policy tests and the foreign-component policy tests so
both exercise the same shapes. Every probe is a well-formed module or
component whose only purpose is to USE one Wasm feature; none of them does
anything beyond returning a small integer.

``CORE_PROBES`` maps a row name of ``capa.runtime._engine.ENGINE_FEATURES``
to a core module (text format) that needs exactly that feature. An engine
built by Capa must compile the probe when the row is enabled and refuse it
when the row is disabled. ``UNPROBED_FEATURES`` names the rows that have no
refusable probe, each with the reason; the engine-policy tests fail when a
row is in neither, so a new decision row cannot land without a probe or a
stated reason.

``FOREIGN_CHILDREN`` maps a short name to ``(feature, component text)``: a
foreign component exporting ``submit(x: s64) -> s64`` (the ABI the policy
tests call) whose core module uses ``feature``. The ``plain`` child uses no
feature outside the allow-list and returns ``x + 1``.
"""

from __future__ import annotations

CORE_PROBES: dict[str, str] = {
    # Enabled rows: Capa's own output and the foreign corpus need these.
    "bulk_memory": (
        '(module (memory 1) (func (export "run") (result i32)'
        " (memory.fill (i32.const 0) (i32.const 42) (i32.const 4))"
        " (i32.load8_u (i32.const 0))))"
    ),
    "multi_value": (
        '(module (func $two (result i32 i32) (i32.const 40) (i32.const 2))'
        ' (func (export "run") (result i32) (call $two) (i32.add)))'
    ),
    "reference_types": (
        '(module (table 1 externref) (func (export "run") (result i32)'
        " (drop (table.get 0 (i32.const 0))) (i32.const 42)))"
    ),
    "tail_call": (
        '(module (func $g (result i32) (i32.const 42))'
        ' (func (export "run") (result i32) (return_call $g)))'
    ),
    "component_model": (
        "(component (core module $m"
        ' (func (export "submit") (param i64) (result i64)'
        " (i64.add (local.get 0) (i64.const 1))))"
        " (core instance $i (instantiate $m))"
        ' (func (export "submit") (param "x" s64) (result s64)'
        ' (canon lift (core func $i "submit"))))'
    ),
    # Disabled rows.
    "exceptions": (
        '(module (tag $t (param i32)) (func (export "run") (result i32)'
        " (block $h (result i32) (try_table (catch $t $h)"
        " (throw $t (i32.const 42))) (i32.const 0))))"
    ),
    "gc": (
        '(module (type $s (struct (field i32))) (func (export "run")'
        " (result i32) (struct.get $s 0 (struct.new $s (i32.const 42)))))"
    ),
    "function_references": (
        '(module (type $f (func (result i32))) (func $g (type $f)'
        ' (i32.const 42)) (elem declare func $g) (func (export "run")'
        " (result i32) (call_ref $f (ref.func $g))))"
    ),
    "wide_arithmetic": (
        '(module (func (export "run") (result i32) (i64.add128'
        " (i64.const 40) (i64.const 0) (i64.const 2) (i64.const 0))"
        " (drop) (i32.wrap_i64)))"
    ),
    "simd": (
        '(module (func (export "run") (result i32)'
        " (i32x4.extract_lane 0 (i32x4.splat (i32.const 42)))))"
    ),
    "relaxed_simd": (
        '(module (func (export "run") (result i32) (i32x4.extract_lane 0'
        " (i32x4.relaxed_trunc_f32x4_s (f32x4.splat (f32.const 42))))))"
    ),
    "memory64": (
        '(module (memory i64 1) (func (export "run") (result i32)'
        " (i32.store (i64.const 0) (i32.const 42))"
        " (i32.load (i64.const 0))))"
    ),
    "multi_memory": (
        '(module (memory $a 1) (memory $b 1) (func (export "run")'
        " (result i32) (i32.store $b (i32.const 0) (i32.const 42))"
        " (i32.load $b (i32.const 0))))"
    ),
    "threads": (
        '(module (memory 1 1 shared) (func (export "run") (result i32)'
        " (i32.atomic.store (i32.const 0) (i32.const 42))"
        " (i32.atomic.load (i32.const 0))))"
    ),
    "custom_page_sizes": (
        '(module (memory 1 (pagesize 1)) (func (export "run") (result i32)'
        " (i32.const 42)))"
    ),
    "stack_switching": (
        "(module (type $ft (func)) (type $ct (cont $ft)) (func $g)"
        ' (elem declare func $g) (func (export "run") (result i32)'
        " (drop (cont.new $ct (ref.func $g))) (i32.const 42)))"
    ),
    "component_model_async": (
        "(component (core module $m"
        ' (func (export "submit") (param i64) (result i32) (i32.const 0))'
        ' (func (export "cb") (param i32 i32 i32) (result i32) (i32.const 0)))'
        " (core instance $i (instantiate $m))"
        ' (type $t (func async (param "x" s64) (result s64)))'
        ' (func (export "submit") (type $t) (canon lift (core func $i "submit")'
        ' async (callback (func $i "cb")))))'
    ),
    "component_model_map": (
        "(component (type (map string u32)))"
    ),
}

# Rows with no probe the engine can be seen to refuse, and why.
UNPROBED_FEATURES: dict[str, str] = {
    "branch_hinting": (
        "hints live in a custom section; with the row off the section is "
        "ignored, so there is no refusal to observe"
    ),
    "relaxed_simd_deterministic": (
        "selects deterministic semantics for relaxed SIMD, which is off; "
        "it adds no instructions of its own"
    ),
    "component_model_async_stackful": (
        "every stackful shape also needs component_model_async, so its "
        "probe is refused by that row first"
    ),
    "component_model_more_async_builtins": (
        "the extra builtins are async builtins, refused by "
        "component_model_async first"
    ),
}


def _child(core_module: str) -> str:
    """Wrap a core module exporting ``submit: i64 -> i64`` as a component
    with the foreign ABI the policy tests call."""
    return (
        f"(component (core module $m {core_module})"
        " (core instance $i (instantiate $m))"
        ' (func (export "submit") (param "x" s64) (result s64)'
        ' (canon lift (core func $i "submit"))))'
    )


_SUBMIT = '(func (export "submit") (param i64) (result i64)'

FOREIGN_CHILDREN: dict[str, tuple[str, str]] = {
    "plain": (
        "",
        _child(f"{_SUBMIT} (i64.add (local.get 0) (i64.const 1)))"),
    ),
    "exceptions": (
        "exceptions",
        _child(
            "(tag $t (param i64))"
            f" {_SUBMIT} (block $h (result i64) (try_table (catch $t $h)"
            " (throw $t (i64.add (local.get 0) (i64.const 1))))"
            " (i64.const 0)))"
        ),
    ),
    "tag_import": (
        "exceptions",
        "(component"
        ' (core module $a (tag (export "t") (param i64)))'
        " (core instance $ai (instantiate $a))"
        ' (core module $m (import "a" "t" (tag $t (param i64)))'
        f" {_SUBMIT} (i64.add (local.get 0) (i64.const 1))))"
        ' (core instance $i (instantiate $m (with "a" (instance $ai))))'
        ' (func (export "submit") (param "x" s64) (result s64)'
        ' (canon lift (core func $i "submit"))))',
    ),
    "gc": (
        "gc",
        _child(
            "(type $s (struct (field i64)))"
            f" {_SUBMIT} (struct.get $s 0 (struct.new $s"
            " (i64.add (local.get 0) (i64.const 1)))))"
        ),
    ),
    "function_references": (
        "function_references",
        _child(
            "(type $f (func (param i64) (result i64)))"
            " (func $g (type $f) (i64.add (local.get 0) (i64.const 1)))"
            " (elem declare func $g)"
            f" {_SUBMIT} (call_ref $f (local.get 0) (ref.func $g)))"
        ),
    ),
    "wide_arithmetic": (
        "wide_arithmetic",
        _child(
            f"{_SUBMIT} (i64.add128 (local.get 0) (i64.const 0)"
            " (i64.const 1) (i64.const 0)) (drop))"
        ),
    ),
    "simd": (
        "simd",
        _child(
            f"{_SUBMIT} (i64x2.extract_lane 0 (i64x2.add"
            " (i64x2.splat (local.get 0)) (i64x2.splat (i64.const 1)))))"
        ),
    ),
    "memory64": (
        "memory64",
        _child(
            "(memory i64 1)"
            f" {_SUBMIT} (i64.store (i64.const 0)"
            " (i64.add (local.get 0) (i64.const 1)))"
            " (i64.load (i64.const 0)))"
        ),
    ),
    "multi_memory": (
        "multi_memory",
        _child(
            "(memory $a 1) (memory $b 1)"
            f" {_SUBMIT} (i64.store $b (i32.const 0)"
            " (i64.add (local.get 0) (i64.const 1)))"
            " (i64.load $b (i32.const 0)))"
        ),
    ),
    "async_lift": (
        "component_model_async",
        CORE_PROBES["component_model_async"],
    ),
    "async_builtin": (
        "component_model_async",
        "(component (type $st (stream u8))"
        " (core func $sn (canon stream.new $st))"
        ' (core module $m (import "" "sn" (func (result i64)))'
        f" {_SUBMIT} (i64.add (local.get 0) (i64.const 1))))"
        ' (core instance $i (instantiate $m (with ""'
        ' (instance (export "sn" (func $sn))))))'
        ' (func (export "submit") (param "x" s64) (result s64)'
        ' (canon lift (core func $i "submit"))))',
    ),
}
