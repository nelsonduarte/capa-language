"""Built-in names are reserved.

Every name the analyzer installs as a built-in global (the free
functions, the capabilities, the built-in types, ``JsonValue`` and the
built-in variants) is reserved: it may not name a variable, parameter,
lambda parameter, pattern binder, loop variable, constant or module-level
function, in the root program or in any dependency, and a built-in
FUNCTION may not be used as a value. With the names reserved, whether a
call names the built-in is a fact about module scope alone, which every
phase and every backend has.

A type-namespace declaration (a struct or sum type, a variant, a
typestate, a trait, a capability, an extern component) may not take one
of the built-in FUNCTION names either. Declaring one with a built-in TYPE
name (``type Range``) is a separate matter and is not refused here (see
the negatives).

The cases are GENERATED over the analyzer's own built-in table (see
``tests/_builtin_name_corpus.py``) crossed with every binder kind. Each
reserved-name program has a same-shaped twin that differs only in the name
(the control), which must stay accepted, so a refusal cannot come from
anything but the name.
"""

from __future__ import annotations

import unittest

from tests._builtin_name_corpus import (
    FUNCTION_SPECS,
    Project,
    analyze_source,
    assert_specs_cover,
    builtin_function_names,
    builtin_global_names,
    fun_type,
    renamed,
    same_file,
    TYPE_DECLS,
    type_decl,
    user_fun,
)


def reserved_marker(name: str) -> str:
    """The fragment every reserved-name refusal carries."""
    return f"{name!r} is the name of a built-in"


def value_marker(name: str) -> str:
    return f"the built-in function {name!r} cannot be used as a value"


def _has(result, marker: str) -> bool:
    return any(marker in e.message for e in result.errors)


# ---------------------------------------------------------------------------
# Binder kinds in a single file. Each template takes the bound name ``N`` and
# returns a whole program; the binder is the ONLY place ``N`` occurs.
# ``lower_only`` marks the shapes that are binders only for a lowercase
# name (in a ``match`` arm a capitalised bare name is a variant pattern, not
# a binder, so there is nothing to reserve there).
# ---------------------------------------------------------------------------

_H = "type H {{ k: Int }}\n\n"

ROOT_BINDERS: dict[str, tuple[str, bool]] = {
    "let": ("fun main()\n    let {N} = 1\n", False),
    "var": ("fun main()\n    var {N} = 1\n", False),
    "let_tuple": ("fun main()\n    let ({N}, k) = (1, 2)\n", False),
    "let_struct_field": (
        _H + "fun main()\n    let h = H {{ k: 1 }}\n    let H {{ k: {N} }} = h\n",
        False,
    ),
    "let_struct_shorthand": (
        "type H {{ {N}: Int }}\n\n"
        "fun main()\n    let h = H {{ {N}: 1 }}\n    let H {{ {N} }} = h\n",
        False,
    ),
    "for": ("fun main()\n    for {N} in [1, 2]\n        let z = 0\n", False),
    "for_tuple": (
        "fun main()\n    for ({N}, k) in [(1, 2)]\n        let z = 0\n", False,
    ),
    "match_ident": (
        "fun main()\n    let z = match 1\n        {N} -> 0\n", True,
    ),
    "match_payload": (
        "fun main()\n    let z = match Some(1)\n        Some({N}) -> 0\n"
        "        None -> 1\n",
        True,
    ),
    "match_struct_shorthand": (
        "type H {{ {N}: Int }}\n\n"
        "fun main()\n    let h = H {{ {N}: 1 }}\n    let z = match h\n"
        "        H {{ {N} }} -> 0\n",
        False,
    ),
    "match_struct_field": (
        _H + "fun main()\n    let h = H {{ k: 1 }}\n    let z = match h\n"
        "        H {{ k: {N} }} -> 0\n",
        True,
    ),
    "param": ("fun go({N}: Int) -> Int\n    return 1\n", False),
    "generic_param": ("fun go<T>({N}: T) -> Int\n    return 1\n", False),
    "lambda_param": (
        "fun main()\n    let g = fun ({N}: Int) -> Int => 1\n", False,
    ),
    "lambda_local": (
        "fun main()\n    let g = fun () -> Int =>\n        let {N} = 1\n"
        "        return 1\n",
        False,
    ),
    "block_local": ("fun main()\n    if true\n        let {N} = 1\n", False),
    "while_local": (
        "fun main()\n    while false\n        let {N} = 1\n", False,
    ),
    "method_param": (
        _H + "impl H\n    fun m(self, {N}: Int) -> Int\n        return 1\n",
        False,
    ),
    "method_local": (
        _H + "impl H\n    fun m(self) -> Int\n        let {N} = 1\n"
        "        return 1\n",
        False,
    ),
    "ct_local": (
        "@constant_time()\nfun go() -> Int\n    let {N} = 1\n    return 1\n",
        False,
    ),
    "const_lambda_param": (
        "const C: Fun(Int) -> Int = fun ({N}: Int) -> Int => 1\n", False,
    ),
    "module_const": ("const {N}: Int = 1\n", False),
    "module_fun": ("fun {N}() -> Int\n    return 1\n", False),
    "module_pub_fun": ("pub fun {N}() -> Int\n    return 1\n", False),
}


def _binder_cases():
    for kind, (tmpl, lower_only) in ROOT_BINDERS.items():
        for name in builtin_global_names():
            if lower_only and name[0].isupper():
                continue
            yield kind, name, tmpl


class TestReservedNameSet(unittest.TestCase):
    """The reserved set is read off the analyzer; pin its shape so a
    change to the built-in table is a visible, deliberate event."""

    def test_reserved_set_is_the_47_installed_globals(self):
        names = builtin_global_names()
        self.assertEqual(len(names), 47, names)
        for expected in ("panic", "to_int", "declassify", "Random",
                         "IoError", "Range", "JsonValue", "Some", "JNull"):
            self.assertIn(expected, names)

    def test_function_specs_cover_every_builtin_function(self):
        assert_specs_cover(self)


class TestReservedBindersRoot(unittest.TestCase):
    """PIN-REFUSE, root program: every binder kind x every reserved name is
    refused with the reserved-name diagnostic, and its renamed twin is
    accepted."""

    def test_every_binder_kind_refuses_every_reserved_name(self):
        accepted, broken_controls, cases = [], [], 0
        for kind, name, tmpl in _binder_cases():
            cases += 1
            _, rx = analyze_source(tmpl.format(N=name))
            if not _has(rx, reserved_marker(name)):
                accepted.append(f"{kind}:{name}")
            _, rr = analyze_source(tmpl.format(N=renamed(name)))
            if not rr.ok:
                broken_controls.append(
                    f"{kind}:{renamed(name)}: {rr.errors[0].message[:90]}"
                )
        self.assertGreater(cases, 900)
        self.assertEqual(broken_controls, [], "controls must stay accepted")
        self.assertEqual(
            accepted, [],
            f"{len(accepted)} of {cases} reserved-name binders were not "
            f"refused",
        )

    def test_refusal_points_at_the_binder(self):
        src = "fun main()\n    let a = 1\n    let panic = 2\n"
        _, r = analyze_source(src)
        hits = [e for e in r.errors if reserved_marker("panic") in e.message]
        self.assertEqual(len(hits), 1, [e.message for e in r.errors])
        self.assertEqual(hits[0].pos.line, 3)


# ---------------------------------------------------------------------------
# Dependencies. A refusal that falls in a dependency names that file.
# ---------------------------------------------------------------------------

_DEP = "helperpkg/util.capa"
_INNER = "innerpkg/inner.capa"
_DEP_TAIL = (
    "pub fun noop() -> Unit\n    return\n\n"
    "pub fun other() -> Int\n    return 1\n"
)
_ROOT_WHOLE = "import helperpkg.util as util\n\nfun main()\n    util.noop()\n"

# kind -> (files template, the file the refusal must name)
DEP_BINDERS: dict[str, tuple[dict[str, str], str]] = {
    "dep_pub_fun": ({
        "main.capa": _ROOT_WHOLE,
        _DEP: "pub fun {N}() -> Int\n    return 1\n\n" + _DEP_TAIL,
    }, _DEP),
    "dep_private_fun": ({
        "main.capa": _ROOT_WHOLE,
        _DEP: "fun {N}() -> Int\n    return 1\n\n" + _DEP_TAIL,
    }, _DEP),
    "dep_pub_const": ({
        "main.capa": _ROOT_WHOLE,
        _DEP: "pub const {N}: Int = 1\n\n" + _DEP_TAIL,
    }, _DEP),
    "dep_local": ({
        "main.capa": _ROOT_WHOLE,
        _DEP: "pub fun g() -> Int\n    let {N} = 1\n    return 1\n\n"
              + _DEP_TAIL,
    }, _DEP),
    "dep_param": ({
        "main.capa": _ROOT_WHOLE,
        _DEP: "pub fun g({N}: Int) -> Int\n    return 1\n\n" + _DEP_TAIL,
    }, _DEP),
    "dep_unselected_fun": ({
        "main.capa": "import helperpkg.util (noop)\n\nfun main()\n    noop()\n",
        _DEP: "pub fun {N}() -> Int\n    return 1\n\n" + _DEP_TAIL,
    }, _DEP),
    "dep_alias_out": ({
        "main.capa": "import helperpkg.util (noop, {N} as zz)\n\n"
                     "fun main()\n    noop()\n",
        _DEP: "pub fun {N}() -> Int\n    return 1\n\n" + _DEP_TAIL,
    }, _DEP),
    "alias_in": ({
        "main.capa": "import helperpkg.util (noop, other as {N})\n\n"
                     "fun main()\n    noop()\n",
        _DEP: _DEP_TAIL,
    }, "main.capa"),
    "transitive_pub_fun": ({
        "main.capa": _ROOT_WHOLE,
        _DEP: "import innerpkg.inner as inner\n\n" + _DEP_TAIL,
        _INNER: "pub fun {N}() -> Int\n    return 1\n",
    }, _INNER),
}


def _fill(files: dict[str, str], name: str) -> dict[str, str]:
    return {rel: text.replace("{N}", name) for rel, text in files.items()}


class TestReservedBindersDependency(unittest.TestCase):
    """PIN-REFUSE, dependencies: the same rule holds in every linked file,
    and the diagnostic names the file the binder is in."""

    def test_every_dependency_binder_is_refused_in_its_own_file(self):
        missed, wrong_file, broken_controls, cases = [], [], [], 0
        for kind, (files, where) in DEP_BINDERS.items():
            for name in builtin_global_names():
                cases += 1
                px = Project(_fill(files, name))
                try:
                    _, rx = px.analyze()
                    hits = [
                        e for e in rx.errors
                        if reserved_marker(name) in e.message
                    ]
                    if not hits:
                        missed.append(f"{kind}:{name}")
                    elif not any(
                        same_file(e.filename, px.path(where)) for e in hits
                    ):
                        wrong_file.append(
                            f"{kind}:{name} -> {[e.filename for e in hits]}"
                        )
                finally:
                    px.close()
                pr = Project(_fill(files, renamed(name)))
                try:
                    _, rr = pr.analyze()
                    if not rr.ok:
                        broken_controls.append(
                            f"{kind}:{renamed(name)}: "
                            f"{rr.errors[0].message[:90]}"
                        )
                finally:
                    pr.close()
        self.assertEqual(cases, len(DEP_BINDERS) * 47)
        self.assertEqual(broken_controls, [], "controls must stay accepted")
        self.assertEqual(wrong_file, [], "refusal must name the binder's file")
        self.assertEqual(
            missed, [],
            f"{len(missed)} of {cases} dependency binders were not refused",
        )

    def test_import_alias_refusal_points_at_the_alias(self):
        main = "import helperpkg.util (noop, other as to_int)\n\nfun main()\n    noop()\n"
        p = Project({"main.capa": main, _DEP: _DEP_TAIL})
        try:
            _, r = p.analyze()
        finally:
            p.close()
        hits = [e for e in r.errors if reserved_marker("to_int") in e.message]
        self.assertEqual(len(hits), 1, [e.message for e in r.errors])
        self.assertEqual(
            (hits[0].pos.line, hits[0].pos.col),
            (1, main.index("to_int") + 1),
        )


# ---------------------------------------------------------------------------
# Type-namespace declarations (owner decision 2026-10-04): a struct, sum
# type, variant, typestate, trait, capability or extern component may not
# take one of the built-in FUNCTION names either, in the root or in any
# dependency. Built-in TYPE names (``Range``) are a separate class.
# ---------------------------------------------------------------------------


def _type_decl_dep_shapes(kind: str) -> dict[str, tuple[dict[str, str], str]]:
    """shape -> (files with ``{N}``, the file the refusal must name)."""
    pub = type_decl(kind, "{N}", pub=True)
    priv = type_decl(kind, "{N}")
    return {
        "dep_pub": ({"main.capa": _ROOT_WHOLE, _DEP: pub + "\n" + _DEP_TAIL}, _DEP),
        "dep_private": ({"main.capa": _ROOT_WHOLE, _DEP: priv + "\n" + _DEP_TAIL}, _DEP),
        "transitive_pub": ({
            "main.capa": _ROOT_WHOLE,
            _DEP: "import innerpkg.inner as inner\n\n" + _DEP_TAIL,
            _INNER: pub,
        }, _INNER),
        "dep_unselected": ({
            "main.capa": "import helperpkg.util (noop)\n\nfun main()\n    noop()\n",
            _DEP: pub + "\n" + _DEP_TAIL,
        }, _DEP),
    }


class TestReservedTypeDeclarations(unittest.TestCase):
    """PIN-REFUSE for type-namespace declarations: every declaration kind x
    every built-in FUNCTION name, root and dependency; the renamed twin is
    accepted."""

    def test_root_type_declarations_refuse_every_function_name(self):
        missed, broken, cases = [], [], 0
        for kind in TYPE_DECLS:
            for name in builtin_function_names():
                cases += 1
                _, rx = analyze_source(type_decl(kind, name))
                if not _has(rx, reserved_marker(name)):
                    missed.append(f"{kind}:{name}")
                _, rr = analyze_source(type_decl(kind, renamed(name)))
                if not rr.ok:
                    broken.append(f"{kind}:{rr.errors[0].message[:90]}")
        self.assertEqual(cases, len(TYPE_DECLS) * 14)
        self.assertEqual(broken, [], "controls must stay accepted")
        self.assertEqual(missed, [], f"{len(missed)} of {cases} accepted")

    def test_dependency_type_declarations_are_refused_in_their_file(self):
        missed, wrong_file, broken, cases = [], [], [], 0
        for kind in TYPE_DECLS:
            for shape, (files, where) in _type_decl_dep_shapes(kind).items():
                for name in builtin_function_names():
                    cases += 1
                    px = Project(_fill(files, name))
                    try:
                        _, rx = px.analyze()
                    finally:
                        px.close()
                    hits = [
                        e for e in rx.errors
                        if reserved_marker(name) in e.message
                    ]
                    if not hits:
                        missed.append(f"{shape}:{kind}:{name}")
                    elif not any(
                        same_file(e.filename, px.path(where)) for e in hits
                    ):
                        wrong_file.append(f"{shape}:{kind}:{name}")
                    pr = Project(_fill(files, renamed(name)))
                    try:
                        _, rr = pr.analyze()
                    finally:
                        pr.close()
                    if not rr.ok:
                        broken.append(
                            f"{shape}:{kind}: {rr.errors[0].message[:90]}"
                        )
        self.assertEqual(cases, len(TYPE_DECLS) * 4 * 14)
        self.assertEqual(broken, [], "controls must stay accepted")
        self.assertEqual(wrong_file, [], "refusal must name the binder's file")
        self.assertEqual(missed, [], f"{len(missed)} of {cases} accepted")

    def test_type_import_alias_is_refused_at_the_alias(self):
        missed = []
        for name in builtin_function_names():
            main = (
                f"import helperpkg.util (noop, Qtype as {name})\n\n"
                "fun main()\n    noop()\n"
            )
            p = Project({
                "main.capa": main,
                _DEP: "pub type Qtype { k: Int }\n\n" + _DEP_TAIL,
            })
            try:
                _, r = p.analyze()
            finally:
                p.close()
            hits = [e for e in r.errors if reserved_marker(name) in e.message]
            if not hits or (hits[0].pos.line, hits[0].pos.col) != (
                1, main.index(f"as {name}") + 4,
            ) or not same_file(hits[0].filename, p.path("main.capa")):
                missed.append(name)
        self.assertEqual(missed, [])


# ---------------------------------------------------------------------------
# PIN-VALUE: a built-in function used as a value. Each position is written
# against a user function of the same shape (``userfn``) as the control, so
# the X twin differs only in which name is referenced.
# ---------------------------------------------------------------------------

VALUE_POSITIONS: dict[str, str] = {
    "let": "fun main()\n    let f = {V}\n",
    "var": "fun main()\n    var f = {V}\n",
    "list": "fun main()\n    let fs = [{V}]\n",
    "tuple": "fun main()\n    let t = ({V}, 1)\n",
    "call_arg": (
        "fun take(f: {T}) -> Int\n    return 1\n\n"
        "fun main()\n    let z = take({V})\n"
    ),
    "named_arg": (
        "fun take(f: {T}) -> Int\n    return 1\n\n"
        "fun main()\n    let z = take(f: {V})\n"
    ),
    "return": "fun give() -> {T}\n    return {V}\n",
    "method_arg": (
        "type H {{ k: Int }}\n\nimpl H\n    fun take(self, f: {T}) -> Int\n"
        "        return 1\n\n"
        "fun main()\n    let h = H {{ k: 1 }}\n    let z = h.take({V})\n"
    ),
    "const_init": "const C: {T} = {V}\n",
    "lambda_body": "fun main()\n    let g = fun () -> {T} => {V}\n",
    "match_arm": (
        "fun main()\n    let f = match 1\n        1 -> {V}\n        _ -> {V}\n"
    ),
    "if_expr": "fun main()\n    let f = if true then {V} else {V}\n",
    "struct_field": (
        "type B {{ f: {T} }}\n\nfun main()\n    let b = B {{ f: {V} }}\n"
    ),
}


class TestBuiltinFunctionAsValue(unittest.TestCase):
    """PIN-VALUE: every value position x every built-in function is
    refused; the same program referencing a user function is accepted."""

    def test_every_value_position_refuses_every_builtin_function(self):
        accepted, broken_controls, cases = [], [], 0
        for pos_kind, tmpl in VALUE_POSITIONS.items():
            for name in builtin_function_names():
                spec = FUNCTION_SPECS[name]
                pre = user_fun("userfn", spec) + "\n"
                cases += 1
                _, rx = analyze_source(
                    pre + tmpl.format(V=name, T=fun_type(spec))
                )
                if not _has(rx, value_marker(name)):
                    accepted.append(f"{pos_kind}:{name}")
                _, rr = analyze_source(
                    pre + tmpl.format(V="userfn", T=fun_type(spec))
                )
                if not rr.ok:
                    broken_controls.append(
                        f"{pos_kind}:{name}: {rr.errors[0].message[:90]}"
                    )
        self.assertEqual(cases, len(VALUE_POSITIONS) * 14)
        self.assertEqual(broken_controls, [], "controls must stay accepted")
        self.assertEqual(
            accepted, [],
            f"{len(accepted)} of {cases} value uses were not refused",
        )


# ---------------------------------------------------------------------------
# What stays legal.
# ---------------------------------------------------------------------------


class TestLegitimateFormsStayAccepted(unittest.TestCase):

    def _ok(self, src: str) -> None:
        _, r = analyze_source(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_direct_calls_of_every_builtin_function_are_untouched(self):
        self._ok(
            "fun main(stdio: Stdio)\n"
            "    let a = to_int(1.5)\n"
            "    let b = to_float(2)\n"
            "    let c = parse_int(\"7\")\n"
            "    let d = parse_float(\"7.5\")\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"k\", 1)\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(1)\n"
            "    let j = parse_json(\"1\")\n"
            "    stdio.println(\"${a} ${b}\")\n"
        )

    def test_builtin_called_inside_a_lambda_is_accepted(self):
        self._ok(
            "fun main()\n"
            "    let f = fun (x: Float) -> Int => to_int(x)\n"
            "    let z = f(1.5)\n"
        )

    def test_user_function_used_as_a_value_is_accepted(self):
        self._ok(
            "fun conv(x: Float) -> Int\n    return 1\n\n"
            "fun main()\n    let f = conv\n    let z = f(1.5)\n"
        )

    def test_payloadless_variant_value_is_accepted(self):
        self._ok("fun main()\n    let o: Option<Int> = None\n")

    def test_methods_named_like_builtins_are_accepted(self):
        self._ok(
            "type H { k: Int }\n\n"
            "impl H\n"
            "    fun to_int(self) -> Int\n        return self.k\n"
            "    fun panic(self) -> Int\n        return 0\n\n"
            "fun main()\n    let h = H { k: 1 }\n"
            "    let a = h.to_int()\n    let b = h.panic()\n"
        )

    def test_struct_fields_named_like_builtins_are_accepted(self):
        self._ok(
            "type H { panic: Int, to_int: Int }\n\n"
            "fun main()\n    let h = H { panic: 1, to_int: 2 }\n"
            "    let a = h.panic + h.to_int\n"
        )

    def test_type_declaration_with_a_builtin_name_is_not_refused(self):
        # Built-in TYPE identity is a separate concern: a type declaration
        # named like a built-in type is not a value binder.
        _, r = analyze_source(
            "type Range { lo: Int, hi: Int }\n\n"
            "fun main()\n    let r = Range { lo: 1, hi: 2 }\n"
        )
        self.assertFalse(
            _has(r, reserved_marker("Range")), [e.message for e in r.errors]
        )

    def test_names_that_only_contain_a_builtin_are_accepted(self):
        self._ok(
            "fun to_int2(x: Int) -> Int\n    return x\n\n"
            "const panicky: Int = 1\n\n"
            "fun main()\n    let my_panic = 1\n    let parse_int_x = 2\n"
        )

    def test_dependency_without_reserved_names_links_and_checks(self):
        p = Project({
            "main.capa": "import helperpkg.util (noop, other as helper)\n\n"
                         "fun main()\n    noop()\n    let z = helper()\n",
            _DEP: _DEP_TAIL,
        })
        try:
            _, r = p.analyze()
            self.assertTrue(r.ok, [e.message for e in r.errors])
        finally:
            p.close()


if __name__ == "__main__":
    unittest.main()
