"""Container mutation under a secret pc: the strict-tier control direction.

Under ``@strict_ifc`` a mutable container (List / Set / Map) mutated inside
a secret-conditioned branch or loop has secret observable state (length,
membership, iteration order) from then on, so a later read of that state
reaching a public sink is an information-flow error. This is the container
analogue of the shipped scalar implicit-assign, struct-field-store and
sink-under-pc rules, and it is routed through the SAME seam those rules
use (``_IfcMixin._join_pc_if_strict``), keyed by the ONE mutator
classification (``_ifc_tables._CONTAINER_MUTATORS``: MEMBERSHIP answers
"does this method mutate observable state?", the value is the possibly
EMPTY set of argument positions that carry data in, so ``List.pop`` is a
member with no taint arguments).

Design: .claude/IFC_PC_DESIGN_2.md (Sibling A), as amended by
.claude/IFC_PC_CONTEST_2.md. Every member test here was RED on main
``1dc0d27`` (the analyzer accepted the program and it leaked at runtime)
and is GREEN with the fix; the negatives were GREEN before and after.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from capa.analyzer._ifc_tables import _CONTAINER_MUTATORS

from tests.analyzer._helpers import check


def _flow_errors(r):
    return [e for e in r.errors if "information-flow" in e.message]


def _flow_warnings(r):
    return [w for w in r.warnings if "information-flow" in w.message]


def _assert_rejected(tc, src, what):
    r = check(src)
    tc.assertFalse(r.ok, f"{what}: expected a strict rejection, got ok")
    tc.assertGreaterEqual(
        len(_flow_errors(r)), 1,
        f"{what}: expected >= 1 information-flow error, got "
        + str([e.message for e in r.errors]),
    )


def _assert_accepted(tc, src, what):
    r = check(src)
    tc.assertTrue(r.ok, f"{what}: " + str([e.message for e in r.errors]))
    tc.assertEqual(
        _flow_errors(r), [],
        f"{what}: " + str([e.message for e in r.errors]),
    )
    tc.assertEqual(
        _flow_warnings(r), [],
        f"{what}: " + str([w.message for w in r.warnings]),
    )
    return r


# ---- the members: one program per mutator / control shape -----------

M01_SET_ADD = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var xs: Set<String> = new_set()\n"
    '    xs.add("base")\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    if k.starts_with("s")\n'
    '        xs.add("extra")\n'
    '    stdio.println("len=${xs.length()}")\n'
)

M02_SET_REMOVE = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var xs: Set<String> = new_set()\n"
    '    xs.add("BIT_IS_ZERO")\n'
    '    xs.add("BIT_IS_ONE")\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    if k.starts_with("s")\n'
    '        xs.remove("BIT_IS_ZERO")\n'
    "    else\n"
    '        xs.remove("BIT_IS_ONE")\n'
    "    for v in xs.to_list()\n"
    '        stdio.println("survivor=" + v)\n'
)

M03_MAP_SET = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var m: Map<String, Int> = new_map()\n"
    '    m.set("base", 1)\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    if k.starts_with("s")\n'
    '        m.set("extra", 2)\n'
    '    stdio.println("len=${m.length()}")\n'
)

M04_MAP_REMOVE = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var m: Map<String, Int> = new_map()\n"
    '    m.set("a", 1)\n'
    '    m.set("b", 2)\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    if k.starts_with("s")\n'
    '        m.remove("a")\n'
    '    stdio.println("len=${m.length()}")\n'
)

M05_LIST_PUSH = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var xs: List<Int> = []\n"
    "    xs.push(0)\n"
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    if k.starts_with("s")\n'
    "        xs.push(1)\n"
    '    stdio.println("len=${xs.length()}")\n'
)

M06_NESTED_IF = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var xs: Set<String> = new_set()\n"
    '    xs.add("base")\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    "    if k.length() > 0\n"
    '        if k.starts_with("s")\n'
    '            xs.add("extra")\n'
    '    stdio.println("len=${xs.length()}")\n'
)

M07_MATCH_ARM = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var xs: Set<String> = new_set()\n"
    '    xs.add("base")\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    match k.starts_with("s")\n'
    '        true -> xs.add("extra")\n'
    '        false -> xs.add("other")\n'
    '    stdio.println("len=${xs.length()}")\n'
)

M08_WHILE = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var xs: Set<String> = new_set()\n"
    '    xs.add("base")\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    "    var i: Int = 0\n"
    '    while k.starts_with("s") and i < 1\n'
    '        xs.add("extra")\n'
    "        i = i + 1\n"
    '    stdio.println("len=${xs.length()}")\n'
)

M09_FIELD_ROOTED = (
    "type Bag {\n"
    "    items: Set<String>\n"
    "}\n"
    "\n"
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var b: Bag = Bag(items: new_set())\n"
    '    b.items.add("base")\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    if k.starts_with("s")\n'
    '        b.items.add("extra")\n'
    '    stdio.println("len=${b.items.length()}")\n'
)

# The F1 member: a NO-ARGUMENT mutator. Nothing secret is stored and no
# argument exists to carry taint; the container's observable length
# afterwards is what depends on the secret. Membership in the
# classification (with an EMPTY index set) is what catches it.
M_POP = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var xs: List<Int> = []\n"
    "    xs.push(1)\n"
    "    xs.push(2)\n"
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    if k.starts_with("s")\n'
    "        let d = xs.pop()\n"
    '    stdio.println("len=${xs.length()}")\n'
)

# The exact boundary of the Fun-value residual: a lambda defined AND
# invoked inside the secret branch is analyzed at its definition site,
# where the pc is already secret, so it IS a member of this class.
M_LAMBDA_IN_BRANCH = (
    "@strict_ifc()\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var xs: Set<String> = new_set()\n"
    '    xs.add("base")\n'
    '    let k = env.get("API_KEY").unwrap_or("none")\n'
    '    if k.starts_with("s")\n'
    '        let f = fun () => xs.add("extra")\n'
    "        f()\n"
    '    stdio.println("len=${xs.length()}")\n'
)


class TestMutationUnderASecretPcIsRejected(unittest.TestCase):
    """T-M01..T-M09 and T-M-POP: every state-mutating container method,
    executed under a secret strict pc with entirely public arguments and
    read afterwards at a public sink, is a flow error. All six mutators
    are covered, across if / nested-if / match / while control and a
    field-rooted receiver. Each program was accepted on main ``1dc0d27``
    with a measured runtime differential (RED), and is rejected with the
    fix (GREEN)."""

    def test_set_add_under_secret_if(self):
        _assert_rejected(self, M01_SET_ADD, "Set.add")

    def test_set_remove_under_secret_if(self):
        _assert_rejected(self, M02_SET_REMOVE, "Set.remove")

    def test_map_set_under_secret_if(self):
        _assert_rejected(self, M03_MAP_SET, "Map.set")

    def test_map_remove_under_secret_if(self):
        _assert_rejected(self, M04_MAP_REMOVE, "Map.remove")

    def test_list_push_under_secret_if(self):
        _assert_rejected(self, M05_LIST_PUSH, "List.push")

    def test_nested_two_branch(self):
        _assert_rejected(self, M06_NESTED_IF, "nested if")

    def test_match_arm_mutation(self):
        _assert_rejected(self, M07_MATCH_ARM, "match arm")

    def test_while_loop_mutation(self):
        _assert_rejected(self, M08_WHILE, "while loop")

    def test_field_rooted_receiver(self):
        _assert_rejected(self, M09_FIELD_ROOTED, "field-rooted receiver")

    def test_list_pop_under_secret_if(self):
        _assert_rejected(self, M_POP, "List.pop")

    def test_lambda_defined_and_called_in_branch(self):
        _assert_rejected(self, M_LAMBDA_IN_BRANCH, "lambda inside branch")


class TestMembershipIsSeparateFromIndices(unittest.TestCase):
    """The second half of the T-M-POP double bite: MEMBERSHIP in the
    classification, not its argument indices, is what makes a
    no-argument mutator a member. Removing ``List.pop`` from the table
    must silence ONLY the pop member while the argument-carrying members
    stay caught, proving the pop rejection rides the classification and
    not some second, hand-synced rule."""

    def test_removing_pop_membership_reopens_only_pop(self):
        saved = _CONTAINER_MUTATORS.pop(("List", "pop"))
        try:
            r_pop = check(M_POP)
            r_add = check(M01_SET_ADD)
            r_rem = check(M04_MAP_REMOVE)
        finally:
            _CONTAINER_MUTATORS[("List", "pop")] = saved
        self.assertTrue(
            r_pop.ok,
            "without its membership the pop member must fall silent; a "
            "rejection here means a second classification exists: "
            + str([e.message for e in r_pop.errors]),
        )
        self.assertFalse(r_add.ok, "Set.add must not depend on the pop entry")
        self.assertFalse(r_rem.ok, "Map.remove must not depend on the pop entry")


class TestOnePcJoinSeam(unittest.TestCase):
    """T-C2, the behavioural tie: the rule "fold the pc into an assigned
    label when strict" lives in ONE function, ``_join_pc_if_strict``.
    Neutralising it to the identity must silence the scalar, the
    container AND the struct-field-store implicit channels together;
    with it intact all three fire. A fix that added a second, private pc
    join for containers would pass the member tests and fail here."""

    SCALAR = (
        "@strict_ifc()\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var x: Int = 0\n"
        '    let k = env.get("API_KEY").unwrap_or("none")\n'
        '    if k.starts_with("s")\n'
        "        x = 1\n"
        '    stdio.println("x=${x}")\n'
    )

    FIELD_STORE = (
        "type Box {\n"
        "    n: Int\n"
        "}\n"
        "\n"
        "@strict_ifc()\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var b: Box = Box(n: 0)\n"
        '    let k = env.get("API_KEY").unwrap_or("none")\n'
        '    if k.starts_with("s")\n'
        "        b.n = 1\n"
        '    stdio.println("n=${b.n}")\n'
    )

    def test_neutralising_the_join_silences_all_three_directions(self):
        from capa.analyzer import _ifc
        saved = _ifc._IfcMixin._join_pc_if_strict
        _ifc._IfcMixin._join_pc_if_strict = lambda self, label: label
        try:
            r_scalar = check(self.SCALAR)
            r_container = check(M01_SET_ADD)
            r_field = check(self.FIELD_STORE)
        finally:
            _ifc._IfcMixin._join_pc_if_strict = saved
        for what, r in (
            ("scalar", r_scalar),
            ("container", r_container),
            ("field store", r_field),
        ):
            self.assertTrue(
                r.ok,
                f"{what}: with the shared pc join neutralised this must "
                "fall silent; an error here means the direction has a "
                "second pc join of its own: "
                + str([e.message for e in r.errors]),
            )

    def test_intact_join_fires_all_three_directions(self):
        _assert_rejected(self, self.SCALAR, "scalar")
        _assert_rejected(self, M01_SET_ADD, "container")
        _assert_rejected(self, self.FIELD_STORE, "field store")


class TestLegitimateFormsStayAccepted(unittest.TestCase):
    """T-N1..T-N4: the negatives that keep the rule from over-rejecting.
    Together with T-N2's zero-warnings assertion they discriminate the
    two over-broad mutations: dropping the strict gate moves the default
    tier (caught only by T-N2), and tainting every strict mutation
    regardless of pc rejects public-conditioned code (caught by T-N1 and
    T-N3)."""

    N01_PUBLIC_COND = (
        "@strict_ifc()\n"
        "fun main(stdio: Stdio, env: Env)\n"
        "    var xs: Set<String> = new_set()\n"
        '    xs.add("base")\n'
        '    let ok = env.allows("X")\n'
        "    if ok\n"
        '        xs.add("extra")\n'
        '    stdio.println("len=${xs.length()}")\n'
    )

    # M01 without the @strict_ifc attribute: the default tier keeps
    # implicit flows out, so this must stay accepted with ZERO warnings
    # (a verdict-only assertion passes under the very mutation this
    # negative exists to catch).
    N02_DEFAULT_TIER = M01_SET_ADD.replace("@strict_ifc()\n", "")

    N03_TAINTED_NOT_SUNK = (
        "@strict_ifc()\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var xs: Set<String> = new_set()\n"
        '    xs.add("base")\n'
        '    let ok = env.allows("X")\n'
        "    if ok\n"
        '        xs.add("pub_extra")\n'
        '    let k = env.get("API_KEY").unwrap_or("none")\n'
        "    var ys: Set<String> = new_set()\n"
        '    if k.starts_with("s")\n'
        '        ys.add("sec_extra")\n'
        '    stdio.println("xs=${xs.length()}")\n'
    )

    N04_SCALAR_DEFAULT = (
        "fun main(env: Env, stdio: Stdio)\n"
        "    var x: Int = 0\n"
        '    let k = env.get("API_KEY").unwrap_or("none")\n'
        '    if k.starts_with("s")\n'
        "        x = 1\n"
        '    stdio.println("x=${x}")\n'
    )

    def test_public_condition_stays_accepted(self):
        _assert_accepted(self, self.N01_PUBLIC_COND, "public condition")

    def test_default_tier_stays_accepted_with_zero_warnings(self):
        r = check(self.N02_DEFAULT_TIER)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            [w.message for w in r.warnings], [],
            "the default tier must not gain ANY diagnostic from the "
            "strict-gated pc join; a warning here means the gate leaked",
        )

    def test_secret_tainted_but_unsunk_container_stays_accepted(self):
        _assert_accepted(self, self.N03_TAINTED_NOT_SUNK, "tainted, not sunk")

    def test_scalar_default_tier_stays_accepted(self):
        r = check(self.N04_SCALAR_DEFAULT)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            [w.message for w in r.warnings], [],
            "container/scalar consistency: the scalar default tier is "
            "warning-free, so the container one must be too",
        )


class TestClassificationGuardFailsClosed(unittest.TestCase):
    """T-GUARD: the completeness guard over the mutator classification.
    Its universe is DERIVED from the builtins registry (every
    non-capability owner in ``capa.builtins.METHODS``), never a
    hand-declared owner tuple, so a future mutable container type cannot
    land with its methods silently treated as non-mutators -- the
    direction that loses a rejection. A new METHOD on a mutable owner
    and a new OWNER must both turn the guard RED."""

    def test_real_table_is_a_complete_partition(self):
        from capa.analyzer._ifc_tables import (
            container_classification_defects,
        )
        self.assertEqual(
            container_classification_defects(), [],
            "every List / Set / Map method must be declared in exactly "
            "one of _CONTAINER_MUTATORS / _CONTAINER_NON_MUTATORS",
        )

    def test_the_partition_covers_the_measured_surface(self):
        from capa.analyzer._ifc_tables import _CONTAINER_NON_MUTATORS
        # 6 measured mutators, 35 declared non-mutators, 41 methods over
        # the three mutable owners: the by-construction enumeration of
        # the design, pinned so a silent shrink of either set is loud.
        self.assertEqual(len(_CONTAINER_MUTATORS), 6)
        self.assertEqual(len(_CONTAINER_NON_MUTATORS), 35)
        self.assertEqual(
            _CONTAINER_MUTATORS[("List", "pop")], frozenset(),
            "List.pop is the no-argument mutator: a member with an "
            "EMPTY taint-index set",
        )

    @staticmethod
    def _methods_plus(extra):
        """A copy of the real registry with synthetic methods added:
        ``extra`` maps owner -> [method names]."""
        from capa.builtins import METHODS
        sim = {owner: list(entries) for owner, entries in METHODS.items()}
        for owner, names in extra.items():
            sim[owner] = sim.get(owner, []) + [(n, None, []) for n in names]
        return sim

    def test_new_method_on_a_mutable_owner_goes_red(self):
        from capa.analyzer._ifc_tables import (
            container_classification_defects,
        )
        defects = container_classification_defects(
            self._methods_plus({"List": ["drain"]}),
        )
        self.assertTrue(
            any("List.drain" in d for d in defects),
            f"an unclassified new method must be a defect: {defects}",
        )

    def test_new_mutable_owner_goes_red(self):
        # The round-2 contest amendment: the guard was fail-closed
        # against a new method but fail-OPEN against a new OWNER when
        # its universe was a hand tuple. Derived from the registry, a
        # synthetic Deque's methods are unclassified and loud.
        from capa.analyzer._ifc_tables import (
            container_classification_defects,
        )
        defects = container_classification_defects(
            self._methods_plus({"Deque": ["push", "pop", "length"]}),
        )
        self.assertTrue(
            any("Deque.push" in d for d in defects),
            f"an unclassified new owner must be a defect: {defects}",
        )

    def test_double_classification_goes_red(self):
        from capa.analyzer import _ifc_tables
        saved = _ifc_tables._CONTAINER_NON_MUTATORS
        _ifc_tables._CONTAINER_NON_MUTATORS = saved | {("List", "push")}
        try:
            defects = _ifc_tables.container_classification_defects()
        finally:
            _ifc_tables._CONTAINER_NON_MUTATORS = saved
        self.assertTrue(
            any("List.push" in d for d in defects),
            f"a method in BOTH sets must be a defect: {defects}",
        )

    def test_entry_outside_the_mutable_universe_goes_red(self):
        from capa.analyzer import _ifc_tables
        saved = _ifc_tables._CONTAINER_NON_MUTATORS
        _ifc_tables._CONTAINER_NON_MUTATORS = saved | {("String", "trim")}
        try:
            defects = _ifc_tables.container_classification_defects()
        finally:
            _ifc_tables._CONTAINER_NON_MUTATORS = saved
        self.assertTrue(
            any("String" in d for d in defects),
            "an entry for an owner outside the mutable universe must be "
            f"a defect: {defects}",
        )


def _run_capa(argv, src):
    """Run ``python -m capa <argv> <file>`` on a temp file holding
    ``src``; return (returncode, stdout_bytes, stderr_bytes)."""
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "prog.capa")
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
        p = subprocess.run(
            [sys.executable, "-m", "capa", *argv, path],
            capture_output=True, timeout=180,
        )
    return p.returncode, p.stdout, p.stderr


class TestRefusalWiredThroughEveryRunMode(unittest.TestCase):
    """The CLI-wiring pin that replaced the near-vacuous reject-parity
    test: the analyzer refuses the leaking strict program BEFORE any
    backend is chosen, so every ``--run`` spelling exits 1. On main
    ``1dc0d27`` all three spellings ran the program (EXIT 0) with a
    measured secret-dependent output differential."""

    def test_run_refuses_m01_on_all_three_spellings(self):
        for argv in (["--run"], ["--run", "--ir"], ["--run", "--wasm"]):
            with self.subTest(argv=argv):
                rc, _out, err = _run_capa(argv, M01_SET_ADD)
                self.assertEqual(
                    rc, 1,
                    f"{argv}: expected the refusal exit, got {rc}; "
                    f"stderr={err[:300]!r}",
                )

    def test_run_refuses_the_pop_member(self):
        rc, _out, err = _run_capa(["--run"], M_POP)
        self.assertEqual(rc, 1, f"stderr={err[:300]!r}")


class TestManifestAgreesWithTheAnalyzer(unittest.TestCase):
    """T-C1', the fail-closed analyzer/manifest agreement: a strict
    program the analyzer refuses obtains NO capability manifest at all
    (exit 1, zero JSON bytes), where main ``1dc0d27`` certified the same
    program clean (exit 0, ``unaudited_secret_sinks = []``). The
    default-tier sibling keeps its clean manifest."""

    def test_strict_leaking_form_gets_no_manifest(self):
        rc, out, _err = _run_capa(["--manifest"], M01_SET_ADD)
        self.assertEqual(rc, 1)
        self.assertEqual(
            out, b"",
            "a refused program must not obtain an attestation",
        )

    def test_default_tier_form_keeps_its_clean_manifest(self):
        src = M01_SET_ADD.replace("@strict_ifc()\n", "")
        rc, out, _err = _run_capa(["--manifest"], src)
        self.assertEqual(rc, 0)
        manifest = json.loads(out)
        self.assertIsInstance(manifest, dict)


class TestRebindImprecisionPinned(unittest.TestCase):
    """The rebind false positive, pinned as ACCEPTED imprecision: the
    per-(binding, path) channel is keyed by root symbol and never
    cleared on a whole-container rebinding, so a container mutated under
    a secret pc and then REBOUND to a fresh value is still rejected.
    This is a consistent extension of a PRE-EXISTING behaviour, not a
    new one: the DATA direction warns on the identical rebind shape on
    main today. Clearing the channel on rebinding would have to land in
    BOTH directions at once or it creates an asymmetry; until then, both
    halves are pinned here."""

    REBIND_PC = (
        "@strict_ifc()\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var xs: Set<String> = new_set()\n"
        '    let k = env.get("API_KEY").unwrap_or("none")\n'
        '    if k.starts_with("s")\n'
        '        xs.add("extra")\n'
        "    xs = new_set()\n"
        '    xs.add("fresh")\n'
        '    stdio.println("len=${xs.length()}")\n'
    )

    REBIND_DATA = (
        "fun main(env: Env, stdio: Stdio)\n"
        "    var xs: Set<String> = new_set()\n"
        '    let k = env.get("API_KEY").unwrap_or("none")\n'
        "    xs.add(k)\n"
        "    xs = new_set()\n"
        '    xs.add("fresh")\n'
        '    stdio.println("len=${xs.length()}")\n'
    )

    def test_control_direction_rebind_is_rejected(self):
        _assert_rejected(self, self.REBIND_PC, "pc-direction rebind")

    def test_data_direction_rebind_warns_identically_on_main(self):
        r = check(self.REBIND_DATA)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_flow_warnings(r)), 1,
            "the data direction's rebind imprecision is the precedent "
            "the control direction extends; if this ever clears, clear "
            "both: " + str([w.message for w in r.warnings]),
        )


class TestFunValueResidualPinned(unittest.TestCase):
    """The Fun-value residual, DISCLOSED and PINNED: a container
    mutation (or a sink call) reached through a Fun VALUE that was
    defined under a public pc and invoked under a secret one is not
    tracked -- the same first-class-function residual family already
    disclosed for the sink direction (SECURITY.md, closure residuals).
    A documented false NEGATIVE, never a false positive. These pins
    convert to RED-first tests the day the Fun-value increment (Sibling
    C of the design) lands; until then they make the boundary impossible
    to move silently."""

    FACES = {
        "let-bound Fun": (
            "@strict_ifc()\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var xs: Set<String> = new_set()\n"
            '    xs.add("base")\n'
            '    let f = fun () => xs.add("extra")\n'
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    if k.starts_with("s")\n'
            "        f()\n"
            '    stdio.println("len=${xs.length()}")\n'
        ),
        "sink sibling": (
            "@strict_ifc()\n"
            "fun main(env: Env, stdio: Stdio)\n"
            '    let f = fun () => stdio.println("hi")\n'
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    if k.starts_with("s")\n'
            "        f()\n"
        ),
        "Fun passed to a HOF": (
            "fun apply(g: Fun() -> Unit)\n"
            "    g()\n"
            "\n"
            "@strict_ifc()\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var xs: Set<String> = new_set()\n"
            '    xs.add("base")\n'
            '    let f = fun () => xs.add("extra")\n'
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    if k.starts_with("s")\n'
            "        apply(f)\n"
            '    stdio.println("len=${xs.length()}")\n'
        ),
        "Fun returned from a function": (
            "fun make(xs: Set<String>) -> Fun() -> Unit\n"
            '    return fun () => xs.add("extra")\n'
            "\n"
            "@strict_ifc()\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var xs: Set<String> = new_set()\n"
            '    xs.add("base")\n'
            "    let f = make(xs)\n"
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    if k.starts_with("s")\n'
            "        f()\n"
            '    stdio.println("len=${xs.length()}")\n'
        ),
        "Fun stored in a struct": (
            "type Holder {\n"
            "    act: Fun() -> Unit\n"
            "}\n"
            "\n"
            "@strict_ifc()\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var xs: Set<String> = new_set()\n"
            '    xs.add("base")\n'
            '    let h = Holder(act: fun () => xs.add("extra"))\n'
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    if k.starts_with("s")\n'
            "        h.act()\n"
            '    stdio.println("len=${xs.length()}")\n'
        ),
        "Fun stored in a list": (
            "@strict_ifc()\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var xs: Set<String> = new_set()\n"
            '    xs.add("base")\n'
            "    var fs: List<Fun() -> Unit> = []\n"
            '    fs.push(fun () => xs.add("extra"))\n'
            "    var seen: Int = 0\n"
            '    let k = env.get("API_KEY").unwrap_or("none")\n'
            '    if k.starts_with("s")\n'
            "        match fs.get(0)\n"
            "            Some(g) -> g()\n"
            "            None -> seen = 1\n"
            '    stdio.println("len=${xs.length()}")\n'
        ),
    }

    def test_fun_value_faces_are_currently_unflagged(self):
        for what, src in self.FACES.items():
            with self.subTest(face=what):
                r = check(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(
                    _flow_errors(r), [],
                    f"{what}: this residual pin records a KNOWN, "
                    "disclosed false negative; if it now errors, the "
                    "Fun-value increment landed and this converts to a "
                    "member test: "
                    + str([e.message for e in r.errors]),
                )


class TestTerminationResidualPinned(unittest.TestCase):
    """The read gate's termination-channel residual, pinned at class
    level: the channel this fix seeds bites only when a read of the
    mutated state can REACH A SINK. A strict-accepted program whose
    only secret-dependent consequence is whether it ABORTS (a trap on a
    read of the unmutated shape) stays accepted, so a strict function's
    termination behaviour / exit status is outside the read gate's
    guarantee -- the same pre-existing strict-tier trap residual the
    panic rule covers for exactly one spelling. Converts to RED-first
    the day an abort-effect design lands."""

    TRAP_SHAPE = (
        "@strict_ifc()\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var xs: List<Int> = []\n"
        '    let k = env.get("API_KEY").unwrap_or("none")\n'
        '    if k.starts_with("s")\n'
        "        xs.push(1)\n"
        "    let v = xs.get(0).unwrap()\n"
        '    stdio.println("done")\n'
    )

    def test_trap_only_consequence_stays_accepted(self):
        r = check(self.TRAP_SHAPE)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            _flow_errors(r), [],
            "this pin records the termination-channel residual; a "
            "rejection here means the read gate's guarantee changed: "
            + str([e.message for e in r.errors]),
        )


if __name__ == "__main__":
    unittest.main()
