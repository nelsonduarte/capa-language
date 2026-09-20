"""Shared harness for the implicit-flow test package.

Every verdict here is produced in-process by ``capa.analyze`` on a program
read from ``tests/implicit_flow/fixtures/<class>/<name>.capa`` (or built by
the generator in ``_generated``), under the scorer's PRECONDITIONS, which
are asserted rather than reported:

- the compiler under test is the one this test tree belongs to
  (``capa.__file__`` resolves inside the repository that holds this file);
- a table of expectations is never empty;
- every program named by a table exists and parses;
- a program expected REFUSED carries at least one error, and in an IFC
  table every one of its errors is an information-flow diagnostic (a parse,
  type or shadowing error counted as a refusal would void the verdict);
- a program expected ACCEPTED has no errors.

A table that fails a precondition fails the test that owns it, so an empty
table or a mis-provenanced compiler cannot print a pass.
"""

from __future__ import annotations

import pathlib
import re

import capa
from capa import AnalysisResult, Lexer, Parser, analyze

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

REFUSE = "REFUSE"
ACCEPT = "ACCEPT"

#: An error is IFC-class when its message names the discipline. The strict
#: sink rule, the constant-time rule and the cross-function summary rule all
#: spell it one of these ways.
_IFC_ERROR = re.compile(
    r"information-flow|@secret|constant-time violation|secret control flow",
    re.I,
)

#: The VALUE half of the discipline: a secret VALUE reaching a public sink,
#: as opposed to the sink merely running under secret control flow. The two
#: are reported separately, and a rule that raises a label without raising
#: the pc (or the reverse) drops exactly one of them, so a pin that needs
#: to see the label move counts these rather than all the errors.
_VALUE_ERROR = re.compile(r"a @secret value reaches")


def provenance_ok() -> bool:
    """True when the imported ``capa`` is the package of THIS repository."""
    return pathlib.Path(capa.__file__).resolve().is_relative_to(REPO)


def check_source(source: str) -> AnalysisResult:
    tokens = Lexer(source).lex()
    module = Parser(tokens, source=source).parse_module()
    return analyze(module, source=source)


def fixture_path(group: str, name: str) -> pathlib.Path:
    return FIXTURES / group / f"{name}.capa"


def read_fixture(group: str, name: str) -> str:
    path = fixture_path(group, name)
    if not path.is_file():
        raise AssertionError(f"missing fixture {group}/{name}.capa")
    return path.read_text(encoding="utf-8")


def check_fixture(group: str, name: str) -> AnalysisResult:
    return check_source(read_fixture(group, name))


def ifc_errors(result: AnalysisResult) -> list:
    return [e for e in result.errors if _IFC_ERROR.search(e.message)]


def other_errors(result: AnalysisResult) -> list:
    return [e for e in result.errors if not _IFC_ERROR.search(e.message)]


def value_errors(result: AnalysisResult) -> list:
    """The errors reporting a secret VALUE at a public sink."""
    return [e for e in result.errors if _VALUE_ERROR.search(e.message)]


def assert_verdict(tc, name: str, result: AnalysisResult, want: str,
                   ifc_only: bool = True) -> None:
    """Assert the verdict of one program under the preconditions."""
    got = ACCEPT if result.ok else REFUSE
    messages = [e.message for e in result.errors]
    if want == REFUSE and ifc_only:
        tc.assertEqual(
            other_errors(result), [],
            f"{name}: a refusal must carry only information-flow errors, "
            f"got {messages}",
        )
    tc.assertEqual(got, want, f"{name}: expected {want}, got {got}: {messages}")


def assert_table(tc, group: str, table: dict, ifc_only: bool = True) -> None:
    """Assert every (name -> verdict) row of a fixture table."""
    tc.assertTrue(provenance_ok(), f"wrong compiler under test: {capa.__file__}")
    tc.assertTrue(table, f"{group}: empty expectation table")
    for name, want in table.items():
        with tc.subTest(program=name):
            assert_verdict(tc, name, check_fixture(group, name), want, ifc_only)
