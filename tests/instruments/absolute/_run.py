"""One run of instrument (a): the corpora, the legs, the outcomes.

The public configuration is the public kinds, corpora and anchors; a
private extension (``_private.load_module("absolute_kinds")``) may add
kinds, corpora, anchors and evaluator mutants. Whatever is loaded, the
public corpora are generated over the public kinds alone, so their
programs and register entries are the same in both configurations.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tests.instruments._outcome import ACCEPT, check_outcome, run_outcome
from tests.instruments._private import load_module
from tests.instruments._register import member_id
from tests.instruments._runner import CLI_LEGS, run_legs
from tests.instruments.absolute import _anchors as AN, _kinds as K
from tests.instruments.absolute._gen import Gen
from tests.instruments.absolute._corpus import (
    PUBLIC_CORPORA, expectation, source_text, write_anchor_programs, write_corpus,
)

INSTRUMENT = "absolute"
PUBLIC_LEGS = ("check", "ir")
PUBLIC_WASM_LEGS = ("wasm",)
PUBLIC_CLI_LEGS = ("cli_ir",)
#: How many programs of each generated corpus join the route sample.
CLI_SAMPLE_PER_CORPUS = 10


def route_sample(programs: list) -> list:
    """The programs the command-line legs run: every anchor (the clauses,
    one shape each) plus the first few of each generated corpus. A sample
    of the first N files of one corpus would miss a routing defect confined
    to a shape they happen not to contain."""
    anchors = [p for p in programs if p.name.startswith("anchor_")]
    by_corpus: dict = {}
    for p in programs:
        if not p.name.startswith("anchor_"):
            by_corpus.setdefault(p.name.rsplit("_", 1)[0], []).append(p)
    out = list(anchors)
    for progs in by_corpus.values():
        out += progs[:CLI_SAMPLE_PER_CORPUS]
    return out


@dataclass
class Configuration:
    kinds: dict
    anchors: list
    corpora: list
    extension_corpora: list = field(default_factory=list)
    mutants: dict = field(default_factory=dict)
    #: Legs the extension adds to every run (in-process and command line).
    legs: tuple = ()
    cli_legs: tuple = ()
    private: bool = False


def anchors_for(g: Gen) -> list:
    """The anchors built from THIS generator's builders (public, plus the
    extension's when loaded), so a mutant installed on ``g`` is what the
    anchors evaluate."""
    out = AN.anchors(g)
    ext = load_module("absolute_kinds")
    if ext is not None:
        out += ext.anchors(g)
    return out


def configuration() -> Configuration:
    ext = load_module("absolute_kinds")
    kinds = dict(K.PUBLIC_KINDS) if ext is None else ext.extend(dict(K.PUBLIC_KINDS))
    g = Gen(random.Random(0), kinds)
    cfg = Configuration(kinds, anchors_for(g), list(PUBLIC_CORPORA))
    if ext is not None:
        cfg.extension_corpora = list(ext.CORPORA)
        cfg.mutants = dict(ext.MUTANTS)
        cfg.legs = tuple(ext.LEGS)
        cfg.cli_legs = tuple(ext.CLI_LEGS)
        cfg.private = True
    return cfg


@dataclass
class Run:
    programs: list
    rows: dict
    outcomes: dict
    legs: tuple


def generate(cfg: Configuration, workdir) -> list:
    """Every program of the configuration: the public corpora over the
    public kinds, the extension corpora over the extended kinds, and the
    anchor programs with their hand-written expectations."""
    workdir = Path(workdir)
    programs = []
    for spec in cfg.corpora:
        programs += write_corpus(workdir / spec.name, spec, K.PUBLIC_KINDS, cfg.anchors)
    for spec in cfg.extension_corpora:
        programs += write_corpus(workdir / spec.name, spec, cfg.kinds, cfg.anchors)
    programs += write_anchor_programs(workdir / "anchors", cfg.anchors)
    return programs


def run(tree, programs: list, legs, workdir, cli_programs: Optional[list] = None) -> Run:
    """``cli_programs`` defaults to the route sample."""
    if cli_programs is None:
        cli_programs = route_sample(programs)
    rows = run_legs(tree, legs, programs, workdir=workdir, cli_programs=cli_programs)
    # Outcomes are register members: the in-process legs only. The command-line
    # legs are judged by the route-agreement check over their rows.
    outcomes = {}
    for p in programs:
        exp = expectation(p)
        mid = member_id(p.name, source_text(p))
        for leg in legs:
            if leg in CLI_LEGS:
                continue
            row = rows.get((p.name, leg))
            if row is None:
                outcomes[(mid, leg)] = "BROKEN"
            elif leg == "check":
                outcomes[(mid, leg)] = check_outcome(ACCEPT, row)
            else:
                outcomes[(mid, leg)] = run_outcome(exp, row)
    return Run(programs, rows, outcomes, tuple(legs))
