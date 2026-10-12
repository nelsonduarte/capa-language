"""The known-outcome register: ONE mechanism for every instrument.

An ENTRY is keyed ``<instrument>|<member>|<leg>`` where the member is
``<file name>#<sha16 of the program text, LF-normalised>``: a regenerated
or edited program cannot inherit an entry, and the gate reads the hash
(a member with the same name and a different hash is REGENERATED, never
matched by name). The value is the registered OUTCOME (``_outcome``), a
one-line reason and the programme step expected to close it; a stdlib
entry also carries the per-leg vectors it was seeded from, and the gate
checks that the outcome is their key.

The DIFF of a run against the register classifies every delta:

  FIXED        registered WRONG, observed CORRECT    (remove the entry, with its reason)
  CHANGED      registered WRONG:a, observed WRONG:b  (a different wrong answer)
  NEW          unregistered, observed WRONG
  REGRESSION   observed REFUSED / TIMEOUT / BROKEN / VOID that is not registered as exactly that
               (never reported as fixed: the instrument stopped looking)
  STALE        registered member absent from the run
  REGENERATED  registered file present with a different program hash

GREEN only when every class is empty. Legs the run did not execute are
not judged.

The RATCHET (shrink-only) is set inclusion against the BASE register:
every entry of the candidate must be present, with the same outcome, in
the base. An added or re-described entry is RED whatever the counts say,
with two declared exceptions that the entry itself must carry:
``accepted_as: REVEAL`` (a BROKEN member that became WRONG once its gap
closed; the entry names the outcome it came from) and ``accepted_as:
REGENERATED`` (the same file, leg and outcome under a new program hash;
the entry names the base key it replaces). The first landing has no base
and is a BOOTSTRAP, said so explicitly.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tests.instruments._outcome import (
    BROKEN, CORRECT, NOT_RUN, WRONG, is_valid, key, outcome_type, wrong,
)
from tests.instruments._private import private_path
from tests.instruments._provenance import REPO_ROOT

FORMAT = 1
PUBLIC_REGISTER = REPO_ROOT / "tests" / "instrument_register.json"
PRIVATE_REGISTER_NAME = "instrument_register.json"

ACCEPTED_KINDS = ("REVEAL", "REGENERATED")


def program_hash(text: str) -> str:
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()[:16]


def member_id(name: str, text: str) -> str:
    return "%s#%s" % (name, program_hash(text))


def split_member(mid: str) -> tuple:
    name, _sep, h = mid.rpartition("#")
    return name, h


def entry_key(instrument: str, mid: str, leg: str) -> str:
    return "%s|%s|%s" % (instrument, mid, leg)


def split_key(k: str) -> tuple:
    instrument, mid, leg = k.split("|")
    return instrument, mid, leg


def composite_vector(vectors: dict) -> list:
    """One vector over several legs' vectors (the stdlib entries pin every
    leg): ``["<leg>=<key of that leg's vector>", ...]`` in leg order."""
    return ["%s=%s" % (leg, key(vectors[leg])) for leg in sorted(vectors)]


def validate(entries: dict, origin: str = "register") -> None:
    for k, e in entries.items():
        split_key(k)
        if not is_valid(e.get("outcome", "")):
            raise ValueError("%s: entry %s has an invalid outcome %r" % (origin, k, e.get("outcome")))
        if outcome_type(e["outcome"]) == CORRECT:
            raise ValueError("%s: entry %s registers CORRECT; only defects are registered" % (origin, k))
        if "vectors" in e and e["outcome"] != wrong(composite_vector(e["vectors"])):
            raise ValueError("%s: entry %s: the outcome is not the key of its vectors" % (origin, k))
        if "accepted_as" in e and e["accepted_as"] not in ACCEPTED_KINDS:
            raise ValueError("%s: entry %s: unknown accepted_as %r" % (origin, k, e["accepted_as"]))


def load(path) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("format") != FORMAT:
        raise ValueError("%s: unknown register format %r" % (path, doc.get("format")))
    entries = doc["entries"]
    validate(entries, str(path))
    return entries


def save(path, entries: dict) -> None:
    validate(entries, str(path))
    doc = {"format": FORMAT, "entries": {k: entries[k] for k in sorted(entries)}}
    Path(path).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_merged(public_path=PUBLIC_REGISTER) -> dict:
    """The public register plus the private one when present. A key in
    both is an error: one entry per member and leg."""
    entries = dict(load(public_path)) if Path(public_path).exists() else {}
    priv = private_path(PRIVATE_REGISTER_NAME)
    if priv is not None:
        for k, e in load(priv).items():
            if k in entries:
                raise ValueError("register entry %s is in both the public and the private register" % k)
            entries[k] = e
    return entries


def members(entries: dict, instrument: str) -> list:
    """Sorted file names registered under ``instrument``."""
    return sorted({split_member(split_key(k)[1])[0] for k in entries if split_key(k)[0] == instrument})


def seed(instrument: str, outcomes: dict, reason: str, closes_in: str, vectors: Optional[dict] = None) -> dict:
    """Entries for every non-CORRECT outcome of a run. ``outcomes`` maps
    ``(member_id, leg)`` to an outcome."""
    out = {}
    for (mid, leg), o in sorted(outcomes.items()):
        if o == CORRECT:
            continue
        e = {"outcome": o, "reason": reason, "closes_in": closes_in}
        if vectors and (mid, leg) in vectors:
            e["vectors"] = vectors[(mid, leg)]
        out[entry_key(instrument, mid, leg)] = e
    return out


@dataclass
class Diff:
    fixed: list = field(default_factory=list)
    changed: list = field(default_factory=list)
    new: list = field(default_factory=list)
    regression: list = field(default_factory=list)
    stale: list = field(default_factory=list)
    regenerated: list = field(default_factory=list)

    @property
    def green(self) -> bool:
        return not any(self.classes().values())

    def classes(self) -> dict:
        return {"FIXED": self.fixed, "CHANGED": self.changed, "NEW": self.new,
                "REGRESSION": self.regression, "STALE": self.stale, "REGENERATED": self.regenerated}

    def counts(self) -> dict:
        return {k: len(v) for k, v in self.classes().items()}

    def report(self, limit: int = 12) -> str:
        lines = ["%s %s" % ("GREEN" if self.green else "RED", self.counts())]
        for name, items in self.classes().items():
            for item in items[:limit]:
                lines.append("  %s %s" % (name, item))
            if len(items) > limit:
                lines.append("  %s ... %d more" % (name, len(items) - limit))
        return "\n".join(lines)


def diff(entries: dict, instrument: str, outcomes: dict, legs_run) -> Diff:
    """Classify a run's ``{(member_id, leg): outcome}`` against the
    register's entries for ``instrument`` over the legs that ran."""
    legs_run = set(legs_run)
    d = Diff()
    observed = {}
    for (mid, leg), o in outcomes.items():
        name, h = split_member(mid)
        observed[(name, leg)] = (h, o)
    registered = set()
    for k, e in entries.items():
        inst, mid, leg = split_key(k)
        if inst != instrument or leg not in legs_run:
            continue
        name, h = split_member(mid)
        registered.add((name, h, leg))
        obs = observed.get((name, leg))
        if obs is None:
            d.stale.append(k)
            continue
        oh, o = obs
        if oh != h:
            d.regenerated.append((k, "now " + oh))
            continue
        if o == e["outcome"]:
            continue
        if outcome_type(o) in NOT_RUN:
            d.regression.append((k, e["outcome"], o))
        elif o == CORRECT:
            d.fixed.append(k)
        else:
            d.changed.append((k, e["outcome"], o))
    for (name, leg), (h, o) in sorted(observed.items()):
        if leg not in legs_run or o == CORRECT or (name, h, leg) in registered:
            continue
        k = entry_key(instrument, "%s#%s" % (name, h), leg)
        if outcome_type(o) in NOT_RUN:
            d.regression.append((k, "unregistered", o))
        else:
            d.new.append((k, o))
    return d


@dataclass
class Ratchet:
    bootstrap: bool = False
    added: list = field(default_factory=list)
    redescribed: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    accepted: list = field(default_factory=list)

    @property
    def green(self) -> bool:
        return not (self.added or self.redescribed)

    def report(self) -> str:
        if self.bootstrap:
            return "BOOTSTRAP: no base register; the candidate (%d entries) is the first" % len(self.accepted)
        lines = ["%s added=%d re-described=%d removed=%d accepted=%d" % (
            "GREEN" if self.green else "RED", len(self.added), len(self.redescribed),
            len(self.removed), len(self.accepted))]
        for k in self.added[:12]:
            lines.append("  ADDED %s" % k)
        for k in self.redescribed[:12]:
            lines.append("  RE-DESCRIBED %s" % (k,))
        for k in self.accepted[:12]:
            lines.append("  accepted %s" % (k,))
        return "\n".join(lines)


def _accepted(k: str, e: dict, base: dict) -> bool:
    kind = e.get("accepted_as")
    if not kind or not e.get("reason"):
        return False
    if kind == "REVEAL":
        b = base.get(k)
        return (b is not None and outcome_type(b["outcome"]) == BROKEN
                and outcome_type(e["outcome"]) == WRONG
                and e.get("from_outcome") == b["outcome"])
    if kind == "REGENERATED":
        src = e.get("from_member")
        b = base.get(src) if src else None
        if b is None:
            return False
        inst_a, mid_a, leg_a = split_key(src)
        inst_b, mid_b, leg_b = split_key(k)
        return (inst_a == inst_b and leg_a == leg_b and b["outcome"] == e["outcome"]
                and split_member(mid_a)[0] == split_member(mid_b)[0])
    return False


def ratchet(base: Optional[dict], cand: dict) -> Ratchet:
    r = Ratchet()
    if base is None:
        r.bootstrap = True
        r.accepted = sorted(cand)
        return r
    for k in sorted(cand):
        if k not in base:
            (r.accepted if _accepted(k, cand[k], base) else r.added).append(k)
        elif cand[k]["outcome"] != base[k]["outcome"]:
            item = (k, base[k]["outcome"], cand[k]["outcome"])
            (r.accepted if _accepted(k, cand[k], base) else r.redescribed).append(item)
    r.removed = sorted(k for k in base if k not in cand)
    return r
