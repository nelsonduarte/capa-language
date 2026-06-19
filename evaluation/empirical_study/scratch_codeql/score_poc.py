"""Score the CodeQL T2b proof-of-concept against the ground truth.

Reads ground_truth.csv (the study's authored (python_function,
capability, how) facts) and codeql_facts.csv (this PoC's CodeQL output)
and reports, per pair and per fact, whether CodeQL caught it, broken
down by the `how` indirection class.
"""
import csv
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve().parent
STUDY = HERE.parent

POC_PAIRS = {
    "config_loader", "http_retry", "session_token", "log_forwarder",
    "command_registry", "event_bus", "reflect_dispatch", "tagged_factory",
    "middleware_chain",
}

# ground truth: (pair, python_function, capability) -> how
gt = {}
with (STUDY / "ground_truth.csv").open() as f:
    for r in csv.DictReader(f):
        if r["pair"] in POC_PAIRS:
            gt[(r["pair"], r["python_function"], r["capability"])] = r["how"]

# codeql facts
cq = set()
with (HERE / "codeql_facts.csv").open() as f:
    for r in csv.DictReader(f):
        cq.add((r["pair"], r["python_function"], r["capability"]))

# Per-fact verdict
rows = []
for (pair, fn, cap), how in sorted(gt.items()):
    caught = (pair, fn, cap) in cq
    rows.append((pair, fn, cap, how, caught))

# Any CodeQL fact NOT in ground truth (over-attribution / false positive)?
extra = sorted(cq - set(gt.keys()))

print("=== PER-FACT VERDICT (ground-truth facts, 9 PoC pairs) ===")
print(f"{'pair':<17}{'function':<18}{'cap':<7}{'how':<13}{'codeql'}")
for pair, fn, cap, how, caught in rows:
    print(f"{pair:<17}{fn:<18}{cap:<7}{how:<13}{'CAUGHT' if caught else 'MISSED'}")

# Aggregate by how
byhow = defaultdict(lambda: [0, 0])  # how -> [caught, total]
for _, _, _, how, caught in rows:
    byhow[how][1] += 1
    if caught:
        byhow[how][0] += 1

print("\n=== RECALL BY INDIRECTION CLASS (CodeQL T2b) ===")
for how in ["direct", "via-helper", "via-dispatch", "via-data"]:
    c, t = byhow.get(how, [0, 0])
    if t:
        print(f"  {how:<14}: {c}/{t} caught")

tot_c = sum(v[0] for v in byhow.values())
tot_t = sum(v[1] for v in byhow.values())
print(f"  {'TOTAL':<14}: {tot_c}/{tot_t} caught")

print("\n=== CodeQL facts NOT in ground truth (over-attribution check) ===")
if extra:
    for e in extra:
        print(f"  EXTRA: {e}")
else:
    print("  (none) -- CodeQL never attributes a capability the ground "
          "truth does not list; no over-approximation / false positive.")
