"""A child that reports a fixed package hash instead of computing it.
The runner must VOID every row of such a child (the provenance control)."""

import json
import os
import sys

tree = os.path.abspath(sys.argv[1])
sys.path.insert(0, tree)
from tests.instruments._provenance import use_tree  # noqa: E402

f = use_tree(tree)
print(json.dumps({"prov": f, "hash": "0000feedface0000", "files": 0}), flush=True)
for line in open(sys.argv[3], encoding="utf-8"):
    if line.strip():
        name = line.split("\t")[0]
        print(json.dumps({"start": name}), flush=True)
        print(json.dumps({"file": name, "leg": sys.argv[2], "phase": "run", "exit_class": "OK",
                          "stdout": "", "stderr": "", "exc_msg": "", "s": 0.0}), flush=True)
