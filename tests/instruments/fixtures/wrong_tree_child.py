"""A child that computes the right hash but imported ``capa`` from
somewhere else (its provenance line names a file outside the tree). The
runner must VOID every row of such a child."""

import json
import os
import sys

tree = os.path.abspath(sys.argv[1])
sys.path.insert(0, tree)
from tests.instruments._provenance import package_hash  # noqa: E402

elsewhere = os.path.join(os.path.dirname(tree), "elsewhere", "capa", "__init__.py")
print(json.dumps({"prov": elsewhere, "hash": package_hash(tree)[0], "files": 0}), flush=True)
for line in open(sys.argv[3], encoding="utf-8"):
    if line.strip():
        name = line.split("\t")[0]
        print(json.dumps({"start": name}), flush=True)
        print(json.dumps({"file": name, "leg": sys.argv[2], "phase": "run", "exit_class": "OK",
                          "stdout": "", "stderr": "", "exc_msg": "", "s": 0.0}), flush=True)
