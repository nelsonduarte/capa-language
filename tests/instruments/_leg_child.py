"""One leg, one process: the child the bounded runner drives.

usage: python -I -X utf8 _leg_child.py <tree> <leg> <listfile>

``leg`` is ``check``, ``run`` (legacy transpiler), ``ir`` (CIR Python
emitter), ``wasm`` or ``manifest``. ``listfile`` names one program per
line as ``<name>\\t<path>\\t<working directory>`` (the directory may be
empty); the name is the identity the parent gave the program and is
echoed back as ``file``.
Prints JSON lines on stdout, in order:

  {"prov": capa.__file__, "hash": <whole-package hash COMPUTED HERE>}
  {"start": <file>}                                   before each program
  one result record per program:
    {"file", "leg", "phase": "check", "ok", "ifc_errors", "ifc_warnings", "errors"}
    {"file", "leg", "phase": "refused", "errors"}       the checker refused it
    {"file", "leg", "phase": "compile", "exc", "msg"}   raised before it ran
    {"file", "leg", "phase": "run", "exit_class", "stdout", "stderr", "exc_msg"}

The in-process leg bodies are the parity harness's own runners
(``tests.test_ir_wasm_parity._run_python`` / ``_run_cir`` / ``_run_wasm``),
imported, so "run on backend X" has one definition. A compile-phase
exception is told from a program abort by where it was raised: a program
ran only if a frame of the executed program (a code object compiled from a
string) or of the runtime package is on the traceback.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
import traceback


def _main() -> None:
    tree, leg, listfile = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3]
    sys.path.insert(0, tree)
    from tests.instruments._provenance import package_hash, use_tree
    from tests.instruments._outcome import exit_class_from_exception
    prov_file = use_tree(tree)
    sys.stdout.reconfigure(encoding="utf-8")
    h, n = package_hash(tree)
    print(json.dumps({"prov": prov_file, "hash": h, "files": n}), flush=True)

    from tests.implicit_flow._harness import check_source, ifc_errors, ifc_warnings
    from tests.instruments.release_differential import manifest_of_source
    from tests.test_ir_wasm_parity import _run_cir, _run_python, _run_wasm
    thunks = {"run": _run_python, "ir": _run_cir, "wasm": _run_wasm}

    def program_ran(exc) -> bool:
        if isinstance(exc, ImportError):
            return False
        runtime_dir = os.path.join(tree, "capa", "runtime") + os.sep
        for frame, _lineno in traceback.walk_tb(exc.__traceback__):
            fn = frame.f_code.co_filename
            if fn.startswith("<") and not fn.startswith("<frozen"):
                return True
            if os.path.abspath(fn).startswith(runtime_dir):
                return True
        return False

    for line in open(listfile, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line:
            continue
        name, path, cwd = line.split("\t")
        print(json.dumps({"start": name}), flush=True)
        t0 = time.perf_counter()
        try:
            src = open(path, encoding="utf-8").read()
            res = check_source(src)
        except BaseException as e:  # a parse failure is a refusal of the program
            print(json.dumps({"file": name, "leg": leg, "phase": "refused",
                              "errors": ["%s: %s" % (type(e).__name__, str(e)[:300])],
                              "s": time.perf_counter() - t0}), flush=True)
            continue
        errors = [x.message for x in res.errors]
        if leg == "check":
            print(json.dumps({"file": name, "leg": leg, "phase": "check", "ok": res.ok,
                              "n_errors": len(errors), "n_warnings": len(res.warnings),
                              "ifc_errors": len(ifc_errors(res)), "ifc_warnings": len(ifc_warnings(res)),
                              "errors": errors[:5], "s": time.perf_counter() - t0}), flush=True)
            continue
        if not res.ok:
            print(json.dumps({"file": name, "leg": leg, "phase": "refused", "errors": errors[:5],
                              "s": time.perf_counter() - t0}), flush=True)
            continue
        if leg == "manifest":
            try:
                doc = json.dumps(manifest_of_source(src, name), default=str, sort_keys=True)
            except BaseException as e:
                print(json.dumps({"file": name, "leg": leg, "phase": "compile", "exc": type(e).__name__,
                                  "msg": str(e)[:300], "s": time.perf_counter() - t0}), flush=True)
                continue
            print(json.dumps({"file": name, "leg": leg, "phase": "run", "exit_class": "OK",
                              "stdout": doc, "stderr": "", "exc_msg": "",
                              "s": time.perf_counter() - t0}), flush=True)
            continue
        out, err = io.StringIO(), io.StringIO()
        saved_out, saved_err, saved_cwd = sys.stdout, sys.stderr, os.getcwd()
        exc = None
        if cwd:
            os.chdir(cwd)
        sys.stdout, sys.stderr = out, err
        try:
            thunks[leg](src)
        except BaseException as e:
            exc = e
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err
            os.chdir(saved_cwd)
        if exc is not None and not program_ran(exc):
            print(json.dumps({"file": name, "leg": leg, "phase": "compile", "exc": type(exc).__name__,
                              "msg": str(exc)[:300], "s": time.perf_counter() - t0}), flush=True)
            continue
        print(json.dumps({"file": name, "leg": leg, "phase": "run",
                          "exit_class": exit_class_from_exception(exc),
                          "stdout": out.getvalue(), "stderr": err.getvalue(),
                          "exc_msg": str(exc)[:300] if exc is not None else "",
                          "s": time.perf_counter() - t0}), flush=True)


if __name__ == "__main__":
    _main()
