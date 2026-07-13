"""Feature #4 hardening: the RESULT-SIZE CAP on the typed foreign-component
sandbox -- the last DoS axis of the foreign resource ceiling.

The fuel / memory caps bound the untrusted CHILD store. They do NOT bound
the HOST-side buffer a granted, host-mediated ``capa:host/<cap>`` closure
allocates: ``fs.read`` materialises the whole file, ``net.get`` /
``net.post`` the whole response body, ``db.query`` the whole result set --
all in the HOST Python process, charging ~no child fuel. So an untrusted
child could OOM the host by asking it to read a multi-GiB result regardless
of ``--foreign-memory-cap``. ``--foreign-result-cap`` bounds that host-side
buffer: a read that would exceed it aborts EARLY (peak host allocation
stays ~cap, never the whole result) and surfaces as
:class:`ForeignResourceExceeded` (a clean exit-1 diagnostic).

Coverage:

- ``Net.get`` / ``Net.post`` ``max_bytes`` unit-tested directly against a
  local ``http.server`` (over-cap raises, under-cap and ``None`` return the
  full body) -- proves the NORMAL (unbounded) path is unchanged.
- ``fs.read`` over / under cap end to end through the CLI, proving the host
  aborts before buffering a large file (a distinctive tail never appears).
- ``db.query`` and ``net.get`` over / under / opt-out through
  ``dispatch_foreign_call`` with the new ``db_query_child.wasm`` /
  ``net_get_child.wasm`` fixtures.
- flag semantics (``0`` opts out, negative rejected, default applies).
"""

from __future__ import annotations

import io
import os
import sqlite3
import sys
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from capa.cli import _wasm_tooling_available, main
from capa.runtime._capabilities import Net, ResultCapExceeded
from capa.runtime._foreign import (
    DEFAULT_FOREIGN_RESULT_CAP_BYTES,
    ForeignResourceExceeded,
    _read_text_capped,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "foreign"


def _run_cli(argv, cwd):
    out, err = io.StringIO(), io.StringIO()
    patches = [
        mock.patch.object(sys, "argv", ["capa"] + list(argv)),
        mock.patch.object(sys, "stdout", out),
        mock.patch.object(sys, "stderr", err),
    ]
    original = os.getcwd()
    try:
        os.chdir(str(cwd))
        for p in patches:
            p.start()
        try:
            rc = main()
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        return rc, out.getvalue(), err.getvalue()
    finally:
        for p in reversed(patches):
            p.stop()
        os.chdir(original)


def _write(td: str, name: str, source: str) -> Path:
    p = Path(td) / name
    p.write_text(source, encoding="utf-8")
    return p


class _BodyServer:
    """A throwaway local HTTP server that answers every GET / POST with a
    fixed-size body. Used to exercise ``Net.get`` / ``Net.post`` bounded
    reads without touching the real network."""

    def __init__(self, nbytes: int):
        body = b"B" * nbytes

        class H(BaseHTTPRequestHandler):
            def _respond(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._respond()

            def do_POST(self):
                # Drain the request body so the socket closes cleanly.
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)
                self._respond()

            def log_message(self, *a):
                pass

        self._srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/" % self._srv.server_address[1]

    def __enter__(self):
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()


# ---- unit: the bounded text-read helper ------------------------------


class TestReadTextCappedUnit(unittest.TestCase):
    def _read(self, text: str, cap):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.txt"
            p.write_text(text, encoding="utf-8")
            with open(p, encoding="utf-8") as f:
                return _read_text_capped(f, cap, "Fs.read")

    def test_exactly_cap_allowed(self):
        # A stream of EXACTLY cap bytes is allowed (boundary is inclusive).
        self.assertEqual(self._read("x" * 100, 100), "x" * 100)

    def test_one_over_cap_raises(self):
        with self.assertRaises(ForeignResourceExceeded) as cm:
            self._read("x" * 101, 100)
        self.assertIn("result cap", str(cm.exception))
        self.assertIn("100 bytes", str(cm.exception))

    def test_under_cap_returns_full(self):
        self.assertEqual(self._read("hello", 1_000_000), "hello")

    def test_multibyte_counted_in_bytes_not_chars(self):
        # A 3-char string of 3-byte chars is 9 bytes: under a 9-byte cap it
        # passes, under an 8-byte cap it is denied (byte, not char, ceiling).
        s = "中" * 3  # 3 chars, 9 UTF-8 bytes
        self.assertEqual(self._read(s, 9), s)
        with self.assertRaises(ForeignResourceExceeded):
            self._read(s, 8)


# ---- unit: Net.get / Net.post max_bytes (the NORMAL path is unchanged) ----


class TestNetMaxBytesUnit(unittest.TestCase):
    def test_get_none_returns_full_body_unchanged(self):
        # max_bytes=None (the default the normal path uses) returns the
        # whole body -- proving the non-foreign path is UNCHANGED.
        with _BodyServer(50_000) as srv:
            r = Net().get(srv.url)
            self.assertEqual(len(r.value), 50_000)
            # Positional / default call still works (no keyword needed).
            r2 = Net().get(srv.url)
            self.assertEqual(len(r2.value), 50_000)

    def test_get_under_cap_returns_full(self):
        with _BodyServer(4_000) as srv:
            r = Net().get(srv.url, max_bytes=1_000_000)
            self.assertEqual(len(r.value), 4_000)

    def test_get_exactly_cap_allowed(self):
        with _BodyServer(4_000) as srv:
            r = Net().get(srv.url, max_bytes=4_000)
            self.assertEqual(len(r.value), 4_000)

    def test_get_over_cap_raises(self):
        with _BodyServer(50_000) as srv:
            with self.assertRaises(ResultCapExceeded):
                Net().get(srv.url, max_bytes=1_000)

    def test_post_none_returns_full_body_unchanged(self):
        with _BodyServer(20_000) as srv:
            r = Net().post(srv.url, "payload")
            self.assertEqual(len(r.value), 20_000)

    def test_post_over_cap_raises(self):
        with _BodyServer(50_000) as srv:
            with self.assertRaises(ResultCapExceeded):
                Net().post(srv.url, "payload", max_bytes=1_000)

    def test_post_under_cap_returns_full(self):
        with _BodyServer(4_000) as srv:
            r = Net().post(srv.url, "payload", max_bytes=1_000_000)
            self.assertEqual(len(r.value), 4_000)


# ---- flag semantics --------------------------------------------------


class TestFlagSemantics(unittest.TestCase):
    def test_negative_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = _write(td, "p.capa", "fun main()\n    let x = 1\n")
            rc, _out, err = _run_cli(
                ["--wasm", "--run", "--foreign-result-cap", "-5", str(p)],
                cwd=td,
            )
            self.assertEqual(rc, 2)
            self.assertIn("--foreign-result-cap must be >= 0", err)

    def test_default_applies_when_unset(self):
        from capa.runtime._wasm_host import WasmHost
        host = WasmHost()
        self.assertEqual(
            host._foreign_result_cap_bytes, DEFAULT_FOREIGN_RESULT_CAP_BYTES,
        )

    def test_zero_opts_out(self):
        from capa.runtime._wasm_host import WasmHost
        host = WasmHost()
        host.configure_foreign_limits(result_cap_bytes=0)
        self.assertIsNone(host._foreign_result_cap_bytes)

    def test_positive_sets_bytes(self):
        from capa.runtime._wasm_host import WasmHost
        host = WasmHost()
        host.configure_foreign_limits(result_cap_bytes=8 * 1024 * 1024)
        self.assertEqual(host._foreign_result_cap_bytes, 8 * 1024 * 1024)


# ---- fs.read over / under cap, end to end through the CLI ------------


_FS_PROG = (
    'extern component Reader from "fs_read_child.wasm"\n'
    "    fun read_it(fs: Fs, path: String) -> String\n"
    "\n"
    "fun main(fs: Fs, stdio: Stdio)\n"
    '    let safe = fs.restrict_to("sandbox")\n'
    '    stdio.println("R=${Reader.read_it(safe, "sandbox/data.txt")}")\n'
)

_TAIL = "TAIL-MARKER-NEVER-BUFFERED"


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignFsResultCap(unittest.TestCase):
    def _prep(self, td, payload: str):
        sandbox = Path(td) / "sandbox"
        sandbox.mkdir()
        (sandbox / "data.txt").write_text(payload, encoding="utf-8")
        shutil.copy(
            _FIXTURES / "fs_read_child.wasm", Path(td) / "fs_read_child.wasm",
        )

    def test_over_cap_denied_without_buffering_whole_file(self):
        # A 4 MiB in-prefix file read under a 1 MiB result cap: the host
        # aborts the read EARLY (peak allocation ~1 MiB), so the distinctive
        # tail at the 4 MiB mark is never buffered and never reaches output.
        with tempfile.TemporaryDirectory() as td:
            big = ("A" * (4 * 1024 * 1024)) + _TAIL
            self._prep(td, big)
            p = _write(td, "prog.capa", _FS_PROG)
            rc, out, err = _run_cli(
                ["--wasm", "--run", "--foreign-result-cap", "1", str(p)],
                cwd=td,
            )
            self.assertEqual(rc, 1, err)
            self.assertIn("result exceeded the foreign result cap", err)
            self.assertIn("Fs.read", err)
            # Proof the whole file was NOT buffered / lifted: the tail marker
            # (4 MiB into the file) never appears anywhere in the output.
            self.assertNotIn(_TAIL, out)
            self.assertNotIn(_TAIL, err)

    def test_under_cap_returns_exact_bytes(self):
        # A small in-prefix file under the cap returns the EXACT bytes.
        with tempfile.TemporaryDirectory() as td:
            self._prep(td, "SMALL-OK")
            p = _write(td, "prog.capa", _FS_PROG)
            rc, out, err = _run_cli(
                ["--wasm", "--run", "--foreign-result-cap", "1", str(p)],
                cwd=td,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("R=SMALL-OK", out)

    def test_opt_out_reads_without_cap(self):
        # With the cap opted out (0), a file larger than a small default is
        # read in full (bounded only by the child memory, unrelated here).
        with tempfile.TemporaryDirectory() as td:
            self._prep(td, "OPTOUT-OK")
            p = _write(td, "prog.capa", _FS_PROG)
            rc, out, err = _run_cli(
                ["--wasm", "--run", "--foreign-result-cap", "0", str(p)],
                cwd=td,
            )
            self.assertEqual(rc, 0, err)
            self.assertIn("R=OPTOUT-OK", out)


# ---- db.query and net.get over / under / opt-out via dispatch --------


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignDbResultCap(unittest.TestCase):
    def _make_db(self, td, rows: int) -> str:
        dbp = os.path.join(td, "t.db")
        conn = sqlite3.connect(dbp)
        conn.execute("create table t(x)")
        conn.executemany(
            "insert into t values (?)", [("row-%d" % i,) for i in range(rows)],
        )
        conn.commit()
        conn.close()
        return dbp

    def _query(self, dbp, sql, cap):
        from capa.runtime._capabilities import Db
        from capa.runtime._foreign import (
            dispatch_foreign_call, new_foreign_engine,
        )
        return dispatch_foreign_call(
            new_foreign_engine(),
            str(_FIXTURES / "db_query_child.wasm"),
            "run_query", {"Db": Db()}, [dbp, sql], "T.run_query",
            result_cap_bytes=cap,
        )

    def test_over_cap_raises(self):
        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td, 500)
            with self.assertRaises(ForeignResourceExceeded) as cm:
                self._query(dbp, "select x from t", 100)
            self.assertIn("Db.query", str(cm.exception))
            self.assertIn("result cap", str(cm.exception))

    def test_under_cap_returns_full_result(self):
        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td, 3)
            r = self._query(dbp, "select x from t order by x", 1_000_000)
            self.assertEqual(r, '[["row-0"], ["row-1"], ["row-2"]]')

    def test_opt_out_unbounded(self):
        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td, 3)
            r = self._query(dbp, "select x from t order by x", 0)
            self.assertEqual(r, '[["row-0"], ["row-1"], ["row-2"]]')


# ---- db.query closure: single-value / multi-row / scoping (no wasm) ---
#
# These drive the ``db.query`` host closure DIRECTLY (no wasm fixture) so
# they run on any interpreter. They pin the CRITICAL DoS fix: the untrusted
# child controls the SQL and can collapse arbitrary size into ONE value
# (``hex(zeroblob(N))``, ``group_concat``, a recursive CTE) that sqlite
# would materialise in host memory BEFORE any per-row check. The fix caps a
# single value at the SOURCE via ``SQLITE_LIMIT_LENGTH`` so the giant value
# is never built.


def _db_query_closure(db, cap):
    """Extract the ``db.query`` host closure the ``_bind_db`` binder
    registers, without instantiating a wasm child. Returns a callable with
    the ``(store, handle, path, sql)`` ABI shape."""
    from capa.runtime._foreign import _bind_db

    captured: dict = {}

    class _Ifc:
        def add_func(self, name, fn):
            captured[name] = fn

        def close(self):
            pass

    class _Root:
        def add_instance(self, _name):
            return _Ifc()

    # Normalise as ``dispatch_foreign_call`` does: a non-positive cap opts
    # out (unbounded) and reaches the binder as ``None``.
    result_cap = cap if (cap is not None and cap > 0) else None
    _bind_db(_Root(), db, result_cap)
    return captured["query"]


class TestForeignDbQueryClosure(unittest.TestCase):
    _CAP = 1024 * 1024  # 1 MiB, the review PoC cap

    def _make_db(self, td: str) -> str:
        dbp = os.path.join(td, "t.db")
        conn = sqlite3.connect(dbp)
        conn.execute("create table t(x)")
        conn.commit()
        conn.close()
        return dbp

    def _peak_of(self, fn) -> int:
        import tracemalloc

        tracemalloc.start()
        tracemalloc.reset_peak()
        try:
            fn()
        finally:
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
        return peak

    def test_single_value_zeroblob_refused_at_cap_peak(self):
        # The exact review PoC: one ~64 MiB value under a 1 MiB cap. It must
        # raise ForeignResourceExceeded AND never materialise -- the peak
        # host allocation stays a few MiB, not the ~200 MiB the review saw.
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(Db(), self._CAP)

            def run():
                with self.assertRaises(ForeignResourceExceeded) as cm:
                    q(None, 0, dbp, "select hex(zeroblob(33554432))")
                self.assertIn("Db.query", str(cm.exception))
                self.assertIn("result cap", str(cm.exception))

            peak = self._peak_of(run)
            # ~cap, not ~200 MiB. Generous 32 MiB bound leaves headroom for
            # interpreter noise while still catching a full materialisation.
            self.assertLess(peak, 32 * 1024 * 1024, f"peak={peak}")

    def test_single_value_group_concat_refused_at_cap_peak(self):
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(Db(), self._CAP)
            # Four ~600 KiB values concatenated into one ~2.4 MiB value:
            # fast to build (4 rows) yet over the 1 MiB cap, so sqlite refuses
            # the group_concat result before host memory grows.
            sql = (
                "select group_concat(hex(zeroblob(300000))) from "
                "(select 1 union all select 2 union all select 3 "
                "union all select 4)"
            )

            def run():
                with self.assertRaises(ForeignResourceExceeded):
                    q(None, 0, dbp, sql)

            self.assertLess(self._peak_of(run), 32 * 1024 * 1024)

    def test_single_value_recursive_cte_refused_at_cap_peak(self):
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(Db(), self._CAP)
            # Doubling CTE: a single value that grows exponentially. sqlite
            # refuses to build the row once it crosses the length limit.
            sql = (
                "with recursive c(x) as (select cast('x' as text) "
                "union all select x || x from c) select x from c"
            )

            def run():
                with self.assertRaises(ForeignResourceExceeded):
                    q(None, 0, dbp, sql)

            self.assertLess(self._peak_of(run), 32 * 1024 * 1024)

    def test_single_stored_value_over_cap_refused(self):
        # A genuine large STORED value larger than the cap is also refused
        # (SQLITE_TOOBIG -> ForeignResourceExceeded), not materialised.
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            conn.execute("insert into t values (hex(zeroblob(4194304)))")
            conn.commit()
            conn.close()
            q = _db_query_closure(Db(), self._CAP)
            with self.assertRaises(ForeignResourceExceeded):
                q(None, 0, dbp, "select x from t")

    def test_multi_row_over_cap_refused_at_bounded_peak(self):
        # Many rows summing past the cap still abort early, with the peak
        # bounded near the cap (a large improvement on the review's ~8.8x).
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            # 2000 rows x ~2 KiB = ~4 MiB total, cap 1 MiB: aborts at ~cap.
            conn.executemany(
                "insert into t values (?)",
                [("x" * 2000,) for _ in range(2000)],
            )
            conn.commit()
            conn.close()
            q = _db_query_closure(Db(), self._CAP)

            def run():
                with self.assertRaises(ForeignResourceExceeded) as cm:
                    q(None, 0, dbp, "select x from t")
                self.assertIn("result cap", str(cm.exception))

            peak = self._peak_of(run)
            # Bounded near the cap: well under the ~4 MiB full result and far
            # under the 8.8x the review measured.
            self.assertLess(peak, 8 * 1024 * 1024, f"peak={peak}")

    def test_empty_string_flood_aborts_at_bounded_peak(self):
        # Vector C: the smoking gun. A recursive CTE emitting 1,000,000 empty
        # strings. A payload-only accumulator counts each ``''`` as 0 bytes, so
        # ``total`` never moves and the cap never fires -- the retained
        # list-of-lists peaks ~100 MiB and the query RETURNS a full result.
        # With the per-row / per-value object charge, ``total`` over-estimates
        # the real retained memory, so the abort fires after ~cap/PER_ROW rows
        # and the peak stays a few MiB.
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(Db(), self._CAP)
            sql = (
                "with recursive c(x) as (select '' union all select '' "
                "from c limit 1000000) select x from c"
            )

            def run():
                with self.assertRaises(ForeignResourceExceeded) as cm:
                    q(None, 0, dbp, sql)
                self.assertIn("result cap", str(cm.exception))

            peak = self._peak_of(run)
            # ~cap, NOT the ~100 MiB a payload-only count let through.
            self.assertLess(peak, 16 * 1024 * 1024, f"peak={peak}")

    def test_select_1_flood_aborts_at_bounded_peak(self):
        # Same axis with a tiny non-empty value (``select 1`` -> "1", 1 byte).
        # A payload-only count barely moves; the object charge aborts at ~cap.
        from capa.runtime._capabilities import Db

        for literal in ("1", "null"):
            with tempfile.TemporaryDirectory() as td:
                dbp = self._make_db(td)
                q = _db_query_closure(Db(), self._CAP)
                sql = (
                    "with recursive c(x) as (select %s union all select %s "
                    "from c limit 3000000) select x from c" % (literal, literal)
                )

                def run(sql=sql):
                    with self.assertRaises(ForeignResourceExceeded):
                        q(None, 0, dbp, sql)

                peak = self._peak_of(run)
                self.assertLess(
                    peak, 16 * 1024 * 1024, f"literal={literal} peak={peak}",
                )

    def test_row_count_does_not_scale_peak(self):
        # Row-count scalability killed: raising the attacker's row count from
        # 1M to 10M does NOT raise the peak beyond ~cap -- the abort happens
        # after ~cap/PER_ROW rows regardless of how many rows the SQL asks for.
        from capa.runtime._capabilities import Db

        peaks = []
        for limit in (1_000_000, 10_000_000):
            with tempfile.TemporaryDirectory() as td:
                dbp = self._make_db(td)
                q = _db_query_closure(Db(), self._CAP)
                sql = (
                    "with recursive c(x) as (select '' union all select '' "
                    "from c limit %d) select x from c" % limit
                )

                def run(sql=sql):
                    with self.assertRaises(ForeignResourceExceeded):
                        q(None, 0, dbp, sql)

                peaks.append(self._peak_of(run))
        for peak in peaks:
            self.assertLess(peak, 16 * 1024 * 1024, f"peaks={peaks}")

    def test_vector_a_wide_single_row_refused_at_cap_peak(self):
        # Vector A: a single row that is arbitrarily WIDE. Under the old
        # per-value + accumulator design ``select zeroblob(900k), ... x 500``
        # materialised ~500 x 900 KiB = 446 MiB in ONE fetch before any check.
        # SQLITE_LIMIT_COLUMN now refuses the >100-column result outright, so
        # no row materialises and the peak stays ~cap.
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(Db(), self._CAP)
            for ncols in (200, 500):
                cols = ", ".join("zeroblob(900000)" for _ in range(ncols))
                sql = "select " + cols

                def run(sql=sql):
                    with self.assertRaises(ForeignResourceExceeded) as cm:
                        q(None, 0, dbp, sql)
                    self.assertIn("result cap", str(cm.exception))

                peak = self._peak_of(run)
                self.assertLess(peak, 32 * 1024 * 1024, f"ncols={ncols} peak={peak}")

    def test_vector_a_at_column_limit_wide_values_refused(self):
        # At EXACTLY the column limit (100) the width passes, but each value is
        # 900 KiB > the per-value length bound, so the length limit refuses the
        # first value at ~cap peak (Vector A cannot smuggle width in under 100
        # columns of giant values either).
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(Db(), self._CAP)
            cols = ", ".join("hex(zeroblob(900000))" for _ in range(100))
            sql = "select " + cols

            def run():
                with self.assertRaises(ForeignResourceExceeded):
                    q(None, 0, dbp, sql)

            peak = self._peak_of(run)
            self.assertLess(peak, 32 * 1024 * 1024, f"peak={peak}")

    def test_vector_b_many_rows_row_at_a_time_bounded_peak(self):
        # Vector B: many rows fetched atomically. The old ``fetchmany(256)``
        # pulled 256 rows x ~1 MiB = 256 MiB into host memory before the
        # accumulator ran. Row-at-a-time fetch means only ONE bounded row is
        # ever materialised; the accumulator aborts near the cap. 400 rows of
        # ~1 MiB each (17 columns x 60 KiB, each value under the per-value
        # bound, 17 under the column bound) would be ~400 MiB unbounded.
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            conn.executemany(
                "insert into t values (?)",
                [("y" * 60000,) for _ in range(400)],
            )
            conn.commit()
            conn.close()
            q = _db_query_closure(Db(), self._CAP)
            wide = ", ".join("x" for _ in range(17))  # ~1 MiB per row

            def run():
                with self.assertRaises(ForeignResourceExceeded) as cm:
                    q(None, 0, dbp, "select " + wide + " from t")
                self.assertIn("result cap", str(cm.exception))

            peak = self._peak_of(run)
            # ~2x cap, nowhere near the ~256 MiB the batch fetch reached.
            self.assertLess(peak, 16 * 1024 * 1024, f"peak={peak}")

    def test_combined_many_rows_many_columns_bounded_peak(self):
        # Combined width x depth: many rows, many (but <= 100) columns. Still
        # bounded ~cap because each row is source-bounded and fetched alone.
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            conn.executemany(
                "insert into t values (?)",
                [("z" * 60000,) for _ in range(500)],
            )
            conn.commit()
            conn.close()
            q = _db_query_closure(Db(), self._CAP)
            wide = ", ".join("x" for _ in range(50))  # 50 cols x 60 KiB per row

            def run():
                with self.assertRaises(ForeignResourceExceeded):
                    q(None, 0, dbp, "select " + wide + " from t")

            peak = self._peak_of(run)
            self.assertLess(peak, 16 * 1024 * 1024, f"peak={peak}")

    def test_tradeoff_single_value_over_per_value_limit_refused(self):
        # Documented trade-off: with a cap set, a single db value larger than
        # ``max(cap // MAX_RESULT_COLUMNS, FLOOR)`` is refused (the price of the
        # single-row bound). A value just UNDER the per-value limit succeeds.
        from capa.runtime._capabilities import Db
        from capa.runtime._foreign import (
            MAX_RESULT_COLUMNS, _FOREIGN_DB_VALUE_FLOOR,
        )

        per_value = max(self._CAP // MAX_RESULT_COLUMNS, _FOREIGN_DB_VALUE_FLOOR)
        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(Db(), self._CAP)
            # Just OVER the per-value bound -> refused, even though the value is
            # far smaller than the cap itself.
            over = per_value + 10
            with self.assertRaises(ForeignResourceExceeded):
                q(None, 0, dbp, "select zeroblob(%d)" % over)
            # Just UNDER the per-value bound -> returned in full.
            under = per_value - 1000
            r = q(None, 0, dbp, "select length(zeroblob(%d))" % under)
            self.assertEqual(r, '[["%d"]]' % under)

    def test_escape_heavy_over_cap_refused_crossing_dump_bounded(self):
        # Vector D: the escape-EXPANSION axis. json.dumps(..., ensure_ascii)
        # expands a control char to ``\uXXXX`` (6x). A result whose RAW payload
        # is UNDER the cap but whose escaped ``json.dumps`` would be ~6x it must
        # ABORT -- charging each value its raw UTF-8 size (the prior accumulator)
        # missed this, letting a ~6x-cap dump cross to the child. 400 rows x
        # 2000 ``chr(1)`` = ~800 KiB raw (< 1 MiB cap) but ~4.8 MiB escaped.
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            conn.executemany(
                "insert into t values (?)",
                [(chr(1) * 2000,) for _ in range(400)],
            )
            conn.commit()
            conn.close()
            q = _db_query_closure(Db(), self._CAP)

            def run():
                with self.assertRaises(ForeignResourceExceeded) as cm:
                    q(None, 0, dbp, "select x from t")
                self.assertIn("result cap", str(cm.exception))

            peak = self._peak_of(run)
            # Raw payload was under the cap; only the escaped charge fires. Peak
            # stays a fraction of the cap (the escaped charge aborts fast).
            self.assertLess(peak, 8 * 1024 * 1024, f"peak={peak}")

    def test_escape_heavy_under_cap_dump_bounded_and_exact(self):
        # The escape-heavy SUCCESS case: a result sized so the ESCAPED dump sits
        # just under the cap round-trips EXACTLY, and the returned dump (the
        # value that crosses to the child) is <= cap for every escape flavour --
        # control char, quote, backslash, astral (surrogate-pair escape), mixed.
        from capa.runtime._capabilities import Db

        for content, nrows in (
            (chr(1) * 2000, 50),      #  -> 6x
            ('"' * 2000, 50),         # \"     -> 2x
            ("\\" * 2000, 50),        # \\     -> 2x
            (chr(0x10000) * 2000, 20),  # 𐀀 -> 12x per char
            (('a"b\\c' + chr(1)) * 500, 20),  # mixed escapes
        ):
            with tempfile.TemporaryDirectory() as td:
                dbp = self._make_db(td)
                conn = sqlite3.connect(dbp)
                conn.executemany(
                    "insert into t values (?)", [(content,)] * nrows,
                )
                conn.commit()
                conn.close()
                q = _db_query_closure(Db(), self._CAP)
                r = q(None, 0, dbp, "select x from t")
                # Exact round-trip: the returned string is json.dumps of the
                # list-of-lists, unchanged content.
                import json as _j
                self.assertEqual(r, _j.dumps([[content]] * nrows))
                # The crossing value is bounded by the cap.
                self.assertLessEqual(
                    len(r), self._CAP, f"content={content[:4]!r} len={len(r)}",
                )

    def test_under_cap_multi_row_multi_column_roundtrips_exact(self):
        # Under-cap correctness: a small legitimate multi-row, multi-column
        # result round-trips EXACTLY (values, order, column count intact).
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            conn.execute("create table m(a, b, c)")
            conn.executemany(
                "insert into m values (?, ?, ?)",
                [("a%d" % i, i, i * 1.5) for i in range(3)],
            )
            conn.commit()
            conn.close()
            q = _db_query_closure(Db(), self._CAP)
            r = q(None, 0, dbp, "select a, b, c from m order by b")
            self.assertEqual(
                r,
                '[["a0", "0", "0.0"], ["a1", "1", "1.5"], '
                '["a2", "2", "3.0"]]',
            )

    def _make_wide_db(self, td, ncols, nrows, value, name="w.db"):
        # A table of ``ncols`` TEXT columns, ``nrows`` rows of ``value``.
        dbp = os.path.join(td, name)
        conn = sqlite3.connect(dbp)
        cols = ", ".join("c%d" % i for i in range(ncols))
        conn.execute("create table w(%s)" % cols)
        placeholders = ", ".join("?" for _ in range(ncols))
        row = tuple(value for _ in range(ncols))
        conn.executemany(
            "insert into w values (%s)" % placeholders, [row] * nrows,
        )
        conn.commit()
        conn.close()
        return dbp

    def _query_wide(self, ncols, nrows, value, cap):
        # Run one wide ``select * from w`` in an ISOLATED temp dir (each db in
        # its own dir so a retained-traceback lock on Windows never blocks a
        # sibling cleanup). Returns the closure result or re-raises its abort.
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_wide_db(td, ncols, nrows, value)
            q = _db_query_closure(Db(), cap)
            try:
                return q(None, 0, dbp, "select * from w")
            finally:
                import gc
                gc.collect()

    def _charged_total(self, value, ncols, nrows):
        # Reproduce the closure's accumulator EXACTLY for a uniform result:
        # seed 2 (outer brackets) + per row (_FOREIGN_DB_PER_ROW_COST + per
        # value charge), where per-value charge is max(len(json.dumps(v)),
        # _FOREIGN_DB_PER_VALUE_COST). Used to assert the soundness invariant
        # total >= len(json.dumps(stringified)) with the code's own constants.
        import json as _j

        from capa.runtime._foreign import (
            _FOREIGN_DB_PER_ROW_COST, _FOREIGN_DB_PER_VALUE_COST,
        )
        per_val = max(len(_j.dumps(value)), _FOREIGN_DB_PER_VALUE_COST)
        return 2 + nrows * (_FOREIGN_DB_PER_ROW_COST + ncols * per_val)

    def test_wide_return_dump_within_cap_and_invariant(self):
        # Regression for the bounded STRUCTURAL UNDERCOUNT the old flat 128
        # per-row charge allowed: json.dumps default separators are TWO bytes
        # (``", "``), so a WIDE row's structural dump bytes (2*k + 2, up to 202
        # at k=100) exceeded the old 128 charge, and a wide result could RETURN
        # with dump > cap (the review PoC: 1000x100 of 62-char values overshot
        # ~1.13%). The per-row charge is now derived from MAX_RESULT_COLUMNS so
        # the invariant total >= len(json.dumps(stringified)) holds again.
        # Build the WIDE PoC shape (100 columns, tight 100-char values so the
        # per-value floor adds no slack) sized just under the 1 MiB cap and
        # prove the returned dump is <= cap AND total >= len(dump).
        import json as _j

        from capa.runtime._foreign import (
            _FOREIGN_DB_PER_ROW_COST, _FOREIGN_DB_PER_VALUE_COST,
        )

        value = "v" * 100  # dumps() = 102 bytes > the 64 floor: no slack
        for ncols in (64, 100):
            per_val = max(len(_j.dumps(value)), _FOREIGN_DB_PER_VALUE_COST)
            charged_per_row = _FOREIGN_DB_PER_ROW_COST + ncols * per_val
            # Largest row count that still RETURNS (total <= cap).
            nrows = (self._CAP - 2) // charged_per_row
            self.assertGreater(nrows, 1, f"ncols={ncols}")
            r = self._query_wide(ncols, nrows, value, self._CAP)
            self.assertIsInstance(r, str)
            # The crossing dump fits the cap -- the overshoot is gone.
            self.assertLessEqual(len(r), self._CAP, f"ncols={ncols}")
            expected = _j.dumps([[value] * ncols] * nrows)
            self.assertEqual(r, expected)
            # The soundness invariant: total >= len(json.dumps(...)).
            self.assertGreaterEqual(
                self._charged_total(value, ncols, nrows), len(expected),
                f"ncols={ncols}",
            )
            # One MORE row must abort (total crosses the cap), never return
            # an over-cap dump.
            with self.assertRaises(ForeignResourceExceeded):
                self._query_wide(ncols, nrows + 1, value, self._CAP)

    def test_column_sweep_no_return_overshoots(self):
        # Sweep k = 1, 2, 63, 64, 99, 100 columns: every successful return has
        # dump <= cap, and the row count one past the return boundary aborts
        # (because total crossed the cap). No k overshoots -- the 2-byte
        # separator undercount is closed across the whole column range.
        import json as _j

        from capa.runtime._foreign import (
            _FOREIGN_DB_PER_ROW_COST, _FOREIGN_DB_PER_VALUE_COST,
        )

        value = "w" * 100
        per_val = max(len(_j.dumps(value)), _FOREIGN_DB_PER_VALUE_COST)
        for ncols in (1, 2, 63, 64, 99, 100):
            charged_per_row = _FOREIGN_DB_PER_ROW_COST + ncols * per_val
            nrows = (self._CAP - 2) // charged_per_row
            self.assertGreaterEqual(nrows, 1, f"ncols={ncols}")
            r = self._query_wide(ncols, nrows, value, self._CAP)
            self.assertIsInstance(r, str, f"ncols={ncols}")
            self.assertLessEqual(len(r), self._CAP, f"ncols={ncols}")
            self.assertGreaterEqual(
                self._charged_total(value, ncols, nrows), len(r),
                f"ncols={ncols}",
            )
            with self.assertRaises(ForeignResourceExceeded):
                self._query_wide(ncols, nrows + 1, value, self._CAP)

    def test_many_short_rows_not_falsely_aborted(self):
        # The slightly larger per-row charge (264 vs the old 128) must NOT trip
        # a legitimate small result: a few hundred short rows under the cap
        # still return in full and round-trip exactly.
        import json as _j

        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            conn.executemany(
                "insert into t values (?)",
                [("short-%d" % i,) for i in range(500)],
            )
            conn.commit()
            conn.close()
            q = _db_query_closure(Db(), self._CAP)
            r = q(None, 0, dbp, "select x from t order by rowid")
            self.assertEqual(r, _j.dumps([["short-%d" % i] for i in range(500)]))
            self.assertLessEqual(len(r), self._CAP)

    def test_under_cap_returns_full_result(self):
        from capa.runtime._capabilities import Db

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            conn.executemany(
                "insert into t values (?)",
                [("row-%d" % i,) for i in range(3)],
            )
            conn.commit()
            conn.close()
            q = _db_query_closure(Db(), self._CAP)
            r = q(None, 0, dbp, "select x from t order by x")
            self.assertEqual(r, '[["row-0"], ["row-1"], ["row-2"]]')

    def test_normal_sql_error_passthrough_not_result_cap(self):
        # A genuine SQL error surfaces as the existing db IoError, NOT as a
        # result-cap breach -- the fix must not swallow real errors.
        from capa.runtime._capabilities import Db
        from capa.runtime._wasm_component_host import IoErrorRecord

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(Db(), self._CAP)
            r = q(None, 0, dbp, "select * from no_such_table")
            self.assertIsInstance(r, IoErrorRecord)
            self.assertEqual(r.message, "SQLite query failed")
            self.assertIn("no_such_table", r.cause)

    def test_setlimit_scoped_and_restored_on_connection(self):
        # The per-query SQLITE_LIMIT_LENGTH and SQLITE_LIMIT_COLUMN must NOT
        # leak: the closure sets both, then RESTORES the prior values in its
        # finally. A recording Connection subclass captures every setlimit call
        # to prove each set is paired with its restore.
        from capa.runtime._capabilities import Db, _install_sqlite_authorizer
        from capa.runtime._foreign import (
            MAX_RESULT_COLUMNS, _FOREIGN_DB_VALUE_FLOOR,
        )

        class _RecordingConn(sqlite3.Connection):
            log: list = []

            def setlimit(self, category, limit):
                prev = super().setlimit(category, limit)
                _RecordingConn.log.append((category, limit, prev))
                return prev

        class _RecordingDb(Db):
            def _connect_verified(self, path):
                conn = sqlite3.connect(path, factory=_RecordingConn)
                _install_sqlite_authorizer(conn)
                return conn

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            _RecordingConn.log = []
            q = _db_query_closure(_RecordingDb(), self._CAP)
            q(None, 0, dbp, "select 1")
            log = _RecordingConn.log
            # Four setlimit calls: set LENGTH, set COLUMN, restore LENGTH,
            # restore COLUMN. Each limit set to its foreign bound then restored
            # to the prior value the set call reported.
            self.assertEqual(len(log), 4)
            per_value = max(self._CAP // MAX_RESULT_COLUMNS, _FOREIGN_DB_VALUE_FLOOR)
            len_set, col_set, len_restore, col_restore = log
            self.assertEqual(len_set[0], sqlite3.SQLITE_LIMIT_LENGTH)
            self.assertEqual(len_set[1], per_value)         # length set to bound
            self.assertEqual(col_set[0], sqlite3.SQLITE_LIMIT_COLUMN)
            self.assertEqual(col_set[1], MAX_RESULT_COLUMNS)  # column set to bound
            self.assertEqual(len_restore[0], sqlite3.SQLITE_LIMIT_LENGTH)
            self.assertEqual(len_restore[1], len_set[2])    # length restored
            self.assertEqual(col_restore[0], sqlite3.SQLITE_LIMIT_COLUMN)
            self.assertEqual(col_restore[1], col_set[2])    # column restored
            self.assertNotEqual(len_restore[1], per_value)  # not left at bound

    def test_normal_path_db_query_uncapped_and_unaffected(self):
        # The trusted (non-foreign) Db.query is uncapped: a stored value far
        # larger than the foreign cap round-trips in full, proving the cap
        # does not leak to the normal path.
        from capa.runtime._capabilities import Db
        from capa.runtime._result import Ok

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            conn = sqlite3.connect(dbp)
            conn.execute("insert into t values (hex(zeroblob(4194304)))")
            conn.commit()
            conn.close()
            r = Db().query(dbp, "select length(x) from t")
            self.assertIsInstance(r, Ok)
            self.assertEqual(r.value, '[["8388608"]]')

    def test_fail_closed_when_setlimit_unavailable(self):
        # On an interpreter whose sqlite connection lacks ``setlimit`` (Python
        # < 3.11), a CAPPED foreign query fails closed rather than risk an
        # unbounded host allocation. Simulated by a proxy that hides setlimit.
        from capa.runtime._capabilities import Db

        class _NoSetlimit:
            def __init__(self, conn):
                object.__setattr__(self, "_c", conn)

            def __getattr__(self, name):
                if name == "setlimit":
                    raise AttributeError(name)
                return getattr(self._c, name)

        class _NoLimitDb(Db):
            def _connect_verified(self, path):
                return _NoSetlimit(super()._connect_verified(path))

        with tempfile.TemporaryDirectory() as td:
            dbp = self._make_db(td)
            q = _db_query_closure(_NoLimitDb(), self._CAP)
            with self.assertRaises(ForeignResourceExceeded) as cm:
                q(None, 0, dbp, "select 1")
            self.assertIn("cannot enforce", str(cm.exception))
            # But opt-out (cap off) still runs unbounded on the same setup.
            q_off = _db_query_closure(_NoLimitDb(), 0)
            self.assertEqual(q_off(None, 0, dbp, "select 1"), '[["1"]]')


@unittest.skipUnless(
    _wasm_tooling_available(), "wasm-tools / wasmtime missing",
)
class TestForeignNetResultCap(unittest.TestCase):
    def _fetch(self, url, cap):
        from capa.runtime._foreign import (
            dispatch_foreign_call, new_foreign_engine,
        )
        return dispatch_foreign_call(
            new_foreign_engine(),
            str(_FIXTURES / "net_get_child.wasm"),
            "fetch", {"Net": Net()}, [url], "T.fetch",
            result_cap_bytes=cap,
        )

    def test_over_cap_raises(self):
        with _BodyServer(50_000) as srv:
            with self.assertRaises(ForeignResourceExceeded) as cm:
                self._fetch(srv.url, 1_000)
            self.assertIn("Net.get", str(cm.exception))
            self.assertIn("result cap", str(cm.exception))

    def test_under_cap_returns_full_body(self):
        # 4 KiB body fits the child's single-page memory; cap is generous.
        with _BodyServer(4_000) as srv:
            r = self._fetch(srv.url, 1_000_000)
            self.assertEqual(len(r), 4_000)

    def test_opt_out_unbounded(self):
        with _BodyServer(4_000) as srv:
            r = self._fetch(srv.url, 0)
            self.assertEqual(len(r), 4_000)


if __name__ == "__main__":
    unittest.main()
