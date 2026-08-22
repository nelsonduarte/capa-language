"""Fail-closed agreement net for the module search-path construction (M6).

The compiler (``capa.cli``) and the language server (``capa.lsp``) both
resolve ``import`` statements through a :class:`capa.loader.ModuleLoader`.
Its two inputs, the search roots and the declared-dependency map, used to
be built twice: the CLI computed the full pair from ``CAPA_PATH`` +
``capa.toml``, while the LSP kept a poorer copy that read only
``CAPA_PATH`` and dropped ``dependency_roots`` entirely. The editor then
resolved imports DIFFERENTLY from the compiler, so go-to-definition and
diagnostics went silent on vendored / path-dependency imports that
``capa --check`` on the same project resolved fine.

M6 single-sources the construction in :func:`capa.loader_paths.resolve_loader_paths`.

``AgreementTests`` is the M2-style guard: it asserts the LSP's loader
wiring (``capa.lsp.context._build_module_loader``) produces the SAME
``search_paths`` + ``dependency_roots`` as the compiler's shared function
for a real project on disk. If a future edit makes one path diverge from
the other (for example, drops ``dependency_roots`` from the LSP wiring
again), the guard fails.

``ResolutionTests`` is the behaviour witness for the fix: on a project
whose dependency directory basename differs from the dependency name, the
old ``CAPA_PATH``-only LSP wiring cannot resolve the import at all, while
the shared wiring resolves it through ``dependency_roots``.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capa.loader import LoaderError, ModuleLoader
from capa.loader_paths import resolve_loader_paths
from capa.lsp.context import _build_module_loader


def _old_capa_search_paths() -> list[Path]:
    """The LSP's pre-M6 search-path copy, verbatim: ``CAPA_PATH`` only.

    Reproduced here so ``ResolutionTests`` can show, side by side, that
    the old wiring missed an import the shared wiring now resolves.
    """
    raw = os.environ.get("CAPA_PATH", "")
    if not raw:
        return []
    out: list[Path] = []
    for entry in raw.split(os.pathsep):
        entry = entry.strip()
        if not entry:
            continue
        p = Path(entry).expanduser()
        if p.is_dir():
            out.append(p)
    return out


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


class _ProjectFixture(unittest.TestCase):
    """A project whose dependency directory basename (``other``) differs
    from the dependency name (``mylib``), so ``dependency_roots`` is
    load-bearing: only it maps ``mylib`` -> ``deps/other`` and resolves
    ``import mylib.util``. The search path alone would look under
    ``deps/mylib/`` and miss it.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.addCleanup(self._tmp.cleanup)

        deps = self.root / "deps" / "other"
        deps.mkdir(parents=True)
        _write(
            deps / "util.capa",
            "pub fun bump(n: Int) -> Int\n    return n + 1\n",
        )
        _write(
            self.root / "capa.toml",
            '[package]\n'
            'name = "demo"\n'
            'version = "0.1.0"\n'
            '\n'
            '[dependencies.mylib]\n'
            'path = "deps/other"\n',
        )
        self.entry = self.root / "main.capa"
        _write(
            self.entry,
            "import mylib.util\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${bump(2)}")\n',
        )

        # Both the compiler and the LSP derive paths from the cwd, so
        # the fixture is only meaningful with the cwd at its root. Also
        # clear CAPA_PATH so the old wiring truly has nothing to fall
        # back on.
        self._prev_cwd = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self._prev_cwd)
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        os.environ.pop("CAPA_PATH", None)
        self.addCleanup(env.stop)


class AgreementTests(_ProjectFixture):
    def test_lsp_wiring_matches_the_compiler_source_of_truth(self) -> None:
        expected = resolve_loader_paths()
        lsp_loader = _build_module_loader()

        # The fixture is non-trivial: if this map were empty the guard
        # would pass vacuously, so assert the load-bearing entry is
        # present before comparing.
        self.assertIn("mylib", expected.dependency_roots)

        self.assertEqual(
            lsp_loader._search_paths, expected.search_paths,
            "LSP search_paths diverged from the compiler's",
        )
        self.assertEqual(
            lsp_loader._dependency_roots, expected.dependency_roots,
            "LSP dependency_roots diverged from the compiler's",
        )


class ResolutionTests(_ProjectFixture):
    def test_old_wiring_cannot_resolve_the_dependency_import(self) -> None:
        # The pre-M6 LSP wiring: CAPA_PATH-only search paths, no
        # dependency_roots. It cannot map ``mylib`` -> ``deps/other``.
        old_loader = ModuleLoader(search_paths=_old_capa_search_paths())
        source = self.entry.read_text(encoding="utf-8")
        with self.assertRaises(LoaderError):
            old_loader.load_root(source, str(self.entry))

    def test_shared_wiring_resolves_the_dependency_import(self) -> None:
        # The M6 LSP wiring resolves it through dependency_roots.
        loader = _build_module_loader()
        source = self.entry.read_text(encoding="utf-8")
        linked = loader.load_root(source, str(self.entry))
        names = {
            getattr(item, "name", None) for item in linked.module.items
        }
        self.assertIn("bump", names)


if __name__ == "__main__":
    unittest.main()
