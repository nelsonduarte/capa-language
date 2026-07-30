"""Regression test that the wheel ships the runtime data files.

The compiler loads several non-``.py`` files from inside the ``capa``
import package at runtime via ``Path(__file__)``:

* ``capa/ir/_builtin_json.capa`` - the bundled JSON parser source spliced
  in on the Wasm path (read by ``capa/ir/_builtin_json.py``).
* ``capa/wasi_wit/**`` - the vendored WASI Preview 2 WIT that
  ``capa/cli.py`` copies next to the generated world for
  ``capa --wasm --component`` (WASI mode) and reads for ``capa --wit``.

setuptools ships only ``.py`` files unless the packaging says otherwise,
so if the ``[tool.setuptools.package-data]`` globs stop covering one of
these, ``pip install capa-language`` produces a compiler that
FileNotFounds the moment a user hits those paths. That failure never
shows up in the source tree, where the files are always present beside
the code, which is exactly why it needs a guard.

The check resolves the declared globs against the package directory on
disk, the same way setuptools does, and asserts each runtime data file is
matched. It reads only the ``package-data`` table, with a small parser so
it runs on the 3.10 floor too (no ``tomllib``), rather than skipping.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
CAPA_DIR = REPO_ROOT / "capa"

# Every non-``.py`` file the compiler loads from under ``capa/`` at
# runtime. Grep for ``Path(__file__)`` under ``capa/`` before extending
# this list; a new runtime data file that is not declared in
# ``package-data`` would ship in the source tree and vanish from the wheel.
RUNTIME_DATA_FILES = [
    CAPA_DIR / "ir" / "_builtin_json.capa",
    *sorted((CAPA_DIR / "wasi_wit").rglob("*.wit")),
]


def _parse_package_data(text: str) -> "dict[str, list[str]]":
    """Extract the ``[tool.setuptools.package-data]`` table.

    Keys are quoted dotted package names, values are inline lists of
    quoted glob strings. This is the only shape the table uses, so a
    full TOML parser (absent on Python 3.10) is not needed.
    """
    lines = text.splitlines()
    try:
        start = lines.index("[tool.setuptools.package-data]") + 1
    except ValueError:  # pragma: no cover - the section must exist
        return {}
    table: "dict[str, list[str]]" = {}
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith("["):  # next table starts here
            break
        if not stripped or stripped.startswith("#"):
            continue
        key_match = re.match(r'^"([^"]+)"\s*=\s*\[(.*)\]\s*$', stripped)
        if key_match is None:
            continue
        package = key_match.group(1)
        globs = re.findall(r'"([^"]+)"', key_match.group(2))
        table[package] = globs
    return table


class PackageDataTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PYPROJECT.is_file(), "pyproject.toml not found")
        self.table = _parse_package_data(PYPROJECT.read_text(encoding="utf-8"))

    def test_table_is_present(self):
        """The runtime data files are useless if the table itself is gone."""
        self.assertTrue(
            self.table,
            "[tool.setuptools.package-data] is missing or empty; the wheel "
            "will ship only .py files",
        )

    def test_runtime_data_files_exist(self):
        """The files this guard tracks must be on disk to guard anything."""
        for data_file in RUNTIME_DATA_FILES:
            self.assertTrue(
                data_file.is_file(),
                f"runtime data file missing from source tree: {data_file}",
            )
        # The WIT tree must not have been emptied out from under the rglob.
        wit_files = [f for f in RUNTIME_DATA_FILES if f.suffix == ".wit"]
        self.assertGreater(len(wit_files), 0, "no vendored .wit files found")

    def test_each_runtime_data_file_is_covered(self):
        """Every runtime data file must match a declared package-data glob.

        The globs are resolved against the owning package's directory on
        disk, exactly as setuptools resolves them when building the wheel,
        so a glob that no longer reaches a file fails here.
        """
        covered: "set[Path]" = set()
        for package, globs in self.table.items():
            pkg_dir = REPO_ROOT / Path(package.replace(".", "/"))
            for pattern in globs:
                covered.update(
                    p.resolve() for p in pkg_dir.glob(pattern) if p.is_file()
                )
        for data_file in RUNTIME_DATA_FILES:
            self.assertIn(
                data_file.resolve(),
                covered,
                f"{data_file} is loaded at runtime but no "
                f"[tool.setuptools.package-data] glob covers it, so it will "
                f"be absent from the wheel",
            )


if __name__ == "__main__":
    unittest.main()
