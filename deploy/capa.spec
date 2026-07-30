# PyInstaller spec for the Capa CLI.
#
# Builds a self-contained executable that bundles the Capa compiler,
# the runtime, and a Python interpreter. End users do not need to
# install Python to run Capa programs.
#
# Build with:
#
#     pip install pyinstaller>=6.0
#     pyinstaller deploy/capa.spec
#
# Result:
#
#     dist/capa            (Linux / macOS)
#     dist/capa.exe        (Windows)
#
# Smoke test the built binary:
#
#     ./dist/capa --run examples/hello.capa
#
# Notes
#
# - The transpiled Capa program runs *in-process* inside the bundled
#   binary (see capa.cli, --run mode). The binary therefore needs to
#   carry capa.runtime as part of the bundle even though the compiler
#   itself does not import it; that is what `hiddenimports` ensures.
# - `capa lsp` starts an LSP server built on pygls (+ lsprotocol,
#   cattrs, attrs). Those are Capa's only runtime dependencies and are
#   needed only for this subcommand. They must be pip-installed in the
#   build environment (e.g. `pip install -e .[lsp]`) for the bundle to
#   ship a working `capa lsp`; see the "Language-server stack" block
#   below for how they are collected.
# - Single-file mode (`exe = EXE(..., onefile=True)` via the EXE
#   constructor) trades startup time (~100-300ms self-extract) for
#   distribution simplicity. For a CLI tool used interactively this
#   is the right default.
# - PyInstaller cannot cross-compile. Each target OS / architecture
#   needs a native build environment. CI handles this via a matrix
#   in .github/workflows/release-binaries.yml.

# Spec files run inside PyInstaller's own context, so its globals
# (Analysis, PYZ, EXE, ...) are pre-injected; flake8 would complain
# about undefined names if it lints this file, but PyInstaller is
# happy.

import os
import sys

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

SPEC_DIR = os.path.dirname(os.path.abspath(SPEC))
ROOT = os.path.abspath(os.path.join(SPEC_DIR, '..'))

# --- Language-server stack -------------------------------------------------
#
# `capa lsp` runs an LSP server built on pygls, which pulls in lsprotocol,
# cattrs and attrs (the only runtime dependencies Capa has, and only for
# this one subcommand). PyInstaller's static analysis follows most of the
# import graph, but cattrs/lsprotocol dispatch some converters at runtime
# rather than via plain top-level imports, so a purely static crawl can
# silently drop submodules and the bundled `capa lsp` then fails at import
# time. To make the bundle reliable we collect every submodule of each
# package explicitly. We also copy each distribution's metadata: it is cheap
# insurance against any of these libraries (now or in a future version)
# reading their own version through importlib.metadata at import time.
#
# pygls also has an *optional* websockets transport; the stdio transport
# used by `capa lsp` (server.start_io()) does not need it, so websockets is
# deliberately left out and the "missing websockets" notes PyInstaller emits
# are expected and harmless.
LSP_PACKAGES = ['pygls', 'lsprotocol', 'cattrs', 'attr', 'attrs']

lsp_hiddenimports = []
for _pkg in LSP_PACKAGES:
    try:
        lsp_hiddenimports += collect_submodules(_pkg)
    except Exception:
        # The package is not installed in this build environment. The core
        # compiler still builds; only `capa lsp` will be unavailable. The
        # release workflow installs the `[lsp]` extra so this path is not
        # taken there.
        pass

lsp_datas = []
for _dist in ['pygls', 'lsprotocol', 'cattrs', 'attrs']:
    try:
        lsp_datas += copy_metadata(_dist)
    except Exception:
        # copy_metadata raises if the distribution is not installed; the
        # core compiler still builds fine without the LSP stack, so skip
        # quietly and let the optional `capa lsp` command be the only thing
        # that is unavailable in such a build.
        pass

# Bundle Capa's OWN distribution metadata. `capa.__version__` resolves the
# package version from `pyproject.toml` when running from a source checkout,
# but that file is not part of the frozen bundle, so inside the binary the
# resolver falls back to `importlib.metadata.version(...)`. Copying the
# dist-info here is what makes that lookup succeed, so the released binary
# reports the real version (e.g. `capa 1.15.0`) instead of a sentinel.
# The distribution is named `capa-language`; the release workflow installs
# the wheel before building, so the installed dist-info is `capa_language-*`.
# We try that name first and fall back to the old `capa` name so a build
# against an older install still bundles metadata. Guard anyway so a
# metadata-less build still produces a working compiler (it would just fall
# back to the sentinel version).
capa_datas = []
for _capa_dist in ('capa-language', 'capa'):
    try:
        capa_datas += copy_metadata(_capa_dist)
        break
    except Exception:
        continue

# Embed the Capa logo as the executable icon. Only Windows PE binaries
# carry an embedded .ico; Linux ELF binaries have no icon slot and
# macOS PyInstaller expects an .icns, so leave the icon unset there to
# keep those builds working unchanged.
ICON = os.path.join(SPEC_DIR, 'capa.ico') if sys.platform == 'win32' else None

block_cipher = None

a = Analysis(
    [os.path.join(SPEC_DIR, 'capa-entry.py')],
    pathex=[ROOT],
    binaries=[],
    datas=lsp_datas + capa_datas,
    hiddenimports=[
        # The transpiled Capa program imports from capa.runtime at
        # runtime via exec(). PyInstaller's static analysis does not
        # see those imports, so list them explicitly.
        'capa.runtime',
    ] + lsp_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # The compiler core has no runtime dependencies outside the
        # Python standard library; the only third-party code in the
        # bundle is the language-server stack (pygls + lsprotocol +
        # cattrs + attrs) wired in above for `capa lsp`. The excludes
        # below trim the resulting binary by dropping things PyInstaller
        # may speculatively include and that neither the compiler nor
        # the LSP server needs.
        'tkinter',
        'unittest',
        'pydoc',
        'doctest',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='capa',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=ICON,
)
