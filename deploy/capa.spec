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
SPEC_DIR = os.path.dirname(os.path.abspath(SPEC))
ROOT = os.path.abspath(os.path.join(SPEC_DIR, '..'))

block_cipher = None

a = Analysis(
    [os.path.join(SPEC_DIR, 'capa-entry.py')],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=[
        # The transpiled Capa program imports from capa.runtime at
        # runtime via exec(). PyInstaller's static analysis does not
        # see those imports, so list them explicitly.
        'capa.runtime',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Capa has zero runtime dependencies outside the Python
        # standard library; nothing else should be pulled in. The
        # excludes below trim the resulting binary by dropping things
        # PyInstaller may speculatively include.
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
)
