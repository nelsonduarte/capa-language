"""Edit ``capa.toml`` to declare a new dependency.

``capa add`` is the ergonomic front for ``capa install``: instead
of hand-editing ``capa.toml`` and then running ``install``, the
caller names the dep + its git URL + a pin and this module appends
the ``[dependencies.<name>]`` block, then the CLI runs the existing
install flow.

The same validators the parser uses at load time
(``_validate_git_url``, ``_validate_pin``, ``_validate_dep_name``)
run here, so a dangerous URL or a duplicate name is refused at add
time rather than slipping into the file and only failing later.

The file is edited textually, not round-tripped through a TOML
serialiser: the new block is appended at the end so comments,
ordering, and formatting of the existing manifest are preserved.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._manifest import (
    MANIFEST_FILENAME,
    ManifestError,
    _validate_dep_name,
    _validate_git_url,
    _validate_pin,
    read_manifest,
)


def add_dependency(
    project_dir: Path,
    name: str,
    git_url: str,
    *,
    tag: Optional[str] = None,
    rev: Optional[str] = None,
    branch: Optional[str] = None,
    verify_key: Optional[str] = None,
    force: bool = False,
) -> str:
    """Edit capa.toml to declare ``[dependencies.<name>]``.

    Returns the pin description string (e.g.
    ``'git=..., tag=v1.0.0'``). Raises ``ManifestError`` on a bad
    URL, a bad pin, a duplicate without ``force``, or a missing
    capa.toml. Does NOT run install (the caller decides).
    """
    manifest_path = project_dir / MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise ManifestError(
            f"no {MANIFEST_FILENAME} in {project_dir}; run `capa init` "
            f"to create one before adding dependencies"
        )

    # Exactly one pin source. ``branch`` is recorded as a tag pin
    # (git resolves a branch name the same way it resolves a tag at
    # clone --branch), so it flows through the existing pin path.
    pins = [("tag", tag), ("rev", rev), ("branch", branch)]
    given = [(kind, value) for kind, value in pins if value is not None]
    if len(given) == 0:
        raise ManifestError(
            "a git dependency needs exactly one pin: pass one of "
            "--tag, --rev, or --branch"
        )
    if len(given) > 1:
        kinds = ", ".join(k for k, _ in given)
        raise ManifestError(
            f"pick exactly one pin; got {kinds}. Use only one of "
            f"--tag, --rev, or --branch"
        )
    pin_kind, pin_value = given[0]

    _validate_dep_name(manifest_path, name)
    _validate_git_url(manifest_path, name, git_url)
    # A branch pin is written into the manifest as a ``tag`` field
    # (the manifest schema has no ``branch`` key); validate it under
    # the field name it will actually carry.
    field_kind = "rev" if pin_kind == "rev" else "tag"
    _validate_pin(manifest_path, name, field_kind, pin_value)

    normalised_key: Optional[str] = None
    if verify_key is not None:
        normalised_key = verify_key.replace(" ", "").replace(":", "").upper()
        if (len(normalised_key) != 40
                or any(c not in "0123456789ABCDEF" for c in normalised_key)):
            raise ManifestError(
                f"--verify-key must be a 40-character GPG fingerprint "
                f"(hex, spaces optional). Got {verify_key!r}"
            )

    # Parse first so the existing file is known-valid and so a
    # duplicate can be reported with its current pin.
    manifest = read_manifest(manifest_path)
    existing = next((d for d in manifest.dependencies if d.name == name), None)
    if existing is not None and not force:
        if existing.is_path:
            current = f"path={existing.path}"
        else:
            existing_pin = (
                f"tag={existing.tag}" if existing.tag is not None
                else f"rev={existing.rev}"
            )
            current = f"git={existing.git}, {existing_pin}"
        raise ManifestError(
            f"dependency {name!r} already declared in {MANIFEST_FILENAME} "
            f"({current}); pass --force to overwrite it"
        )

    block = _render_block(name, git_url, field_kind, pin_value, normalised_key)
    text = manifest_path.read_text(encoding="utf-8")
    if existing is not None:
        text = _strip_block(text, name)
    if text and not text.endswith("\n"):
        text += "\n"
    if text and not text.endswith("\n\n"):
        text += "\n"
    manifest_path.write_text(text + block, encoding="utf-8")

    return f"git={git_url}, {field_kind}={pin_value}"


def _render_block(
    name: str,
    git_url: str,
    field_kind: str,
    pin_value: str,
    verify_key: Optional[str],
) -> str:
    lines = [
        f"[dependencies.{name}]",
        f'git = "{git_url}"',
        f'{field_kind} = "{pin_value}"',
    ]
    if verify_key is not None:
        lines.append(f'verify_key = "{verify_key}"')
    return "\n".join(lines) + "\n"


def _strip_block(text: str, name: str) -> str:
    """Remove an existing ``[dependencies.<name>]`` block so a
    ``--force`` overwrite does not leave a stale duplicate.

    Drops the header line and every subsequent line up to (but not
    including) the next table header or end of file.
    """
    header = f"[dependencies.{name}]"
    out: list[str] = []
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        if lines[i].strip() == header:
            i += 1
            while i < len(lines) and not lines[i].lstrip().startswith("["):
                i += 1
            # Drop a single trailing blank line left by the block.
            while out and out[-1].strip() == "":
                out.pop()
                break
            continue
        out.append(lines[i])
        i += 1
    return "".join(out)
