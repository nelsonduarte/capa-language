"""WASI Fs emission (wasi:filesystem + guest-side attenuation).

Path normalisation / containment, the preopen resolver, exists /
is_dir / mkdir / read / write / list_dir, restrict_to / allows, and
their error helpers. Split out of the former single-file ``_wasi.py``
with no behaviour change.
"""

from __future__ import annotations

from ._constants import _WASI_FS_READ_CHUNK, _WASI_FS_WRITE_CHUNK


class _WasiFsMixin:
    """Fs wrappers of the ``--wasi`` emitter; folded into
    ``WasmEmitter`` via ``_WasiEmissionMixin``."""

    def _wasi_fs_list_dir_needs_str_cmp(self) -> bool:
        """True when ``--wasi`` is active and the program reaches
        ``Fs.list_dir``, whose guest-side wrapper sorts the directory
        entry names via ``$str_cmp`` to match the oracle's
        ``sorted(os.listdir(path))`` order. The default path routes the
        sort through the Python host's ``sorted``, so this gate is
        WASI-only; it ensures ``$str_cmp`` is emitted even when the
        program uses no String ``<`` / ``>`` operator."""
        return self._wasi and ("Fs", "list_dir") in self._used_caps


    def _wasi_fs_uses_attenuation(self) -> bool:
        """True when ``--wasi`` is active and the program reaches the
        FINE Fs attenuators ``restrict_to`` / ``allows`` (Level 2 of
        ``docs/design/wasi-attenuation.md``) OR any privileged Fs op
        that the attenuation gate sits in front of (exists / is_dir /
        mkdir / read / write / list_dir).

        Gates the emission of the guest-side attenuation helpers
        (``$Fs_path_contained`` / ``$Fs_path_allowed``) and the
        ``$Fs_restrict_to`` / ``$Fs_allows`` wrappers. Every migrated Fs
        op consults ``$Fs_path_allowed`` in its fail-closed prologue, so
        the helper must be present whenever any Fs op is, not only when
        ``restrict_to`` / ``allows`` appear textually: a program that
        receives a restricted Fs from a CALLER (across a function
        boundary) and only ever reads through it must still re-check the
        allow-list it carries."""
        return self._wasi and any(
            cap == "Fs"
            and method in (
                "restrict_to", "allows",
                "exists", "is_dir", "mkdir", "read", "write", "list_dir",
            )
            for (cap, method) in self._used_caps
        )


    def _emit_wasi_fs_normalize_helper(self) -> None:
        """``$__fs_normalize (src_ptr i32, src_len i32, dst_ptr i32) ->
        i32`` -> writes the LEXICALLY normalised path into ``[dst_ptr,
        dst_ptr+ret)`` and returns its length ``ret``.

        Collapses ``.`` and ``..`` segments the way ``os.path.realpath``
        does for the NO-SYMLINK case (the lexical part the guest can
        reproduce without a kernel walk), so the containment gate matches
        the Python oracle (``Fs.allows``, which canonicalises via
        ``realpath``) for ``.`` / ``..``. Symlinks are still NOT resolved
        -- that remains the documented Level-2 loss
        (``docs/design/wasi_mode.md``).

        Rules (validated byte-for-byte against ``os.path.normpath`` and a
        9331-input fuzz of the segment reference, scratchpad
        ``wat_sim2.py``):
          - split on ``/``; drop empty segments (``//``, trailing ``/``)
            and ``.``;
          - ``..`` POPS the previous emitted segment when one exists AND
            it is not itself a (locked) leading ``..``; otherwise, for an
            ABSOLUTE path it is dropped (cannot escape root), for a
            RELATIVE path it is KEPT (a leading ``..`` escapes the prefix,
            so containment must fail);
          - an absolute path keeps its single leading ``/``; a relative
            path that normalises to empty becomes ``.``.
        The output is never longer than the input, so the caller sizes the
        destination buffer at ``max(src_len, 1)``.

        WAT-local helpers are inlined: segment append (prepend ``/`` when
        ``dst_len > 0``) and the ``..`` pop / last-segment-is-``..`` test
        (scan back from ``dst_len`` to the previous ``/`` or to 0)."""
        self._write(
            "(func $__fs_normalize (param $src_ptr i32) "
            "(param $src_len i32) (param $dst_ptr i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $is_abs i32)")
        self._write("(local $i i32)")
        self._write("(local $dst_len i32)")
        self._write("(local $seg_start i32)")
        self._write("(local $seg_len i32)")
        self._write("(local $last_start i32)")
        self._write("(local $j i32)")
        # is_abs = src_len > 0 && src[0] == '/'.
        self._write("local.get $src_len")
        self._write("i32.const 0")
        self._write("i32.gt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $src_ptr")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("end")
        self._write("local.set $is_abs")
        # If absolute, the leading '/' is emitted at the end; dst here
        # holds only the RELATIVE remainder (so the pop / leading-'..'
        # logic never crosses the root slash). dst_len starts at 0.
        self._write("i32.const 0")
        self._write("local.set $dst_len")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $scan_done")
        self._indent += 1
        self._write("(loop $scan")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $src_len")
        self._write("i32.ge_u")
        self._write("br_if $scan_done")
        # skip a '/' run.
        self._write("local.get $src_ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # segment = [seg_start, i) until next '/' or end.
        self._write("local.get $i")
        self._write("local.set $seg_start")
        self._write("(block $seg_done")
        self._indent += 1
        self._write("(loop $seg")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $src_len")
        self._write("i32.ge_u")
        self._write("br_if $seg_done")
        self._write("local.get $src_ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._write("br_if $seg_done")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $seg")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._write("local.get $i")
        self._write("local.get $seg_start")
        self._write("i32.sub")
        self._write("local.set $seg_len")
        # '.' (len 1, byte '.') -> drop.
        self._write("local.get $seg_len")
        self._write("i32.const 1")
        self._write("i32.eq")
        self._write("local.get $src_ptr")
        self._write("local.get $seg_start")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # '..' (len 2, both bytes '.') -> pop / drop / keep.
        self._write("local.get $seg_len")
        self._write("i32.const 2")
        self._write("i32.eq")
        self._write("local.get $src_ptr")
        self._write("local.get $seg_start")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("local.get $src_ptr")
        self._write("local.get $seg_start")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # last_start = start of the last emitted segment in dst: scan back
        # from dst_len for the previous '/'; 0 if none.
        self._write("i32.const 0")
        self._write("local.set $last_start")
        self._write("local.get $dst_len")
        self._write("local.set $j")
        self._write("(block $back_done")
        self._indent += 1
        self._write("(loop $back")
        self._indent += 1
        self._write("local.get $j")
        self._write("i32.eqz")
        self._write("br_if $back_done")
        self._write("local.get $dst_ptr")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $j")
        self._write("local.set $last_start")
        self._write("br $back_done")
        self._indent -= 1
        self._write("end")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $j")
        self._write("br $back")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # can_pop = dst_len > 0 AND last segment != '..'. The last segment
        # is '..' iff (dst_len - last_start == 2) and both its bytes are
        # '.'. Compute "last_is_dotdot".
        # If dst_len == 0 -> not poppable.
        self._write("local.get $dst_len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # empty dst: absolute drops, relative keeps '..'.
        self._write("local.get $is_abs")
        self._write("if")
        self._indent += 1
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # relative + empty: append '..' (no leading '/').
        self._write("local.get $dst_ptr")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("local.get $dst_ptr")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("i32.const 2")
        self._write("local.set $dst_len")
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # dst_len > 0: is the last segment exactly '..'?
        self._write("local.get $dst_len")
        self._write("local.get $last_start")
        self._write("i32.sub")
        self._write("i32.const 2")
        self._write("i32.eq")
        self._write("local.get $dst_ptr")
        self._write("local.get $last_start")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("local.get $dst_ptr")
        self._write("local.get $last_start")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 46")
        self._write("i32.eq")
        self._write("i32.and")
        self._write("if")
        self._indent += 1
        # last segment is a locked leading '..': absolute can't happen here
        # (a leading '..' is only kept for relative), so keep another '..'.
        self._write("local.get $is_abs")
        self._write("if")
        self._indent += 1
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # append '/..' (dst_len > 0 so prepend a separator).
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.add")
        self._write("i32.const 47")
        self._write("i32.store8")
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("i32.add")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.const 2")
        self._write("i32.add")
        self._write("i32.add")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("local.get $dst_len")
        self._write("i32.const 3")
        self._write("i32.add")
        self._write("local.set $dst_len")
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # poppable: truncate dst to last_start (drop the '/segment').
        # last_start is the byte AFTER the separator, so the new length is
        # last_start - 1 when last_start > 0 (drop the separator too), or 0.
        self._write("local.get $last_start")
        self._write("i32.eqz")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $last_start")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._indent -= 1
        self._write("end")
        self._write("local.set $dst_len")
        self._write("br $scan")
        self._indent -= 1
        self._write("end")
        # normal segment: append it (prepend '/' when dst_len > 0).
        self._write("local.get $dst_len")
        self._write("i32.const 0")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.add")
        self._write("i32.const 47")
        self._write("i32.store8")
        self._write("local.get $dst_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $dst_len")
        self._indent -= 1
        self._write("end")
        # copy seg_len bytes src[seg_start..] -> dst[dst_len..].
        self._write("i32.const 0")
        self._write("local.set $j")
        self._write("(block $copy_done")
        self._indent += 1
        self._write("(loop $copy")
        self._indent += 1
        self._write("local.get $j")
        self._write("local.get $seg_len")
        self._write("i32.ge_u")
        self._write("br_if $copy_done")
        self._write("local.get $dst_ptr")
        self._write("local.get $dst_len")
        self._write("i32.add")
        self._write("local.get $src_ptr")
        self._write("local.get $seg_start")
        self._write("i32.add")
        self._write("local.get $j")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.store8")
        self._write("local.get $dst_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $dst_len")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $j")
        self._write("br $copy")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._write("br $scan")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Post-loop: build the final layout.
        # Absolute: shift the relative remainder one byte right and write a
        # leading '/'. dst currently holds [0, dst_len) of the relative
        # remainder; we move it up so index 0 is '/'.
        self._write("local.get $is_abs")
        self._write("if")
        self._indent += 1
        # shift bytes right by 1, from the top down (no overlap clobber).
        self._write("local.get $dst_len")
        self._write("local.set $j")
        self._write("(block $shift_done")
        self._indent += 1
        self._write("(loop $shift")
        self._indent += 1
        self._write("local.get $j")
        self._write("i32.eqz")
        self._write("br_if $shift_done")
        self._write("local.get $dst_ptr")
        self._write("local.get $j")
        self._write("i32.add")
        self._write("local.get $dst_ptr")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.store8")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $j")
        self._write("br $shift")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._write("local.get $dst_ptr")
        self._write("i32.const 47")
        self._write("i32.store8")
        self._write("local.get $dst_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Relative + empty result -> '.'.
        self._write("local.get $dst_len")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("local.get $dst_ptr")
        self._write("i32.const 46")
        self._write("i32.store8")
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $dst_len")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_path_contained_helper(self) -> None:
        """``$Fs_path_contained (path_ptr i32, path_len i32,
        pre_ptr i32, pre_len i32) -> i32`` -> 1 iff ``path`` is the
        directory/file ``prefix`` itself or lies under it, by path-segment
        containment AFTER lexical ``.``/``..`` normalisation.

        This is the guest-side analogue of the Python oracle's
        ``Path(os.path.realpath(path)).is_relative_to(
        os.path.realpath(prefix))`` (``Fs.allows``,
        ``capa/runtime/_capabilities.py:173-183``). The guest cannot
        ``realpath`` (no kernel syscall), but it FIRST normalises ``.`` and
        ``..`` in BOTH the path and the prefix lexically (``$__fs_normalize``,
        the ``os.path.normpath``-style collapse), reproducing what
        ``realpath`` does for those segments in the no-symlink case. So
        ``sub/../secret.txt`` normalises to ``secret.txt`` (NOT contained
        in ``sub`` -> denied, matching the oracle) and ``sub/../sub/ok.txt``
        normalises to ``sub/ok.txt`` (contained -> allowed). For paths
        whose ONLY non-canonical feature is ``.``/``..`` the result is now
        BYTE-IDENTICAL to the oracle (``realpath`` also prepends the SAME
        process CWD to a relative path and its relative prefix, so the CWD
        cancels in the containment). SYMLINKS are still NOT resolved -- a
        symlink inside the prefix that points outside it is admitted here
        (caught only by the Level-1 preopen ceiling); that is the only
        remaining Level-2 loss (TOCTOU / symlink) in
        ``docs/design/wasi_mode.md``.

        Algorithm (matching the segment-aware ``is_relative_to``), run on
        the NORMALISED path / prefix:

          1. strip trailing ``/`` from both path and prefix (keep a lone
             ``/`` as ``/``), so ``dir/`` and ``dir`` compare equal.
          2. if the stripped prefix is LONGER than the stripped path,
             not contained.
          3. the first ``pre_len`` bytes of path must equal prefix
             byte-for-byte.
          4. SEGMENT BOUNDARY: either the lengths are equal (path IS the
             prefix) or the byte at ``path[pre_len]`` is ``/`` (the
             prefix ends on a separator, so ``data/ab`` is NOT contained
             in ``data/a``)."""
        self._write(
            "(func $Fs_path_contained (param $path_ptr i32) "
            "(param $path_len i32) (param $pre_ptr i32) "
            "(param $pre_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $pl i32)")
        self._write("(local $ql i32)")
        self._write("(local $i i32)")
        self._write("(local $npath_ptr i32)")
        self._write("(local $npath_len i32)")
        self._write("(local $npre_ptr i32)")
        self._write("(local $npre_len i32)")
        # LEXICAL normalisation of '.' / '..' FIRST, on BOTH path and
        # prefix, so the containment matches the oracle (which canonicalises
        # both via realpath). e.g. "sub/../secret.txt" normalises to
        # "secret.txt" (NOT contained in "sub" -> denied), while
        # "sub/../sub/ok.txt" normalises to "sub/ok.txt" (contained ->
        # allowed). Each output is <= its input length; allocate
        # max(len, 1) so an empty input still has a 1-byte buffer for the
        # '.' result. Symlinks are NOT resolved (the documented Level-2
        # loss); only '.' / '..' are collapsed.
        self._write("local.get $path_len")
        self._write("i32.const 1")
        self._write("local.get $path_len")
        self._write("i32.const 0")
        self._write("i32.gt_u")
        self._write("select")
        self._write("call $alloc")
        self._write("local.set $npath_ptr")
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("local.get $npath_ptr")
        self._write("call $__fs_normalize")
        self._write("local.set $npath_len")
        self._write("local.get $pre_len")
        self._write("i32.const 1")
        self._write("local.get $pre_len")
        self._write("i32.const 0")
        self._write("i32.gt_u")
        self._write("select")
        self._write("call $alloc")
        self._write("local.set $npre_ptr")
        self._write("local.get $pre_ptr")
        self._write("local.get $pre_len")
        self._write("local.get $npre_ptr")
        self._write("call $__fs_normalize")
        self._write("local.set $npre_len")
        # From here the compare runs on the NORMALISED buffers.
        self._write("local.get $npath_ptr")
        self._write("local.set $path_ptr")
        self._write("local.get $npath_len")
        self._write("local.set $path_len")
        self._write("local.get $npre_ptr")
        self._write("local.set $pre_ptr")
        self._write("local.get $npre_len")
        self._write("local.set $pre_len")
        # pl = strip_trailing_slash_len(path); ql = ...(prefix). A
        # trailing '/' is dropped unless the string is a lone '/'.
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("call $__fs_strip_slash_len")
        self._write("local.set $pl")
        self._write("local.get $pre_ptr")
        self._write("local.get $pre_len")
        self._write("call $__fs_strip_slash_len")
        self._write("local.set $ql")
        # if ql > pl, not contained.
        self._write("local.get $ql")
        self._write("local.get $pl")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Compare the first ql bytes: path[i] == prefix[i] for i<ql.
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $cmp_done")
        self._indent += 1
        self._write("(loop $cmp")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $ql")
        self._write("i32.ge_u")
        self._write("br_if $cmp_done")
        # if path_ptr[i] != pre_ptr[i] -> return 0
        self._write("local.get $path_ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("local.get $pre_ptr")
        self._write("local.get $i")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $cmp")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Segment boundary: equal lengths (path IS prefix) -> contained.
        self._write("local.get $pl")
        self._write("local.get $ql")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Otherwise contained iff path[ql] == '/' (0x2f).
        self._write("local.get $path_ptr")
        self._write("local.get $ql")
        self._write("i32.add")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.eq")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_strip_slash_helper(self) -> None:
        """``$__fs_strip_slash_len (ptr i32, len i32) -> i32`` -> the
        length of ``[ptr, ptr+len)`` with trailing ``/`` bytes removed,
        but never below 1 (a lone ``/`` keeps length 1).

        Matches the oracle's ``rstrip('/')`` normalisation used before
        the containment compare so ``dir/`` and ``dir`` are the same
        prefix. Pure length arithmetic; reads no bytes past ``ptr+len``."""
        self._write(
            "(func $__fs_strip_slash_len (param $ptr i32) "
            "(param $len i32) (result i32)"
        )
        self._indent += 1
        self._write("(block $strip_done")
        self._indent += 1
        self._write("(loop $strip")
        self._indent += 1
        # if len <= 1, stop (keep a lone '/' or empty as-is).
        self._write("local.get $len")
        self._write("i32.const 1")
        self._write("i32.le_u")
        self._write("br_if $strip_done")
        # if last byte (ptr + len - 1) != '/', stop.
        self._write("local.get $ptr")
        self._write("local.get $len")
        self._write("i32.add")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.load8_u")
        self._write("i32.const 47")
        self._write("i32.ne")
        self._write("br_if $strip_done")
        # len -= 1; continue.
        self._write("local.get $len")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $len")
        self._write("br $strip")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._write("local.get $len")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_path_allowed_helper(self) -> None:
        """``$Fs_path_allowed (handle i32, path_ptr i32, path_len i32)
        -> i32`` -> 1 iff the Fs value ``handle`` admits ``path``.

        The shared containment test behind both ``allows`` (its whole
        body) and every privileged Fs op (its fail-closed prologue):

          handle == 0  -> 1 (unrestricted root Fs: every path allowed)
          else         -> handle is a pointer to a List<String> header
                          (len@0, data_ptr@8) whose entries are the
                          canonicalised prefixes accumulated by
                          ``restrict_to``. ``path`` is admitted iff it is
                          contained (``$Fs_path_contained``) in EVERY
                          stored prefix.

        Mirrors ``Fs.allows`` exactly: the oracle requires
        ``is_relative_to`` ALL prefixes (the INTERSECTION of the prefix
        containments, ``capa/runtime/_capabilities.py:180-183``), so a
        single non-containing prefix denies. An empty prefix list (which
        ``restrict_to`` never produces -- it always adds one prefix)
        would vacuously allow; a fresh non-zero allow-list always holds
        at least one prefix."""
        self._emit_wasi_fs_strip_slash_helper()
        self._write(
            "(func $Fs_path_allowed (param $handle i32) "
            "(param $path_ptr i32) (param $path_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $data i32)")
        self._write("(local $count i32)")
        self._write("(local $i i32)")
        self._write("(local $entry i32)")
        # Unrestricted root: handle 0 admits every path.
        self._write("local.get $handle")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 1")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Restricted: require containment in EVERY stored prefix.
        # count = header.len@0; data = header.data_ptr@8.
        self._write("local.get $handle")
        self._write("i32.load offset=0")
        self._write("local.set $count")
        self._write("local.get $handle")
        self._write("i32.load offset=8")
        self._write("local.set $data")
        self._write("i32.const 0")
        self._write("local.set $i")
        self._write("(block $allow_done")
        self._indent += 1
        self._write("(loop $scan_prefixes")
        self._indent += 1
        # if i >= count, every prefix contained -> break (allowed).
        self._write("local.get $i")
        self._write("local.get $count")
        self._write("i32.ge_u")
        self._write("br_if $allow_done")
        # entry = data + i*8 (packed (pre_ptr@0, pre_len@4)).
        self._write("local.get $data")
        self._write("local.get $i")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $entry")
        # if NOT contained(path, entry.prefix) -> return 0 (denied).
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("local.get $entry")
        self._write("i32.load offset=0")
        self._write("local.get $entry")
        self._write("i32.load offset=4")
        self._write("call $Fs_path_contained")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # i += 1; continue.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $scan_prefixes")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Contained in all prefixes (or count was 0): allowed.
        self._write("i32.const 1")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_allows_wrapper(self) -> None:
        """``$Fs_allows (handle i32, path_ptr i32, path_len i32) ->
        i32`` -> the Bool result of ``fs.allows(path)``.

        Matches the call shape ``_emit_cap_allows_with_handle`` produces
        (receiver handle + path (ptr, len) -> i32 Bool). Delegates
        straight to the shared ``$Fs_path_allowed`` so the query answer
        is identical to the gate every privileged Fs op consults (no
        guest-side divergence) and to the Python oracle for canonical
        paths."""
        self._write(
            "(func $Fs_allows (param $handle i32) (param $path_ptr i32) "
            "(param $path_len i32) (result i32)"
        )
        self._indent += 1
        self._write("local.get $handle")
        self._write("local.get $path_ptr")
        self._write("local.get $path_len")
        self._write("call $Fs_path_allowed")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_restrict_to_wrapper(self) -> None:
        """``$Fs_restrict_to (handle i32, pre_ptr i32, pre_len i32) ->
        i32`` -> a fresh Fs value (pointer to a new ``List<String>``
        prefix allow-list).

        Matches the call shape ``_emit_fs_restrict_to`` produces
        (receiver handle + the prefix String as (ptr, len)).

        Builds the UNION of the parent's prefix list with the new
        ``prefix``, identical to ``Fs.restrict_to``
        (``existing | {canon}``, ``capa/runtime/_capabilities.py:168-171``):

          parent unrestricted (handle == 0): result = [prefix].
          parent restricted: result = parent's prefixes ++ [prefix].

        Unlike Env (which INTERSECTS its key set), Fs ACCUMULATES
        prefixes by union and ``allows`` then requires containment in ALL
        of them (so the EFFECTIVE admitted set is the intersection of the
        containments -- the monotone narrowing the model intends; see the
        design doc section 2.2). The prefix BYTES are shared, not copied
        (the prefix arg already lives in linear memory for the program's
        lifetime); only the (ptr, len) pairs are stored. The new header
        is always non-zero (``$alloc`` never returns 0), so a restricted
        Fs is always distinguishable from the unrestricted 0 sentinel."""
        self._write(
            "(func $Fs_restrict_to (param $handle i32) "
            "(param $pre_ptr i32) (param $pre_len i32) (result i32)"
        )
        self._indent += 1
        self._write("(local $header i32)")
        self._write("(local $out_data i32)")
        self._write("(local $parent_n i32)")
        self._write("(local $parent_data i32)")
        self._write("(local $out_n i32)")
        # Parent prefix count: 0 when handle is the unrestricted root,
        # else header.len@0.
        self._write("local.get $handle")
        self._write("i32.eqz")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $handle")
        self._write("i32.load offset=0")
        self._indent -= 1
        self._write("end")
        self._write("local.set $parent_n")
        # out_n = parent_n + 1 (the new prefix).
        self._write("local.get $parent_n")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $out_n")
        # Allocate the result header (16 bytes) + data buffer
        # (out_n * 8 bytes for the packed (ptr, len) pairs).
        self._write("i32.const 16")
        self._write("call $alloc")
        self._write("local.set $header")
        self._write("local.get $out_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $out_data")
        # Copy the parent's prefix pairs (parent_n * 8 bytes) into the
        # front of out_data, when the parent is restricted.
        self._write("local.get $parent_n")
        self._write("if")
        self._indent += 1
        self._write("local.get $handle")
        self._write("i32.load offset=8")
        self._write("local.set $parent_data")
        # memory.copy(dst=out_data, src=parent_data, n=parent_n*8).
        self._write("local.get $out_data")
        self._write("local.get $parent_data")
        self._write("local.get $parent_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("memory.copy")
        self._indent -= 1
        self._write("end")
        # Append the new prefix at out_data[parent_n] = (pre_ptr, pre_len).
        self._write("local.get $out_data")
        self._write("local.get $parent_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $pre_ptr")
        self._write("i32.store offset=0")
        self._write("local.get $out_data")
        self._write("local.get $parent_n")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $pre_len")
        self._write("i32.store offset=4")
        # Fill the List<String> header: len@0 = cap@4 = out_n,
        # data_ptr@8 = out_data, pad@12 = 0.
        self._write("local.get $header")
        self._write("local.get $out_n")
        self._write("i32.store offset=0")
        self._write("local.get $header")
        self._write("local.get $out_n")
        self._write("i32.store offset=4")
        self._write("local.get $header")
        self._write("local.get $out_data")
        self._write("i32.store offset=8")
        self._write("local.get $header")
        self._write("i32.const 0")
        self._write("i32.store offset=12")
        # Return the header pointer (the new restricted Fs value).
        self._write("local.get $header")
        self._indent -= 1
        self._write(")")

    # ----- Fs metadata via wasi:filesystem (no streams) ----------


    def _emit_wasi_fs_preopen_desc_helper(self) -> None:
        """``$__wasi_fs_preopen_desc (idx i32) -> i32`` -> the
        directory descriptor handle for preopen ``idx``.

        Lazily calls ``preopens.get-directories`` ONCE (an
        indirect-return ``list<tuple<descriptor, string>>``) into the
        reserved 8-byte scratch (data_ptr @0, len @4), caches the data
        pointer in the ``$__wasi_fs_pre_data`` global, and returns the
        descriptor handle of the ``idx``-th element. Each element is a
        12-byte record: descriptor(own i32) @0, str_ptr @4, str_len
        @8; only the handle @0 is needed (the compiler resolved each
        literal Fs path to its preopen index + basename, so the guest
        never matches the preopen path strings at runtime).

        The descriptors are returned in the host's preopen registration
        order, which the host installs in the SAME sorted order the
        compiler used to assign indices (see capa.ir._fs_ceiling), so
        index K names directory K. The descriptors live for the
        component's lifetime (they are the preopen roots, never
        dropped); caching the list pointer is sound."""
        scratch = self._wasi_fs_scratch_offset
        self._write(
            "(func $__wasi_fs_preopen_desc (param $idx i32) (result i32)"
        )
        self._indent += 1
        # First call: fetch + cache the preopen list data pointer.
        self._write("global.get $__wasi_fs_pre_inited")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_fs_get_directories")
        self._write(f"i32.const {scratch}")
        self._write("i32.load offset=0")
        self._write("global.set $__wasi_fs_pre_data")
        self._write("i32.const 1")
        self._write("global.set $__wasi_fs_pre_inited")
        self._indent -= 1
        self._write("end")
        # desc = pre_data[idx].handle@0 = *(pre_data + idx*12)
        self._write("global.get $__wasi_fs_pre_data")
        self._write("local.get $idx")
        self._write("i32.const 12")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i32.load offset=0")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_exists_wrapper(self) -> None:
        """``$Fs_exists (handle i32, full_ptr i32, full_len i32,
        idx i32, rel_ptr i32, rel_len i32) -> i32``.

        FAIL-CLOSED ATTENUATION (guest-side, Level 2): before touching
        the filesystem, consult the receiver Fs's prefix allow-list via
        ``$Fs_path_allowed(handle, full_path)`` (the FULL original
        literal path, against which the ``restrict_to`` prefixes were
        recorded). When the Fs is restricted and the path is not
        admitted, return 0 (fail-closed-as-absent) WITHOUT any
        ``stat-at`` -- byte-identical to the Python oracle
        (``if not self.allows(path): return False``,
        ``capa/runtime/_capabilities.py:259-261``). An unrestricted Fs
        (``handle == 0``) short-circuits to allowed.

        stat-at(preopen_desc(idx), path-flags=symlink-follow(1),
        rel_path) into the reserved scratch; the result discriminant
        @0 is 0 on Ok (the entry exists) and non-zero on Err
        (no-entry, ...). Returns 1 when the entry exists, 0 otherwise
        -- byte-identical to the Python oracle's
        ``os.path.exists`` gated by the cap (the preopen is the Level-1
        ceiling, the allow-list the Level-2 fine attenuation)."""
        scratch = self._wasi_fs_scratch_offset
        self._write(
            "(func $Fs_exists (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (result i32)"
        )
        self._indent += 1
        # Fail-closed: denied path reports absent (0) without a syscall.
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")  # path-flags: symlink-follow
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_fs_stat_at")
        # exists iff discriminant byte @0 == 0 (Ok).
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_is_dir_wrapper(self) -> None:
        """``$Fs_is_dir (idx i32, rel_ptr i32, rel_len i32) -> i32``.

        stat-at as ``exists``; on Ok, the ``descriptor-stat`` Ok
        payload starts at offset 8 (u64 alignment), and its first
        field ``%type`` is a ``descriptor-type`` enum (1 byte), where
        value 3 == ``directory`` in the wasi:filesystem 0.2.0 enum
        order. Returns 1 iff the stat succeeded AND the type is
        directory, else 0 -- byte-identical to the oracle's
        ``os.path.isdir`` (a denied / absent path reports false, so the
        cap leaks no path type).

        FAIL-CLOSED ATTENUATION (guest-side, Level 2): same prologue as
        ``$Fs_exists`` -- a path the receiver Fs does not admit reports
        false (0) WITHOUT a ``stat-at``, matching the Python oracle
        (``if not self.allows(path): return False``,
        ``capa/runtime/_capabilities.py:267-269``)."""
        scratch = self._wasi_fs_scratch_offset
        self._write(
            "(func $Fs_is_dir (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (result i32)"
        )
        self._indent += 1
        # Fail-closed: denied path reports not-a-dir (0) without a syscall.
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_fs_stat_at")
        # if Err (disc != 0) -> 0; else type@+8 == 3 (directory).
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=0")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=8")
        self._write("i32.const 3")
        self._write("i32.eq")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_mkdir_wrapper(self) -> None:
        """``$Fs_mkdir (idx i32, rel_ptr i32, rel_len i32,
        ret_area i32)`` -> writes a ``result<_, io-error>`` (20-byte
        canonical-ABI shape) into ``ret_area``.

        Matches the call shape ``_emit_wasi_fs_metadata_call`` produces
        for mkdir (preopen index + rel (ptr, len) + ret_area), so the
        existing ``result_unit_io_error`` materialiser lifts the result
        into a Capa ``Result<Unit, IoError>`` unchanged, exactly as the
        capa:host mkdir does.

        create-directory-at(preopen_desc(idx), rel_path) into the
        wasi-call scratch. Idempotent (matching the oracle's
        ``os.makedirs(path, exist_ok=True)``): an Ok (disc @0 == 0) is
        success, and an Err whose error-code @+1 == 7 (``exist`` in the
        wasi:filesystem 0.2.0 enum order) is also treated as success;
        both write ``ret_area.tag = 0`` (Ok<Unit>). Any other Err
        writes ``ret_area.tag = 1`` plus an IoError record (message =
        the interned ``mkdir failed`` string, empty cause) into the
        Err arm fields the materialiser reads (m_ptr @4, m_len @8,
        c_ptr @12, c_len @16).

        One segment per call: ``create-directory-at`` creates ONE
        directory relative to the preopen descriptor. The full
        recursive ``os.makedirs(exist_ok=True)`` (creating every missing
        intermediate segment) is replicated at the CALL SITE, not here:
        ``_emit_wasi_fs_metadata_call`` splits the resolved relative
        path into its cumulative prefixes (``a`` / ``a/b`` / ``a/b/c``,
        all compile-time literals) and calls this wrapper once per
        prefix in order, sharing one ret area and short-circuiting on a
        genuine error. Each call here is idempotent, so re-creating an
        already-existing intermediate (or the leaf) is an Ok, matching
        the oracle. This wrapper therefore stays a single-segment
        primitive; the recursion is the sequence the call site emits.

        FAIL-CLOSED ATTENUATION (guest-side, Level 2): before any
        ``create-directory-at``, consult ``$Fs_path_allowed(handle,
        full_path)``. When the Fs is restricted and the path is not
        admitted, write the deny ``Err(IoError)`` and return WITHOUT
        creating anything -- byte-identical (on the Result discriminant)
        to the Python oracle (``if not self.allows(path): return
        self._deny(...)``, ``capa/runtime/_capabilities.py:275-276``).
        Because the call site calls this wrapper once per cumulative
        mkdir prefix sharing one full path + ret area, the gate is the
        SAME full literal for every prefix call; a denied target denies
        the whole sequence on the first prefix and short-circuits."""
        scratch = self._wasi_fs_scratch_offset
        msg_off, msg_len = self._intern_string("mkdir failed")
        self._write(
            "(func $Fs_mkdir (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        # Fail-closed: denied path writes Err(IoError), creates nothing.
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_unit_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write(f"i32.const {scratch}")
        self._write("call $wasi_fs_create_directory_at")
        # success = Ok (disc @0 == 0) OR Err code @+1 == 7 (exist).
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write(f"i32.const {scratch}")
        self._write("i32.load8_u offset=1")
        self._write("i32.const 7")
        self._write("i32.eq")
        self._write("i32.or")
        self._write("if")
        self._indent += 1
        # Ok<Unit>: tag = 0.
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Err<io-error>: tag = 1; message = interned string; cause "".
        self._write("local.get $ret_area")
        self._write("i32.const 1")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_off}")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_len}")
        self._write("i32.store offset=8")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=12")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=16")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_unit_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_unit_io_error`` 20-byte shape: tag@0 = 1, message = the
        interned fixed string (m_ptr@4, m_len@8), empty cause (c_ptr@12 =
        0, c_len@16 = 0). Shared by the ``mkdir`` fail-closed prologue
        (the deny path) and identical to ``_emit_wasi_fs_write_err``'s
        body; ``$ret_area`` is in scope (the wrapper's trailing param)."""
        self._write("local.get $ret_area")
        self._write("i32.const 1")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_off}")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_len}")
        self._write("i32.store offset=8")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=12")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=16")


    def _emit_wasi_fs_mkdir_recursive_helper(self) -> None:
        """``$Fs_mkdir_recursive (handle, full_ptr, full_len, idx,
        rel_ptr, rel_len, ret_area)`` -> recursive ``mkdir`` over a
        RUNTIME relative path (WASI Fs layer b1, dynamic ``--preopen``).

        A dynamic ``fs.mkdir(path)`` path is not known at compile time, so
        the literal call site's cumulative-prefix unrolling cannot run.
        This helper replicates ``os.makedirs(exist_ok=True)`` AT RUNTIME:
        it scans the relative path for ``/`` separators and calls the
        existing single-segment ``$Fs_mkdir`` once per cumulative prefix
        (``a`` then ``a/b`` then ``a/b/c``), in order, each idempotent
        (``$Fs_mkdir`` maps ``exist`` to Ok). It SHORT-CIRCUITS the
        moment a prefix writes a genuine ``Err`` (ret_area tag@0 != 0),
        leaving that Err in ``ret_area`` for the materialiser -- exactly
        the literal path's behaviour, so a multi-segment dynamic mkdir is
        byte-parity with the oracle. The FULL path is passed unchanged to
        every ``$Fs_mkdir`` call so the fine-attenuation gate sees the
        same full path each time (a denied target denies the first
        prefix). ``$Fs_mkdir`` is REUSED verbatim; this helper only
        sequences the prefixes a runtime path cannot pre-enumerate."""
        self._write(
            "(func $Fs_mkdir_recursive (param $handle i32) "
            "(param $full_ptr i32) (param $full_len i32) (param $idx i32) "
            "(param $rel_ptr i32) (param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $k i32)")
        # Walk k = 1 .. rel_len; at each k that is either a '/' boundary
        # (rel[k] == '/') or the end (k == rel_len), mkdir the prefix
        # rel[0:k]. A leading '/' yields a zero-length first prefix the
        # boundary loop never emits (k starts at 1 and rel[0]=='/' is a
        # boundary that mkdirs rel[0:1] == "/", which $Fs_mkdir handles).
        self._write("i32.const 1")
        self._write("local.set $k")
        self._write("(block $done")
        self._indent += 1
        self._write("(loop $seg")
        self._indent += 1
        # if k > rel_len -> done.
        self._write("local.get $k")
        self._write("local.get $rel_len")
        self._write("i32.gt_u")
        self._write("br_if $done")
        # boundary = (k == rel_len) OR (rel[k] == '/'). Guard the load
        # behind the end check so k == rel_len never reads out of range.
        self._write("local.get $k")
        self._write("local.get $rel_len")
        self._write("i32.eq")
        self._write("if (result i32)")
        self._indent += 1
        self._write("i32.const 1")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $rel_ptr")
        self._write("local.get $k")
        self._write("i32.add")
        self._write("i32.load8_u offset=0")
        self._write("i32.const 47")  # '/'
        self._write("i32.eq")
        self._indent -= 1
        self._write("end")
        self._write("if")
        self._indent += 1
        # mkdir(prefix = rel[0:k]).
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("local.get $idx")
        self._write("local.get $rel_ptr")    # prefix ptr = rel_ptr
        self._write("local.get $k")          # prefix len = k
        self._write("local.get $ret_area")
        self._write("call $Fs_mkdir")
        # Short-circuit on a genuine Err (tag@0 != 0).
        self._write("local.get $ret_area")
        self._write("i32.load8_u offset=0")
        self._write("br_if $done")
        self._indent -= 1
        self._write("end")
        # k += 1; continue.
        self._write("local.get $k")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $k")
        self._write("br $seg")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")

    # ----- Fs.read via wasi:filesystem + wasi:io/streams ---------


    def _emit_wasi_fs_read_wrapper(self) -> None:
        """``$Fs_read (idx i32, rel_ptr i32, rel_len i32, ret_area i32)``
        -> writes a ``result<string, io-error>`` (20-byte canonical-ABI
        shape) into ``ret_area``.

        Matches the call shape ``_emit_wasi_fs_read_call`` produces
        (preopen index + rel (ptr, len) + ret_area), so the existing
        ``result_string_io_error`` materialiser lifts the result into a
        Capa ``Result<String, IoError>`` unchanged, exactly as the
        capa:host read does.

        Sequence (validated against wasm-tools 1.249.0 / wasmtime
        44.0.1; convention captured in docs/design/wasi_mode.md):

          1. resolve the preopen descriptor for ``idx``.
          2. ``open-at(desc, symlink-follow, rel, open-flags=0,
             descriptor-flags=read)`` -> result<descriptor, error-code>.
             On Err: write Err(IoError) and return (nothing opened).
          3. ``read-via-stream(file_desc, offset=0)`` ->
             result<input-stream, error-code>. On Err: drop the opened
             descriptor, write Err, return.
          4. LOOP ``blocking-read(stream, CHUNK)`` ->
             result<list<u8>, stream-error>:
               * Ok(chunk): append chunk bytes to a heap accumulation
                 buffer, continue.
               * Err(stream-error): variant disc @+4 == 1 is ``closed``
                 = EOF (the normal terminator) -> break and build the
                 String. disc @+4 == 0 is ``last-operation-failed`` ->
                 drop the carried error handle (@+8), drop the stream +
                 descriptor, write Err, return.
          5. drop the input-stream, then drop the opened descriptor
             (resource OWN handles; the preopen ROOTS are never
             dropped), and write Ok(String) = (accumulated buffer ptr,
             accumulated length). The accumulated bytes are the raw file
             bytes; the Capa String is UTF-8 by construction, matching
             the Python oracle's ``f.read()`` (UTF-8 decode) and the
             capa:host bridge.

        Resource drops fire on EVERY exit path (success, EOF, and the
        two error paths) so no OWN handle leaks and none is dropped
        twice. The accumulation buffer grows by re-allocating a larger
        block and copying when a chunk would overflow the current
        capacity, reusing ``$alloc`` + ``$memcpy`` (the same heap infra
        the List / String builders use)."""
        open_ret = self._wasi_fs_read_scratch_offset            # 8 bytes
        rvs_ret = self._wasi_fs_read_scratch_offset + 8         # 8 bytes
        br_ret = self._wasi_fs_read_scratch_offset + 16         # 12 bytes
        chunk = _WASI_FS_READ_CHUNK
        msg_off, msg_len = self._intern_string("failed to read file")
        self._write(
            "(func $Fs_read (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $desc i32)")
        self._write("(local $stream i32)")
        self._write("(local $buf i32)")
        self._write("(local $buf_cap i32)")
        self._write("(local $buf_len i32)")
        self._write("(local $chunk_ptr i32)")
        self._write("(local $chunk_len i32)")
        self._write("(local $need i32)")
        self._write("(local $newcap i32)")
        self._write("(local $newbuf i32)")
        # Fail-closed attenuation (guest-side, Level 2): a path the
        # receiver Fs does not admit writes Err(IoError) and returns
        # WITHOUT opening anything, byte-identical (on the Result
        # discriminant) to the Python oracle (``if not self.allows(path):
        # return self._deny("read", path)``,
        # capa/runtime/_capabilities.py:231-232).
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_read_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # open-at(preopen_desc(idx), path-flags=symlink-follow(1), rel,
        # open-flags=0, descriptor-flags=read(1), open_ret).
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")            # path-flags: symlink-follow
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write("i32.const 0")            # open-flags: none
        self._write("i32.const 1")            # descriptor-flags: read
        self._write(f"i32.const {open_ret}")
        self._write("call $wasi_fs_open_at")
        # if open Err (disc @0 != 0): write Err, return.
        self._write(f"i32.const {open_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_read_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # desc = open_ret.value @4 (the opened OWN descriptor).
        self._write(f"i32.const {open_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $desc")
        # read-via-stream(desc, offset=0, rvs_ret).
        self._write("local.get $desc")
        self._write("i64.const 0")
        self._write(f"i32.const {rvs_ret}")
        self._write("call $wasi_fs_read_via_stream")
        # if rvs Err: drop desc, write Err, return.
        self._write(f"i32.const {rvs_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_read_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # stream = rvs_ret.value @4 (the OWN input-stream).
        self._write(f"i32.const {rvs_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $stream")
        # Accumulation buffer: start empty (len 0, cap 0, ptr from a
        # zero-size alloc, a stable non-overlapping heap pointer).
        self._write("i32.const 0")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $buf_cap")
        self._write("i32.const 0")
        self._write("local.set $buf_len")
        # Loop blocking-read(stream, CHUNK, br_ret).
        self._write("(block $read_done")
        self._indent += 1
        self._write("(loop $read_loop")
        self._indent += 1
        self._write("local.get $stream")
        self._write(f"i64.const {chunk}")
        self._write(f"i32.const {br_ret}")
        self._write("call $wasi_io_blocking_read")
        # if Ok (disc @0 == 0): append chunk; else handle stream-error.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load8_u offset=0")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # chunk_ptr = br_ret.data_ptr @4; chunk_len = br_ret.len @8.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $chunk_ptr")
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=8")
        self._write("local.set $chunk_len")
        # Grow the buffer if buf_len + chunk_len > buf_cap.
        self._write("local.get $buf_len")
        self._write("local.get $chunk_len")
        self._write("i32.add")
        self._write("local.set $need")
        self._write("local.get $need")
        self._write("local.get $buf_cap")
        self._write("i32.gt_u")
        self._write("if")
        self._indent += 1
        # newcap = max(need, buf_cap*2, CHUNK); grow geometrically so a
        # large file does not realloc once per chunk.
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._write("local.get $need")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $need")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._indent -= 1
        self._write("end")
        self._write("local.set $newcap")
        # newbuf = alloc(newcap); copy old bytes; buf = newbuf.
        self._write("local.get $newcap")
        self._write("call $alloc")
        self._write("local.set $newbuf")
        # memory.copy(dst=newbuf, src=buf, n=buf_len).
        self._write("local.get $newbuf")
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("memory.copy")
        self._write("local.get $newbuf")
        self._write("local.set $buf")
        self._write("local.get $newcap")
        self._write("local.set $buf_cap")
        self._indent -= 1
        self._write("end")
        # memory.copy(dst=buf + buf_len, src=chunk_ptr, n=chunk_len).
        self._write("local.get $buf")
        self._write("local.get $buf_len")
        self._write("i32.add")
        self._write("local.get $chunk_ptr")
        self._write("local.get $chunk_len")
        self._write("memory.copy")
        # buf_len += chunk_len; continue.
        self._write("local.get $buf_len")
        self._write("local.get $chunk_len")
        self._write("i32.add")
        self._write("local.set $buf_len")
        self._write("br $read_loop")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        # Err(stream-error): variant disc @+4. 1 == closed (EOF,
        # normal). 0 == last-operation-failed(error) -> drop the carried
        # error handle @+8, then fall through to the shared cleanup as
        # an error path.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=4")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # last-operation-failed: drop the error resource, drop stream +
        # descriptor, write Err, return.
        self._write(f"i32.const {br_ret}")
        self._write("i32.load offset=8")
        self._write("call $wasi_io_drop_error")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_read_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # closed: EOF, the normal terminator. Break to build the String.
        self._write("br $read_done")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # EOF reached: drop the stream, then the opened descriptor.
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_input_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        # Ok(String): tag=0, ptr=buf @4, len=buf_len @8.
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write("local.get $buf")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write("local.get $buf_len")
        self._write("i32.store offset=8")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_read_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_string_io_error`` 20-byte shape: tag@0 = 1, message =
        the interned fixed string (m_ptr@4, m_len@8), empty cause
        (c_ptr@12 = 0, c_len@16 = 0).

        The message is fixed (``failed to read file``) rather than the
        Python oracle's path-and-errno cause, which carries OS-specific
        bytes no cross-backend comparison can reproduce; parity is on
        the Result DISCRIMINANT (is_err), as the metadata / Net error
        paths already assert. ``$ret_area`` is in scope (the wrapper's
        trailing param)."""
        self._write("local.get $ret_area")
        self._write("i32.const 1")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_off}")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_len}")
        self._write("i32.store offset=8")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=12")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=16")

    # ----- Fs.write via wasi:filesystem + wasi:io/streams --------


    def _emit_wasi_fs_write_wrapper(self) -> None:
        """``$Fs_write (idx i32, rel_ptr i32, rel_len i32,
        content_ptr i32, content_len i32, ret_area i32)`` -> writes a
        ``result<_, io-error>`` (20-byte canonical-ABI shape) into
        ``ret_area``.

        Matches the call shape ``_emit_wasi_fs_write_call`` produces
        (preopen index + rel (ptr, len) + content (ptr, len) + ret_area),
        so the existing ``result_unit_io_error`` materialiser lifts the
        result into a Capa ``Result<Unit, IoError>`` unchanged, exactly
        as the capa:host write does.

        Sequence (the inverse of ``$Fs_read``; convention captured in
        docs/design/wasi_mode.md):

          1. resolve the preopen descriptor for ``idx``.
          2. ``open-at(desc, symlink-follow, rel, open-flags=create|
             truncate (9), descriptor-flags=write (2))`` ->
             result<descriptor, error-code>. create makes a new file,
             truncate empties an existing one (matching the Python
             oracle's ``open(p, "w")`` create-or-truncate). On Err: write
             Err(IoError) and return (nothing opened).
          3. ``write-via-stream(file_desc, offset=0)`` ->
             result<output-stream, error-code>. On Err: drop the opened
             descriptor, write Err, return.
          4. LOOP over ``content`` in chunks of <= ``_WASI_FS_WRITE_CHUNK``
             (4096, one OS page) bytes:
               ``blocking-write-and-flush(stream, (cursor, n))`` ->
               result<_, stream-error>. blocking-write-and-flush
               self-limits to a page AND flushes, so the wrapper never
               has to track the check-write permit window. On Err: drop
               the carried error handle (last-operation-failed), drop
               stream + descriptor, write Err, return.
             A zero-length ``content`` runs the loop zero times; the file
             is already truncated empty by open, so a 0-byte file results
             (matching ``open(p, "w")`` + ``write("")``).
          5. ``blocking-flush(stream)`` -> result<_, stream-error> for
             durability of any buffered bytes (harmless when nothing was
             written). On Err: same drop+Err cleanup.
          6. drop the output-stream, then drop the opened descriptor
             (resource OWN handles; the preopen ROOTS are never dropped),
             and write Ok(Unit) = tag 0.

        Resource drops fire on EVERY exit path (success and the error
        paths) so no OWN handle leaks and none is dropped twice. The
        content bytes are NOT copied: they already live in linear memory
        (the String ``content`` argument) and each chunk is handed to
        blocking-write-and-flush as ``(content_ptr + cursor, n)``."""
        wvs_ret = self._wasi_fs_write_scratch_offset            # 8 bytes
        wf_ret = self._wasi_fs_write_scratch_offset + 8         # 12 bytes
        chunk = _WASI_FS_WRITE_CHUNK
        msg_off, msg_len = self._intern_string("failed to write file")
        self._write(
            "(func $Fs_write (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $content_ptr i32) "
            "(param $content_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $desc i32)")
        self._write("(local $stream i32)")
        self._write("(local $cursor i32)")
        self._write("(local $remaining i32)")
        self._write("(local $n i32)")
        # Fail-closed attenuation (guest-side, Level 2): a path the
        # receiver Fs does not admit writes Err(IoError) and returns
        # WITHOUT opening / truncating anything, byte-identical (on the
        # Result discriminant) to the Python oracle (``if not
        # self.allows(path): return self._deny("write", path)``,
        # capa/runtime/_capabilities.py:242-243). The oracle never
        # touches the file on a deny, and neither does this (open-at is
        # reached only after the gate passes), so no empty file is left
        # behind for a denied write -- the same guarantee the capa:host
        # post-open guard gives.
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_write_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # open-at(preopen_desc(idx), path-flags=symlink-follow(1), rel,
        # open-flags=create|truncate(9), descriptor-flags=write(2),
        # wvs_ret). The 8-byte wvs_ret slot holds open-at's
        # result<descriptor, error-code> first, then is reused for
        # write-via-stream's result<output-stream, error-code>: the two
        # never overlap in time (write-via-stream runs only after open's
        # result has been consumed into $desc).
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")            # path-flags: symlink-follow
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write("i32.const 9")            # open-flags: create|truncate
        self._write("i32.const 2")            # descriptor-flags: write
        self._write(f"i32.const {wvs_ret}")
        self._write("call $wasi_fs_open_at")
        # if open Err (disc @0 != 0): write Err, return (nothing opened).
        self._write(f"i32.const {wvs_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_write_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # desc = open result.value @4 (the opened OWN descriptor).
        self._write(f"i32.const {wvs_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $desc")
        # write-via-stream(desc, offset=0, wvs_ret).
        self._write("local.get $desc")
        self._write("i64.const 0")
        self._write(f"i32.const {wvs_ret}")
        self._write("call $wasi_fs_write_via_stream")
        # if wvs Err: drop desc, write Err, return.
        self._write(f"i32.const {wvs_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_write_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # stream = wvs_ret.value @4 (the OWN output-stream).
        self._write(f"i32.const {wvs_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $stream")
        # cursor = 0; remaining = content_len.
        self._write("i32.const 0")
        self._write("local.set $cursor")
        self._write("local.get $content_len")
        self._write("local.set $remaining")
        # Loop blocking-write-and-flush(stream, (content_ptr+cursor, n)).
        self._write("(block $write_done")
        self._indent += 1
        self._write("(loop $write_loop")
        self._indent += 1
        # if remaining == 0, done.
        self._write("local.get $remaining")
        self._write("i32.eqz")
        self._write("br_if $write_done")
        # n = min(remaining, CHUNK).
        self._write("local.get $remaining")
        self._write(f"i32.const {chunk}")
        self._write("i32.lt_u")
        self._write("if (result i32)")
        self._indent += 1
        self._write("local.get $remaining")
        self._indent -= 1
        self._write("else")
        self._indent += 1
        self._write(f"i32.const {chunk}")
        self._indent -= 1
        self._write("end")
        self._write("local.set $n")
        # blocking-write-and-flush(stream, content_ptr+cursor, n, wf_ret).
        self._write("local.get $stream")
        self._write("local.get $content_ptr")
        self._write("local.get $cursor")
        self._write("i32.add")
        self._write("local.get $n")
        self._write(f"i32.const {wf_ret}")
        self._write("call $wasi_io_blocking_write_and_flush")
        # if Err (disc @0 != 0): handle stream-error and bail.
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_write_stream_err(wf_ret, msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # cursor += n; remaining -= n; continue.
        self._write("local.get $cursor")
        self._write("local.get $n")
        self._write("i32.add")
        self._write("local.set $cursor")
        self._write("local.get $remaining")
        self._write("local.get $n")
        self._write("i32.sub")
        self._write("local.set $remaining")
        self._write("br $write_loop")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Final blocking-flush(stream, wf_ret) for durability.
        self._write("local.get $stream")
        self._write(f"i32.const {wf_ret}")
        self._write("call $wasi_io_blocking_flush")
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_write_stream_err(wf_ret, msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Success: drop the output-stream, then the opened descriptor.
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_output_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        # Ok(Unit): tag = 0.
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_write_stream_err(
        self, wf_ret: int, msg_off: int, msg_len: int,
    ) -> None:
        """Shared error cleanup for a failed
        ``blocking-write-and-flush`` / ``blocking-flush``. ``$stream``
        and ``$desc`` are in scope (both already opened by the time any
        stream op runs). Drops the carried error resource when the
        variant is last-operation-failed (disc @+4 == 0; the error
        handle @+8 is an OWN resource that must be dropped), then drops
        the output-stream and the opened descriptor (the preopen ROOT is
        never dropped), and writes Err(IoError) into ``$ret_area``.

        The ``closed`` variant (disc @+4 == 1) carries no error handle,
        so it skips the error drop and just drops stream + descriptor."""
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load offset=4")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        # last-operation-failed: drop the carried error resource @+8.
        self._write(f"i32.const {wf_ret}")
        self._write("i32.load offset=8")
        self._write("call $wasi_io_drop_error")
        self._indent -= 1
        self._write("end")
        self._write("local.get $stream")
        self._write("call $wasi_io_drop_output_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_write_err(msg_off, msg_len)


    def _emit_wasi_fs_write_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_unit_io_error`` 20-byte shape: tag@0 = 1, message = the
        interned fixed string (m_ptr@4, m_len@8), empty cause (c_ptr@12 =
        0, c_len@16 = 0).

        The message is fixed (``failed to write file``) rather than the
        Python oracle's path-and-errno cause, which carries OS-specific
        bytes no cross-backend comparison can reproduce; parity is on the
        Result DISCRIMINANT (is_err), as the read / metadata / Net error
        paths already assert. ``$ret_area`` is in scope (the wrapper's
        trailing param)."""
        self._write("local.get $ret_area")
        self._write("i32.const 1")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_off}")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_len}")
        self._write("i32.store offset=8")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=12")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=16")

    # ----- Fs.list_dir via wasi:filesystem directory enumeration -----


    def _emit_wasi_fs_list_dir_wrapper(self) -> None:
        """``$Fs_list_dir (idx i32, rel_ptr i32, rel_len i32,
        ret_area i32)`` -> writes a ``result<list<string>, io-error>``
        (20-byte canonical-ABI shape) into ``ret_area``.

        Matches the call shape ``_emit_wasi_fs_list_dir_call`` produces
        (preopen index + rel (ptr, len) + ret_area), so the existing
        ``result_list_string_io_error`` materialiser lifts the result
        into a Capa ``Result<List<String>, IoError>`` unchanged, exactly
        as the capa:host list_dir does.

        Sequence (validated against wasm-tools 1.249.0 / wasmtime 44.0.1;
        convention captured in docs/design/wasi_mode.md):

          1. resolve the preopen descriptor for ``idx``.
          2. ``open-at(desc, symlink-follow, rel, open-flags=directory(2),
             descriptor-flags=read(1))`` -> result<descriptor,
             error-code>. The ``directory`` open-flag makes opening a
             non-directory (a regular file) fail at open-at (confirmed by
             oracle). On Err: write Err(IoError) and return (nothing
             opened).
          3. ``read-directory(dir_desc)`` ->
             result<directory-entry-stream, error-code>. On Err: drop the
             opened descriptor, write Err, return. The OWN
             directory-entry-stream is value @4.
          4. LOOP ``read-directory-entry(stream)`` ->
             result<option<directory-entry>, error-code>:
               * result disc @0 != 0 (Err): drop stream + descriptor,
                 write Err, return.
               * option disc @4 == 0 (none): END of stream (the normal
                 terminator, NOT an error) -> break.
               * option disc @4 == 1 (some): the directory-entry record
                 starts at @8 (type @8 ignored; name_ptr @12, name_len
                 @16). Append the (name_ptr, name_len) pair to a heap
                 accumulation buffer (8 bytes per pair, grown
                 geometrically), continue.
          5. SORT the accumulated (ptr, len) pairs lexicographically via
             ``$str_cmp`` (unsigned byte compare == Python's code-point
             ``sorted()`` over str), an in-place stable insertion sort.
             wasi returns entries in FILESYSTEM order; the oracle returns
             ``sorted(os.listdir(path))``, so the guest-side sort is what
             makes the ORDER byte-identical across the three backends.
             read-directory does NOT include "." / ".." (confirmed by
             oracle, matching os.listdir), so no filtering is needed.
          6. drop the directory-entry-stream, then drop the opened
             descriptor (OWN handles; the preopen ROOT is never dropped),
             and write Ok(list<string>): ret_area Ok arm = data_ptr @4,
             count @8. The materialiser wraps the (ptr, len)-pair buffer
             in a 16-byte List<String> header.

        Resource drops fire on EVERY exit path (success, EOF, and the two
        error paths) so no OWN handle leaks and none is dropped twice. The
        name BYTES are NOT copied: the host wrote each entry name into
        canonical-ABI memory (via the component's cabi_realloc) that lives
        for the call's duration, and the accumulation buffer stores only
        the (ptr, len) pairs pointing at them, exactly as the
        get-arguments / get-environment readers do for their string
        lists."""
        rd_ret = self._wasi_fs_list_dir_scratch_offset          # 8 bytes
        rde_ret = self._wasi_fs_list_dir_scratch_offset + 8     # 20 bytes
        msg_off, msg_len = self._intern_string("failed to list directory")
        self._write(
            "(func $Fs_list_dir (param $handle i32) (param $full_ptr i32) "
            "(param $full_len i32) (param $idx i32) (param $rel_ptr i32) "
            "(param $rel_len i32) (param $ret_area i32)"
        )
        self._indent += 1
        self._write("(local $desc i32)")
        self._write("(local $stream i32)")
        self._write("(local $buf i32)")        # pair buffer base (8B/pair)
        self._write("(local $buf_cap i32)")    # capacity in PAIRS
        self._write("(local $count i32)")      # accumulated entry count
        self._write("(local $name_ptr i32)")
        self._write("(local $name_len i32)")
        self._write("(local $newcap i32)")
        self._write("(local $newbuf i32)")
        self._write("(local $i i32)")
        self._write("(local $j i32)")
        self._write("(local $a i32)")          # &pairs[j]
        self._write("(local $b i32)")          # &pairs[j-1]
        self._write("(local $t0 i32)")         # swap temp ptr
        self._write("(local $t1 i32)")         # swap temp len
        # Fail-closed attenuation (guest-side, Level 2): a path the
        # receiver Fs does not admit writes Err(IoError) and returns
        # WITHOUT opening the directory, byte-identical (on the Result
        # discriminant) to the Python oracle (``if not self.allows(path):
        # return self._deny("list_dir", path)``,
        # capa/runtime/_capabilities.py:288-289).
        self._write("local.get $handle")
        self._write("local.get $full_ptr")
        self._write("local.get $full_len")
        self._write("call $Fs_path_allowed")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_list_dir_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # open-at(preopen_desc(idx), symlink-follow(1), rel,
        # open-flags=directory(2), descriptor-flags=read(1), rd_ret).
        self._write("local.get $idx")
        self._write("call $__wasi_fs_preopen_desc")
        self._write("i32.const 1")            # path-flags: symlink-follow
        self._write("local.get $rel_ptr")
        self._write("local.get $rel_len")
        self._write("i32.const 2")            # open-flags: directory
        self._write("i32.const 1")            # descriptor-flags: read
        self._write(f"i32.const {rd_ret}")
        self._write("call $wasi_fs_open_at")
        # if open Err (disc @0 != 0): write Err, return (nothing opened).
        self._write(f"i32.const {rd_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._emit_wasi_fs_list_dir_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # desc = open_ret.value @4 (the opened OWN directory descriptor).
        self._write(f"i32.const {rd_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $desc")
        # read-directory(desc, rd_ret) -> result<dir-entry-stream, ec>.
        # rd_ret (8 bytes) is reused: open-at's result was consumed into
        # $desc, so the slot is free.
        self._write("local.get $desc")
        self._write(f"i32.const {rd_ret}")
        self._write("call $wasi_fs_read_directory")
        # if read-directory Err: drop desc, write Err, return.
        self._write(f"i32.const {rd_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_list_dir_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # stream = rd_ret.value @4 (the OWN directory-entry-stream).
        self._write(f"i32.const {rd_ret}")
        self._write("i32.load offset=4")
        self._write("local.set $stream")
        # Accumulation buffer: start empty (count 0, cap 0 pairs, ptr from
        # a zero-size alloc, a stable non-overlapping heap pointer).
        self._write("i32.const 0")
        self._write("call $alloc")
        self._write("local.set $buf")
        self._write("i32.const 0")
        self._write("local.set $buf_cap")
        self._write("i32.const 0")
        self._write("local.set $count")
        # Loop read-directory-entry(stream, rde_ret).
        self._write("(block $list_done")
        self._indent += 1
        self._write("(loop $list_loop")
        self._indent += 1
        self._write("local.get $stream")
        self._write(f"i32.const {rde_ret}")
        self._write("call $wasi_fs_read_directory_entry")
        # if result Err (disc @0 != 0): drop stream + desc, write Err,
        # return.
        self._write(f"i32.const {rde_ret}")
        self._write("i32.load8_u offset=0")
        self._write("if")
        self._indent += 1
        self._write("local.get $stream")
        self._write("call $wasi_fs_drop_dir_entry_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        self._emit_wasi_fs_list_dir_err(msg_off, msg_len)
        self._write("return")
        self._indent -= 1
        self._write("end")
        # option disc @4 == 0 (none): END of stream -> break.
        self._write(f"i32.const {rde_ret}")
        self._write("i32.load8_u offset=4")
        self._write("i32.eqz")
        self._write("br_if $list_done")
        # some(directory-entry): name_ptr @12, name_len @16.
        self._write(f"i32.const {rde_ret}")
        self._write("i32.load offset=12")
        self._write("local.set $name_ptr")
        self._write(f"i32.const {rde_ret}")
        self._write("i32.load offset=16")
        self._write("local.set $name_len")
        # Grow the pair buffer if count == buf_cap (need one more pair).
        self._write("local.get $count")
        self._write("local.get $buf_cap")
        self._write("i32.ge_u")
        self._write("if")
        self._indent += 1
        # newcap = max(buf_cap*2, 4) pairs; geometric growth so a large
        # directory does not realloc once per entry.
        self._write("local.get $buf_cap")
        self._write("i32.const 1")
        self._write("i32.shl")
        self._write("local.tee $newcap")
        self._write("i32.const 4")
        self._write("i32.lt_u")
        self._write("if")
        self._indent += 1
        self._write("i32.const 4")
        self._write("local.set $newcap")
        self._indent -= 1
        self._write("end")
        # newbuf = alloc(newcap * 8 bytes); copy old (count*8) bytes.
        self._write("local.get $newcap")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $newbuf")
        self._write("local.get $newbuf")
        self._write("local.get $buf")
        self._write("local.get $count")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("memory.copy")
        self._write("local.get $newbuf")
        self._write("local.set $buf")
        self._write("local.get $newcap")
        self._write("local.set $buf_cap")
        self._indent -= 1
        self._write("end")
        # pairs[count] = (name_ptr, name_len); count += 1.
        self._write("local.get $buf")
        self._write("local.get $count")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $name_ptr")
        self._write("i32.store offset=0")
        self._write("local.get $buf")
        self._write("local.get $count")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $name_len")
        self._write("i32.store offset=4")
        self._write("local.get $count")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $count")
        self._write("br $list_loop")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # Sort the accumulated (ptr, len) pairs lexicographically to
        # match the oracle's sorted(os.listdir(path)). Stable insertion
        # sort over the pair buffer; $str_cmp returns -1/0/1 for the
        # unsigned byte order (== Python str code-point order). i from 1.
        self._write("i32.const 1")
        self._write("local.set $i")
        self._write("(block $sort_done")
        self._indent += 1
        self._write("(loop $sort_outer")
        self._indent += 1
        self._write("local.get $i")
        self._write("local.get $count")
        self._write("i32.ge_u")
        self._write("br_if $sort_done")
        # j = i; while j > 0 and pairs[j] < pairs[j-1]: swap; j -= 1.
        self._write("local.get $i")
        self._write("local.set $j")
        self._write("(block $inner_done")
        self._indent += 1
        self._write("(loop $sort_inner")
        self._indent += 1
        # if j == 0, stop.
        self._write("local.get $j")
        self._write("i32.eqz")
        self._write("br_if $inner_done")
        # a = &pairs[j]; b = &pairs[j-1].
        self._write("local.get $buf")
        self._write("local.get $j")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $a")
        self._write("local.get $buf")
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $b")
        # if str_cmp(a.ptr, a.len, b.ptr, b.len) >= 0, in order: stop.
        self._write("local.get $a")
        self._write("i32.load offset=0")
        self._write("local.get $a")
        self._write("i32.load offset=4")
        self._write("local.get $b")
        self._write("i32.load offset=0")
        self._write("local.get $b")
        self._write("i32.load offset=4")
        self._write("call $str_cmp")
        self._write("i32.const 0")
        self._write("i32.ge_s")
        self._write("br_if $inner_done")
        # swap pairs[j] and pairs[j-1] (both i32 fields).
        self._write("local.get $a")
        self._write("i32.load offset=0")
        self._write("local.set $t0")
        self._write("local.get $a")
        self._write("i32.load offset=4")
        self._write("local.set $t1")
        self._write("local.get $a")
        self._write("local.get $b")
        self._write("i32.load offset=0")
        self._write("i32.store offset=0")
        self._write("local.get $a")
        self._write("local.get $b")
        self._write("i32.load offset=4")
        self._write("i32.store offset=4")
        self._write("local.get $b")
        self._write("local.get $t0")
        self._write("i32.store offset=0")
        self._write("local.get $b")
        self._write("local.get $t1")
        self._write("i32.store offset=4")
        # j -= 1; continue inner.
        self._write("local.get $j")
        self._write("i32.const 1")
        self._write("i32.sub")
        self._write("local.set $j")
        self._write("br $sort_inner")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # i += 1; continue outer.
        self._write("local.get $i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $i")
        self._write("br $sort_outer")
        self._indent -= 1
        self._write(")")
        self._indent -= 1
        self._write(")")
        # EOF + sorted: drop the directory-entry-stream, then the opened
        # descriptor (the preopen ROOT is never dropped).
        self._write("local.get $stream")
        self._write("call $wasi_fs_drop_dir_entry_stream")
        self._write("local.get $desc")
        self._write("call $wasi_fs_drop_descriptor")
        # Ok(list<string>): tag=0, data_ptr=buf @4, count @8. The data
        # buffer holds N packed (str_ptr, str_len) i32 pairs, exactly the
        # canonical list<string> data layout the materialiser wraps.
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write("local.get $buf")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write("local.get $count")
        self._write("i32.store offset=8")
        self._indent -= 1
        self._write(")")


    def _emit_wasi_fs_list_dir_err(self, msg_off: int, msg_len: int) -> None:
        """Write an ``Err(IoError)`` into ``$ret_area`` for the
        ``result_list_string_io_error`` 20-byte shape: tag@0 = 1, message
        = the interned fixed string (m_ptr@4, m_len@8), empty cause
        (c_ptr@12 = 0, c_len@16 = 0).

        The message is fixed (``failed to list directory``) rather than
        the Python oracle's path-and-errno cause, which carries OS-specific
        bytes no cross-backend comparison can reproduce; parity is on the
        Result DISCRIMINANT (is_err), as the read / write / metadata / Net
        error paths already assert. ``$ret_area`` is in scope (the
        wrapper's trailing param)."""
        self._write("local.get $ret_area")
        self._write("i32.const 1")
        self._write("i32.store offset=0")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_off}")
        self._write("i32.store offset=4")
        self._write("local.get $ret_area")
        self._write(f"i32.const {msg_len}")
        self._write("i32.store offset=8")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=12")
        self._write("local.get $ret_area")
        self._write("i32.const 0")
        self._write("i32.store offset=16")


    # ----- Net.get via wasi:http (Phase 1) -----------------------

