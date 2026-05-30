#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""nspa/librtpi_sweep.py — automated pthread → librtpi conversion via libclang.

NSPA RT v2.1 — the tree-wide sweep that the old wine-librtpi 0100 patch
carried by hand. Re-runnable on every Wine version sync.

Two-phase design:
  Phase 1 — pairing discovery: scan every target .c file, extract every
            pthread_cond_wait(C, M) / pthread_cond_timedwait(C, M, T) call,
            build a multimap  cond_expr → { mutex_expr, ... }  keyed on
            the textual expression of the cond argument.
  Phase 2 — rewrite: walk each file's libclang AST, emit in-place rewrites
            for pthread_* → pi_*. For pthread_cond_signal/broadcast, look
            up the paired mutex in the map built in Phase 1.

Hard-fails (NO FIXMEs, full automation):
  - pthread_cond_signal/broadcast on a cond with no paired mutex anywhere
    in the target scope  (= cond is never used with cond_wait = dead code
    or analysis gap — refuse to sweep the file)
  - pthread_cond_signal/broadcast on a cond with multiple paired mutexes
    and libclang AST scope analysis cannot disambiguate
  - any libclang parse error in a file (refuse to sweep that file)

Recursive mutexes:
  - Mutexes initialized with PTHREAD_MUTEX_RECURSIVE (via
    pthread_mutexattr_settype) cannot be converted (librtpi has no
    recursive support). Such mutexes are detected and left as
    pthread_mutex_t — their lock/unlock calls stay as pthread_mutex_*.

Usage:
  nspa/librtpi_sweep.py --wine-root /path/to/wine [--dry-run] [scope_dirs...]

If no scope dirs are given, sweeps the default target list (ntdll/unix,
server, win32u, and the main audio/graphics driver Unixlibs).
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

try:
    import clang.cindex
    from clang.cindex import CursorKind, Index, TranslationUnit, CompilationDatabase
except ImportError:
    sys.stderr.write('error: python-clang is not installed. pacman -S python-clang\n')
    sys.exit(2)


# ============================================================================
#   Configuration
# ============================================================================

TYPE_RENAMES = {
    'pthread_mutex_t': 'pi_mutex_t',
    'pthread_cond_t':  'pi_cond_t',
}

INIT_MACROS = {
    'PTHREAD_MUTEX_INITIALIZER': 'PI_MUTEX_INIT(0)',
    'PTHREAD_COND_INITIALIZER':  'PI_COND_INIT(0)',
}

SIMPLE_CALL_RENAMES = {
    'pthread_mutex_lock':     'pi_mutex_lock',
    'pthread_mutex_unlock':   'pi_mutex_unlock',
    'pthread_mutex_destroy':  'pi_mutex_destroy',
    'pthread_mutex_trylock':  'pi_mutex_trylock',
    'pthread_cond_wait':      'pi_cond_wait',
    'pthread_cond_timedwait': 'pi_cond_timedwait',
    'pthread_cond_destroy':   'pi_cond_destroy',
}

DEFAULT_SCOPE = [
    'dlls/ntdll/unix',
    'dlls/win32u',
    'dlls/winealsa.drv',
    'dlls/winex11.drv',
    'dlls/winewayland.drv',
    'dlls/winegstreamer',
    'dlls/winepulse.drv',
    'dlls/winecoreaudio.drv',
    'dlls/wineoss.drv',
    'dlls/opengl32',
    'dlls/winebus.sys',
    'dlls/wineusb.sys',
    'dlls/nsiproxy.sys',
]
# winemac.drv and wineandroid.drv are excluded from scope per user:
# Wine-NSPA targets Linux (and possibly *BSD/Wayland). macOS and Android
# builds are not maintained here. Their Makefile.in files and sources
# are left untouched by the sweep.

# ----------------------------------------------------------------------------
# Opt-out lists.
#
# These override DEFAULT_SCOPE and any CLI-passed scope: a file or directory
# listed here is NEVER rewritten, even if the user explicitly requests its
# parent directory. The reasoning for each entry is captured in
# memory/reference_librtpi_sweep_opt_outs.md — in short:
#
#   process.c          : contains fork() callsites. pi_mutex owner TID is
#                        stored in the futex word; the child inherits a
#                        corrupted mutex. Even though Wine execs immediately
#                        after fork, we exclude the entire file to avoid
#                        any accidental mutex touch in the fork window.
#
#   signal_*.c         : per-arch signal handler implementations. Deep
#                        call chains from segv_handler / usr1_handler /
#                        trap_handler can reach locks; pi_mutex under async
#                        signal context is unvetted. The one concrete
#                        problematic mutex we found — instrumentation_callback_mutex
#                        in signal_x86_64.c — is covered by the file-level
#                        exclude.
#
#   server/            : wineserver is a single-process event loop. Its
#                        mutexes never contend across threads (there's only
#                        one thread by design), so pi_mutex gives zero
#                        benefit and pure overhead. Also simpler than
#                        auditing the request-handling paths.
#
# Adding to these lists: if a future Wine release introduces a new fork
# path, signal handler, or process-shared mutex pattern, add the file here
# and update memory/reference_librtpi_sweep_opt_outs.md with the reasoning.
# ----------------------------------------------------------------------------

EXCLUDE_FILES = frozenset([
    'dlls/ntdll/unix/process.c',
    'dlls/ntdll/unix/signal_i386.c',
    'dlls/ntdll/unix/signal_x86_64.c',
    'dlls/ntdll/unix/signal_arm.c',
    'dlls/ntdll/unix/signal_arm64.c',
])

EXCLUDE_DIRS = frozenset([
    'server',
])

# Compile flags libclang doesn't understand, doesn't have 32-bit builtin
# headers for, or that cause cosmetic noise. Stripped from compile_commands.json
# before handing to libclang.parse().
LIBCLANG_STRIP_FLAGS_PREFIX = (
    '-mpreferred-stack-boundary',
    '-mlong-double-',
    '-Wno-misleading-indentation',
    '-Wno-packed-not-aligned',
    '-Wlogical-op',
    '-Wshift-overflow',
    '-gdwarf',
    '-ffunction-sections',
    '-fno-omit-frame-pointer',
    '-fcf-protection',
    '-fvisibility',
    '-fno-stack-protector',
)

# Flags that cause libclang to need multilib builtin headers that aren't
# installed on Arch. Drop entirely; parse as native arch.
LIBCLANG_DROP_FLAGS_EXACT = (
    '-m32',
    '-m64',
    '-pipe',
)


# ============================================================================
#   Source text extraction
# ============================================================================

_source_cache = {}

def get_source_bytes(path):
    if path not in _source_cache:
        with open(path, 'rb') as f:
            _source_cache[path] = f.read()
    return _source_cache[path]

def invalidate_source_cache(path):
    _source_cache.pop(path, None)

def cursor_text(cursor):
    """Get the raw source text covered by a cursor's extent."""
    extent = cursor.extent
    path = str(extent.start.file) if extent.start.file else None
    if not path:
        return ''
    src = get_source_bytes(path)
    try:
        return src[extent.start.offset:extent.end.offset].decode('utf-8', errors='replace')
    except Exception:
        return ''

def call_arg_text(cursor, idx):
    """Get the source text of the idx'th argument of a CALL_EXPR cursor."""
    args = list(cursor.get_arguments())
    if idx >= len(args):
        return None
    return cursor_text(args[idx]).strip()

def call_callee_extent(cursor):
    """Return the (start, end) offset of the callee identifier in a
    CALL_EXPR cursor (the function name, not the whole call)."""
    for child in cursor.walk_preorder():
        if child.kind == CursorKind.DECL_REF_EXPR:
            return child.extent.start.offset, child.extent.end.offset
    name = cursor.spelling
    if name:
        return (cursor.extent.start.offset,
                cursor.extent.start.offset + len(name))
    return None


# ============================================================================
#   Compile command lookup
# ============================================================================

_clang_builtin_includes = None
def _get_clang_builtin_includes():
    """Return the -isystem args needed for libclang to find its builtin
    headers (stddef.h, stdarg.h, stdbool.h, etc). These live in clang's
    resource directory, typically /usr/lib/clang/<version>/include."""
    global _clang_builtin_includes
    if _clang_builtin_includes is not None:
        return _clang_builtin_includes

    import subprocess
    try:
        out = subprocess.check_output(['clang', '-print-resource-dir'],
                                       stderr=subprocess.DEVNULL).decode().strip()
        inc = os.path.join(out, 'include')
        if os.path.isdir(inc):
            _clang_builtin_includes = ['-isystem', inc]
            return _clang_builtin_includes
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    _clang_builtin_includes = []
    return _clang_builtin_includes


class CompileDB:
    """Wrapper around Wine's build/compile_commands.json."""
    def __init__(self, wine_root):
        self.wine_root = os.path.abspath(wine_root)
        self.path = os.path.join(self.wine_root, 'build', 'compile_commands.json')
        self.db = {}    # abs_file -> (cwd, args)
        if os.path.exists(self.path):
            with open(self.path) as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
            for entry in data:
                cwd = entry.get('directory', '')
                f_abs = os.path.abspath(os.path.join(cwd, entry['file']))
                args = entry.get('arguments')
                if args is None and 'command' in entry:
                    args = entry['command'].split()
                self.db[f_abs] = (cwd, args or [])

    def args_for(self, file_path):
        abs_path = os.path.abspath(file_path)
        entry = self.db.get(abs_path)
        if entry:
            cwd, args = entry
            return self._clean(cwd, args)
        return self._defaults()

    def _clean(self, cwd, args):
        """Filter out the compiler binary, the -o output, the input file,
        and flags libclang doesn't recognize. Also resolve any -I relative
        paths against the build cwd so the caller doesn't need to chdir.
        Prepend libclang's builtin header directory for stddef.h etc."""
        out = list(_get_clang_builtin_includes())
        skip_next = False
        for i, a in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if i == 0:
                continue
            if a == '-c':
                continue
            if a == '-o':
                skip_next = True
                continue
            if a in LIBCLANG_DROP_FLAGS_EXACT:
                continue
            if a.startswith(LIBCLANG_STRIP_FLAGS_PREFIX):
                continue
            if a.endswith('.c') and (os.path.exists(a) or os.path.exists(os.path.join(cwd, a))):
                continue
            if a.startswith('-I') and len(a) > 2 and not os.path.isabs(a[2:]):
                out.append('-I' + os.path.normpath(os.path.join(cwd, a[2:])))
                continue
            if a.startswith('-isystem') and len(a) > 8 and not os.path.isabs(a[8:]):
                out.append('-isystem' + os.path.normpath(os.path.join(cwd, a[8:])))
                continue
            out.append(a)
        return out

    def _defaults(self):
        return list(_get_clang_builtin_includes()) + [
            '-D__WINESRC__',
            '-DWINE_UNIX_LIB',
            '-D_GNU_SOURCE',
            f'-I{self.wine_root}/include',
            f'-I{self.wine_root}/dlls/ntdll',
            f'-I{self.wine_root}/build/include',
        ]


# ============================================================================
#   Phase 1: pairing discovery
# ============================================================================

def cursor_function_name(cursor):
    """Best-effort function name extraction for a CALL_EXPR cursor."""
    if cursor.spelling:
        return cursor.spelling
    if cursor.referenced:
        return cursor.referenced.spelling
    return None

def canonical_cond_key(expr):
    """Reduce a cond expression to its canonical field-name suffix.

    Used by the Phase 1 pairing discovery + Phase 2 signal/broadcast
    resolution so that textually-different expressions referring to
    the same underlying cond variable can still be matched. Examples:

        &stream->event_empty_cond             -> event_empty_cond
        &parser->streams[i]->event_empty_cond -> event_empty_cond
        &my_cond                              -> my_cond
        &ctx->audio.ready_cond                -> ready_cond
        &q->items[n].cond                     -> cond

    Transformation steps:
      1. strip leading whitespace and `&` address-of
      2. remove all [N] array subscripts
      3. split on '->' and '.'
      4. return the final segment (rightmost field name)

    Rationale for this shape: the cond_wait call site often uses a
    local variable alias (`stream->event_empty_cond`) while the
    cond_signal site uses the full chain through the owning struct
    (`parser->streams[i]->event_empty_cond`). Both point at the same
    heap location; the sweep needs to recognize them as the same
    conceptual cond to pair them. The final field name is invariant
    under pointer chasing and array indexing.

    Collisions are possible in theory (two unrelated conds named
    "cond" in the same TU), but the resolver catches ambiguity at
    lookup time and errors out. In practice Wine's cond variables
    have descriptive names (event_empty_cond, read_done_cond, etc.)
    so collisions are rare.
    """
    import re
    s = expr.strip()
    if s.startswith('&'):
        s = s[1:].lstrip()
    # Strip array subscripts anywhere in the expression
    s = re.sub(r'\[[^\]]*\]', '', s)
    # Split on struct-member separators (-> or .)
    parts = re.split(r'->|\.', s)
    return parts[-1].strip()


def discover_pairings(files, cdb):
    """Phase 1: scan all files, return (by_full, by_canonical) pairing maps.

    by_full is a dict: cond_full_text -> {mutex_exprs}
    by_canonical is a dict: cond_canonical_key -> {mutex_exprs}

    Signal/broadcast lookups try by_full first, then fall back to
    by_canonical if the exact textual form isn't known."""
    by_full = defaultdict(set)
    by_canonical = defaultdict(set)
    index = Index.create()

    for f in files:
        args = cdb.args_for(f)
        try:
            tu = index.parse(f, args=args,
                             options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        except clang.cindex.TranslationUnitLoadError:
            continue

        for cursor in tu.cursor.walk_preorder():
            if cursor.kind != CursorKind.CALL_EXPR:
                continue
            fname = cursor_function_name(cursor)
            if fname not in ('pthread_cond_wait', 'pthread_cond_timedwait'):
                continue
            cond_text = call_arg_text(cursor, 0)
            mutex_text = call_arg_text(cursor, 1)
            if cond_text and mutex_text:
                by_full[cond_text].add(mutex_text)
                by_canonical[canonical_cond_key(cond_text)].add(mutex_text)

    # Pack both into one struct for backward compat — callers use
    # a tuple (by_full, by_canonical).
    return (by_full, by_canonical)


# ============================================================================
#   Recursive mutex detection
# ============================================================================

def param_type_names(fn_decl):
    """Return a list of the type spellings for each PARM_DECL of a
    FUNCTION_DECL cursor."""
    out = []
    if not fn_decl:
        return out
    for child in fn_decl.get_children():
        if child.kind != CursorKind.PARM_DECL:
            continue
        out.append(child.type.spelling)
    return out

def is_mutex_param_type(type_spelling):
    return ('pthread_mutex_t' in type_spelling or 'pi_mutex_t' in type_spelling)

def propagate_mutex_taint(files, cdb, recursive_exprs, recursive_names):
    """Historical taint propagation — now a no-op.

    When this sweep was first designed, any function that touched a
    recursive mutex became "tainted" (had to stay on pthread_mutex_t)
    because pi_mutex_t couldn't represent recursion. The transitive
    fixpoint would poison every mutex that shared a wrapper with a
    recursive one, leaving them all as pthread.

    NSPA RT v2.0.1 added NSPA_RTPI_MUTEX_RECURSIVE to rtpi.h: pi_mutex_t
    now carries a recursion flag inside the struct, and pi_mutex_lock
    handles both recursive and non-recursive mutexes at runtime via
    that flag. Wrapper functions can therefore take `pi_mutex_t *` and
    work for both kinds — no distinction needed at the type level.

    Consequence: the propagation is no longer necessary. We still need
    the INITIAL set of recursive mutex names (from Phase 0 — the
    PTHREAD_MUTEX_RECURSIVE attr+init pattern) so that
    _rewrite_mutex_init can pass NSPA_RTPI_MUTEX_RECURSIVE for those
    specific mutexes. Everything else is freely convertible.

    Returns (recursive_exprs, recursive_names, tainted_funcs) with
    tainted_funcs always empty — same tuple shape as before so callers
    don't need to change."""
    return recursive_exprs, recursive_names, set()


def find_recursive_mutexes(files, cdb):
    """Find mutexes initialized with PTHREAD_MUTEX_RECURSIVE.
    Returns (expr_set, name_set):
      expr_set — the mutex argument expressions as they appeared in the
                 pthread_mutex_init call (e.g. '&virtual_mutex'). Used
                 when matching call sites that take a mutex argument.
      name_set — the bare variable names (e.g. 'virtual_mutex'). Used
                 when matching declarator names for type rewrites.
    """
    expr_set = set()
    name_set = set()
    index = Index.create()

    for f in files:
        args = cdb.args_for(f)
        try:
            tu = index.parse(f, args=args)
        except clang.cindex.TranslationUnitLoadError:
            continue

        recursive_attrs_in_file = set()
        for c in tu.cursor.walk_preorder():
            if c.kind != CursorKind.CALL_EXPR:
                continue
            if cursor_function_name(c) != 'pthread_mutexattr_settype':
                continue
            attr_text = call_arg_text(c, 0)
            type_text = call_arg_text(c, 1)
            if attr_text and type_text and 'PTHREAD_MUTEX_RECURSIVE' in type_text:
                recursive_attrs_in_file.add(attr_text)

        if not recursive_attrs_in_file:
            continue

        for c in tu.cursor.walk_preorder():
            if c.kind != CursorKind.CALL_EXPR:
                continue
            if cursor_function_name(c) != 'pthread_mutex_init':
                continue
            mutex_text = call_arg_text(c, 0)
            attr_text = call_arg_text(c, 1)
            if attr_text in recursive_attrs_in_file and mutex_text:
                expr_set.add(mutex_text)
                # Extract bare variable name for type-rewrite skip checks.
                # Handle common forms: &m, &m->field, &m.field
                bare = mutex_text.lstrip('&').strip()
                # For "s->m" or "s.m", take the last component
                if '->' in bare:
                    bare = bare.rsplit('->', 1)[-1]
                if '.' in bare:
                    bare = bare.rsplit('.', 1)[-1]
                name_set.add(bare)

    return expr_set, name_set


# ============================================================================
#   Phase 2: rewrite
# ============================================================================

class RewriteError(Exception):
    pass

class FileRewriter:
    def __init__(self, path, tu, pairings, recursive_exprs, recursive_names, tainted_funcs):
        self.path = path
        self.tu = tu
        self.pairings = pairings
        self.recursive = recursive_exprs
        self.recursive_names = recursive_names
        self.tainted_funcs = tainted_funcs
        self.edits = {}
        self._skipped_type_refs = set()
        self._skipped_ranges = []        # tainted declarator byte ranges
        self._tainted_body_ranges = []   # tainted FUNCTION_DECL body byte ranges
        self.needs_rtpi_include = False

    def add_edit(self, start, end, replacement):
        key = (start, end)
        if key in self.edits and self.edits[key] != replacement:
            raise RewriteError(
                f'conflicting edit at [{start}:{end}]: '
                f'"{self.edits[key]}" vs "{replacement}"')
        self.edits[key] = replacement
        self.needs_rtpi_include = True

    def resolve_mutex_for_cond(self, cond_text):
        # self.pairings is (by_full, by_canonical). Try exact text match
        # first, then fall back to canonical-suffix match. See
        # canonical_cond_key() for why that's useful — cond_wait and
        # cond_signal sites often use different textual forms (one via
        # a local alias, one via the full struct chain) for the same
        # underlying cond variable.
        by_full, by_canonical = self.pairings
        mutexes = by_full.get(cond_text, set())
        if len(mutexes) == 1:
            return next(iter(mutexes))
        if len(mutexes) == 0:
            # Exact lookup failed — try canonical suffix fallback.
            canonical = canonical_cond_key(cond_text)
            mutexes = by_canonical.get(canonical, set())
            if len(mutexes) == 1:
                return next(iter(mutexes))
            if len(mutexes) == 0:
                raise RewriteError(
                    f'pthread_cond_signal/broadcast on "{cond_text}" has no '
                    f'paired mutex — cond is never used with cond_wait anywhere '
                    f'in the sweep scope (also tried canonical key "{canonical}"). '
                    f'Cannot auto-resolve.')
            # canonical has multiple candidates — fall through to ambiguity.
            raise RewriteError(
                f'pthread_cond_signal/broadcast on "{cond_text}" has no exact '
                f'textual pairing; canonical fallback "{canonical}" has '
                f'{len(mutexes)} candidate mutexes: {sorted(mutexes)}. '
                f'Ambiguous, cannot auto-resolve.')
        # Exact match had >1 candidate — real ambiguity.
        raise RewriteError(
            f'pthread_cond_signal/broadcast on "{cond_text}" has '
            f'{len(mutexes)} candidate mutexes: {sorted(mutexes)}. '
            f'Ambiguous, cannot auto-resolve.')

    def visit(self):
        """Visit the cursors belonging to this file path."""
        self._visit_cursors(self._cursors_for_path(self.path))

    def visit_header_in_tu(self, header_path):
        """Visit the cursors in the given header, as seen through
        self.tu. Used for headers included by the main parsed .c."""
        self._visit_cursors(self._cursors_for_path(header_path))

    def _cursors_for_path(self, path):
        abs_path = os.path.abspath(path)
        out = []
        for cursor in self.tu.cursor.walk_preorder():
            loc_file = cursor.location.file
            if not loc_file or os.path.abspath(str(loc_file)) != abs_path:
                continue
            out.append(cursor)
        return out

    def _visit_cursors(self, cursors):
        """Two-pass visit:
         1a. Record tainted FUNCTION_DECL body ranges.
         1b. Process declarators (sets _skipped_ranges).
         2.  Process everything else (TYPE_REF, CALL_EXPR, MACRO_INSTANTIATION).
        """
        # Pass 1a: record tainted function-definition ranges
        for cursor in cursors:
            if cursor.kind == CursorKind.FUNCTION_DECL:
                if cursor.spelling in self.tainted_funcs and cursor.is_definition():
                    ext = cursor.extent
                    self._tainted_body_ranges.append(
                        (ext.start.offset, ext.end.offset))

        # Pass 1b: declarators
        for cursor in cursors:
            if cursor.kind in (CursorKind.VAR_DECL, CursorKind.FIELD_DECL, CursorKind.PARM_DECL):
                self._handle(cursor)

        # Pass 2: everything else
        for cursor in cursors:
            if cursor.kind not in (CursorKind.VAR_DECL, CursorKind.FIELD_DECL, CursorKind.PARM_DECL, CursorKind.FUNCTION_DECL):
                self._handle(cursor)

    def _handle(self, cursor):
        kind = cursor.kind

        # Type rewrites are driven from declarators, not bare TYPE_REFs,
        # because libclang doesn't give TYPE_REF cursors a usable
        # semantic_parent (it returns None). Standalone TYPE_REFs (in casts,
        # typeof, sizeof exprs) are not handled — those are rare enough to
        # deal with separately if encountered.
        #
        # We track the TYPE_REF extents we've skipped as "recursive" so
        # nothing else processes them.
        if kind in (CursorKind.VAR_DECL, CursorKind.FIELD_DECL, CursorKind.PARM_DECL):
            decl_name = cursor.spelling
            # Historical: we used to skip declarations whose mutex name was in
            # recursive_names (so the declaration would keep pthread_mutex_t).
            # NSPA_RTPI_MUTEX_RECURSIVE makes that unnecessary — recursive and
            # non-recursive mutexes both become pi_mutex_t, and the distinction
            # is stored at init time via the flag (see _rewrite_mutex_init).
            # Similarly tainted_funcs is always empty in the relaxed design, so
            # the "parameter of tainted function" branch never fires.
            skip_recursive = False
            _ = decl_name  # still computed for potential future use

            # Process TYPE_REF child (the declared type)
            for child in cursor.get_children():
                if child.kind != CursorKind.TYPE_REF:
                    continue
                name = child.spelling.replace('struct ', '').replace('union ', '').strip()
                if name not in TYPE_RENAMES:
                    break
                if skip_recursive:
                    ext = child.extent
                    self._skipped_type_refs.add((ext.start.offset, ext.end.offset))
                    break
                ext = child.extent
                self.add_edit(ext.start.offset, ext.end.offset, TYPE_RENAMES[name])
                break

            # If this declarator is a skipped tainted mutex, record its
            # full byte range so any MACRO_INSTANTIATION that falls inside
            # it (e.g. PTHREAD_MUTEX_INITIALIZER) can be identified and
            # skipped too.  MACRO_INSTANTIATION cursors are not direct
            # children of VAR_DECL in libclang's AST — they live in the
            # preprocessing record and are only reachable via walk_preorder
            # on the top-level TU cursor. So we use offset containment
            # instead of child-walking.
            if skip_recursive:
                ext = cursor.extent
                self._skipped_ranges.append((ext.start.offset, ext.end.offset))
            return

        # Standalone TYPE_REF fallback — only rewrite if not already
        # explicitly skipped by the declarator handler above.
        if kind == CursorKind.TYPE_REF:
            name = cursor.spelling.replace('struct ', '').replace('union ', '').strip()
            if name not in TYPE_RENAMES:
                return
            ext = cursor.extent
            key = (ext.start.offset, ext.end.offset)
            if key in self._skipped_type_refs:
                return
            if key in self.edits:
                return  # already rewritten by declarator handler
            self.add_edit(ext.start.offset, ext.end.offset, TYPE_RENAMES[name])
            return

        if kind == CursorKind.MACRO_INSTANTIATION:
            name = cursor.spelling
            if name in INIT_MACROS:
                ext = cursor.extent
                # Check if this macro falls inside any skipped declarator range
                mstart = ext.start.offset
                mend = ext.end.offset
                for rstart, rend in self._skipped_ranges:
                    if rstart <= mstart and mend <= rend:
                        return  # inside a tainted declarator, don't rewrite
                self.add_edit(mstart, mend, INIT_MACROS[name])
            return

        if kind == CursorKind.CALL_EXPR:
            fn = cursor_function_name(cursor)
            if fn in SIMPLE_CALL_RENAMES:
                self._rewrite_simple_call(cursor, fn)
            elif fn == 'pthread_mutex_init':
                self._rewrite_mutex_init(cursor)
            elif fn == 'pthread_cond_init':
                self._rewrite_cond_init(cursor)
            elif fn == 'pthread_cond_signal':
                self._rewrite_cond_signal(cursor, broadcast=False)
            elif fn == 'pthread_cond_broadcast':
                self._rewrite_cond_signal(cursor, broadcast=True)
            return

    def _rewrite_simple_call(self, cursor, fn):
        # Historical: we used to skip calls inside tainted-function bodies
        # and skip calls whose mutex arg was recursive. NSPA_RTPI_MUTEX_RECURSIVE
        # makes both unnecessary — pi_mutex_lock handles recursion at runtime
        # via the flag stored in the mutex struct, so every pthread_mutex_*
        # call site can be uniformly rewritten. The _tainted_body_ranges
        # list is always empty now (propagate_mutex_taint is a no-op), so
        # this loop no longer excludes anything — left in place only as a
        # defensive check in case a future change reintroduces taint.
        cstart = cursor.extent.start.offset
        cend = cursor.extent.end.offset
        for bstart, bend in self._tainted_body_ranges:
            if bstart <= cstart and cend <= bend:
                return
        callee = call_callee_extent(cursor)
        if not callee:
            return
        self.add_edit(callee[0], callee[1], SIMPLE_CALL_RENAMES[fn])

    def _rewrite_mutex_init(self, cursor):
        args = list(cursor.get_arguments())
        if len(args) != 2:
            return
        mutex_text = cursor_text(args[0]).strip()
        start = cursor.extent.start.offset
        end = cursor.extent.end.offset
        # Recursive mutexes get NSPA_RTPI_MUTEX_RECURSIVE in the flags
        # argument so pi_mutex_lock/unlock will honor re-entry.
        # Non-recursive mutexes get 0.
        flag = 'NSPA_RTPI_MUTEX_RECURSIVE' if mutex_text in self.recursive else '0'
        replacement = f'pi_mutex_init({mutex_text}, {flag})'
        self.add_edit(start, end, replacement)

    def _rewrite_cond_init(self, cursor):
        args = list(cursor.get_arguments())
        if len(args) != 2:
            return
        cond_text = cursor_text(args[0]).strip()
        start = cursor.extent.start.offset
        end = cursor.extent.end.offset
        replacement = f'pi_cond_init({cond_text}, 0)'
        self.add_edit(start, end, replacement)

    def _rewrite_cond_signal(self, cursor, broadcast):
        args = list(cursor.get_arguments())
        if len(args) != 1:
            return
        cond_text = cursor_text(args[0]).strip()
        mutex = self.resolve_mutex_for_cond(cond_text)
        start = cursor.extent.start.offset
        end = cursor.extent.end.offset
        fn = 'pi_cond_broadcast' if broadcast else 'pi_cond_signal'
        replacement = f'{fn}({cond_text}, {mutex})'
        self.add_edit(start, end, replacement)

    def apply(self):
        if not self.edits:
            return None
        src = bytearray(get_source_bytes(self.path))
        ordered = sorted(self.edits.items(), key=lambda kv: kv[0][0], reverse=True)
        for (start, end), replacement in ordered:
            src[start:end] = replacement.encode('utf-8')
        result = bytes(src)
        if b'<rtpi.h>' not in result and b'"rtpi.h"' not in result:
            result = inject_rtpi_include(result)
        return result


def inject_rtpi_include(src_bytes):
    """Inject #include <rtpi.h> into a source file.

    Injects after the LAST include in the first contiguous block of
    includes at the top of the file. This keeps the new include in the
    "header section" rather than deep in the file where conditional
    #include blocks live (e.g. #ifdef __APPLE__ or #ifdef sun sections
    that pull in platform-specific headers late in the source).

    Note: we do NOT try to skip injection when a file includes
    "unix_private.h" — each Wine DLL with Unix-side code has its OWN
    unix_private.h (ntdll's, nsiproxy.sys's, etc.), and we can't tell
    from the textual filename alone whether a given one transitively
    pulls in rtpi.h. Always inject; a redundant include is harmless.
    The ntdll/unix/unix_private.h already has its own #include <rtpi.h>
    so the redundancy only affects its consumers' own source files.
    """
    lines = src_bytes.split(b'\n')
    first_block_end = -1
    in_block = False
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(b'#include'):
            first_block_end = i
            in_block = True
            continue
        # A blank line or a non-include does NOT end the block yet — we
        # allow blank lines between include groups. But a non-comment,
        # non-blank, non-preprocessor line DOES end the block.
        if not stripped or stripped.startswith(b'//') or stripped.startswith(b'/*') \
                or stripped.startswith(b'*') or stripped.startswith(b'#'):
            continue
        if in_block:
            break

    if first_block_end < 0:
        first_block_end = 0
    lines.insert(first_block_end + 1, b'#include <rtpi.h>')
    return b'\n'.join(lines)


# ============================================================================
#   File discovery
# ============================================================================

def find_target_files(wine_root, scope_dirs):
    """Enumerate .c AND .h files in scope that reference pthread_ symbols.
    Headers are included because Wine has internal wrapper functions
    (e.g. unix_private.h's mutex_lock/mutex_unlock guards) that take
    pthread_mutex_t * and must be rewritten in sync with the .c files
    that use them. The visitor is restricted to process each file only
    once regardless of how many TUs include it."""
    out = []
    excluded_count = 0
    for d in scope_dirs:
        # Directory-level opt-out: a whole subtree skipped even if passed
        # on the CLI. See EXCLUDE_DIRS reasoning above.
        if d in EXCLUDE_DIRS or any(d.startswith(ex + os.sep) for ex in EXCLUDE_DIRS):
            print(f'[opt-out] skipping directory: {d}')
            continue
        full = os.path.join(wine_root, d)
        if not os.path.isdir(full):
            continue
        for root, _, files in os.walk(full):
            rel_dir = os.path.relpath(root, wine_root)
            # Also skip EXCLUDE_DIRS encountered transitively
            # (e.g. if scope is '.' and server/ is nested)
            rel_parts = rel_dir.split(os.sep)
            if any(p in EXCLUDE_DIRS for p in rel_parts):
                continue
            if 'tests' in rel_parts:
                continue
            for f in files:
                if not (f.endswith('.c') or f.endswith('.h')):
                    continue
                rel_path = os.path.join(rel_dir, f).replace(os.sep, '/')
                # File-level opt-out: specific files stay on pthread forever.
                if rel_path in EXCLUDE_FILES:
                    excluded_count += 1
                    print(f'[opt-out] skipping file: {rel_path}')
                    continue
                path = os.path.join(root, f)
                try:
                    with open(path, 'rb') as fh:
                        content = fh.read()
                except OSError:
                    continue
                if b'pthread_' in content:
                    out.append(path)
    if excluded_count:
        print(f'[opt-out] {excluded_count} file(s) excluded by EXCLUDE_FILES')
    return sorted(set(out))


# ============================================================================
#   Driver
# ============================================================================

def main():
    ap = argparse.ArgumentParser(description='librtpi sweep tool for Wine-NSPA')
    ap.add_argument('--wine-root', required=True, help='path to Wine source tree')
    ap.add_argument('--dry-run', action='store_true',
                    help="don't write files, just report what would change")
    ap.add_argument('--verbose', '-v', action='store_true')
    ap.add_argument('dirs', nargs='*', help='scope directories (relative to wine-root)')
    args = ap.parse_args()

    wine_root = os.path.abspath(args.wine_root)
    scope = args.dirs if args.dirs else DEFAULT_SCOPE

    print(f'wine root: {wine_root}')
    print(f'scope: {scope}')

    files = find_target_files(wine_root, scope)
    print(f'found {len(files)} .c files referencing pthread_ in scope')
    if not files:
        return 0

    cdb = CompileDB(wine_root)
    print(f'compile_commands.json: {len(cdb.db)} entries loaded')

    print('\n=== Phase 0: recursive-mutex detection ===')
    recursive_exprs, recursive_names = find_recursive_mutexes(files, cdb)
    if recursive_exprs:
        print(f'found {len(recursive_exprs)} initial recursive mutexes:')
        for m in sorted(recursive_exprs):
            print(f'  {m}')
    else:
        print('no recursive mutexes detected')

    print('\n=== Phase 0b: taint propagation (no-op since NSPA_RTPI_MUTEX_RECURSIVE) ===')
    recursive_exprs, recursive_names, tainted_funcs = propagate_mutex_taint(
        files, cdb, recursive_exprs, recursive_names)
    print(f'recursive mutexes to flag at init: {len(recursive_exprs)}')
    print(f'tainted functions: {len(tainted_funcs)} (always 0 in relaxed mode)')
    if args.verbose or (len(recursive_exprs) < 50 and recursive_exprs):
        for m in sorted(recursive_exprs):
            print(f'  {m}  (will get NSPA_RTPI_MUTEX_RECURSIVE at init)')

    print('\n=== Phase 1: cond_wait pairing discovery ===')
    pairings = discover_pairings(files, cdb)
    # pairings is (by_full, by_canonical)
    by_full, by_canonical = pairings
    print(f'discovered {len(by_full)} exact cond_wait pairings '
          f'({len(by_canonical)} canonical keys)')
    if args.verbose:
        for cond, mutexes in sorted(by_full.items()):
            print(f'  {cond!r} -> {sorted(mutexes)!r}')

    print('\n=== Phase 2: rewriting files ===')
    # Headers are parsed by piggy-backing on a .c file that includes them:
    # we process the .c files first, and for each we also visit cursors
    # whose source file matches any header in the scope. Track which
    # headers we've rewritten so we don't double-process.
    header_set = set(os.path.abspath(f) for f in files if f.endswith('.h'))
    processed_headers = set()

    index = Index.create()
    errors = []
    modified = 0

    # Only .c files drive the parse (headers are included by .c files).
    c_files = [f for f in files if f.endswith('.c')]

    # Accumulator for header rewriters across all TUs — we visit each
    # header's cursors in each TU, but only emit edits once.
    header_rewriters = {}  # abs_header_path -> FileRewriter

    for f in c_files:
        parse_args = cdb.args_for(f)
        try:
            tu = index.parse(f, args=parse_args,
                             options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        except clang.cindex.TranslationUnitLoadError as e:
            errors.append((f, f'parse error: {e}'))
            print(f'ERROR: parse failed: {f}: {e}')
            continue

        # Rewrite the .c file
        rewriter = FileRewriter(f, tu, pairings, recursive_exprs, recursive_names, tainted_funcs)
        try:
            rewriter.visit()
        except RewriteError as e:
            errors.append((f, str(e)))
            print(f'ERROR: {f}: {e}')
            continue

        result = rewriter.apply()
        if result is not None:
            modified += 1
            if args.dry_run:
                print(f'[dry-run] would rewrite: {f}  ({len(rewriter.edits)} edits)')
            else:
                invalidate_source_cache(f)
                with open(f, 'wb') as fh:
                    fh.write(result)
                print(f'rewrote: {f}  ({len(rewriter.edits)} edits)')

        # Also rewrite any in-scope headers visible in this TU
        for hpath in header_set:
            if hpath in processed_headers:
                continue
            if hpath not in header_rewriters:
                header_rewriters[hpath] = FileRewriter(
                    hpath, tu, pairings, recursive_exprs, recursive_names, tainted_funcs)
            try:
                header_rewriters[hpath].visit_header_in_tu(hpath)
            except RewriteError as e:
                errors.append((hpath, str(e)))
                print(f'ERROR: {hpath}: {e}')

    # After visiting all TUs, flush header rewriters
    for hpath, rewriter in header_rewriters.items():
        result = rewriter.apply()
        if result is None:
            continue
        modified += 1
        processed_headers.add(hpath)
        if args.dry_run:
            print(f'[dry-run] would rewrite: {hpath}  ({len(rewriter.edits)} edits)')
        else:
            invalidate_source_cache(hpath)
            with open(hpath, 'wb') as fh:
                fh.write(result)
            print(f'rewrote: {hpath}  ({len(rewriter.edits)} edits)')

    print('\n=== Summary ===')
    print(f'files scanned: {len(files)}')
    print(f'files modified: {modified}')
    print(f'errors: {len(errors)}')
    if errors:
        for f, e in errors:
            print(f'  {f}: {e}')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
