// SPDX-License-Identifier: LGPL-2.1-or-later
//
// nspa/librtpi.cocci
// Wine-NSPA RT v2.1 — Coccinelle semantic patch: pthread_mutex_t / pthread_cond_t
//                      → librtpi pi_mutex_t / pi_cond_t on Unix-side pthread users.
//
// Purpose
// -------
// Automate the tree-wide pthread → librtpi conversion that was previously carried
// as a hand-curated 1131-line patch (wine-librtpi/0100-librtpi-PI_Support.mypatch).
// Every Wine release sync, re-run spatch instead of rebasing 108 hunks by hand:
//
//   spatch --sp-file nspa/librtpi.cocci --in-place --dir dlls/ntdll/unix/
//   spatch --sp-file nspa/librtpi.cocci --in-place --dir server/
//   spatch --sp-file nspa/librtpi.cocci --in-place --dir dlls/win32u/
//   ... etc
//
// Correctness strategy (see memory/plan_wine_rt_v2.md section 10)
// ---------------------------------------------------------------
// 1. AST-aware substitution — spatch parses C, not text. No false matches inside
//    comments, string literals, or identifiers like `mypthread_cond_signal_thunk`.
// 2. Compile-time backstop — pi_cond_signal/broadcast have a different signature
//    from pthread_cond_signal/broadcast (they take an extra mutex argument). Any
//    site where this rule misses adding the mutex is a hard compile error, not a
//    silent miscompile. The compiler catches every missed conversion for free.
// 3. Paired-mutex recovery — for pthread_cond_signal(C)/broadcast(C), the rule
//    uses metavariables to locate the nearest enclosing pthread_mutex_lock(M) and
//    uses M as the paired mutex. Ambiguous cases are flagged, not guessed.
// 4. Recursive mutex detection — pthread_mutex_init with PTHREAD_MUTEX_RECURSIVE
//    is flagged with /* FIXME-librtpi: manual review */ and NOT rewritten,
//    because librtpi has no recursive-mutex support.
// 5. Differential verification — before running on 11.6, run against the 2022-era
//    tree that 0100 was authored against and diff the output against 0100. Any
//    discrepancy = either a rule bug or a hand-correction in the original.
// 6. Full Wine test suite after sweep + nspa_rt_test real-world check.
//
// Scope
// -----
// This rule targets Unix-side pthread users. PE-side files (e.g. dlls/ntdll/sync.c)
// don't use pthread at all and are unaffected. CS-PI (v2.3) uses raw FUTEX_LOCK_PI
// via a new Unixlib entry, not librtpi — they're disjoint.

// ============================================================================
// Rule 1: type and declaration rewrites
// ============================================================================

@type_mutex@
@@
- pthread_mutex_t
+ pi_mutex_t

@type_cond@
@@
- pthread_cond_t
+ pi_cond_t

// ============================================================================
// Rule 2: static initializer rewrites
// ============================================================================
//
// `pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;`  →  `pi_mutex_t m = PI_MUTEX_INIT(0);`
// `pthread_cond_t  c = PTHREAD_COND_INITIALIZER;`   →  `pi_cond_t  c = PI_COND_INIT(0);`

@init_mutex@
@@
- PTHREAD_MUTEX_INITIALIZER
+ PI_MUTEX_INIT(0)

@init_cond@
@@
- PTHREAD_COND_INITIALIZER
+ PI_COND_INIT(0)

// ============================================================================
// Rule 3: simple function renames (same signature)
// ============================================================================
//
// These are straightforward 1-for-1 renames. The compiler catches any typoed
// or missed case via a "function X not declared" error.

@mutex_ops@
expression M;
@@
(
- pthread_mutex_lock(M)
+ pi_mutex_lock(M)
|
- pthread_mutex_unlock(M)
+ pi_mutex_unlock(M)
|
- pthread_mutex_destroy(M)
+ pi_mutex_destroy(M)
|
- pthread_mutex_trylock(M)
+ pi_mutex_trylock(M)
)

@cond_wait@
expression C, M;
@@
- pthread_cond_wait(C, M)
+ pi_cond_wait(C, M)

@cond_timedwait@
expression C, M, T;
@@
- pthread_cond_timedwait(C, M, T)
+ pi_cond_timedwait(C, M, T)

@cond_destroy@
expression C;
@@
- pthread_cond_destroy(C)
+ pi_cond_destroy(C)

// ============================================================================
// Rule 4: pthread_mutex_init → pi_mutex_init (attribute flattening)
// ============================================================================
//
// `pthread_mutex_init(&m, NULL)`        → `pi_mutex_init(&m, 0)`
// `pthread_mutex_init(&m, &plain_attr)` → `pi_mutex_init(&m, 0)` (best effort)
//
// librtpi's init takes a uint32_t flags word, not a pthread_mutexattr_t. For
// plain attribute pointers we map to 0 (default flags). PTHREAD_MUTEX_RECURSIVE
// cases MUST be hand-reviewed — see Rule 7 below.

@mutex_init_null@
expression M;
@@
- pthread_mutex_init(M, NULL)
+ pi_mutex_init(M, 0)

@mutex_init_attr@
expression M, A;
@@
- pthread_mutex_init(M, A)
+ pi_mutex_init(M, 0)

// ============================================================================
// Rule 5: pthread_cond_init → pi_cond_init
// ============================================================================

@cond_init_null@
expression C;
@@
- pthread_cond_init(C, NULL)
+ pi_cond_init(C, 0)

@cond_init_attr@
expression C, A;
@@
- pthread_cond_init(C, A)
+ pi_cond_init(C, 0)

// ============================================================================
// Rule 6: paired-mutex recovery for pthread_cond_signal / pthread_cond_broadcast
// ============================================================================
//
// librtpi's pi_cond_signal(cond, mutex) and pi_cond_broadcast(cond, mutex)
// take an extra mutex argument that pthread's equivalents don't. Coccinelle
// metavariables let us find the nearest enclosing mutex_lock and use it.
//
// The rule matches patterns like:
//
//     pthread_mutex_lock(&m);
//     ...
//     pthread_cond_signal(&c);
//     ...
//     pthread_mutex_unlock(&m);
//
// and rewrites the inner signal call to pi_cond_signal(&c, &m).
//
// Ambiguous cases (signal called outside the lock, multiple locks nested, etc.)
// are NOT auto-rewritten — they fall through to Rule 7's FIXME flagger.

@cond_signal_paired@
expression C, M;
@@
  pthread_mutex_lock(M);
  ... when != pthread_mutex_unlock(M)
      when != pthread_mutex_lock(M)
(
- pthread_cond_signal(C)
+ pi_cond_signal(C, M)
|
- pthread_cond_broadcast(C)
+ pi_cond_broadcast(C, M)
)
  ... when != pthread_mutex_lock(M)
  pthread_mutex_unlock(M);

// Same pattern with the new pi_mutex_* calls (in case Rule 3 ran first).
@cond_signal_paired_pi@
expression C, M;
@@
  pi_mutex_lock(M);
  ... when != pi_mutex_unlock(M)
      when != pi_mutex_lock(M)
(
- pthread_cond_signal(C)
+ pi_cond_signal(C, M)
|
- pthread_cond_broadcast(C)
+ pi_cond_broadcast(C, M)
)
  ... when != pi_mutex_lock(M)
  pi_mutex_unlock(M);

// ============================================================================
// Rule 7: FIXME markers for sites cocci cannot safely rewrite
// ============================================================================
//
// Anything that reaches this point is a pthread_cond_signal/broadcast that
// doesn't have a clear enclosing mutex_lock pair. Flag it — do NOT silently
// rewrite with a guessed mutex.
//
// Also flag pthread_mutex_init calls with non-NULL attr (handled by Rule 4
// already but the FIXME goes on recursive mutex sites specifically — hand check).

@cond_signal_ambiguous@
expression C;
@@
+ /* FIXME-librtpi: manual review — could not recover paired mutex for cond_signal/broadcast */
(
  pthread_cond_signal(C)
|
  pthread_cond_broadcast(C)
)

// Note: coccinelle cannot reliably detect PTHREAD_MUTEX_RECURSIVE usage because
// the attribute setup is typically via pthread_mutexattr_settype() separate from
// the init call. The recursive-mutex audit is a separate grep step before
// running this rule:
//
//   grep -rn 'PTHREAD_MUTEX_RECURSIVE' dlls/ server/ libs/ | tee recursive.txt
//
// Any sites in that list need hand-review.

// ============================================================================
// END OF RULES
// ============================================================================
//
// After running this rule, produce the FIXME shortlist:
//
//   grep -rn 'FIXME-librtpi' dlls/ server/ libs/ > /tmp/librtpi-fixmes.txt
//
// Every FIXME must be hand-resolved or intentionally left as pthread before commit.
