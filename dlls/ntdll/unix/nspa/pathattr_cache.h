/*
 * NSPA path-attribute cache — header.
 *
 * Process-local (dev, ino) → (attr, reparse_tag) cache wrapping
 * dlls/ntdll/unix/file.c:get_file_info().  Each call to get_file_info
 * does up to 5 syscalls (lstat + symlink stat + parent stat + 2×
 * xattr_get) most of which return predictable results for stable
 * system paths.  Caching by (dev, ino) collapses subsequent hits to a
 * single lstat (still needed to derive the cache key).
 *
 * NSPA-gated via nspa_rt_prio_base: when RT is off, lookup/store/
 * invalidate short-circuit to no-ops, leaving upstream behaviour
 * byte-identical.
 *
 * Cross-process xattr / mode changes are caught by TTL (50ms default).
 * Same-process mutations call nspa_pathattr_invalidate{,_by_fd,_by_path}
 * explicitly from the mutation site.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_NTDLL_NSPA_PATHATTR_CACHE_H
#define __WINE_NTDLL_NSPA_PATHATTR_CACHE_H

#include <sys/types.h>

/* Lookup.  Returns 1 + populates *attr_out / *reparse_tag_out on a
 * fresh hit; returns 0 on miss, stale entry, or NSPA gate off.
 *
 * reparse_tag_out may be NULL — caller doesn't always care. */
int  nspa_pathattr_lookup( unsigned long long device,
                           unsigned long long inode,
                           unsigned int *attr_out,
                           unsigned int *reparse_tag_out );

/* Store.  Overwrites an existing matching slot or evicts the oldest
 * slot in the bucket on insert.  No-op when NSPA gate is off. */
void nspa_pathattr_store( unsigned long long device,
                          unsigned long long inode,
                          unsigned int attr,
                          unsigned int reparse_tag );

/* Invalidate by (dev, ino).  Called from any xattr / chmod / unlink /
 * rename path that mutates a file we may have cached.  No-op when
 * NSPA gate is off or entry not present. */
void nspa_pathattr_invalidate( unsigned long long device,
                               unsigned long long inode );

/* Invalidate by open fd.  Convenience for call sites that have an fd
 * but no pre-computed (dev, ino).  Performs an fstat to derive the
 * key.  No-op on fstat failure / NSPA gate off. */
void nspa_pathattr_invalidate_by_fd( int fd );

/* Invalidate by path.  Convenience for call sites that have a path
 * but no fd / stat result.  Performs an lstat.  No-op on lstat
 * failure / NSPA gate off. */
void nspa_pathattr_invalidate_by_path( const char *path );

#endif /* __WINE_NTDLL_NSPA_PATHATTR_CACHE_H */
