/*
 * NSPA local-file bypass — server-side header.
 *
 * Inline declarations for the inode-aggregation table publish hooks.
 * Implementation in server/nspa_local_file.c.  Called from server/fd.c
 * whenever an fd is added to or removed from inode->open.
 */
#ifndef __WINE_SERVER_NSPA_LOCAL_FILE_H
#define __WINE_SERVER_NSPA_LOCAL_FILE_H

/* Publish per-(device,inode) aggregated state to the shared table.
 * Caller (in server/fd.c, where struct inode internals live) walks
 * inode->open to compute the aggregates and passes them in.
 *
 *   refcount == 0  → clears the slot for this (dev, ino)
 *   refcount > 0   → write/update the slot (allocate if first open)
 *
 * Idempotent.  No-op if the shared region was never allocated
 * (memfd_create unsupported, no client has called nspa_get_inode_table
 * yet).  Single-threaded server context — caller does not lock.
 *
 * Bucket overflow (rare with 4 slots × 1024 buckets vs. realistic
 * file-open counts) is silently dropped — clients fall back to server
 * create_file as today, no correctness loss. */
extern void nspa_inode_publish_slot( unsigned long long device, unsigned long long inode,
                                     unsigned int refcount,
                                     unsigned int agg_existing_access,
                                     unsigned int agg_existing_sharing );

/* True if the shared region has been materialised (some client called
 * nspa_get_inode_table at least once).  Hooks check this to avoid the
 * publish overhead before any client has opted in. */
extern int nspa_inode_table_is_active( void );

#endif /* __WINE_SERVER_NSPA_LOCAL_FILE_H */
