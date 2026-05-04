/*
 * NSPA mapping helpers — cold-path init-time helpers extracted from
 * server/mapping.c.
 */

#ifndef __WINE_SERVER_NSPA_MAPPING_HELPERS_H
#define __WINE_SERVER_NSPA_MAPPING_HELPERS_H

#include <sys/types.h>

#ifdef __linux__
extern size_t nspa_get_min_hugepage_size( void );
#endif

#endif /* __WINE_SERVER_NSPA_MAPPING_HELPERS_H */
