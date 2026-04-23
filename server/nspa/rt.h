/*
 * NSPA RT scheduling — wineserver side. Public declarations.
 */
#ifndef __WINE_SERVER_NSPA_RT_H
#define __WINE_SERVER_NSPA_RT_H

struct thread;

extern int  nspa_rt_prio_base;      /* -1 when RT is disabled */
extern int  nspa_rt_policy;         /* SCHED_FIFO / SCHED_RR / SCHED_OTHER */
extern int  nspa_rt_skip_apply;     /* set by DECL_HANDLER(set_thread_info) when client-side applied */
extern int  nspa_srv_rt_prio;       /* wineserver main-thread RT priority; -1 disabled */
extern int  nspa_srv_rt_policy;     /* SCHED_FIFO / SCHED_RR for wineserver main thread */

extern void nspa_rt_init( void );
extern int  nspa_rt_map_prio( int nt_band );
extern void nspa_rt_apply( int unix_tid, int nt_band );
extern void nspa_rt_maybe_demote( int unix_tid );

#endif /* __WINE_SERVER_NSPA_RT_H */
