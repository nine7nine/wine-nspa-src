/*
 * Ntdll Unix private interface
 *
 * Copyright (C) 2020 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __NTDLL_UNIX_PRIVATE_H
#define __NTDLL_UNIX_PRIVATE_H

#include <pthread.h>
#include <signal.h>
#include <rtpi.h>
#include "unixlib.h"
#include "wine/unixlib.h"
#include "wine/server.h"
#include "wine/list.h"
#include "wine/debug.h"

struct msghdr;

typedef struct
{
    union
    {
        NTSTATUS Status;
        ULONG Pointer;
    };
    ULONG Information;
} IO_STATUS_BLOCK32;

#ifdef __i386__
static const WORD current_machine = IMAGE_FILE_MACHINE_I386;
#elif defined(__x86_64__)
static const WORD current_machine = IMAGE_FILE_MACHINE_AMD64;
#elif defined(__arm__)
static const WORD current_machine = IMAGE_FILE_MACHINE_ARMNT;
#elif defined(__aarch64__)
static const WORD current_machine = IMAGE_FILE_MACHINE_ARM64;
#endif
extern WORD native_machine;

static const BOOL is_win64 = (sizeof(void *) > sizeof(int));

static const ULONG_PTR limit_2g = (ULONG_PTR)1 << 31;
static const ULONG_PTR limit_4g = (ULONG_PTR)((ULONGLONG)1 << 32);

static inline BOOL is_machine_64bit( WORD machine )
{
    return (machine == IMAGE_FILE_MACHINE_AMD64 || machine == IMAGE_FILE_MACHINE_ARM64);
}

#ifdef _WIN64
typedef TEB32 WOW_TEB;
typedef PEB32 WOW_PEB;
static inline TEB64 *NtCurrentTeb64(void) { return NULL; }
#else
typedef TEB64 WOW_TEB;
typedef PEB64 WOW_PEB;
static inline TEB64 *NtCurrentTeb64(void) { return (TEB64 *)NtCurrentTeb()->GdiBatchCount; }
#endif

extern WOW_PEB *wow_peb;
extern ULONG_PTR user_space_wow_limit;
extern SECTION_IMAGE_INFORMATION main_image_info;

static inline WOW_TEB *get_wow_teb( TEB *teb )
{
    return teb->WowTebOffset ? (WOW_TEB *)((char *)teb + teb->WowTebOffset) : NULL;
}

static inline BOOL is_wow64(void)
{
    return !!wow_peb;
}

/* check for old-style Wow64 (using a 32-bit ntdll.so) */
static inline BOOL is_old_wow64(void)
{
    return !is_win64 && wow_peb;
}

static inline BOOL is_arm64ec(void)
{
    return (current_machine == IMAGE_FILE_MACHINE_ARM64 &&
            main_image_info.Machine == IMAGE_FILE_MACHINE_AMD64);
}

#ifdef __linux__
/* NSPA v1.5 shmem IPC: mirror of server-side struct request_shm layout.
 * Must match server/thread.h exactly. See request.c send_request_shm /
 * wait_reply_shm for the state machine. */
#ifndef NSPA_REQUEST_SHM_SIZE
# define NSPA_REQUEST_SHM_SIZE (1 * 1024 * 1024)
#endif
struct request_shm
{
    int futex;
    int server_dispatch_tid;  /* NSPA v2.4: Linux TID of the wineserver
                               * dispatch thread for this shm. Written
                               * once by that thread on startup. The
                               * client reads this to manually boost
                               * the server's scheduling priority while
                               * blocked on a reply (manual PI, same
                               * pattern as CS-PI v2.3). 0 = not set.
                               * Must match server/thread.h exactly. */
    union
    {
        union generic_request req;
        union generic_reply   reply;
    } u;
};
#endif

/* per-thread data for the Unix side, stored at the bottom of the signal stack */

struct thread_data
{
    TEB         *teb;               /* TEB */
    int          request_fd;        /* fd for sending server requests */
    int          reply_fd;          /* fd for receiving server replies */
    int          wait_fd[2];        /* fd for sleeping server requests */
    int          alert_fd;          /* inproc sync fd for user apc alerts */
    DWORD        tid;               /* thread id */
    BOOL         allow_writes;      /* ThreadAllowWrites flags */
    pthread_t    pthread_id;        /* pthread thread id */
    void        *jmp_buf;           /* setjmp buffer for exception handling */
    void        *start;             /* thread entry point */
    void        *param;             /* thread entry point parameter */
    struct list  entry;             /* entry in TEB list */
    char         debug_info[0x800]; /* debug_info structure */
#ifdef __linux__
    int                           request_shm_fd; /* NSPA v1.5: shared memory fd */
    volatile struct request_shm  *request_shm;    /* NSPA v1.5: shared memory mapping */
#endif
    char         signal_stack[];    /* signal stack */
    /* char kernel_stack[] */
};

extern pthread_key_t thread_data_key;

static inline struct thread_data *get_thread_data(void)
{
    return pthread_getspecific( thread_data_key );
}

/* thread private data, stored in NtCurrentTeb()->GdiTebBatch */
struct teb_data
{
    void                     *cpu_data[16];  /* 1d4/02f0 reserved for CPU-specific data */
    SYSTEM_SERVICE_TABLE     *syscall_table; /* 214/0370 syscall table */
    struct syscall_frame     *syscall_frame; /* 218/0378 current syscall frame */
    int                       syscall_trace; /* 21c/0380 syscall trace flag */
    DWORD                     nspa_unix_tid; /* NSPA v2.3: cached Linux kernel TID
                                              * for CS-PI fast path. 0 = uninitialized.
                                              * Populated on first NtNspaGetUnixTid call. */
    int                       nspa_rt_cached_policy;  /* NSPA v2.5: cached sched policy
                                                       * (SCHED_FIFO/RR/OTHER). Updated by
                                                       * nspa_rt_apply_tid on self (tid==0). */
    int                       nspa_rt_cached_prio;    /* NSPA v2.5: cached sched_priority.
                                                       * 0 = not RT / uninitialized. */
};

C_ASSERT( sizeof(struct teb_data) <= sizeof(((TEB *)0)->GdiTebBatch) );
#ifdef _WIN64
C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct teb_data, syscall_table ) == 0x370 );
C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct teb_data, syscall_frame ) == 0x378 );
C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct teb_data, syscall_trace ) == 0x380 );
#else
C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct teb_data, syscall_table ) == 0x214 );
C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct teb_data, syscall_frame ) == 0x218 );
C_ASSERT( offsetof( TEB, GdiTebBatch ) + offsetof( struct teb_data, syscall_trace ) == 0x21c );
#endif

/* NSPA v2.3 — offset of nspa_unix_tid from the start of GdiTebBatch.
 * PE-side code (which cannot include unix_private.h) needs this as a
 * literal constant. The PE-side value is hardcoded in dlls/ntdll/sync.c
 * (see NSPA_UNIX_TID_OFFSET). The C_ASSERTs below verify that the PE
 * literal matches the real struct layout — if the struct changes, the
 * build fails and both sides need updating in sync. */
#ifdef _WIN64
C_ASSERT( offsetof( struct teb_data, nspa_unix_tid ) == 0x94 );
#else
C_ASSERT( offsetof( struct teb_data, nspa_unix_tid ) == 0x4c );
#endif

/* NSPA: compat alias for code that uses the old wine-11.6 struct name.
 * The new wine-11.8 layout split fields between struct thread_data
 * (signal stack, FDs, request_shm) and struct teb_data (TEB->GdiTebBatch,
 * syscall + NSPA PE-accessible fields). Code accessing nspa_unix_tid /
 * nspa_rt_cached_* uses ntdll_get_thread_data(); code accessing FDs or
 * request_shm uses get_thread_data(). */
#define ntdll_thread_data teb_data

static inline struct teb_data *ntdll_get_thread_data(void)
{
    return (struct teb_data *)&NtCurrentTeb()->GdiTebBatch;
}

/* returns TRUE if the async is complete; FALSE if it should be restarted */
typedef BOOL async_callback_t( void *user, ULONG_PTR *info, unsigned int *status );

struct async_fileio
{
    async_callback_t    *callback;
    struct async_fileio *next;
    HANDLE               handle;
};

struct pe_mapping_info
{
    HANDLE               shared_file;
    UNICODE_STRING       nt_name;
    ANSI_STRING          exp_name;
    void                *version_res;
    ULONG                version_len;
    struct pe_image_info image;
    char                 data[];
};

static const SIZE_T page_size = 0x1000;
static const SIZE_T signal_stack_mask = 0xffff;
static const SIZE_T signal_stack_size = 0x10000 - offsetof( struct thread_data, signal_stack );
static const SIZE_T kernel_stack_size = 0x100000;
static const SIZE_T min_kernel_stack  = 0x2000;
static const LONG teb_offset = 0x2000;

#define FILE_WRITE_TO_END_OF_FILE      ((LONGLONG)-1)
#define FILE_USE_FILE_POINTER_POSITION ((LONGLONG)-2)

/* callbacks to PE ntdll from the Unix side */
extern void *pDbgUiRemoteBreakin;
extern void *pKiRaiseUserExceptionDispatcher;
extern void *pKiUserExceptionDispatcher;
extern void *pKiUserApcDispatcher;
extern void *pKiUserCallbackDispatcher;
extern void *pKiUserEmulationDispatcher;
extern void *pLdrInitializeThunk;
extern void *pRtlUserThreadStart;
extern void *p__wine_ctrl_routine;
extern SYSTEM_DLL_INIT_BLOCK *pLdrSystemDllInitBlock;

struct _FILE_FS_DEVICE_INFORMATION;

extern const char wine_build[];

extern const char *home_dir;
extern const char *data_dir;
extern const char *build_dir;
extern const char *config_dir;
extern const char *wineloader;
extern const char *user_name;
extern const char **dll_paths;
extern const char **system_dll_paths;
extern PEB *peb;
extern DWORD pid;
extern USHORT *uctable;
extern USHORT *lctable;
extern SIZE_T startup_info_size;
extern BOOL is_prefix_bootstrap;
extern int main_argc;
extern char **main_argv;
extern WCHAR **main_wargv;
extern const WCHAR system_dir[];
extern unsigned int supported_machines_count;
extern USHORT supported_machines[8];
extern BOOL process_exiting;
extern HANDLE keyed_event;
extern int inproc_device_fd;
extern int nspa_request_channel_fd; /* NSPA gamma: per-process ntsync channel for shm-IPC */
extern timeout_t server_start_time;
extern sigset_t server_block_set;
extern pi_mutex_t fd_cache_mutex;
extern struct _KUSER_SHARED_DATA *user_shared_data;
extern ULONG process_cookie;

extern void init_environment(void);
extern void init_startup_info(void);

/* NSPA RT v1.2: exposed so other ntdll/unix files can access the
 * HANDLE→unix_tid map and cached process priority class. All live in
 * dlls/ntdll/unix/thread.c. */
/* NSPA RT constants (shared between thread.c intercept sites and nspa/rt.c). */
#ifndef NSPA_RT_TIME_CRITICAL
# define NSPA_RT_TIME_CRITICAL 15  /* THREAD_PRIORITY_TIME_CRITICAL from winnt.h */
#endif
#ifndef NSPA_THREAD_PRIORITY_IDLE
# define NSPA_THREAD_PRIORITY_IDLE (-15)
#endif
extern void nspa_rt_set_cached_priocls( int cls );
extern void nspa_rt_map_remove( HANDLE handle );
extern void nspa_rt_map_add( HANDLE handle, int tid );
extern int  nspa_rt_map_lookup( HANDLE handle );
extern void nspa_rt_probe( void );
extern int  nspa_rt_apply_tid( int tid, int nt_band );
extern int  nspa_resolve_nt_band( int base_priority );
extern int  nspa_rt_prio_base;
extern int  nspa_rt_policy_v;

/* NSPA local NT timer dispatcher (dlls/ntdll/unix/nspa_local_timer.c).
 * Each entry point returns STATUS_NOT_IMPLEMENTED when the feature gate is
 * off or the handle is not a managed timer, signalling the caller to fall
 * through to the server path. */
extern NTSTATUS nspa_local_timer_create( HANDLE *handle, ACCESS_MASK access,
                                         const OBJECT_ATTRIBUTES *attr,
                                         TIMER_TYPE timer_type );
extern NTSTATUS nspa_local_timer_set( HANDLE handle, const LARGE_INTEGER *when,
                                      PTIMER_APC_ROUTINE callback, void *arg,
                                      ULONG period, BOOLEAN *previous_state );
extern NTSTATUS nspa_local_timer_cancel( HANDLE handle, BOOLEAN *previous_state );
extern NTSTATUS nspa_local_timer_query( HANDLE handle, TIMER_BASIC_INFORMATION *info );
extern void     nspa_local_timer_close( HANDLE handle );
extern NTSTATUS nspa_local_timer_check_duplicate( HANDLE source_handle, HANDLE source_process,
                                                  HANDLE target_process );
extern NTSTATUS nspa_local_timer_register_duplicate( HANDLE source_handle, HANDLE new_handle );
extern void     nspa_local_file_diag_categorize( const OBJECT_ATTRIBUTES *attr, ACCESS_MASK access,
                                                 ULONG sharing, ULONG disposition, ULONG options );
extern void     nspa_local_file_diag_lazy_start( void );
extern NTSTATUS nspa_local_file_publish_open( unsigned long long device, unsigned long long inode,
                                              unsigned int access, unsigned int sharing );
extern void     nspa_local_file_publish_close( unsigned long long device, unsigned long long inode );
extern NTSTATUS nspa_local_file_table_add( HANDLE handle, int unix_fd,
                                           unsigned long long device, unsigned long long inode,
                                           unsigned int access, unsigned int sharing,
                                           unsigned int options,
                                           unsigned int attributes,
                                           const UNICODE_STRING *nt_name );
extern int      nspa_local_file_table_remove( HANDLE handle, int *unix_fd_out,
                                              unsigned long long *device_out,
                                              unsigned long long *inode_out );
extern int      nspa_local_file_table_lookup_unix_fd( HANDLE handle );
extern int      nspa_local_file_table_lookup_full( HANDLE handle, int *unix_fd_out, unsigned int *options_out );
extern NTSTATUS nspa_local_file_check_sharing( unsigned long long device, unsigned long long inode,
                                               unsigned int my_access, unsigned int my_sharing );
extern NTSTATUS nspa_local_file_try_bypass( HANDLE *handle, const char *unix_name,
                                            const UNICODE_STRING *nt_name,
                                            ACCESS_MASK access, ULONG sharing,
                                            ULONG options, ULONG attributes,
                                            IO_STATUS_BLOCK *io );
extern void     nspa_local_file_promote_inheritable( void );
extern int      nspa_local_file_is_local_handle( HANDLE h );
extern int      nspa_local_file_close( HANDLE handle );
extern void     nspa_local_file_section_intercept_bump( int cause );
extern void     nspa_local_file_get_unix_fd_intercept_bump( void );
extern HANDLE   nspa_local_file_get_or_promote_server_handle( HANDLE local_handle );
extern HANDLE   nspa_promote_if_local( HANDLE h );
extern HANDLE   nspa_promote_if_local_traced( HANDLE h, const char *tag, unsigned int info );
extern int      nspa_local_file_try_get_unix_fd( HANDLE handle, unsigned int wanted_access,
                                                 int *unix_fd, int *needs_close,
                                                 enum server_fd_type *type, unsigned int *options );
extern void *create_startup_info( const UNICODE_STRING *nt_image, ULONG process_flags,
                                  const RTL_USER_PROCESS_PARAMETERS *params,
                                  const struct pe_image_info *pe_info, DWORD *info_size );
extern char *get_alternate_wineloader( WORD machine );
extern NTSTATUS exec_wineloader( char **argv, int socketfd, const struct pe_image_info *pe_info );
extern NTSTATUS load_builtin( struct pe_mapping_info *pe_mapping, USHORT machine,
                              SECTION_IMAGE_INFORMATION *info, void **module, SIZE_T *size,
                              ULONG_PTR limit_low, ULONG_PTR limit_high, off_t offset );
extern NTSTATUS load_unixlib_by_name( const UNICODE_STRING *nt_name, void **handle_ret );
extern BOOL is_system_dir_path( const UNICODE_STRING *path, WORD *machine );
extern NTSTATUS load_main_exe( UNICODE_STRING *nt_name, USHORT load_machine, void **module );
extern NTSTATUS load_start_exe( UNICODE_STRING *nt_name, void **module );
extern ULONG_PTR redirect_arm64ec_rva( void *module, ULONG_PTR rva, const IMAGE_ARM64EC_METADATA *metadata );
extern void start_server( BOOL debug );

extern unsigned int server_call_unlocked( void *req_ptr );
extern void server_enter_uninterrupted_section( pi_mutex_t *mutex, sigset_t *sigset );
extern void server_leave_uninterrupted_section( pi_mutex_t *mutex, sigset_t *sigset );
extern unsigned int server_select( const union select_op *select_op, data_size_t size, UINT flags,
                                   timeout_t abs_timeout, struct context_data *context, struct user_apc *user_apc );
extern unsigned int server_wait( const union select_op *select_op, data_size_t size, UINT flags,
                                 const LARGE_INTEGER *timeout );
extern unsigned int server_wait_for_object( HANDLE handle, BOOL alertable, const LARGE_INTEGER *timeout );
extern unsigned int server_queue_process_apc( HANDLE process, const union apc_call *call,
                                              union apc_result *result );
extern int server_get_unix_fd( HANDLE handle, unsigned int wanted_access, int *unix_fd,
                               int *needs_close, enum server_fd_type *type, unsigned int *options );
extern int wine_server_receive_fd( obj_handle_t *handle );
extern void process_exit_wrapper( int status ) DECLSPEC_NORETURN;
extern size_t server_init_process(void);
extern void server_init_process_done(void);
extern void server_init_thread( void *entry_point, BOOL *suspend );
extern int server_pipe( int fd[2] );

extern void fpux_to_fpu( I386_FLOATING_SAVE_AREA *fpu, const XSAVE_FORMAT *fpux );
extern void fpu_to_fpux( XSAVE_FORMAT *fpux, const I386_FLOATING_SAVE_AREA *fpu );

static inline void set_context_exception_reporting_flags( DWORD *context_flags, DWORD reporting_flag )
{
    if (!(*context_flags & CONTEXT_EXCEPTION_REQUEST))
    {
        *context_flags &= ~(CONTEXT_EXCEPTION_REPORTING | CONTEXT_SERVICE_ACTIVE | CONTEXT_EXCEPTION_ACTIVE);
        return;
    }
    *context_flags = (*context_flags & ~(CONTEXT_SERVICE_ACTIVE | CONTEXT_EXCEPTION_ACTIVE))
                     | CONTEXT_EXCEPTION_REPORTING | reporting_flag;
}

extern unsigned int xstate_get_size( UINT64 compaction_mask, UINT64 mask );
extern void copy_xstate( XSAVE_AREA_HEADER *dst, XSAVE_AREA_HEADER *src, UINT64 mask );

extern void set_process_instrumentation_callback( void *callback );

extern void *get_cpu_area( USHORT machine );
extern void set_thread_id( struct thread_data *data );
extern NTSTATUS init_thread_stack( TEB *teb, ULONG_PTR limit, SIZE_T reserve_size, SIZE_T commit_size );
extern void DECLSPEC_NORETURN abort_thread( int status );
extern void DECLSPEC_NORETURN abort_process( int status );
extern void DECLSPEC_NORETURN exit_process( int status );
extern void wait_suspend( CONTEXT *context );
extern NTSTATUS send_debug_event( EXCEPTION_RECORD *rec, CONTEXT *context, BOOL first_chance, BOOL exception );
extern NTSTATUS set_thread_context( HANDLE handle, const void *context, BOOL *self, USHORT machine );
extern NTSTATUS get_thread_context( HANDLE handle, void *context, BOOL *self, USHORT machine );
extern unsigned int alloc_object_attributes( const OBJECT_ATTRIBUTES *attr, struct object_attributes **ret,
                                             data_size_t *ret_len );
extern NTSTATUS system_time_precise( void *args );

/* NSPA: large-pages allocation type for anon_mmap_alloc and map_view.
 * NONE = ordinary pages (the legacy behavior). LARGE = MAP_HUGETLB at
 * the smallest hugepage size (typically 2 MB on x86_64) — what Windows
 * calls a "large page". HUGE = MAP_HUGETLB at 1 GB — what Windows calls
 * a "huge page" (the MEM_EXTENDED_PARAMETER_NONPAGED_HUGE attribute).
 * See dlls/ntdll/unix/virtual.c::mmap_large_pages_flags for the
 * mapping to mmap flags. */
enum large_pages_type
{
    LARGE_PAGES_NONE  = 0,
    LARGE_PAGES_LARGE = 1,
    LARGE_PAGES_HUGE  = 2,
};

extern void *anon_mmap_fixed( void *start, size_t size, int prot, int flags );
extern void *anon_mmap_alloc( size_t size, int prot, enum large_pages_type type );
extern void virtual_init(void);
extern ULONG_PTR get_system_affinity_mask(void);
extern void virtual_get_system_info( SYSTEM_BASIC_INFORMATION *info, BOOL wow64 );
extern NTSTATUS virtual_map_builtin_module( HANDLE mapping, void **module, SIZE_T *size,
                                            SECTION_IMAGE_INFORMATION *info, ULONG_PTR limit_low,
                                            ULONG_PTR limit_high, WORD machine, BOOL prefer_native, off_t offset );
extern NTSTATUS virtual_map_module( HANDLE mapping, void **module, SIZE_T *size,
                                    SECTION_IMAGE_INFORMATION *info, ULONG_PTR limit_low,
                                    ULONG_PTR limit_high, USHORT machine );
extern NTSTATUS virtual_create_builtin_view( void *module, const UNICODE_STRING *nt_name,
                                             struct pe_image_info *info, void *so_handle );
extern NTSTATUS virtual_relocate_module( void *module );
extern TEB *virtual_alloc_first_teb(void);
extern NTSTATUS virtual_alloc_teb( struct thread_data *data );
struct thread_data *virtual_alloc_thread_data(void);
extern void virtual_free_thread_data( struct thread_data *data );
extern NTSTATUS virtual_clear_tls_index( ULONG index );
extern NTSTATUS virtual_alloc_thread_stack( INITIAL_TEB *stack, ULONG_PTR limit_low, ULONG_PTR limit_high,
                                            SIZE_T reserve_size, SIZE_T commit_size, BOOL guard_page );
extern void virtual_map_user_shared_data(void);
extern void virtual_init_user_shared_data(void);
extern NTSTATUS virtual_handle_fault( struct thread_data *data, EXCEPTION_RECORD *rec, void *stack );
extern unsigned int virtual_locked_server_call( void *req_ptr );
extern ssize_t virtual_locked_read( int fd, void *addr, size_t size );
extern ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset );
extern ssize_t virtual_locked_recvmsg( int fd, struct msghdr *hdr, int flags );
extern BOOL virtual_is_valid_code_address( const void *addr, SIZE_T size );
extern void *virtual_setup_exception( struct thread_data *data, void *stack_ptr, size_t size, EXCEPTION_RECORD *rec );
extern BOOL virtual_check_buffer_for_read( const void *ptr, SIZE_T size );
extern BOOL virtual_check_buffer_for_write( void *ptr, SIZE_T size );
extern SIZE_T virtual_uninterrupted_read_memory( const void *addr, void *buffer, SIZE_T size );
extern NTSTATUS virtual_uninterrupted_write_memory( void *addr, const void *buffer, SIZE_T size );
extern void virtual_set_force_exec( BOOL enable );
extern void virtual_enable_write_exceptions( BOOL enable );
extern void virtual_set_large_address_space(void);
extern void virtual_fill_image_information( const struct pe_image_info *pe_info,
                                            SECTION_IMAGE_INFORMATION *info );
extern void *get_builtin_so_handle( void *module );
extern NTSTATUS set_builtin_unixlib_name( void *module, const char *name );

extern NTSTATUS get_thread_ldt_entry( HANDLE handle, THREAD_DESCRIPTOR_INFORMATION *info, ULONG len );
extern void *get_native_context( CONTEXT *context );
extern void *get_wow_context( CONTEXT *context );
extern BOOL get_thread_times( int unix_pid, int unix_tid, LARGE_INTEGER *kernel_time,
                              LARGE_INTEGER *user_time );
extern NTSTATUS signal_alloc_thread( TEB *teb );
extern void signal_free_thread( TEB *teb );
extern void signal_disable_syscall_dispatch(void);
extern void signal_init_process(void);
extern void DECLSPEC_NORETURN signal_start_thread( PRTL_THREAD_START_ROUTINE entry, void *arg,
                                                   BOOL suspend, TEB *teb );
extern SYSTEM_SERVICE_TABLE KeServiceDescriptorTable[4];
extern void __wine_syscall_dispatcher(void);
extern void __wine_syscall_dispatcher_return(void);
extern void __wine_unix_call_dispatcher(void);
extern NTSTATUS signal_set_full_context( CONTEXT *context );
extern NTSTATUS get_thread_wow64_context( HANDLE handle, void *ctx, ULONG size );
extern NTSTATUS set_thread_wow64_context( HANDLE handle, const void *ctx, ULONG size );
extern void fill_vm_counters( VM_COUNTERS_EX *pvmi, int unix_pid );
extern NTSTATUS open_hkcu_key( const char *path, HANDLE *key );

extern NTSTATUS sync_ioctl( HANDLE file, ULONG code, void *in_buffer, ULONG in_size,
                            void *out_buffer, ULONG out_size );
extern NTSTATUS cdrom_DeviceIoControl( HANDLE device, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                       IO_STATUS_BLOCK *io, UINT code, void *in_buffer,
                                       UINT in_size, void *out_buffer, UINT out_size );
extern NTSTATUS serial_DeviceIoControl( HANDLE device, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                        IO_STATUS_BLOCK *io, UINT code, void *in_buffer,
                                        UINT in_size, void *out_buffer, UINT out_size );
extern NTSTATUS serial_FlushBuffersFile( int fd );
extern NTSTATUS sock_ioctl( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user, IO_STATUS_BLOCK *io,
                            UINT code, void *in_buffer, UINT in_size, void *out_buffer, UINT out_size );
extern NTSTATUS sock_read( HANDLE handle, int fd, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                           IO_STATUS_BLOCK *io, void *buffer, ULONG length );
extern NTSTATUS sock_write( HANDLE handle, int fd, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                            IO_STATUS_BLOCK *io, const void *buffer, ULONG length );
extern NTSTATUS tape_DeviceIoControl( HANDLE device, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                      IO_STATUS_BLOCK *io, UINT code, void *in_buffer,
                                      UINT in_size, void *out_buffer, UINT out_size );

extern struct async_fileio *alloc_fileio( DWORD size, async_callback_t callback, HANDLE handle );
extern void release_fileio( struct async_fileio *io );
extern NTSTATUS errno_to_status( int err );
extern NTSTATUS get_nt_and_unix_names( OBJECT_ATTRIBUTES *attr, UNICODE_STRING *nt_name,
                                       char **unix_name, UINT disposition, BOOL open_reparse );
extern NTSTATUS unix_to_nt_file_name( const char *unix_name, WCHAR **nt, UINT disposition );
extern NTSTATUS get_full_path( char *name, const WCHAR *curdir, UNICODE_STRING *nt_name );
extern NTSTATUS get_nt_path( const WCHAR *name, UNICODE_STRING *nt_name );
extern NTSTATUS open_unix_file( HANDLE *handle, const char *unix_name, ACCESS_MASK access,
                                OBJECT_ATTRIBUTES *attr, ULONG attributes, ULONG sharing, ULONG disposition,
                                ULONG options, void *ea_buffer, ULONG ea_length );
extern NTSTATUS get_device_info( int fd, struct _FILE_FS_DEVICE_INFORMATION *info );
extern void init_files(void);
extern void init_cpu_info(void);
extern void init_shared_data_cpuinfo( struct _KUSER_SHARED_DATA *data );
extern void file_complete_async( HANDLE handle, unsigned int options, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                 IO_STATUS_BLOCK *io, NTSTATUS status, ULONG_PTR information );
extern void set_async_direct_result( HANDLE *async_handle, unsigned int options, IO_STATUS_BLOCK *io,
                                     NTSTATUS status, ULONG_PTR information, BOOL mark_pending );

extern NTSTATUS unixcall_wine_dbg_write( void *args );
extern NTSTATUS unixcall_wine_server_call( void *args );
extern NTSTATUS unixcall_wine_server_fd_to_handle( void *args );
extern NTSTATUS unixcall_wine_server_handle_to_fd( void *args );
extern NTSTATUS unixcall_wine_server_signal_internal_sync( void *args );
extern NTSTATUS unixcall_wine_spawnvp( void *args );
#ifdef _WIN64
extern NTSTATUS wow64_wine_dbg_write( void *args );
extern NTSTATUS wow64_wine_server_call( void *args );
extern NTSTATUS wow64_wine_server_fd_to_handle( void *args );
extern NTSTATUS wow64_wine_server_handle_to_fd( void *args );
extern NTSTATUS wow64_wine_server_signal_internal_sync( void *args );
extern NTSTATUS wow64_wine_spawnvp( void *args );
#endif

extern void dbg_init(void);

/* io_uring integration (io_uring.c) — all return -ENOSYS if unavailable */
extern BOOL ntdll_io_uring_enabled(void);
extern void ntdll_io_uring_cleanup(void);
extern int  ntdll_io_uring_poll( int fd, short events, int timeout_ms );
extern void ntdll_io_uring_process_completions(void);
extern int  ntdll_io_uring_get_eventfd(void);
extern void ntdll_client_poll_set( int unix_fd );
extern void ntdll_client_poll_clear( int unix_fd );
extern void ntdll_io_uring_flush_deferred(void);
extern void ntdll_signal_event_direct( HANDLE event );
extern int  ntdll_resolve_event_sync_fd( HANDLE event );
extern int  ntdll_io_uring_submit_socket_poll( int unix_fd, short events,
                                               HANDLE handle, HANDLE wait_handle,
                                               HANDLE event, PIO_APC_ROUTINE apc,
                                               void *apc_user, IO_STATUS_BLOCK *io,
                                               unsigned int options, void *sock_async,
                                               BOOL is_send );
extern int  ntdll_io_uring_submit_file_read( int unix_fd, int needs_close, void *buffer,
                                             ULONG already, ULONG count, HANDLE handle,
                                             HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                             IO_STATUS_BLOCK *io, unsigned int options,
                                             BOOL avail_mode );
extern int  ntdll_io_uring_submit_file_write( int unix_fd, int needs_close, const void *buffer,
                                              ULONG already, ULONG count, HANDLE handle,
                                              HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                              IO_STATUS_BLOCK *io, unsigned int options );
extern int  ntdll_io_uring_submit_recv( int unix_fd, int needs_close, struct msghdr *hdr,
                                        int flags, HANDLE handle, HANDLE event,
                                        PIO_APC_ROUTINE apc, void *apc_user,
                                        IO_STATUS_BLOCK *io, unsigned int options );
extern int  ntdll_io_uring_submit_send( int unix_fd, int needs_close, struct msghdr *hdr,
                                        int flags, HANDLE handle, HANDLE event,
                                        PIO_APC_ROUTINE apc, void *apc_user,
                                        IO_STATUS_BLOCK *io, unsigned int options );

extern void close_inproc_sync( HANDLE handle );
extern BOOL is_client_handle( HANDLE handle );
extern void close_client_inproc_sync( HANDLE handle );
extern void abandon_client_mutexes( DWORD tid );

extern NTSTATUS call_user_apc_dispatcher( CONTEXT *context_ptr, unsigned int flags, ULONG_PTR arg1, ULONG_PTR arg2,
                                          ULONG_PTR arg3, PNTAPCFUNC func, NTSTATUS status );
extern NTSTATUS call_user_exception_dispatcher( EXCEPTION_RECORD *rec, CONTEXT *context );
extern void call_raise_user_exception_dispatcher(void);

#define IMAGE_DLLCHARACTERISTICS_PREFER_NATIVE 0x0010 /* Wine extension */

#define TICKSPERSEC 10000000
#define NSECPERSEC 1000000000
#define SECS_1601_TO_1970  ((369 * 365 + 89) * (ULONGLONG)86400)

static inline ULONGLONG ticks_from_time_t( time_t time )
{
    if (sizeof(time_t) == sizeof(int))  /* time_t may be signed */
        return ((ULONGLONG)(ULONG)time + SECS_1601_TO_1970) * TICKSPERSEC;
    else
        return ((ULONGLONG)time + SECS_1601_TO_1970) * TICKSPERSEC;
}

static inline const char *debugstr_us( const UNICODE_STRING *us )
{
    if (!us) return "<null>";
    return debugstr_wn( us->Buffer, us->Length / sizeof(WCHAR) );
}

/* convert from straight ASCII to Unicode without depending on the current codepage */
static inline void ascii_to_unicode( WCHAR *dst, const char *src, size_t len )
{
    while (len--) *dst++ = (unsigned char)*src++;
}

static inline void *get_kernel_stack( struct thread_data *data )
{
    return data->signal_stack + signal_stack_size;
}

static inline struct teb_data *get_teb_data( struct thread_data *data )
{
    return (struct teb_data *)&data->teb->GdiTebBatch;
}

static inline struct syscall_frame *get_syscall_frame( struct thread_data *data )
{
    return get_teb_data(data)->syscall_frame;
}

static inline void alloc_syscall_frame( SIZE_T frame_size )
{
    struct thread_data *data = get_thread_data();
    void *frame = (char *)get_kernel_stack(data) + kernel_stack_size - frame_size;
    get_teb_data(data)->syscall_frame = frame;
}

static inline BOOL is_inside_signal_stack( struct thread_data *data, void *ptr )
{
    return ((char *)ptr >= data->signal_stack && (char *)ptr < data->signal_stack + signal_stack_size);
}

static inline BOOL is_inside_syscall( struct thread_data *data, ULONG_PTR sp )
{
    return ((char *)sp >= (char *)get_kernel_stack( data ) &&
            (char *)sp <= (char *)get_syscall_frame( data ));
}

static inline BOOL is_ec_code( ULONG_PTR ptr )
{
    const UINT64 *map = (const UINT64 *)peb->EcCodeBitMap;
    ULONG_PTR page = ptr / page_size;
    return (map[page / 64] >> (page & 63)) & 1;
}

static inline void mutex_lock( pi_mutex_t *mutex )
{
    if (!process_exiting) pi_mutex_lock( mutex );
}

static inline void mutex_unlock( pi_mutex_t *mutex )
{
    if (!process_exiting) pi_mutex_unlock( mutex );
}

static inline struct async_data server_async( HANDLE handle, struct async_fileio *user, HANDLE event,
                                              PIO_APC_ROUTINE apc, void *apc_context, client_ptr_t iosb )
{
    struct async_data async;
    async.handle      = wine_server_obj_handle( handle );
    async.user        = wine_server_client_ptr( user );
    async.iosb        = iosb;
    async.event       = wine_server_obj_handle( event );
    async.apc         = wine_server_client_ptr( apc );
    async.apc_context = wine_server_client_ptr( apc_context );
    return async;
}

static inline NTSTATUS wait_async( HANDLE handle, BOOL alertable )
{
    return server_wait_for_object( handle, alertable, NULL );
}

static inline BOOL in_wow64_call(void)
{
    return is_win64 && is_wow64();
}

static inline void set_async_iosb( client_ptr_t iosb, NTSTATUS status, ULONG_PTR info )
{
    if (!iosb) return;

    /* GetOverlappedResult() and WSAGetOverlappedResult() expect that if the
     * status is written, that the information (and buffer, which was written
     * earlier from the async callback) will be available. Hence we need to
     * store the status last, with release semantics to ensure that those
     * writes are visible. This release is paired with a read-acquire in
     * GetOverlappedResult() and WSAGetOverlappedResult():
     *
     * CPU 0 (set_async_iosb)            CPU 1 (GetOverlappedResultEx)
     * ===========================       ===========================
     * write buffer
     * write Information
     * WriteRelease(Status) <--------.
     *                               |
     *                               |
     *                (paired with)  `-> ReadAcquire(Status)
     *                                   read Information
     */

    if (in_wow64_call())
    {
        IO_STATUS_BLOCK32 *io = wine_server_get_ptr( iosb );
        io->Information = info;
        WriteRelease( &io->Status, status );
    }
    else
    {
        IO_STATUS_BLOCK *io = wine_server_get_ptr( iosb );
        io->Information = info;
        WriteRelease( &io->Status, status );
    }
}

static inline client_ptr_t iosb_client_ptr( IO_STATUS_BLOCK *io )
{
    if (io && in_wow64_call()) return wine_server_client_ptr( io->Pointer );
    return wine_server_client_ptr( io );
}

static inline ULONG_PTR get_zero_bits_limit( ULONG_PTR zero_bits )
{
    unsigned int shift;

    if (zero_bits == 0) return 0;

    if (zero_bits < 32) shift = 32 + zero_bits;
    else
    {
        shift = 63;
#ifdef _WIN64
        if (zero_bits >> 32) { shift -= 32; zero_bits >>= 32; }
#endif
        if (zero_bits >> 16) { shift -= 16; zero_bits >>= 16; }
        if (zero_bits >> 8) { shift -= 8; zero_bits >>= 8; }
        if (zero_bits >> 4) { shift -= 4; zero_bits >>= 4; }
        if (zero_bits >> 2) { shift -= 2; zero_bits >>= 2; }
        if (zero_bits >> 1) { shift -= 1; }
    }
    return (~(UINT64)0) >> shift;
}


enum loadorder
{
    LO_INVALID,
    LO_DISABLED,
    LO_NATIVE,
    LO_BUILTIN,
    LO_NATIVE_BUILTIN,  /* native then builtin */
    LO_BUILTIN_NATIVE,  /* builtin then native */
    LO_DEFAULT          /* nothing specified, use default strategy */
};

extern void set_load_order_app_name( const WCHAR *app_name );
extern enum loadorder get_load_order( const UNICODE_STRING *nt_name, BOOL is_system_dir,
                                      const struct pe_mapping_info *pe_mapping );

static inline WCHAR ntdll_towupper( WCHAR ch )
{
    return ch + uctable[uctable[uctable[ch >> 8] + ((ch >> 4) & 0x0f)] + (ch & 0x0f)];
}

static inline WCHAR ntdll_towlower( WCHAR ch )
{
    return ch + lctable[lctable[lctable[ch >> 8] + ((ch >> 4) & 0x0f)] + (ch & 0x0f)];
}

static inline WCHAR *ntdll_wcsupr( WCHAR *str )
{
    WCHAR *ret;
    for (ret = str; *str; str++) *str = ntdll_towupper(*str);
    return ret;
}

#define wcsupr(str)        ntdll_wcsupr(str)
#define towupper(c)        ntdll_towupper(c)
#define towlower(c)        ntdll_towlower(c)

static inline void init_unicode_string( UNICODE_STRING *str, const WCHAR *data )
{
    str->Length = wcslen(data) * sizeof(WCHAR);
    str->MaximumLength = str->Length + sizeof(WCHAR);
    str->Buffer = (WCHAR *)data;
}

static inline NTSTATUS map_section( HANDLE mapping, void **ptr, SIZE_T *size, ULONG protect )
{
    *ptr = NULL;
    *size = 0;
    return NtMapViewOfSection( mapping, NtCurrentProcess(), ptr, user_space_wow_limit,
                               0, NULL, size, ViewShare, 0, protect );
}

/* LDT definitions */

#if defined(__i386__) || defined(__x86_64__)

struct ldt_bits
{
    unsigned int limit : 24;
    unsigned int type : 5;
    unsigned int granularity : 1;
    unsigned int default_big : 1;
};

#define LDT_SIZE 8192

extern UINT ldt_bitmap[LDT_SIZE / 32];

extern void ldt_set_entry( WORD sel, LDT_ENTRY entry );
extern WORD ldt_update_entry( WORD sel, LDT_ENTRY entry );
extern NTSTATUS ldt_get_entry( WORD sel, CLIENT_ID client_id, LDT_ENTRY *entry );

static const LDT_ENTRY null_entry;
static const struct ldt_bits data_segment = { .type = 0x13, .default_big = 1 };
static const struct ldt_bits code_segment = { .type = 0x1b, .default_big = 1 };

static inline unsigned int ldt_get_base( LDT_ENTRY ent )
{
    return (ent.BaseLow |
            (unsigned int)ent.HighWord.Bits.BaseMid << 16 |
            (unsigned int)ent.HighWord.Bits.BaseHi << 24);
}

static inline struct ldt_bits ldt_set_limit( struct ldt_bits bits, unsigned int limit )
{
    if ((bits.granularity = (limit >= 0x100000))) limit >>= 12;
    bits.limit = limit;
    return bits;
}

static inline LDT_ENTRY ldt_make_entry( unsigned int base, struct ldt_bits bits )
{
    LDT_ENTRY entry;

    entry.BaseLow                   = (WORD)base;
    entry.HighWord.Bits.BaseMid     = (BYTE)(base >> 16);
    entry.HighWord.Bits.BaseHi      = (BYTE)(base >> 24);
    entry.LimitLow                  = (WORD)bits.limit;
    entry.HighWord.Bits.LimitHi     = bits.limit >> 16;
    entry.HighWord.Bits.Dpl         = 3;
    entry.HighWord.Bits.Pres        = 1;
    entry.HighWord.Bits.Type        = bits.type;
    entry.HighWord.Bits.Granularity = bits.granularity;
    entry.HighWord.Bits.Sys         = 0;
    entry.HighWord.Bits.Reserved_0  = 0;
    entry.HighWord.Bits.Default_Big = bits.default_big;
    return entry;
}

static inline WORD ldt_alloc_entry( LDT_ENTRY entry )
{
    int idx;
    for (idx = 0; idx < ARRAY_SIZE(ldt_bitmap); idx++)
    {
        if (ldt_bitmap[idx] == ~0u) continue;
        idx = idx * 32 + __builtin_ffs( ~ldt_bitmap[idx] ) - 1;
        return ldt_update_entry( (idx << 3) | 7, entry );
    }
    return 0;
}

static inline void ldt_free_entry( WORD sel )
{
    unsigned int index = sel >> 3;
    ldt_bitmap[index / 32] &= ~(1u << (index & 31));
}

static inline LDT_ENTRY ldt_make_cs32_entry(void)
{
    return ldt_make_entry( 0, ldt_set_limit( code_segment, ~0u ));
}

static inline LDT_ENTRY ldt_make_ds32_entry(void)
{
    return ldt_make_entry( 0, ldt_set_limit( data_segment, ~0u ));
}

static inline LDT_ENTRY ldt_make_fs32_entry( void *teb )
{
    return ldt_make_entry( PtrToUlong(teb), ldt_set_limit( data_segment, page_size - 1 ));
}

static inline int is_gdt_sel( WORD sel )
{
    return !(sel & 4);
}

#endif  /* defined(__i386__) || defined(__x86_64__) */

#endif /* __NTDLL_UNIX_PRIVATE_H */
