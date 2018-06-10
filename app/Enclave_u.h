#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_key_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stat64_t {
	uint64_t st_dev;
	uint64_t st_ino;
	uint64_t st_nlink;
	uint32_t st_mode;
	uint32_t st_uid;
	uint32_t st_gid;
	int __pad0;
	uint64_t st_rdev;
	uint64_t st_size;
	int64_t st_blksize;
	int64_t st_blocks;
	int64_t st_atime;
	int64_t st_atime_nsec;
	int64_t st_mtime;
	int64_t st_mtime_nsec;
	int64_t st_ctime;
	int64_t st_ctime_nsec;
	int64_t __reserved[3];
} stat64_t;

size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_stdin_ocall, (void* buf, size_t nbytes));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_stdout_ocall, (const void* buf, size_t nbytes));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_stderr_ocall, (const void* buf, size_t nbytes));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_open_ocall, (int* error, const char* pathname, int flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_close_ocall, (int* error, int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_fcntl_ocall, (int* error, int fd, int cmd, int arg));
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_mmap_ocall, (int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_backtrace_munmap_ocall, (int* error, void* start, size_t length));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_open64_ocall, (int* error, const char* path, int oflag, int mode));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_read_ocall, (int* error, int fd, void* buf, size_t count));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_pread64_ocall, (int* error, int fd, void* buf, size_t count, int64_t offset));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_write_ocall, (int* error, int fd, const void* buf, size_t count));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_pwrite64_ocall, (int* error, int fd, const void* buf, size_t count, int64_t offset));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_close_ocall, (int* error, int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fcntl_arg0_ocall, (int* error, int fd, int cmd));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fcntl_arg1_ocall, (int* error, int fd, int cmd, int arg));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_ioctl_arg0_ocall, (int* error, int fd, int request));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_ioctl_arg1_ocall, (int* error, int fd, int request, int* arg));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fstat64_ocall, (int* error, int fd, struct stat64_t* buf));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fsync_ocall, (int* error, int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fdatasync_ocall, (int* error, int fd));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_ftruncate64_ocall, (int* error, int fd, int64_t length));
int64_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_lseek64_ocall, (int* error, int fd, int64_t offset, int whence));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_fchmod_ocall, (int* error, int fd, uint32_t mode));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_unlink_ocall, (int* error, const char* pathname));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_link_ocall, (int* error, const char* oldpath, const char* newpath));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_rename_ocall, (int* error, const char* oldpath, const char* newpath));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_chmod_ocall, (int* error, const char* path, uint32_t mode));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_readlink_ocall, (int* error, const char* path, char* buf, size_t bufsz));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_symlink_ocall, (int* error, const char* path1, const char* path2));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_stat64_ocall, (int* error, const char* path, struct stat64_t* buf));
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_lstat64_ocall, (int* error, const char* path, struct stat64_t* buf));
char* SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_realpath_ocall, (int* error, const char* pathname));
void SGX_UBRIDGE(SGX_NOCONVENTION, u_fs_free_ocall, (void* p));

sgx_status_t ecall_create_report(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_target_info_t* target_info, sgx_report_t* report);
sgx_status_t ecall_test_sealing_storage_key(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t t_global_init_ecall(sgx_enclave_id_t eid, uint64_t id, const uint8_t* path, size_t len);
sgx_status_t t_global_exit_ecall(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
