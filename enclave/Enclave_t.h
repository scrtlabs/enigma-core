#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

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

sgx_status_t ecall_create_report(const sgx_target_info_t* target_info, sgx_report_t* report);
sgx_status_t ecall_test_sealing_storage_key();
void t_global_init_ecall(uint64_t id, const uint8_t* path, size_t len);
void t_global_exit_ecall();

sgx_status_t SGX_CDECL u_stdin_ocall(size_t* retval, void* buf, size_t nbytes);
sgx_status_t SGX_CDECL u_stdout_ocall(size_t* retval, const void* buf, size_t nbytes);
sgx_status_t SGX_CDECL u_stderr_ocall(size_t* retval, const void* buf, size_t nbytes);
sgx_status_t SGX_CDECL u_backtrace_open_ocall(int* retval, int* error, const char* pathname, int flags);
sgx_status_t SGX_CDECL u_backtrace_close_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_backtrace_fcntl_ocall(int* retval, int* error, int fd, int cmd, int arg);
sgx_status_t SGX_CDECL u_backtrace_mmap_ocall(void** retval, int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset);
sgx_status_t SGX_CDECL u_backtrace_munmap_ocall(int* retval, int* error, void* start, size_t length);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_fs_open64_ocall(int* retval, int* error, const char* path, int oflag, int mode);
sgx_status_t SGX_CDECL u_fs_read_ocall(size_t* retval, int* error, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL u_fs_pread64_ocall(size_t* retval, int* error, int fd, void* buf, size_t count, int64_t offset);
sgx_status_t SGX_CDECL u_fs_write_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL u_fs_pwrite64_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count, int64_t offset);
sgx_status_t SGX_CDECL u_fs_close_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_fs_fcntl_arg0_ocall(int* retval, int* error, int fd, int cmd);
sgx_status_t SGX_CDECL u_fs_fcntl_arg1_ocall(int* retval, int* error, int fd, int cmd, int arg);
sgx_status_t SGX_CDECL u_fs_ioctl_arg0_ocall(int* retval, int* error, int fd, int request);
sgx_status_t SGX_CDECL u_fs_ioctl_arg1_ocall(int* retval, int* error, int fd, int request, int* arg);
sgx_status_t SGX_CDECL u_fs_fstat64_ocall(int* retval, int* error, int fd, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_fs_fsync_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_fs_fdatasync_ocall(int* retval, int* error, int fd);
sgx_status_t SGX_CDECL u_fs_ftruncate64_ocall(int* retval, int* error, int fd, int64_t length);
sgx_status_t SGX_CDECL u_fs_lseek64_ocall(int64_t* retval, int* error, int fd, int64_t offset, int whence);
sgx_status_t SGX_CDECL u_fs_fchmod_ocall(int* retval, int* error, int fd, uint32_t mode);
sgx_status_t SGX_CDECL u_fs_unlink_ocall(int* retval, int* error, const char* pathname);
sgx_status_t SGX_CDECL u_fs_link_ocall(int* retval, int* error, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL u_fs_rename_ocall(int* retval, int* error, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL u_fs_chmod_ocall(int* retval, int* error, const char* path, uint32_t mode);
sgx_status_t SGX_CDECL u_fs_readlink_ocall(size_t* retval, int* error, const char* path, char* buf, size_t bufsz);
sgx_status_t SGX_CDECL u_fs_symlink_ocall(int* retval, int* error, const char* path1, const char* path2);
sgx_status_t SGX_CDECL u_fs_stat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_fs_lstat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf);
sgx_status_t SGX_CDECL u_fs_realpath_ocall(char** retval, int* error, const char* pathname);
sgx_status_t SGX_CDECL u_fs_free_ocall(void* p);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
