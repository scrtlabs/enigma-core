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

sgx_status_t ecall_create_report(const sgx_target_info_t* target_info, sgx_report_t* report);
void ecall_test_seal_unseal();
sgx_status_t ecall_seal_key(uint8_t* sealed_log_out);
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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
