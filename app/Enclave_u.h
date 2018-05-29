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

sgx_status_t ecall_create_report(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_target_info_t* target_info, sgx_report_t* report);
sgx_status_t t_global_init_ecall(sgx_enclave_id_t eid, uint64_t id, const uint8_t* path, size_t len);
sgx_status_t t_global_exit_ecall(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
