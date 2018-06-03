#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_create_report_t {
	sgx_status_t ms_retval;
	sgx_target_info_t* ms_target_info;
	sgx_report_t* ms_report;
} ms_ecall_create_report_t;

typedef struct ms_ecall_seal_key_t {
	sgx_status_t ms_retval;
	uint8_t* ms_sealed_log_out;
} ms_ecall_seal_key_t;

typedef struct ms_t_global_init_ecall_t {
	uint64_t ms_id;
	uint8_t* ms_path;
	size_t ms_len;
} ms_t_global_init_ecall_t;

typedef struct ms_u_stdin_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stdin_ocall_t;

typedef struct ms_u_stdout_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stdout_ocall_t;

typedef struct ms_u_stderr_ocall_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_nbytes;
} ms_u_stderr_ocall_t;

typedef struct ms_u_backtrace_open_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_pathname;
	int ms_flags;
} ms_u_backtrace_open_ocall_t;

typedef struct ms_u_backtrace_close_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_backtrace_close_ocall_t;

typedef struct ms_u_backtrace_fcntl_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
	int ms_arg;
} ms_u_backtrace_fcntl_ocall_t;

typedef struct ms_u_backtrace_mmap_ocall_t {
	void* ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
	int ms_prot;
	int ms_flags;
	int ms_fd;
	int64_t ms_offset;
} ms_u_backtrace_mmap_ocall_t;

typedef struct ms_u_backtrace_munmap_ocall_t {
	int ms_retval;
	int* ms_error;
	void* ms_start;
	size_t ms_length;
} ms_u_backtrace_munmap_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_u_stdin_ocall(void* pms)
{
	ms_u_stdin_ocall_t* ms = SGX_CAST(ms_u_stdin_ocall_t*, pms);
	ms->ms_retval = u_stdin_ocall(ms->ms_buf, ms->ms_nbytes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_stdout_ocall(void* pms)
{
	ms_u_stdout_ocall_t* ms = SGX_CAST(ms_u_stdout_ocall_t*, pms);
	ms->ms_retval = u_stdout_ocall((const void*)ms->ms_buf, ms->ms_nbytes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_stderr_ocall(void* pms)
{
	ms_u_stderr_ocall_t* ms = SGX_CAST(ms_u_stderr_ocall_t*, pms);
	ms->ms_retval = u_stderr_ocall((const void*)ms->ms_buf, ms->ms_nbytes);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_open_ocall(void* pms)
{
	ms_u_backtrace_open_ocall_t* ms = SGX_CAST(ms_u_backtrace_open_ocall_t*, pms);
	ms->ms_retval = u_backtrace_open_ocall(ms->ms_error, (const char*)ms->ms_pathname, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_close_ocall(void* pms)
{
	ms_u_backtrace_close_ocall_t* ms = SGX_CAST(ms_u_backtrace_close_ocall_t*, pms);
	ms->ms_retval = u_backtrace_close_ocall(ms->ms_error, ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_fcntl_ocall(void* pms)
{
	ms_u_backtrace_fcntl_ocall_t* ms = SGX_CAST(ms_u_backtrace_fcntl_ocall_t*, pms);
	ms->ms_retval = u_backtrace_fcntl_ocall(ms->ms_error, ms->ms_fd, ms->ms_cmd, ms->ms_arg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_mmap_ocall(void* pms)
{
	ms_u_backtrace_mmap_ocall_t* ms = SGX_CAST(ms_u_backtrace_mmap_ocall_t*, pms);
	ms->ms_retval = u_backtrace_mmap_ocall(ms->ms_error, ms->ms_start, ms->ms_length, ms->ms_prot, ms->ms_flags, ms->ms_fd, ms->ms_offset);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_backtrace_munmap_ocall(void* pms)
{
	ms_u_backtrace_munmap_ocall_t* ms = SGX_CAST(ms_u_backtrace_munmap_ocall_t*, pms);
	ms->ms_retval = u_backtrace_munmap_ocall(ms->ms_error, ms->ms_start, ms->ms_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[13];
} ocall_table_Enclave = {
	13,
	{
		(void*)Enclave_u_stdin_ocall,
		(void*)Enclave_u_stdout_ocall,
		(void*)Enclave_u_stderr_ocall,
		(void*)Enclave_u_backtrace_open_ocall,
		(void*)Enclave_u_backtrace_close_ocall,
		(void*)Enclave_u_backtrace_fcntl_ocall,
		(void*)Enclave_u_backtrace_mmap_ocall,
		(void*)Enclave_u_backtrace_munmap_ocall,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_create_report(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_target_info_t* target_info, sgx_report_t* report)
{
	sgx_status_t status;
	ms_ecall_create_report_t ms;
	ms.ms_target_info = (sgx_target_info_t*)target_info;
	ms.ms_report = report;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_test_seal_unseal(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_seal_key(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* sealed_log_out)
{
	sgx_status_t status;
	ms_ecall_seal_key_t ms;
	ms.ms_sealed_log_out = sealed_log_out;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t t_global_init_ecall(sgx_enclave_id_t eid, uint64_t id, const uint8_t* path, size_t len)
{
	sgx_status_t status;
	ms_t_global_init_ecall_t ms;
	ms.ms_id = id;
	ms.ms_path = (uint8_t*)path;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t t_global_exit_ecall(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

