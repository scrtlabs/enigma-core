#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_create_report_t {
	sgx_status_t ms_retval;
	sgx_target_info_t* ms_target_info;
	sgx_report_t* ms_report;
} ms_ecall_create_report_t;

typedef struct ms_ecall_test_sealing_storage_key_t {
	sgx_status_t ms_retval;
} ms_ecall_test_sealing_storage_key_t;

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

typedef struct ms_u_fs_open64_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_path;
	int ms_oflag;
	int ms_mode;
} ms_u_fs_open64_ocall_t;

typedef struct ms_u_fs_read_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_u_fs_read_ocall_t;

typedef struct ms_u_fs_pread64_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	int64_t ms_offset;
} ms_u_fs_pread64_ocall_t;

typedef struct ms_u_fs_write_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_u_fs_write_ocall_t;

typedef struct ms_u_fs_pwrite64_ocall_t {
	size_t ms_retval;
	int* ms_error;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	int64_t ms_offset;
} ms_u_fs_pwrite64_ocall_t;

typedef struct ms_u_fs_close_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fs_close_ocall_t;

typedef struct ms_u_fs_fcntl_arg0_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
} ms_u_fs_fcntl_arg0_ocall_t;

typedef struct ms_u_fs_fcntl_arg1_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_cmd;
	int ms_arg;
} ms_u_fs_fcntl_arg1_ocall_t;

typedef struct ms_u_fs_ioctl_arg0_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_request;
} ms_u_fs_ioctl_arg0_ocall_t;

typedef struct ms_u_fs_ioctl_arg1_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int ms_request;
	int* ms_arg;
} ms_u_fs_ioctl_arg1_ocall_t;

typedef struct ms_u_fs_fstat64_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	struct stat64_t* ms_buf;
} ms_u_fs_fstat64_ocall_t;

typedef struct ms_u_fs_fsync_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fs_fsync_ocall_t;

typedef struct ms_u_fs_fdatasync_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
} ms_u_fs_fdatasync_ocall_t;

typedef struct ms_u_fs_ftruncate64_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	int64_t ms_length;
} ms_u_fs_ftruncate64_ocall_t;

typedef struct ms_u_fs_lseek64_ocall_t {
	int64_t ms_retval;
	int* ms_error;
	int ms_fd;
	int64_t ms_offset;
	int ms_whence;
} ms_u_fs_lseek64_ocall_t;

typedef struct ms_u_fs_fchmod_ocall_t {
	int ms_retval;
	int* ms_error;
	int ms_fd;
	uint32_t ms_mode;
} ms_u_fs_fchmod_ocall_t;

typedef struct ms_u_fs_unlink_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_pathname;
} ms_u_fs_unlink_ocall_t;

typedef struct ms_u_fs_link_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_oldpath;
	char* ms_newpath;
} ms_u_fs_link_ocall_t;

typedef struct ms_u_fs_rename_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_oldpath;
	char* ms_newpath;
} ms_u_fs_rename_ocall_t;

typedef struct ms_u_fs_chmod_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_path;
	uint32_t ms_mode;
} ms_u_fs_chmod_ocall_t;

typedef struct ms_u_fs_readlink_ocall_t {
	size_t ms_retval;
	int* ms_error;
	char* ms_path;
	char* ms_buf;
	size_t ms_bufsz;
} ms_u_fs_readlink_ocall_t;

typedef struct ms_u_fs_symlink_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_path1;
	char* ms_path2;
} ms_u_fs_symlink_ocall_t;

typedef struct ms_u_fs_stat64_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_path;
	struct stat64_t* ms_buf;
} ms_u_fs_stat64_ocall_t;

typedef struct ms_u_fs_lstat64_ocall_t {
	int ms_retval;
	int* ms_error;
	char* ms_path;
	struct stat64_t* ms_buf;
} ms_u_fs_lstat64_ocall_t;

typedef struct ms_u_fs_realpath_ocall_t {
	char* ms_retval;
	int* ms_error;
	char* ms_pathname;
} ms_u_fs_realpath_ocall_t;

typedef struct ms_u_fs_free_ocall_t {
	void* ms_p;
} ms_u_fs_free_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_create_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_report_t* ms = SGX_CAST(ms_ecall_create_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_target_info_t* _tmp_target_info = ms->ms_target_info;
	size_t _len_target_info = sizeof(*_tmp_target_info);
	sgx_target_info_t* _in_target_info = NULL;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(*_tmp_report);
	sgx_report_t* _in_report = NULL;

	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);
	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_target_info, _tmp_target_info, _len_target_info);
	}
	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}

	ms->ms_retval = ecall_create_report((const sgx_target_info_t*)_in_target_info, _in_report);
err:
	if (_in_target_info) free((void*)_in_target_info);
	if (_in_report) {
		memcpy(_tmp_report, _in_report, _len_report);
		free(_in_report);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_test_sealing_storage_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_test_sealing_storage_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_test_sealing_storage_key_t* ms = SGX_CAST(ms_ecall_test_sealing_storage_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_test_sealing_storage_key();


	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_init_ecall(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_t_global_init_ecall_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_t_global_init_ecall_t* ms = SGX_CAST(ms_t_global_init_ecall_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_path = ms->ms_path;
	size_t _tmp_len = ms->ms_len;
	size_t _len_path = _tmp_len;
	uint8_t* _in_path = NULL;

	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_path != NULL && _len_path != 0) {
		_in_path = (uint8_t*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_path, _tmp_path, _len_path);
	}

	t_global_init_ecall(ms->ms_id, (const uint8_t*)_in_path, _tmp_len);
err:
	if (_in_path) free((void*)_in_path);

	return status;
}

static sgx_status_t SGX_CDECL sgx_t_global_exit_ecall(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	t_global_exit_ecall();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_create_report, 0},
		{(void*)(uintptr_t)sgx_ecall_test_sealing_storage_key, 0},
		{(void*)(uintptr_t)sgx_t_global_init_ecall, 0},
		{(void*)(uintptr_t)sgx_t_global_exit_ecall, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[39][4];
} g_dyn_entry_table = {
	39,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL u_stdin_ocall(size_t* retval, void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stdin_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stdin_ocall_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stdin_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stdin_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stdout_ocall(size_t* retval, const void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stdout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stdout_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stdout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stdout_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stderr_ocall(size_t* retval, const void* buf, size_t nbytes)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbytes;

	ms_u_stderr_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stderr_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stderr_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stderr_ocall_t));

	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_nbytes = nbytes;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_open_ocall(int* retval, int* error, const char* pathname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_backtrace_open_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_open_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_open_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_open_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		memcpy(__tmp, pathname, _len_pathname);
		__tmp = (void *)((size_t)__tmp + _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_close_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_backtrace_close_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_close_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_close_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_close_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_fcntl_ocall(int* retval, int* error, int fd, int cmd, int arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_backtrace_fcntl_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_fcntl_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_fcntl_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_fcntl_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_mmap_ocall(void** retval, int* error, void* start, size_t length, int prot, int flags, int fd, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_backtrace_mmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_mmap_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_mmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_mmap_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_start = SGX_CAST(void*, start);
	ms->ms_length = length;
	ms->ms_prot = prot;
	ms->ms_flags = flags;
	ms->ms_fd = fd;
	ms->ms_offset = offset;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_backtrace_munmap_ocall(int* retval, int* error, void* start, size_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_backtrace_munmap_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_backtrace_munmap_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_backtrace_munmap_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_backtrace_munmap_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_start = SGX_CAST(void*, start);
	ms->ms_length = length;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_open64_ocall(int* retval, int* error, const char* path, int oflag, int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_fs_open64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_open64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_open64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_open64_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		memcpy(__tmp, path, _len_path);
		__tmp = (void *)((size_t)__tmp + _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_oflag = oflag;
	ms->ms_mode = mode;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_read_ocall(size_t* retval, int* error, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_buf = count;

	ms_u_fs_read_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_read_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_read_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_read_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_pread64_ocall(size_t* retval, int* error, int fd, void* buf, size_t count, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_buf = count;

	ms_u_fs_pread64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_pread64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_pread64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_pread64_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	ms->ms_offset = offset;
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_write_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_buf = count;

	ms_u_fs_write_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_write_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_write_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_write_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_pwrite64_ocall(size_t* retval, int* error, int fd, const void* buf, size_t count, int64_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_buf = count;

	ms_u_fs_pwrite64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_pwrite64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_pwrite64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_pwrite64_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (void*)__tmp;
		memcpy(__tmp, buf, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_count = count;
	ms->ms_offset = offset;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_close_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_close_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_close_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_close_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_close_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fcntl_arg0_ocall(int* retval, int* error, int fd, int cmd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_fcntl_arg0_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fcntl_arg0_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fcntl_arg0_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fcntl_arg0_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fcntl_arg1_ocall(int* retval, int* error, int fd, int cmd, int arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_fcntl_arg1_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fcntl_arg1_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fcntl_arg1_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fcntl_arg1_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_cmd = cmd;
	ms->ms_arg = arg;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_ioctl_arg0_ocall(int* retval, int* error, int fd, int request)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_ioctl_arg0_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_ioctl_arg0_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_ioctl_arg0_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_ioctl_arg0_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_request = request;
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_ioctl_arg1_ocall(int* retval, int* error, int fd, int request, int* arg)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_arg = sizeof(*arg);

	ms_u_fs_ioctl_arg1_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_ioctl_arg1_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (arg != NULL && sgx_is_within_enclave(arg, _len_arg)) ? _len_arg : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_ioctl_arg1_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_ioctl_arg1_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_request = request;
	if (arg != NULL && sgx_is_within_enclave(arg, _len_arg)) {
		ms->ms_arg = (int*)__tmp;
		memcpy(__tmp, arg, _len_arg);
		__tmp = (void *)((size_t)__tmp + _len_arg);
	} else if (arg == NULL) {
		ms->ms_arg = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fstat64_ocall(int* retval, int* error, int fd, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_buf = sizeof(*buf);

	ms_u_fs_fstat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fstat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fstat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fstat64_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (struct stat64_t*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fsync_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_fsync_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fsync_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fsync_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fsync_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fdatasync_ocall(int* retval, int* error, int fd)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_fdatasync_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fdatasync_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fdatasync_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fdatasync_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_ftruncate64_ocall(int* retval, int* error, int fd, int64_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_ftruncate64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_ftruncate64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_ftruncate64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_ftruncate64_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_length = length;
	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_lseek64_ocall(int64_t* retval, int* error, int fd, int64_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_lseek64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_lseek64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_lseek64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_lseek64_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_offset = offset;
	ms->ms_whence = whence;
	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_fchmod_ocall(int* retval, int* error, int fd, uint32_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);

	ms_u_fs_fchmod_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_fchmod_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_fchmod_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_fchmod_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_fd = fd;
	ms->ms_mode = mode;
	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_unlink_ocall(int* retval, int* error, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_fs_unlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_unlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_unlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_unlink_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		memcpy(__tmp, pathname, _len_pathname);
		__tmp = (void *)((size_t)__tmp + _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_link_ocall(int* retval, int* error, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_fs_link_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_link_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (oldpath != NULL && sgx_is_within_enclave(oldpath, _len_oldpath)) ? _len_oldpath : 0;
	ocalloc_size += (newpath != NULL && sgx_is_within_enclave(newpath, _len_newpath)) ? _len_newpath : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_link_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_link_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (oldpath != NULL && sgx_is_within_enclave(oldpath, _len_oldpath)) {
		ms->ms_oldpath = (char*)__tmp;
		memcpy(__tmp, oldpath, _len_oldpath);
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
	} else if (oldpath == NULL) {
		ms->ms_oldpath = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (newpath != NULL && sgx_is_within_enclave(newpath, _len_newpath)) {
		ms->ms_newpath = (char*)__tmp;
		memcpy(__tmp, newpath, _len_newpath);
		__tmp = (void *)((size_t)__tmp + _len_newpath);
	} else if (newpath == NULL) {
		ms->ms_newpath = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(30, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_rename_ocall(int* retval, int* error, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_fs_rename_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_rename_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (oldpath != NULL && sgx_is_within_enclave(oldpath, _len_oldpath)) ? _len_oldpath : 0;
	ocalloc_size += (newpath != NULL && sgx_is_within_enclave(newpath, _len_newpath)) ? _len_newpath : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_rename_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_rename_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (oldpath != NULL && sgx_is_within_enclave(oldpath, _len_oldpath)) {
		ms->ms_oldpath = (char*)__tmp;
		memcpy(__tmp, oldpath, _len_oldpath);
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
	} else if (oldpath == NULL) {
		ms->ms_oldpath = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (newpath != NULL && sgx_is_within_enclave(newpath, _len_newpath)) {
		ms->ms_newpath = (char*)__tmp;
		memcpy(__tmp, newpath, _len_newpath);
		__tmp = (void *)((size_t)__tmp + _len_newpath);
	} else if (newpath == NULL) {
		ms->ms_newpath = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(31, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_chmod_ocall(int* retval, int* error, const char* path, uint32_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_fs_chmod_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_chmod_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_chmod_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_chmod_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		memcpy(__tmp, path, _len_path);
		__tmp = (void *)((size_t)__tmp + _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_mode = mode;
	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_readlink_ocall(size_t* retval, int* error, const char* path, char* buf, size_t bufsz)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = bufsz;

	ms_u_fs_readlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_readlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_readlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_readlink_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		memcpy(__tmp, path, _len_path);
		__tmp = (void *)((size_t)__tmp + _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (char*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_bufsz = bufsz;
	status = sgx_ocall(33, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_symlink_ocall(int* retval, int* error, const char* path1, const char* path2)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_path1 = path1 ? strlen(path1) + 1 : 0;
	size_t _len_path2 = path2 ? strlen(path2) + 1 : 0;

	ms_u_fs_symlink_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_symlink_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (path1 != NULL && sgx_is_within_enclave(path1, _len_path1)) ? _len_path1 : 0;
	ocalloc_size += (path2 != NULL && sgx_is_within_enclave(path2, _len_path2)) ? _len_path2 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_symlink_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_symlink_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path1 != NULL && sgx_is_within_enclave(path1, _len_path1)) {
		ms->ms_path1 = (char*)__tmp;
		memcpy(__tmp, path1, _len_path1);
		__tmp = (void *)((size_t)__tmp + _len_path1);
	} else if (path1 == NULL) {
		ms->ms_path1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path2 != NULL && sgx_is_within_enclave(path2, _len_path2)) {
		ms->ms_path2 = (char*)__tmp;
		memcpy(__tmp, path2, _len_path2);
		__tmp = (void *)((size_t)__tmp + _len_path2);
	} else if (path2 == NULL) {
		ms->ms_path2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(34, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_stat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(*buf);

	ms_u_fs_stat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_stat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_stat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_stat64_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		memcpy(__tmp, path, _len_path);
		__tmp = (void *)((size_t)__tmp + _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (struct stat64_t*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(35, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_lstat64_ocall(int* retval, int* error, const char* path, struct stat64_t* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_buf = sizeof(*buf);

	ms_u_fs_lstat64_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_lstat64_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	void *__tmp_buf = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) ? _len_buf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_lstat64_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_lstat64_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		memcpy(__tmp, path, _len_path);
		__tmp = (void *)((size_t)__tmp + _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buf != NULL && sgx_is_within_enclave(buf, _len_buf)) {
		ms->ms_buf = (struct stat64_t*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
	} else if (buf == NULL) {
		ms->ms_buf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(36, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
		if (buf) memcpy((void*)buf, __tmp_buf, _len_buf);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_realpath_ocall(char** retval, int* error, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_error = sizeof(*error);
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_fs_realpath_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_realpath_ocall_t);
	void *__tmp = NULL;

	void *__tmp_error = NULL;
	ocalloc_size += (error != NULL && sgx_is_within_enclave(error, _len_error)) ? _len_error : 0;
	ocalloc_size += (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) ? _len_pathname : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_realpath_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_realpath_ocall_t));

	if (error != NULL && sgx_is_within_enclave(error, _len_error)) {
		ms->ms_error = (int*)__tmp;
		__tmp_error = __tmp;
		memset(__tmp_error, 0, _len_error);
		__tmp = (void *)((size_t)__tmp + _len_error);
	} else if (error == NULL) {
		ms->ms_error = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pathname != NULL && sgx_is_within_enclave(pathname, _len_pathname)) {
		ms->ms_pathname = (char*)__tmp;
		memcpy(__tmp, pathname, _len_pathname);
		__tmp = (void *)((size_t)__tmp + _len_pathname);
	} else if (pathname == NULL) {
		ms->ms_pathname = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(37, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (error) memcpy((void*)error, __tmp_error, _len_error);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fs_free_ocall(void* p)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fs_free_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fs_free_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fs_free_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fs_free_ocall_t));

	ms->ms_p = SGX_CAST(void*, p);
	status = sgx_ocall(38, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

