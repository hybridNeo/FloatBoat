#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

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


typedef struct ms_generate_random_number_t {
	int ms_retval;
} ms_generate_random_number_t;

typedef struct ms_ecall_start_raft_main_t {
	char* ms_ip_addr;
	char* ms_port;
	char* ms_intro_ip;
	char* ms_intro_port;
} ms_ecall_start_raft_main_t;

typedef struct ms_ecall_s_node_t {
	char* ms_ip_addr;
	char* ms_port;
	char* ms_intro_ip;
	char* ms_intro_port;
} ms_ecall_s_node_t;

typedef struct ms_ecall_heartbeat_handler_t {
	char* ms_retval;
	char* ms_request;
	char* ms_r_ep;
} ms_ecall_heartbeat_handler_t;

typedef struct ms_ecall_get_vote_t {
	char* ms_ip;
	int ms_port;
} ms_ecall_get_vote_t;

typedef struct ms_ecall_api_handler_t {
	char* ms_request;
} ms_ecall_api_handler_t;

typedef struct ms_ecall_send_heartbeat_t {
	char* ms_message;
	char* ms_ip;
	int ms_port;
} ms_ecall_send_heartbeat_t;

typedef struct ms_seal_t {
	sgx_status_t ms_retval;
	uint8_t* ms_plaintext;
	size_t ms_plaintext_len;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_seal_t;

typedef struct ms_unseal_t {
	sgx_status_t ms_retval;
	sgx_sealed_data_t* ms_sealed_data;
	size_t ms_sealed_size;
	uint8_t* ms_plaintext;
	uint32_t ms_plaintext_len;
} ms_unseal_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

typedef struct ms_ocall_sleep_t {
	int ms_time;
} ms_ocall_sleep_t;

typedef struct ms_ocall_get_vote_t {
	char* ms_ip;
	int ms_port;
} ms_ocall_get_vote_t;

typedef struct ms_ocall_heartbeat_server_t {
	int ms_port;
} ms_ocall_heartbeat_server_t;

typedef struct ms_ocall_api_server_t {
	int ms_port;
} ms_ocall_api_server_t;

typedef struct ms_ocall_start_node_t {
	char* ms_ip_addr;
	char* ms_port;
	char* ms_intro_ip;
	char* ms_intro_port;
} ms_ocall_start_node_t;

typedef struct ms_ocall_send_heartbeat_t {
	char* ms_request;
	char* ms_host;
	int ms_port_no;
} ms_ocall_send_heartbeat_t;

typedef struct ms_ocall_f_wrapper_t {
	char* ms_request;
	char* ms_host;
	int ms_port_no;
} ms_ocall_f_wrapper_t;

typedef struct ms_ocall_udp_sendmsg_t {
	char* ms_retval;
	char* ms_request;
	char* ms_host;
	int ms_port_no;
} ms_ocall_udp_sendmsg_t;

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

static sgx_status_t SGX_CDECL sgx_generate_random_number(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_random_number_t));
	ms_generate_random_number_t* ms = SGX_CAST(ms_generate_random_number_t*, pms);
	sgx_status_t status = SGX_SUCCESS;


	ms->ms_retval = generate_random_number();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_start_raft_main(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_start_raft_main_t));
	ms_ecall_start_raft_main_t* ms = SGX_CAST(ms_ecall_start_raft_main_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_ip_addr = ms->ms_ip_addr;
	size_t _len_ip_addr = _tmp_ip_addr ? strlen(_tmp_ip_addr) + 1 : 0;
	char* _in_ip_addr = NULL;
	char* _tmp_port = ms->ms_port;
	size_t _len_port = _tmp_port ? strlen(_tmp_port) + 1 : 0;
	char* _in_port = NULL;
	char* _tmp_intro_ip = ms->ms_intro_ip;
	size_t _len_intro_ip = _tmp_intro_ip ? strlen(_tmp_intro_ip) + 1 : 0;
	char* _in_intro_ip = NULL;
	char* _tmp_intro_port = ms->ms_intro_port;
	size_t _len_intro_port = _tmp_intro_port ? strlen(_tmp_intro_port) + 1 : 0;
	char* _in_intro_port = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ip_addr, _len_ip_addr);
	CHECK_UNIQUE_POINTER(_tmp_port, _len_port);
	CHECK_UNIQUE_POINTER(_tmp_intro_ip, _len_intro_ip);
	CHECK_UNIQUE_POINTER(_tmp_intro_port, _len_intro_port);

	if (_tmp_ip_addr != NULL && _len_ip_addr != 0) {
		_in_ip_addr = (char*)malloc(_len_ip_addr);
		if (_in_ip_addr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_ip_addr, _tmp_ip_addr, _len_ip_addr);
		_in_ip_addr[_len_ip_addr - 1] = '\0';
	}
	if (_tmp_port != NULL && _len_port != 0) {
		_in_port = (char*)malloc(_len_port);
		if (_in_port == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_port, _tmp_port, _len_port);
		_in_port[_len_port - 1] = '\0';
	}
	if (_tmp_intro_ip != NULL && _len_intro_ip != 0) {
		_in_intro_ip = (char*)malloc(_len_intro_ip);
		if (_in_intro_ip == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_intro_ip, _tmp_intro_ip, _len_intro_ip);
		_in_intro_ip[_len_intro_ip - 1] = '\0';
	}
	if (_tmp_intro_port != NULL && _len_intro_port != 0) {
		_in_intro_port = (char*)malloc(_len_intro_port);
		if (_in_intro_port == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_intro_port, _tmp_intro_port, _len_intro_port);
		_in_intro_port[_len_intro_port - 1] = '\0';
	}
	ecall_start_raft_main((const char*)_in_ip_addr, (const char*)_in_port, (const char*)_in_intro_ip, (const char*)_in_intro_port);
err:
	if (_in_ip_addr) free((void*)_in_ip_addr);
	if (_in_port) free((void*)_in_port);
	if (_in_intro_ip) free((void*)_in_intro_ip);
	if (_in_intro_port) free((void*)_in_intro_port);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_s_node(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_s_node_t));
	ms_ecall_s_node_t* ms = SGX_CAST(ms_ecall_s_node_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_ip_addr = ms->ms_ip_addr;
	size_t _len_ip_addr = _tmp_ip_addr ? strlen(_tmp_ip_addr) + 1 : 0;
	char* _in_ip_addr = NULL;
	char* _tmp_port = ms->ms_port;
	size_t _len_port = _tmp_port ? strlen(_tmp_port) + 1 : 0;
	char* _in_port = NULL;
	char* _tmp_intro_ip = ms->ms_intro_ip;
	size_t _len_intro_ip = _tmp_intro_ip ? strlen(_tmp_intro_ip) + 1 : 0;
	char* _in_intro_ip = NULL;
	char* _tmp_intro_port = ms->ms_intro_port;
	size_t _len_intro_port = _tmp_intro_port ? strlen(_tmp_intro_port) + 1 : 0;
	char* _in_intro_port = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ip_addr, _len_ip_addr);
	CHECK_UNIQUE_POINTER(_tmp_port, _len_port);
	CHECK_UNIQUE_POINTER(_tmp_intro_ip, _len_intro_ip);
	CHECK_UNIQUE_POINTER(_tmp_intro_port, _len_intro_port);

	if (_tmp_ip_addr != NULL && _len_ip_addr != 0) {
		_in_ip_addr = (char*)malloc(_len_ip_addr);
		if (_in_ip_addr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_ip_addr, _tmp_ip_addr, _len_ip_addr);
		_in_ip_addr[_len_ip_addr - 1] = '\0';
	}
	if (_tmp_port != NULL && _len_port != 0) {
		_in_port = (char*)malloc(_len_port);
		if (_in_port == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_port, _tmp_port, _len_port);
		_in_port[_len_port - 1] = '\0';
	}
	if (_tmp_intro_ip != NULL && _len_intro_ip != 0) {
		_in_intro_ip = (char*)malloc(_len_intro_ip);
		if (_in_intro_ip == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_intro_ip, _tmp_intro_ip, _len_intro_ip);
		_in_intro_ip[_len_intro_ip - 1] = '\0';
	}
	if (_tmp_intro_port != NULL && _len_intro_port != 0) {
		_in_intro_port = (char*)malloc(_len_intro_port);
		if (_in_intro_port == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_intro_port, _tmp_intro_port, _len_intro_port);
		_in_intro_port[_len_intro_port - 1] = '\0';
	}
	ecall_s_node((const char*)_in_ip_addr, (const char*)_in_port, (const char*)_in_intro_ip, (const char*)_in_intro_port);
err:
	if (_in_ip_addr) free((void*)_in_ip_addr);
	if (_in_port) free((void*)_in_port);
	if (_in_intro_ip) free((void*)_in_intro_ip);
	if (_in_intro_port) free((void*)_in_intro_port);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_heartbeat_handler(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_heartbeat_handler_t));
	ms_ecall_heartbeat_handler_t* ms = SGX_CAST(ms_ecall_heartbeat_handler_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_request = ms->ms_request;
	size_t _len_request = _tmp_request ? strlen(_tmp_request) + 1 : 0;
	char* _in_request = NULL;
	char* _tmp_r_ep = ms->ms_r_ep;
	size_t _len_r_ep = _tmp_r_ep ? strlen(_tmp_r_ep) + 1 : 0;
	char* _in_r_ep = NULL;

	CHECK_UNIQUE_POINTER(_tmp_request, _len_request);
	CHECK_UNIQUE_POINTER(_tmp_r_ep, _len_r_ep);

	if (_tmp_request != NULL && _len_request != 0) {
		_in_request = (char*)malloc(_len_request);
		if (_in_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_request, _tmp_request, _len_request);
		_in_request[_len_request - 1] = '\0';
	}
	if (_tmp_r_ep != NULL && _len_r_ep != 0) {
		_in_r_ep = (char*)malloc(_len_r_ep);
		if (_in_r_ep == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_r_ep, _tmp_r_ep, _len_r_ep);
		_in_r_ep[_len_r_ep - 1] = '\0';
	}
	ms->ms_retval = ecall_heartbeat_handler((const char*)_in_request, (const char*)_in_r_ep);
err:
	if (_in_request) free((void*)_in_request);
	if (_in_r_ep) free((void*)_in_r_ep);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_start_raft(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_start_raft();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_vote(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_vote_t));
	ms_ecall_get_vote_t* ms = SGX_CAST(ms_ecall_get_vote_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_ip = ms->ms_ip;
	size_t _len_ip = _tmp_ip ? strlen(_tmp_ip) + 1 : 0;
	char* _in_ip = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ip, _len_ip);

	if (_tmp_ip != NULL && _len_ip != 0) {
		_in_ip = (char*)malloc(_len_ip);
		if (_in_ip == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_ip, _tmp_ip, _len_ip);
		_in_ip[_len_ip - 1] = '\0';
	}
	ecall_get_vote((const char*)_in_ip, ms->ms_port);
err:
	if (_in_ip) free((void*)_in_ip);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_leader_fn(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_leader_fn();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_api_handler(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_api_handler_t));
	ms_ecall_api_handler_t* ms = SGX_CAST(ms_ecall_api_handler_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_request = ms->ms_request;
	size_t _len_request = _tmp_request ? strlen(_tmp_request) + 1 : 0;
	char* _in_request = NULL;

	CHECK_UNIQUE_POINTER(_tmp_request, _len_request);

	if (_tmp_request != NULL && _len_request != 0) {
		_in_request = (char*)malloc(_len_request);
		if (_in_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_request, _tmp_request, _len_request);
		_in_request[_len_request - 1] = '\0';
	}
	ecall_api_handler((const char*)_in_request);
err:
	if (_in_request) free((void*)_in_request);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_send_heartbeat(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_send_heartbeat_t));
	ms_ecall_send_heartbeat_t* ms = SGX_CAST(ms_ecall_send_heartbeat_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_message = ms->ms_message;
	size_t _len_message = _tmp_message ? strlen(_tmp_message) + 1 : 0;
	char* _in_message = NULL;
	char* _tmp_ip = ms->ms_ip;
	size_t _len_ip = _tmp_ip ? strlen(_tmp_ip) + 1 : 0;
	char* _in_ip = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_ip, _len_ip);

	if (_tmp_message != NULL && _len_message != 0) {
		_in_message = (char*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_message, _tmp_message, _len_message);
		_in_message[_len_message - 1] = '\0';
	}
	if (_tmp_ip != NULL && _len_ip != 0) {
		_in_ip = (char*)malloc(_len_ip);
		if (_in_ip == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_ip, _tmp_ip, _len_ip);
		_in_ip[_len_ip - 1] = '\0';
	}
	ecall_send_heartbeat((const char*)_in_message, (const char*)_in_ip, ms->ms_port);
err:
	if (_in_message) free((void*)_in_message);
	if (_in_ip) free((void*)_in_ip);

	return status;
}

static sgx_status_t SGX_CDECL sgx_seal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_seal_t));
	ms_seal_t* ms = SGX_CAST(ms_seal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	size_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);
	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);

	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		_in_plaintext = (uint8_t*)malloc(_len_plaintext);
		if (_in_plaintext == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_plaintext, _tmp_plaintext, _len_plaintext);
	}
	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		if ((_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_data, 0, _len_sealed_data);
	}
	ms->ms_retval = seal(_in_plaintext, _tmp_plaintext_len, _in_sealed_data, _tmp_sealed_size);
err:
	if (_in_plaintext) free(_in_plaintext);
	if (_in_sealed_data) {
		memcpy(_tmp_sealed_data, _in_sealed_data, _len_sealed_data);
		free(_in_sealed_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_unseal_t));
	ms_unseal_t* ms = SGX_CAST(ms_unseal_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_sealed_data_t* _tmp_sealed_data = ms->ms_sealed_data;
	size_t _tmp_sealed_size = ms->ms_sealed_size;
	size_t _len_sealed_data = _tmp_sealed_size;
	sgx_sealed_data_t* _in_sealed_data = NULL;
	uint8_t* _tmp_plaintext = ms->ms_plaintext;
	uint32_t _tmp_plaintext_len = ms->ms_plaintext_len;
	size_t _len_plaintext = _tmp_plaintext_len;
	uint8_t* _in_plaintext = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data, _len_sealed_data);
	CHECK_UNIQUE_POINTER(_tmp_plaintext, _len_plaintext);

	if (_tmp_sealed_data != NULL && _len_sealed_data != 0) {
		_in_sealed_data = (sgx_sealed_data_t*)malloc(_len_sealed_data);
		if (_in_sealed_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_sealed_data, _tmp_sealed_data, _len_sealed_data);
	}
	if (_tmp_plaintext != NULL && _len_plaintext != 0) {
		if ((_in_plaintext = (uint8_t*)malloc(_len_plaintext)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plaintext, 0, _len_plaintext);
	}
	ms->ms_retval = unseal(_in_sealed_data, _tmp_sealed_size, _in_plaintext, _tmp_plaintext_len);
err:
	if (_in_sealed_data) free(_in_sealed_data);
	if (_in_plaintext) {
		memcpy(_tmp_plaintext, _in_plaintext, _len_plaintext);
		free(_in_plaintext);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_generate_random_number, 0},
		{(void*)(uintptr_t)sgx_ecall_start_raft_main, 0},
		{(void*)(uintptr_t)sgx_ecall_s_node, 0},
		{(void*)(uintptr_t)sgx_ecall_heartbeat_handler, 0},
		{(void*)(uintptr_t)sgx_ecall_start_raft, 0},
		{(void*)(uintptr_t)sgx_ecall_get_vote, 0},
		{(void*)(uintptr_t)sgx_ecall_leader_fn, 0},
		{(void*)(uintptr_t)sgx_ecall_api_handler, 0},
		{(void*)(uintptr_t)sgx_ecall_send_heartbeat, 0},
		{(void*)(uintptr_t)sgx_seal, 0},
		{(void*)(uintptr_t)sgx_unseal, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[16][11];
} g_dyn_entry_table = {
	16,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_start_raft()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(1, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_sleep(int time)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_sleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sleep_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sleep_t));

	ms->ms_time = time;
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_vote(const char* ip, int port)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ip = ip ? strlen(ip) + 1 : 0;

	ms_ocall_get_vote_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_vote_t);
	void *__tmp = NULL;

	ocalloc_size += (ip != NULL && sgx_is_within_enclave(ip, _len_ip)) ? _len_ip : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_vote_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_vote_t));

	if (ip != NULL && sgx_is_within_enclave(ip, _len_ip)) {
		ms->ms_ip = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ip);
		memcpy((void*)ms->ms_ip, ip, _len_ip);
	} else if (ip == NULL) {
		ms->ms_ip = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_port = port;
	status = sgx_ocall(3, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_heartbeat_server(int port)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_heartbeat_server_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_heartbeat_server_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_heartbeat_server_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_heartbeat_server_t));

	ms->ms_port = port;
	status = sgx_ocall(4, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_leader_fn()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(5, NULL);

	return status;
}

sgx_status_t SGX_CDECL ocall_api_server(int port)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_api_server_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_api_server_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_api_server_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_api_server_t));

	ms->ms_port = port;
	status = sgx_ocall(6, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_start_node(const char* ip_addr, const char* port, const char* intro_ip, const char* intro_port)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ip_addr = ip_addr ? strlen(ip_addr) + 1 : 0;
	size_t _len_port = port ? strlen(port) + 1 : 0;
	size_t _len_intro_ip = intro_ip ? strlen(intro_ip) + 1 : 0;
	size_t _len_intro_port = intro_port ? strlen(intro_port) + 1 : 0;

	ms_ocall_start_node_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_start_node_t);
	void *__tmp = NULL;

	ocalloc_size += (ip_addr != NULL && sgx_is_within_enclave(ip_addr, _len_ip_addr)) ? _len_ip_addr : 0;
	ocalloc_size += (port != NULL && sgx_is_within_enclave(port, _len_port)) ? _len_port : 0;
	ocalloc_size += (intro_ip != NULL && sgx_is_within_enclave(intro_ip, _len_intro_ip)) ? _len_intro_ip : 0;
	ocalloc_size += (intro_port != NULL && sgx_is_within_enclave(intro_port, _len_intro_port)) ? _len_intro_port : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_start_node_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_start_node_t));

	if (ip_addr != NULL && sgx_is_within_enclave(ip_addr, _len_ip_addr)) {
		ms->ms_ip_addr = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ip_addr);
		memcpy((void*)ms->ms_ip_addr, ip_addr, _len_ip_addr);
	} else if (ip_addr == NULL) {
		ms->ms_ip_addr = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (port != NULL && sgx_is_within_enclave(port, _len_port)) {
		ms->ms_port = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_port);
		memcpy((void*)ms->ms_port, port, _len_port);
	} else if (port == NULL) {
		ms->ms_port = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (intro_ip != NULL && sgx_is_within_enclave(intro_ip, _len_intro_ip)) {
		ms->ms_intro_ip = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_intro_ip);
		memcpy((void*)ms->ms_intro_ip, intro_ip, _len_intro_ip);
	} else if (intro_ip == NULL) {
		ms->ms_intro_ip = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (intro_port != NULL && sgx_is_within_enclave(intro_port, _len_intro_port)) {
		ms->ms_intro_port = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_intro_port);
		memcpy((void*)ms->ms_intro_port, intro_port, _len_intro_port);
	} else if (intro_port == NULL) {
		ms->ms_intro_port = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(7, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_send_heartbeat(const char* request, const char* host, int port_no)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_request = request ? strlen(request) + 1 : 0;
	size_t _len_host = host ? strlen(host) + 1 : 0;

	ms_ocall_send_heartbeat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_send_heartbeat_t);
	void *__tmp = NULL;

	ocalloc_size += (request != NULL && sgx_is_within_enclave(request, _len_request)) ? _len_request : 0;
	ocalloc_size += (host != NULL && sgx_is_within_enclave(host, _len_host)) ? _len_host : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_send_heartbeat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_send_heartbeat_t));

	if (request != NULL && sgx_is_within_enclave(request, _len_request)) {
		ms->ms_request = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_request);
		memcpy((void*)ms->ms_request, request, _len_request);
	} else if (request == NULL) {
		ms->ms_request = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (host != NULL && sgx_is_within_enclave(host, _len_host)) {
		ms->ms_host = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_host);
		memcpy((void*)ms->ms_host, host, _len_host);
	} else if (host == NULL) {
		ms->ms_host = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_port_no = port_no;
	status = sgx_ocall(8, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_f_wrapper(const char* request, const char* host, int port_no)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_request = request ? strlen(request) + 1 : 0;
	size_t _len_host = host ? strlen(host) + 1 : 0;

	ms_ocall_f_wrapper_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_f_wrapper_t);
	void *__tmp = NULL;

	ocalloc_size += (request != NULL && sgx_is_within_enclave(request, _len_request)) ? _len_request : 0;
	ocalloc_size += (host != NULL && sgx_is_within_enclave(host, _len_host)) ? _len_host : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_f_wrapper_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_f_wrapper_t));

	if (request != NULL && sgx_is_within_enclave(request, _len_request)) {
		ms->ms_request = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_request);
		memcpy((void*)ms->ms_request, request, _len_request);
	} else if (request == NULL) {
		ms->ms_request = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (host != NULL && sgx_is_within_enclave(host, _len_host)) {
		ms->ms_host = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_host);
		memcpy((void*)ms->ms_host, host, _len_host);
	} else if (host == NULL) {
		ms->ms_host = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_port_no = port_no;
	status = sgx_ocall(9, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_udp_sendmsg(char** retval, const char* request, const char* host, int port_no)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_request = request ? strlen(request) + 1 : 0;
	size_t _len_host = host ? strlen(host) + 1 : 0;

	ms_ocall_udp_sendmsg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_udp_sendmsg_t);
	void *__tmp = NULL;

	ocalloc_size += (request != NULL && sgx_is_within_enclave(request, _len_request)) ? _len_request : 0;
	ocalloc_size += (host != NULL && sgx_is_within_enclave(host, _len_host)) ? _len_host : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_udp_sendmsg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_udp_sendmsg_t));

	if (request != NULL && sgx_is_within_enclave(request, _len_request)) {
		ms->ms_request = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_request);
		memcpy((void*)ms->ms_request, request, _len_request);
	} else if (request == NULL) {
		ms->ms_request = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (host != NULL && sgx_is_within_enclave(host, _len_host)) {
		ms->ms_host = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_host);
		memcpy((void*)ms->ms_host, host, _len_host);
	} else if (host == NULL) {
		ms->ms_host = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_port_no = port_no;
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

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
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memset(ms->ms_cpuinfo, 0, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(11, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

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
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;

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
	status = sgx_ocall(13, ms);

	if (retval) *retval = ms->ms_retval;

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
	status = sgx_ocall(14, ms);

	if (retval) *retval = ms->ms_retval;

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
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(15, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

