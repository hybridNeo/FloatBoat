#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_generate_random_number_t {
	int ms_retval;
} ms_generate_random_number_t;

typedef struct ms_ecall_start_raft_t {
	char* ms_ip_addr;
	char* ms_port;
	char* ms_intro_ip;
	char* ms_intro_port;
} ms_ecall_start_raft_t;

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

typedef struct ms_ocall_heartbeat_server_t {
	int ms_port;
} ms_ocall_heartbeat_server_t;

typedef struct ms_ocall_start_node_t {
	char* ms_ip_addr;
	char* ms_port;
	char* ms_intro_ip;
	char* ms_intro_port;
} ms_ocall_start_node_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_heartbeat_server(void* pms)
{
	ms_ocall_heartbeat_server_t* ms = SGX_CAST(ms_ocall_heartbeat_server_t*, pms);
	ocall_heartbeat_server(ms->ms_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_start_node(void* pms)
{
	ms_ocall_start_node_t* ms = SGX_CAST(ms_ocall_start_node_t*, pms);
	ocall_start_node((const char*)ms->ms_ip_addr, (const char*)ms->ms_port, (const char*)ms->ms_intro_ip, (const char*)ms->ms_intro_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_udp_sendmsg(void* pms)
{
	ms_ocall_udp_sendmsg_t* ms = SGX_CAST(ms_ocall_udp_sendmsg_t*, pms);
	ms->ms_retval = ocall_udp_sendmsg((const char*)ms->ms_request, (const char*)ms->ms_host, ms->ms_port_no);

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
	void * table[9];
} ocall_table_Enclave = {
	9,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_heartbeat_server,
		(void*)Enclave_ocall_start_node,
		(void*)Enclave_ocall_udp_sendmsg,
		(void*)Enclave_sgx_oc_cpuidex,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t generate_random_number(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_generate_random_number_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_start_raft(sgx_enclave_id_t eid, const char* ip_addr, const char* port, const char* intro_ip, const char* intro_port)
{
	sgx_status_t status;
	ms_ecall_start_raft_t ms;
	ms.ms_ip_addr = (char*)ip_addr;
	ms.ms_port = (char*)port;
	ms.ms_intro_ip = (char*)intro_ip;
	ms.ms_intro_port = (char*)intro_port;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_s_node(sgx_enclave_id_t eid, const char* ip_addr, const char* port, const char* intro_ip, const char* intro_port)
{
	sgx_status_t status;
	ms_ecall_s_node_t ms;
	ms.ms_ip_addr = (char*)ip_addr;
	ms.ms_port = (char*)port;
	ms.ms_intro_ip = (char*)intro_ip;
	ms.ms_intro_port = (char*)intro_port;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_heartbeat_handler(sgx_enclave_id_t eid, char** retval, const char* request, const char* r_ep)
{
	sgx_status_t status;
	ms_ecall_heartbeat_handler_t ms;
	ms.ms_request = (char*)request;
	ms.ms_r_ep = (char*)r_ep;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* plaintext, size_t plaintext_len, sgx_sealed_data_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_seal_t ms;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_sealed_data_t* sealed_data, size_t sealed_size, uint8_t* plaintext, uint32_t plaintext_len)
{
	sgx_status_t status;
	ms_unseal_t ms;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	ms.ms_plaintext = plaintext;
	ms.ms_plaintext_len = plaintext_len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

