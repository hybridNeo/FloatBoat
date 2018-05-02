#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_start_raft(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_start_raft();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_sleep(void* pms)
{
	ms_ocall_sleep_t* ms = SGX_CAST(ms_ocall_sleep_t*, pms);
	ocall_sleep(ms->ms_time);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_get_vote(void* pms)
{
	ms_ocall_get_vote_t* ms = SGX_CAST(ms_ocall_get_vote_t*, pms);
	ocall_get_vote((const char*)ms->ms_ip, ms->ms_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_heartbeat_server(void* pms)
{
	ms_ocall_heartbeat_server_t* ms = SGX_CAST(ms_ocall_heartbeat_server_t*, pms);
	ocall_heartbeat_server(ms->ms_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_leader_fn(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_leader_fn();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_api_server(void* pms)
{
	ms_ocall_api_server_t* ms = SGX_CAST(ms_ocall_api_server_t*, pms);
	ocall_api_server(ms->ms_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_start_node(void* pms)
{
	ms_ocall_start_node_t* ms = SGX_CAST(ms_ocall_start_node_t*, pms);
	ocall_start_node((const char*)ms->ms_ip_addr, (const char*)ms->ms_port, (const char*)ms->ms_intro_ip, (const char*)ms->ms_intro_port);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_send_heartbeat(void* pms)
{
	ms_ocall_send_heartbeat_t* ms = SGX_CAST(ms_ocall_send_heartbeat_t*, pms);
	ocall_send_heartbeat((const char*)ms->ms_request, (const char*)ms->ms_host, ms->ms_port_no);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_f_wrapper(void* pms)
{
	ms_ocall_f_wrapper_t* ms = SGX_CAST(ms_ocall_f_wrapper_t*, pms);
	ocall_f_wrapper((const char*)ms->ms_request, (const char*)ms->ms_host, ms->ms_port_no);

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
	void * table[16];
} ocall_table_Enclave = {
	16,
	{
		(void*)Enclave_ocall_print,
		(void*)Enclave_ocall_start_raft,
		(void*)Enclave_ocall_sleep,
		(void*)Enclave_ocall_get_vote,
		(void*)Enclave_ocall_heartbeat_server,
		(void*)Enclave_ocall_leader_fn,
		(void*)Enclave_ocall_api_server,
		(void*)Enclave_ocall_start_node,
		(void*)Enclave_ocall_send_heartbeat,
		(void*)Enclave_ocall_f_wrapper,
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

sgx_status_t ecall_start_raft_main(sgx_enclave_id_t eid, const char* ip_addr, const char* port, const char* intro_ip, const char* intro_port)
{
	sgx_status_t status;
	ms_ecall_start_raft_main_t ms;
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

sgx_status_t ecall_start_raft(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_get_vote(sgx_enclave_id_t eid, const char* ip, int port)
{
	sgx_status_t status;
	ms_ecall_get_vote_t ms;
	ms.ms_ip = (char*)ip;
	ms.ms_port = port;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_leader_fn(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_api_handler(sgx_enclave_id_t eid, const char* request)
{
	sgx_status_t status;
	ms_ecall_api_handler_t ms;
	ms.ms_request = (char*)request;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_send_heartbeat(sgx_enclave_id_t eid, const char* message, const char* ip, int port)
{
	sgx_status_t status;
	ms_ecall_send_heartbeat_t ms;
	ms.ms_message = (char*)message;
	ms.ms_ip = (char*)ip;
	ms.ms_port = port;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
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
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
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
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

