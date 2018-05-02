#include "Enclave_t.h"
#include <string>

int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}

void ecall_start_raft(const char* ip_addr, const char* port, const char* , const char* intro_port){

}
