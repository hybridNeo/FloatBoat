#include <stdio.h>
#include <iostream>
#include <thread>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "com.hpp"
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

std::string heartbeat_handler(std::string& request, udp::endpoint r_ep){
    char **a = (char**)malloc(100*100);
    ecall_heartbeat_handler(global_eid, a, request.c_str() ,r_ep.address().to_string().c_str());
    std::string ret(*a);
    delete a;
    return ret;
}

void heartbeat_server_t(int port){
    try{

        std::cout << "port is " << port << std::endl;
        boost::asio::io_service io_service;
        udp_server server(io_service, port, heartbeat_handler);
        std::cout << "[heartbeat Server] Started    \n";
        io_service.run();
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
}

void start_node_t(const char* ip_addr,const char* port,const char* intro_ip , const char* intro_port){
    ecall_s_node(global_eid, ip_addr , port , intro_ip , intro_port );

}

void ocall_start_node(const char* ip_addr,const char* port,const char* intro_ip , const char* intro_port){
    std::thread t(start_node_t,ip_addr,port,intro_ip,intro_port);
    t.detach();
}

char* ocall_udp_sendmsg(const char* request, const char* host, int port_no){
    std::string response;
    udp_sendmsg(request,host,port_no,response);
    return (char *)response.c_str();
}

void ocall_heartbeat_server(int port){
    std::cout << "port is " << port << std::endl;
    std::thread t(heartbeat_server_t, port);
    t.detach();
}


int main(int argc,const char* argv[]){
    //std::string ip_addr = argv[1];
    //raft_main(argc, argv[1], argv[2] , argv[3] , argv[3] );
    //test();
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    //int ptr;
    if (argc == 5)
        ecall_start_raft(global_eid,argv[1],argv[2],argv[3],argv[4]);
    else
        std::cout << "Invalid Arguments, try again \n";
    
    /*
     * sgx_status_t status = generate_random_number(global_eid, &ptr);
    
    std::cout << status << std::endl;
    if (status != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    printf("Random number: %d\n", ptr);

    // Seal the random number
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (uint8_t*)&ptr, sizeof(ptr),
            (sgx_sealed_data_t*)sealed_data, sealed_size);

    if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
        return 1;
    }

    int unsealed;
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data, sealed_size,
            (uint8_t*)&unsealed, sizeof(unsealed));

    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
        return 1;
    }

    std::cout << "Seal round trip success! Receive back " << unsealed << std::endl;
    */
    return 0;
}
