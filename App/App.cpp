#include <stdio.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include <unistd.h>
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
    std::cout << " start node " << ip_addr << port << intro_ip << intro_port << std::endl;

    ecall_s_node(global_eid, ip_addr , port , intro_ip , intro_port );

}

void ocall_start_node(const char* ip_addr,const char* port,const char* intro_ip , const char* intro_port){
    std::cout << "ocall " << ip_addr << port << intro_ip << intro_port << std::endl;
    // For some reason the memory is encryped here 
    std::string n_ip_addr(ip_addr);
    std::string n_port(port);
    std::string n_intro_ip(intro_ip);
    std::string n_intro_port(intro_port);
    std::cout << "ocall2 " << n_ip_addr.c_str() << n_port.c_str() << n_intro_ip.c_str() << n_intro_port.c_str() << std::endl;

    std::thread t(start_node_t,n_ip_addr.c_str(),n_port.c_str(), n_intro_ip.c_str(), n_intro_port.c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    t.detach();
}

void ocall_sleep(int time){
    std::this_thread::sleep_for(std::chrono::milliseconds(time));
    //usleep(time);
}

/*
 * @param string request
 * @param string r_ep
 */
std::string api_handler(std::string& request, udp::endpoint r_ep){
    // std::vector<std::string> vs1;
    // boost::split(vs1, request , boost::is_any_of(";"));
    // std::cout << "Request is " << request << std::endl ; 
    
    // if( vs1[0] == "SET" && vs1.size() >= 3){
    //     log_entry l(SET,vs1[1],vs1[2]);
    //     int id = info.log_.size();
    //     info.log_.push_back(l);
    //     while(info.log_[id].committed_ == false){

    //     }
    // }
    // return "OK";
    ecall_api_handler(global_eid, request.c_str() );
    return "OK";
}

void ocall_f_wrapper(const char* msg,const char* host, int port)
{
    std::string message(msg);
    std::string ip(host);
    std::mutex m;
    std::condition_variable cv;

    std::thread t([&m, &cv, message,ip, port]() 
    {
        ecall_send_heartbeat(global_eid, message.c_str(),ip.c_str(),port);
        cv.notify_one();
    });

    t.detach();

    {
        std::unique_lock<std::mutex> l(m);
        if(cv.wait_for(l, std::chrono::milliseconds(1000)) == std::cv_status::timeout) 
            throw std::runtime_error("Timeout");
    }

}

void send_heartbeat_t(const char* message, const char* ip , int port){
    ecall_send_heartbeat(global_eid, message, ip , port);
}

void ocall_send_heartbeat(const char* message, const char* ip, int port){
    std::thread t(ocall_send_heartbeat, message, ip , port );
    t.detach();
}

void ocall_api_server(int port){
    try{

        boost::asio::io_service io_service;
        udp_server server(io_service, port, api_handler);
        std::cout << "[API Server] Started on port "  << port <<  " \n";
        io_service.run();
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
}

void get_vote_t(const char* ip, int port){
    std::cout << "get_vote_t " << ip << std::endl;
    ecall_get_vote(global_eid,ip,port);
}

void ocall_get_vote(const char* ip, int port){
    std::cout << "ocall_get_vote " << ip << std::endl;
    char buf[25];
    std::strcpy(buf,ip);
    std::thread t(get_vote_t, ip , port);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    t.detach();
}

void leader_fn_t(){
    ecall_leader_fn(global_eid);
}

void ocall_leader_fn(){
    std::thread t(leader_fn_t);
    t.detach();

}

void start_raft_t(){
    ecall_straft(global_eid);
}

void ocall_straft(){
    std::thread t(start_raft_t);
    t.detach();

}

void ocall_udp_sendmsg(char ** res, const char* request, const char* host, int port_no){
    std::string response;
    std::cout << "request is " << request << "  " << host << std::endl;
    udp_sendmsg(request,host,port_no,response);
    std::cout << "response is " << response << std::endl;
    //return (char *)response.c_str();
    strcpy(*res,response.c_str());
}

void ocall_heartbeat_server(int port){
    //std::cout << "port is " << port << std::endl;
    std::thread t(heartbeat_server_t, port);
    t.detach();
}


int main(int argc,const char* argv[]){
    //std::string ip_addr = argv[1];
    //raft_main(argc, argv[1], argv[2] , argv[3] , argv[3] );
    //test();

  
    //int ptr;
    if (argc == 5)
    {
      //  global_eid = std::stoi(std::string(argv[2]));
        if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
            std::cout << "Failed to initialize enclave \n";
            return 1;
        }else{
            std::cout << argv[1] << " " << argv[2] << " " << argv[3] << " " << argv[4] << std::endl; 
            ecall_start_raft_main(global_eid,argv[1],argv[2],argv[3],argv[4]);
            
        }
    }    
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
