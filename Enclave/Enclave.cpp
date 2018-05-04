#include "Enclave_t.h"
#include <string>
#include <vector>
#include "raft.hpp"
#include <thread>
#include <mutex>
#include <sgx_trts.h>

#include <condition_variable>
#include <chrono>
#include <ctime>

int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}


std::string udp_sendmsg(std::string request, std::string host, int port_no)
{
	std::string response;
    char* a = (char *)malloc(100 * 100);
    ocall_udp_sendmsg(&a, request.c_str(), host.c_str() , port_no);
    // ocall_print("enclave response is ");
    // ocall_print(a);
    std::string temp(a);
    //std::strcpy(response,a);
    response = a;
    free(a);
   // response = strcpy(*a);
    //ocall_udp_sendmsg(request,host,port_no);
    return response;
}


class node{
public:
	std::string port_;
	std::string ip_addr_;
	
	node(std::string ip_addr, std::string port)
	:port_(port),ip_addr_(ip_addr){

	}
	node(){
		port_ = "";
		ip_addr_ = "";
	}
	friend bool operator==(const node& lhs, const node& rhs){
		if(lhs.ip_addr_ == rhs.ip_addr_ && lhs.port_ == rhs.port_ ){
			return true;
		}
		return false;
	}

	friend bool operator!=(const node& lhs, const node& rhs){
		return !(lhs == rhs);
	}

};

class node_info{
public:
	std::vector<node> node_list_;
	bool vote_available_;
	bool leader_tout_;
	std::mutex vote_m_;
	node cur_;
	int term_;
	node leader_;
	log_t log_;
	node_info(){
		vote_available_ = true;
		leader_tout_ = true;
		term_ = 0;
	}
	std::string serialize(){
		std::string ret = "";
		for(node n : node_list_){
			ret += n.ip_addr_ + "," + n.port_ + ";";
		}
		return ret;
	}

	/*
	 * TODO improve performance , change node_list_ to map
	 */
	void deserialize(std::string str){
		std::vector<std::string> vs1;
    	split(vs1, str , ";");
    	for( int i=0; i < vs1.size()-1;++i ){
    		std::string s = vs1[i];
    		std::vector<std::string> vs2;
    		split(vs2, s , ",");
 			bool found = false;
 			node n(vs2[0],vs2[1]);
 			for(node itr : node_list_){
 				if(n == itr)
 				{
 					found = true;
 					break;
 				}
 			}
 			if( !found){

 				node_list_.push_back(n);
 			}
    	}
	}
}info;
std::mutex info_m;
bool execute_cmd( int i);


void update_nodes(){
	for(int i =0; i < info.node_list_.size()-1;++i){
		std::string message = "UPDATE;" + info.serialize();
		std::string response;
	    if(info.node_list_[i].ip_addr_ != info.cur_.ip_addr_ && info.node_list_[i].port_ != info.cur_.port_){
	    	response = udp_sendmsg(message, info.node_list_[i].ip_addr_, std::stoi(info.node_list_[i].port_));
	    		
	    }
	   
	} 
}


void ecall_send_heartbeat(const char* msg,const char* host, int port){
	std::string message(msg);;
	std::string ip(host);
	std::string response;
	
	response = udp_sendmsg(message,ip,port);
	
	//t.detach();
}



char* ecall_api_handler(const char* req){
	ocall_print("API REQQQQQQQUEST q0");
	ocall_print(req);
   
	std::string request(req);
	std::vector<std::string> vs1;
    split(vs1, request , ";");
   
    //std::cout << "Request is " << request << std::endl ; 
    if( vs1[0] == "SET" && vs1.size() >= 3){
    	ocall_print("g1");
        log_entry l(SET,vs1[1],vs1[2]);
        int id = info.log_.size();
        ocall_set(id,0);
        info.log_.push_back(l);
        int state = 0;
        ocall_get(&state,id);
        while(state == 0){
        	ocall_get(&state,id);
        	if(state == 1){
        		ocall_print("State  is 1 \n");
        	}
        }
    }
    return "OK";
}


void ecall_leader_fn(){
	ocall_print("here 5");
	ocall_api_server(API_PORT);
	//std::thread api_t(api_server);
	info.term_++;
	while(1){
		int dead_node = -1;
		int count = 0;
		std::string message = "LEADER;" + std::to_string(info.term_) + ";" + info.log_.serialize();
		int ssize = info.log_.size();
		for(int i=0 ; i < info.node_list_.size();++i){
			
			if(info.node_list_[i].ip_addr_ != info.cur_.ip_addr_ || info.node_list_[i].port_ != info.cur_.port_){
				//std::cout << "Heartbeating " << info.node_list_[i].ip_addr_ + " : " << info.node_list_[i].port_ << "\n";
				try{
					ocall_f_wrapper(message.c_str(),info.node_list_[i].ip_addr_.c_str(),std::stoi(info.node_list_[i].port_));
				}catch(std::runtime_error& e){
					//std::cout << "Thread timeout\n";
					dead_node = i;
					count++;
				}

				ocall_send_heartbeat(message.c_str(), info.node_list_[i].ip_addr_.c_str(), std::stoi(info.node_list_[i].port_));
				
				//std::thread t(send_heartbeat,message,info.node_list_[i].ip_addr_, std::stoi(info.node_list_[i].port_));	
				//t.detach();
			}


		}
		if(count < info.node_list_.size()/2){
			if(info.log_.st_cnt_ > info.log_.cmt_cnt_){
				for(int i=info.log_.cmt_cnt_; i <= info.log_.st_cnt_;++i ){
					execute_cmd(i);
					info.log_.cmt_cnt_++;
				}
			}
			info.log_.st_cnt_ = ssize;
		}
		if(dead_node != -1){
			info.node_list_.erase(info.node_list_.begin() + dead_node);
		}
		ocall_sleep(HB_FREQ);
		//std::this_thread::sleep_for(std::chrono::milliseconds(HB_FREQ));
	}
	

}

int rand(){
	// char buf[10];
	// sgx_read_rand((unsigned char*) buf,5);
	// return atoi(buf);
	return 1000;
}

void ecall_straft(){
	
	info.leader_tout_ = true;
	int sleep_amt = LOWER_TIMEOUT + (rand() % (UPPER_TIMEOUT - LOWER_TIMEOUT));
	//std::string printstr = "Sleeping for " + sleep_amt;
	//ocall_print("sleeping");
	//std::cout << "Sleeping for " << sleep_amt << "milliseconds \n";
	//std::this_thread::sleep_for(std::chrono::milliseconds(sleep_amt));
	ocall_sleep(sleep_amt);
	//std::cout << "here1\n";
	//ocall_print("here 1 ");
	if(info.node_list_.size() >= NODE_THRESHOLD && info.leader_tout_ == true){
		info.vote_m_.lock();
		if(info.vote_available_ == true){
			//std::cout << "here2\n";
			ocall_print("here 2");
			info.vote_available_ = false;
			info.vote_m_.unlock();
			start_election();
			return;

		}else{
			//send_heartbeat();
			info.vote_m_.unlock();
		}
		
	}
	info.vote_m_.lock();
	info.vote_available_ = true;
	info.vote_m_.unlock();
	ecall_straft();
}

int num_votes;
std::mutex nv_m;
void ecall_get_vote( const char* ip_add, int port){
	ocall_print("here 4");
	ocall_print(ip_add);
	ocall_print(std::to_string(port).c_str());
	std::string ip(ip_add);
	std::string message = "ELECT;" + info.cur_.ip_addr_ + ";" + info.cur_.port_ ;
	std::string response;
	response = udp_sendmsg(message,ip,port);
	
	
	
	if(response == "OK"){
		nv_m.lock();
		num_votes++;
		nv_m.unlock();
	}
}


void start_election(){
	num_votes = 0;

	for(int i =0; i < info.node_list_.size();++i){
		ocall_get_vote(info.node_list_[i].ip_addr_.c_str(), std::stoi(info.node_list_[i].port_));
		// s.detach();
	}
	ocall_sleep(VOTE_TIME);
	//std::this_thread::sleep_for(std::chrono::milliseconds(VOTE_TIME));
	if(num_votes+1 > (info.node_list_.size()/2)){
		ocall_print("Leader Elected");
		ocall_leader_fn();
		//std::cout << "Leader Elected \n";
		// std::thread t(leader_fn);
		// t.detach();
	}else{
		ecall_straft();
	}
	//std::cout << "num votes is " << num_votes << "\n";

}



char* ecall_ah(const char* req, const char* r_ep){
	
   
	std::string request(req);
	std::vector<std::string> vs1;
    ocall_print("AH API REQQQQQQQUEST q0");
	ocall_print(req);
    split(vs1, request , ";");
   	
    //std::cout << "Request is " << request << std::endl ; 
    if( vs1[0] == "SET" && vs1.size() >= 3){
    	ocall_print("g1");
        log_entry l(SET,vs1[1],vs1[2]);
        int id = info.log_.size();
        info.log_.push_back(l);
        while(info.log_[id].committed_ == false){
        	ocall_sleep(100);
        }
    }
    return "OK";
}


/*
 * this function receives the hearbeat from the neighbour
 * @param const char* request 
 * @param const char* r_ep
 */
char* ecall_heartbeat_handler(const char* req, const char* r_ep){
	// ocall_print("request is " );
	// ocall_print(req);
	// return "OK";
	std::string request(req);
	ocall_print(req);
	// ocall_print("hearbeat_handler request : ");
	// ocall_print(request.c_str());
	// ocall_print(r_ep);

	std::vector<std::string> vs1;
    split(vs1, request ,";");
//    ocall_print(vs1[1].c_str());
    std::string ret = "OK";
    if(vs1[0] == "JOIN"){
    	info_m.lock();
    	info.node_list_.push_back(node(r_ep,vs1[1]));
    	info_m.unlock();
    	update_nodes();
    	// std::thread t(update_nodes);
    	// t.detach();
    	//std::cout << "info : " << info.serialize();
    	return (char *)info.serialize().c_str();
    }else if(vs1[0] == "UPDATE"){
    	std::string req = request.substr(7);
    	info.deserialize(req);

    }else if(vs1[0] == "ELECT"){
    	info.vote_m_.lock();
    	if(info.vote_available_ == true){
    		info.vote_available_ = false;
    		info.vote_m_.unlock();
    		return "OK";
    	}else{
    		info.vote_m_.unlock();
    		return "NOK";
    	}

    }else if(vs1[0] == "LEADER"){
    	info.leader_tout_ = false;
    	ocall_print("here in leader");
    	//std::cout << "heartbeat recevied\n";
    	info.term_ = max(info.term_,std::stoi(vs1[1]));
    	if(info.term_ > std::stoi(vs1[1])){
    		//ignore packet
    		return "NOK";
    	}else{
    		std::string r_log = request.substr(vs1[0].size()+vs1[1].size() +2);
    		//std::cout << "rlog:" << r_log;
    		log_t new_log(r_log);
    		
    		ocall_print(std::to_string(info.log_.size()).c_str());
    		info.log_ = new_log;
    		ocall_print(std::to_string(info.log_.size()).c_str());
    		if(info.log_.st_cnt_ > info.log_.cmt_cnt_){
    			//execute
    			for(int i= info.log_.cmt_cnt_; i <= info.log_.st_cnt_;++i ){
    				execute_cmd( i);
    			}
    			//info.log_.cmt_cnt_ = info.log_.st_cnt_;
    			return "COMMIT";
    		}
    	}
    	
    	
    }
  
    return "OK";
}


void ecall_s_node(const char* ip_addr, const char* port, const char* intro_ip, const char* intro_port){
	std::string u_ip_addr(ip_addr);
	std::string u_port(port);
	std::string i_ip_addr(intro_ip);
	std::string i_port(intro_port);
	//ocall_print(u_ip_addr.c_str());
	// ocall_print(ip_addr);
	// ocall_print(port);
	// ocall_print(intro_ip);
	// ocall_print(intro_port);
	if(u_ip_addr == i_ip_addr && u_port == i_port){
		//case where this is the first node
		//ocall_print("HERE\n");
		info.node_list_.push_back(node(u_ip_addr,u_port));
	}
	else{
		std::string response;
		std::string message = "JOIN;" + u_port;
		response = udp_sendmsg(message, i_ip_addr, std::stoi(i_port));
	    //std::cout << "Response is " << response << std::endl;
		info.deserialize(response);
	}
}

void ecall_start_raft_main(const char* ip_addr, const char* port, const char* intro_ip, const char* intro_port){
	info.cur_.port_ = port;
	info.cur_.ip_addr_ = ip_addr;
	ocall_print(ip_addr);
	//ocall_print("done");
	ocall_heartbeat_server(std::stoi(port));
	ocall_sleep(500);
	ocall_start_node(ip_addr,port,intro_ip,intro_port);
	//std::thread t2(start_node, u_ip_addr,u_port,i_ip_addr,i_port);
	//ecall_straft();
	// ocall_sleep(10000);
	// ocall_print("here");
	ocall_straft();
	//std::thread t3(start_raft);
	while(1){

	}
}


bool execute_cmd( int i){
	ocall_print("hmp 1 ");
	//std::string type =  "";//((info.log_[i].req_type_ == SET) ? "SET" : "GET");
	// if(info.log_[i].req_type_ == SET){
	// 	type = "SET";
	// }else if(info.log_[i].req_type_ == GET){
	// 	type = "GET";
	// }
	// if(type != ""){
	// 	ocall_print("hmp 3 ");
	// 	std::string res = "Executing " + type  + " " + info.log_[i].key_ + " " + info.log_[i].val_ + "\n";
	// 	ocall_print("hmp 4 ");
	// 	ocall_print(res.c_str());	
	// }

	// ocall_print(std::to_string(i).c_str());
	// ocall_print(std::to_string(info.log_.size()).c_str());
	// ocall_print("hmp 2");
	
	// info.log_[i].committed_ = true;
	ocall_set(i,1);
	return true;
}