#include "Enclave_t.h"
#include <string>
#include <vector>
#include "raft.hpp"
#include <thread>
#include <mutex>

int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
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


/*
 * this function receives the hearbeat from the neighbour
 * @param const char* request 
 * @param const char* r_ep
 */
char* ecall_heartbeat_handler(const char* request, const char* r_ep){
	ocall_print("request is " );
	ocall_print(request);
	return "OK";

	// std::vector<std::string> vs1;
 //    boost::split(vs1, request , boost::is_any_of(";"));
 //    std::string ret = "OK";
 //    if(vs1[0] == "JOIN"){
 //    	info_m.lock();
 //    	info.node_list_.push_back(node(r_ep,vs1[1]));
 //    	info_m.unlock();
 //    	std::thread t(update_nodes);
 //    	t.detach();
 //    	//std::cout << "info : " << info.serialize();
 //    	return info.serialize();
 //    }else if(vs1[0] == "UPDATE"){
 //    	std::string req = request.substr(7);
 //    	info.deserialize(req);

 //    }else if(vs1[0] == "ELECT"){
 //    	info.vote_m_.lock();
 //    	if(info.vote_available_ == true){
 //    		info.vote_available_ = false;
 //    		info.vote_m_.unlock();
 //    		return "OK";
 //    	}else{
 //    		info.vote_m_.unlock();
 //    		return "NOK";
 //    	}

 //    }else if(vs1[0] == "LEADER"){
 //    	info.leader_tout_ = false;
 //    	//std::cout << "heartbeat recevied\n";
 //    	info.term_ = max(info.term_,std::stoi(vs1[1]));
 //    	if(info.term_ > std::stoi(vs1[1])){
 //    		//ignore packet
 //    		return "NOK";
 //    	}else{
 //    		std::string r_log = request.substr(vs1[0].size()+vs1[1].size() +2);
 //    		//std::cout << "rlog:" << r_log;
 //    		log_t new_log(r_log);
 //    		info.log_ = new_log;
 //    		if(info.log_.st_cnt_ > info.log_.cmt_cnt_){
 //    			//execute
 //    			for(int i= info.log_.cmt_cnt_; i <= info.log_.st_cnt_;++i ){
 //    				execute_cmd( i);
 //    			}
 //    			//info.log_.cmt_cnt_ = info.log_.st_cnt_;
 //    			return "COMMIT";
 //    		}
 //    	}
    	
    	
 //    }
  
 //    return ret;
}

void ecall_start_raft(const char* ip_addr, const char* port, const char* , const char* intro_port){
	info.cur_.port_ = port;
	info.cur_.ip_addr_ = ip_addr;

	ocall_heartbeat_server(std::stoi(port));
	//std::thread t2(start_node, u_ip_addr,u_port,i_ip_addr,i_port);
	//std::thread t3(start_raft);
	while(1){
		
		
	}
}
