#include "Enclave_t.h"
#include <string>
#include <vector>
#include "raft.hpp"
#include <thread>
#include <mutex>

#include <condition_variable>
#include <chrono>
#include <ctime>

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
std::mutex info_m;
bool execute_cmd( int i);


void update_nodes(){
	for(int i =0; i < info.node_list_.size()-1;++i){
		std::string message = "UPDATE;" + info.serialize();
		std::string response;
	    try{
	    	if(info.node_list_[i].ip_addr_ != info.cur_.ip_addr_ && info.node_list_[i].port_ != info.cur_.port_){
	    		udp_sendmsg(message, info.node_list_[i].ip_addr_, std::stoi(info.node_list_[i].port_), response);
	    		
	    	}
	    }catch(...){
	    	ocall_print("[ENCLAVE] error in update_nodes\n ");
	    	//std::cout << "Error sending message\n";
	    }
	} 
}


void send_heartbeat(std::string message,std::string ip, int port){
	std::string response;
	
	udp_sendmsg(message,ip,port,response);
	
	//t.detach();
}

void f_wrapper(std::string message,std::string ip, int port)
{
    // std::mutex m;
    // std::condition_variable cv;

    // std::thread t([&m, &cv, message,ip, port]() 
    // {
    //     send_heartbeat(message,ip,port);
    //     cv.notify_one();
    // });

    // t.detach();

    // {
    //     std::unique_lock<std::mutex> l(m);
    //     if(cv.wait_for(l, std::chrono::milliseconds(1000)) == std::cv_status::timeout) 
    //         throw std::runtime_error("Timeout");
    // }

}


void leader_fn(){
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
					f_wrapper(message,info.node_list_[i].ip_addr_,std::stoi(info.node_list_[i].port_));
				}catch(std::runtime_error& e){
					//std::cout << "Thread timeout\n";
					dead_node = i;
					count++;
				}
				
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
		//std::this_thread::sleep_for(std::chrono::milliseconds(HB_FREQ));
	}
	

}

void start_raft(){
	
	info.leader_tout_ = true;
	//int sleep_amt = LOWER_TIMEOUT + (rand() % (UPPER_TIMEOUT - LOWER_TIMEOUT));
	//std::cout << "Sleeping for " << sleep_amt << "milliseconds \n";
	//std::this_thread::sleep_for(std::chrono::milliseconds(sleep_amt));
	//std::cout << "here1\n";
	if(info.node_list_.size() >= NODE_THRESHOLD && info.leader_tout_ == true){
		info.vote_m_.lock();
		if(info.vote_available_ == true){
			//std::cout << "here2\n";
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
	start_raft();
}

int num_votes;
std::mutex nv_m;
void get_vote( std::string ip, int port){
	std::string message = "ELECT;" + info.cur_.ip_addr_ + ";" + info.cur_.port_ ;
	std::string response;
	try{
		udp_sendmsg(message,ip,port,response);
	}
	catch(std::exception& e){
		//std::cout << "Unable to contact host " << "\n";
	}
	
	if(response == "OK"){
		nv_m.lock();
		num_votes++;
		nv_m.unlock();
	}
}


void start_election(){
	num_votes = 0;

	for(int i =0; i < info.node_list_.size();++i){
		// std::thread s(get_vote, info.node_list_[i].ip_addr_, std::stoi(info.node_list_[i].port_));
		// s.detach();
	}
	//std::this_thread::sleep_for(std::chrono::milliseconds(VOTE_TIME));
	if(num_votes+1 > (info.node_list_.size()/2)){
		//std::cout << "Leader Elected \n";
		// std::thread t(leader_fn);
		// t.detach();
	}else{
		start_raft();
	}
	//std::cout << "num votes is " << num_votes << "\n";

}





/*
 * this function receives the hearbeat from the neighbour
 * @param const char* request 
 * @param const char* r_ep
 */
char* ecall_heartbeat_handler(const char* req, const char* r_ep){
	// ocall_print("request is " );
	// ocall_print(request);
	// return "OK";
	std::string request(req);

	std::vector<std::string> vs1;
    split(vs1, request ,";");
    std::string ret = "OK";
    if(vs1[0] == "JOIN"){
    	info_m.lock();
    	info.node_list_.push_back(node(r_ep,vs1[1]));
    	info_m.unlock();
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
    	//std::cout << "heartbeat recevied\n";
    	info.term_ = max(info.term_,std::stoi(vs1[1]));
    	if(info.term_ > std::stoi(vs1[1])){
    		//ignore packet
    		return "NOK";
    	}else{
    		std::string r_log = request.substr(vs1[0].size()+vs1[1].size() +2);
    		//std::cout << "rlog:" << r_log;
    		log_t new_log(r_log);
    		info.log_ = new_log;
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
  
    return (char *)ret.c_str();
}


void ecall_s_node(const char* ip_addr, const char* port, const char* intro_ip, const char* intro_port){
	std::string u_ip_addr(ip_addr);
	std::string u_port(port);
	std::string i_ip_addr(intro_ip);
	std::string i_port(intro_port);
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
		try{
	        udp_sendmsg(message, i_ip_addr, std::stoi(i_port), response);
	    }catch(...){
	    	ocall_print("[ENCLAVE]Error in start_node \n");
	    }
	    //std::cout << "Response is " << response << std::endl;
	    info.deserialize(response);
	}
}

void ecall_start_raft(const char* ip_addr, const char* port, const char* intro_ip, const char* intro_port){
	info.cur_.port_ = port;
	info.cur_.ip_addr_ = ip_addr;

	ocall_heartbeat_server(std::stoi(port));
	ocall_start_node(ip_addr,port,intro_ip,intro_port);
	//std::thread t2(start_node, u_ip_addr,u_port,i_ip_addr,i_port);
	//std::thread t3(start_raft);
	while(1){
		
		
	}
}


bool execute_cmd( int i){
	std::string type =  "";//((info.log_[i].req_type_ == SET) ? "SET" : "GET");
	if(info.log_[i].req_type_ == SET){
		type = "SET";
	}else if(info.log_[i].req_type_ == GET){
		type = "GET";
	}
	if(type != ""){
		std::string res = "Executing " + type  + " " + info.log_[i].key_ + " " + info.log_[i].val_ + "\n";
		ocall_print(res.c_str());	
	}
	info.log_[i].committed_ = true;
	return true;
}