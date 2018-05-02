CFLAGS = -g -fPIC  -std=c++11 
OUTPUT_DIR =  out
LDFLAGS = -shared 
TARGET_LIB = libraft.so
all: raft 

raft: $(OUTPUT_DIR)/$(TARGET_LIB)

tests: $(OUTPUT_DIR)/tester

$(OUTPUT_DIR)/$(TARGET_LIB):  $(OUTPUT_DIR)/com.o $(OUTPUT_DIR)/node.o $(OUTPUT_DIR)/raft.o
	mkdir  -p $(OUTPUT_DIR)
	g++ $(CFLAGS) $(LDFLAGS)  $(OUTPUT_DIR)/node.o $(OUTPUT_DIR)/com.o -o $(OUTPUT_DIR)/$(TARGET_LIB) -lboost_system -pthread

$(OUTPUT_DIR)/tester: $(OUTPUT_DIR)/com.o $(OUTPUT_DIR)/tester.o $(OUTPUT_DIR)/raft.o
	mkdir -p $(OUTPUT_DIR)
	g++ $(CFLAGS)  $(OUTPUT_DIR)/tester.o  $(OUTPUT_DIR)/com.o -o $(OUTPUT_DIR)/tester -lboost_system -pthread

$(OUTPUT_DIR)/node.o: node.cpp node.hpp raft.hpp
	mkdir  -p $(OUTPUT_DIR)
	g++ $(CFLAGS) -c node.cpp  -o $(OUTPUT_DIR)/node.o

$(OUTPUT_DIR)/tester.o: tester.cpp raft.hpp
	mkdir  -p $(OUTPUT_DIR)
	g++ $(CFLAGS) -c tester.cpp -o $(OUTPUT_DIR)/tester.o

$(OUTPUT_DIR)/com.o: com.hpp com.cpp 
	mkdir -p $(OUTPUT_DIR)
	g++ $(CFLAGS) -c com.cpp -o $(OUTPUT_DIR)/com.o

$(OUTPUT_DIR)/raft.o: raft.hpp 
	mkdir -p $(OUTPUT_DIR)
	g++ $(CFLAGS) -c raft.hpp -o $(OUTPUT_DIR)/raft.o


clean:
	rm -rf $(OUTPUT_DIR)
