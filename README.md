# FloatBoat - SGX based RAFT BFT 

FloatBoat is a BFT algorithm which leverages Intel SGX to achieve Byzantine Fault Tolerance for a RAFT style protocol



## How to build

- Setup Intel SGX and run `source $HOME/linux-sgx/linux/installer/bin/sgxsdk/environment`
- make `SGX_MODE=SIM` for emulator mode and `make` for HW mode

## Running the Protocol ( default requires 5 nodes)
- The first node acts as introducer 
- `./app <IP_ADDRESS_OF_MACHINE> <PORT> <IP_INTRODUCER> <PORT_INTRODUCER>`
- For example run introducer as `./app 192.168.1.1 2000 192.168.1.1 2000`

## Changing settings like Heartbeat

- Enclave/raft.hpp define HB_FREQ , change that to change HB frequency

- make clean and make again after that

