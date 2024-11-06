## Download and install eunomia-bpf Development Tools?
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
./ecli -h

## Download the ecli tool for running eBPF programs
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
./ecc -h

## Install the ecc and ecli commands
sudo apt install clang llvm
./ecc <program>.bpf.c
## Run the compiled program
sudo ./ecli run package.json


## Basic Framework of eBPF Program
- Include header files
- Define a license (typically using "Dual BSD/GPL")
- Define a BPF function. Need to define a BPF function, which takes a parameter and returns int (normally written in the C language)
- Use BPF helper functions
- Return value
