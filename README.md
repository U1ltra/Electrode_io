# Speeding Distributed Protocols using eBPF and io_uring

The following explains how to run our code on CloudLab.

## Cluster Configuration
### Quick Setup
Configure a cluster of 4-nodes x86 machines. For easy setup, use profiles
- electrodeio-c6525-100g (verified)

### Mannual Setup
If c6525-100g not available, consider the following
- c6525-25g
- xl170
- other x86 machines (not sure)

Do the following
- `Start Experiment`
- `Next`
- Parameters
  - 4 Nodes
  - UBUNTU 22.04
  - \<node-type\> 
  - check `Start X11 VNC on your nodes`
- Finalize and wait for the shell to comeup

## Env and Compile

### 6.0.0 kernel
On all four machines, 
```bash
wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
sudo bash ubuntu-mainline-kernel.sh -i 6.0.0
sudo reboot
```

### dependencies and repo
On all four machines, 
```bash
sudo apt update
sudo apt install llvm clang gpg curl tar xz-utils make gcc flex bison libssl-dev libelf-dev protobuf-compiler pkg-config libunwind-dev libssl-dev libprotobuf-dev libevent-dev libgtest-dev

cd ~
git clone https://github.com/U1ltra/Electrode_io
cd ~/Electrode_io/

bash kernel-src-download.sh
bash kernel-src-prepare.sh

```

### network stack setup
On all four machines, 
```bash
ifconfig # check MAC address of the interface

sudo ifconfig <interface-name> mtu 3000 up
sudo ethtool -C <interface-name> adaptive-rx off adaptive-tx off rx-frames 1 rx-usecs 0  tx-frames 1 tx-usecs 0
sudo ethtool -C <interface-name> adaptive-rx off adaptive-tx off rx-frames 1 rx-usecs 0  tx-frames 1 tx-usecs 0
sudo ethtool -L <interface-name> combined 1
sudo service irqbalance stop
(let CPU=0; cd /sys/class/net/<interface-name>/device/msi_irqs/;
for IRQ in *; do
      echo $CPU | sudo tee /proc/irq/$IRQ/smp_affinity_list
done)
```

### config replica addresses
On all four machines, 
```bash
ifconfig # check ip and MAC addresses
```
Find the following in `utils/autoconfig.py` and replace the placeholders with the actual replica addresses.
```python
...
if __name__ == "__main__":
    ips = "ip1, ip2, ip3".split(", ")
    macs = "mac1, mac2, mac3".split(", ")
...
```
Under `Electrode_io/` run
```bash
python utils/autoconfig.py
```

### install io_uring dependency
On all four machines, 
```bash
cd ~
git clone https://github.com/axboe/liburing
cd liburing
make
sudo make install
```

### compile the code
On all four machines, 
```bash
cd ~/Electrode_io/xdp-handler
make clean && make EXTRA_CFLAGS="-DTC_BROADCAST -DFAST_QUORUM_PRUNE -DFAST_REPLY"

cd ..
make clean && make CXXFLAGS="-DTC_BROADCAST -DFAST_QUORUM_PRUNE -DFAST_REPLY"
```

## Launching Experiment
On the three replicas, start xdp-handler,
```bash
# start ebpf in the background
cd ~/Electrode_io/xdp-handler
nohup sudo ./fast <interface-name> &
echo $! > pid.file

# cd ~/Electrode_io/xdp-handler
# kill -2 $(cat pid.file) # to stop the ebpf program safely
```

On the three replicas, start paxos server,
```bash
cd ~/Electrode_io/
sudo taskset -c 1 ./bench/replica -c config.txt -m vr -i {idx} # idx=0/1/2 when f=1
```

On the one client node
```bash
cd ~/Electrode_io/
./bench/client -c config.txt -m vr -n 10000 # -n is the number of requests
```

## Known Issue
Error `20241101-093256-3254 18489 * ResendPrepare   (replica.cc:480):   [0] Resending prepare`
- Restart the experiment from `xdp-handler`. Kill the previous xdp-handler process in the background using `kill -2 $(cat pid.file)`
