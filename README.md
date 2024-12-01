# Speeding Distributed Protocols using eBPF and io_uring

Configure a cluster of 4-nodes x86 machines. For easy setup, use profiles
- c6525-25g/c6525-100g (best option if available)
- m400
- m510_reduced

In all shells
```bash
wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
sudo bash ubuntu-mainline-kernel.sh -i 6.0.0
sudo reboot

sudo apt update
sudo apt install llvm clang gpg curl tar xz-utils make gcc flex bison libssl-dev libelf-dev protobuf-compiler pkg-config libunwind-dev libssl-dev libprotobuf-dev libevent-dev libgtest-dev

git clone https://github.com/U1ltra/Electrode_io
cd Electrode_io/

bash kernel-src-download.sh
bash kernel-src-prepare.sh

ifconfig
```

```bash
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

use `ifconfig` to check the IP address of each paxos nodes and make sure `./config.txt` has correct IP addresses (likely no modification is needed)

write the MACADDR of the cluster in ```line 281``` of ```xdp-handler/fast_user.c```. 

Also you need to modify the ```line 17``` of `xdp-handler/fast_common.h`, the `CLUSTER_SIZE` should equals to $2f + 1$. (nothing to change if using a 3-nodes paxos)

```bash
cd xdp-handler
make clean && make EXTRA_CFLAGS="-DTC_BROADCAST -DFAST_QUORUM_PRUNE -DFAST_REPLY"

cd ..
make clean && make CXXFLAGS="-DTC_BROADCAST -DFAST_QUORUM_PRUNE -DFAST_REPLY"

cd xdp-handler
sudo ./fast <interface-name>

cd xdp-handler
nohup sudo ./fast <interface-name> &
echo $! > pid.file

# kill -2 $(cat pid.file)
```

In new terminals:

```bash
cd ./Electrode_io/
sudo taskset -c 1 ./bench/replica -c config.txt -m vr -i {idx} # idx=0/1/2 when f=1
```

On the client node
```bash
cd ./Electrode_io/
./bench/client -c config.txt -m vr -n 10000
```

## Learning resources
- https://www.youtube.com/watch?v=0p987hCplbk
- https://sematext.com/blog/ebpf-and-xdp-for-processing-packets-at-bare-metal-speed/
- https://www.brendangregg.com/blog/2018-10-08/dtrace-for-linux-2018.html
- https://dl.acm.org/doi/pdf/10.1145/3371038

## Setting up Electrode & io_uring
The main issue in the existing setup with io_uring is the kernel version. Linux kernel 6.0+ is needed to support our implementation.

So at the current stage, before the implementation is ready for debugging, we should search for usable cloudlab machine types, maybe outside the Utah region. Some node types that has been verified are

- c6525-25g
- c6525-100g

But these two types are too scarce to support experiments.

### creating cloudlab experiment
- allocating one node is enough for env testing
- use nodes with x86 architecture
- don't select any profile, directly go to next
      - use ubuntu 22.04 OS image
- wait for the shell to come up

### io_uring test
Change the kernel to 6.0.0

```bash
wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
sudo bash ubuntu-mainline-kernel.sh -i 6.0.0
sudo reboot
```

If the reboot is successful, install io_uring for user space programming
```bash
git clone https://github.com/axboe/liburing
cd liburing
make
sudo make install
```

If the above does not with, refer to [this solution](https://askubuntu.com/questions/1378948/availability-of-liburing-in-ubuntu-20-04).


```bash
git clone https://github.com/U1ltra/Electrode_io
cd Electrode_io/io_uring_verify
gcc -o recv_multishot recv_multishot.c -luring
```

If that compiles without saying io_uring_prep_recvmsg_multishot undefined, the environment should be working for our io_uring implementation.

### Electrode test
Go through the rest of [Reproducing the results](#reproducing-the-results) section without changing the kernel to 5.8.0. Test that the replica and client's code are both working.

