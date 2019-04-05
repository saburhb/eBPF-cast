# ebpf-switch
This program uses BPF program to perform the switching/NAT functionality.
The bpf prgram is hooked at the qdisc traffic classifier so that it can 
have information about the network interface. The userspace then accesses
the bpf map and defines the switching rules by updating the shared hash table. 
The shared hash table can be read in the bpf kernel space and bpf redirect will
kick in. The bpf program then modifies the ioutgoing interface corresponding
to the destination interface index mentioned in the shared MAP.

### To execute the program run the following:
```
python test_ebpf.py <interface 1> <interface 2>
```

### Example:
```
python test_ebpf.py enp3s0 virbr0
```
### Output:

```
Interface In 	 MAC address In 	 IP address In 	     Interface Out 	 MAC address Out 	 IP address Out
------------ 	 -------------- 	 ------------- 	     ------------- 	 --------------- 	 --------------
enp3s0 		 18:03:73:d4:4d:52 	 10.145.240.201 	virbr0 		 fe:54:00:7e:a3:41 	 192.168.122.1
virbr0 		 fe:54:00:7e:a3:41 	 192.168.122.1 		enp3s0 		 18:03:73:d4:4d:52 	 10.145.240.201
```
