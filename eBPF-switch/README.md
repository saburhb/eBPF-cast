# ebpf-switch
This program uses BPF program to perform the switching/NAT functionality.
The bpf prgram is hooked at the qdisc traffic classifier so that it can 
have information about the network interface. The userspace then accesses
the bpf map and defines the switching rules by updating the shared hash table. 
The shared hash table can be read in the bpf kernel space and bpf redirect will
kick in. The bpf program then modifies the ioutgoing interface corresponding
to the destination interface index mentioned in the shared MAP.
