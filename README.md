# eBPF-cast
This program uses BPF program to perform the switching/NAT functionality.
The bpf prgram is hooked at the qdisc traffic classifier so that it can 
have information about the network interface. The userspace then accesses
the bpf map and defines the switching rules by updating the shared hash table. 
The shared hash table can be read in the bpf kernel space and bpf redirect will
kick in. The bpf program then modifies the ioutgoing interface corresponding
to the destination interface index mentioned in the shared MAP.

The details about the architecture and some preliminary results are presented in our [paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8407006). If you find this code useful in your research, please consider citing:

```
@inproceedings{baidya2018ebpf,
  title={eBPF-based content and computation-aware communication for real-time edge computing},
  author={Baidya, Sabur and Chen, Yan and Levorato, Marco},
  booktitle={IEEE INFOCOM 2018-IEEE Conference on Computer Communications Workshops (INFOCOM WKSHPS)},
  pages={865--870},
  year={2018},
  organization={IEEE}
}
```
