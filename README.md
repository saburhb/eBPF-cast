# eBPF-cast
This program uses BPF program to perform the packet processing, selective clonning and switching/NAT functionality for redirection to specific interfaces. The bpf prgram is hooked at the qdisc traffic classifier so that it can have information about the network interface. The userspace then accesses the bpf map and defines the switching rules by updating the shared hash table. The shared hash table can be read in the bpf kernel space and bpf redirect will kick in. The bpf program then modifies the ioutgoing interface corresponding to the destination interface index mentioned in the shared MAP. 

They Python program defines the function(s) that need to be connected to the socket / traffic clasifier / or, device driver's receive function. The functions that executed inside eBPF in-kernel VM does check the video frame type (whether a reference frame or differential frame) based on Deep Packet Inspaction (DPI) on the packet payloads after removing the headers. Based on the frame type, it drops certain percentage of packets of specific types and clones and forwards the packet in-place before sending any copy of the packet to the application layer. The code uses the hypervisor interface for packet reception and then virtual interfaces of the VMs runnig on the hypervisor for the selective clone and forwarding. 


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

If you want to test just the switching functionality using eBPF, see the code in eBPF-switch. The video processing with selective clone and forward is in the eBPF-clone-n-cast folder. The video transmission application can be setup with standard socket program (not incuded in this repository). Only rerequirement is that the video application uses deep packet inspaction (DPI) based on Transport Stream (TS) formatted video. If you convert a mpeg4/h.264 AVC video and encode it with TS (in .ts format), the DPI will work fine. However, this is just a framework provided for any virtual netowrk function or packet processing function to be implemented on top of it.

