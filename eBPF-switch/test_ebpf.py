#!/usr/bin/python

from __future__ import print_function
from ctypes import c_ushort, c_int, c_ulonglong
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB

import sys
import socket
import os

import logging
logging.basicConfig()

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

ifc = ipdb.interfaces.enp3s0
dst = ipdb.interfaces.virbr0
#dst = ipdb.interfaces.veth0

print(ifc.index)


try:
    bpf = BPF(src_file = "test_ebpf.c", debug=0)
    function_test_switching = bpf.load_func("test_switching", BPF.SCHED_CLS)
  
               
    idx = ifc.index
    out = dst.index

    print(idx);
    print(out);
    
    portmap = bpf.get_table("portmap")
    portmap[portmap.Key(idx)] = portmap.Leaf(out)
    
    if "idx" in locals():
        ipr.tc("del", "ingress", idx, "ffff:")
    ipr.tc("add", "ingress", idx, "ffff:")
    ipr.tc("add-filter", "bpf", idx, ":1", fd=function_test_switching.fd, name=function_test_switching.name, parent="ffff:", action="ok", classid=1)
   
    revport = bpf.get_table("revport")
    revport[revport.Key(out)] = revport.Leaf(idx)

    if "out" in locals():
        ipr.tc("del", "ingress", out, "ffff:")
    ipr.tc("add", "ingress", out, "ffff:")
    ipr.tc("add-filter", "bpf", out, ":1", fd=function_test_switching.fd, name=function_test_switching.name, parent="ffff:", action="ok", classid=1)
   
    for i in range (1, 5):
        for s, d in bpf["portmap"].items():
                print((s.value), (d.value))

    for i in range (1, 5):
        for s, d in bpf["revport"].items():
                print((s.value), (d.value))
   
 
finally:
    print('OK')
    ipdb.release()



