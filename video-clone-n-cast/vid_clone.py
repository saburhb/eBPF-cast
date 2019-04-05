#!/usr/bin/python

from __future__ import print_function
from ctypes import c_ushort, c_int, c_ulong, c_ulonglong
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB

import sys
import socket
import os

##### Avoid logging error #######
import logging
logging.basicConfig()


####### Read index of all available interfaces #########
os.system('cat /sys/class/net/*/ifindex > iflist.txt')


####### Read two interfaces from command line arguments ######
#print('Number of arguments:', len(sys.argv), 'arguments.')
ln=len(sys.argv)
argList=[]
for arg in sys.argv:
    #print(arg)
    argList.append(arg)

srcif=argList[1]
#dstif1=argList[2]
#dstif2=argList[3]

#print(srcif)
#print(dstif)


###### Get IPDB of the system #######
ipr = IPRoute()
ipdb = IPDB(nl=ipr)

##### Load all the interfaces from IPDB #####
ifall = ipdb.interfaces


##### Identify the specific IPDB interfaces as per command line arguments ####

dstList=[]

f = open('iflist.txt')
for line in iter(f):
    i=int(line)
    #print(i)
    if(ifall[i].ifname == srcif):
        ifc = ifall[i]
    elif(ifall[i].ifname.find('veth1_') == 0):
	print('Found Interface \n', ifall[i].ifname);
        dstList.append(ifall[i])
f.close()


try:
    ############### Load the BPF program from C file at specific kernel hook #################
    bpf = BPF(src_file = "vid_clone.c", debug=0)
    function_test_switching = bpf.load_func("replicate_forward", BPF.SCHED_CLS)
  
    idx = ifc.index
    out1 = dstList[0].index
    out2 = dstList[1].index

    print(idx);
    print(out1);
    print(out2);
   
    print(dstList[0].ifname);
    print(dstList[1].ifname);
    
    ######## Define the forward switching rule in the BPF MAP ########
    myList=[]
    for i in range(100):
        myList.append(1)

    for j in range(len(dstList)):
	myList[j] = dstList[j].index
    #myList[0]=out1
    #myList[1]=out2
    arr = (c_ulong * len(myList))(*myList)
	
    portmap = bpf.get_table("portmap")
    #portmap[portmap.Key(idx)] = portmap.Leaf(out1, out2, 0)
    portmap[portmap.Key(idx)] = portmap.Leaf(arr, 0)
    tsmap = bpf.get_table("tsmap")
    tsKey = 1;
    tsmap[tsmap.Key(tsKey)] = tsmap.Leaf(0)
 

    ####### Add the bpf filter at the interface traffic control #######
    if "idx" in locals():
        ipr.tc("del", "ingress", idx, "ffff:")
    ipr.tc("add", "ingress", idx, "ffff:")
    ipr.tc("add-filter", "bpf", idx, ":1", fd=function_test_switching.fd, name=function_test_switching.name, parent="ffff:", action="ok", classid=1)
   

  
    ######### Display switching interface details from the BPF map ########## 
    print('\n');
    print('Interface In', '\t', 'MAC address In', '\t', 'IP address In' , '\t    ', 'Interface Out', '\t', 'MAC address Out', '\t', 'IP address Out')
    print('------------', '\t', '--------------', '\t', '-------------' , '\t    ', '-------------', '\t', '---------------', '\t', '--------------')


    
    ############ Print details of forward switching #############     
    for s, d in bpf["portmap"].items():
        f = open('iflist.txt')
	for line in iter(f):
            i=int(line)
            if(i == s.value):
                sr = ifall[i]
        	c1=sr.ipaddr[-1]
        	l1=list(c1.values())
        	print(sr.ifname, '\t\t', sr.address, '\t', l1[-1], '\t', end="")
	f.close()
	f = open('iflist.txt')
        for line in iter(f):
	    i=int(line)
            if(i == d.out[0]):
                ds = ifall[i]
        	c2=ds.ipaddr[-1]
        	l2=list(c2.values())
		print(ds.ifname, '\t\t', ds.address, '\t', l2[-1], '\t', end="")
	f.close()
	f = open('iflist.txt')
        for line in iter(f):
	    i=int(line)
            if(i == d.out[1]):
                ds3 = ifall[i]
        	c3=ds3.ipaddr[-1]
        	l3=list(c3.values())
		print(ds3.ifname, '\t\t', ds3.address, '\t', l3[-1])
	f.close()
    

    while 1:
        try:
            (task, pid, cpu, flags, ts, msg) = bpf.trace_fields()
            (_tag, s1, s2) = msg.split(" ")

        except ValueError:
            continue

        if _tag != "test_dpi":
            continue

        print(s1,s2)

   
    #while 1: 
	#for s, d in bpf["portmap"].items():
	    #print(d.counter) 
finally:
    #print('OK')
    print('\n')
    ipdb.release()



