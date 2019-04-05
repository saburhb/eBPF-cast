#!/bin/bash

HOME=/home/envi
NUM_CONT=$1

# Remove all existing containers
docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)


for i in `seq 1 $NUM_CONT`;
do
	ip link add veth1_$i type veth peer name veth2_$i
	### Next 3 lines required for IPDB to populate with interface details, then remove the assigned address
	ifconfig veth1_$i 2.2.2.2/24 up
	ping -c 1 2.2.2.2
	ifconfig veth1_$i 0.0.0.0 up
	ifconfig veth2_$i up
done

sleep 1

# Create and setup receiver containers
for i in `seq 1 $NUM_CONT`;
do
	echo $i
	docker run -it -d --name cont$i ebpf_container_image
	sudo $HOME/pipework/pipework --direct-phys veth2_$i cont$i 10.20.30.40/24 26:2e:71:98:60:8f
	docker exec cont$i /share_sabur/cliserv/server 1234 &
	#j=$((($i) + 1))
	#sudo $HOME/pipework/pipework --direct-phys veth1_$i cont0 10.20.10.$j/24
	#docker exec cont0 ping -c 1 10.10.10.$j 
	#docker exec cont$i ping -c 1 10.20.30.40
done

sleep 1

# Create and setup sender container
ip netns delete ns
ip netns add ns

ip link delete v0
ip link add v0 type veth peer name v1
ifconfig v0 up
ifconfig v1 up
ip link set v1 netns ns
ip netns exec ns ip link set dev lo up
ip netns exec ns ping -c 1 127.0.0.1
ip netns exec ns ifconfig v1 10.20.30.30/24 up
ip netns exec ns ping -c 1 10.20.30.30
ip netns exec ns arp -s 10.20.30.40 26:2e:71:98:60:8f


### run the eBPF program
#python /home/envi/bcc/examples/networking/vid_clone/vid_clone.py v0 &

#ip netns exec ns /home/envi/Downloads/share_sabur/cliserv/client 10.20.30.40 1234 /home/envi/Downloads/uci_campus1.ts











