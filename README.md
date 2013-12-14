vxlan-netmap
============

under construction.


	 ./vxlan-netmap: 
	 usage of vxlan-netmap
	 	 -o : overlay interface name
	 	 -i : internal interface name
	 	 -s : source vtep address
	 	 -v : vni-vlan-mcastaddr mapping


	 gcc -g vxlan-netmap.c -I../../sys -o vxlan-netmap -lpthread
	 sudo ./vxlan-netmap -o ixgbe0 -i ixgbe1 -s 10.0.1.2 -v 1-10-239.0.0.1


まだうまく動かない。。。
