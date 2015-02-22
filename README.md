vxlan-netmap
============

netmap is a framework for high speed packet I/O.
about netmap, please see http://info.iet.unipi.it/~luigi/netmap/ .
this implementation is vxlan gateway using netmap I/O.

	 ./vxlan-netmap 
	 usage of vxlan-netmap
	 	 -o : overlay interface name
	 	 -i : internal interface name
	 	 -s : source vtep address
	 	 -v : vni-vlan-mcastaddr mapping



	 ethtool -K ixgbe0 rxvlan off txvlan off
	 ethtool -K ixgbe1 rxvlan off txvlan off
	 
	 gcc -g vxlan-netmap.c -o vxlan-netmap -lpthread
	 sudo ./vxlan-netmap -o ixgbe0 -i ixgbe1 -s 10.0.1.2 -v 1-10-239.0.0.10 -v 2-20-239.0.0.20


Packets including vlan id from a internal interface are encapsulated
with a VNI which is configured by -v options, and transmited to vxlan
overlay network from an overlay interface. specifying vlan id 0 means
untaged packet.



Todo
----
+ show commands
+ strip vlan tag in overlay networks


Contact
-------
upa@haeena.net
