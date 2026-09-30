# PyWall

PyWall is a basic packet filter firewall built in Python. In the joyous spirit of learning how firewalls work at the fundamental networking level, I couldn’t think of a better first Python project to do than this. How hard can it be?



## How it works

1. A packet comes in and hits the NIC, then the kernel. Netfilter, the kernel framework that allows the OS to allow/block/modify network packets, picks up the packet at the NF_INET_LOCAL_IN kernel hook

1. Netfilter hands the packet off to PyWall for Analysis
PyWall unpacks the IP header to extract the protocol number. If the protocol number matches TCP or UDP, the packet is held for further analysis ,else it's let through so I don't break my kernel's network stack

1. PyWall unpacks the Transport layer header to extract the port number

1. The port number is matched against the ALLOW/BLOCK list of the firewall
A BLOCK command is sent to the kernel to drop the packet if it is on the block list or the ACCEPT command is issued to allow further travel along the network stack 
