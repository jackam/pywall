# PyWall

PyWall is a basic packet filter firewall built in Python. In the joyous spirit of learning how firewalls work at the fundamental networking level, I couldn’t think of a better first Python project do than this. How hard can it be?

## How it works

An incoming IP packet hits the NIC and then kernel. PyWall monitors the Linux kernel's built in packet processor called Netfilter and utilizes it's NF_INET_LOCAL_IN hook to intercept each packet and apply the firewall rules, either allowing the packet through or dropping it.  
