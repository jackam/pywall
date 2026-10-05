# PyWall TODO list

- [x] Array of allowed port numbers
- [x] NF_INET_LOCAL_IN hook to grab packets
- [x] Struct to convert binary raw data to integer format
- [x] Network and Transport layer parsers to extract header data from struct: protocol number, port number
- [x] Hold packet if the protocol number matches TCP/UDP protocol numbers
- [x] Match port number allow array: Send drop command to the kernel if the port is not in the array, else allow through
- [x] Run python script
- [x] Run iptables cmd: sudo iptables -I INPUT -j NFQUEUE --queue-num 1 
