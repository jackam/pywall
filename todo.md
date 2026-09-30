# PyWall TODO list

- [ ] Array of allowed port numbers
- [ ] NF_INET_LOCAL_IN hook to grab packets
- [ ] Struct to convert binary raw data to integer format
- [ ] Network and Transport layer parsers to extract header data from struct: protocol number, port number
- [ ] Hold packet if the protocol number matches TCP/UDP protocol numbers
- [ ] Match port number allow array: Send drop command to the kernel if the port is not in the array, else allow through
