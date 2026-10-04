#
# main.py
# author: jack a.m.
# desc: pywall main app
#

from netfilterqueue import NetfilterQueue
import struct

# port number allow list
ALLOWED_PORTS = [20,21,22,23,25,110,53,67,68,80,443,69,445,161,162,389,636,3389,1812,1813,49,5060,5061,88]

def packet_handler( payload ): 

    # get the packet payload
    packet = payload.get_payload()
   
    # accept if the payload length is at least the size of a tcp/udp header (20 bytes) 
    if len(packet) < 20:
        packet.accept()
        return

    # layer 3 parsing
    # get the first byte of the packet
    version_ihl = packet[0]
    # filter byte for lower 4 bits (lower=header length, upper=ip version)
    # an ihl of 5 is 5 words, 4 bytes per word 
    # 5 words * 4 bytes = 20 byte header length or 160 bits
    ihl = (version_ihl & 0x0F) * 4
    
    # extact protocol number (tcp=6, udp=17)
    protocol = packet[9]

    if protocol in (6,17):
        dest_port_offset = ihl + 2

        if len(packet) >= dest_port_offset + 2:
            dest_port = struct.unpack('!H', packet[dest_port_offset:dest_port_offset + 2])[0]
    
        if dest_port in ALLOWED_PORTS:
                print(f"[+] ALLOWED: Port {dest_port}")
                payload.accept()
                return
        else:
            print(f"[-] BLOCKED: Port {dest_port}")
            payload.drop()
            return
    
    # fallback for non-tcp/udp packets
    payload.accept()

def main():

    nfqueue = NetfilterQueue()
    nfqueue.bind(100, packet_handler)

    try:
        print("[+] PyWall is running. Ctrl-C to stop")
    except KeyboardInterrupt:
        print("\n[-] Flushing queue and shutting down PyWall")

if __name__ == "__main__":
    main()


# bash: sudo iptables -I INPUT -j NFQUEUE --queue-num 101
