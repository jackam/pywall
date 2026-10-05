# main.py
# author: jack a.m.
# desc: pywall main app - netfilter hook integration

from netfilterqueue import NetfilterQueue

# Item 1: Array of allowed port numbers (Strict Allowlist / Default Deny)
ALLOWED_PORTS = [22, 80, 443]  # Add whatever ports you want to permit


def packet_callback(packet):
    """Callback function triggered every time the kernel hands a packet to PyWall."""
    # Print raw payload length or examine packet bytes for now
    print(f"[*] Captured packet of size: {len(packet.get_payload())}")

    # TODO: Step 3 & 4 - Unpack struct and extract protocol/port numbers
    # TODO: Step 5 & 6 - Check allowlist and issue ACCEPT or DROP

    # For testing right now, let's accept everything until parsers are ready
    packet.accept()

    # To drop a packet manually, you would use:
    # packet.drop()


def main():
    print("[*] Starting PyWall Netfilter Engine...")
 
    nfqueue = NetfilterQueue()

    try:
        # Bind to queue number 1 (matching our iptables rule)
        nfqueue.bind(1, packet_callback)
        print("[*] Bound to queue #1. Listening for packets...")

        # Start the packet interception loop
        nfqueue.run()

    except KeyboardInterrupt:
        print("\n[*] Shutting down PyWall and unbinding queue...")
        nfqueue.unbind()


if __name__ == "__main__":
    main()




import struct

ALLOWED_PORTS = [22, 80, 443]

def packet_callback(packet):
    """Callback function triggered every time the kernel hands a packet to PyWall."""
    payload = packet.get_payload()
    
    # Ensure the packet is at least long enough to contain an IPv4 header (20 bytes)
    if len(payload) < 20:
        packet.accept()
        return

    # --- Step 3: Layer 3 (IP Header) Parsing ---
    # The first byte contains Version (upper 4 bits) and IHL / Header Length (lower 4 bits)
    version_ihl = payload[0]
    ihl = (version_ihl & 0x0F) * 4  # IHL counts 32-bit words, multiply by 4 to get bytes
    
    # Protocol number is at byte offset 9 (6 = TCP, 17 = UDP)
    protocol = payload[9]
    
    # Pass through non-TCP/UDP traffic safely so we don't break network operations
    if protocol not in (6, 17):
        packet.accept()
        return

    # --- Step 4: Layer 4 (Transport Header) Parsing ---
    # The transport header starts immediately after the IP header (at index 'ihl')
    transport_payload = payload[ihl:]
    
    # Ensure transport payload has enough bytes for ports (at least 4 bytes)
    if len(transport_payload) < 4:
        packet.accept()
        return

    # Unpack source port and destination port using network byte order ('!HH')
    # '!': network byte-order (big-endian), 'H': unsigned short (2 bytes)
    src_port, dst_port = struct.unpack('!HH', transport_payload[:4])

    # --- Step 5 & 6: Allowlist Enforcement (Default Deny) ---
    if dst_port in ALLOWED_PORTS:
        print(f"[+] ACCEPT: Protocol {protocol}, Dest Port {dst_port}")
        packet.accept()
    else:
        print(f"[-] DROP: Unauthorized Dest Port {dst_port}")
        packet.drop()
