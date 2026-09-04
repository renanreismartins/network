import os
import struct
import fcntl
import errno

# --- 1. Construct the Ethernet Header ---
# Destination MAC (Broadcast): ff:ff:ff:ff:ff:ff
# Source MAC (Replace with your Mac's en0 MAC, e.g., 11:22:33:44:55:66)
# EtherType: 0x0806 (ARP)
eth_header = struct.pack("! 6B 6B H", 
                         255, 255, 255, 255, 255, 255, 
                         0xce, 0x97, 0x4d, 0x82, 0x25, 0xc7,
                         0x0806)

# --- 2. Construct the ARP Payload ---
# Sender IP (e.g., 192.168.1.100) and Target IP (e.g., 192.168.1.1)
arp_payload = struct.pack("! H H B B H 6B 4B 6B 4B",
                          1,          # Hardware Type (Ethernet)
                          0x0800,     # Protocol Type (IPv4)
                          6,          # Hardware Address Length
                          4,          # Protocol Address Length
                          1,          # Operation (1 = Request)
                          0xce, 0x97, 0x4d, 0x82, 0x25, 0xc7,  # Sender MAC
                          192, 168, 1, 100,                    # Sender IP
                          0, 0, 0, 0, 0, 0,                    # Target MAC (all zeros)
                          192, 168, 1, 1)                      # Target IP

packet = eth_header + arp_payload

# --- 3. Find and open a BPF device ---
fd = None
for i in range(100):
    try:
        fd = os.open(f"/dev/bpf{i}", os.O_RDWR)
        break
    except OSError as e:
        if e.errno in (errno.EBUSY, errno.ENOENT):
            continue
        raise
else:
    raise Exception("No free /dev/bpf0-99 devices found")

try:
    # --- 4. Bind BPF to the interface ---
    iface = b"en0"
    ifreq = struct.pack("16s", iface)
    BIOCSETIF = 0x8020426c # macOS ioctl command
    
    fcntl.ioctl(fd, BIOCSETIF, ifreq)
    
    # --- 5. Inject the packet ---
    #bytes_sent = os.write(fd, packet)
    #print(f"Sent {bytes_sent} bytes: ARP Request injected on {iface.decode()}")






    # macOS ioctl command to enable Immediate Mode (BIOCIMMEDIATE)
    BIOCIMMEDIATE = 0x80044270

    # Set the value to 1 (True) packed as an unsigned int ("I")
    enable_immediate = struct.pack("I", 1)
    fcntl.ioctl(fd, BIOCIMMEDIATE, enable_immediate)
    while True:
        packet = os.read(fd, 4096)
        
        # 18-byte BPF header + 14-byte Ethernet header = 32
        eth_header = packet[18:32] 
        eth_tuple = struct.unpack("! 6B 6B H", eth_header)
        
        if eth_tuple[12] == 0x0806: # It's an ARP packet!
            print("Got an ARP packet")
finally:
    # Clean up the file descriptor
    os.close(fd)