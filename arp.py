import os
import struct
import fcntl
import errno

# --- 0. Local config -------------------------------------------------------
# Source MAC must be en0's *in-use* address (`ifconfig en0` -> ether), not the
# burned-in one from `networksetup`. macOS randomizes it per network, and the
# AP will only relay frames from the MAC that actually associated.
IFACE = b"en0"
SRC_MAC = (0x7a, 0xe2, 0x83, 0x0e, 0xa7, 0x9a)
SRC_IP = (192, 168, 1, 90)
TARGET_IP = (192, 168, 1, 96)   # router; swap in the phone's IP

ETHERTYPE_ARP = 0x0806
ARP_REQUEST = 1
ARP_REPLY = 2

# --- 1. Construct the Ethernet Header --------------------------------------
# Destination MAC is broadcast: we don't know who owns TARGET_IP yet -- that
# is the entire point of the request.
eth_header = struct.pack("! 6B 6B H",
                         255, 255, 255, 255, 255, 255,
                         *SRC_MAC,
                         ETHERTYPE_ARP)

# --- 2. Construct the ARP Payload ------------------------------------------
arp_payload = struct.pack("! H H B B H 6B 4B 6B 4B",
                          1,            # Hardware Type (Ethernet)
                          0x0800,       # Protocol Type (IPv4)
                          6,            # Hardware Address Length
                          4,            # Protocol Address Length
                          ARP_REQUEST,  # Operation
                          *SRC_MAC,     # Sender MAC
                          *SRC_IP,      # Sender IP
                          0, 0, 0, 0, 0, 0,  # Target MAC (unknown -> zeros)
                          *TARGET_IP)   # Target IP

packet = eth_header + arp_payload

# --- 3. Find and open a BPF device -----------------------------------------
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

BIOCSETIF = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN = 0x40044266
BPF_ALIGNMENT = 4


def word_align(x):
    return (x + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1)


def frames(buf):
    """Yield (frame, truncated) for each BPF record in one read buffer.

    A single read() returns *several* records back to back, each preceded by a
    struct bpf_hdr and padded to a 4-byte boundary. The header is host-memory
    layout, so "<" (little-endian, unpadded) -- not "!".
    """
    off = 0
    while off < len(buf):
        _sec, _usec, caplen, datalen, hdrlen = struct.unpack_from("<iiIIH", buf, off)
        start = off + hdrlen
        yield buf[start:start + caplen], caplen < datalen
        off += word_align(hdrlen + caplen)


def fmt_mac(bs):
    return ":".join(f"{b:02x}" for b in bs)


def fmt_ip(bs):
    return ".".join(str(b) for b in bs)


try:
    # --- 4. Bind BPF to the interface --------------------------------------
    # BIOCSETIF expects a 32-byte struct ifreq, not just the 16-byte name.
    fcntl.ioctl(fd, BIOCSETIF, struct.pack("32s", IFACE))

    # Deliver packets as they arrive instead of waiting for a full buffer.
    fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack("I", 1))

    # The read buffer must be exactly BIOCGBLEN bytes or read() gives EINVAL.
    blen = struct.unpack("I", fcntl.ioctl(fd, BIOCGBLEN, struct.pack("I", 0)))[0]

    # --- 5. Inject the packet ----------------------------------------------
    bytes_sent = os.write(fd, packet)
    print(f"Sent {bytes_sent} bytes: ARP request for {fmt_ip(TARGET_IP)} on {IFACE.decode()}")
    print(f"Listening (BPF buffer {blen} bytes)...\n")

    # --- 6. Read replies ---------------------------------------------------
    while True:
        for frame, truncated in frames(os.read(fd, blen)):
            if len(frame) < 14:
                continue

            eth_tuple = struct.unpack("! 6B 6B H", frame[:14])
            if eth_tuple[12] != ETHERTYPE_ARP:
                continue
            if len(frame) < 42:
                continue

            arp = struct.unpack("! H H B B H 6B 4B 6B 4B", frame[14:42])
            op = arp[4]
            sender_mac, sender_ip = arp[5:11], arp[11:15]
            target_ip = arp[21:25]

            if op == ARP_REQUEST:
                print(f"REQUEST  {fmt_ip(sender_ip)} ({fmt_mac(sender_mac)}) "
                      f"asks who has {fmt_ip(target_ip)}")
            elif op == ARP_REPLY:
                print(f"REPLY    {fmt_ip(sender_ip)} is at {fmt_mac(sender_mac)} "
                      f"(told to {fmt_ip(target_ip)})")
finally:
    os.close(fd)
