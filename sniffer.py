import os, socket, sys
import struct
import threading, time
import argparse
from ctypes import *
from netaddr import IPNetwork, IPAddress


class IP(Structure):
    _fields_ = [
        ("ihl",     c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos",     c_ubyte),
        ("len",     c_ushort),
        ("id",      c_ushort),
        ("offset",  c_ushort),
        ("ttl",     c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum",     c_ushort),
        # Changed from c_ulong to c_uint
        ("src",     c_uint),
        ("dst",     c_uint)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ICMP(Structure):

    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


def udp_sender(subnet, magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message.encode(),("{}".format(ip), 65212))
        except:
            pass


if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

args = argparse.ArgumentParser()
args.add_argument("-host", "-o", dest="host", type=str, help="Host IP to bind to")
args.add_argument("-subnet", "-s", dest="subnet", type=str, help="Subnet to scan")
args.add_argument("-message", "-m", dest="message", type=str,
                  help="Magic message to send with pings",
                  default="0xDEADBEEF")
pa = args.parse_args(sys.argv[1:])

magic_message = pa.message

host = pa.host
subnet_mask = pa.subnet

if host is None or subnet_mask is None:
    args.print_help()
    print("Error! Both host and subnet are required parameters")
    sys.exit(1)

sniffer =  socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

t = threading.Thread(target=udp_sender, args=(subnet_mask,magic_message))
t.start()

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:20])
        if ip_header.protocol == "ICMP":
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset+sizeof(ICMP)]
            icmp_header = ICMP(buf)
            if icmp_header.type != 3 or icmp_header.code != 3:
                continue
            if IPAddress(ip_header.src_address) in IPNetwork(subnet_mask):
                if raw_buffer[len(raw_buffer) - len(magic_message):] == magic_message.encode():
                    print("Host up: {}".format(ip_header.src_address))
        else:
            print("Protocol: {} {} -> {}".format(ip_header.protocol, ip_header.src_address, ip_header.dst_address))

except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

sniffer.close()