#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'cocot%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.5/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))

# Create TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
SERVER_IP, SERVER_PORT = '10.0.2.8', 4433
sock.connect((SERVER_IP, SERVER_PORT))

while True:
    ready, _, _ = select.select([sock, tun], [], [])
    
    for fd in ready:
        if fd is sock:
            data = sock.recv(2048)
            if data != b'':
                pkt = IP(data)
                print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
                os.write(tun, bytes(pkt))
            else:
                print("Server closed")
                exit()
        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            sock.send(packet)
