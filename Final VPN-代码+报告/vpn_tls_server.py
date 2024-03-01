#!/usr/bin/env python3

import fcntl
import struct
import os
import time
import ssl
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

os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

# os.system("ip route add 10.0.2.0/24 dev {}".format(ifname))

SERVER_CERT = '/volumes/server-certs/server.crt'
SERVER_PRIVATE = '/volumes/server-certs/server.key'

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # For Ubuntu 20.04 VM
context.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

# Create TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

IP_A = '10.0.2.8'
PORT = 4433
sock.bind((IP_A, PORT))
sock.listen(5)
inputs = [sock,tun]
outputs = sock

while True:
    ready, _, _ = select.select(inputs, [], [])
    
    for fd in ready:
        if fd is sock:
            con, addr = sock.accept()
            ssock = context.wrap_socket(con, server_side=True)
            inputs.append(ssock)
            outputs = ssock
        elif fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            outputs.sendall(packet)
        else:
            data = fd.recv(2048)
            if data != b'':
                pkt = IP(data)
                print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
                os.write(tun, bytes(pkt))
            else:
                print("Closing {}".format(addr))
                inputs.remove(fd)
                fd.close()
                