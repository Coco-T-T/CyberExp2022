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

os.system("ip addr add 192.168.53.5/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))

hostname = sys.argv[1]

# port = 4433
# cadir = '/etc/ssl/certs'
cadir = './ca-client'
# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
SERVER_IP, SERVER_PORT = '10.0.2.8', 4433
sock.connect((SERVER_IP, SERVER_PORT))

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("TLS handshake Finish.")

flag = 1

while True:
    ready, _, _ = select.select([ssock, tun], [], [])
    
    for fd in ready:
        if fd is ssock:
            if flag == 1:
                continue
            data = ssock.recv(2048)
            if data != b'':
                pkt = IP(data)
                print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
                os.write(tun, bytes(pkt))
            else:
                print("Server closed")
                exit()
        if fd is tun:
            flag = 0
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            ssock.send(packet)
