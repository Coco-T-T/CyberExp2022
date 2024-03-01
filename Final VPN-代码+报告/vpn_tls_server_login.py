#!/usr/bin/env python3

import fcntl
import struct
import os
import time
import ssl
import spwd
import crypt
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

def login(username, password):
    try:
        enc_pwd = spwd.getspnam(username)[1]
        if enc_pwd in ["NP", "!", "", None]:
            return "user '%s' has no password set" % username
        if enc_pwd in ["LK", "*"]:
            return "account is locked"
        if enc_pwd == "!!":
            return "password has expired"
        # Encryption happens here, the hash is stripped from the
        # enc_pwd and the algorithm id and salt are used to encrypt
        # the password.
        if crypt.crypt(password, enc_pwd) == enc_pwd:
            return True
        else:
            return "incorrect password"
    except KeyError:
        return "user '%s' not found" % username
    return "unknown error"

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
context.num_tickets = 0 # Important Parameter

# Create TCP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

IP_A = '10.0.2.8'
PORT = 4433
sock.bind((IP_A, PORT))
sock.listen(5)

inputs = [sock,tun]
outputs = sock

flag = 2
username = ''
password = ''

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
            outputs.send(packet)
        else:
            data = fd.recv(2048)    
            if data != b'':
                if flag == 0:  # communication
                    pkt = IP(data)
                    print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
                    os.write(tun, bytes(pkt))
                elif flag == 2:  # name
                    username = str(data, encoding = "utf-8")
                    flag = flag - 1
                else:  # pswd
                    password = str(data, encoding = "utf-8")
                    flag = flag - 1
                    status = login(username, password)
                    if status == True:
                        opt = "Login Succeed!"
                        print(opt)
                        outputs.send(opt.encode())
                    else:
                        opt = "Login Fail: " + status + "."
                        print(opt)
                        outputs.send(opt.encode())
                        print("Closing {}".format(addr))
                        flag = 2  # need login
                        inputs.remove(fd)
                        fd.close()  
            else:
                print("Closing {}".format(addr))
                flag = 2  # need login
                inputs.remove(fd)
                fd.close()
                