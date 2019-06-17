#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
import ctypes as ct
import ipaddress
import socket
import argparse
import binascii
import struct
import re

# Utils
def ip_strton(ip_address):
    # struct.unpack("I", socket.inet_aton(ip_address))[0]
    return socket.htonl((int) (ipaddress.ip_address(ip_address)))

def ip_ntostr(ip_address):
    if isinstance(ip_address, ct.c_uint):
        ip_address = ip_address.value
    return ipaddress.ip_address(socket.ntohl(ip_address))

def mac_btostr(mac_address):
    bytestr = bytes(mac_address).hex()
    return ':'.join(bytestr[i:i+2] for i in range(0,12,2))

def ip_mac_tostr(mac_address, ip_address):
    return "{}/{}".format(mac_btostr(mac_address),ip_ntostr(ip_address))

def server_tostr(server):
    return ip_ntostr(server["ip"])

# Custom argument parser
def ip_parser(s):
    try:
        ip = ip_strton(s)
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid IP address '{}' : {}".format(ip, str(e)))
    return {"ip":ip}

# Parse Arguments
parser = argparse.ArgumentParser()
parser.add_argument("ifnet", help="network interface to load balance (e.g. eth0)")
parser.add_argument("-vs", "--virtual_server", type=ip_parser, help="<Required> Virtual server address (e.g. 10.40.0.1)", required=True)
parser.add_argument("-rs", "--real_server", type=ip_parser, nargs=1, help="<Required> Real server address(es) (e.g. 10.40.0.1)", required=True)
parser.add_argument("-p", "--port", type=int, nargs='+', help="<Required> UDP port(s) to load balance", required=True)
parser.add_argument("-d", "--debug", type=int, choices=[0, 1, 2, 3, 4],
                    help="Use to set bpf verbosity (0 is minimal)", default=0)
args = parser.parse_args()

# Get configuration from Arguments
ifnet = args.ifnet                   # network interface to attach xdp program
virtual_server = args.virtual_server # virtual server (ethernet and IP address)
real_servers = args.real_server      # list of real servers (ethernet and IP address)
ports = args.port                    # ports to load balance
debug = args.debug                   # bpf verbosity

print("\nLoad balancing UDP traffic over {} interface for port(s) {} from :".format(ifnet, ports, ip_ntostr(virtual_server['ip'])))
for real_server in real_servers:
    print ("VIP:{} <=======> Real Server:{}".format(server_tostr(virtual_server), server_tostr(real_server)))


# Shared structure used for perf_buffer
class Data(ct.Structure):
    _fields_ = [
        ("dmac", ct.c_ubyte * 6),   
        ("smac", ct.c_ubyte * 6),
        ("daddr", ct.c_uint),
        ("saddr", ct.c_uint)
    ]

# Compile & attach bpf program
b = BPF(src_file ="ulb.c", debug=debug, cflags=["-w", "-DCTXTYPE=xdp_md"])
fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp(ifnet, fn)

# Set Configurations
## Virtual server config
virtual_server_map = b.get_table("virtualServer")
virtual_server_map[virtual_server_map.Key(0)] = virtual_server_map.Leaf(virtual_server['ip'])
## Ports configs
ports_map = b["ports"]
for port in ports:
    ports_map[ports_map.Key(socket.htons(port))] = ports_map.Leaf(True)
## Real servers configs
real_servers_array = b.get_table("realServersArray")
real_servers_map = b.get_table("realServersMap")
i = 0 
for real_server in real_servers:
    real_servers_array[real_servers_array.Key(i)] = real_servers_array.Leaf(real_server['ip'])
    real_servers_map[real_servers_map.Key(real_server['ip'])] = real_servers_map.Leaf(real_server['ip'])
    i+=1

# Utility function to print udp dest NAT.
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("source {} --> dest {}".format(ip_mac_tostr(event.smac, event.saddr),ip_mac_tostr(event.dmac, event.daddr)))

# Loop to read perf buffer
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
        # DEBUG STUFF
        #(task, pid, cpu, flags, ts, msg) = b.trace_fields(nonblocking = True)
        #while msg:
        #    print("%s \n" % (msg))
        #    (task, pid, cpu, flags, ts, msg) = b.trace_fields(nonblocking = True)
    except ValueError:
        continue
    except KeyboardInterrupt:
        break;

# Detach bpf progam
b.remove_xdp(ifnet)
