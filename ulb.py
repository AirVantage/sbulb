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
    return struct.unpack("I", socket.inet_aton(ip_address))[0]
    # return socket.htonl((int) (ipaddress.ip_address(ip_address)))

def ip_ntostr(ip_address):
    if isinstance(ip_address, ct.c_uint):
        ip_address = ip_address.value
    return ipaddress.ip_address(socket.ntohl(ip_address))

def mac_strtob(mac_address):
    bytes = binascii.unhexlify(mac_address.replace(':',''))
    if len(bytes) is not 6:
        raise TypeError("mac address must be a 6 bytes arrays")
    return bytes

def mac_btostr(mac_address):
    #bytestr = bytes(mac_address).hex()
    bytestr = binascii.hexlify(bytearray(mac_address))
    return ':'.join(bytestr[i:i+2] for i in range(0,12,2))

def ip_mac_tostr(mac_address, ip_address):
    return "{}/{}".format(mac_btostr(mac_address),ip_ntostr(ip_address))

# Custom argument parser
def mac_ip_parser(s,pat=re.compile("^(.+?)/(.+)$")):
    m = pat.match(s)
    if not m:
        raise argparse.ArgumentTypeError("Invalid address '{}': format is 'MAC_addr/IP_addr' (e.g. 5E:FF:56:A2:AF:15/10.40.0.1)".format(s))
    try:
        mac = mac_strtob(m.group(1))
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid MAC address '{}' : {}".format(m.group(1), str(e)))
    try:
        ip = ip_strton(m.group(2))
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid IP address '{}' : {}".format(m.group(2), str(e)))

    return {"ip":ip,"mac":mac}

# Parse Arguments
parser = argparse.ArgumentParser()
parser.add_argument("ifnet", help="network interface to load balance (e.g. eth0)")
parser.add_argument("-vip", "--virtual_ip", help="<Required> The virtual IP of this loadbalancer", required=True)
parser.add_argument("-rs", "--real_server",type=mac_ip_parser, nargs=1, help="<Required> Real server addresse(s)  e.g. 5E:FF:56:A2:AF:15/10.40.0.1", required=True)
parser.add_argument("-p", "--port", type=int, nargs='+', help="<Required> UDP port(s) to load balance", required=True)
parser.add_argument("-d", "--debug", type=int, choices=[0, 1, 2, 3, 4],
                    help="Use to set bpf verbosity (0 is minimal)", default=0)
args = parser.parse_args()

# Get configuration from Arguments
ifnet = args.ifnet                # network interface to attach xdp program
vip = ip_strton(args.virtual_ip) # virtual ip of load balancer
real_servers = args.real_server
ports = args.port                 # ports of to load balance
debug = args.debug                # bpf verbosity

print("\nLoad balancing UDP traffic over {} interface for port(s) {} from :".format(ifnet, ports, ip_ntostr(vip)))
for real_server in real_servers:
    print ("VIP:{} <=======> Real Server:{}".format(ip_ntostr(vip), ip_mac_tostr(real_server["mac"],real_server["ip"])))


# Shared structure used for perf_buffer
class Data(ct.Structure):
    _fields_ = [
        ("dmac", ct.c_ubyte * 6),   
        ("smac", ct.c_ubyte * 6),
        ("daddr", ct.c_uint),
        ("saddr", ct.c_uint)
    ]

# Compile & attach bpf program
b = BPF(src_file ="ulb.c", debug=debug, cflags=["-w", "-DVIP={}".format(vip), "-DCTXTYPE=xdp_md"])
fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp(ifnet, fn)

# Set Configurations
## Ports configs
ports_map = b["ports"]
for port in ports:
    ports_map[ports_map.Key(socket.htons(port))] = ports_map.Leaf(True)
## Real servers configs
real_servers_map = b.get_table("realServers")
i = 0 
for real_server in real_servers:
    real_servers_map[real_servers_map.Key(i)] = real_servers_map.Leaf(real_server['ip'], (ct.c_ubyte * 6).from_buffer_copy(real_server['mac']))
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
        #(task, pid, cpu, flags, ts, msg) = b.trace_fields()
        #print("%s \n" % (msg))
    except ValueError:
        continue
    except KeyboardInterrupt:
        break;

# Detach bpf progam
b.remove_xdp(ifnet)
