#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
import ctypes as ct
import ipaddress
import socket
import argparse
import configparser
import binascii
import struct
import re
import os
import signal

# Utils
def ip_strton(ip_address):
    return socket.htonl((int) (ipaddress.ip_address(ip_address)))

def ip_ntostr(ip_address):
    if isinstance(ip_address, ct.c_uint):
        ip_address = ip_address.value
    return str(ipaddress.ip_address(socket.ntohl(ip_address)))

def mac_btostr(mac_address):
    bytestr = bytes(mac_address).hex()
    return ':'.join(bytestr[i:i+2] for i in range(0,12,2))

def ip_mac_tostr(mac_address, ip_address):
    return "{}/{}".format(mac_btostr(mac_address),ip_ntostr(ip_address))

def associationType_tostr(atype):
    if atype == 0:
        return "replaced by"
    elif atype == 1:
        return "(NEW ASSOCIATION)"
    elif atype == 2:
        return "(REUSED ASSOCIATION)"
    else:
        return "UNKNOWN"

def ips_tostr(ips):
    return ", ".join(map(ip_ntostr, ips))

# Custom argument parser
def ip_parser(s):
    try:
        return ip_strton(s)
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid IP address '{}' : {}".format(s, str(e)))

# Parse Arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("ifnet", help="network interface to load balance (e.g. eth0)")
parser.add_argument("-vs", "--virtual_server", type=ip_parser, help="<Required> Virtual server address (e.g. 10.40.0.1)", required=True)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-rs", "--real_server", type=ip_parser, nargs='+', help="<Required> Real server address(es) (e.g. 10.40.0.1)")
group.add_argument("-cfg", "--config_file", type=argparse.FileType('r'), help='''<Required> a path to a file containing real server address(es). 
File will be polled each second for modification and configuration
updated dynamically. A file content example :

[Real Servers]
10.0.0.4
10.0.0.2
10.0.0.6

''')
parser.add_argument("-p", "--port", type=int, nargs='+', help="<Required> UDP port(s) to load balance", required=True)
parser.add_argument("-d", "--debug", type=int, choices=[0, 1, 2, 3, 4],
                    help="Use to set bpf verbosity (0 is minimal)", default=0)
args = parser.parse_args()

# Get configuration from Arguments
ifnet = args.ifnet                   # network interface to attach xdp program
virtual_server_ip = args.virtual_server # virtual server IP address
ports = args.port                    # ports to load balance
debug = args.debug                   # bpf verbosity

real_server_ips = []                 # list of real server IP addresses
config_file = args.config_file       # config file containing real server IP address list
config_file_mtime = 0                # last modification time of config file

def load_config(cfgFile):
    """Load configuration from file object and return a list of server"""
    print ("\nLoading real servers from {} file ...".format(cfgFile.name))
    config = configparser.ConfigParser(allow_no_value=True)
    config.read_file(cfgFile)
    rs = []
    for ip in config["Real Servers"]:
        rs.append(ip_parser(ip))
    if len(rs) == 0:
        raise ValueError ("real server list must not be empty")
    print ("...real servers loaded : {}.".format(ips_tostr(rs)))
    return rs

if config_file is not None:
    try:
        real_server_ips = load_config(config_file)
        config_file_mtime = os.fstat(config_file.fileno()).st_mtime
    except Exception as e:
        print ("Unable to parse {} file : {}".format(config_file.name, e));
        exit()
    finally:
        config_file.close()
else:
    real_server_ips = args.real_server   # list of real servers IP addresses


# Shared structure used for perf_buffer
class Data(ct.Structure):
    _fields_ = [
        ("dmac", ct.c_ubyte * 6),   
        ("smac", ct.c_ubyte * 6),
        ("daddr", ct.c_uint),
        ("saddr", ct.c_uint),
        ("associationType", ct.c_uint)
    ]

# Compile & attach bpf program
print("\nCompiling & attaching bpf code ...")
b = BPF(src_file ="ulb.c", debug=debug)
fn = b.load_func("xdp_prog", BPF.XDP)
b.attach_xdp(ifnet, fn)
print("... compilation and attachement succeed.")


# Set Configurations
## Virtual server config
print("\nApplying config to bpf ...")
virtual_server_map = b.get_table("virtualServer")
virtual_server_map[virtual_server_map.Key(0)] = virtual_server_map.Leaf(virtual_server_ip)
## Ports configs
ports_map = b["ports"]
for port in ports:
    ports_map[ports_map.Key(socket.htons(port))] = ports_map.Leaf(True)
## Real servers configs
real_servers_array = b.get_table("realServersArray")
real_servers_map = b.get_table("realServersMap")

def update_real_server(old_server_ips, new_server_ips):
    """Update 'real server' bpf map content."""
    nbOld = len(old_server_ips)
    nbNew = len(new_server_ips)
    for i in range(max(nbOld, nbNew)):
        if i >= nbOld:
            #addition
            new_server_ip = new_server_ips[i]
            real_servers_map[real_servers_map.Key(new_server_ip)] = real_servers_map.Leaf(new_server_ip)
            real_servers_array[real_servers_array.Key(i)] = real_servers_array.Leaf(new_server_ip)
            print("Add {} at index {}".format(ip_ntostr(new_server_ip), i))
        elif i >= nbNew:
            #deletion
            old_server_ip = old_server_ips[i]
            if old_server_ip in new_server_ips:
                print ("don't remove {} from map".format(ip_ntostr(old_server_ip)))
            else:
                del real_servers_map[real_servers_map.Key(old_server_ip)]
            del real_servers_array[real_servers_array.Key(i)]
            print("delete {} at index {}".format(ip_ntostr(old_server_ip), i))
        else:
            #update
            new_server_ip = new_server_ips[i]
            old_server_ip = old_server_ips[i]
            if new_server_ip == old_server_ip:
                print ("No change for {} at index {}".format(ip_ntostr(new_server_ip), i)) 
            else:            
                real_servers_map[real_servers_map.Key(new_server_ip)] = real_servers_map.Leaf(new_server_ip)
                real_servers_array[real_servers_array.Key(i)] = real_servers_array.Leaf(new_server_ip)
                if old_server_ip in new_server_ips:
                    print ("don't remove {} from map".format(ip_ntostr(old_server_ip)))
                else:
                    del real_servers_map[real_servers_map.Key(old_server_ip)]
                print("Update {} to {} at index {}".format(ip_ntostr(old_server_ip),ip_ntostr(new_server_ip), i))
           
def dump_map():
    """Dump 'real servers' bpf map content."""
    for i,v in real_servers_array.iteritems():
        print ("[{}]={}".format(i.value,ip_ntostr(v)))
    for i,v in real_servers_map.iteritems():
        print ("[{}]={}".format(ip_ntostr(i),ip_ntostr(v)))

update_real_server([], real_server_ips)
dump_map()
print("... config applied to bpf.")

# Started
print("\nLoad balancing UDP traffic over {} interface for port(s) {} from :".format(ifnet, ports, ip_ntostr(virtual_server_ip)))
for real_server_ip in real_server_ips:
    print ("VIP:{} <=======> Real Server:{}".format(ip_ntostr(virtual_server_ip), ip_ntostr(real_server_ip)))

# Utility function to print udp NAT.
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("source {} --> dest {} {}".format(ip_mac_tostr(event.smac, event.saddr),ip_mac_tostr(event.dmac, event.daddr), associationType_tostr(event.associationType)))

# Handle Signal
class Stopper:
  _stop = False
  def __init__(self):
    signal.signal(signal.SIGTERM, self.stop)
    signal.signal(signal.SIGINT, self.stop) # keyboard interruption

  def stop(self,signum, frame):
    print ("\nStopping by signal {}({})...".format(signal.Signals(signum).name, signum));  
    self._stop = True

  def isStopped(self):
    return self._stop

# Program loop
try:
    b["events"].open_perf_buffer(print_event)
    stopper = Stopper()
    while not stopper.isStopped():
        # read and log perf_buffer
        b.perf_buffer_poll(1000)
        # watch if config file changed
        new_mtime = os.stat(config_file.name).st_mtime
        if  new_mtime != config_file_mtime:
            # load real server from config
            new_real_server_ips = None
            try:
                config_file_mtime = new_mtime
                with open(config_file.name) as f:
                    new_real_server_ips = load_config(f)
            except Exception as e:
                print ("Unable to load config {} file : {}".format(config_file.name, e))
                print ("Old Config is keeping : {}".format(ips_tostr(real_server_ips)))

            # if succeed try to update bpf map
            if new_real_server_ips is not None:
                print("Apply new config ...")
                update_real_server(real_server_ips, new_real_server_ips)
                real_server_ips = new_real_server_ips
                dump_map()
                print("... new config applied.")
        # DEBUG STUFF
        #(task, pid, cpu, flags, ts, msg) = b.trace_fields(nonblocking = True)
        #while msg:
        #    print("%s \n" % (msg))
        #    (task, pid, cpu, flags, ts, msg) = b.trace_fields(nonblocking = True)
finally:
    # Detach bpf progam
    print ("Detaching bpf code ...")
    b.remove_xdp(ifnet)
    print ("... code detached.")
    print ("... sbulb stopped.")

