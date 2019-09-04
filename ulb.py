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
from enum import Enum
import logging

# Define pythons log level
logLevelNames = ["CRITICAL","ERROR","WARNING","INFO","DEBUG","TRACE"]
logging.addLevelName(5, "TRACE") # add TRACE level

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

def ips_tostr(ips):
    return ", ".join(map(ip_ntostr, ips))

# Custom argument parser
def ip_parser(s):
    try:
        return ip_strton(s)
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid IP address '{}' : {}".format(s, str(e)))

def positive_int(s):
    if not s.isdigit():
        raise argparse.ArgumentTypeError("{} is not a valid positive int".format(s))
    try:
        i = int(s)
    except Exception as e:
        raise argparse.ArgumentTypeError("{} is not a valid positive int : {}".format(s,str(e)))
    if i < 0:
        raise argparse.ArgumentTypeError("{} is not a valid positive int".format(s))
    # TODO It is not clear what is current mapsize limit for map allowed by BPF.
    # so for now just check it is an unsigned int...
    max_long_value = ct.c_uint(-1)
    if i > max_long_value.value :
        raise argparse.ArgumentTypeError("{} is not a valid positive int, max value is {}".format(s, max_long_value.value))

    return i

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
parser.add_argument("-l", "--loglevel", choices=logLevelNames, help="Use to set logging verbosity.", default="ERROR")
parser.add_argument("-mp", "--max_ports", type=positive_int, help="Set the maximum number of port to load balance.", default=16)
parser.add_argument("-mrs", "--max_realservers", type=positive_int, help="Set the maximum number of real servers.", default=32)
parser.add_argument("-ma", "--max_associations", type=positive_int, help="Set the maximum number of associations,\nmeaning the number of foreign peers supported at the same time.", default=1048576)
args = parser.parse_args()

# Get configuration from Arguments
ifnet = args.ifnet                       # network interface to attach xdp program
virtual_server_ip = args.virtual_server  # virtual server IP address
ports = args.port                        # ports to load balance
debug = args.debug                       # bpf verbosity
loglevel = args.loglevel                 # log level to used
max_ports = args.max_ports               # maximum number of load balanced port (Virtual server ports)
max_realservers = args.max_realservers   # maximum number of real servers
max_associations = args.max_associations # maximum number of associations

real_server_ips = []                     # list of real server IP addresses
config_file = args.config_file           # config file containing real server IP address list
config_file_mtime = 0                    # last modification time of config file

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

# Define log code constant
class Direction(Enum):
    INGRESS = 1,
    EGRESS = 2,
    UNKNOWN = 3,
class Kind(Enum):
    NOTIP = 1,
    UNCHANGED = 2,
    NAT = 3,
class LogCode(Enum):
    # NOT IP (message with out address) 
    INVALID_ETH_SIZE            = "{} <-> {} Invalid size for ethernet packet", Direction.UNKNOWN, Kind.NOTIP
    NOT_IP_V4                   = "{} <-> {} Not IPv4 packet", Direction.UNKNOWN, Kind.NOTIP

    # UNCHANGED (message with origin address only)
    INVALID_IP_SIZE             = "{} <─> {} Invalid size for IP packet", Direction.UNKNOWN, Kind.UNCHANGED
    TOO_SMALL_IP_HEADER         = "{} <─> {} Too small IP header", Direction.UNKNOWN, Kind.UNCHANGED
    NOT_UDP                     = "{} <─> {} Not UDP packet", Direction.UNKNOWN, Kind.UNCHANGED
    TOO_BIG_IP_HEADER           = "{} <─> {} Too big IP header", Direction.UNKNOWN, Kind.UNCHANGED
    FRAGMENTED_IP_PACKET        = "{} <─> {} Fragmented IP packet", Direction.UNKNOWN, Kind.UNCHANGED
    INVALID_UDP_SIZE            = "{} <─> {} Invalid size for UDP packet", Direction.UNKNOWN, Kind.UNCHANGED
    NO_VIRTUAL_SERVER           = "{} <─> {} No virtual server configured", Direction.UNKNOWN, Kind.UNCHANGED
    UNHANDLED_TRAFFIC           = "{} <─> {} Unhandled traffic", Direction.UNKNOWN, Kind.UNCHANGED
    
    INGRESS_NOT_HANDLED_PORT    = "{} ──> {} Unhandled port", Direction.INGRESS, Kind.UNCHANGED
    INGRESS_CANNOT_CREATE_ASSO  = "{} ──> {} Unable to create association", Direction.INGRESS, Kind.UNCHANGED
    INGRESS_CANNOT_CREATE_ASSO2 = "{} ──> {} Unable to create association (MUST not happened", Direction.INGRESS, Kind.UNCHANGED

    EGRESS_NOT_HANDLED_PORT     = "{} <── {} Unhandled port", Direction.EGRESS, Kind.UNCHANGED
    EGRESS_CANNOT_CREATE_ASSO   = "{} <── {} Unable to create association", Direction.EGRESS, Kind.UNCHANGED
    EGRESS_NOT_AUTHORIZED       = "{} <── {} Not associated real server", Direction.EGRESS, Kind.UNCHANGED

    # NAT (message with origin an destination addresses)
    INGRESS_NEW_NAT             = "{} ─┐  {} Destination NAT\n{}  └> {} (NEW ASSOCIATION)", Direction.INGRESS, Kind.NAT
    INGRESS_REUSED_NAT          = "{} ─┐  {} Destination NAT\n{}  └> {} (REUSED ASSOCIATION)", Direction.INGRESS, Kind.NAT

    EGRESS_NEW_NAT              = "{}   ┌ {} Source NAT\n{} <─┘ {} (NEW ASSOCIATION)", Direction.EGRESS, Kind.NAT
    EGRESS_REUSED_NAT           = "{}   ┌ {} Source NAT\n{} <─┘ {} (REUSED ASSOCIATION)", Direction.EGRESS, Kind.NAT

    def __new__(cls, msg, direction, kind):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value
        obj.msg = msg
        obj.direction = direction
        obj.kind = kind
        return obj

    def log(self, event):
        """Print log message."""
        mac_ip_str_size = 33
        if self.kind is Kind.NAT:
            if self.direction is Direction.INGRESS:
                print(self.msg.format(
                    ip_mac_tostr(event.osmac, event.osaddr).rjust(mac_ip_str_size),
                    ip_mac_tostr(event.odmac, event.odaddr).ljust(mac_ip_str_size),
                    " "*mac_ip_str_size,
                    ip_mac_tostr(event.ndmac, event.ndaddr).ljust(mac_ip_str_size)))
            elif self.direction is Direction.EGRESS:
                print(self.msg.format(
                    " "*mac_ip_str_size,
                    ip_mac_tostr(event.osmac, event.osaddr).ljust(mac_ip_str_size),
                    ip_mac_tostr(event.ndmac, event.ndaddr).rjust(mac_ip_str_size),
                    ip_mac_tostr(event.nsmac, event.nsaddr).ljust(mac_ip_str_size)))
            else:
                print("Invalid direction for NAT log event:{}".format(self.direction))
        elif self.kind is Kind.UNCHANGED:
            if self.direction is Direction.INGRESS or self.direction is Direction.UNKNOWN :
                print(self.msg.format(
                     ip_mac_tostr(event.osmac, event.osaddr).rjust(mac_ip_str_size),
                     ip_mac_tostr(event.odmac, event.odaddr).ljust(mac_ip_str_size)))
            elif self.direction is Direction.EGRESS:
                print(self.msg.format(
                     ip_mac_tostr(event.odmac, event.odaddr).rjust(mac_ip_str_size),
                     ip_mac_tostr(event.osmac, event.osaddr).ljust(mac_ip_str_size)))
            else:
                print("Invalid direction of UNCHANGED log event : {}".format(self.direction))
        elif self.kind is Kind.NOTIP:
            if self.direction is Direction.UNKNOWN:
                print(self.msg.format(
                    " "*mac_ip_str_size,
                    " "*mac_ip_str_size))
            else:
                print("Invalid direction of NOT IP log event : {}".format(self.direction))
        else:
            print("Invalid kind of log event : {}".format(self.kind))
            
    def toMacros():
        """Export all logCode as C macro list."""
        macros = []
        for code in LogCode:
            macros.append("-D{}={}".format(code.name, code.value))
        return macros

# Check Config
if len(ports) > max_ports:
    print ("\nInconsistent config : too many ports, {} ports configured, {} maximum allowed.\nSee option -mp.".format(len(ports), max_ports))
    exit()
if len(real_server_ips) > max_realservers:
    print ("\nInconsistent config : too many real servers, {} real servers configured, {} maximum allowed.\nSee option -mrs.".format(len(real_server_ips), max_realservers))
    exit()

# Build C flags
cflags = LogCode.toMacros()
for levelName in logLevelNames:
    cflags.append("-D{}={}".format(levelName, logging.getLevelName(levelName)))
cflags.append("-D{}={}".format("LOGLEVEL", loglevel))
cflags.append("-D{}={}".format("MAX_PORTS", max_ports))
cflags.append("-D{}={}".format("MAX_REALSERVERS", max_realservers))
cflags.append("-D{}={}".format("MAX_ASSOCIATIONS", max_associations))

# Compile & attach bpf program
print("\nCompiling & attaching bpf code ...")
print("log level : {}".format(loglevel))
print("max ports : {}".format(max_ports))
print("max realservers : {}".format(max_realservers))
print("max associations : {}".format(max_associations))
print("\nCompiling & attaching bpf code ...")
b = BPF(src_file ="ulb.c", debug=debug, cflags=cflags)
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
print("\nLoad balancing UDP traffic over {} interface for port(s) {} :".format(ifnet, ports, ip_ntostr(virtual_server_ip)))
ip_str_size = 15
print("{}           {}".format("Virtual Server".rjust(ip_str_size),"Real Server(s)".ljust(ip_str_size)))
if len(real_server_ips) == 1:
    print ("{} <───────> {}\n".format(ip_ntostr(virtual_server_ip).rjust(ip_str_size), ip_ntostr(real_server_ips[0]).ljust(ip_str_size)))
elif len(real_server_ips) > 1:
    print ("{} <───┬───> {}".format(ip_ntostr(virtual_server_ip).rjust(ip_str_size), ip_ntostr(real_server_ips[0]).ljust(ip_str_size)))
    for n in range(1,len(real_server_ips)-1):    
        print ("{}     ├───> {}".format(" " * ip_str_size, ip_ntostr(real_server_ips[n]).ljust(ip_str_size)))
    print ("{}     └───> {}\n".format(" " * ip_str_size, ip_ntostr(real_server_ips[-1]).ljust(ip_str_size)))
# Shared structure used for "logs" perf_buffer
class LogEvent(ct.Structure):
    _fields_ = [
	# code identied the kind of events
        ("code", ct.c_uint),
	# old/original packet addresses
        ("odmac", ct.c_ubyte * 6),   
        ("osmac", ct.c_ubyte * 6),
        ("odaddr", ct.c_uint),
        ("osaddr", ct.c_uint),
	# new/modified packet addresses
        ("ndmac", ct.c_ubyte * 6),   
        ("nsmac", ct.c_ubyte * 6),
        ("ndaddr", ct.c_uint),
        ("nsaddr", ct.c_uint),
    ]
        
# Utility function to print log
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(LogEvent)).contents
    LogCode(event.code).log(event)

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
    b["logs"].open_perf_buffer(print_event)
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
                    if len(new_real_server_ips) > max_realservers:
                        raise ValueError("too many real servers, {} real servers configured, {} maximum allowed".format(len(new_real_server_ips), max_realservers))
            except Exception as e:
                new_real_server_ips = None
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

