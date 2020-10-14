#!/usr/bin/python

import argparse
import ctypes
import ipaddress
from sbulb import Cfg, LoadBalancer


# Custom argument parser
def ip_parser(s):
    try:
        return ipaddress.ip_address(s)
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid IP address '{}' : {}" \
                                         .format(s, str(e)))


def positive_int(s):
    if not s.isdigit():
        raise argparse.ArgumentTypeError("{} is not a valid positive int" \
                                         .format(s))
    try:
        i = int(s)
    except Exception as e:
        raise argparse.ArgumentTypeError("{} is not a valid positive int : {}" \
                                         .format(s, str(e)))
    if i < 0:
        raise argparse.ArgumentTypeError("{} is not a valid positive int" \
                                         .format(s))
    # TODO It is not clear what is current mapsize limit for map allowed by BPF.
    # so for now just check it is an unsigned int...
    max_long_value = ctypes.c_uint(-1)
    if i > max_long_value.value :
        raise argparse.ArgumentTypeError(\
                "{} is not a valid positive int, max value is {}"\
                .format(s, max_long_value.value))
    return i


# Parse Arguments
parser = argparse.ArgumentParser(prog="sbulb",
                                 formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument("ifnet",
  help="network interface to load balance (e.g. eth0)")
parser.add_argument("-vs", "--virtual_server", type=ip_parser, required=True,
  help="<Required> Virtual server address (e.g. 10.40.0.1)")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-rs", "--real_server", type=ip_parser, nargs='+',
  help="<Required> Real server address(es) (e.g. 10.40.0.2 10.40.0.3)")
group.add_argument("-cfg", "--config_file", type=argparse.FileType('r'),
  help='''<Required> a path to a file containing real server address(es). 
File will be polled each second for modification and configuration
updated dynamically. A file content example :

[Real Servers]
10.0.0.4
10.0.0.2
10.0.0.6

''')
parser.add_argument("-p", "--port", type=int, nargs='+', required=True,
  help="<Required> UDP port(s) to load balance")
parser.add_argument("-d", "--debug", type=int,
  choices=[0, 1, 2, 3, 4], default=0,
  help="Use to set bpf verbosity, 0 is minimal. (default: %(default)s)")
parser.add_argument("-l", "--loglevel", default="ERROR",
  choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"],
  help="Use to set logging verbosity. (default: %(default)s)")
parser.add_argument("-mp", "--max_ports", type=positive_int, default=16,
  help="Set the maximum number of port to load balance. (default: %(default)s)")
parser.add_argument("-mrs", "--max_realservers", type=positive_int, default=32,
  help="Set the maximum number of real servers. (default: %(default)s)")
parser.add_argument("-ma", "--max_associations",
  type=positive_int, default=1048576,
  help="Set the maximum number of associations. (default: %(default)s)\n\
This defined the maximum number of foreign peers supported at the same time.")

args = parser.parse_args()

# Get configuration from Arguments
cfg = Cfg();
cfg.ifnet = args.ifnet
cfg.virtual_server_ip = args.virtual_server
cfg.ip_version = cfg.virtual_server_ip.version
cfg.ports = args.port
cfg.debug = args.debug
cfg.loglevel = args.loglevel
cfg.max_ports = args.max_ports
cfg.max_realservers = args.max_realservers
cfg.max_associations = args.max_associations
cfg.real_server_ips = args.real_server
if args.config_file:
    cfg.config_file = args.config_file.name

try:
    cfg.validate()
except ValueError as e:
    print("Invalid argument : {}".format(e))
    exit()

# Create load balancer
loadbalancer = LoadBalancer(cfg);

# Attach it to XDP
loadbalancer.attach()

# Launch it
loadbalancer.loop()
