import atexit
from bcc import BPF
from builtins import staticmethod
import configparser
import ctypes
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import _IPAddressBase  # @UnusedImport
import ipaddress
import logging
import os
import signal
import socket
import subprocess
from typing import List  # @UnusedImport

from sbulb.util import ip_mac_tostr, ip_strton, ip_ntostr

# Define pythons log level
_log_level_name = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"]
logging.addLevelName(5, "TRACE")  # add TRACE level


@dataclass
class Cfg:
    # network interface to attach xdp program
    ifnet: str = ""
    # virtual server IP address
    virtual_server_ip: _IPAddressBase = None
    # ports to load balanced
    ports: List[int] = field(default_factory=list)
    # list of real server IP addresses
    real_server_ips: List[_IPAddressBase] = field(default_factory=list)
    # Name of file containing list of real servers
    config_file :str = None
    config_file_mtime :int = 0
    # the current ip version used (4 or 6)
    ip_version: int = 4
    # bpf verbosity
    debug: int = 0
    # log level to used
    loglevel: str = "ERROR"
    # maximum number of load balanced port
    max_ports: int = 5
    # maximum number of real servers
    max_realservers: int = 5
    # maximum number of associations
    max_associations: int = 10000

    def validate(self, apply_config_file=False):
        # TODO can we check ifnet exits?
        # check ip version
        if self.ip_version not in (4, 6):
            raise ValueError(
                  "Invalid config : Invalid ip verison {} should be 4 or 6)",
                   self.ip_version)

        # check virtual server
        if self.virtual_server_ip.version is not self.ip_version :
            raise ValueError(
             "Virtual server ip {} seems to be ipv{} address. ipv{} is expected"
             .format(self.virtual_server_ip,
                     self.virtual_server_ip.version,
                     self.ip_version))

        # check real server
        if self.config_file :
            if apply_config_file :
                print ("\nLoading real servers from {} file ..."\
                       .format(self.config_file))
                self.real_server_ips = self.load_real_server()
                # update last load time (see config_file_changed)
                self.config_file_mtime = os.stat(self.config_file).st_mtime
                for s in self.real_server_ips:
                    print("  {}".format(s))
                print ("...real servers loaded.")
            else:
                self.load_real_server()
        else:
            self._check_real_server(self.real_server_ips)

        # check ports
        for p in self.ports:
            if p not in range(0, 65535):
                raise ValueError(
                    "Invalid port {} should be in range 0..65535." \
                    .format(p))

        if len(self.ports) > self.max_ports:
            raise ValueError(
                    "Too many ports, {} ports configured, {} maximum allowed." \
                    .format(len(self.ports), self.max_ports))
        # check debug
        if self.debug not in range(0, 5):
            raise ValueError("Invalid debug value {}, must be between 0..5" \
                             .format(self.debug))

        # check log level
        if self.loglevel not in _log_level_name:
            raise ValueError("Invalid loglevel value {}, must be {}" \
                             .format(self.loglevel, _log_level_name))

    def config_file_changed(self):
        new_mtime = os.stat(self.config_file).st_mtime
        changed = new_mtime != self.config_file_mtime
        self.config_file_mtime = new_mtime
        return changed

    def load_real_server(self):
        config = configparser.ConfigParser(allow_no_value=True,
                                           delimiters=("="))
        with open(self.config_file, 'r') as f :
            config.read_file(f)

        rs = []
        for ip in config["Real Servers"]:
            rs.append(ipaddress.ip_address(ip))
        if len(rs) == 0:
            raise ValueError ("real server list must not be empty")
        self._check_real_server(rs)
        return rs

    def _check_real_server(self, real_servers):
        if len(real_servers) > self.max_realservers:
            raise ValueError("too many real servers, \
                              {} real servers configured,\
                              {} maximum allowed" \
                              .format(len(real_servers),
                                      self.max_realservers))
        for ip in real_servers:
            if ip.version is not  self.ip_version:
                raise ValueError("Real server ip {} seems to be ipv{} address. \
                                  ipv{} is expected".format(ip, ip.version,
                                                            self.ip_version))


class LoadBalancer:
    """An UDP Loadbalancer based on bcc(xdp)"""
    bpf: BPF = None  # bpf pointer
    func = None  # xdp function
    cfg: Cfg = None  # config
    # Bpf Maps
    virtual_server_map = None
    ports_map = None
    real_servers_array = None
    real_servers_map = None

    def __init__(self, cfg:Cfg):
        self.cfg = cfg
        cfg.validate(apply_config_file=True);

        # Build C flags
        cflags = LogCode.toMacros()
        for levelName in _log_level_name:
            cflags.append("-D{}={}".format(levelName,
                                           logging.getLevelName(levelName)))
        cflags.append("-D{}={}".format("LOGLEVEL",
                                       logging.getLevelName(cfg.loglevel)))
        cflags.append("-D{}={}".format("MAX_PORTS", cfg.max_ports))
        cflags.append("-D{}={}".format("MAX_REALSERVERS", cfg.max_realservers))
        cflags.append("-D{}={}".format("MAX_ASSOCIATIONS",
                                        cfg.max_associations))
        if cfg.ip_version is 6:
            cflags.append("-DIPV6=true");

        # Compile bpf program
        print("\nCompiling bpf code & apply config ...")
        print("log level : {}".format(cfg.loglevel))
        print("max ports : {}".format(cfg.max_ports))
        print("max realservers : {}".format(cfg.max_realservers))
        print("max associations : {}".format(cfg.max_associations))
        self.bpf = BPF(src_file=b"sbulb/bpf/loadbalancer.c",
                       debug=cfg.debug, cflags=cflags)
        self.func = self.bpf.load_func(b"xdp_prog", BPF.XDP)

        # Apply config to bpf maps
        self.virtual_server_map = self.bpf[b"virtualServer"]
        self.ports_map = self.bpf[b"ports"]
        self.real_servers_array = self.bpf[b"realServersArray"]
        self.real_servers_map = self.bpf[b"realServersMap"]
        self.virtual_server_map[self.virtual_server_map.Key(0)] = \
            ip_strton(self.cfg.virtual_server_ip)
        for port in self.cfg.ports:
            self.ports_map[ self.ports_map.Key(socket.htons(port))] = \
                    self.ports_map.Leaf(True)
        self._update_real_server([], self.cfg.real_server_ips)

        # Display current map state
        self._dump_real_server_map()
        print("... compilation succeed & configuration applied.")

    def _update_real_server(self, old_server_ips, new_server_ips):
        """Update 'real server' bpf map content."""
        nbOld = len(old_server_ips)
        nbNew = len(new_server_ips)

        for i in range(max(nbOld, nbNew)):
            if i >= nbOld:
                # addition
                new_server_ip = new_server_ips[i]
                new_server_nip = ip_strton(new_server_ip)
                self.real_servers_map[new_server_nip] = new_server_nip
                self.real_servers_array[self.real_servers_array.Key(i)] = \
                    new_server_nip
                print("Add {} at index {}".format(new_server_ip, i))
            elif i >= nbNew:
                # deletion
                old_server_ip = old_server_ips[i]
                if old_server_ip in new_server_ips:
                    print ("don't remove {} from map".format(old_server_ip))
                else:
                    old_server_nip = ip_strton(old_server_ip)
                    del self.real_servers_map[old_server_nip]
                del self.real_servers_array[self.real_servers_array.Key(i)]
                print("delete {} at index {}".format(old_server_ip, i))
            else:
                # update
                new_server_ip = new_server_ips[i]
                old_server_ip = old_server_ips[i]
                if new_server_ip == old_server_ip:
                    print ("No change for {} at index {}" \
                           .format(new_server_ip, i))
                else:
                    new_server_nip = ip_strton(new_server_ip)
                    self.real_servers_map[new_server_nip] = new_server_nip
                    self.real_servers_array[self.real_servers_array.Key(i)] = \
                        new_server_nip
                    if old_server_ip in new_server_ips:
                        print ("don't remove {} from map".format(old_server_ip))
                    else:
                        old_server_nip = ip_strton(old_server_ip)
                        del self.real_servers_map[old_server_nip]
                    print("Update {} to {} at index {}" \
                          .format(old_server_ip, new_server_ip, i))

    def _dump_real_server_map(self):
        """Dump 'real servers' bpf map content."""
        for i, v in self.real_servers_array.iteritems():
            print ("[{}]={}".format(i.value, ip_ntostr(v)))
        for i, v in self.real_servers_map.iteritems():
            print ("[{}]={}".format(ip_ntostr(i), ip_ntostr(v)))

    def attach(self, detach_on_exit=True, notify_systemd=True):
        print("\nAttaching bpf code ...")
        self.bpf.attach_xdp(self.cfg.ifnet, self.func)
        if detach_on_exit:
            atexit.register(self.detach)

        # Support systemd notify services.
        if notify_systemd and 'NOTIFY_SOCKET' in os.environ:
            try:
                subprocess.call("systemd-notify --ready", shell=True)
            except:
                    pass
        print("...bpf code attached.")

    def loop(self):
        print("\nLoop watching logs buffer and config file ...")
        # Program loop
        self._open_log_buffer()
        stopper = Stopper()
        while not stopper.isStopped():
            # read and log perf_buffer
            self.bpf.perf_buffer_poll(1000)
            # watch if config file changed
            if self.cfg.config_file:
                if  self.cfg.config_file_changed():
                    # load real server from config
                    new_real_server_ips = None
                    try:
                        new_real_server_ips = self.cfg.load_real_server()
                    except Exception as e:
                        new_real_server_ips = None
                        print ("Unable to load config {} file : {}"\
                               .format(self.config_file, e))
                        print ("Old Config is keeping : {}".\
                               format(self.cfg.real_server_ips))

                    # if succeed try to update bpf map
                    if new_real_server_ips is not None:
                        print("Apply new config ...")
                        self._update_real_server(self.cfg.real_server_ips,
                                                 new_real_server_ips)
                        self.cfg.real_server_ips = new_real_server_ips
                        self._dump_map()
                        print("... new config applied.")
            # DEBUG STUFF
            # (task, pid, cpu, flags, ts, msg) =
            #     b.trace_fields(nonblocking = True)
            # while msg:
            #    print("%s \n" % (msg))
            #    (task, pid, cpu, flags, ts, msg) =
            #        b.trace_fields(nonblocking = True)
        print("... watching stopped.")

    def _open_log_buffer(self):
        ip_version = self.cfg.ip_version

        # Shared structure used for "logs" perf_buffer
        class LogEvent(ctypes.Structure):
            _fields_ = [
            # code identied the kind of events
                ("code", ctypes.c_uint),
            # old/original packet addresses
                ("odmac", ctypes.c_ubyte * 6),
                ("osmac", ctypes.c_ubyte * 6),
                ("odaddr", ctypes.c_ubyte * 16 if ip_version is 6
                    else ctypes.c_uint),
                ("osaddr", ctypes.c_ubyte * 16 if ip_version is 6
                    else ctypes.c_uint),
            # new/modified packet addresses
                ("ndmac", ctypes.c_ubyte * 6),
                ("nsmac", ctypes.c_ubyte * 6),
                ("ndaddr", ctypes.c_ubyte * 16 if ip_version is 6
                     else ctypes.c_uint),
                ("nsaddr", ctypes.c_ubyte * 16 if ip_version is 6
                    else ctypes.c_uint),
            ]

        # Define Utility function to print log
        def print_event(cpu, data, size):
            event = ctypes.cast(data, ctypes.POINTER(LogEvent)).contents
            LogCode(event.code).log(event, ip_version)

        # Open perf buffer dedicated to logs
        self.bpf["logs"].open_perf_buffer(print_event)

    def detach(self):
        print ("\n Detaching bpf code ...")
        self.bpf.remove_xdp(self.cfg.ifnet)
        print (" ... code detached.")

    def flush_log_buffer(self):
        # read and log perf_buffer
        self.bpf.perf_buffer_poll(1000)


# Handle Signal
class Stopper:
    _stop = False

    def __init__(self):
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)  # keyboard interruption

    def stop(self, signum, frame):  # @UnusedVariable
        print ("\n... stopping by signal {}({}) ..." \
               .format(signal.Signals(signum).name, signum));
        self._stop = True

    def isStopped(self):
        return self._stop


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
    INVALID_ETH_SIZE = "{} <-> {} Invalid size for ethernet packet", \
                        Direction.UNKNOWN, Kind.NOTIP
    NOT_IP_V4 = "{} <-> {} Not IPv4 packet", Direction.UNKNOWN, Kind.NOTIP
    NOT_IP_V6 = "{} <-> {} Not IPv6 packet", Direction.UNKNOWN, Kind.NOTIP
    UNEXPECTED_IPHDR_PARSING_ERR = \
                    "{} <-> {} Unexpected error return by ip header parsing", \
                     Direction.UNKNOWN, Kind.NOTIP

    # UNCHANGED (message with origin address only)
    INVALID_IP_SIZE = "{} <─> {} Invalid size for IP packet", \
                       Direction.UNKNOWN, Kind.UNCHANGED
    TOO_SMALL_IP_HEADER = "{} <─> {} Too small IP header", \
                           Direction.UNKNOWN, Kind.UNCHANGED
    NOT_UDP = "{} <─> {} Not UDP packet", Direction.UNKNOWN, Kind.UNCHANGED
    TOO_BIG_IP_HEADER = "{} <─> {} Too big IP header", \
                         Direction.UNKNOWN, Kind.UNCHANGED
    FRAGMENTED_IP_PACKET = "{} <─> {} Fragmented IP packet", \
                            Direction.UNKNOWN, Kind.UNCHANGED
    INVALID_UDP_SIZE = "{} <─> {} Invalid size for UDP packet", \
                        Direction.UNKNOWN, Kind.UNCHANGED
    NO_VIRTUAL_SERVER = "{} <─> {} No virtual server configured", \
                         Direction.UNKNOWN, Kind.UNCHANGED
    UNHANDLED_TRAFFIC = "{} <─> {} Unhandled traffic", \
                         Direction.UNKNOWN, Kind.UNCHANGED
    LIFETIME_EXPIRED = "{} <-> {} TTL or hoplimit expired", \
                        Direction.UNKNOWN, Kind.UNCHANGED

    INGRESS_NOT_HANDLED_PORT = "{} ──> {} Unhandled port", \
                                Direction.INGRESS, Kind.UNCHANGED
    INGRESS_CANNOT_CREATE_ASSO = "{} ──> {} Unable to create association", \
                                  Direction.INGRESS, Kind.UNCHANGED
    INGRESS_CANNOT_CREATE_ASSO2 = \
                 "{} ──> {} Unable to create association (MUST not happened)", \
                 Direction.INGRESS, Kind.UNCHANGED

    EGRESS_NOT_HANDLED_PORT = "{} <── {} Unhandled port", \
                               Direction.EGRESS, Kind.UNCHANGED
    EGRESS_CANNOT_CREATE_ASSO = "{} <── {} Unable to create association", \
                                Direction.EGRESS, Kind.UNCHANGED
    EGRESS_NOT_AUTHORIZED = "{} <── {} Not associated real server", \
                             Direction.EGRESS, Kind.UNCHANGED

    # NAT (message with origin an destination addresses)
    INGRESS_NEW_NAT = \
                "{} ─┐  {} Destination NAT\n{}  └> {} (NEW ASSOCIATION)", \
                Direction.INGRESS, Kind.NAT
    INGRESS_REUSED_NAT = \
                "{} ─┐  {} Destination NAT\n{}  └> {} (REUSED ASSOCIATION)", \
                 Direction.INGRESS, Kind.NAT

    EGRESS_NEW_NAT = "{}   ┌ {} Source NAT\n{} <─┘ {} (NEW ASSOCIATION)" , \
                      Direction.EGRESS, Kind.NAT
    EGRESS_REUSED_NAT = \
                "{}   ┌ {} Source NAT\n{} <─┘ {} (REUSED ASSOCIATION)", \
                 Direction.EGRESS, Kind.NAT

    def __new__(cls, msg, direction, kind):
        value = len(cls.__members__) + 1
        obj = object.__new__(cls)
        obj._value_ = value
        obj.msg = msg
        obj.direction = direction
        obj.kind = kind
        return obj

    def log(self, event, ip_version):
        """Print log message."""
        mac_ip_str_size = 57 if ip_version is 6 else 33
        if self.kind is Kind.NAT:
            if self.direction is Direction.INGRESS:
                print(self.msg.format(
                    ip_mac_tostr(event.osmac,
                                 event.osaddr).rjust(mac_ip_str_size),
                    ip_mac_tostr(event.odmac,
                                 event.odaddr).ljust(mac_ip_str_size),
                    " "*mac_ip_str_size,
                    ip_mac_tostr(event.ndmac,
                                 event.ndaddr).ljust(mac_ip_str_size)))
            elif self.direction is Direction.EGRESS:
                print(self.msg.format(
                    " "*mac_ip_str_size,
                    ip_mac_tostr(event.osmac,
                                 event.osaddr).ljust(mac_ip_str_size),
                    ip_mac_tostr(event.ndmac,
                                 event.ndaddr).rjust(mac_ip_str_size),
                    ip_mac_tostr(event.nsmac,
                                 event.nsaddr).ljust(mac_ip_str_size)))
            else:
                print("Invalid direction for NAT log event:{}" \
                      .format(self.direction))
        elif self.kind is Kind.UNCHANGED:
            if self.direction is Direction.INGRESS \
            or self.direction is Direction.UNKNOWN :
                print(self.msg.format(
                     ip_mac_tostr(event.osmac,
                                  event.osaddr).rjust(mac_ip_str_size),
                     ip_mac_tostr(event.odmac,
                                  event.odaddr).ljust(mac_ip_str_size)))
            elif self.direction is Direction.EGRESS:
                print(self.msg.format(
                     ip_mac_tostr(event.odmac,
                                  event.odaddr).rjust(mac_ip_str_size),
                     ip_mac_tostr(event.osmac,
                                  event.osaddr).ljust(mac_ip_str_size)))
            else:
                print("Invalid direction of UNCHANGED log event : {}" \
                      .format(self.direction))
        elif self.kind is Kind.NOTIP:
            if self.direction is Direction.UNKNOWN:
                print(self.msg.format(
                    " "*mac_ip_str_size,
                    " "*mac_ip_str_size))
            else:
                print("Invalid direction of NOT IP log event : {}"\
                      .format(self.direction))
        else:
            print("Invalid kind of log event : {}".format(self.kind))

    @staticmethod
    def toMacros():
        """Export all logCode as C macro list."""
        macros = []
        for code in LogCode:
            macros.append("-D{}={}".format(code.name, code.value))
        return macros
