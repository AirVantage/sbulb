import ipaddress
import socket
import ctypes as ct


# Utils
def ip_strton(ip_address):
    addr = ipaddress.ip_address(ip_address)
    if addr.version == 4:
        return ct.c_uint(socket.htonl((int) (addr)))
    else:
        return (ct.c_ubyte * 16)(*list(addr.packed))


def ip_ntostr(ip_address):
    # handle ipv4
    if isinstance(ip_address, ct.c_uint):
        ip_address = ip_address.value;
    if isinstance(ip_address, int):
        return str(ipaddress.IPv4Address(socket.ntohl(ip_address)))
    # handle ipv6
    if "in6_addr" in str(type(ip_address)):
        ip_address = ip_address.in6_u.u6_addr8
    if isinstance(ip_address, ct.c_ubyte * 16):
        ip_address = bytes(bytearray(ip_address))
        return str(ipaddress.IPv6Address(ip_address))


def ipversion(ip_address):
    if isinstance(ip_address, ct.c_uint):
        return 4
    if isinstance(ip_address, ct.c_ubyte * 16):
        return 6
    raise ValueError("unable to guess ip version of {} (type{})".format(ip_address, type(ip_address)))


def mac_btostr(mac_address):
    bytestr = bytes(mac_address).hex()
    return ':'.join(bytestr[i:i + 2] for i in range(0, 12, 2))


def ip_mac_tostr(mac_address, ip_address):
    return "{}/{}".format(mac_btostr(mac_address), ip_ntostr(ip_address))


def ips_tostr(ips):
    return ", ".join(map(ip_ntostr, ips))


def ips_ton(ips):
    return map(ip_strton, ips)
