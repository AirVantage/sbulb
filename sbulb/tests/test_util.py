from bcc import libbcc, BPF
import ctypes
from dataclasses import dataclass
from scapy.compat import raw
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet


def assert_redirect_to_real_server_ipv4(test, real_server_ip,
                                        packet_in, result):
    test.assertEqual(BPF.XDP_TX, result.retval)
    # client -> virtual server
    # become
    # client -> given real server
    expected = packet_in.copy()
    expected[Ether].dst = packet_in[Ether].src
    expected[Ether].src = packet_in[Ether].dst
    expected[IP].dst = real_server_ip
    expected[IP].ttl = packet_in[IP].ttl - 1
    # force checksum calculation
    del expected[IP].chksum
    del expected[UDP].chksum
    expected = Ether(raw(expected))

    test.assertEqual(expected, result.packet)


def assert_redirect_to_real_server_ipv6(test, real_server_ip,
                                        packet_in, result):
    test.assertEqual(BPF.XDP_TX, result.retval)
    # client -> virtual server
    # become
    # client -> given real server
    expected = packet_in.copy()
    expected[Ether].dst = packet_in[Ether].src
    expected[Ether].src = packet_in[Ether].dst
    expected[IPv6].dst = real_server_ip
    expected[IPv6].hlim = packet_in[IPv6].hlim - 1
    # force checksum calculation
    del expected[UDP].chksum
    expected = Ether(raw(expected))

    test.assertEqual(expected, result.packet)


def assert_redirect_from_real_server_ipv4(test, virtual_server_ip,
                                          packet_in, result):
    test.assertEqual(BPF.XDP_TX, result.retval)

    # real server -> client
    # become
    # virtual server -> client
    expected = packet_in.copy()
    expected[Ether].dst = packet_in[Ether].src
    expected[Ether].src = packet_in[Ether].dst
    expected[IP].src = virtual_server_ip
    expected[IP].ttl = packet_in[IP].ttl - 1
    # force checksum calculation
    del expected[IP].chksum
    del expected[UDP].chksum
    expected = Ether(raw(expected))

    test.assertEqual(expected, result.packet)


def assert_redirect_from_real_server_ipv6(test, virtual_server_ip,
                                          packet_in, result):
    test.assertEqual(BPF.XDP_TX, result.retval)

    # real server -> client
    # become
    # virtual server -> client
    expected = packet_in.copy()
    expected[Ether].dst = packet_in[Ether].src
    expected[Ether].src = packet_in[Ether].dst
    expected[IPv6].src = virtual_server_ip
    expected[IPv6].hlim = packet_in[IPv6].hlim - 1
    # force checksum calculation
    del expected[UDP].chksum
    expected = Ether(raw(expected))

    test.assertEqual(expected, result.packet)


def assert_dropped(test, result):
    test.assertEqual(BPF.XDP_DROP, result.retval)


def run_test(test, func, data, data_out_len=1514):
    size = len(data)
    data = ctypes.create_string_buffer(raw(data), size)
    data_out = ctypes.create_string_buffer(data_out_len)
    size_out = ctypes.c_uint32()
    retval = ctypes.c_uint32()
    duration = ctypes.c_uint32()
    repeat = 1

    ret = libbcc.lib.bpf_prog_test_run(func.fd, repeat,
                                       ctypes.byref(data), size,
                                       ctypes.byref(data_out),
                                       ctypes.byref(size_out),
                                       ctypes.byref(retval),
                                       ctypes.byref(duration))
    test.assertEqual(ret, 0)

    return Result(retval.value, Ether(data_out[:size_out.value]))


@dataclass
class Result:
    retval: ctypes.c_int32
    packet: Packet
