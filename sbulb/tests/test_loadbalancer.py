from abc import ABC, abstractmethod
import ipaddress
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
import unittest

from sbulb import Cfg, LoadBalancer
from sbulb.tests.test_util import run_test, assert_dropped, \
    assert_redirect_from_real_server_ipv6, assert_redirect_to_real_server_ipv6, \
    assert_redirect_from_real_server_ipv4, assert_redirect_to_real_server_ipv4


class AbstractTestCase(ABC):
    load_balancer = None
    ports = [5683]

    # defined in subclasses :
    cli_ip = []  # client IP addresses
    vs_ip = None  # virtual server IP address
    rs_ip = []  # real servers IP addresses
    IP  # class used to create IP layer

    def setUp(self):
        cfg = Cfg();
        cfg.ifnet = "test"
        cfg.loglevel = "DEBUG"
        cfg.max_associations = 4
        cfg.virtual_server_ip = ipaddress.ip_address(self.vs_ip)
        cfg.ip_version = cfg.virtual_server_ip.version
        cfg.ports = self.ports
        cfg.real_server_ips = [ipaddress.ip_address(self.rs_ip[0]), \
                               ipaddress.ip_address(self.rs_ip[1])]

        self.load_balancer = LoadBalancer(cfg)
        self.load_balancer._open_log_buffer()

    def tearDown(self):
        self.load_balancer.flush_log_buffer()
        unittest.TestCase.tearDown(self)

    @abstractmethod
    def assert_redirect_from_real_server(self):
        ...

    @abstractmethod
    def assert_redirect_to_real_server(self):
        ...

    def test_client_initiated(self):
        # from client 0  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 0  STILL associated to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # answer to client 0 from real server 0
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[0], dst=self.cli_ip[0]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_from_real_server(self.vs_ip, packet_in, res)

        # server initiated from real server 1 to client 0 : dropped
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[1], dst=self.cli_ip[0]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        assert_dropped(self, res)

    def test_server_initiated(self):
        # from server 1  associating to client 0
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[1], dst=self.cli_ip[0]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_from_real_server(self.vs_ip, packet_in, res)

        # from server 1  STILL associated to client 0
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[1], dst=self.cli_ip[0]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_from_real_server(self.vs_ip, packet_in, res)

        # server initiated from real server 0 to client 0 : dropped
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[0], dst=self.cli_ip[0]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        assert_dropped(self, res)

        # from client 0  associated to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

    def test_round_robin(self):
        # from client 0  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 1  associating to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[1], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

        # from client 2  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[2], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 3  associating to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[3], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

    def test_round_robin_sameip(self):
        # from client 0  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(sport=1000, dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 1  associating to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(sport=1001, dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

        # from client 2  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(sport=1003, dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 3  associating to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(sport=1004, dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

    def test_remove_first_real_server(self):
        # from client 0  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # server initiated from real server 1 to client 0 : dropped
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[1], dst=self.cli_ip[0]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        assert_dropped(self, res)

        # remove real server 0
        self.load_balancer.flush_log_buffer()
        self.load_balancer._update_real_server(
                self.load_balancer.cfg.real_server_ips,
                self.load_balancer.cfg.real_server_ips[1:])

        # from server 1  associating to client 0
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[1], dst=self.cli_ip[0]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_from_real_server(self.vs_ip, packet_in, res)

    def test_remove_last_real_server(self):
        # from client 0  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 1  associating to real server 2
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[1], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

        # server initiated from real server 0 to client 1 : dropped
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[0], dst=self.cli_ip[1]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        assert_dropped(self, res)

        # remove real server 0
        self.load_balancer.flush_log_buffer()
        self.load_balancer._update_real_server(
                self.load_balancer.cfg.real_server_ips,
                self.load_balancer.cfg.real_server_ips[:1])

        # from server 0  associating to client 1
        packet_in = Ether() \
                    / self.IP(src=self.rs_ip[0], dst=self.cli_ip[1]) \
                    / UDP(sport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_from_real_server(self.vs_ip, packet_in, res)

    def test_add_real_server(self):
        # from client 0  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 1  associating to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[1], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

        # add real server
        self.load_balancer.flush_log_buffer()
        new_rs_ips = self.load_balancer.cfg.real_server_ips.copy()
        new_rs_ips.append(ipaddress.ip_address(self.rs_ip[2]))
        self.load_balancer._update_real_server(
                self.load_balancer.cfg.real_server_ips, new_rs_ips)

        # from client 2  associating to real server 2
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[2], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[2], packet_in, res)

    def test_update_real_server(self):
        # from client 0  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 1  associating to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[1], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

        # add real server
        self.load_balancer.flush_log_buffer()
        new_rs_ips = self.load_balancer.cfg.real_server_ips.copy()
        new_rs_ips[0] = ipaddress.ip_address(self.rs_ip[2])
        new_rs_ips[1] = ipaddress.ip_address(self.rs_ip[3])
        self.load_balancer._update_real_server(
                self.load_balancer.cfg.real_server_ips, new_rs_ips)

        # from client 0  associating to real server 2
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[2], packet_in, res)

        # from client 0  associating to real server 3
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[1], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[3], packet_in, res)

    def test_lru(self):
        # test is configure with 4 association maximum
        # from client 0  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 1  associating to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[1], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

        # from client 2  associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[2], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 3  associating to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[3], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

        # from client 0  still associated to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[0], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 1  still associated to real server 1
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[1], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)

        # from client 4 associating to real server 0
        packet_in = Ether() \
                    / self.IP(src=self.cli_ip[4], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[0], packet_in, res)

        # from client 2 lost its association with 0 (least recently used)
        # and should now be associating to real server 1
        packet_in = Ether() \
                    / self. IP(src=self.cli_ip[2], dst=self.vs_ip) \
                    / UDP(dport=self.ports[0])
        res = run_test(self, self.load_balancer.func, packet_in)
        self.assert_redirect_to_real_server(self.rs_ip[1], packet_in, res)


class IPv6TestCase(AbstractTestCase, unittest.TestCase):
    # client IP addresses
    cli_ip = ["5555:0000:0000:0000:0000:0000:0000:0001",
              "5555:0000:0000:0000:0000:0000:0000:0002",
              "5555:0000:0000:0000:0000:0000:0000:0003",
              "5555:0000:0000:0000:0000:0000:0000:0004",
              "5555:0000:0000:0000:0000:0000:0000:0005"]
    # virtual server IP address
    vs_ip = "1111:0000:0000:0000:0000:0000:0000:0001"
    # real servers IP addresses
    rs_ip = ["4444:0000:0000:0000:0000:0000:0000:0001",
             "4444:0000:0000:0000:0000:0000:0000:0002",
             "4444:0000:0000:0000:0000:0000:0000:0003",
             "4444:0000:0000:0000:0000:0000:0000:0004"]
    # class used to create IP layer
    IP = IPv6

    def assert_redirect_from_real_server(self, virtual_server_ip,
                                         packet_in, result):
        assert_redirect_from_real_server_ipv6(self, virtual_server_ip,
                                              packet_in, result)

    def assert_redirect_to_real_server(self, real_server_ip,
                                         packet_in, result):
        assert_redirect_to_real_server_ipv6(self, real_server_ip,
                                            packet_in, result)


class IPv4TestCase(AbstractTestCase, unittest.TestCase):
    # client IP addresses
    cli_ip = ["55.0.0.1", "55.0.0.2", "55.0.0.3", "55.0.0.4", "55.0.0.5"]
    # virtual server IP address
    vs_ip = "11.0.0.1"
    # real servers IP addresses
    rs_ip = ["44.0.0.1", "44.0.0.2", "44.0.0.3", "44.0.0.4"]
    # class used to create IP layer
    IP = IP

    def assert_redirect_from_real_server(self, virtual_server_ip,
                                         packet_in, result):
        assert_redirect_from_real_server_ipv4(self, virtual_server_ip,
                                              packet_in, result)

    def assert_redirect_to_real_server(self, real_server_ip,
                                         packet_in, result):
        assert_redirect_to_real_server_ipv4(self, real_server_ip,
                                            packet_in, result)


if __name__ == '__main__':
    unittest.main()
