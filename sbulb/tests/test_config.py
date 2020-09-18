from ipaddress import IPv6Address, IPv4Address
import ipaddress
import unittest

from sbulb import Cfg


class ConfigTestCase(unittest.TestCase):

    def test_ipv4(self):
        cfg = Cfg();
        cfg.ifnet = "test"
        cfg.virtual_server_ip = ipaddress.ip_address("10.0.0.1")
        cfg.ip_version = cfg.virtual_server_ip.version
        cfg.ports = [5683]
        cfg.config_file = "./sbulb/tests/ipv4.cfg"

        self.assertEqual([], cfg.real_server_ips)
        cfg.validate(True);
        self.assertEqual(2, len(cfg.real_server_ips))

        servers = cfg.load_real_server();
        self.assertEqual(cfg.real_server_ips, servers)
        self.assertTrue(
            all((type(s) is IPv4Address) for s in servers))

        self.assertFalse(cfg.config_file_changed())

    def test_ipv6(self):
        cfg = Cfg();
        cfg.ifnet = "test"
        cfg.virtual_server_ip = ipaddress.ip_address(\
                                "2222:0000:0000:0000:0000:0000:0000:0001")
        cfg.ip_version = cfg.virtual_server_ip.version
        cfg.ports = [5683]
        cfg.config_file = "./sbulb/tests/ipv6.cfg"

        self.assertEqual([], cfg.real_server_ips)
        cfg.validate(True);
        self.assertEqual(3, len(cfg.real_server_ips))

        servers = cfg.load_real_server();
        self.assertEqual(cfg.real_server_ips, servers)
        self.assertTrue(
            all((type(s) is IPv6Address) for s in servers))

        self.assertFalse(cfg.config_file_changed())


if __name__ == '__main__':
    unittest.main()
