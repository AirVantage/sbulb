import unittest

from sbulb.tests.test_config import ConfigTestCase
from sbulb.tests.test_loadbalancer import IPv4TestCase
from sbulb.tests.test_loadbalancer import IPv6TestCase


def suite():
    suite = unittest.TestSuite()
    suite.addTest(ConfigTestCase())
    suite.addTest(IPv4TestCase())
    suite.addTest(IPv6TestCase())
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suite())
