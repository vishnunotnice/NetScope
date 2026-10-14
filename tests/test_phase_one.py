import ipaddress
import unittest

from netscope.nmap import command_for, parse_xml
from netscope.targets import TargetPolicy, TargetValidationError


XML = """<nmaprun><host><status state='up'/><address addr='192.168.1.10' addrtype='ipv4'/><address addr='AA:BB:CC:DD:EE:FF' addrtype='mac' vendor='Example'/><hostnames><hostname name='router.local'/></hostnames><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https' product='Example HTTPS' version='1.2'/></port></ports><os><osmatch name='Linux' accuracy='92'><osclass name='Linux'/></osmatch></os></host></nmaprun>"""


class PhaseOneTests(unittest.TestCase):
    def test_target_policy_rejects_oversized_ranges(self):
        with self.assertRaises(TargetValidationError):
            TargetPolicy(max_addresses=4).validate("10.0.0.0/29")

    def test_target_policy_enforces_allowlist(self):
        with self.assertRaises(TargetValidationError):
            TargetPolicy(allowlist=(ipaddress.ip_network("192.168.0.0/24"),)).validate("10.0.0.5")

    def test_parse_nmap_xml_extracts_host_service_and_os(self):
        result = parse_xml(XML, target="192.168.1.10", profile="os")
        host = result.hosts[0]
        self.assertEqual(host.address, "192.168.1.10")
        self.assertEqual(host.hostname, "router.local")
        self.assertEqual(host.services[0].product, "Example HTTPS")
        self.assertEqual(host.os_name, "Linux")
        self.assertEqual(host.os_accuracy, 92)

    def test_command_is_argument_safe(self):
        command = command_for("192.168.1.0/24", "quick")
        self.assertEqual(command[-1], "192.168.1.0/24")
        self.assertTrue(all(";" not in item and "&&" not in item for item in command))


if __name__ == "__main__":
    unittest.main()
