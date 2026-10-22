# -*- coding: utf-8 -*-
"""Rex WiFi Guard — test suite (no network needed for most tests)."""
import unittest, sys, ipaddress
from unittest.mock import patch
from core import wifi_info, devices, speedtest, risk_audit

SAMPLE_NETSH_IF = """There are 2 wireless interfaces on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : MyHomeWiFi
    BSSID                  : aa:bb:cc:11:22:33
    Signal                : 86%
    Channel                : 36
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
"""

class TestWifiInfo(unittest.TestCase):
    def test_parse_status(self):
        with patch.object(wifi_info, "OS", "Windows"), \
             patch.object(wifi_info, "_run", return_value=SAMPLE_NETSH_IF):
            st = wifi_info.get_wifi_status()
        self.assertTrue(st["connected"])
        self.assertEqual(st["ssid"], "MyHomeWiFi")
        self.assertIn("WPA2", st["auth"])
        self.assertEqual(st["signal"], "86%")

    def test_profiles_parse(self):
        sample = "\n    All User Profile : NetOne\n    All User Profile : PTCL-Home\n"
        with patch.object(wifi_info, "OS", "Windows"), \
             patch.object(wifi_info, "_run", return_value=sample):
            names = wifi_info.list_saved_profiles()
        self.assertEqual(names, ["NetOne", "PTCL-Home"])

    def test_password_parse(self):
        sample = "\n    Key Content    : Secret@123\n"
        with patch.object(wifi_info, "OS", "Windows"), \
             patch.object(wifi_info, "_run", return_value=sample):
            self.assertEqual(wifi_info.get_profile_password("X"), "Secret@123")

class TestDevices(unittest.TestCase):
    def test_mac_vendor(self):
        self.assertEqual(devices.mac_vendor("F8:DB:88:11:22:33"), "Dell")
        self.assertEqual(devices.mac_vendor("b4:75:0e:aa:bb:cc"), "Intel")
        self.assertEqual(devices.mac_vendor("00:00:00:00:00:00"), "Unknown")

    def test_subnet(self):
        # local IP → /24 subnet string logic used by scan_network
        ip = "192.168.1.55"
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        net = ipaddress.ip_network(subnet, strict=False)
        self.assertEqual(net.num_addresses, 256)
        self.assertIn(ipaddress.ip_address("192.168.1.55"), list(net.hosts()))

    def test_arp_parse_windows(self):
        sample = """
Interface: 192.168.1.55 --- 0x4
  Internet Address      Physical Address     Type
  192.168.1.1           a0-40-a0-11-22-33    dynamic
  192.168.1.9           f8-db-88-aa-bb-cc    dynamic
"""
        with patch.object(devices, "OS", "Windows"), \
             patch.object(devices, "_run", return_value=sample):
            t = devices.arp_table()
        self.assertEqual(t["192.168.1.1"], "A0:40:A0:11:22:33")
        self.assertEqual(t["192.168.1.9"], "F8:DB:88:AA:BB:CC")

    def test_arp_parse_linux(self):
        sample = """192.168.1.1 dev eth0 lladdr a0:40:a0:11:22:33 STALE
192.168.1.9 dev eth0 lladdr f8:db:88:aa:bb:cc REACHABLE
"""
        with patch.object(devices, "OS", "Linux"), \
             patch.object(devices, "_run", return_value=sample):
            t = devices.arp_table()
        self.assertEqual(t["192.168.1.1"], "A0:40:A0:11:22:33")

class TestQuality(unittest.TestCase):
    def test_grades(self):
        self.assertIn("A+", speedtest.quality_grade(12, 2, 0)[0])
        g, sc = speedtest.quality_grade(200, 50, 30)
        self.assertIn("D", g)

class TestRiskScoring(unittest.TestCase):
    def test_score_bounds(self):
        # simulate failing everything → still 0..100
        st = {"auth": "Open", "connected": True}
        with patch.object(risk_audit, "get_wifi_status", return_value=st), \
             patch.object(risk_audit, "get_gateway", return_value="192.168.1.1"), \
             patch.object(risk_audit, "_port_open", return_value=True):
            r = risk_audit.run_risk_audit()
        self.assertTrue(0 <= r["score"] <= 100)
        self.assertLess(r["score"], 70)  # open network must lose points

    def test_wpa3_best(self):
        st = {"auth": "WPA3-Personal", "connected": True}
        with patch.object(risk_audit, "get_wifi_status", return_value=st), \
             patch.object(risk_audit, "get_gateway", return_value=None):
            r = risk_audit.run_risk_audit()
        self.assertEqual(r["score"], 100)

if __name__ == "__main__":
    unittest.main(verbosity=2, exit=sys.exit(unittest.TextTestRunner().run(unittest.defaultTestLoader.discover(".")).wasSuccessful() or 0))
