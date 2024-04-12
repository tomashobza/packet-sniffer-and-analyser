#!/usr/bin/env python3

import unittest
import subprocess
import os
import time


class TestIPKSniffer(unittest.TestCase):
    def setUp(self):
        # Ensure the ipk-sniffer binary is executable and exists
        self.sniffer_path = "./ipk-sniffer"
        self.assertTrue(os.path.isfile(self.sniffer_path))
        os.chmod(self.sniffer_path, 0o755)

        # Define a network interface for testing
        self.interface = "eth0"  # Change to your testing interface

    def get_network_interfaces(self):
        # This method obtains a list of active network interfaces to be used for validation
        # Adjust the method used to list interfaces based on your system/environment
        # For Unix/Linux, you might parse the output of "ip link show" or "ifconfig -a"
        completed_process = subprocess.run(
            ["ip", "link", "show"], capture_output=True, text=True
        )
        interfaces = [
            line.split(":")[1].strip()
            for line in completed_process.stdout.split("\n")
            if ": " in line and "lo" not in line
        ]
        return interfaces

    def test_help_option(self):
        # Test if the help/usage message is displayed
        completed_process = subprocess.run(
            [self.sniffer_path, "-h"], capture_output=True, text=True
        )
        self.assertIn("usage", completed_process.stdout.lower())

    def test_without_interface_specified(self):
        # Test if a list of active interfaces is printed when no interface is specified
        completed_process = subprocess.run(
            [self.sniffer_path], capture_output=True, text=True
        )
        # Check if the output contains at least one of the known interfaces
        output = completed_process.stdout
        if (
            not self.known_interfaces
        ):  # If no interfaces could be determined, skip this test
            self.skipTest("No known interfaces to check against")
        self.assertTrue(any(interface in output for interface in self.known_interfaces))

    def test_list_interfaces(self):
        # Test listing network interfaces
        completed_process = subprocess.run(
            [self.sniffer_path, "-i"], capture_output=True, text=True
        )
        self.assertIn(self.interface, completed_process.stdout)

    def test_capture_tcp(self):
        # Example test to capture only TCP packets
        # Note: This requires actual TCP traffic; consider setting up a test server/client or skipping this test
        completed_process = subprocess.run(
            [self.sniffer_path, "-i", self.interface, "--tcp", "-n", "1"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertIn("tcp", completed_process.stdout.lower())

    def test_capture_udp(self):
        # Similar to TCP, for UDP
        # Again, requires UDP traffic; consider adjusting the setup accordingly
        completed_process = subprocess.run(
            [self.sniffer_path, "-i", self.interface, "--udp", "-n", "1"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertIn("udp", completed_process.stdout.lower())

    def test_invalid_option(self):
        # Test the response to an invalid option
        completed_process = subprocess.run(
            [self.sniffer_path, "--notanoption"], capture_output=True, text=True
        )
        self.assertNotEqual(completed_process.returncode, 0)

    # Add more tests for specific protocols and filters as needed


if __name__ == "__main__":
    unittest.main()
