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

    def test_help_option(self):
        # Test if the help/usage message is displayed
        completed_process = subprocess.run(
            [self.sniffer_path, "-h"], capture_output=True, text=True
        )
        self.assertIn("usage", completed_process.stdout.lower())

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
