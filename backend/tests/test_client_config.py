"""Tests for the generated WireGuard client profile (stdlib only)."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as averiq_app  # noqa: E402


class ClientConfigTests(unittest.TestCase):
    def setUp(self):
        self.old_endpoint = averiq_app.WG_ENDPOINT
        self.old_port = averiq_app.WG_PORT
        averiq_app.WG_ENDPOINT = "79.137.184.71"
        averiq_app.WG_PORT = 51820

    def tearDown(self):
        averiq_app.WG_ENDPOINT = self.old_endpoint
        averiq_app.WG_PORT = self.old_port

    def test_ipv4_full_tunnel_does_not_claim_unconfigured_ipv6(self):
        config = averiq_app.build_client_config(
            private_key="test-client-private-key",
            client_ip="10.66.66.10",
            server_public="test-server-public-key",
        )
        self.assertIn("AllowedIPs = 0.0.0.0/0\n", config)
        self.assertNotIn("::/0", config)

    def test_profile_contains_endpoint_and_keepalive(self):
        config = averiq_app.build_client_config(
            private_key="test-client-private-key",
            client_ip="10.66.66.10",
            server_public="test-server-public-key",
        )
        self.assertIn("Endpoint = 79.137.184.71:51820\n", config)
        self.assertIn("PersistentKeepalive = 25\n", config)
        self.assertIn("Address = 10.66.66.10/32\n", config)


if __name__ == "__main__":
    unittest.main()
