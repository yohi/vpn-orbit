import json
import unittest
from unittest.mock import patch

from vpn_orbit.geoip import GeoDecision, lookup_geoip


class GeoipKeyTests(unittest.TestCase):
    def test_empty_key_never_creates_http_opener(self) -> None:
        for key in ("", "  "):
            with self.subTest(key=key), patch("vpn_orbit.geoip._create_opener") as opener:
                response = opener.return_value.open.return_value.__enter__.return_value
                response.getcode.return_value = 200
                response.read.return_value = json.dumps({
                    "ip": "8.8.8.8", "location": {"country_code": "JP", "state": "Tokyo"},
                }).encode()
                decision = lookup_geoip("8.8.8.8", api_key=key)
                self.assertEqual(decision, GeoDecision.UNKNOWN)
                opener.assert_not_called()
