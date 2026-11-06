import unittest
from datetime import UTC, datetime
from unittest.mock import Mock

from secman_intra_mon.models import DiscoveredHost
from secman_intra_mon.secman import SecmanClient


class ObservationContractTest(unittest.TestCase):
    def client(self):
        client = object.__new__(SecmanClient)
        response = Mock()
        response.json.return_value = {"created": True}
        client._request = Mock(return_value=response)
        return client

    def test_live_discovery_preserves_observation_time(self):
        client = self.client()
        at = datetime(2026, 10, 14, 12, tzinfo=UTC)
        self.assertTrue(client.push_asset(DiscoveredHost("192.0.2.1"), "ops", observed_at=at))
        self.assertEqual(client._request.call_args.args, ("PUT", "/api/assets/import"))
        self.assertEqual(client._request.call_args.kwargs["json"]["observedAt"], at.isoformat())

    def test_stored_metadata_does_not_mint_observation(self):
        client = self.client()
        client.push_asset(DiscoveredHost("192.0.2.1"), "ops")
        self.assertNotIn("observedAt", client._request.call_args.kwargs["json"])

    def test_timezone_is_required(self):
        client = self.client()
        with self.assertRaises(ValueError):
            client.push_asset(DiscoveredHost("192.0.2.1"), "ops", observed_at=datetime(2026, 10, 14))
        client._request.assert_not_called()
