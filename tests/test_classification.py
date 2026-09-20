import unittest

from secman_intra_mon.classification import classify_host
from secman_intra_mon.models import DiscoveredHost, DiscoveredPort


def host(*ports: tuple[int, str], **kwargs: str) -> DiscoveredHost:
    return DiscoveredHost(
        ip="192.168.1.10",
        ports=[DiscoveredPort(port=number, service=service) for number, service in ports],
        **kwargs,
    )


class ClassificationTests(unittest.TestCase):
    def test_network_protocol_classifies_network_device(self) -> None:
        result = classify_host(host((161, "snmp")))
        self.assertEqual(result.kind, "network_device")
        self.assertIn("service:snmp", result.evidence)

    def test_vendor_and_protocol_give_high_network_confidence(self) -> None:
        result = classify_host(host((179, "bgp"), mac_vendor="Cisco Systems"))
        self.assertEqual(result.kind, "network_device")
        self.assertEqual(result.confidence, "high")

    def test_common_hosted_services_classify_server(self) -> None:
        self.assertEqual(classify_host(host((22, "ssh"), (443, "https"))).kind, "server")

    def test_workstation_hint_beats_single_server_port(self) -> None:
        observed = host((22, "ssh"), os_guess="Microsoft Windows 11")
        self.assertEqual(classify_host(observed).kind, "endpoint")

    def test_weak_evidence_remains_unknown(self) -> None:
        self.assertEqual(classify_host(host((12345, "unknown"))).kind, "unknown")


if __name__ == "__main__":
    unittest.main()
