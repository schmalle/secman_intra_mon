import unittest
from unittest.mock import MagicMock, patch

from secman_intra_mon.scanners import nmap


class NmapTests(unittest.TestCase):
    @patch("secman_intra_mon.scanners.nmap.run_tool")
    def test_service_scan_skips_duplicate_host_discovery(self, run_tool: MagicMock) -> None:
        run_tool.return_value.returncode = 0
        run_tool.return_value.stdout = "<nmaprun/>"
        nmap.service_scan(["192.168.1.10"])
        argv = run_tool.call_args.args[0]
        self.assertIn("-Pn", argv)

    @patch("secman_intra_mon.scanners.nmap.run_tool")
    def test_service_scan_can_enable_nmap_discovery(self, run_tool: MagicMock) -> None:
        run_tool.return_value.returncode = 0
        run_tool.return_value.stdout = "<nmaprun/>"
        nmap.service_scan(["192.168.1.10"], skip_discovery=False)
        argv = run_tool.call_args.args[0]
        self.assertNotIn("-Pn", argv)


if __name__ == "__main__":
    unittest.main()
