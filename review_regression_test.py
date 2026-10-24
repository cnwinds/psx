"""回归检查：PS5 候选发现与 ELF 代发输入边界。"""
import unittest
from unittest.mock import patch

import serve


class RegressionTests(unittest.TestCase):
    def test_ps5_candidate_discovery_and_elfsend_validation(self):
        with patch.object(serve, "_seen_devices", {}):
            serve.record_ps5_candidate("127.0.0.1", "dns", "回环应忽略")
            self.assertEqual(serve._seen_devices, {})
            serve.record_ps5_candidate("192.168.30.86", "ps5-ua", "PS5 浏览器")
            serve.record_ps5_candidate("192.168.30.105", "dns", "DNS 请求")
            with patch.object(serve, "ranked_lan_ips", return_value=["192.168.30.182"]), \
                 patch.object(serve, "read_arp_neighbors", return_value=["192.168.30.128"]), \
                 patch.object(serve, "probe_ports_map", side_effect=lambda ip, *_a, **_kw: {
                     "9021": ip == "192.168.30.86",
                     "2120": ip in ("192.168.30.86", "192.168.30.105"),
                     "8888": False,
                     "8080": False,
                 }):
                cands = serve.discover_ps5_candidates(client_ip="127.0.0.1", scan_subnet=False)
                self.assertEqual([c["ip"] for c in cands], [
                    "192.168.30.86",
                    "192.168.30.105",
                    "192.168.30.128",
                ])
                self.assertTrue(cands[0]["online"])
                self.assertGreater(cands[0]["score"], cands[1]["score"])

        handler = type("Request", (), {"client_address": ("127.0.0.1", 12345)})()
        with self.assertRaisesRegex(ValueError, "非法 ELF 文件名"):
            serve.SiteHandler._api_elfsend(handler, {"file": ["../serve.py"]})


if __name__ == "__main__":
    unittest.main()
