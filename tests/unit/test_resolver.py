"""asset_resolver 판정 로직 단위 테스트.  실행: python3 -m unittest discover -s tests/unit"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import asset_resolver as ar  # noqa: E402

H = 3600.0


def sig(ts, ip, signal, value, source="dhcp", conf=90):
    return ar.Sig({"ts": ts, "ip": ip, "signal": signal, "value": value, "source": source, "confidence": conf})


def resolve(sigs, **kw):
    return ar.resolve(sorted(sigs, key=lambda s: s.ts), **kw)


def by_host(result):
    return {a["hostname"]: a for a in result["assets"]}


class TestResolver(unittest.TestCase):
    def test_ip_reuse_splits_assets(self):
        r = resolve([
            sig(0, "10.0.0.5", "mac", "aa:aa:aa:aa:aa:01"),
            sig(0, "10.0.0.5", "hostname", "laptop"),
            sig(60, "10.0.0.5", "os_hint", "windows 10/11", "http_ua", 50),
            sig(4 * H, "10.0.0.5", "mac", "aa:aa:aa:aa:aa:02"),
            sig(4 * H, "10.0.0.5", "hostname", "phone"),
        ])
        hosts = by_host(r)
        self.assertEqual(set(hosts), {"laptop", "phone"})
        self.assertEqual(hosts["laptop"]["os"], "windows 10/11")
        self.assertEqual(hosts["phone"]["os"], "")
        self.assertIn("10.0.0.5", r["reused_ips"])

    def test_same_mac_across_ips_is_one_asset(self):
        r = resolve([
            sig(0, "10.0.0.5", "mac", "aa:aa:aa:aa:aa:01"),
            sig(0, "10.0.0.5", "hostname", "pc01"),
            sig(2 * H, "10.0.0.9", "mac", "aa:aa:aa:aa:aa:01", "arp", 85),
        ])
        self.assertEqual(len(r["assets"]), 1)
        self.assertEqual([i["ip"] for i in r["assets"][0]["ips"]], ["10.0.0.5", "10.0.0.9"])

    def test_machine_account_domain_forms_merge(self):
        r = resolve([
            sig(0, "10.0.0.5", "machine_account", "corp.local\\pc01$", "kerberos", 95),
            sig(5 * H, "10.0.0.7", "machine_account", "corp\\pc01$", "ntlm", 90),
        ])
        self.assertEqual(len(r["assets"]), 1)
        self.assertEqual(r["assets"][0]["id_type"], "machine_account")

    def test_shared_gateway_mac_is_not_identity(self):
        gw = "00:00:5e:00:01:01"
        sigs = [sig(i, "10.20.0.%d" % i, "mac", gw, "conn", 40) for i in range(1, 5)]
        sigs.append(sig(0, "10.0.0.1", "mac", gw, "arp", 85))
        r = resolve(sigs)
        self.assertIn(gw, r["shared_macs"])
        ip_only = [a for a in r["assets"] if a["id_type"] == "ip"]
        self.assertEqual(len(ip_only), 4)
        gw_asset = [a for a in r["assets"] if a["id_type"] == "mac"][0]
        self.assertEqual(gw_asset["ips"][0]["ip"], "10.0.0.1")
        self.assertIn("게이트웨이/라우터(추정)", gw_asset["roles"])

    def test_hostname_does_not_merge_conflicting_macs(self):
        r = resolve([
            sig(0, "10.0.0.5", "mac", "aa:aa:aa:aa:aa:01"),
            sig(0, "10.0.0.5", "hostname", "iphone"),
            sig(0, "10.0.0.6", "mac", "aa:aa:aa:aa:aa:02"),
            sig(0, "10.0.0.6", "hostname", "iphone"),
        ])
        self.assertEqual(len(r["assets"]), 2)
        self.assertTrue(r["conflicts"])

    def test_nbns_group_name_is_not_hostname(self):
        r = resolve([
            sig(0, "10.0.0.5", "hostname", "pc01", "nbns", 75),
            sig(0, "10.0.0.5", "hostname", "corp", "nbns", 50),
            sig(0, "10.0.0.5", "domain", "corp", "nbns", 60),
        ])
        a = r["assets"][0]
        self.assertEqual(a["hostnames"], ["pc01"])
        self.assertEqual(a["domain"], "corp")

    def test_netbios_truncation_matches_full_hostname(self):
        r = resolve([
            sig(0, "10.0.0.5", "hostname", "desktop-1234567890ab", "dhcp", 85),
            sig(30 * H, "10.0.0.8", "hostname", "desktop-1234567", "nbns", 75),
        ])
        self.assertEqual(len(r["assets"]), 1)

    def test_roles_and_os_priority(self):
        r = resolve([
            sig(0, "10.0.0.10", "mac", "aa:aa:aa:aa:aa:10", "arp", 85),
            sig(0, "10.0.0.10", "service", "tcp/88", "service"),
            sig(0, "10.0.0.10", "service", "tcp/389", "service"),
            sig(0, "10.0.0.10", "service", "udp/53", "service"),
            sig(0, "10.0.0.10", "os_hint", "windows", "dhcp", 60),
            sig(0, "10.0.0.10", "os_hint", "windows nt 10.0 build 20348", "ntlm", 80),
        ])
        a = r["assets"][0]
        self.assertIn("도메인 컨트롤러", a["roles"])
        self.assertIn("DNS 서버", a["roles"])
        self.assertTrue(a["os"].startswith("Windows 11/Server 2022+"))

    def test_conn_only_mac_is_low_confidence(self):
        r = resolve([
            sig(0, "10.0.0.5", "mac", "00:50:56:00:00:05", "conn", 40),
            sig(0, "10.0.0.6", "mac", "00:50:56:00:00:06", "arp", 85),
        ])
        conf = {a["ips"][0]["ip"]: a["confidence"] for a in r["assets"]}
        self.assertEqual(conf, {"10.0.0.5": "낮음", "10.0.0.6": "중간"})

    def test_duplicate_hostnames_reported(self):
        r = resolve([
            sig(0, "10.0.0.5", "mac", "00:50:56:00:00:05", "conn", 40),
            sig(0, "10.0.0.5", "hostname", "desktop-1", "mdns", 70),
            sig(0, "10.0.0.6", "mac", "00:50:56:00:00:06", "conn", 40),
            sig(0, "10.0.0.6", "hostname", "desktop-1", "mdns", 70),
        ])
        self.assertEqual(len(r["assets"]), 2)
        self.assertEqual(list(r["dup_hostnames"]), ["desktop-1"])


class TestCli(unittest.TestCase):
    def test_outputs_created(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "asset_signal.log")
            with open(log, "w") as f:
                for s in ({"ts": 1.0, "ip": "10.0.0.5", "signal": "hostname", "value": "pc01",
                           "source": "dhcp", "confidence": 85},
                          {"ts": 2.0, "ip": "10.0.0.5", "signal": "mac", "value": "aa:aa:aa:aa:aa:01",
                           "source": "dhcp", "confidence": 90}):
                    f.write(json.dumps(s) + "\n")
            subprocess.run([sys.executable, os.path.join(ROOT, "tools", "asset_resolver.py"), log, "-o", d, "-q"],
                           check=True)
            for name in ("assets.csv", "assets.json", "report.txt", "report.html"):
                self.assertTrue(os.path.getsize(os.path.join(d, name)) > 0, name)
            with open(os.path.join(d, "report.html"), encoding="utf-8") as f:
                self.assertNotIn("/*__DATA__*/null", f.read())


if __name__ == "__main__":
    unittest.main()
