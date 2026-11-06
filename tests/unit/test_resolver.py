"""asset_resolver 판정 로직 단위 테스트.  실행: python3 -m unittest discover -s tests/unit"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict

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

    def test_asymmetric_route_mac_does_not_split_or_merge(self):
        # 프록시 2대: 자기 MAC + 응답 경로의 방화벽 MAC(두 IP 공유)이 conn에서 번갈아 보임
        fw = "94:3f:c2:dd:ff:4e"
        r = resolve([
            sig(0, "172.25.1.15", "mac", "7c:c2:55:65:a4:f4", "conn", 40),
            sig(0, "172.25.1.15", "mac", fw, "conn", 40),
            sig(0, "172.25.1.16", "mac", "7c:c2:55:65:a3:f4", "conn", 40),
            sig(0, "172.25.1.16", "mac", fw, "conn", 40),
            sig(H, "172.25.1.15", "mac", "7c:c2:55:65:a4:f4", "conn", 40),
            sig(H + 10, "172.25.1.15", "mac", fw, "conn", 40),
        ])
        self.assertEqual(r["reused_ips"], {})
        self.assertIn(fw, r["shared_macs"])
        self.assertEqual(sorted(a["macs"][0] for a in r["assets"]), ["7c:c2:55:65:a3:f4", "7c:c2:55:65:a4:f4"])

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
        self.assertEqual(a["os"], "Windows Server 2022 (build 20348)")

    def test_ntlm_build_names(self):
        f = ar.ntlm_os_name
        self.assertEqual(f("windows nt 10.0 build 19045"), "Windows 10 22H2 (build 19045)")
        self.assertEqual(f("windows nt 10.0 build 22631"), "Windows 11 23H2 (build 22631)")
        self.assertEqual(f("windows nt 10.0 build 26100"), "Windows 11 24H2 (build 26100)")
        self.assertEqual(f("windows nt 10.0 build 26100", server=True), "Windows Server 2025 (build 26100)")
        self.assertEqual(f("windows nt 10.0 build 14393", server=True), "Windows Server 2016 (build 14393)")
        self.assertEqual(f("windows nt 10.0 build 20348"), "Windows Server 2022 (build 20348)")
        self.assertEqual(f("windows nt 10.0 build 27000"), "Windows 11 (build 27000)")
        self.assertEqual(f("windows nt 6.1 build 7601"), "Windows 7/Server 2008 R2 (build 7601)")

    def test_shared_build_resolved_by_role(self):
        pc = [sig(0, "10.0.0.5", "os_hint", "windows nt 10.0 build 26100", "ntlm", 80),
              sig(0, "10.0.0.5", "service", "tcp/445", "service")]   # 파일 공유만 있는 PC
        dc = [sig(0, "10.0.0.6", "os_hint", "windows nt 10.0 build 26100", "ntlm", 80),
              sig(0, "10.0.0.6", "service", "tcp/88", "service"), sig(0, "10.0.0.6", "service", "tcp/389", "service")]
        os_by_ip = {a["ips"][0]["ip"]: a["os"] for a in resolve(pc + dc)["assets"]}
        self.assertEqual(os_by_ip["10.0.0.5"], "Windows 11 24H2 (build 26100)")
        self.assertEqual(os_by_ip["10.0.0.6"], "Windows Server 2025 (build 26100)")

    def test_default_hostnames_decide_shared_build(self):
        srv = [sig(0, "10.0.0.7", "os_hint", "windows nt 10.0 build 17763", "ntlm", 80),
               sig(0, "10.0.0.7", "hostname", "win-rmkukhvf5i7", "ntlm", 85)]
        pc = [sig(0, "10.0.0.8", "os_hint", "windows nt 10.0 build 26100", "ntlm", 80),
              sig(0, "10.0.0.8", "hostname", "desktop-j2rjh6s", "ntlm", 85),
              sig(0, "10.0.0.8", "service", "tcp/80", "service")]          # 웹 서비스가 있어도 PC 기본 이름이면 PC
        os_by_ip = {a["ips"][0]["ip"]: a["os"] for a in resolve(srv + pc)["assets"]}
        self.assertEqual(os_by_ip["10.0.0.7"], "Windows Server 2019 (build 17763)")
        self.assertEqual(os_by_ip["10.0.0.8"], "Windows 11 24H2 (build 26100)")

    def test_conn_only_mac_is_low_confidence(self):
        r = resolve([
            sig(0, "10.0.0.5", "mac", "00:50:56:00:00:05", "conn", 40),
            sig(0, "10.0.0.6", "mac", "00:50:56:00:00:06", "arp", 85),
        ])
        conf = {a["ips"][0]["ip"]: a["confidence"] for a in r["assets"]}
        self.assertEqual(conf, {"10.0.0.5": "낮음", "10.0.0.6": "중간"})

    def test_dns_domain_preferred_over_netbios(self):
        r = resolve([
            sig(0, "10.0.0.5", "machine_account", "ahnbang\\pc01$", "ntlm", 90),
            sig(0, "10.0.0.5", "domain", "ahnbang", "kerberos", 90),
            sig(1, "10.0.0.5", "domain", "ahnbang", "ntlm", 60),
            sig(2, "10.0.0.5", "domain", "ahnbang.ahnlab.com", "kerberos", 90),
        ])
        self.assertEqual(r["assets"][0]["domain"], "ahnbang.ahnlab.com")

    def test_proxy_role(self):
        sigs = [sig(0, "10.0.0.9", "dns_name", "site%d.example.com" % i, "tls", 50) for i in range(20)]
        sigs.append(sig(0, "10.0.0.8", "service", "tcp/3128/http", "service"))
        roles = {a["ips"][0]["ip"]: a["roles"] for a in resolve(sigs)["assets"]}
        self.assertIn("프록시/로드밸런서(추정)", roles["10.0.0.9"])
        self.assertIn("프록시/로드밸런서(추정)", roles["10.0.0.8"])

    def test_duplicate_hostnames_reported(self):
        r = resolve([
            sig(0, "10.0.0.5", "mac", "00:50:56:00:00:05", "conn", 40),
            sig(0, "10.0.0.5", "hostname", "desktop-1", "mdns", 70),
            sig(0, "10.0.0.6", "mac", "00:50:56:00:00:06", "conn", 40),
            sig(0, "10.0.0.6", "hostname", "desktop-1", "mdns", 70),
        ])
        self.assertEqual(len(r["assets"]), 2)
        self.assertEqual(list(r["dup_hostnames"]), ["desktop-1"])


class TestMultiMachineAccounts(unittest.TestCase):
    def test_relay_ip_accounts_are_not_identity(self):
        # ldap_invalid_credentials.pcap 재현: 공격자 IP가 DC·피해 PC의 머신 계정으로 연달아 인증
        r = resolve([
            sig(0, "192.168.66.138", "hostname", "dc01-zion", "ntlm", 85),
            sig(0, "192.168.66.138", "machine_account", "matrix\\dc01-zion$", "kerberos", 95),
            sig(1, "192.168.66.141", "hostname", "desktop-evil", "ntlm", 85),
            sig(20, "192.168.66.141", "machine_account", "matrix\\dc01-zion$", "ntlm", 90),
            sig(46, "192.168.66.141", "machine_account", "matrix\\desktop-evil$", "ntlm", 90),
            sig(46, "192.168.66.141", "machine_account", "matrix\\desktop-victim$", "ntlm", 90),
            sig(47, "192.168.66.141", "hostname", "desktop-victim", "kerberos", 90),
        ])
        self.assertEqual(r["multi_account_ips"]["192.168.66.141"],
                         ["matrix\\dc01-zion$", "matrix\\desktop-evil$", "matrix\\desktop-victim$"])
        self.assertEqual(r["reused_ips"], {})                       # 가짜 IP 재사용 없음
        by_ip = defaultdict(list)
        for a in r["assets"]:
            by_ip[a["ips"][0]["ip"]].append(a)
        self.assertEqual(len(by_ip["192.168.66.141"]), 1)            # 가짜 자산 없음
        evil = by_ip["192.168.66.141"][0]
        self.assertEqual((evil["id_type"], evil["hostname"]), ("hostname", "desktop-evil"))
        self.assertEqual(len(evil["multi_machine_accounts"]), 3)
        dc = by_ip["192.168.66.138"][0]                              # DC 자산과 합쳐지지 않음
        self.assertEqual([i["ip"] for i in dc["ips"]], ["192.168.66.138"])

    def test_same_account_repeated_is_fine(self):
        r = resolve([sig(t, "10.0.0.5", "machine_account", "corp\\pc05$", "kerberos", 95) for t in (0, 60, 120)])
        self.assertEqual(r["multi_account_ips"], {})
        self.assertEqual(r["assets"][0]["id_type"], "machine_account")


class TestDevicesAgents(unittest.TestCase):
    def test_device_roles_agents_and_shared_ssh_keys(self):
        r = resolve([
            sig(0, "10.30.1.20", "device", "vmware-esxi", "syslog", 80),
            sig(0, "10.30.1.20", "hostname", "esx01", "syslog", 70),
            sig(0, "10.30.0.5", "service", "udp/514", "syslog"),
            sig(0, "10.30.4.10", "device", "ahnlab-mds", "x509", 70),
            sig(0, "10.30.3.11", "security_agent", "ahnlab:V3ES90ASD/5.6.0.55", "ahnlab", 80),
            sig(0, "10.30.5.1", "ssh_host_key", "aa:bb", "ssh", 80),
            sig(0, "10.30.5.2", "ssh_host_key", "aa:bb", "ssh", 80),
        ])
        by_ip = {a["ips"][0]["ip"]: a for a in r["assets"]}
        self.assertEqual(by_ip["10.30.1.20"]["roles"][0], "VMware ESXi")
        self.assertIn("로그 수집 서버", by_ip["10.30.0.5"]["roles"])
        self.assertEqual(by_ip["10.30.4.10"]["roles"], ["AhnLab MDS"])
        self.assertEqual(by_ip["10.30.3.11"]["security_agents"], ["ahnlab:V3ES90ASD/5.6.0.55"])
        # 호스트 키는 식별 키가 아니므로 두 서버는 따로 남고, 공유 사실만 보고한다
        self.assertEqual(len(r["shared_ssh_keys"]["aa:bb"]), 2)
        q = ar.id_quality(r["assets"], {"10.30.3.11", "10.30.1.20"}, 0, 60)
        self.assertEqual((q["active_passive"]["active"]["agent"], q["active_passive"]["active"]["agent_pct"]), (1, 50.0))


class TestUsersAndSmbGuid(unittest.TestCase):
    def test_recent_users_latest_first(self):
        r = resolve([
            sig(0, "10.0.0.5", "machine_account", "corp\\pc05$", "kerberos", 95),
            sig(10, "10.0.0.5", "user_account", "corp\\kim", "kerberos", 70),
            sig(50, "10.0.0.5", "user_account", "corp\\lee", "ntlm", 70),
            sig(90, "10.0.0.5", "user_account", "corp\\kim", "kerberos", 70),
        ])
        users = r["assets"][0]["recent_users"]
        self.assertEqual([(u["user"], u["last"], u["source"]) for u in users],
                         [("corp\\kim", 90, "kerberos"), ("corp\\lee", 50, "ntlm")])

    def test_smb_guid_stats(self):
        r = resolve([
            sig(0, "10.0.0.5", "mac", "aa:aa:aa:aa:aa:05"),
            sig(0, "10.0.0.5", "smb_client_guid", "g-1", "smb", 70),
            sig(0, "10.0.0.6", "mac", "aa:aa:aa:aa:aa:06"),
            sig(0, "10.0.0.6", "smb_client_guid", "g-1", "smb", 70),   # 복제 VM처럼 공유
            sig(0, "10.0.0.7", "mac", "aa:aa:aa:aa:aa:07"),
            sig(0, "10.0.0.7", "smb_client_guid", "g-2", "smb", 70),
            sig(9, "10.0.0.7", "smb_client_guid", "g-3", "smb", 70),   # 변경
        ])
        g = r["smb_guid_stats"]
        self.assertEqual((g["assets"], g["guids"]), (3, 3))
        self.assertEqual(len(g["shared"]["g-1"]), 2)
        self.assertEqual(len(g["changed"]), 1)
        self.assertEqual(len(r["assets"]), 3)   # 참고 정보라 자산을 합치지 않는다


class TestIdQuality(unittest.TestCase):
    def test_rates_curve_and_active_split(self):
        r = resolve([
            sig(0, "10.0.0.5", "os_hint", "windows", "http_ua", 50),
            sig(20 * 60, "10.0.0.5", "machine_account", "corp\\pc05$", "kerberos", 95),
            sig(0, "10.0.0.6", "mac", "aa:aa:aa:aa:aa:06", "conn", 40),
            sig(0, "10.0.1.7", "service", "tcp/443", "service"),
        ])
        q = ar.id_quality(r["assets"], {"10.0.0.5", "10.0.1.7"}, 0, 3600)
        self.assertEqual((q["overall"]["n"], q["overall"]["identified"], q["overall"]["trusted"]), (3, 2, 1))
        curve = {label: (seen, idn) for label, seen, idn, _ in q["curve"]}
        self.assertEqual(curve["10분"], (3, 1))   # pc05는 20분에 식별
        self.assertEqual(curve["30분"], (3, 2))
        self.assertEqual(dict(q["tti"])["10~30분"], 1)
        self.assertEqual(q["active_passive"]["active"]["identified"], 1)
        self.assertEqual(q["active_passive"]["passive"]["n"], 1)
        self.assertEqual(dict(q["subnets"])["10.0.0.0/24"]["n"], 2)
        self.assertEqual(q["breakdown"], [("머신 계정(높음)", 1), ("MAC(낮음)", 1)])


class TestCaptureHealth(unittest.TestCase):
    def write_conn(self, d, histories):
        with open(os.path.join(d, "conn.log"), "w") as f:
            for i, (orig, h) in enumerate(histories):
                f.write(json.dumps({"proto": "tcp", "history": h, "id.orig_h": orig,
                                    "id.resp_h": "10.9.0.%d" % (i % 250), "id.resp_p": 1000 + i}) + "\n")
            f.write(json.dumps({"proto": "udp", "history": "D", "id.orig_h": "10.0.0.1"}) + "\n")

    def test_one_way_mirror_detected(self):
        with tempfile.TemporaryDirectory() as d:
            # 요청측이 데이터를 보냈는데 응답이 안 보임 -> 단방향 미러
            self.write_conn(d, [("10.0.0.1", "ShADadFf"), ("10.0.0.2", "SAD"), ("10.0.0.3", "SAD"), ("10.0.0.4", "D")])
            cap = ar.capture_health(d)
        self.assertEqual((cap["tcp"], cap["data"], cap["data_both"]), (4, 4, 1))
        self.assertEqual(cap["data_both_pct"], 25.0)
        self.assertTrue(ar.one_way_suspected(cap))
        self.assertIsNone(ar.capture_health(None))

    def test_scan_is_not_one_way(self):
        with tempfile.TemporaryDirectory() as d:
            # 정상 양방향 연결 3개 + 데이터 없는 연결 시도 100개(스캔)
            self.write_conn(d, [("10.0.0.1", "ShADadFf")] * 3 + [("10.0.0.66", "S")] * 100)
            cap = ar.capture_health(d)
        self.assertLess(cap["both_pct"], 50)           # 예전 지표라면 오경보
        self.assertEqual(cap["data_both_pct"], 100.0)
        self.assertFalse(ar.one_way_suspected(cap))
        self.assertEqual(cap["attempts"], 100)
        self.assertEqual(cap["attempt_top"][0], {"ip": "10.0.0.66", "attempts": 100, "hosts": 100, "ports": 100})


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
