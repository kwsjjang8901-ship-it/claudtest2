#!/usr/bin/env python3
"""asset_signal.log -> 자산 목록 (PoC용 Manager 자산 판정 대체).

판정 키 우선순위(원페이저 6장):
    머신 계정 > DHCP client-id > MAC > 호스트명(+도메인) > IP+시간 구간

알고리즘
  1. 공유 MAC 판별: conn 출처 MAC이 여러 IP(기본 2개 이상)에 걸치면 게이트웨이/라우터/방화벽 MAC으로
     보고 식별 키에서 제외한다(ARP/DHCP 출처 MAC은 유지).
  2. IP 점유 구간(tenancy) 분할: IP별 신호를 시간순으로 보며, 강한 키(머신 계정, client-id, L2 MAC)가
     기존 값과 다르게 나타나거나 max-idle 이상 신호가 끊기면 새 점유 구간을 시작한다.
     conn 출처 MAC은 라우팅 경로(요청/응답 방향)에 따라 바뀌므로 분할 근거로 쓰지 않는다.
     -> DHCP로 같은 IP를 다른 단말이 받아도 자산이 섞이지 않는다.
  3. 점유 구간 결합: 같은 식별 키(머신 계정/client-id/MAC/호스트명)를 공유하는 구간을 하나의 자산으로
     묶는다. 단, 강한 키 값이 서로 다르면 묶지 않는다(오결합보다 중복을 택함).
  4. 식별 키가 전혀 없는 구간은 IP+시간 구간 자산으로 남는다.

표준 라이브러리만 사용한다(Python 3.8+).
"""

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import os
import re
import sys
import unicodedata
from collections import Counter, defaultdict

STRONG = ("machine_account", "dhcp_client_id", "mac")
KEY_PRIORITY = ("machine_account", "dhcp_client_id", "mac", "hostname", "ip")
KEY_LABEL = {
    "machine_account": "머신 계정",
    "dhcp_client_id": "DHCP client-id",
    "mac": "MAC",
    "hostname": "호스트명",
    "ip": "IP+시간",
}
KEY_CONFIDENCE = {"machine_account": "높음", "dhcp_client_id": "높음", "mac": "중간",
                  "hostname": "중간", "ip": "낮음"}
# 구체적인 정보를 주는 출처 우선 (DHCP vendor class는 OS 계열만 알려줌)
OS_SOURCE_RANK = {"ntlm": 5, "smb": 4, "ssh": 3, "http_ua": 2, "dhcp": 1}

# (역할, 판정 함수: 포트 집합 -> bool)
ROLE_RULES = [
    ("도메인 컨트롤러", lambda p: "88" in p and ({"389", "636", "3268"} & p)),
    ("DNS 서버", lambda p: "53" in p),
    ("DHCP 서버", lambda p: "67" in p),
    ("웹 서버", lambda p: {"80", "443", "8080", "8443"} & p),
    ("파일 서버(SMB)", lambda p: {"445", "139"} & p),
    ("DB 서버", lambda p: {"1433", "1521", "3306", "5432", "6379", "27017", "9200"} & p),
    ("메일 서버", lambda p: {"25", "465", "587", "110", "143", "993", "995"} & p),
    ("SSH 서버", lambda p: "22" in p),
    ("RDP 호스트", lambda p: "3389" in p),
    ("원격관리(WinRM/VNC)", lambda p: {"5985", "5986", "5900"} & p),
    ("프린터", lambda p: {"9100", "515", "631"} & p),
    ("SNMP 장비", lambda p: "161" in p),
]


# ---------------------------------------------------------------- 입력

class Sig:
    __slots__ = ("ts", "ip", "signal", "value", "source", "conf", "mac", "uid")

    def __init__(self, d):
        self.ts = float(d["ts"])
        self.ip = d["ip"]
        self.signal = d["signal"]
        self.value = d["value"]
        self.source = d.get("source", "")
        self.conf = int(d.get("confidence", 0))
        self.mac = d.get("mac", "")
        self.uid = d.get("uid", "")


def load_signals(path):
    sigs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                sigs.append(Sig(json.loads(line)))
            except (ValueError, KeyError) as e:
                print("경고: 해석할 수 없는 줄 무시: %s (%s)" % (line[:80], e), file=sys.stderr)
    sigs.sort(key=lambda s: s.ts)
    return sigs


def host_key(v):
    """호스트명 비교 키: 소문자 단축명, NetBIOS 15자 절단 반영."""
    v = v.strip().lower().split("\\")[-1].split(".")[0].rstrip("$")
    return v[:15]


def machine_key(v):
    """'corp.local\\pc01$' 와 'corp\\pc01$' 를 같은 키로: 도메인 첫 레이블 + 계정."""
    if "\\" in v:
        dom, name = v.split("\\", 1)
        return "%s\\%s" % (dom.split(".")[0], name)
    return v


def ntlm_os_name(v):
    m = re.match(r"windows nt (\d+)\.(\d+) build (\d+)", v)
    if not m:
        return v
    major, minor, build = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if major == 10:
        name = "Windows 11/Server 2022+" if build >= 20348 else "Windows 10/Server 2016+"
    else:
        name = {(6, 3): "Windows 8.1/Server 2012 R2", (6, 2): "Windows 8/Server 2012",
                (6, 1): "Windows 7/Server 2008 R2", (6, 0): "Windows Vista/Server 2008",
                (5, 2): "Windows XP x64/Server 2003", (5, 1): "Windows XP"}.get((major, minor), v)
    return "%s (build %d)" % (name, build)


def fmt_ts(ts, tz):
    return dt.datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- 판정

class Tenancy:
    """하나의 IP를 한 단말이 점유한 시간 구간과 그 동안의 신호."""

    def __init__(self, ip, ts):
        self.ip = ip
        self.first = self.last = ts
        self.sigs = []
        self.strong = {}  # type -> value

    def add(self, s):
        self.sigs.append(s)
        self.last = max(self.last, s.ts)


def identity_of(s, shared_macs, domain_names):
    """신호가 식별 키이면 (type, key) 반환, 아니면 None."""
    if s.signal == "machine_account":
        return ("machine_account", machine_key(s.value))
    if s.signal == "dhcp_client_id":
        return ("dhcp_client_id", s.value)
    if s.signal == "mac":
        if s.source == "conn" and s.value in shared_macs:
            return None
        return ("mac", s.value)
    if s.signal == "hostname":
        k = host_key(s.value)
        if not k or is_group_name(s, domain_names):
            return None
        return ("hostname", k)
    return None


def is_group_name(s, domain_names):
    """NBNS <00> 이름은 워크스테이션/워크그룹 공용이라, 도메인 이름과 같으면 호스트명이 아니다."""
    return s.source == "nbns" and host_key(s.value) in domain_names


def find_shared_macs(sigs, threshold):
    ips = defaultdict(set)
    for s in sigs:
        if s.signal == "mac" and s.source == "conn":
            ips[s.value].add(s.ip)
    return {m: sorted(v) for m, v in ips.items() if len(v) >= threshold}


def build_tenancies(sigs, shared_macs, domain_names, max_idle):
    by_ip = defaultdict(list)
    for s in sigs:
        by_ip[s.ip].append(s)

    tenancies, reused = [], {}
    for ip, lst in by_ip.items():
        cur = None
        splits = []
        for s in lst:
            ident = identity_of(s, shared_macs, domain_names)
            new = cur is None or s.ts - cur.last > max_idle
            # conn L2 주소는 경로에 따라 바뀌는 약한 증거라 점유 단말 변경 근거로 쓰지 않는다.
            splits_on = ident and ident[0] in STRONG and not (ident[0] == "mac" and s.source == "conn")
            if not new and splits_on:
                old = cur.strong.get(ident[0])
                new = old is not None and old != ident[1]
            if new:
                if cur is not None:
                    splits.append(s.ts)
                cur = Tenancy(ip, s.ts)
                tenancies.append(cur)
            if ident and ident[0] in STRONG:
                cur.strong.setdefault(ident[0], ident[1])
            cur.add(s)
        if splits:
            reused[ip] = splits
    return tenancies, reused


class DSU:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x


def resolve(sigs, shared_threshold=2, max_idle=86400):
    domain_names = set()
    for s in sigs:
        if s.signal == "domain":
            domain_names.add(s.value.split(".")[0][:15])
            domain_names.add(s.value[:15])

    shared_macs = find_shared_macs(sigs, shared_threshold)
    tenancies, reused = build_tenancies(sigs, shared_macs, domain_names, max_idle)

    n = len(tenancies)
    dsu = DSU(n)
    strong = [dict() for _ in range(n)]  # root -> {type: value}
    keys = [set() for _ in range(n)]
    for i, t in enumerate(tenancies):
        strong[i] = dict(t.strong)
        for s in t.sigs:
            ident = identity_of(s, shared_macs, domain_names)
            if ident:
                keys[i].add(ident)

    conflicts = []

    def union(a, b):
        ra, rb = dsu.find(a), dsu.find(b)
        if ra == rb:
            return
        for k in STRONG:
            va, vb = strong[ra].get(k), strong[rb].get(k)
            if va and vb and va != vb:
                conflicts.append((tenancies[a], tenancies[b], k, va, vb))
                return
        dsu.p[rb] = ra
        for k, v in strong[rb].items():
            strong[ra].setdefault(k, v)

    # 우선순위 높은 키부터 결합해야 약한 키(호스트명)가 잘못된 결합을 먼저 만들지 않는다.
    for ktype in KEY_PRIORITY[:-1]:
        owner = {}
        for i in range(n):
            for k in keys[i]:
                if k[0] != ktype:
                    continue
                if k in owner:
                    union(owner[k], i)
                else:
                    owner[k] = i

    groups = defaultdict(list)
    for i in range(n):
        groups[dsu.find(i)].append(tenancies[i])

    assets = [summarize(ts, shared_macs, domain_names) for ts in groups.values()]
    assets.sort(key=lambda a: (KEY_PRIORITY.index(a["id_type"]), a["hostname"] or "~", a["ips"][0]["ip"]))
    by_name = defaultdict(list)
    for a in assets:
        if a["hostname"]:
            by_name[host_key(a["hostname"])].append(a["asset_id"])
    return {
        "dup_hostnames": {k: v for k, v in sorted(by_name.items()) if len(v) > 1},
        "assets": assets,
        "shared_macs": shared_macs,
        "reused_ips": reused,
        "conflicts": conflicts,
    }


def best(counter_conf):
    """{value: (max_conf, count)} -> 신뢰도, 횟수 순 최상 값."""
    if not counter_conf:
        return ""
    return max(counter_conf.items(), key=lambda kv: (kv[1][0], kv[1][1]))[0]


def best_domain(domains):
    """'ahnbang'(NetBIOS)과 'ahnbang.ahnlab.com'(DNS)처럼 같은 도메인이면 DNS 형태를 고른다."""
    top = best(domains)
    if not top:
        return ""
    longer = [d for d in domains if d.split(".")[0] == top.split(".")[0] and len(d) > len(top)]
    return max(longer, key=len) if longer else top


def summarize(tenancies, shared_macs, domain_names):
    vals = defaultdict(dict)  # signal -> {value: (max_conf, count)}
    sources = Counter()
    l2_mac = False  # ARP/DHCP 등 L2에서 직접 확인한 MAC이 있는지
    os_cands = {}
    ips = []
    count = 0
    for t in tenancies:
        ips.append({"ip": t.ip, "first": t.first, "last": t.last})
        for s in t.sigs:
            count += 1
            sources[s.source] += 1
            v = s.value
            if s.signal == "mac" and s.source == "conn" and v in shared_macs:
                vals["via_gateway_mac"][v] = (0, 1)
                continue
            if s.signal == "mac" and s.source != "conn":
                l2_mac = True
            if s.signal == "hostname" and is_group_name(s, domain_names):
                continue
            if s.signal == "machine_account":
                v = machine_key(v)
            if s.signal == "os_hint":
                name = ntlm_os_name(v) if s.source == "ntlm" else v
                rank = (OS_SOURCE_RANK.get(s.source, 1), s.conf)
                if name not in os_cands or os_cands[name] < rank:
                    os_cands[name] = rank
                continue
            c, k = vals[s.signal].get(v, (0, 0))
            vals[s.signal][v] = (max(c, s.conf), k + 1)

    ips.sort(key=lambda x: x["first"])
    ports = set()
    for svc in vals.get("service", {}):
        parts = svc.split("/")
        if len(parts) >= 2:
            ports.add(parts[1])
    roles = [name for name, rule in ROLE_RULES if rule(ports)]
    if any(m in shared_macs for m in vals.get("mac", {})):
        roles.insert(0, "게이트웨이/라우터(추정)")
    # 프록시 포트를 열었거나, 서로 다른 서버 이름이 센서 상한(max_server_names)까지 몰린 IP
    if "3128" in ports or len(vals.get("dns_name", {})) >= 20:
        roles.insert(0, "프록시/로드밸런서(추정)")

    hostname = best(vals.get("hostname"))
    # 자기 신고 이름이 없으면 DNS 이름으로 표시만 한다(식별 키로는 쓰지 않음).
    display_name = hostname or (host_key(best(vals.get("dns_name"))) + " (dns)" if vals.get("dns_name") else "")
    id_type, id_value = "ip", "%s@%s" % (ips[0]["ip"], int(ips[0]["first"]))
    for k in KEY_PRIORITY[:-1]:
        if vals.get(k):
            id_type, id_value = k, best(vals[k])
            break
    if id_type == "hostname":
        id_value = host_key(id_value)
    confidence = KEY_CONFIDENCE[id_type]
    if id_type == "mac" and not l2_mac:
        # conn L2 주소로만 본 MAC: 공유 MAC 임계값 미만의 라우터 MAC일 가능성이 남는다.
        confidence = "낮음"

    os_list = sorted(os_cands, key=lambda k: os_cands[k], reverse=True)
    return {
        "asset_id": "A-" + hashlib.sha1(("%s|%s" % (id_type, id_value)).encode()).hexdigest()[:10],
        "id_type": id_type,
        "id_value": id_value,
        "confidence": confidence,
        "hostname": hostname,
        "display_name": display_name,
        "fqdn": best(vals.get("fqdn")),
        "domain": best_domain(vals.get("domain")),
        "machine_accounts": sorted(vals.get("machine_account", {})),
        "dhcp_client_ids": sorted(vals.get("dhcp_client_id", {})),
        "macs": sorted(vals.get("mac", {})),
        "via_gateway_mac": sorted(vals.get("via_gateway_mac", {})),
        "hostnames": sorted(vals.get("hostname", {}), key=lambda v: -vals["hostname"][v][0]),
        "dns_names": sorted(vals.get("dns_name", {})),
        "os": os_list[0] if os_list else "",
        "os_hints": os_list,
        "roles": roles,
        "services": sorted(vals.get("service", {}), key=lambda s: (s.split("/")[0], int(s.split("/")[1]) if s.split("/")[1].isdigit() else 0)),
        "users": sorted(vals.get("user_account", {})),
        "software": sorted(vals.get("software", {})),
        "dhcp_vendor_class": best(vals.get("dhcp_vendor_class")),
        "dhcp_fingerprint": best(vals.get("dhcp_fingerprint")),
        "ips": ips,
        "first_seen": min(i["first"] for i in ips),
        "last_seen": max(i["last"] for i in ips),
        "signal_count": count,
        "sources": dict(sources.most_common()),
    }


# ---------------------------------------------------------------- 출력

CSV_FIELDS = ["asset_id", "id_type", "id_value", "confidence", "display_name", "hostname", "fqdn", "domain",
              "os", "roles", "macs", "ips", "machine_accounts", "dhcp_client_ids", "users", "services",
              "dns_names", "via_gateway_mac", "first_seen", "last_seen", "signal_count", "sources"]


def ip_text(a, tz):
    return "; ".join("%s(%s~%s)" % (i["ip"], fmt_ts(i["first"], tz), fmt_ts(i["last"], tz)[11:])
                     for i in a["ips"])


def write_csv(path, assets, tz):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(CSV_FIELDS)
        for a in assets:
            row = []
            for k in CSV_FIELDS:
                v = a.get(k)
                if k == "ips":
                    v = ip_text(a, tz)
                elif k in ("first_seen", "last_seen"):
                    v = fmt_ts(v, tz)
                elif k == "sources":
                    v = " ".join("%s:%d" % kv for kv in v.items())
                elif isinstance(v, list):
                    v = " ".join(v)
                row.append(v)
            w.writerow(row)


def capture_health(zeek_dir):
    """conn.log로 미러 품질 점검: TCP 연결 중 양방향(요청+응답)이 보인 비율.
    history의 대문자는 연결 시작측, 소문자는 응답측 활동이다. JSON/TSV 둘 다 읽는다."""
    path = os.path.join(zeek_dir or "", "conn.log")
    if not zeek_dir or not os.path.isfile(path):
        return None
    tcp = both = orig_only = resp_only = 0
    fields = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if line[0] == "{":
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
            elif fields:
                d = dict(zip(fields, line.rstrip("\n").split("\t")))
            else:
                continue
            if d.get("proto") != "tcp":
                continue
            h = d.get("history") or ""
            tcp += 1
            up, low = any(c.isupper() for c in h), any(c.islower() for c in h)
            if up and low:
                both += 1
            elif up:
                orig_only += 1
            elif low:
                resp_only += 1
    if not tcp:
        return None
    return {"tcp": tcp, "both": both, "orig_only": orig_only, "resp_only": resp_only,
            "both_pct": round(100.0 * both / tcp, 1)}


# 양방향 비율이 이보다 낮으면 단방향 미러로 의심한다.
BIDIR_WARN_PCT = 50


def stats(result, sigs, zeek_dir, signal_path):
    assets = result["assets"]
    n = len(assets) or 1
    cov = lambda pred: sum(1 for a in assets if pred(a))
    coverage = [
        ("머신 계정", cov(lambda a: a["machine_accounts"])),
        ("DHCP client-id", cov(lambda a: a["dhcp_client_ids"])),
        ("MAC", cov(lambda a: a["macs"])),
        ("호스트명", cov(lambda a: a["hostname"])),
        ("도메인", cov(lambda a: a["domain"])),
        ("OS 추정", cov(lambda a: a["os"])),
        ("역할 추정", cov(lambda a: a["roles"])),
    ]
    vol = None
    if zeek_dir and os.path.isdir(zeek_dir):
        total = sum(os.path.getsize(os.path.join(zeek_dir, f)) for f in os.listdir(zeek_dir)
                    if f.endswith(".log") and f != os.path.basename(signal_path))
        if total:
            vol = (os.path.getsize(signal_path), total)
    return {
        "signal_count": len(sigs),
        "time_range": (sigs[0].ts, sigs[-1].ts) if sigs else (0, 0),
        "by_signal": Counter(s.signal for s in sigs).most_common(),
        "by_source": Counter(s.source for s in sigs).most_common(),
        "asset_count": len(assets),
        "by_id_type": [(KEY_LABEL[k], sum(1 for a in assets if a["id_type"] == k)) for k in KEY_PRIORITY],
        "coverage": [(k, v, 100.0 * v / n) for k, v in coverage],
        "volume": vol,
        "capture": capture_health(zeek_dir),
    }


def write_report(path, result, st, tz, src):
    out = []
    p = out.append
    rule = "=" * 78
    p(rule)
    p(" Zeek 자산 식별 PoC 리포트")
    p(rule)
    p("입력            : %s" % src)
    if st["signal_count"]:
        p("관측 구간       : %s ~ %s" % (fmt_ts(st["time_range"][0], tz), fmt_ts(st["time_range"][1], tz)))
    p("자산 신호 수    : %d" % st["signal_count"])
    if st["volume"]:
        sig_b, total_b = st["volume"]
        ratio = (100.0 * sig_b / total_b) if total_b else 0
        p("로그량          : asset_signal %s / Zeek 전체 로그 %s (%.1f%%)" % (hsize(sig_b), hsize(total_b), ratio))
    cap = st["capture"]
    if cap:
        p("캡처 품질       : TCP 연결 %d개 중 양방향 %.1f%% (요청만 %d, 응답만 %d)" % (
            cap["tcp"], cap["both_pct"], cap["orig_only"], cap["resp_only"]))
        if cap["both_pct"] < BIDIR_WARN_PCT:
            p("  ! 단방향 미러 의심: 응답(또는 요청) 패킷이 대부분 없음. 서비스/서버 응답 기반 신호")
            p("    (서비스, DNS 응답, NTLM CHALLENGE, SSH 서버 배너 등)가 수집되지 않는다.")
            p("    SPAN을 양방향(both/rx+tx)으로 설정하거나, TAP 두 포트를 mergecap으로 합쳐서 다시 측정 필요.")
    p("")
    p("[자산 요약]  총 %d개" % st["asset_count"])
    for label, c in st["by_id_type"]:
        p("  - 식별 키 %-15s: %d" % (label, c))
    p("")
    p("[키 커버리지]  (자산 중 해당 정보가 확인된 비율)")
    for label, c, pct in st["coverage"]:
        p("  %-15s %4d  %5.1f%%  %s" % (label, c, pct, "#" * int(pct / 5)))
    p("")
    p("[신호 종류별 건수]")
    p("  " + ", ".join("%s=%d" % kv for kv in st["by_signal"]))
    p("[출처별 건수]")
    p("  " + ", ".join("%s=%d" % kv for kv in st["by_source"]))
    p("")
    if result["shared_macs"]:
        p("[공유 MAC (게이트웨이/라우터 추정, 식별 키에서 제외)]")
        for m, ips in result["shared_macs"].items():
            p("  %s  <- IP %d개: %s" % (m, len(ips), ", ".join(ips[:8]) + (" ..." if len(ips) > 8 else "")))
        p("")
    if result["reused_ips"]:
        p("[IP 재사용 (점유 단말 변경)]")
        for ip, splits in result["reused_ips"].items():
            p("  %s  변경 시각: %s" % (ip, ", ".join(fmt_ts(t, tz) for t in splits)))
        p("")
    if result["dup_hostnames"]:
        p("[같은 호스트명, 다른 자산 (VM 복제/이미지 배포 또는 이름 재사용 의심)]")
        for name, ids in list(result["dup_hostnames"].items())[:20]:
            p("  %-20s 자산 %d개: %s" % (name, len(ids), ", ".join(ids[:5]) + (" ..." if len(ids) > 5 else "")))
        p("")
    if result["conflicts"]:
        p("[결합 보류 (같은 키를 공유하지만 강한 키 값이 달라 합치지 않음)]")
        for a, b, k, va, vb in result["conflicts"][:20]:
            p("  %s vs %s : %s %s != %s" % (a.ip, b.ip, k, va, vb))
        p("")
    p("[자산 목록]")
    widths = (13, 22, 20, 16, 18, 28)
    p(row_text(widths, ("asset_id", "식별 키(신뢰도)", "호스트명", "IP", "MAC", "OS"), "역할"))
    p("-" * 140)
    for a in result["assets"]:
        extra = ", ".join(a["roles"])
        cells = (a["asset_id"], "%s(%s)" % (KEY_LABEL[a["id_type"]], a["confidence"]), a["display_name"] or "-",
                 ",".join(i["ip"] for i in a["ips"]), a["macs"][0] if a["macs"] else "-", a["os"] or "-")
        p(row_text(widths, cells, extra))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    return "\n".join(out)


def disp_width(s):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def row_text(widths, cells, tail):
    out = []
    for w, c in zip(widths, cells):
        c = str(c)
        while disp_width(c) > w:
            c = c[:-1]
        out.append(c + " " * (w - disp_width(c)))
    return " ".join(out) + " " + tail


def hsize(b):
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return "%.1f%s" % (b, unit)
        b /= 1024.0
    return "%.1fTB" % b


def write_html(path, result, st, tz, src, sigs):
    by_asset_sigs = {}
    for a in result["assets"]:
        by_asset_sigs[a["asset_id"]] = []
    # 자산별 신호 타임라인: (ip, 구간) 매칭
    index = defaultdict(list)
    for a in result["assets"]:
        for i in a["ips"]:
            index[i["ip"]].append((i["first"], i["last"], a["asset_id"]))
    for s in sigs:
        for first, last, aid in index.get(s.ip, ()):
            if first <= s.ts <= last:
                by_asset_sigs[aid].append([fmt_ts(s.ts, tz), s.ip, s.signal, s.value, s.source, s.conf])
                break

    data = {
        "src": src,
        "generated": dt.datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S"),
        "stats": {
            "signal_count": st["signal_count"],
            "time_range": [fmt_ts(t, tz) for t in st["time_range"]] if st["signal_count"] else [],
            "asset_count": st["asset_count"],
            "by_id_type": st["by_id_type"],
            "coverage": st["coverage"],
            "by_signal": st["by_signal"],
            "by_source": st["by_source"],
            "capture": st["capture"],
            "bidir_warn_pct": BIDIR_WARN_PCT,
            "volume": [hsize(v) for v in st["volume"]] + [round(100.0 * st["volume"][0] / st["volume"][1], 1) if st["volume"][1] else 0] if st["volume"] else None,
        },
        "shared_macs": result["shared_macs"],
        "reused_ips": {ip: [fmt_ts(t, tz) for t in v] for ip, v in result["reused_ips"].items()},
        "dup_hostnames": result["dup_hostnames"],
        "assets": [dict(a, ips_text=ip_text(a, tz), id_label=KEY_LABEL[a["id_type"]],
                        first_seen=fmt_ts(a["first_seen"], tz), last_seen=fmt_ts(a["last_seen"], tz),
                        ips=[dict(i, first=fmt_ts(i["first"], tz), last=fmt_ts(i["last"], tz)) for i in a["ips"]])
                   for a in result["assets"]],
        "signals": by_asset_sigs,
    }
    tpl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report_template.html")
    with open(tpl_path, encoding="utf-8") as f:
        tpl = f.read()
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    with open(path, "w", encoding="utf-8") as f:
        f.write(tpl.replace("/*__DATA__*/null", payload).replace("__TITLE__", html.escape(os.path.basename(src))))


def main(argv=None):
    ap = argparse.ArgumentParser(description="asset_signal.log 로 자산을 판정하고 리포트를 만든다.")
    ap.add_argument("signal_log", help="Zeek asset_signal.log (JSON)")
    ap.add_argument("-o", "--out-dir", default=".", help="출력 디렉터리 (기본: 현재)")
    ap.add_argument("-z", "--zeek-dir", help="Zeek 로그 디렉터리 (로그량 비교용, 기본: signal_log 위치)")
    ap.add_argument("--shared-mac-threshold", type=int, default=2,
                    help="conn 출처 MAC이 이 개수 이상의 IP에 보이면 공유 MAC으로 판단 (기본 2)")
    ap.add_argument("--max-idle", type=float, default=24, help="IP 신호가 이 시간(시) 이상 끊기면 새 점유 구간 (기본 24)")
    ap.add_argument("--tz", type=float, default=9, help="표시 시간대 UTC 오프셋(시) (기본 9 = KST)")
    ap.add_argument("-q", "--quiet", action="store_true", help="터미널에 리포트를 출력하지 않음")
    args = ap.parse_args(argv)

    tz = dt.timezone(dt.timedelta(hours=args.tz))
    sigs = load_signals(args.signal_log)
    result = resolve(sigs, args.shared_mac_threshold, args.max_idle * 3600)

    os.makedirs(args.out_dir, exist_ok=True)
    zeek_dir = args.zeek_dir or os.path.dirname(os.path.abspath(args.signal_log))
    st = stats(result, sigs, zeek_dir, args.signal_log)

    write_csv(os.path.join(args.out_dir, "assets.csv"), result["assets"], tz)
    with open(os.path.join(args.out_dir, "assets.json"), "w", encoding="utf-8") as f:
        json.dump(result["assets"], f, ensure_ascii=False, indent=1)
    text = write_report(os.path.join(args.out_dir, "report.txt"), result, st, tz, args.signal_log)
    write_html(os.path.join(args.out_dir, "report.html"), result, st, tz, args.signal_log, sigs)
    if not args.quiet:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
