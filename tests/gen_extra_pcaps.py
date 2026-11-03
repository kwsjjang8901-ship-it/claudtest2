#!/usr/bin/env python3
"""장비·제품 식별 신호 회귀 테스트용 합성 pcap 생성기.

운영 pcap(eth5)에서 확인한 형식을 재현한다.
  - syslog: VMware ESXi(ISO 시각), Cisco ASA, Cisco IOS(RFC 3164), FortiGate(key=value),
            UTM(백틱 구분), RFC 5424
  - HTTP User-Agent: AhnLab 제품(v3inet4/버전/제품코드/, MeDCore), git, Microsoft NCSI, 브라우저
  - TLS 1.2 서버 인증서: CN=AhnLab MDS(자체 서명), VMware(SAN 호스트 이름)

사용법:
  pip install scapy cryptography
  python3 tests/gen_extra_pcaps.py tests/pcaps/extras.pcap
"""

import datetime as dt
import random
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
from scapy.layers.tls.all import (TLS, TLSCertificate, TLSChangeCipherSpec, TLSClientHello,
                                  TLSServerHello, TLSServerHelloDone)
from scapy.layers.tls.cert import Cert

T0 = dt.datetime(2026, 11, 3, 9, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=9))).timestamp()
MAC = "00:50:56:00:00:%02x"
rng = random.Random(11)
pkts = []


def at(t, p):
    p.time = T0 + t
    pkts.append(p)


def mac(ip):
    return MAC % int(ip.split(".")[-1])


def syslog(t, src, dst, msg, pri=166):
    at(t, Ether(src=mac(src), dst=mac(dst)) / IP(src=src, dst=dst) / UDP(sport=514, dport=514)
       / Raw(("<%d>%s" % (pri, msg)).encode()))


def tcp_exchange(t, cli, srv, dport, msgs):
    """3-way handshake 후 msgs = [('c'|'s', bytes)] 순서대로 주고받는다."""
    sport = rng.randint(49152, 65000)
    seq = {"c": rng.randint(1, 2**31), "s": rng.randint(1, 2**31)}
    ep = {"c": (cli, sport), "s": (srv, dport)}

    def pkt(d, flags, data=b""):
        o = "s" if d == "c" else "c"
        p = (Ether(src=mac(ep[d][0]), dst=mac(ep[o][0])) / IP(src=ep[d][0], dst=ep[o][0])
             / TCP(sport=ep[d][1], dport=ep[o][1], flags=flags, seq=seq[d], ack=seq[o]))
        return p / Raw(data) if data else p

    at(t, Ether(src=mac(cli), dst=mac(srv)) / IP(src=cli, dst=srv)
       / TCP(sport=sport, dport=dport, flags="S", seq=seq["c"] - 1))
    at(t + 0.001, pkt("s", "SA"))
    seq["s"] += 1
    at(t + 0.002, pkt("c", "A"))
    for i, (d, data) in enumerate(msgs):
        at(t + 0.003 + i * 0.001, pkt(d, "PA", data))
        seq[d] += len(data)


def http_get(t, cli, srv, host, ua):
    req = ("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n" % (host, ua)).encode()
    tcp_exchange(t, cli, srv, 80, [("c", req), ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])


def make_cert(subject, issuer=None, san=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name(subject)
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(x509.Name(issuer or subject))
         .public_key(key.public_key()).serial_number(1000 + len(pkts))
         .not_valid_before(dt.datetime(2026, 1, 1)).not_valid_after(dt.datetime(2030, 1, 1)))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    der = b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    return Cert(der)


def tls12(t, cli, srv, cert, dport=443):
    ch = TLS(version=0x0303, msg=[TLSClientHello(version=0x0303, ciphers=[0xC02B])])
    sh = TLS(version=0x0303, msg=[TLSServerHello(version=0x0303, cipher=0xC02B),
                                  TLSCertificate(certs=[cert]), TLSServerHelloDone()])
    ccs = TLS(version=0x0303, msg=[TLSChangeCipherSpec()])
    tcp_exchange(t, cli, srv, dport, [("c", bytes(ch)), ("s", bytes(sh)), ("c", bytes(ccs)), ("s", bytes(ccs))])


def build():
    collector = "10.30.0.5"
    syslog(1, "10.30.1.20", collector, "2026-11-03T00:00:01.123Z esx01.lab.corp Vpxa: verbose vpxa[2101] heartbeat")
    syslog(2, "10.30.1.21", collector, "Nov 03 2026 09:00:02: %ASA-4-106023: Deny tcp src inside:10.30.9.9/5000 dst outside:1.1.1.1/80")
    syslog(3, "10.30.1.22", collector, "Nov  3 09:00:03 core-sw01 %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to up")
    syslog(4, "10.30.1.23", collector, 'date=2026-11-03 time=09:00:04 devname="FGT-HQ01" devid="FG100FTK00000000" type="traffic"')
    syslog(5, "10.30.1.24", collector, "1`0`1`1`a12ece`2026`20261103`09:00:05`1`1`UTM_OUT`allow")
    syslog(6, "10.30.1.25", collector, "1 2026-11-03T00:00:06Z app-srv01.lab.corp sshd 811 - - Accepted publickey", pri=38)
    # 시각만 있고 호스트명 자리에 IP가 오는 형식 -> 호스트명으로 쓰지 않는다
    syslog(7, "10.30.1.26", collector, "Nov  3 09:00:07 10.30.1.26 kernel: link up")

    web = "10.30.2.10"
    http_get(10, "10.30.3.11", web, "update.example", "v3inet4/5.6.0.55/V3ES90ASD/")
    http_get(11, "10.30.3.12", web, "update.example", "v3inet4/5.6.0.55/EDRCLIENT/")
    http_get(12, "10.30.3.13", web, "gms.example", "MeDCore")
    http_get(13, "10.30.3.14", web, "repo.example", "git/2.52.0 (Linux)")
    http_get(14, "10.30.3.15", web, "www.msftconnecttest.com", "Microsoft NCSI")
    http_get(15, "10.30.3.16", web, "portal.example",
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36")

    mds = make_cert([x509.NameAttribute(NameOID.COMMON_NAME, "AhnLab MDS"),
                     x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AhnLab, Inc.")])
    vc = make_cert([x509.NameAttribute(NameOID.COMMON_NAME, "10.30.4.11"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VMware")],
                   san=["vcsa01.lab.corp", "*.lab.corp"])
    tls12(20, "10.30.3.11", "10.30.4.10", mds, dport=8006)
    tls12(21, "10.30.3.11", "10.30.4.11", vc)

    pkts.sort(key=lambda p: p.time)
    return pkts


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "tests/pcaps/extras.pcap"
    wrpcap(out, build())
    print("wrote %d packets -> %s" % (len(pkts), out))
