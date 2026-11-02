#!/usr/bin/env python3
"""PoC 데모용 합성 pcap 생성기.

자산 식별에서 확인해야 할 상황을 한 파일에 담는다.

  - DHCP DORA (client-id, 호스트명, FQDN, vendor class, 파라미터 지문)
  - Kerberos AS-REQ 머신 계정 / 사용자 계정
  - NBNS 이름 등록, LLMNR 응답, mDNS 프로브/응답
  - DNS A/PTR 응답 (dns_name)
  - HTTP User-Agent, SSH 배너, 서비스(DC, 웹, 프린터)
  - DHCP IP 재사용: 같은 IP를 시간차로 다른 단말이 할당받음 (자산 2개여야 함)
  - 라우팅 구간: 원격 대역 IP들이 게이트웨이 MAC으로 보임 (공유 MAC)
  - CLDAP Netlogon ping(DC 찾기), 사내 서버 이름(TLS SNI, HTTP Host)
  - NTLM: Zeek 테스트 trace(raw_ntlm_in_smb.pcap)가 있으면 IP/MAC을 바꿔 섞음

사용법:
  pip install scapy
  python3 tests/gen_demo_pcap.py tests/pcaps/demo.pcap [--ntlm-trace raw_ntlm_in_smb.pcap]
"""

import argparse
import datetime as dt
import random

from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, rdpcap, wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.kerberos import KRB_AS_REQ, KRB_KDC_REQ_BODY, Kerberos, PrincipalName
from scapy.layers.netbios import NBNSHeader, NBNSRegistrationRequest
from scapy.layers.ldap import (LDAP, LDAP_Filter, LDAP_FilterAnd, LDAP_FilterEqual, LDAP_SearchRequest,
                               LDAP_SearchRequestAttribute)
from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, ServerName
from scapy.asn1.asn1 import ASN1_GENERAL_STRING, ASN1_GENERALIZED_TIME, ASN1_INTEGER, ASN1_STRING

BCAST = "ff:ff:ff:ff:ff:ff"
T0 = dt.datetime(2026, 10, 30, 9, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=9))).timestamp()

GW = ("10.10.0.1", "00:00:5e:00:01:01")
DC = ("10.10.1.10", "00:50:56:aa:10:10")
WEB = ("10.10.1.20", "52:54:00:12:34:56")
PRN = ("10.10.2.50", "00:1b:a9:77:88:99")
HR01 = ("10.10.0.101", "3c:52:82:11:22:33")
MAC_DEV = ("10.10.0.102", "a4:83:e7:44:55:66")
DEV02 = ("10.10.0.150", "3c:52:82:aa:bb:cc")
LAPTOP = ("10.10.0.120", "00:21:cc:01:02:03")
PHONE = ("10.10.0.120", "02:1a:11:fe:dc:ba")
INTERNET = "93.184.215.14"
REMOTE = ["10.20.5.%d" % i for i in range(11, 16)]
NTLM_CLIENT = "10.20.5.13"
NTLM_SERVER = ("10.10.1.30", "00:50:56:aa:30:30")
PROXY = ("10.10.1.40", "00:50:56:aa:40:40")

pkts = []
rng = random.Random(7)


def at(offset_sec, pkt):
    pkt.time = T0 + offset_sec
    pkts.append(pkt)


def eth(src, dst):
    return Ether(src=src, dst=dst)


def tcp_session(t, cli, cli_mac, srv, srv_mac, dport, c2s=b"", s2c=b"", sport=None):
    """3-way handshake + 선택적 데이터 교환."""
    sport = sport or rng.randint(49152, 65000)
    cseq, sseq = rng.randint(1, 2**31), rng.randint(1, 2**31)
    c = lambda: eth(cli_mac, srv_mac) / IP(src=cli, dst=srv)
    s = lambda: eth(srv_mac, cli_mac) / IP(src=srv, dst=cli)
    at(t, c() / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
    at(t + 0.001, s() / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
    at(t + 0.002, c() / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
    cseq, sseq = cseq + 1, sseq + 1
    if s2c and not c2s:  # 서버가 먼저 말하는 프로토콜(SSH)
        at(t + 0.003, s() / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(s2c))
        sseq += len(s2c)
        s2c = b""
    if c2s:
        at(t + 0.004, c() / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(c2s))
        cseq += len(c2s)
    if s2c:
        at(t + 0.005, s() / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(s2c))
        sseq += len(s2c)
    at(t + 0.006, c() / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
    at(t + 0.007, s() / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))
    at(t + 0.008, c() / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))


def dhcp_dora(t, mac, ip, hostname, vendor=None, fqdn=None, params=(1, 3, 6, 15), xid=None):
    xid = xid or rng.randint(1, 2**31)
    chaddr = bytes.fromhex(mac.replace(":", ""))
    client_id = b"\x01" + chaddr
    req_opts = [("client_id", client_id), ("hostname", hostname.encode())]
    if vendor:
        req_opts.append(("vendor_class_id", vendor.encode()))
    if fqdn:
        req_opts.append(("client_FQDN", b"\x00\x00\x00" + fqdn.encode()))
    req_opts.append(("param_req_list", list(params)))

    def cli(msg_type, extra):
        return (eth(mac, BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
                / BOOTP(op=1, chaddr=chaddr, xid=xid, flags=0x8000)
                / DHCP(options=[("message-type", msg_type)] + extra + req_opts + ["end"]))

    def srv(msg_type):
        return (eth(DC[1], BCAST) / IP(src=DC[0], dst="255.255.255.255") / UDP(sport=67, dport=68)
                / BOOTP(op=2, chaddr=chaddr, xid=xid, yiaddr=ip, siaddr=DC[0])
                / DHCP(options=[("message-type", msg_type), ("server_id", DC[0]),
                                ("lease_time", 14400), ("subnet_mask", "255.255.0.0"),
                                ("router", GW[0]), ("name_server", DC[0]),
                                ("domain", b"corp.local"), "end"]))

    at(t, cli("discover", []))
    at(t + 0.01, srv("offer"))
    at(t + 0.02, cli("request", [("requested_addr", ip), ("server_id", DC[0])]))
    at(t + 0.03, srv("ack"))
    # 할당 직후 gratuitous ARP
    at(t + 0.5, eth(mac, BCAST) / ARP(op=1, hwsrc=mac, psrc=ip, pdst=ip))


def arp_reply(t, ip, mac, to_ip, to_mac):
    at(t, eth(mac, to_mac) / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=to_mac, pdst=to_ip))


def krb_as_req(t, cli, cli_mac, principal, realm="CORP.LOCAL"):
    body = KRB_KDC_REQ_BODY(
        kdcOptions="forwardable+renewable+canonicalize",
        cname=PrincipalName(nameType=ASN1_INTEGER(1), nameString=[ASN1_GENERAL_STRING(principal)]),
        realm=ASN1_GENERAL_STRING(realm),
        sname=PrincipalName(nameType=ASN1_INTEGER(2),
                            nameString=[ASN1_GENERAL_STRING("krbtgt"), ASN1_GENERAL_STRING(realm)]),
        till=ASN1_GENERALIZED_TIME("20370913024805Z"),
        nonce=ASN1_INTEGER(rng.randint(1, 2**31)),
        etype=[ASN1_INTEGER(18), ASN1_INTEGER(17), ASN1_INTEGER(23)],
    )
    req = Kerberos(root=KRB_AS_REQ(reqBody=body))
    at(t, eth(cli_mac, DC[1]) / IP(src=cli, dst=DC[0]) / UDP(sport=rng.randint(49152, 65000), dport=88) / req)


def nbns_register(t, ip, mac, name, suffix, group=False):
    at(t, eth(mac, BCAST) / IP(src=ip, dst="10.10.255.255") / UDP(sport=137, dport=137)
       / NBNSHeader(OPCODE=5, NM_FLAGS=0x11, QDCOUNT=1, ARCOUNT=1, NAME_TRN_ID=rng.randint(1, 65535))
       / NBNSRegistrationRequest(QUESTION_NAME=name, SUFFIX=suffix,
                                 G=1 if group else 0, NB_ADDRESS=ip))


def dns_answer(t, cli, cli_mac, qname, rrs, qtype="A", srv=DC, sport=53, dport=None, dst=None,
               src=None, src_mac=None, dst_mac=None):
    tid = rng.randint(1, 65535)
    cport = dport or rng.randint(49152, 65000)
    q = DNS(id=tid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    at(t, eth(cli_mac, dst_mac or srv[1]) / IP(src=cli, dst=dst or srv[0]) / UDP(sport=cport, dport=sport) / q)
    r = DNS(id=tid, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=qname, qtype=qtype), an=rrs)
    at(t + 0.002, eth(src_mac or srv[1], cli_mac) / IP(src=src or srv[0], dst=cli)
       / UDP(sport=sport, dport=cport) / r)


def proxy_session(t, cli, cli_mac, payloads, dport=3128):
    """프록시 연결: payloads = [(방향 'c'|'s', bytes), ...] 순서대로 주고받는다."""
    sport = rng.randint(49152, 65000)
    seq = {"c": rng.randint(1, 2**31), "s": rng.randint(1, 2**31)}
    ends = {"c": (cli, cli_mac, sport), "s": (PROXY[0], PROXY[1], dport)}

    def pkt(d, flags, data=b""):
        o = "s" if d == "c" else "c"
        (sip, smac, sp), (dip, dmac, dp) = ends[d], ends[o]
        p = eth(smac, dmac) / IP(src=sip, dst=dip) / TCP(sport=sp, dport=dp, flags=flags, seq=seq[d], ack=seq[o])
        return p / Raw(data) if data else p

    at(t, eth(cli_mac, PROXY[1]) / IP(src=cli, dst=PROXY[0]) / TCP(sport=sport, dport=dport, flags="S", seq=seq["c"] - 1))
    at(t + 0.001, pkt("s", "SA"))
    seq["s"] += 1
    at(t + 0.002, pkt("c", "A"))
    for i, (d, data) in enumerate(payloads):
        at(t + 0.003 + i * 0.001, pkt(d, "PA", data))
        seq[d] += len(data)


def cldap_netlogon(t, cli, cli_mac, host, domain="corp.local", user=True):
    """DC 찾기 Netlogon ping: (&(DnsDomain=..)(Host=..)(User=HOST$)(NtVer=..)) 를 CLDAP(udp/389)로."""
    def eq(a, v):
        return LDAP_Filter(filter=LDAP_FilterEqual(attributeType=ASN1_STRING(a), attributeValue=ASN1_STRING(v)))
    flt = LDAP_Filter(filter=LDAP_FilterAnd(vals=[
        eq(b"DnsDomain", domain.encode()), eq(b"Host", host.encode())]
        + ([eq(b"User", host.encode() + b"$")] if user else []) + [eq(b"NtVer", b"\x16\x00\x00\x20")]))
    req = LDAP(messageID=rng.randint(1, 1000), protocolOp=LDAP_SearchRequest(
        baseObject=b"", scope=0, filter=flt,
        attributes=[LDAP_SearchRequestAttribute(type=ASN1_STRING(b"Netlogon"))]))
    at(t, eth(cli_mac, DC[1]) / IP(src=cli, dst=DC[0]) / UDP(sport=rng.randint(49152, 65000), dport=389)
       / Raw(bytes(req)))


def tls_hello(t, cli, cli_mac, srv, srv_mac, sni):
    hello = TLS(msg=[TLSClientHello(ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())])])])
    tcp_session(t, cli, cli_mac, srv, srv_mac, 443, bytes(hello))


def http_get(t, cli, cli_mac, ua, host="example.com"):
    req = ("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n" % (host, ua)).encode()
    rsp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"
    tcp_session(t, cli, cli_mac, INTERNET, GW[1], 80, req, rsp)


def mix_ntlm_trace(path, t):
    """Zeek 테스트 trace의 SMB/NTLM 세션을 데모 대역으로 옮겨 섞는다(라우팅 구간 클라이언트)."""
    ipmap = {"192.168.56.1": NTLM_CLIENT, "192.168.56.101": NTLM_SERVER[0]}
    macmap = {NTLM_CLIENT: GW[1], NTLM_SERVER[0]: NTLM_SERVER[1]}
    src = rdpcap(path)
    base = float(src[0].time)
    for p in src:
        if IP not in p or p[IP].src not in ipmap or p[IP].dst not in ipmap:
            continue
        p = p.copy()
        p[IP].src, p[IP].dst = ipmap[p[IP].src], ipmap[p[IP].dst]
        p[Ether].src, p[Ether].dst = macmap[p[IP].src], macmap[p[IP].dst]
        del p[IP].chksum
        if TCP in p:
            del p[TCP].chksum
        at(t + float(p.time) - base, p)


def build(ntlm_trace=None):
    m = 60
    ua_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
    ua_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
    ua_android = "Mozilla/5.0 (Linux; Android 14; SM-S921N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36"

    # 인프라: 게이트웨이, DC, 웹서버, 프린터 (고정 IP)
    arp_reply(1, GW[0], GW[1], DC[0], DC[1])
    arp_reply(2, DC[0], DC[1], GW[0], GW[1])
    arp_reply(3, WEB[0], WEB[1], GW[0], GW[1])
    arp_reply(4, PRN[0], PRN[1], GW[0], GW[1])

    # WIN10-HR01: 도메인 가입 Windows PC
    dhcp_dora(10, HR01[1], HR01[0], "WIN10-HR01", vendor="MSFT 5.0", fqdn="win10-hr01.corp.local",
              params=(1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252))
    nbns_register(12, HR01[0], HR01[1], "WIN10-HR01", 0x4141)        # <00>
    nbns_register(12.1, HR01[0], HR01[1], "WIN10-HR01", 0x4341)      # <20>
    nbns_register(12.2, HR01[0], HR01[1], "CORP", 0x4141, group=True)  # <00> 그룹
    nbns_register(12.3, HR01[0], HR01[1], "CORP", 0x424f, group=True)  # <1e>
    krb_as_req(15, HR01[0], HR01[1], "WIN10-HR01$")
    krb_as_req(5 * m, HR01[0], HR01[1], "kim.hr")
    tcp_session(5 * m + 5, HR01[0], HR01[1], DC[0], DC[1], 445)
    tcp_session(5 * m + 6, HR01[0], HR01[1], DC[0], DC[1], 389)
    tcp_session(5 * m + 7, HR01[0], HR01[1], DC[0], DC[1], 88)
    tcp_session(5 * m + 8, HR01[0], HR01[1], DC[0], DC[1], 135)
    dns_answer(6 * m, HR01[0], HR01[1], "dc01.corp.local", DNSRR(rrname="dc01.corp.local", type="A", rdata=DC[0]))
    dns_answer(6 * m + 1, HR01[0], HR01[1], "20.1.10.10.in-addr.arpa",
               DNSRR(rrname="20.1.10.10.in-addr.arpa", type="PTR", rdata="srv-web01.corp.local"), qtype="PTR")
    http_get(7 * m, HR01[0], HR01[1], ua_win)
    tcp_session(8 * m, HR01[0], HR01[1], PRN[0], PRN[1], 9100, b"\x1b%-12345X@PJL\r\n")
    tcp_session(9 * m, HR01[0], HR01[1], WEB[0], WEB[1], 443)
    tcp_session(9 * m + 1, HR01[0], HR01[1], WEB[0], WEB[1], 22,
                c2s=b"SSH-2.0-PuTTY_Release_0.81\r\n", s2c=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n")

    # macbook-dev: macOS (mDNS)
    dhcp_dora(20, MAC_DEV[1], MAC_DEV[0], "macbook-dev", params=(1, 121, 3, 6, 15, 119, 252, 95, 44, 46))
    dns_answer(21, MAC_DEV[0], MAC_DEV[1], "macbook-dev.local", [], qtype="ALL", sport=5353, dport=5353,
               dst="224.0.0.251", dst_mac="01:00:5e:00:00:fb", src=MAC_DEV[0], src_mac=MAC_DEV[1])
    at(22, eth(MAC_DEV[1], "01:00:5e:00:00:fb") / IP(src=MAC_DEV[0], dst="224.0.0.251") / UDP(sport=5353, dport=5353)
       / DNS(qr=1, aa=1, an=DNSRR(rrname="macbook-dev.local", type="A", rdata=MAC_DEV[0], ttl=120)))
    http_get(10 * m, MAC_DEV[0], MAC_DEV[1], ua_mac)

    # WIN10-DEV02: 고정 IP Windows (DHCP 없음) - LLMNR 응답 + Kerberos 머신 계정
    at(30, eth(HR01[1], "01:00:5e:00:00:fc") / IP(src=HR01[0], dst="224.0.0.252") / UDP(sport=55001, dport=5355)
       / DNS(id=0x1234, qd=DNSQR(qname="win10-dev02")))
    at(30.01, eth(DEV02[1], HR01[1]) / IP(src=DEV02[0], dst=HR01[0]) / UDP(sport=5355, dport=55001)
       / DNS(id=0x1234, qr=1, qd=DNSQR(qname="win10-dev02"),
             an=DNSRR(rrname="win10-dev02", type="A", rdata=DEV02[0], ttl=30)))
    krb_as_req(40, DEV02[0], DEV02[1], "WIN10-DEV02$")
    http_get(11 * m, DEV02[0], DEV02[1], ua_win)

    # DHCP IP 재사용: 같은 10.10.0.120을 노트북(오전) -> 휴대폰(4시간 후)
    dhcp_dora(50, LAPTOP[1], LAPTOP[0], "LAPTOP-SALES07", vendor="MSFT 5.0",
              params=(1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252))
    http_get(12 * m, LAPTOP[0], LAPTOP[1], ua_win)
    dhcp_dora(4 * 3600 + 30, PHONE[1], PHONE[0], "Galaxy-S24", vendor="android-dhcp-14",
              params=(1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108))
    http_get(4 * 3600 + 60, PHONE[0], PHONE[1], ua_android)

    # 라우팅 구간: 원격 대역 PC들이 DC에 접속 (출발지 MAC = 게이트웨이 MAC)
    for i, rip in enumerate(REMOTE):
        tcp_session(13 * m + i, rip, GW[1], DC[0], DC[1], 445)

    if ntlm_trace:
        mix_ntlm_trace(ntlm_trace, 14 * m)

    # 라우팅 구간 PC의 DC 찾기 (출발지 MAC = 게이트웨이) -> 호스트명/도메인/머신 계정
    cldap_netlogon(15 * m, "10.20.5.11", GW[1], "BRANCH-PC11")
    # 사내 서버 이름: TLS SNI, HTTP Host
    tls_hello(16 * m, HR01[0], HR01[1], WEB[0], WEB[1], "portal.corp.local")
    req = b"GET / HTTP/1.1\r\nHost: intranet.corp.local\r\nUser-Agent: curl/8.5.0\r\n\r\n"
    tcp_session(16 * m + 5, HR01[0], HR01[1], WEB[0], WEB[1], 80, req, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    # User 없는 Netlogon ping -> Host$ 를 머신 계정으로
    cldap_netlogon(17 * m, "10.20.5.12", GW[1], "BRANCH-PC12", user=False)
    # 프록시 경유 요청: 외부 사이트 이름(Host/SNI)이 프록시의 서버 이름으로 붙으면 안 된다
    hello = TLS(msg=[TLSClientHello(ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"www.example.com")])])])
    proxy_session(18 * m, HR01[0], HR01[1], [
        ("c", b"CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n"),
        ("s", b"HTTP/1.1 200 Connection established\r\n\r\n"),
        ("c", bytes(hello))])
    proxy_session(18 * m + 5, HR01[0], HR01[1], [
        ("c", b"GET http://news.example.com/ HTTP/1.1\r\nHost: news.example.com\r\n\r\n"),
        ("s", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])

    pkts.sort(key=lambda p: p.time)
    return pkts


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--ntlm-trace", help="Zeek testing/btest/Traces/smb/raw_ntlm_in_smb.pcap 경로")
    args = ap.parse_args()
    wrpcap(args.out, build(args.ntlm_trace))
    print("wrote %d packets -> %s" % (len(pkts), args.out))


if __name__ == "__main__":
    main()
