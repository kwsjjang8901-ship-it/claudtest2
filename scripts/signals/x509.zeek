##! 서버 인증서 신호: TLS 서버가 보낸 인증서(leaf)의 이름과 제품/장비 종류.
##!
##! 사내 서버는 IP로 접속하는 경우가 많아 SNI가 비는데, 인증서에는 이름이나 제품명이 남는다.
##!   CN/SAN의 호스트 이름          -> dns_name (서버 이름 신호와 같은 상한·프록시 제외 적용)
##!   "CN=AhnLab MDS", VMware 인증서 -> device
##! TLS 1.3은 인증서가 암호화되어 보이지 않는다.

@load base/protocols/ssl
@load base/files/x509
@load ./server_names
@load ../main

module AssetID;

## 인증서 주체/발급자 문자열로 제품·장비 종류.
function x509_device(subject: string, issuer: string): string
	{
	local s = subject + " " + issuer;

	if ( /CN=AhnLab MDS/ in subject )
		return "ahnlab-mds";
	if ( /CN=AhnLab EPP/ in subject )
		return "ahnlab-epp";
	if ( /VMware|vmca@vmware\.com/ in s )
		return "vmware";
	if ( /Fortinet|FortiGate/ in s )
		return "fortinet";
	if ( /Palo Alto Networks/ in s )
		return "paloalto";
	if ( /iDRAC/ in s )
		return "dell-idrac";
	if ( /iLO/ in s )
		return "hpe-ilo";
	if ( /Synology/ in s )
		return "synology";

	return "";
	}

## 인증서 이름이 서버 호스트 이름으로 쓸 만한지(와일드카드, IP, localhost, 공백 포함 제외).
function x509_name_ok(n: string): bool
	{
	return /\./ in n && /[ *]/ !in n && ! is_valid_ip(n) && /^localhost/ !in n;
	}

## 이미 인증서를 확인한 연결 uid.
global x509_done: set[string] &create_expire=1hr;

function x509_from_conn(c: connection)
	{
	if ( ! enable_x509 || c$uid in x509_done || ! c?$ssl || ! c$ssl?$cert_chain ||
	     |c$ssl$cert_chain| == 0 )
		return;

	local leaf = c$ssl$cert_chain[0];
	if ( ! leaf?$x509 )
		return;

	add x509_done[c$uid];

	local cert = leaf$x509$certificate;
	local ip = c$id$resp_h;

	emit(ip, DEVICE, x509_device(cert$subject, cert$issuer), "x509", 70, c$uid);

	if ( cert?$cn && x509_name_ok(normalize_name(cert$cn)) )
		server_name(ip, cert$cn, "x509", c$uid);

	if ( leaf$x509?$san && leaf$x509$san?$dns )
		for ( _, n in leaf$x509$san$dns )
			if ( x509_name_ok(normalize_name(n)) )
				server_name(ip, n, "x509", c$uid);
	}

event ssl_established(c: connection)
	{
	x509_from_conn(c);
	}

# 핸드셰이크 끝이 캡처되지 않은 연결(캡처 시작/종료 경계 등)도 인증서는 받았을 수 있다.
event connection_state_remove(c: connection)
	{
	x509_from_conn(c);
	}
