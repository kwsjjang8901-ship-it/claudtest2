##! 이름 신호: NBNS(137), LLMNR(5355), mDNS(5353), 일반 DNS(53).
##!
##! - NBNS 등록/갱신 요청: 송신자가 자기 이름을 등록 -> hostname / domain(워크그룹)
##! - NBNS/LLMNR/mDNS 응답: 응답자가 자기 이름에 대한 A/AAAA 응답 -> hostname
##! - mDNS PTR(역방향) 응답 -> hostname
##!   (mDNS 프로브는 기록하지 않음: 이름 충돌 중인 후보 이름까지 나와서 오염된다)
##! - 일반 DNS PTR/A 응답 -> dns_name (별칭일 수 있어 식별 키로 쓰지 않음)

@load base/protocols/dns
@load ../main

module AssetID;

const NBNS_PORT = 137/udp;
const LLMNR_PORT = 5355/udp;
const MDNS_PORT = 5353/udp;
const DNS_PORTS = { 53/udp, 53/tcp };

function on_port(c: connection, p: port): bool
	{
	return c$id$orig_p == p || c$id$resp_p == p;
	}

## mDNS 호스트 이름(<host>.local)에서 단축 호스트명.
## 서비스 인스턴스 이름("has01(3)._smb._tcp.local" 등)은 호스트명이 아니므로 제외한다.
function mdns_host(name: string): string
	{
	local n = normalize_name(name);

	if ( /^[^._][^.]*\.local$/ !in n )
		return "";

	return split_string1(n, /\./)[0];
	}

## NBNS 인코딩 이름 -> (이름, suffix). 실패 시 이름은 빈 문자열.
function nbns_decode(encoded: string): vector of string
	{
	local label = to_upper(split_string1(encoded, /\./)[0]);
	local name = normalize_name(decode_netbios_name(label));
	local suffix = decode_netbios_name_type(label);

	return vector(name, cat(suffix));
	}

## NetBIOS suffix 에 따라 hostname 또는 domain(워크그룹)으로 기록.
## <20> 서버 서비스 -> 호스트명 확실, <00> 은 워크스테이션/워크그룹 공용이라 낮은 신뢰도,
## <1b>/<1c>/<1d>/<1e> 는 도메인/워크그룹 그룹 이름.
function nbns_emit(ip: addr, encoded: string, uid: string)
	{
	local d = nbns_decode(encoded);
	local name = d[0];
	local suffix = to_count(d[1]);

	if ( name == "" || name == "*" )
		return;

	if ( suffix == 0x20 )
		emit(ip, HOSTNAME, name, "nbns", 75, uid);
	else if ( suffix == 0x00 )
		emit(ip, HOSTNAME, name, "nbns", 50, uid);
	else if ( suffix == 0x1b || suffix == 0x1c || suffix == 0x1d || suffix == 0x1e )
		emit(ip, DOMAIN, name, "nbns", 60, uid);
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)
	{
	if ( enable_nbns && on_port(c, NBNS_PORT) )
		{
		# opcode 5 = registration, 8 = refresh, 15 = multi-homed registration
		if ( msg$opcode == 5 || msg$opcode == 8 || msg$opcode == 15 )
			nbns_emit(c$id$orig_h, original_query, c$uid);
		return;
		}
	}

function name_reply(c: connection, ans: dns_answer, a: addr)
	{
	# 멀티캐스트/브로드캐스트 이름 해석은 응답자가 자기 이름을 답한다.
	local self_answer = (a == c$id$orig_h || a == c$id$resp_h);

	if ( enable_nbns && on_port(c, NBNS_PORT) )
		{
		if ( self_answer )
			nbns_emit(a, ans$query, c$uid);
		}
	else if ( enable_llmnr && on_port(c, LLMNR_PORT) )
		{
		if ( self_answer )
			emit(a, HOSTNAME, normalize_name(ans$query), "llmnr", 70, c$uid);
		}
	else if ( enable_mdns && on_port(c, MDNS_PORT) )
		{
		if ( self_answer )
			emit(a, HOSTNAME, mdns_host(ans$query), "mdns", 70, c$uid);
		}
	else if ( enable_dns && (c$id$resp_p in DNS_PORTS) )
		emit(a, DNS_NAME, normalize_name(ans$query), "dns", 40, c$uid);
	}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	name_reply(c, ans, a);
	}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	name_reply(c, ans, a);
	}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string)
	{
	if ( /\.(in-addr|ip6)\.arpa$/ !in ans$query )
		return;

	local ip = ptr_name_to_addr(ans$query);

	if ( enable_mdns && on_port(c, MDNS_PORT) )
		emit(ip, HOSTNAME, mdns_host(name), "mdns", 70, c$uid);
	else if ( enable_dns && (c$id$resp_p in DNS_PORTS) )
		emit(ip, DNS_NAME, normalize_name(name), "dns", 50, c$uid);
	}
