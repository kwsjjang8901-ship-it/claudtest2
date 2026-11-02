##! 서버 이름 신호: 클라이언트가 서버에 접속할 때 쓴 이름.
##!   SMB 공유 경로(\\server\share), TLS SNI, HTTP Host -> 응답측 IP의 dns_name
##!
##! 별칭(CNAME, DFS, 가상 호스트)일 수 있으므로 식별 키가 아니라 표시용 이름이다.
##!
##! 프록시를 거친 요청(CONNECT, 절대 URL)의 Host/SNI는 외부 사이트 이름이므로 제외한다.
##! 그래도 이름이 몰리는 IP(프록시, 로드밸런서)는 max_server_names 개까지만 기록한다.

@load base/protocols/smb
@load base/protocols/ssl
@load base/protocols/http
@load ../main

module AssetID;

## 프록시 요청이 지나간 연결 uid.
global proxied_conns: set[string] &create_expire=1hr;

## IP별로 기록한 서버 이름 수.
global server_name_count: table[addr] of count &default=0 &create_expire=suppress_interval;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	if ( method == "CONNECT" || /^[a-zA-Z]+:\/\// in original_URI )
		add proxied_conns[c$uid];
	}

function server_name(ip: addr, name: string, source: string, uid: string)
	{
	if ( ! enable_server_names || uid in proxied_conns )
		return;

	if ( server_name_count[ip] >= max_server_names )
		return;

	local n = normalize_name(name);

	# IP 주소, 포트가 붙은 값, 빈 값은 이름이 아니다.
	n = split_string1(n, /:/)[0];
	if ( n == "" || is_valid_ip(n) || /^\[/ in n )
		return;

	if ( emit(ip, DNS_NAME, n, source, 50, uid) )
		++server_name_count[ip];
	}

## "\\\\server\\share" -> "server"
function unc_server(path: string): string
	{
	local p = sub(path, /^\\\\+/, "");
	return split_string1(p, /\\/)[0];
	}

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string)
	{
	server_name(c$id$resp_h, unc_server(path), "smb", c$uid);
	}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string)
	{
	server_name(c$id$resp_h, unc_server(path), "smb", c$uid);
	}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
	{
	if ( is_client && |names| > 0 )
		server_name(c$id$resp_h, names[0], "tls", c$uid);
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( is_orig && name == "HOST" )
		server_name(c$id$resp_h, value, "http", c$uid);
	}
