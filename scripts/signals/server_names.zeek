##! 서버 이름 신호: 클라이언트가 서버에 접속할 때 쓴 이름.
##!   SMB 공유 경로(\\server\share), TLS SNI, HTTP Host -> 응답측 IP의 dns_name
##!
##! 별칭(CNAME, DFS, 가상 호스트)일 수 있으므로 식별 키가 아니라 표시용 이름이다.

@load base/protocols/smb
@load base/protocols/ssl
@load base/protocols/http
@load ../main

module AssetID;

function server_name(ip: addr, name: string, source: string, uid: string)
	{
	if ( ! enable_server_names )
		return;

	local n = normalize_name(name);

	# IP 주소, 포트가 붙은 값, 빈 값은 이름이 아니다.
	n = split_string1(n, /:/)[0];
	if ( n == "" || is_valid_ip(n) || /^\[/ in n )
		return;

	emit(ip, DNS_NAME, n, source, 50, uid);
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
