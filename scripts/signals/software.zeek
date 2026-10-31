##! OS/SW 추정 신호: HTTP User-Agent, SSH 배너, SMB1 native OS, RDP 클라이언트 이름.

@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/smb
@load base/protocols/rdp
@load ../main

module AssetID;

## User-Agent에서 OS 계열만 추출(값 종류를 줄여 로그량을 억제).
function ua_os(ua: string): string
	{
	local m: string_vec;

	if ( /Windows NT [0-9]+\.[0-9]+/ in ua )
		{
		m = find_all_ordered(ua, /Windows NT [0-9]+\.[0-9]+/);
		local ver = m[0][11:];
		switch ( ver ) {
		case "10.0": return "windows 10/11";
		case "6.3": return "windows 8.1";
		case "6.2": return "windows 8";
		case "6.1": return "windows 7";
		case "6.0": return "windows vista";
		case "5.1", "5.2": return "windows xp";
		default: return "windows nt " + ver;
		}
		}

	if ( /iPhone|iPad/ in ua )
		return "ios";
	if ( /Android [0-9]+/ in ua )
		{
		m = find_all_ordered(ua, /Android [0-9]+/);
		return to_lower(m[0]);
		}
	if ( /CrOS/ in ua )
		return "chromeos";
	if ( /Mac OS X/ in ua )
		return "macos";
	if ( /Ubuntu/ in ua )
		return "linux(ubuntu)";
	if ( /Linux/ in ua )
		return "linux";
	if ( /^Microsoft-(CryptoAPI|WNS|Delivery-Optimization)\// in ua )
		return "windows";

	return "";
	}

## SSH 배너(SSH-2.0-OpenSSH_8.9p1 Ubuntu-3)에서 OS 계열.
function ssh_os(banner: string): string
	{
	local b = to_lower(banner);

	for ( os in set("ubuntu", "debian", "freebsd", "raspbian", "centos", "redhat") )
		if ( strstr(b, os) > 0 )
			return "linux(" + os + ")";

	if ( /for_windows/ in b )
		return "windows";
	if ( /cisco/ in b )
		return "cisco";

	return "";
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( ! enable_http_ua || ! is_orig || name != "USER-AGENT" )
		return;

	emit(c$id$orig_h, OS_HINT, ua_os(value), "http_ua", 50, c$uid);
	}

function ssh_banner(ip: addr, version: string, uid: string)
	{
	if ( ! enable_ssh )
		return;

	emit(ip, SOFTWARE, "ssh:" + version, "ssh", 70, uid);
	emit(ip, OS_HINT, ssh_os(version), "ssh", 60, uid);
	}

event ssh_client_version(c: connection, version: string)
	{
	ssh_banner(c$id$orig_h, version, c$uid);
	}

event ssh_server_version(c: connection, version: string)
	{
	ssh_banner(c$id$resp_h, version, c$uid);
	}

event smb1_session_setup_andx_request(c: connection, hdr: SMB1::Header, request: SMB1::SessionSetupAndXRequest)
	{
	if ( ! enable_smb )
		return;

	emit(c$id$orig_h, OS_HINT, normalize_name(request$native_os), "smb", 70, c$uid);

	if ( request?$primary_domain )
		emit(c$id$orig_h, DOMAIN, normalize_name(request$primary_domain), "smb", 60, c$uid);
	}

event rdp_client_core_data(c: connection, data: RDP::ClientCoreData)
	{
	if ( ! enable_rdp )
		return;

	emit(c$id$orig_h, HOSTNAME, normalize_name(data$client_name), "rdp", 80, c$uid);
	}

event rdp_connect_request(c: connection, cookie: string, flags: count)
	{
	if ( ! enable_rdp )
		return;

	# mstshash 쿠키는 사용자 입력값(사용자명 또는 domain\user).
	emit(c$id$orig_h, USER_ACCOUNT, normalize_name(cookie), "rdp", 50, c$uid);
	}
