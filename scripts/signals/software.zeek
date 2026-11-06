##! OS/SW 추정 신호: HTTP User-Agent, SSH 배너·호스트 키, SMB1 native OS, RDP 클라이언트 이름.
##!
##! User-Agent
##!   - 브라우저(Mozilla/...)  -> OS 계열만 (os_hint)
##!   - 그 밖의 프로그램        -> 제품 토큰 (software "ua:git/2.52.0")
##!   - AhnLab 제품            -> security_agent ("ahnlab:V3ES90ASD/5.6.0.55", "ahnlab:MeDCore")
##!     MeDCore 요청 파라미터 값은 의미가 확인되지 않아 기록하지 않는다.

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
	if ( /^Microsoft-(CryptoAPI|WNS|Delivery-Optimization)\// in ua ||
	     /^(Microsoft NCSI|WinHttp-Autoproxy-Service)/ in ua )
		return "windows";

	return "";
	}

## SSH 배너(SSH-2.0-OpenSSH_8.9p1 Ubuntu-3)에서 OS 계열.
function ssh_os(banner: string): string
	{
	local b = to_lower(banner);

	# 순서가 중요하다: Ubuntu·Raspbian 배너에는 "Debian"도 들어 있다(예: "Debian-5ubuntu1").
	# set은 순회 순서가 정해지지 않으므로 vector로 우선순위를 고정한다.
	for ( _, os in vector("ubuntu", "raspbian", "debian", "freebsd", "centos", "redhat") )
		if ( strstr(b, os) > 0 )
			return "linux(" + os + ")";

	if ( /for_windows/ in b )
		return "windows";
	if ( /cisco/ in b )
		return "cisco";

	return "";
	}

## AhnLab 제품 User-Agent -> "ahnlab:<제품코드>/<버전>". 아니면 빈 문자열.
function ahnlab_agent(ua: string): string
	{
	# v3inet4/5.6.0.55/V3ES90ASD/
	if ( /^v3inet[0-9]*\/[0-9.]+\/[A-Za-z0-9_]+/ in ua )
		{
		local parts = split_string(ua, /\//);
		return fmt("ahnlab:%s/%s", parts[2], parts[1]);
		}

	if ( ua == "MeDCore" )
		return "ahnlab:MeDCore";

	return "";
	}

## 브라우저가 아닌 프로그램의 제품 토큰("git/2.52.0 (...)" -> "git/2.52.0").
function ua_product(ua: string): string
	{
	if ( /^Mozilla\// in ua || ua == "" )
		return "";

	# "Microsoft NCSI"처럼 이름에 공백이 있는 경우는 통째로 쓴다(최대 48자).
	local tok = /^Microsoft / in ua ? ua : split_string1(ua, / /)[0];
	return "ua:" + tok[:48];
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
	{
	if ( ! is_orig || name != "USER-AGENT" )
		return;

	local ip = c$id$orig_h;
	local agent = ahnlab_agent(value);

	if ( agent != "" )
		{
		if ( enable_agents )
			emit(ip, SECURITY_AGENT, agent, "ahnlab", 80, c$uid);
		return;
		}

	if ( ! enable_http_ua )
		return;

	emit(ip, OS_HINT, ua_os(value), "http_ua", 50, c$uid);
	emit(ip, SOFTWARE, ua_product(value), "http_ua", 50, c$uid);
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

event ssh_server_host_key(c: connection, hash: string)
	{
	if ( ! enable_ssh_host_key )
		return;

	# 서버마다 고정된 키 지문. 템플릿 복제 VM은 키를 공유할 수 있어 식별 키가 아닌 참고 정보로 둔다.
	emit(c$id$resp_h, SSH_HOST_KEY, to_lower(hash), "ssh", 80, c$uid);
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
