##! NTLM 신호 (SMB/HTTP/LDAP/DCE-RPC 등 NTLMSSP를 쓰는 모든 프로토콜).
##!
##! AUTHENTICATE(클라이언트 -> 서버): workstation(호스트명), 도메인, 계정, OS 버전
##! CHALLENGE(서버 -> 클라이언트): 서버의 NetBIOS/DNS 이름, 도메인, OS 버전

@load base/protocols/ntlm
@load ../main

module AssetID;

function ntlm_version(v: NTLM::Version): string
	{
	return fmt("windows nt %d.%d build %d", v$major, v$minor, v$build);
	}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
	{
	if ( ! enable_ntlm )
		return;

	local ip = c$id$orig_h;
	local domain = request?$domain_name ? normalize_name(request$domain_name) : "";

	if ( request?$workstation )
		emit(ip, HOSTNAME, normalize_name(request$workstation), "ntlm", 85, c$uid);

	if ( request?$user_name && request$user_name != "" )
		{
		local user = normalize_name(request$user_name);
		local account = domain != "" ? fmt("%s\\%s", domain, user) : user;

		if ( user[-1] == "$" )
			emit(ip, MACHINE_ACCOUNT, account, "ntlm", 90, c$uid);
		else
			emit(ip, USER_ACCOUNT, account, "ntlm", 70, c$uid);
		}

	# 로컬 계정 로그인이면 domain이 상대 서버/자기 이름일 수 있어 신뢰도를 낮춘다.
	emit(ip, DOMAIN, domain, "ntlm", 60, c$uid);

	if ( request?$version )
		emit(ip, OS_HINT, ntlm_version(request$version), "ntlm", 80, c$uid);
	}

event ntlm_challenge(c: connection, challenge: NTLM::Challenge)
	{
	if ( ! enable_ntlm )
		return;

	local ip = c$id$resp_h;

	if ( challenge?$target_info )
		{
		local ti = challenge$target_info;
		local host = normalize_name(ti$nb_computer_name);
		emit(ip, HOSTNAME, host, "ntlm", 85, c$uid);

		local nb_domain = normalize_name(ti$nb_domain_name);
		local dns_domain = ti?$dns_domain_name ? normalize_name(ti$dns_domain_name) : "";

		# 워크그룹 장비는 도메인 이름 = 자기 컴퓨터 이름이다.
		if ( dns_domain != "" && dns_domain != host )
			emit(ip, DOMAIN, dns_domain, "ntlm", 85, c$uid);
		else if ( nb_domain != host )
			emit(ip, DOMAIN, nb_domain, "ntlm", 80, c$uid);

		if ( ti?$dns_computer_name )
			{
			local fqdn = normalize_name(ti$dns_computer_name);
			if ( fqdn != host )
				emit(ip, FQDN, fqdn, "ntlm", 85, c$uid);
			}
		}

	if ( challenge?$version )
		emit(ip, OS_HINT, ntlm_version(challenge$version), "ntlm", 80, c$uid);
	}
