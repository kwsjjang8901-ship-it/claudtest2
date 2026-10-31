##! Kerberos 신호: AS-REQ의 클라이언트 주체로 머신 계정/사용자 계정/도메인.
##!
##! 도메인 가입 PC는 부팅 시 "HOST$@REALM"으로 AS-REQ를 보낸다.
##! 머신 계정은 Manager 판정 우선순위 1순위 키다.

@load base/protocols/krb
@load ../main

module AssetID;

event krb_as_request(c: connection, msg: KRB::KDC_Request)
	{
	if ( ! enable_kerberos || ! msg?$client_name )
		return;

	# enterprise principal(user@REALM)은 앞부분만, 서비스 주체(a/b)는 제외.
	local name = normalize_name(split_string1(msg$client_name, /@/)[0]);

	if ( name == "" || /\// in name )
		return;

	local realm = msg?$service_realm ? normalize_name(msg$service_realm) : "";
	local ip = c$id$orig_h;
	local account = realm != "" ? fmt("%s\\%s", realm, name) : name;

	if ( realm != "" )
		emit(ip, DOMAIN, realm, "kerberos", 90, c$uid);

	if ( name[-1] == "$" )
		{
		emit(ip, MACHINE_ACCOUNT, account, "kerberos", 95, c$uid);
		emit(ip, HOSTNAME, name[:-1], "kerberos", 90, c$uid);
		}
	else
		emit(ip, USER_ACCOUNT, account, "kerberos", 70, c$uid);
	}
