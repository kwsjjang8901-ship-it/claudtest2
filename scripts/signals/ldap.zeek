##! LDAP/CLDAP 신호: Netlogon ping(DC 찾기, MS-ADTS 6.3.3).
##!
##! 도메인 PC는 로그온·그룹 정책 갱신 등에서 DC를 찾을 때 CLDAP(udp/389)로
##! "(&(DnsDomain=corp.local)(Host=PC01)(User=PC01$)(NtVer=...))" 검색을 보낸다.
##! Host는 요청한 PC 자신의 이름이므로 라우팅 구간에서도 호스트명/도메인을 얻을 수 있다.

@load base/protocols/ldap
@load ../main

module AssetID;

## 필터에서 "(Attr=value)" 값을 꺼낸다. 없으면 빈 문자열.
function ldap_filter_value(filter: string, attr: string): string
	{
	local m = find_all_ordered(filter, string_to_pattern("\\(" + attr + "=[^)]*\\)", F));

	if ( |m| == 0 )
		return "";

	return m[0][|attr| + 2:-1];
	}

event LDAP::search_request(c: connection, message_id: int, base_object: string,
                           scope: LDAP::SearchScope, deref: LDAP::SearchDerefAlias,
                           size_limit: int, time_limit: int, types_only: bool,
                           filter: string, attributes: vector of string)
	{
	if ( ! enable_ldap || /\(NtVer=/ !in filter )
		return;

	local ip = c$id$orig_h;
	local host = normalize_name(ldap_filter_value(filter, "Host"));
	local domain = normalize_name(ldap_filter_value(filter, "DnsDomain"));
	local user = normalize_name(ldap_filter_value(filter, "User"));

	emit(ip, HOSTNAME, split_string1(host, /\./)[0], "ldap", 85, c$uid);
	emit(ip, DOMAIN, domain, "ldap", 85, c$uid);

	if ( host != "" && domain != "" )
		emit(ip, FQDN, split_string1(host, /\./)[0] + "." + domain, "ldap", 80, c$uid);

	if ( user != "" && user[-1] == "$" && domain != "" )
		emit(ip, MACHINE_ACCOUNT, domain + "\\" + user, "ldap", 85, c$uid);
	}
