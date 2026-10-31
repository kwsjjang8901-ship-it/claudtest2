##! DHCP 신호: client-id, MAC, 호스트명, FQDN, 도메인, vendor class, 파라미터 지문.
##!
##! 클라이언트 요청(DISCOVER/REQUEST/INFORM)의 옵션을 xid 단위로 모아 두었다가
##! 서버 ACK에서 할당 IP(yiaddr, INFORM이면 ciaddr)가 확정될 때 한 번에 기록한다.
##! ACK가 보이지 않는 갱신(ciaddr가 있는 REQUEST/INFORM)은 요청 시점에 기록한다.

@load base/protocols/dhcp
@load ../main

module AssetID;

type DhcpClient: record {
	mac:         string &default="";
	client_id:   string &default="";
	host_name:   string &default="";
	fqdn:        string &default="";
	vendor:      string &default="";
	fingerprint: string &default="";
};

global dhcp_xids: table[count] of DhcpClient &create_expire=dhcp_xid_timeout;

function dhcp_os_hint(vendor: string): string
	{
	local v = to_lower(vendor);

	if ( /^msft/ in v )
		return "windows";
	if ( /^android-dhcp/ in v )
		return "android";
	if ( /^dhcpcd/ in v )
		return "linux";
	if ( /^udhcp/ in v )
		return "linux(embedded)";
	if ( /cisco/ in v )
		return "cisco";

	return "";
	}

function dhcp_emit(ip: addr, cl: DhcpClient, uid: string)
	{
	local mac = cl$mac;

	emit(ip, MAC, mac, "dhcp", 90, uid, mac);
	emit(ip, DHCP_CLIENT_ID, cl$client_id, "dhcp", 90, uid, mac);
	emit(ip, HOSTNAME, cl$host_name, "dhcp", 85, uid, mac);

	if ( cl$fqdn != "" )
		{
		local parts = split_string1(cl$fqdn, /\./);
		emit(ip, FQDN, cl$fqdn, "dhcp", 85, uid, mac);
		emit(ip, HOSTNAME, parts[0], "dhcp", 85, uid, mac);

		if ( |parts| > 1 )
			emit(ip, DOMAIN, parts[1], "dhcp", 70, uid, mac);
		}

	emit(ip, DHCP_VENDOR_CLASS, cl$vendor, "dhcp", 60, uid, mac);
	emit(ip, OS_HINT, dhcp_os_hint(cl$vendor), "dhcp", 60, uid, mac);
	emit(ip, DHCP_FINGERPRINT, cl$fingerprint, "dhcp", 60, uid, mac);
	}

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
	{
	if ( ! enable_dhcp )
		return;

	# op 1 = BOOTREQUEST(클라이언트), 2 = BOOTREPLY(서버)
	if ( msg$op == 1 )
		{
		local cl = msg$xid in dhcp_xids ? dhcp_xids[msg$xid] : DhcpClient();
		cl$mac = normalize_mac(msg$chaddr);

		if ( options?$client_id )
			cl$client_id = fmt("%d:%s", options$client_id$hwtype,
			                   to_lower(options$client_id$hwaddr));
		if ( options?$host_name )
			{
			# option 12에 FQDN을 넣는 클라이언트도 있다.
			cl$host_name = normalize_name(options$host_name);
			if ( /\./ in cl$host_name && cl$fqdn == "" )
				cl$fqdn = cl$host_name;
			cl$host_name = split_string1(cl$host_name, /\./)[0];
			}
		if ( options?$client_fqdn )
			cl$fqdn = normalize_name(options$client_fqdn$domain_name);
		if ( options?$vendor_class )
			cl$vendor = strip(options$vendor_class);
		if ( options?$param_list )
			{
			local params: string_vec;
			for ( _, opt in options$param_list )
				params += cat(opt);
			cl$fingerprint = join_string_vec(params, ",");
			}

		dhcp_xids[msg$xid] = cl;

		# 이미 IP를 가진 클라이언트(갱신, INFORM)는 ACK 없이도 확정 가능.
		if ( msg$ciaddr != 0.0.0.0 && (msg$m_type == 3 || msg$m_type == 8) )
			dhcp_emit(msg$ciaddr, cl, c$uid);

		return;
		}

	# DHCPACK
	if ( msg$m_type != 5 )
		return;

	local ip = msg$yiaddr != 0.0.0.0 ? msg$yiaddr : msg$ciaddr;
	local acked = msg$xid in dhcp_xids ? dhcp_xids[msg$xid] : DhcpClient();

	if ( acked$mac == "" )
		acked$mac = normalize_mac(msg$chaddr);

	dhcp_emit(ip, acked, c$uid);

	if ( options?$domain_name )
		emit(ip, DOMAIN, normalize_name(options$domain_name), "dhcp", 70, c$uid, acked$mac);

	if ( options?$serv_addr )
		emit(options$serv_addr, SERVICE, "udp/67", "dhcp", 90, c$uid);
	}
