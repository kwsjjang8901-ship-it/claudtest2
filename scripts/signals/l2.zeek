##! L2 신호: ARP(IP-MAC 바인딩), conn의 L2 주소.
##!
##! conn L2 주소는 같은 L2 구간이면 단말 MAC이지만, 라우팅을 거친 트래픽이면
##! 게이트웨이 MAC이다. 그래서 신뢰도를 낮게(40) 기록하고, 여러 IP에 걸친
##! 공유 MAC 판별은 Manager(리졸버)에서 한다.

@load ../main

module AssetID;

function arp_emit(spa: addr, sha: string, source: string)
	{
	if ( ! enable_arp )
		return;

	local mac = normalize_mac(sha);
	emit(spa, MAC, mac, source, 85, "", mac);
	}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	# SPA 0.0.0.0(ARP probe)은 is_asset_addr에서 걸러진다.
	arp_emit(SPA, SHA, "arp");
	}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	arp_emit(SPA, SHA, "arp");
	}

event new_connection(c: connection)
	{
	if ( ! enable_conn_mac )
		return;

	if ( c$orig?$l2_addr )
		{
		local om = normalize_mac(c$orig$l2_addr);
		emit(c$id$orig_h, MAC, om, "conn", 40, c$uid, om);
		}

	if ( c$resp?$l2_addr )
		{
		local rm = normalize_mac(c$resp$l2_addr);
		emit(c$id$resp_h, MAC, rm, "conn", 40, c$uid, rm);
		}
	}
