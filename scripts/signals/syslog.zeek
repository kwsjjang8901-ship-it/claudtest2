##! syslog 신호: 로그를 보내는 장비의 호스트명과 장비 종류, 받는 쪽의 로그 수집 서비스.
##!
##! 네트워크·가상화 장비는 다른 식별 신호가 거의 없어서 syslog 형식이 가장 좋은 단서다.
##! 메시지 본문은 기록하지 않고 형식(헤더, 제품 고유 태그)만 본다.
##!
##!   "2026-11-03T05:14:16.123Z esx01.corp Vpxa: ..."   -> hostname esx01, device vmware-esxi
##!   "Nov  3 14:14:16 sw01 %LINK-3-UPDOWN: ..."         -> hostname sw01, device cisco-ios
##!   "Nov 03 2026 14:14:16: %ASA-4-106023: ..."         -> device cisco-asa (호스트명 없음)
##!   "date=... devname="FGT01" devid="FG100F..." ..."   -> hostname fgt01, device fortinet-fortigate

@load base/protocols/syslog
@load ../main

module AssetID;

## 송신 장비별로 suppress_interval 동안 해석할 최대 메시지 수(장비 종류를 찾을 만큼만).
const syslog_parse_limit = 50 &redef;

global syslog_parsed: table[addr] of count &default=0 &create_expire=suppress_interval;

## 호스트명으로 쓸 수 있는 토큰인지(시각, IP, 콜론으로 끝나는 태그 제외).
function syslog_hostname_ok(tok: string): bool
	{
	return /^[A-Za-z][A-Za-z0-9._-]{0,62}$/ in tok && ! is_valid_ip(tok);
	}

## 헤더에서 호스트명. RFC 5424, ISO 시각(ESXi 등), RFC 3164 순으로 본다.
function syslog_hostname(msg: string): string
	{
	local t = split_string(strip(msg), / +/);

	if ( |t| >= 4 && t[0] == "1" && /^[0-9]{4}-/ in t[1] )      # RFC 5424: VERSION TIMESTAMP HOSTNAME
		return syslog_hostname_ok(t[2]) ? t[2] : "";

	if ( |t| >= 3 && /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/ in t[0] )    # ISO 시각 + HOSTNAME
		return syslog_hostname_ok(t[1]) ? t[1] : "";

	if ( |t| >= 5 && /^[A-Z][a-z]{2}$/ in t[0] && /^[0-9]{1,2}$/ in t[1] &&
	     /^[0-9]{2}:[0-9]{2}:[0-9]{2}$/ in t[2] )               # RFC 3164: Mmm dd hh:mm:ss HOSTNAME
		return syslog_hostname_ok(t[3]) ? t[3] : "";

	if ( /devname=\"?[^\" ]+/ in msg )                            # FortiGate key=value
		{
		local m = find_all_ordered(msg, /devname=\"?[^\" ]+/);
		local v = sub(m[0], /^devname=\"?/, "");
		return syslog_hostname_ok(v) ? v : "";
		}

	return "";
	}

## 제품 고유 태그로 장비 종류.
function syslog_device(msg: string): string
	{
	if ( /%ASA-[0-7]-/ in msg )
		return "cisco-asa";
	if ( /%FTD-[0-7]-/ in msg )
		return "cisco-ftd";
	if ( /%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+:/ in msg )
		return "cisco-ios";
	if ( / (Vpxa|Hostd|Rhttpproxy|vmkernel|vobd|Fdm|vpxa|hostd)(\[[0-9]+\])?:/ in msg )
		return "vmware-esxi";
	if ( /devid=\"?FG/ in msg )
		return "fortinet-fortigate";
	if ( /^[0-9]+`/ in msg && /`UTM_/ in msg )
		return "utm";

	return "";
	}

event syslog_message(c: connection, facility: count, severity: count, msg: string)
	{
	if ( ! enable_syslog )
		return;

	local sender = c$id$orig_h;
	local proto = get_port_transport_proto(c$id$resp_p);

	emit(c$id$resp_h, SERVICE, fmt("%s/%d", proto, port_to_count(c$id$resp_p)), "syslog", 90, c$uid);

	if ( syslog_parsed[sender] >= syslog_parse_limit )
		return;

	++syslog_parsed[sender];

	local host = normalize_name(syslog_hostname(msg));
	if ( host != "" && host !in ignore_hostnames )
		{
		emit(sender, HOSTNAME, split_string1(host, /\./)[0], "syslog", 70, c$uid);
		if ( /\./ in host )
			emit(sender, FQDN, host, "syslog", 70, c$uid);
		}

	emit(sender, DEVICE, syslog_device(msg), "syslog", 80, c$uid);
	}
