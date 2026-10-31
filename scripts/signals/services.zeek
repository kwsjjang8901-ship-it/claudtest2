##! 서비스 신호: 이 IP가 실제로 응답한 서비스(proto/port[/app]).
##! 역할(DC, DNS, 웹, DB 서버 등)은 Manager(리졸버)가 서비스 조합으로 판정한다.
##!
##! - service_ports의 TCP 포트: 연결 성립(SYN-ACK) 시 -> "tcp/445"
##! - 연결 종료 시 응답측이 패킷을 보냈고 분석기가 프로토콜을 확인한 경우:
##!     service_ports의 포트 -> "udp/53",  그 밖의 포트 -> "tcp/8081/http"

@load base/protocols/conn
@load ../main

module AssetID;

function service_value(p: port): string
	{
	return fmt("%s/%d", get_port_transport_proto(p), port_to_count(p));
	}

event connection_established(c: connection)
	{
	if ( ! enable_services )
		return;

	local p = c$id$resp_p;

	if ( p in service_ports && p !in ignore_service_ports )
		emit(c$id$resp_h, SERVICE, service_value(p), "service", 90, c$uid);
	}

event connection_state_remove(c: connection)
	{
	if ( ! enable_services || |c$service| == 0 || c$resp$num_pkts == 0 )
		return;

	local p = c$id$resp_p;

	if ( p in ignore_service_ports || port_to_count(p) >= ephemeral_port_min )
		return;

	if ( p in service_ports )
		{
		emit(c$id$resp_h, SERVICE, service_value(p), "service", 90, c$uid);
		return;
		}

	for ( s in c$service )
		{
		local app = to_lower(s);
		if ( app !in nested_analyzers )
			emit(c$id$resp_h, SERVICE, service_value(p) + "/" + app, "service", 90, c$uid);
		}
	}
