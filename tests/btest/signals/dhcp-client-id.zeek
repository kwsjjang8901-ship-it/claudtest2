# @TEST-DOC: ACK 없는 DISCOVER만 있으면 IP가 확정되지 않았으므로 아무것도 기록하지 않는다
# @TEST-EXEC: zeek -C -r $TRACES/zeek/dhcp_discover_param_req_and_client_id.pcap $PKG %INPUT
# @TEST-EXEC: test ! -s asset_signal.log

redef AssetID::asset_nets = { 0.0.0.0/0 };
