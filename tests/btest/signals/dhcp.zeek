# @TEST-DOC: DHCP ACK에서 할당 IP + MAC/호스트명/도메인, DHCP 서버 서비스
# @TEST-EXEC: zeek -C -r $TRACES/zeek/dhcp.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 0.0.0.0/0 };
