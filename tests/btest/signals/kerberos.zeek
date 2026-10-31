# @TEST-DOC: Kerberos AS-REQ: 사용자 계정/도메인, 서비스 주체 제외
# @TEST-EXEC: zeek -C -r $TRACES/zeek/kinit.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
