# @TEST-DOC: Cisco 라우터 DHCP(client-id hwtype 0) (Zeek 테스트 trace)
# @TEST-EXEC: zeek -C -r $TRACES/zeek/hw-type0.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
