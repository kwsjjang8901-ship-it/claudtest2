# @TEST-DOC: Linux(pop-os) DHCP 호스트명·도메인 (Zeek 테스트 trace)
# @TEST-EXEC: zeek -C -r $TRACES/zeek/dhcp_time_and_nameserver.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
