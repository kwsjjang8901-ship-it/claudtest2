# @TEST-DOC: 실제 Windows DNS 동적 업데이트 -> 호스트명/FQDN/도메인 (Zeek 테스트 trace)
# @TEST-REQUIRES: zeek -e 'if ( Version::number < 90000 ) exit(1);'
# @TEST-EXEC: zeek -C -r $TRACES/zeek/dynamic-update.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
