# @TEST-DOC: DNS 동적 업데이트(opcode 5) -> 호스트명/FQDN/도메인. Zeek 9.x부터 UPDATE를 파싱하므로 8.x에서는 건너뛴다.
# @TEST-REQUIRES: zeek -e 'if ( Version::number < 90000 ) exit(1);'
# @TEST-EXEC: zeek -C -r $TRACES/dns_update.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep dns_update > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
