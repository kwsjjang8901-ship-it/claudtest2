# @TEST-DOC: mDNS PTR 응답 -> 호스트명 (IPv4/IPv6)
# @TEST-EXEC: zeek -C -r $TRACES/zeek/mdns.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8, [fd00::]/8, [fe80::]/10 };
