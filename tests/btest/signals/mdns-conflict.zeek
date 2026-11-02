# @TEST-DOC: mDNS 이름 충돌 프로브와 서비스 인스턴스 이름은 호스트명으로 쓰지 않는다 (운영 pcap 이슈 재현)
# @TEST-EXEC: zeek -C -r $TRACES/mdns_conflict.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source < asset_signal.log | grep hostname > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
