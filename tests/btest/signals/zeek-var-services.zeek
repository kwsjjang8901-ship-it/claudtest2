# @TEST-DOC: ARP, mDNS, SSH 호스트 키, macOS UA가 섞인 소규모 환경 (Zeek 테스트 trace)
# @TEST-EXEC: zeek -C -r $TRACES/zeek/var-services-std-ports.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 172.16.0.0/12, 141.142.0.0/16 };
