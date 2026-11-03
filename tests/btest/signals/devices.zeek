# @TEST-DOC: syslog 장비(ESXi/ASA/IOS/FortiGate/UTM/RFC5424), AhnLab 제품 UA, 비브라우저 UA, TLS 서버 인증서
# @TEST-EXEC: zeek -C -r $TRACES/extras.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
