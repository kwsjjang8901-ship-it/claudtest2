# @TEST-DOC: SSH 서버 호스트 키 지문
# @TEST-EXEC: zeek -C -r $TRACES/zeek/ssh_kex_curve25519.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep ssh > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
