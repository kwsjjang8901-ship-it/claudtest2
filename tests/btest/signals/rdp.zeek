# @TEST-DOC: RDP client core data -> 클라이언트 호스트명, 쿠키 -> 사용자
# @TEST-EXEC: zeek -C -r $TRACES/zeek/rdp-proprietary-encryption.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 0.0.0.0/0 };
