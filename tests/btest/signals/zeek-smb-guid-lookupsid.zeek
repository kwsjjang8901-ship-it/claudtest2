# @TEST-DOC: 실제 SMB2 클라이언트 GUID + NTLM + Server 2022(WIN- 기본 이름) (Zeek 테스트 trace)
# @TEST-EXEC: zeek -C -r $TRACES/zeek/lookupsid-plaintext.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
