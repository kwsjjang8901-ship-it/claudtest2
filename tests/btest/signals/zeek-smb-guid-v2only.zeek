# @TEST-DOC: SMB2 클라이언트 GUID(v1 형식) + NTLM, Server 2019 (Zeek 테스트 trace)
# @TEST-EXEC: zeek -C -r $TRACES/zeek/smb_v2_only_non_zero_reserved1.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 172.16.0.0/12 };
