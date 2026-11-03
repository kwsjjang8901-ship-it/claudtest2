# @TEST-DOC: SMB 공유 경로의 서버 이름 -> 서버 dns_name, NTLM 로컬 계정 도메인 처리, SMB2 클라이언트 GUID
# @TEST-EXEC: zeek -C -r $TRACES/zeek/smb3.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
