# @TEST-DOC: NTLM AUTHENTICATE/CHALLENGE: 양쪽 호스트명, 도메인, OS 버전
# @TEST-EXEC: zeek -C -r $TRACES/zeek/raw_ntlm_in_smb.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
