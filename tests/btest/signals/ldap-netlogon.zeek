# @TEST-DOC: CLDAP Netlogon ping(DC 찾기) -> 호스트명, 도메인, FQDN, 머신 계정
# @TEST-EXEC: zeek -C -r $TRACES/cldap_netlogon.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
