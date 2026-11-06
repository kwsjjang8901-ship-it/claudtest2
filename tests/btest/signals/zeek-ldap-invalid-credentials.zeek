# @TEST-DOC: 한 IP가 여러 머신 계정(dc01-zion$, desktop-evil$, desktop-victim$)으로 NTLM 인증 (Zeek 테스트 trace, Zeek 9.x 필요)
# @TEST-REQUIRES: zeek -e 'if ( Version::number < 90000 ) exit(1);'
# @TEST-EXEC: zeek -C -r $TRACES/zeek/ldap_invalid_credentials.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
