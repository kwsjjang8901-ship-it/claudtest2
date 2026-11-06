# @TEST-DOC: TCP syslog RFC 3164 호스트명 (Zeek 테스트 trace, Zeek 9.x 필요)
# @TEST-REQUIRES: zeek -e 'if ( Version::number < 90000 ) exit(1);'
# @TEST-EXEC: zeek -C -r $TRACES/zeek/tcp-syslog.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log | grep -v '	mac	.*	conn	' | sort > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
