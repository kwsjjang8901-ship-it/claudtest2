# @TEST-DOC: 같은 (ip, signal, value, source)는 suppress_interval 동안 1회만 기록
# @TEST-EXEC: zeek -C -r $TRACES/zeek/kinit.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source < asset_signal.log | sort | uniq -d > dup.out
# @TEST-EXEC: btest-diff dup.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
