# @TEST-DOC: asset_nets 미설정 시 사설 대역만 기록 (공인 IP 제외)
# @TEST-EXEC: zeek -C -r $TRACES/demo.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip < asset_signal.log | sort -u > ips.out
# @TEST-EXEC: btest-diff ips.out
