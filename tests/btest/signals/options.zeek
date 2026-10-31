# @TEST-DOC: 신호 소스 on/off 옵션
# @TEST-EXEC: zeek -C -r $TRACES/demo.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut source < asset_signal.log | sort | uniq -c > sources.out
# @TEST-EXEC: btest-diff sources.out

redef AssetID::enable_conn_mac = F;
redef AssetID::enable_services = F;
redef AssetID::enable_dns = F;
