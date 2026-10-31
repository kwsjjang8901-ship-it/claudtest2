# @TEST-DOC: ARP request/reply -> IP-MAC
# @TEST-EXEC: zeek -C -r $TRACES/zeek/arp-who-has.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
