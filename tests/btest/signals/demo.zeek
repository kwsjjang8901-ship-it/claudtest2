# @TEST-DOC: 합성 데모: NBNS/LLMNR/mDNS/Kerberos 머신계정/DHCP 재할당/게이트웨이 MAC
# @TEST-EXEC: zeek -C -r $TRACES/demo.pcap $PKG %INPUT
# @TEST-EXEC: zeek-cut ip signal value source confidence < asset_signal.log > signals.out
# @TEST-EXEC: btest-diff signals.out

redef AssetID::asset_nets = { 10.0.0.0/8 };
