# @TEST-DOC: 리졸버 종단 테스트(Zeek 9.x 필요: 8.x는 LDAP 안의 NTLM을 꺼내지 않음) — 여러 머신 계정으로 인증한 IP는 머신 계정을 식별 키로 쓰지 않는다(가짜 자산·가짜 IP 재사용 없음)
# @TEST-REQUIRES: zeek -e 'if ( Version::number < 90000 ) exit(1);'
# @TEST-EXEC: zeek -C -r $TRACES/zeek/ldap_invalid_credentials.pcap $PKG %INPUT LogAscii::use_json=T
# @TEST-EXEC: python3 $RESOLVER asset_signal.log -o out -q
# @TEST-EXEC: sed -n '/다중 머신 계정 인증/,/^$/p' out/report.txt > multi.out
# @TEST-EXEC: grep -E '^A-' out/report.txt | awk '{print $2, $3, $4}' | sort >> multi.out
# @TEST-EXEC: ! grep -q 'IP 재사용' out/report.txt
# @TEST-EXEC: btest-diff multi.out

redef AssetID::asset_nets = { 192.168.0.0/16 };
