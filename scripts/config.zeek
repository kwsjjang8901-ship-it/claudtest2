##! 자산 식별(AssetID) 설정값.
##!
##! 모든 값은 redef 또는 Config 프레임워크(option)로 운영 중 변경할 수 있다.
##! nsm_rules에 머지할 때 이 파일만 고객 환경에 맞게 덮어쓰면 된다.

module AssetID;

export {
	## 자산으로 취급할 내부 대역.
	## 비어 있으면 Site::local_nets, 그것도 비어 있으면
	## Site::private_address_space(RFC1918 등)를 사용한다.
	option asset_nets: set[subnet] = {};

	## 동일 (ip, signal, value) 신호를 다시 기록하지 않는 기간.
	## 로그량과 IP-자산 시계열 바인딩 해상도 사이의 trade-off.
	const suppress_interval = 1hr &redef;

	## DHCP 트랜잭션(xid) 상태 보관 시간.
	const dhcp_xid_timeout = 5min &redef;

	## 신호 소스별 on/off.
	option enable_dhcp = T;
	option enable_arp = T;
	option enable_conn_mac = T;     ##< conn L2 주소(라우팅 구간이면 게이트웨이 MAC)
	option enable_kerberos = T;
	option enable_ntlm = T;
	option enable_nbns = T;
	option enable_llmnr = T;
	option enable_mdns = T;
	option enable_dns = T;          ##< 일반 DNS(53) PTR/A 응답 -> dns_name
	option enable_rdp = T;
	option enable_smb = T;
	option enable_http_ua = T;
	option enable_ssh = T;
	option enable_services = T;
	option enable_ldap = T;         ##< CLDAP/LDAP Netlogon ping (DC 찾기) -> hostname, domain
	option enable_server_names = T; ##< SMB 공유 경로, TLS SNI, HTTP Host -> 서버 dns_name

	## 잘 알려진 서비스 포트. TCP는 연결 성립만으로, UDP는 분석기 확인 시 기록하며
	## 값은 "tcp/445"처럼 proto/port 로 남긴다(역할 판정은 Manager에서 포트 기준).
	## 이 목록에 없는 포트는 분석기가 프로토콜을 확인한 경우에만 "tcp/8081/http"처럼
	## 앱 이름을 붙여 기록한다.
	option service_ports: table[port] of string = {
		[21/tcp] = "ftp", [22/tcp] = "ssh", [23/tcp] = "telnet",
		[25/tcp] = "smtp", [53/tcp] = "dns", [80/tcp] = "http",
		[88/tcp] = "kerberos", [110/tcp] = "pop3", [135/tcp] = "msrpc",
		[139/tcp] = "netbios-ssn", [143/tcp] = "imap", [389/tcp] = "ldap",
		[443/tcp] = "https", [445/tcp] = "smb", [465/tcp] = "smtps",
		[515/tcp] = "lpd", [587/tcp] = "smtp", [631/tcp] = "ipp",
		[636/tcp] = "ldaps", [993/tcp] = "imaps", [995/tcp] = "pop3s",
		[1433/tcp] = "mssql", [1521/tcp] = "oracle", [2049/tcp] = "nfs",
		[3268/tcp] = "gc", [3269/tcp] = "gc-ssl", [3306/tcp] = "mysql",
		[3389/tcp] = "rdp", [5432/tcp] = "postgresql", [5900/tcp] = "vnc",
		[5985/tcp] = "winrm", [5986/tcp] = "winrm-ssl", [6379/tcp] = "redis",
		[8080/tcp] = "http-alt", [8443/tcp] = "https-alt", [9100/tcp] = "jetdirect",
		[9200/tcp] = "elasticsearch", [27017/tcp] = "mongodb",
		[53/udp] = "dns", [67/udp] = "dhcp", [69/udp] = "tftp",
		[88/udp] = "kerberos", [123/udp] = "ntp",
		[161/udp] = "snmp", [389/udp] = "cldap", [514/udp] = "syslog",
		[1812/udp] = "radius",
	};

	## 다른 프로토콜 안에 실려 확인되는 분석기. 서비스로 따로 기록하지 않는다.
	option nested_analyzers: set[string] = {
		"ntlm", "gssapi", "krb", "krb_tcp", "dce_rpc", "smb", "ftp_data",
	};

	## 거의 모든 단말이 응답하는 이름 해석/탐색 포트. 서비스로 기록하지 않는다.
	option ignore_service_ports: set[port] = {
		137/udp, 138/udp, 1900/udp, 5353/udp, 5355/udp,
	};

	## 식별에 쓸 수 없는 일반 이름. hostname 신호로 기록하지 않는다.
	option ignore_hostnames: set[string] = {
		"localhost", "localhost.localdomain", "localdomain", "unknown", "(none)",
	};

	## 응답측 포트가 이 값 이상이면 임시 포트로 보고 서비스로 기록하지 않는다.
	const ephemeral_port_min = 49152 &redef;
}
