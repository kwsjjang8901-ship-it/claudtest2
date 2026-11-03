# Zeek 자산 식별 (AssetID) PoC

NSM 원페이저 6장 "자산 식별"의 센서 측 PoC입니다. 미러 트래픽(pcap)에서 **자산 신호**를 뽑아
`asset_signal.log`(JSON)로 남기고, Manager 역할을 대신하는 리졸버가 판정 키 우선순위
(**머신 계정 > DHCP client-id > MAC > 호스트명 > IP+시간**)로 자산을 묶어 리포트를 만듭니다.

- `scripts/`: 센서(Zeek 8.x / 9.x) 패키지. nsm_rules에 머지할 대상입니다.
- `tools/`: PoC 확인용 도구(실행 스크립트, 리졸버, 리포트). 머지 대상이 아닙니다.

## 빠른 시작

필요한 것: `python3` (3.8+), 그리고 `zeek` 8.x 이상 **또는** `docker`(없으면 자동으로 `zeek/zeek:9.0.1` 이미지 사용).

검증한 Zeek 버전: **8.0.9, 9.0.1** (btest 모두 통과, 두 버전의 출력이 같음).
Docker로 8.0을 쓰려면 `ZEEK_IMAGE=zeek/zeek:8.0.9 tools/run_poc.sh ...`처럼 실행합니다.

```bash
# 1) 데모 pcap으로 확인
tools/run_poc.sh tests/pcaps/demo.pcap

# 2) 운영 pcap
tools/run_poc.sh -n 10.0.0.0/8,172.16.0.0/12 /data/capture.pcap
```

| 옵션 | 설명 |
|---|---|
| `-n CIDRS` | 자산 대역(쉼표 구분). 생략하면 Zeek 사설 대역(RFC1918 등). **내부망에 공인 IP를 쓰면 반드시 지정** |
| `-o DIR` | 출력 디렉터리 (기본 `out/<pcap 이름>/`) |
| `-d` | 로컬 zeek가 있어도 Docker 사용 |
| `-z ARGS` | zeek 추가 인자. 예) `-z "AssetID::suppress_interval=30min"` |

pcap이 여러 개이면 `mergecap -w merged.pcap *.pcap`으로 합친 뒤 실행합니다.

## 결과물 (`out/<이름>/`)

| 파일 | 내용 |
|---|---|
| `report.html` | 브라우저 리포트: 요약 카드, 식별 품질(식별률·능동/수동·캡처 시간별·구간별), 키 커버리지, 확인 필요 항목, 검색·정렬 가능한 자산 표. 행을 누르면 근거 신호 타임라인이 열림 |
| `report.txt` | 터미널 요약 (실행 시 화면에도 출력) |
| `assets.csv` | 자산 목록 (Excel에서 바로 열림, UTF-8 BOM) |
| `assets.json` | 자산 목록 원본 (Manager 연동 검토용) |
| `zeek/asset_signal.log` | 센서 원본 신호 (JSON) + Zeek 기본 로그 (교차 확인용) |

데모 pcap 결과 예시 (`report.txt` 일부):

```
[공유 MAC (게이트웨이/라우터 추정, 식별 키에서 제외)]
  00:00:5e:00:01:01  <- IP 5개: 10.20.5.11, 10.20.5.12, 10.20.5.13, 10.20.5.14, 10.20.5.15
[IP 재사용 (점유 단말 변경)]
  10.10.0.120  변경 시각: 2026-10-30 13:00:30

asset_id      식별 키(신뢰도)        호스트명             IP               MAC                OS                           역할
A-98f274dde0  머신 계정(높음)        win10-hr01           10.10.0.101      3c:52:82:11:22:33  windows 10/11
A-88f72467ac  DHCP client-id(높음)   galaxy-s24           10.10.0.120      02:1a:11:fe:dc:ba  android 14
A-83ce25a445  DHCP client-id(높음)   laptop-sales07       10.10.0.120      00:21:cc:01:02:03  windows 10/11
A-96823b3723  MAC(중간)              dc01 (dns)           10.10.1.10       00:50:56:aa:10:10  -                            도메인 컨트롤러, DNS 서버, DHCP 서버, 파일 서버(SMB)
A-74eaea43f4  IP+시간(낮음)          -                    10.20.5.11       -                  -
```

## 수집하는 신호

| 신호 (`signal`) | 출처 (`source`) | 용도 |
|---|---|---|
| `machine_account` | kerberos(AS-REQ `HOST$`), ldap(CLDAP Netlogon ping), ntlm | 식별 키 1순위 |
| `dhcp_client_id` | dhcp(option 61) | 식별 키 2순위 |
| `mac` | dhcp, arp, conn(L2 주소) | 식별 키 3순위 |
| `hostname` | dhcp, kerberos, ldap, ntlm, rdp, nbns, llmnr, mdns | 식별 키 4순위 |
| `fqdn`, `domain` | dhcp, kerberos, ntlm, nbns, smb | 보조 |
| `os_hint`, `software` | ntlm(버전), smb(native OS), ssh 배너, http User-Agent, dhcp vendor | OS 추정 |
| `service` | 연결 성립/프로토콜 확인 | 역할 추정 (DC, DNS, 웹, DB, 프린터 등) |
| `dns_name` | dns(A/PTR 응답), smb(공유 경로), tls(SNI), http(Host), x509(서버 인증서) | 서버 표시 이름 (별칭일 수 있어 식별 키 아님) |
| `device` | syslog(ESXi, Cisco ASA/IOS, FortiGate, UTM), x509(AhnLab MDS/EPP, VMware 등) | 장비·제품 종류 → 리포트 역할 |
| `security_agent` | ahnlab(User-Agent `v3inet4/…`, `MeDCore`) | 단말의 AhnLab 제품 통신 |
| `ssh_host_key` | ssh | SSH 서버 호스트 키 지문 (참고 정보) |
| `user_account`, `dhcp_vendor_class`, `dhcp_fingerprint` | kerberos/ntlm/rdp, dhcp | 참고 정보 (식별 키 아님) |

신호 정의, 신뢰도 기준, 판정 알고리즘, 한계는 [docs/DESIGN.md](docs/DESIGN.md)에, 검증·개선 계획은 [docs/PLAN.md](docs/PLAN.md)에 있습니다.

## 테스트

```bash
tests/run_tests.sh                               # Zeek btest(17) + 리졸버 unittest(20)
ZEEK_IMAGE=zeek/zeek:8.0.9 tests/run_tests.sh    # Zeek 8.0으로 btest
```

- `tests/pcaps/extras.pcap`: 장비·제품 신호(syslog, User-Agent, 서버 인증서) 합성 pcap. `tests/gen_extra_pcaps.py`로 다시 만들 수 있습니다.
- `tests/pcaps/demo.pcap`: 합성 데모. `tests/gen_demo_pcap.py`로 다시 만들 수 있습니다(`pip install scapy`).
- `tests/pcaps/zeek/`: Zeek 프로젝트 테스트 trace 일부(BSD 라이선스, zeek/zeek v9.0.1 `testing/btest/Traces`).

## nsm_rules에 머지

`scripts/` 디렉터리를 nsm_rules 아래로 복사하고 `@load ./asset-id` 한 줄을 추가하면 됩니다.
자세한 내용은 [docs/DESIGN.md의 머지 가이드](docs/DESIGN.md#7-nsm_rules-머지-가이드)를 참고하세요.

## 범위 밖 (Next 단계 검토)

- **MDS Agent 목록 대조(미관리 자산 판정):** 원페이저의 "미관리 자산 가시화" 기능입니다. 이번 PoC 범위에서 제외했고,
  Manager의 Agent 목록 조회 인터페이스가 확정되면 Next 단계에서 검토합니다.
