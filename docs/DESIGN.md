# AssetID 설계

## 1. 역할 분담

```
 미러 트래픽 ──▶ [센서: Zeek + scripts/]  ──asset_signal.log──▶ [Manager: 자산 판정]
                  관측 사실(신호)만 기록                        엔티티 리졸루션, IP-자산 시계열 바인딩,
                  판정하지 않음                                 Agent 목록 대조(미관리 판정)
                                                              (PoC: tools/asset_resolver.py)
```

원페이저 6장에 따라 센서는 신호만 남기고 판정은 Manager가 합니다. 그래서 센서 스크립트는 상태를 적게 유지하고
(중복 억제 테이블, DHCP xid 테이블만 사용), 판정 규칙이 바뀌어도 센서는 다시 배포하지 않아도 됩니다.

## 2. 로그 스키마 (`asset_signal.log`)

| 필드 | 타입 | 설명 |
|---|---|---|
| `ts` | time | 관측 시각 |
| `uid` | string (선택) | 근거 연결 uid. conn.log 등 Zeek 원본 로그와 연결 |
| `ip` | addr | 신호가 가리키는 자산 IP |
| `mac` | string (선택) | 관측 시점의 MAC (DHCP/ARP/conn) |
| `signal` | string | 신호 종류 (`AssetID::MACHINE_ACCOUNT` 등의 상수) |
| `value` | string | 정규화된 값 (이름류는 소문자, 끝의 `.` 제거) |
| `source` | string | 출처 프로토콜 |
| `confidence` | count | 출처 기준 신뢰도 0-100 |

**중복 억제:** 같은 `(ip, signal, value, source)`는 `suppress_interval`(기본 1시간) 동안 한 번만 기록합니다.
신호가 계속 관측되면 1시간마다 다시 기록되므로, Manager는 이 간격으로 IP 점유 구간을 갱신할 수 있습니다.

**대상 IP:** `asset_nets` → `Site::local_nets` → `Site::private_address_space` 순으로 정한 내부 대역만 기록합니다.
멀티캐스트, 브로드캐스트, 0.0.0.0은 제외합니다.

## 3. 신호와 신뢰도

| signal | source | conf | 근거 |
|---|---|---|---|
| machine_account | kerberos | 95 | AS-REQ 클라이언트 주체 `HOST$@REALM` (도메인 PC 부팅/갱신 시) |
| machine_account | ntlm | 90 | AUTHENTICATE user가 `$`로 끝남 |
| dhcp_client_id | dhcp | 90 | option 61 (`hwtype:hwaddr`). ACK에서 IP 확정 시 기록 |
| mac | dhcp / arp / conn | 90 / 85 / 40 | chaddr / ARP 송신자 / 연결의 L2 주소(라우팅 구간이면 게이트웨이 MAC) |
| hostname | kerberos / ntlm / dhcp / rdp | 90 / 85 / 85 / 80 | 머신 계정 / workstation, 서버 CHALLENGE의 NetBIOS 이름 / option 12, 81 / client core data |
| hostname | nbns `<20>` / `<00>` | 75 / 50 | 이름 등록·갱신 요청. `<00>`은 워크그룹 이름과 섞여 낮음 |
| hostname | llmnr / mdns | 70 / 70 | 자기 이름에 대한 응답 (`<host>.local` 형태만). mDNS 프로브와 서비스 인스턴스 이름은 기록하지 않음 |
| domain | kerberos / ntlm / dhcp / nbns | 90 / 60-85 / 70 / 60 | realm / 도메인 필드 / option 15·81 / 그룹 suffix `<1b,1c,1d,1e>` |
| os_hint | ntlm / smb / ssh / dhcp / http_ua | 80 / 70 / 60 / 60 / 50 | NTLM 버전 구조체 / SMB1 native OS / 배너 / vendor class / UA OS 토큰 |
| service | service / dhcp | 90 | TCP 연결 성립(SYN-ACK) 또는 응답이 있는 연결에서 분석기가 프로토콜을 확인 |
| dns_name | dns | 40-50 | 일반 DNS A/PTR 응답. 별칭/로드밸런서일 수 있어 **식별 키로 쓰지 않음** |
| user_account | kerberos / ntlm / rdp | 70 / 70 / 50 | 로그인 사용자 (참고 정보) |

신뢰도 값은 PoC 초기값입니다. 운영 pcap 실측 후 SRS에 반영해 조정합니다.

## 4. 판정 알고리즘 (`tools/asset_resolver.py`)

1. **공유 MAC 판별:** conn 출처 MAC이 IP 3개(`--shared-mac-threshold`) 이상에 보이면 게이트웨이/라우터 MAC으로 판단합니다.
   이 MAC은 conn 출처일 때만 식별 키에서 빼고, ARP/DHCP 출처일 때는 그대로 둡니다(게이트웨이 자신은 자산으로 남음).
2. **IP 점유 구간(tenancy) 분할:** IP별 신호를 시간순으로 보며, 강한 키(머신 계정·client-id·MAC)가 기존 값과 다르게
   나타나거나 `--max-idle`(24시간) 넘게 신호가 끊기면 새 구간을 시작합니다. 이렇게 해서 DHCP 재할당으로 생기는 오결합을 막습니다.
3. **구간 결합:** 우선순위가 높은 키부터(머신 계정 → client-id → MAC → 호스트명) 같은 키를 공유하는 구간을 union-find로 묶습니다.
   두 묶음의 강한 키 값이 서로 다르면 묶지 않고 "결합 보류"로 리포트합니다. **오결합보다 중복을 택하는 정책**입니다.
4. **대표 키:** 묶음 안에서 가장 우선순위가 높은 키입니다. 식별 키가 하나도 없으면 `IP+시간` 자산이 됩니다.
5. **정규화 규칙**
   - 머신 계정: `corp.local\pc01$`와 `corp\pc01$`를 같게 봅니다(도메인 첫 레이블 기준).
   - 호스트명: 소문자 단축명을 쓰고, 15자로 잘라 비교합니다(NetBIOS 이름 길이 제한 반영).
   - NBNS 이름이 도메인/워크그룹 이름과 같으면 호스트명으로 쓰지 않습니다.
6. **보조 정보:** OS는 출처 우선순위(ntlm > smb > ssh > http_ua > dhcp), 역할은 서비스 포트 조합(88+389 → DC 등)으로 정합니다.
7. **미관리 판정:** Agent 목록과 MAC → 호스트명(DNS 이름, 머신 계정 포함) → IP 순서로 대조합니다.

## 5. 설정 (`scripts/config.zeek`)

| 항목 | 기본값 | 설명 |
|---|---|---|
| `AssetID::asset_nets` | `{}` | 자산 대역. `option`이라 Config 프레임워크로 운영 중 변경 가능 |
| `AssetID::suppress_interval` | `1hr` | 중복 억제 기간 (`&redef`) |
| `AssetID::enable_*` | `T` | 신호 소스별 on/off (`dhcp, arp, conn_mac, kerberos, ntlm, nbns, llmnr, mdns, dns, rdp, smb, http_ua, ssh, services`) |
| `AssetID::service_ports` | 주요 포트 | 포트만으로 서비스로 인정할 목록 |
| `AssetID::ignore_hostnames` | localhost 등 | 식별에 쓸 수 없는 일반 이름 |
| `AssetID::ignore_service_ports` | 137,138,1900,5353,5355/udp | 거의 모든 단말이 응답하는 포트 |
| `AssetID::nested_analyzers` | ntlm, gssapi, krb… | 다른 프로토콜 안에서 확인되는 분석기 (서비스로 따로 기록하지 않음) |

## 6. 알려진 한계와 운영 테스트 확인 항목

| 항목 | 내용 | 운영 pcap에서 확인할 것 |
|---|---|---|
| 미러 구간 | 라우팅 구간에서는 단말 MAC/ARP/DHCP 브로드캐스트가 보이지 않음 | 공유 MAC 수, `IP+시간` 자산 비율 |
| DHCP 릴레이 | 서버 쪽 미러에서는 릴레이(giaddr)를 통한 유니캐스트로 보임. 현재 로직으로 처리되지만 실측 필요 | DHCP 출처 신호 수 |
| 비대칭 캡처 | ACK가 안 보이면 DHCP 신호가 남지 않음 (갱신 REQUEST는 ciaddr로 기록) | dhcp.log와 비교 |
| MAC 랜덤화 | 모바일 단말은 SSID별 랜덤 MAC → 같은 단말이 여러 자산으로 보일 수 있음 | locally administered 비트(02:..) MAC 수 |
| 다중 NIC/VM | 한 IP에 MAC이 바뀌면 점유 구간이 나뉨 (보수적 정책) | 결합 보류, IP 재사용 목록 |
| IPv6 | DHCPv6, NDP는 아직 수집하지 않음 (mDNS/LLMNR/일반 신호는 IPv6도 기록) | IPv6 자산 비율 |
| SMB2 OS | SMB2/3 협상에는 OS 문자열이 없음. NTLM 버전으로 대체 | OS 커버리지 |
| 성능 | `new_connection`/`connection_state_remove`에서 테이블 조회 1-2회. 실측 필요 | `zeek` CPU/메모리, 처리 시간 |

### 운영 pcap 1차 결과 (200초, 2026-11-02)

| 항목 | 결과 | 해석 / 조치 |
|---|---|---|
| 자산 / 신호 | 3,177개 / 5,449건 | 대부분 내부 사설 대역 |
| 로그량 | asset_signal 870.7KB / Zeek 전체 423.5MB (**0.2%**) | 선별 전송 부담 작음 |
| DHCP, ARP 신호 | 0건 | 미러 구간이 라우팅 구간이거나 DHCP/ARP가 미러에 없음 → MAC/client-id 키 확보 불가 |
| 공유 MAC | 25개 (최대 IP 1,204개) | 게이트웨이 MAC. 식별 키에서 정상 제외 |
| 대표 키 | IP+시간 2,642 (83%), MAC(conn) 532, 호스트명 2, 머신 계정 1 | 200초 동안 Kerberos AS-REQ/NTLM이 거의 없음 |
| mDNS 호스트명 오염 | VMware 복제 VM 수십 대의 `has01(N)` 충돌 프로브가 IP당 70여 개 기록됨 | **수정:** 프로브/서비스 인스턴스 이름 제외, 확정 응답만 기록 (btest `mdns-conflict`) |
| conn 출처 MAC만 있는 자산 | 532개를 "중간"으로 표시 | **수정:** L2(ARP/DHCP) 확인이 없으면 "낮음" |
| Agent 매칭 | 0 / 3,177 | 목록 형식 문제 추정. **수정:** CP949/탭/한글 헤더/MAC 표기 다양화 지원, 리포트에 로드·매칭 건수 진단 출력 |

다음 측정 권장: 출근 시간대(로그온·DHCP 갱신 집중)를 포함해 1시간 이상 캡처, DHCP 서버·DC 구간 미러 포함 여부 확인.

운영 테스트 후 기록할 지표: 자산 수, 대표 키 분포, 키 커버리지, 공유 MAC/IP 재사용/결합 보류 건수,
`asset_signal.log` 크기(원본 로그 대비 %), 수동 표본 검증(예: 30대) 정확도.

## 7. nsm_rules 머지 가이드

1. `scripts/` 디렉터리를 `nsm_rules/asset-id/`로 복사합니다.
2. nsm_rules의 `__load__.zeek`(또는 local.zeek)에 `@load ./asset-id`를 추가합니다.
3. 고객 환경 값은 별도 설정 파일에서 redef 합니다.
   ```zeek
   redef AssetID::asset_nets = { 10.0.0.0/8, 172.20.0.0/16 };
   redef AssetID::suppress_interval = 2hr;
   ```
4. 다른 탐지 스크립트에서 신호를 추가할 때는 `AssetID::emit()`을 호출합니다.
   ```zeek
   AssetID::emit(c$id$orig_h, AssetID::HOSTNAME, name, "ldap", 80, c$uid);
   ```
5. Manager로 보낼 선별 전송 대상에 `asset_signal` 로그를 추가합니다. 수집 에이전트에서 JSON으로 처리합니다.
6. 회귀 테스트: `tests/btest`를 nsm_rules 테스트 디렉터리로 옮기거나 `PKG` 환경 변수만 바꿔서 사용합니다.

머지 시 충돌을 피하기 위한 원칙:
- 모든 식별자는 `AssetID` 모듈 안에 있습니다.
- Zeek 기본 로그와 레코드를 수정하지 않습니다(redef로 필드를 추가하지 않음). 이벤트 핸들러만 추가합니다.
- 각 신호 파일은 필요한 `base/protocols/*`를 직접 `@load`하므로 어떤 순서로 로드해도 됩니다.
