##! SMB2 클라이언트 GUID 신호.
##!
##! SMB2 NEGOTIATE 요청의 ClientGuid는 클라이언트가 정하는 16바이트 값이다. Windows는 기기별로
##! 같은 값을 계속 쓰는 것으로 알려져 있어, DC·DHCP가 안 보이는 라우팅 구간에서도 PC를 이어 줄
##! 후보 키다. 다만 재부팅·복제 VM에서의 고정·고유 여부는 실측이 필요해 식별 키가 아닌
##! 참고 정보(smb_client_guid)로 기록하고, 리포트에서 공유·변경 통계로 검증한다.
##!
##! Zeek SMB 분석기는 이 값을 이벤트로 넘겨주지 않아 시그니처로 첫 메시지만 잡아 직접 읽는다.
##! SMB1 NEGOTIATE로 시작하는 연결(구형 클라이언트)은 대상이 아니다.

@load-sigs ./smb2-negotiate.sig
@load ../main

module AssetID;

## SMB2 헤더(64) + StructureSize(2) DialectCount(2) SecurityMode(2) Reserved(2) Capabilities(4)
const SMB2_CLIENT_GUID_OFFSET = 76;

## 16바이트 GUID(앞 세 필드 리틀 엔디언) -> "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
function guid_string(b: string): string
	{
	local h = bytestring_to_hexstr(b);
	local le = function(s: string): string
		{
		local r = "";
		local i = |s|;
		while ( i > 0 )
			{
			r += s[i-2:i];
			i -= 2;
			}
		return r;
		};

	return fmt("%s-%s-%s-%s-%s", le(h[0:8]), le(h[8:12]), le(h[12:16]), h[16:20], h[20:32]);
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	if ( ! enable_smb_guid || state$sig_id != "assetid-smb2-negotiate" )
		return;

	local i = strstr(data, "\xfeSMB");    # 1부터 센다
	if ( i == 0 )
		return;

	local off = i - 1 + SMB2_CLIENT_GUID_OFFSET;
	if ( |data| < off + 16 )
		return;

	local raw = data[off:off + 16];
	if ( raw == "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" )
		return;

	local c = state$conn;
	emit(c$id$orig_h, SMB_CLIENT_GUID, guid_string(raw), "smb", 70, c$uid);
	}
