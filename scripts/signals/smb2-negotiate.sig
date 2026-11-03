# SMB2 NEGOTIATE 요청(연결 첫 메시지). 클라이언트 GUID를 꺼내기 위해 smb_guid.zeek에서 사용한다.
#   NetBIOS 세션 헤더(4) + SMB2 헤더(64, ProtocolId \xfeSMB, Command 0x0000 = NEGOTIATE)
#   + NEGOTIATE StructureSize 0x0024
# 연결 시작(^)에 고정해 첫 메시지만 본다(파일 전송 등 나머지 스트림은 검사하지 않음).
signature assetid-smb2-negotiate {
  ip-proto == tcp
  dst-port == 445
  payload /^\x00...\xfeSMB.{8}\x00\x00.{50}\x24\x00/
  event "smb2_negotiate_request"
}
