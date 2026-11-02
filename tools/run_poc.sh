#!/usr/bin/env bash
# Zeek 자산 식별 PoC 실행: pcap -> Zeek(asset_signal.log) -> 리졸버(assets.csv, report.txt/html)
#
# 사용법: tools/run_poc.sh [옵션] <pcap>
#   -o DIR     출력 디렉터리 (기본: out/<pcap 이름>)
#   -n CIDRS   자산 대역, 쉼표 구분 (기본: RFC1918 등 사설 대역)  예) -n 10.0.0.0/8,172.20.0.0/16
#   -a CSV     MDS Agent 목록 CSV (미관리 자산 판정)
#   -d         로컬 zeek가 있어도 Docker(zeek/zeek) 사용
#   -z ARGS    zeek에 추가로 넘길 인자 (예: -z "AssetID::suppress_interval=30min")
#   -h         도움말
#
# 환경 변수: ZEEK_IMAGE (기본 zeek/zeek:9.0.1), PYTHON (기본 python3)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:9.0.1}"
PYTHON="${PYTHON:-python3}"
OUT="" NETS="" AGENTS="" FORCE_DOCKER=0 ZEEK_EXTRA=""

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts "o:n:a:dz:h" opt; do
	case "$opt" in
		o) OUT="$OPTARG" ;;
		n) NETS="$OPTARG" ;;
		a) AGENTS="$OPTARG" ;;
		d) FORCE_DOCKER=1 ;;
		z) ZEEK_EXTRA="$OPTARG" ;;
		h) usage 0 ;;
		*) usage 1 ;;
	esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage 1

PCAP="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
[ -f "$PCAP" ] || { echo "pcap 없음: $1" >&2; exit 1; }
[ -z "$AGENTS" ] || AGENTS="$(cd "$(dirname "$AGENTS")" && pwd)/$(basename "$AGENTS")"

NAME="$(basename "$PCAP")"; NAME="${NAME%.*}"
OUT="${OUT:-$ROOT/out/$NAME}"
mkdir -p "$OUT/zeek"
OUT="$(cd "$OUT" && pwd)"
rm -f "$OUT"/zeek/*.log

# 자산 대역 설정 파일
{
	echo "# run_poc.sh 가 생성"
	if [ -n "$NETS" ]; then
		echo "redef AssetID::asset_nets = { ${NETS//,/, } };"
	fi
} > "$OUT/zeek/poc_local.zeek"

# Zeek 실행 (로컬 8.x 이상 우선, 없으면 Docker). 검증 버전: 8.0.9, 9.0.1
zeek_major() { zeek --version 2>/dev/null | sed -E 's/.* ([0-9]+)\..*/\1/'; }
use_docker=$FORCE_DOCKER
if [ "$use_docker" -eq 0 ]; then
	if ! command -v zeek >/dev/null 2>&1; then
		use_docker=1
	elif [ "$(zeek_major)" -lt 8 ]; then
		echo "경고: 로컬 $(zeek --version) 는 8.x 미만(미검증) -> Docker 사용" >&2
		use_docker=1
	fi
fi

# shellcheck disable=SC2206
extra=( $ZEEK_EXTRA )
echo "[1/2] Zeek 분석: $PCAP"
start=$(date +%s)
if [ "$use_docker" -eq 1 ]; then
	command -v docker >/dev/null || { echo "zeek 8.x 이상 또는 docker가 필요합니다." >&2; exit 1; }
	echo "      (Docker $ZEEK_IMAGE)"
	docker run --rm --user "$(id -u):$(id -g)" \
		-v "$ROOT/scripts:/pkg/scripts:ro" \
		-v "$(dirname "$PCAP"):/pcap:ro" \
		-v "$OUT/zeek:/out" -w /out \
		"$ZEEK_IMAGE" \
		zeek -C -r "/pcap/$(basename "$PCAP")" /pkg/scripts /out/poc_local.zeek \
		LogAscii::use_json=T "${extra[@]}"
else
	echo "      (로컬 $(zeek --version))"
	(cd "$OUT/zeek" && zeek -C -r "$PCAP" "$ROOT/scripts" "$OUT/zeek/poc_local.zeek" \
		LogAscii::use_json=T "${extra[@]}")
fi
echo "      완료 ($(( $(date +%s) - start ))초)"

[ -f "$OUT/zeek/asset_signal.log" ] || touch "$OUT/zeek/asset_signal.log"

echo "[2/2] 자산 판정"
args=( "$OUT/zeek/asset_signal.log" -o "$OUT" -z "$OUT/zeek" )
[ -z "$AGENTS" ] || args+=( -a "$AGENTS" )
"$PYTHON" "$ROOT/tools/asset_resolver.py" "${args[@]}"

echo
echo "결과: $OUT"
echo "  - report.html   브라우저로 열기"
echo "  - report.txt    텍스트 요약"
echo "  - assets.csv    자산 목록 (Excel)"
[ -z "$AGENTS" ] || echo "  - unmanaged.csv 미관리 자산"
echo "  - zeek/asset_signal.log  센서 원본 신호"
