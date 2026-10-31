#!/usr/bin/env bash
# 전체 테스트: Zeek 신호(btest) + 리졸버(unittest)
# 로컬 zeek 9.x + btest 가 없으면 Docker(zeek/zeek) 이미지로 btest 실행.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:9.0.1}"

echo "== Zeek btest"
if command -v btest >/dev/null 2>&1 && command -v zeek >/dev/null 2>&1; then
	(cd "$ROOT/tests/btest" && btest -d "$@")
else
	docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$ROOT:/w" -w /w/tests/btest "$ZEEK_IMAGE" btest -d "$@"
fi

echo "== resolver unittest"
python3 -m unittest discover -s "$ROOT/tests/unit"
