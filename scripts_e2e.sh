#!/usr/bin/env bash
# 本地端到端验证（真实 uvicorn + curl），演示主要攻击路径的判定结果。
set -u
PORT=8131
BASE="http://127.0.0.1:${PORT}"
mkdir -p .runlogs
BOOTSTRAP_ADMIN_USER=root BOOTSTRAP_ADMIN_PASSWORD=Admin12345 \
  uv run uvicorn main:app --port "$PORT" >.runlogs/e2e.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT
sleep 3

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)"; }

echo "== 自助注册 viewer/editor（admin 仅由引导创建） =="
for r in viewer editor; do
  curl -s -X POST "$BASE/auth/register" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$r\",\"password\":\"Sup3rSecret\",\"roles\":[\"$r\"]}"
  echo
done
echo "== 自助注册 admin 被拒（垂直越权防护） =="
curl -s -X POST "$BASE/auth/register" -H 'Content-Type: application/json' \
  -d '{"username":"evil","password":"Sup3rSecret","roles":["admin"]}'; echo

echo "== 登录 viewer =="
LOGIN=$(curl -s -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -H 'Origin: http://local.test' \
  -d '{"username":"viewer","password":"Sup3rSecret"}')
echo "$LOGIN" | python3 -m json.tool
SID=$(echo "$LOGIN" | j "['session_id']")
CSRF=$(echo "$LOGIN" | j "['csrf_token']")

echo "== 用户不存在 / 口令错误：对外一致 =="
curl -s -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"ghost","password":"whatever1"}'; echo
curl -s -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"wrongpass1"}'; echo

echo "== 越权（viewer 写 docs/）=> FORBIDDEN =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test' \
  -d '{"resource":"docs/a","action":"write"}'; echo

echo "== CSRF 跨来源 => CSRF_BOUND_ORIGIN =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://evil' \
  -d '{"resource":"docs/a","action":"write"}'; echo

echo "== CSRF 缺失 => CSRF_MISSING =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" \
  -d '{"resource":"docs/a","action":"write"}'; echo

echo "== 正常读 docs/a => allowed =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" \
  -d '{"resource":"docs/a","action":"read"}'; echo

echo "== 登出后重放旧标识 => SESSION_REPLAYED =="
curl -s -X POST "$BASE/auth/logout" \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test'; echo
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -d '{"resource":"docs/a","action":"read"}'; echo

echo "== 自助会话管理：清单 / 定向收回 / 引用判定 =="
# viewer 重新登录两次，制造两条活动会话
V1=$(curl -s -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -H 'Origin: http://local.test' \
  -d '{"username":"viewer","password":"Sup3rSecret"}')
S1=$(echo "$V1" | j "['session_id']"); C1=$(echo "$V1" | j "['csrf_token']")
curl -s -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -H 'Origin: http://local.test' \
  -d '{"username":"viewer","password":"Sup3rSecret"}' >/dev/null
echo "-- 活动会话清单（按创建时间稳定排序，引用为 64 hex）--"
curl -s "$BASE/account/sessions" -H "X-Session-Id: $S1" | python3 -m json.tool
REF=$(curl -s "$BASE/account/sessions" -H "X-Session-Id: $S1" | \
  python3 -c "import sys,json;print(next(s['reference'] for s in json.load(sys.stdin)['sessions'] if not s['current']))")
echo "-- 定向收回非当前会话 => status=revoked --"
curl -s -X POST "$BASE/account/sessions/revoke" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $S1" -H "X-CSRF-Token: $C1" -H 'Origin: http://local.test' \
  -d "{\"reference\":\"$REF\"}"; echo
echo "-- 同一引用再收回 => 410 SESSION_REFERENCE_REVOKED --"
curl -s -X POST "$BASE/account/sessions/revoke" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $S1" -H "X-CSRF-Token: $C1" -H 'Origin: http://local.test' \
  -d "{\"reference\":\"$REF\"}"; echo
echo "-- 伪造引用 => 404 SESSION_REFERENCE_UNKNOWN；缺 CSRF => CSRF_MISSING --"
curl -s -X POST "$BASE/account/sessions/revoke" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $S1" -H "X-CSRF-Token: $C1" -H 'Origin: http://local.test' \
  -d "{\"reference\":\"$(python3 -c 'print("0"*64)')\"}"; echo
curl -s -X POST "$BASE/account/sessions/revoke" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $S1" -H 'Origin: http://local.test' \
  -d "{\"reference\":\"$REF\"}"; echo

echo "E2E_DONE"
