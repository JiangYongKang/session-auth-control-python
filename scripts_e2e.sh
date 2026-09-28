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

echo "== 轮换标识 => 返回新 session_id / csrf_token =="
ROT=$(curl -s -X POST "$BASE/auth/rotate" \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test')
echo "$ROT"
NEW_SID=$(echo "$ROT" | j "['session_id']")
NEW_CSRF=$(echo "$ROT" | j "['csrf_token']")

echo "== 新标识+新令牌 同源读 => allowed（新令牌立即生效） =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $NEW_SID" \
  -d '{"resource":"docs/a","action":"read"}'; echo

echo "== 新标识+旧令牌 => CSRF_REVOKED（区别于伪造 CSRF_INVALID） =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $NEW_SID" -H "X-CSRF-Token: $CSRF" \
  -H 'Origin: http://local.test' \
  -d '{"resource":"docs/a","action":"write"}'; echo

echo "== 新标识+伪造令牌 => CSRF_INVALID =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $NEW_SID" -H "X-CSRF-Token: $(python3 -c 'print("00"*32)')" \
  -H 'Origin: http://local.test' \
  -d '{"resource":"docs/a","action":"write"}'; echo

echo "== 旧标识重放 => SESSION_REPLAYED（区别于从未存在 UNAUTHENTICATED） =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -d '{"resource":"docs/a","action":"read"}'; echo

echo "== 用新令牌登出 => logged_out =="
curl -s -X POST "$BASE/auth/logout" \
  -H "X-Session-Id: $NEW_SID" -H "X-CSRF-Token: $NEW_CSRF" \
  -H 'Origin: http://local.test'; echo
echo "== 登出后重放新标识 => SESSION_REPLAYED =="
curl -s -X POST "$BASE/access/resource" -H 'Content-Type: application/json' \
  -H "X-Session-Id: $NEW_SID" -d '{"resource":"docs/a","action":"read"}'; echo

echo "E2E_DONE"
