#!/usr/bin/env bash
# 端到端调用示例：对运行中的服务执行一次完整的换发核验流程。
# 用法: ./scripts/demo.sh [BASE_URL]   （默认 http://localhost:8000）
set -euo pipefail

BASE="${1:-http://localhost:8000}/api/v1"
JQ="python3 -m json.tool"

echo "==> 0. 健康检查"
curl -s "${BASE%/api/v1}/healthz" | $JQ

echo "==> 1. 查看信任根版本（种子数据已导入 demo-root-v1 并激活）"
curl -s "$BASE/trust-roots" | $JQ

echo "==> 2. 查看已导入证书（取第一张证书的指纹）"
curl -s "$BASE/certificates" | $JQ
FP=$(curl -s "$BASE/certificates" | python3 -c "import json,sys;print(json.load(sys.stdin)['items'][0]['fingerprint_sha256'])")
echo "   fingerprint = $FP"

echo "==> 3. 查看 demo.example.com 的服务窗口"
curl -s "$BASE/service-windows?domain=demo.example.com" | $JQ

echo "==> 4. 创建换发计划并评估（窗口首尾相接 → 无断档）"
curl -s -X POST "$BASE/plans" -H 'Content-Type: application/json' -d '{
  "domain": "demo.example.com",
  "eval_start": "2026-01-01T00:00:00Z",
  "eval_end":   "2027-01-01T00:00:00Z"
}' | $JQ

echo "==> 5. 查看种子计划 #1（已批准，含冻结判定）"
curl -s "$BASE/plans/1" | $JQ

echo "==> 6. 断档计划 #2 尝试批准（应 409 拒绝）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/plans/2/approve"

echo "==> 7. 错误处理示例"
echo "-- 7.1 PEM 格式错误（应 400）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/certificates" \
  -H 'Content-Type: application/json' -d '{"pem":"not-a-pem"}'
echo "-- 7.2 未知信任根版本（应 404）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/plans" \
  -H 'Content-Type: application/json' -d '{"domain":"demo.example.com","eval_start":"2026-01-01T00:00:00Z","eval_end":"2027-01-01T00:00:00Z","trust_root_version":"v999"}'
echo "-- 7.3 无效时间窗口（应 400）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/service-windows" \
  -H 'Content-Type: application/json' -d "{\"domain\":\"demo.example.com\",\"certificate_fingerprint\":\"$FP\",\"role\":\"planned\",\"start\":\"2027-01-01T00:00:00Z\",\"end\":\"2026-01-01T00:00:00Z\"}"

echo "==> 8. 服务窗口变动 → 已批准计划转待复核"
curl -s -X POST "$BASE/service-windows" -H 'Content-Type: application/json' -d "{
  \"domain\": \"demo.example.com\",
  \"certificate_fingerprint\": \"$FP\",
  \"role\": \"planned\",
  \"start\": \"2027-01-01T00:00:00Z\",
  \"end\":   \"2027-07-01T00:00:00Z\"
}" | $JQ
curl -s "$BASE/plans/1" | python3 -c "import json,sys;d=json.load(sys.stdin);print('plan 1 status =', d['status'])"

echo "==> 9. 复核：重新评估并再次批准"
curl -s -X POST "$BASE/plans/1/evaluate" | python3 -c "import json,sys;d=json.load(sys.stdin);print('has_gaps =', d['has_gaps'])"
curl -s -X POST "$BASE/plans/1/approve" | python3 -c "import json,sys;d=json.load(sys.stdin);print('re-approved, status =', d['plan']['status'])"

echo "==> 10. 批准历史（历史判定全部保留）"
curl -s "$BASE/plans/1/approvals" | $JQ

echo "==> 11. CRL 撤销快照：列表与详情（种子数据已导入 demo-crl-v1 / demo-crl-v2）"
curl -s "$BASE/crl-snapshots" | $JQ
curl -s "$BASE/crl-snapshots/demo-crl-v2" | $JQ

echo "==> 12. 计划 #3 已绑定干净快照 demo-crl-v1 并批准；切换到撤销快照 demo-crl-v2"
echo "    （拟启用证书 2026-09-01 起被撤销 → 断档，已批准计划先转待复核）"
curl -s -X POST "$BASE/plans/3/evaluate" -H 'Content-Type: application/json' \
  -d '{"crl_snapshot_version": "demo-crl-v2"}' | $JQ
curl -s "$BASE/plans/3" | python3 -c "import json,sys;d=json.load(sys.stdin);print('plan 3 status =', d['status'], '| snapshot =', d['crl_snapshot_version'])"
echo "-- 有断档，批准应 409"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/plans/3/approve"

echo "==> 13. 导入新快照 demo-crl-v3（种子离线签发的 PEM CRL，撤销现用证书）"
CRL_FILE="${DEMO_CRL_FILE:-./data/demo-crl-v3.pem}"
if [ -f "$CRL_FILE" ]; then
  python3 -c "import json,sys;print(json.dumps({'version':'demo-crl-v3','pem':open(sys.argv[1]).read()}))" "$CRL_FILE" \
    | curl -s -X POST "$BASE/crl-snapshots" -H 'Content-Type: application/json' -d @- | $JQ
  echo "-- 切换到 demo-crl-v3：现用证书 2026-03-01 起被撤销 → 断档 [2026-03-01, 2026-07-01)"
  curl -s -X POST "$BASE/plans/3/evaluate" -H 'Content-Type: application/json' \
    -d '{"crl_snapshot_version": "demo-crl-v3"}' \
    | python3 -c "import json,sys;d=json.load(sys.stdin);print('has_gaps =', d['has_gaps'], '| gaps =', d['gaps'])"
else
  echo "    (未找到 $CRL_FILE，跳过导入演示；本地运行时由 seed 写入 ./data/)"
fi

echo "==> 14. 切回干净快照 demo-crl-v1 → 无断档 → 重新批准"
curl -s -X POST "$BASE/plans/3/evaluate" -H 'Content-Type: application/json' \
  -d '{"crl_snapshot_version": "demo-crl-v1"}' | python3 -c "import json,sys;print('has_gaps =', json.load(sys.stdin)['has_gaps'])"
curl -s -X POST "$BASE/plans/3/approve" | python3 -c "import json,sys;d=json.load(sys.stdin);print('re-approved, status =', d['plan']['status'], '| snapshot =', d['approval']['crl_snapshot_version'])"

echo "==> 15. 评估与批准历史（各自保留快照版本与判定）"
curl -s "$BASE/plans/3/evaluations" | python3 -c "import json,sys;[print(' eval', e['id'], e['crl_snapshot_version'], 'has_gaps =', e['has_gaps']) for e in json.load(sys.stdin)['items']]"
curl -s "$BASE/plans/3/approvals" | python3 -c "import json,sys;[print(' approval', a['id'], a['crl_snapshot_version'], 'superseded =', a['superseded']) for a in json.load(sys.stdin)['items']]"

echo "==> 16. 错误处理：未知快照（应 404）/ 非法 CRL（应 400）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/plans" -H 'Content-Type: application/json' \
  -d '{"domain":"demo.example.com","eval_start":"2026-01-01T00:00:00Z","eval_end":"2027-01-01T00:00:00Z","crl_snapshot_version":"no-such-snapshot"}'
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/crl-snapshots" \
  -H 'Content-Type: application/json' -d '{"version":"bad-crl","pem":"not-a-crl"}'

echo "demo done."
