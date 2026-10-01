# TLS 证书换发核验服务（tls-cert-checker）

面向运维团队的**离线** TLS 证书换发核验服务。导入 PEM 证书链与分版本的本地信任根，
为域名登记现用（current）/拟启用（planned）证书的服务窗口，按 X.509 规则校验
签名链、CA 约束、域名 SAN 与有效期，并评估指定区间内是否存在证书覆盖断档；
仅无断档的计划可批准，批准即冻结判定依据。换发计划还可选择不可变的离线
CRL 撤销快照：评估时要求证书链每张非根证书都被其签发者的 CRL 覆盖且未被撤销。

- 技术栈：Python 3.11 · FastAPI · SQLite（标准库 sqlite3）· cryptography
- 全部计算在本地完成，不依赖任何外部服务，可离线运行

## 快速启动

### Docker Compose（一键启动并初始化）

```bash
docker compose up --build
```

启动后自动建库并写入演示数据（演示 CA、三个域名的证书/窗口/计划与 CRL 快照，
详见下文），服务地址：**http://localhost:8000**，交互式 API 文档：
**http://localhost:8000/docs**。

### 本地运行

```bash
pip install -r requirements.txt
SEED_DEMO=1 python -m scripts.seed_demo          # 可选：写入演示数据
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 运行测试

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `TLS_CHECKER_DB` | 容器内 `/data/tls_checker.db`，本地 `./data/tls_checker.db` | SQLite 数据库文件路径 |
| `SEED_DEMO` | `1` | 启动时是否写入演示数据（幂等，已初始化则跳过） |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | 监听地址与端口 |

## 概念与规则

- **信任根版本**：每个版本是一组 PEM 根证书；首个导入的版本自动激活，
  `POST /trust-roots/{version}/activate` 切换在用版本。
- **证书链**：导入的 PEM 中第一个块为叶子证书，其余为中间证书；
  以叶子证书 DER 的 SHA-256 为指纹，全局唯一。
- **服务窗口**：域名 + 证书指纹 + 角色（current/planned）+ UTC 半开区间
  `[start, end)`；前一窗口的 `end` 与后一窗口的 `start` 相接**不算断档**。
- **X.509 校验**：签名链必须逐级验证至在用版本信任根；链上每个签发者必须
  `basicConstraints CA=TRUE`、不超出 `pathLength`、`keyUsage` 含 `keyCertSign`；
  叶子证书 SAN 须匹配域名（支持 `*.example.com` 单标签通配）；
  评估时刻须落在整条链的有效期交集内。
- **断档评估**：在 `[eval_start, eval_end)` 内，每一时刻至少一张证书
  「处于服务窗口且验证通过」。返回全部断档区间与每张证书的不可用原因。
- **CRL 撤销快照（可选）**：运维导入带版本的一组 PEM CRL（`POST /crl-snapshots`）。
  每条 CRL 须由已知 CA（任一信任根版本或已导入证书链中的 CA）签署且带
  `nextUpdate`；快照导入后不可变。重复版本、同一签发者的冲突 CRL、无法解析
  或验签失败的内容一律拒绝。
- **快照约束的评估**：计划选择快照后，每次评估还须为证书链每张非根证书找到
  由其签发者签署的 CRL；仅 CRL 的 `[thisUpdate, nextUpdate)` 内且尚未到撤销
  生效时刻（`revocationDate`）的部分可用。撤销可用区间再与服务窗口、证书
  有效期和评估区间求交（端点相接不算断档）；缺失、过期或已撤销的时段计入
  断档，并返回逐证书原因（`crl_checks` + `reasons`）。非法 CRL、未知快照或
  不完整的撤销证据**不得**静默判为安全。
- **快照切换与待复核**：`POST /plans/{id}/evaluate` 可指定 `crl_snapshot_version`
  切换快照；已批准计划切换后先转 `pending_review`，历史评估与冻结批准各自
  保留当时的快照版本与判定，复核无断档后可再次批准。未选择快照的计划保持
  原评估与响应语义（不做 CRL 检查，评估结果不含 CRL 字段）。
- **批准与冻结**：仅无断档计划可批准；批准时冻结证书指纹集合、信任根版本、
  CRL 快照版本与判定结果。
- **待复核**：信任根换版或服务窗口增删后，相关已批准计划自动转为
  `pending_review`；历史评估与历史批准（含冻结判定）全部保留，
  重新评估无断档后可再次批准。
- **拒绝规则**：PEM 格式错误 → 400；无效时间窗口/评估区间 → 400；
  未知信任根版本/证书指纹/CRL 快照版本 → 404；重复信任根版本/证书指纹/
  CRL 快照版本 → 409；同一快照内同一签发者的冲突 CRL → 409；
  CRL 验签失败或签发者未知 → 400；时间戳缺时区 → 422。

## API 一览（前缀 `/api/v1`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康检查 |
| POST | `/trust-roots` | 导入信任根版本（PEM bundle） |
| GET | `/trust-roots` | 列出版本 |
| POST | `/trust-roots/{version}/activate` | 切换在用版本（触发待复核） |
| POST | `/crl-snapshots` | 导入 CRL 撤销快照（PEM，不可变） |
| GET | `/crl-snapshots` / `/crl-snapshots/{version}` | 查询快照（含每条 CRL 明细） |
| POST | `/certificates` | 导入 PEM 证书链 |
| GET | `/certificates` / `/certificates/{fp}` | 查询证书 |
| POST | `/service-windows` | 登记服务窗口 |
| GET | `/service-windows?domain=` | 查询窗口 |
| DELETE | `/service-windows/{id}` | 删除窗口（触发待复核） |
| POST | `/plans` | 创建计划并立即评估（可选 `crl_snapshot_version`） |
| GET | `/plans` / `/plans/{id}` | 查询计划（含最新评估与批准） |
| POST | `/plans/{id}/evaluate` | 重新评估（可换信任根版本 / CRL 快照） |
| POST | `/plans/{id}/approve` | 批准（仅无断档） |
| GET | `/plans/{id}/evaluations` | 评估历史 |
| GET | `/plans/{id}/approvals` | 批准历史（冻结判定） |

## 调用示例

以下示例假设服务运行于 `http://localhost:8000` 且已写入演示数据
（`SEED_DEMO=1`：演示计划 #1 已批准、计划 #2 有断档、计划 #3 绑定 CRL 快照
`demo-crl-v1` 并已批准；快照 `demo-crl-v2` 撤销了计划 #3 的拟启用证书）。
完整可执行脚本见 `scripts/demo.sh`：`./scripts/demo.sh`。

### 1. 导入信任根版本

```bash
jq -n --arg v "root-2026Q3" --rawfile pem root-ca.pem '{version: $v, pem: $pem}' \
  | curl -s -X POST http://localhost:8000/api/v1/trust-roots \
      -H 'Content-Type: application/json' -d @-
# 201 → {"version":"root-2026Q3","cert_count":1,"is_active":false,...}
# 版本重复 → 409；PEM 错误 → 400
```

### 2. 导入证书链（叶子在前，中间证书随后）

```bash
jq -n --arg pem "$(cat leaf-and-intermediate.pem)" '{label: "api.example.com-2026", pem: $pem}' \
  | curl -s -X POST http://localhost:8000/api/v1/certificates \
      -H 'Content-Type: application/json' -d @-
# 201 → {"fingerprint_sha256":"ab12...","san_dns":["api.example.com"],...}
# 指纹重复 → 409
```

### 3. 登记服务窗口（现用 + 拟启用，端点相接）

```bash
FP=<上一步返回的 fingerprint_sha256>
curl -s -X POST http://localhost:8000/api/v1/service-windows \
  -H 'Content-Type: application/json' -d "{
    \"domain\": \"api.example.com\",
    \"certificate_fingerprint\": \"$FP\",
    \"role\": \"current\",
    \"start\": \"2026-01-01T00:00:00Z\",
    \"end\":   \"2026-07-01T00:00:00Z\"}"
# 再为拟启用证书登记 [2026-07-01, 2027-01-01) 的 planned 窗口……
```

### 4. 创建计划并评估

```bash
curl -s -X POST http://localhost:8000/api/v1/plans \
  -H 'Content-Type: application/json' -d '{
    "domain": "demo-gap.example.com",
    "eval_start": "2026-01-01T00:00:00Z",
    "eval_end":   "2027-01-01T00:00:00Z"}'
```

响应（节选，演示数据中存在 14 天断档）：

```json
{
  "plan": {"id": 3, "status": "pending", "trust_root_version": "demo-root-v1", ...},
  "evaluation": {
    "has_gaps": true,
    "gaps": [{"start": "2026-06-01T00:00:00.000Z", "end": "2026-06-15T00:00:00.000Z"}],
    "certificates": [
      {"role": "current",  "usable_intervals": [{"start": "2026-01-01T00:00:00.000Z", "end": "2026-06-01T00:00:00.000Z"}], "reasons": []},
      {"role": "planned",  "usable_intervals": [{"start": "2026-06-15T00:00:00.000Z", "end": "2027-01-01T00:00:00.000Z"}], "reasons": []}
    ]
  }
}
```

证书不可用原因示例：`SAN ['x'] does not match domain '...'`、
`signature chain incomplete: ...`、`CA constraint violation: ... CA=FALSE`、
`certificate chain expires at ..., before window end ...`。

### 5. 批准计划（仅无断档）

```bash
curl -s -X POST http://localhost:8000/api/v1/plans/1/approve
# 200 → approval 中冻结 cert_fingerprints / trust_root_version / verdict
curl -s -X POST http://localhost:8000/api/v1/plans/2/approve
# 409 → {"detail":"plan has 1 coverage gap(s); only gap-free plans can be approved"}
```

### 6. 信任根换版 → 待复核 → 复核

```bash
curl -s -X POST http://localhost:8000/api/v1/trust-roots/root-2026Q4/activate
# → {"plans_marked_pending_review": N}，冻结版本不一致的已批准计划转为 pending_review
curl -s -X POST http://localhost:8000/api/v1/plans/1/evaluate \
  -H 'Content-Type: application/json' -d '{"trust_root_version": "root-2026Q4"}'
curl -s -X POST http://localhost:8000/api/v1/plans/1/approve     # 无断档后重新批准
curl -s http://localhost:8000/api/v1/plans/1/approvals           # 历史判定全部保留
```

### 7. 导入 CRL 撤销快照

```bash
# 种子数据已离线签发 demo-crl-v3.pem（撤销 demo-crl.example.com 的现用证书），
# 本地运行时位于 ./data/，容器内位于 /data/
jq -n --arg v "demo-crl-v3" --rawfile pem data/demo-crl-v3.pem '{version: $v, pem: $pem}' \
  | curl -s -X POST http://localhost:8000/api/v1/crl-snapshots \
      -H 'Content-Type: application/json' -d @-
# 201 → {"version":"demo-crl-v3","crl_count":1,"issuers":["CN=Demo Root CA,O=Ops Demo"],...}
# 版本重复 → 409；同一签发者冲突 → 409；无法解析/验签失败 → 400

curl -s http://localhost:8000/api/v1/crl-snapshots/demo-crl-v3
# → {"entries":[{"issuer":"CN=Demo Root CA,O=Ops Demo",
#    "this_update":"2026-01-01T00:00:00.000Z","next_update":"2027-01-01T00:00:00.000Z",
#    "revoked_count":1}],...}
```

### 8. 创建绑定快照的计划 / 切换快照 → 待复核 → 复核

```bash
# 创建时选择快照（未知快照 → 404）
curl -s -X POST http://localhost:8000/api/v1/plans \
  -H 'Content-Type: application/json' -d '{
    "domain": "demo-crl.example.com",
    "eval_start": "2026-01-01T00:00:00Z",
    "eval_end":   "2027-01-01T00:00:00Z",
    "crl_snapshot_version": "demo-crl-v1"}'

# 计划 #3（种子已批准）切换到撤销快照 demo-crl-v2：
# 拟启用证书 2026-09-01 起被撤销 → 断档，且已批准计划先转 pending_review
curl -s -X POST http://localhost:8000/api/v1/plans/3/evaluate \
  -H 'Content-Type: application/json' -d '{"crl_snapshot_version": "demo-crl-v2"}'
```

响应（节选）：

```json
{
  "crl_snapshot_version": "demo-crl-v2",
  "has_gaps": true,
  "gaps": [{"start": "2026-09-01T00:00:00.000Z", "end": "2027-01-01T00:00:00.000Z"}],
  "certificates": [
    {"role": "planned",
     "usable_intervals": [{"start": "2026-07-01T00:00:00.000Z", "end": "2026-09-01T00:00:00.000Z"}],
     "reasons": ["certificate 'CN=demo-crl.example.com,O=Ops Demo' revoked by 'CN=Demo Root CA,O=Ops Demo' effective 2026-09-01T00:00:00.000Z"],
     "crl_checks": [{"subject": "CN=demo-crl.example.com,O=Ops Demo", "issuer": "CN=Demo Root CA,O=Ops Demo",
                     "this_update": "2026-01-01T00:00:00.000Z", "next_update": "2027-01-01T00:00:00.000Z",
                     "revoked": true, "revocation_date": "2026-09-01T00:00:00.000Z"}]}
  ]
}
```

```bash
curl -s -X POST http://localhost:8000/api/v1/plans/3/approve   # 409：有断档不可批准
# 切回干净快照复核 → 无断档后重新批准；历史评估/批准各自保留快照版本
curl -s -X POST http://localhost:8000/api/v1/plans/3/evaluate \
  -H 'Content-Type: application/json' -d '{"crl_snapshot_version": "demo-crl-v1"}'
curl -s -X POST http://localhost:8000/api/v1/plans/3/approve
curl -s http://localhost:8000/api/v1/plans/3/evaluations   # 每次评估的快照版本与判定
curl -s http://localhost:8000/api/v1/plans/3/approvals     # 冻结批准含 crl_snapshot_version
```

## 项目结构

```
app/
  main.py       FastAPI 路由
  service.py    业务逻辑（导入/窗口/评估/批准/待复核/CRL 快照）
  certutils.py  PEM 解析（证书与 CRL）、签名链构建、CA 约束与 SAN 校验、CRL 验签
  coverage.py   半开区间断档计算
  db.py         SQLite 连接、建表与列迁移
  models.py     请求模型（时区强制、域名归一化）
scripts/
  seed_demo.py  离线生成演示 CA/证书/CRL 并初始化演示数据（幂等）
  demo.sh       端到端 curl 调用示例
  docker-entrypoint.sh
tests/          pytest 测试（49 例，覆盖全部拒绝规则、CRL 约束与复核流程）
Dockerfile / docker-compose.yml
```
