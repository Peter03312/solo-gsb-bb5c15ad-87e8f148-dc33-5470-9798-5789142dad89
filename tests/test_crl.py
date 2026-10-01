"""CRL 撤销快照：导入校验、评估约束、快照切换与待复核流程测试。"""
import pytest

from tests.helpers import crl_pem, make_ca, make_cert, make_crl, pem

DOMAIN = "crl.example.com"


@pytest.fixture()
def root(client):
    ca, ca_key = make_ca()
    client.post("/api/v1/trust-roots", json={"version": "v1", "pem": pem(ca)})
    return ca, ca_key


def _make_leaf(ca, ca_key, domain=DOMAIN, nb="2026-01-01", na="2027-01-01",
               sans=None, issuer_cert=None, issuer_key=None):
    issuer_cert = issuer_cert or ca
    issuer_key = issuer_key or ca_key
    leaf, _ = make_cert(issuer_cert, issuer_key, domain, nb=nb, na=na,
                        sans=sans if sans is not None else [domain])
    return leaf


def _import(client, *certs, label=None):
    r = client.post("/api/v1/certificates", json={"pem": pem(*certs), "label": label})
    assert r.status_code == 201, r.text
    return r.json()["fingerprint_sha256"]


def _window(client, fp, start="2026-01-01T00:00:00Z", end="2027-01-01T00:00:00Z",
            role="current", domain=DOMAIN):
    r = client.post("/api/v1/service-windows", json={
        "domain": domain, "certificate_fingerprint": fp, "role": role,
        "start": start, "end": end,
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _snapshot(client, version, pem_str):
    return client.post("/api/v1/crl-snapshots",
                       json={"version": version, "pem": pem_str})


def _plan(client, snapshot=None, domain=DOMAIN,
          start="2026-01-01T00:00:00Z", end="2027-01-01T00:00:00Z"):
    body = {"domain": domain, "eval_start": start, "eval_end": end}
    if snapshot:
        body["crl_snapshot_version"] = snapshot
    return client.post("/api/v1/plans", json=body)


# ---------------------------------------------------------------------------
# 快照导入
# ---------------------------------------------------------------------------

def test_import_snapshot_ok_list_and_detail(client, root):
    ca, ca_key = root
    inter, inter_key = make_cert(ca, ca_key, "Inter CA", is_ca=True, path_length=0)
    # 导入一条经过该中间 CA 的链，使其成为已知 CA
    leaf = _make_leaf(ca, ca_key, issuer_cert=inter, issuer_key=inter_key)
    _import(client, leaf, inter)
    crl_root = make_crl(ca, ca_key)
    crl_inter = make_crl(inter, inter_key, revoked=[(12345, "2026-05-01")])
    r = _snapshot(client, "crl-2026Q1", crl_pem(crl_root, crl_inter))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["version"] == "crl-2026Q1"
    assert body["crl_count"] == 2
    assert len(body["issuers"]) == 2

    items = client.get("/api/v1/crl-snapshots").json()["items"]
    assert [i["version"] for i in items] == ["crl-2026Q1"]

    detail = client.get("/api/v1/crl-snapshots/crl-2026Q1").json()
    assert detail["crl_count"] == 2
    entries = {e["issuer"]: e for e in detail["entries"]}
    assert any("Test Root CA" in k for k in entries)
    inter_entry = next(e for k, e in entries.items() if "Inter CA" in k)
    assert inter_entry["this_update"] == "2026-01-01T00:00:00.000Z"
    assert inter_entry["next_update"] == "2027-01-01T00:00:00.000Z"
    assert inter_entry["revoked_count"] == 1


def test_import_snapshot_bad_pem_rejected(client, root):
    ca, ca_key = root
    assert _snapshot(client, "bad1", "not a pem at all").status_code == 400
    # CRL 块之外混入垃圾内容同样拒绝
    crl = make_crl(ca, ca_key)
    assert _snapshot(client, "bad2", crl_pem(crl) + "\nGARBAGE\n").status_code == 400
    # 截断的 CRL 块
    assert _snapshot(client, "bad3", "-----BEGIN X509 CRL-----\nMIIB\n").status_code == 400
    # 证书 PEM 不是 CRL
    assert _snapshot(client, "bad4", pem(ca)).status_code == 400


def test_import_snapshot_duplicate_version_rejected(client, root):
    ca, ca_key = root
    assert _snapshot(client, "s1", crl_pem(make_crl(ca, ca_key))).status_code == 201
    r = _snapshot(client, "s1", crl_pem(make_crl(ca, ca_key)))
    assert r.status_code == 409
    assert "already exists" in r.json()["detail"]


def test_import_snapshot_conflicting_issuer_rejected(client, root):
    """同一快照内同一签发者出现两张 CRL → 冲突，拒绝。"""
    ca, ca_key = root
    crl_a = make_crl(ca, ca_key, next_update="2026-07-01")
    crl_b = make_crl(ca, ca_key, this_update="2026-07-01", next_update="2027-01-01")
    r = _snapshot(client, "conflict", crl_pem(crl_a, crl_b))
    assert r.status_code == 409
    assert "conflicting CRLs" in r.json()["detail"]


def test_import_snapshot_unknown_issuer_rejected(client, root):
    """CRL 签发者不是任何已知 CA → 无法验证签名，拒绝。"""
    stranger, stranger_key = make_ca("Stranger CA")
    r = _snapshot(client, "stranger", crl_pem(make_crl(stranger, stranger_key)))
    assert r.status_code == 400
    assert "not a known CA" in r.json()["detail"]


def test_import_snapshot_bad_signature_rejected(client, root):
    """签发者名称匹配但密钥不同（验签失败）→ 拒绝。"""
    ca, _ = root
    impostor, impostor_key = make_ca()  # 同名 "Test Root CA"，不同密钥
    assert impostor.subject == ca.subject
    r = _snapshot(client, "forged", crl_pem(make_crl(impostor, impostor_key)))
    assert r.status_code == 400
    assert "signature" in r.json()["detail"]


def test_unknown_snapshot_rejected(client, root):
    ca, ca_key = root
    fp = _import(client, _make_leaf(ca, ca_key))
    _window(client, fp)
    assert _plan(client, snapshot="no-such-snapshot").status_code == 404
    assert client.get("/api/v1/crl-snapshots/no-such-snapshot").status_code == 404
    plan_id = _plan(client).json()["plan"]["id"]
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": "no-such-snapshot"})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# 选择快照的评估
# ---------------------------------------------------------------------------

def test_snapshot_full_coverage_no_gap(client, root):
    ca, ca_key = root
    fp = _import(client, _make_leaf(ca, ca_key))
    _window(client, fp)
    _snapshot(client, "s1", crl_pem(make_crl(ca, ca_key)))

    r = _plan(client, snapshot="s1")
    assert r.status_code == 201, r.text
    assert r.json()["plan"]["crl_snapshot_version"] == "s1"
    ev = r.json()["evaluation"]
    assert ev["has_gaps"] is False
    assert ev["crl_snapshot_version"] == "s1"
    checks = ev["certificates"][0]["crl_checks"]
    assert len(checks) == 1
    assert checks[0]["revoked"] is False
    assert "Test Root CA" in checks[0]["issuer"]


def test_missing_crl_counts_as_gap(client, root):
    """快照中没有链签发者的 CRL → 撤销证据不完整，不得判为安全。"""
    ca, ca_key = root
    other, other_key = make_ca("Other Root CA")
    client.post("/api/v1/trust-roots", json={"version": "v2", "pem": pem(other)})
    fp = _import(client, _make_leaf(ca, ca_key))
    _window(client, fp)
    _snapshot(client, "s-other", crl_pem(make_crl(other, other_key)))

    ev = _plan(client, snapshot="s-other").json()["evaluation"]
    assert ev["has_gaps"] is True
    assert ev["gaps"] == [{"start": "2026-01-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == []
    assert any("no CRL issued by" in r for r in cert["reasons"])
    assert cert["crl_checks"][0]["error"] == "crl_missing"
    # 有断档 → 不可批准
    plan_id = client.get("/api/v1/plans").json()["items"][0]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 409


def test_crl_expired_mid_window_gap(client, root):
    ca, ca_key = root
    fp = _import(client, _make_leaf(ca, ca_key))
    _window(client, fp)
    _snapshot(client, "s1", crl_pem(make_crl(ca, ca_key, next_update="2026-07-01")))

    ev = _plan(client, snapshot="s1").json()["evaluation"]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == [{"start": "2026-01-01T00:00:00.000Z",
                                         "end": "2026-07-01T00:00:00.000Z"}]
    assert any("expired at" in r for r in cert["reasons"])
    assert ev["gaps"] == [{"start": "2026-07-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]


def test_crl_not_yet_valid_gap(client, root):
    ca, ca_key = root
    fp = _import(client, _make_leaf(ca, ca_key))
    _window(client, fp)
    _snapshot(client, "s1", crl_pem(make_crl(ca, ca_key, this_update="2026-03-01")))

    ev = _plan(client, snapshot="s1").json()["evaluation"]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == [{"start": "2026-03-01T00:00:00.000Z",
                                         "end": "2027-01-01T00:00:00.000Z"}]
    assert any("not valid until" in r for r in cert["reasons"])
    assert ev["gaps"] == [{"start": "2026-01-01T00:00:00.000Z",
                           "end": "2026-03-01T00:00:00.000Z"}]


def test_revoked_leaf_usable_until_revocation_date(client, root):
    """撤销生效时刻之前仍可用，之后计入断档。"""
    ca, ca_key = root
    leaf = _make_leaf(ca, ca_key)
    fp = _import(client, leaf)
    _window(client, fp)
    crl = make_crl(ca, ca_key, revoked=[(leaf.serial_number, "2026-06-01")])
    _snapshot(client, "s1", crl_pem(crl))

    ev = _plan(client, snapshot="s1").json()["evaluation"]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == [{"start": "2026-01-01T00:00:00.000Z",
                                         "end": "2026-06-01T00:00:00.000Z"}]
    assert any("revoked" in r and "2026-06-01" in r for r in cert["reasons"])
    check = cert["crl_checks"][0]
    assert check["revoked"] is True
    assert check["revocation_date"] == "2026-06-01T00:00:00.000Z"
    assert ev["gaps"] == [{"start": "2026-06-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]


def test_revocation_at_window_end_no_gap(client, root):
    """撤销生效时刻恰与窗口终点相接 → 不算断档。"""
    ca, ca_key = root
    leaf = _make_leaf(ca, ca_key)
    fp = _import(client, leaf)
    _window(client, fp)
    crl = make_crl(ca, ca_key, revoked=[(leaf.serial_number, "2027-01-01")])
    _snapshot(client, "s1", crl_pem(crl))

    ev = _plan(client, snapshot="s1").json()["evaluation"]
    assert ev["has_gaps"] is False


def test_revocation_before_window_start_no_usable_time(client, root):
    """撤销生效时刻早于窗口起点 → 整段不可用。"""
    ca, ca_key = root
    leaf = _make_leaf(ca, ca_key)
    fp = _import(client, leaf)
    _window(client, fp)
    crl = make_crl(ca, ca_key, revoked=[(leaf.serial_number, "2025-06-01")])
    _snapshot(client, "s1", crl_pem(crl))

    ev = _plan(client, snapshot="s1").json()["evaluation"]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == []
    assert any("revoked" in r for r in cert["reasons"])
    assert ev["gaps"] == [{"start": "2026-01-01T00:00:00.000Z",
                           "end": "2027-01-01T00:00:00.000Z"}]


def test_revocation_handoff_to_next_window_no_gap(client, root):
    """现用证书在窗口终点被撤销，拟启用证书端点相接 → 无断档。"""
    ca, ca_key = root
    cur = _make_leaf(ca, ca_key, na="2026-08-01")
    nxt = _make_leaf(ca, ca_key, nb="2026-06-01", na="2027-02-01")
    cur_fp, nxt_fp = _import(client, cur), _import(client, nxt)
    _window(client, cur_fp, "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z", "current")
    _window(client, nxt_fp, "2026-07-01T00:00:00Z", "2027-01-01T00:00:00Z", "planned")
    crl = make_crl(ca, ca_key, revoked=[(cur.serial_number, "2026-07-01")])
    _snapshot(client, "s1", crl_pem(crl))

    ev = _plan(client, snapshot="s1").json()["evaluation"]
    assert ev["has_gaps"] is False


def test_intermediate_chain_requires_crl_for_every_non_root(client, root):
    """链上每张非根证书（含中间 CA）都需要其签发者的 CRL。"""
    ca, ca_key = root
    inter, inter_key = make_cert(ca, ca_key, "Inter CA", is_ca=True, path_length=0)
    leaf = _make_leaf(ca, ca_key, issuer_cert=inter, issuer_key=inter_key)
    fp = _import(client, leaf, inter)
    _window(client, fp)

    # 只有中间 CA 的 CRL（覆盖叶子），缺根 CA 的 CRL（覆盖中间证书）→ 断档
    _snapshot(client, "s-partial", crl_pem(make_crl(inter, inter_key)))
    ev = _plan(client, snapshot="s-partial").json()["evaluation"]
    assert ev["has_gaps"] is True
    reasons = ev["certificates"][0]["reasons"]
    assert any("no CRL issued by" in r and "Test Root CA" in r for r in reasons)

    # 两个签发者的 CRL 齐备 → 无断档
    _snapshot(client, "s-full",
              crl_pem(make_crl(ca, ca_key), make_crl(inter, inter_key)))
    plan_id = client.get("/api/v1/plans").json()["items"][0]["id"]
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": "s-full"})
    assert r.json()["has_gaps"] is False
    checks = r.json()["certificates"][0]["crl_checks"]
    assert len(checks) == 2  # 叶子 + 中间证书


def test_intermediate_cert_revoked_by_root(client, root):
    """中间 CA 证书被根撤销 → 撤销生效后链不可用。"""
    ca, ca_key = root
    inter, inter_key = make_cert(ca, ca_key, "Inter CA", is_ca=True, path_length=0)
    leaf = _make_leaf(ca, ca_key, issuer_cert=inter, issuer_key=inter_key)
    fp = _import(client, leaf, inter)
    _window(client, fp)
    crl_root = make_crl(ca, ca_key, revoked=[(inter.serial_number, "2026-06-01")])
    _snapshot(client, "s1", crl_pem(crl_root, make_crl(inter, inter_key)))

    ev = _plan(client, snapshot="s1").json()["evaluation"]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == [{"start": "2026-01-01T00:00:00.000Z",
                                         "end": "2026-06-01T00:00:00.000Z"}]
    assert any("CA certificate" in r and "revoked" in r for r in cert["reasons"])


def test_crl_must_be_signed_by_actual_chain_issuer(client, root):
    """CRL 由同名但不同密钥的 CA 签署：导入期可过，评估时对不上链签发者 → 断档。"""
    ca, ca_key = root
    inter1, inter1_key = make_cert(ca, ca_key, "Inter CA", is_ca=True, path_length=0)
    inter2, inter2_key = make_cert(ca, ca_key, "Inter CA", is_ca=True, path_length=0)
    leaf1 = _make_leaf(ca, ca_key, issuer_cert=inter1, issuer_key=inter1_key)
    leaf2 = _make_leaf(ca, ca_key, issuer_cert=inter2, issuer_key=inter2_key)
    fp1 = _import(client, leaf1, inter1, label="chain-1")
    _import(client, leaf2, inter2, label="chain-2")  # inter2 成为已知 CA
    _window(client, fp1)
    # CRL 由 inter2 签署（导入期验签通过），但 fp1 的链签发者是 inter1
    _snapshot(client, "s1",
              crl_pem(make_crl(ca, ca_key), make_crl(inter2, inter2_key)))

    ev = _plan(client, snapshot="s1").json()["evaluation"]
    cert = ev["certificates"][0]
    assert cert["usable_intervals"] == []
    assert any("failed" in r and "signature" in r for r in cert["reasons"])
    errors = {c.get("error") for c in cert["crl_checks"]}
    assert "crl_signature_invalid" in errors
    assert ev["has_gaps"] is True


# ---------------------------------------------------------------------------
# 快照切换、待复核与历史保留
# ---------------------------------------------------------------------------

def test_switch_snapshot_marks_approved_plan_pending_review(client, root):
    ca, ca_key = root
    leaf = _make_leaf(ca, ca_key)
    fp = _import(client, leaf)
    _window(client, fp)
    _snapshot(client, "s-clean", crl_pem(make_crl(ca, ca_key)))

    plan_id = _plan(client, snapshot="s-clean").json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200
    approval = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"][0]
    assert approval["crl_snapshot_version"] == "s-clean"

    # 新快照撤销了该证书 → 切换后已批准计划先转待复核
    crl = make_crl(ca, ca_key, revoked=[(leaf.serial_number, "2026-06-01")])
    _snapshot(client, "s-revoked", crl_pem(crl))
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": "s-revoked"})
    assert r.json()["has_gaps"] is True
    assert r.json()["crl_snapshot_version"] == "s-revoked"
    plan = client.get(f"/api/v1/plans/{plan_id}").json()
    assert plan["status"] == "pending_review"
    assert plan["crl_snapshot_version"] == "s-revoked"
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 409

    # 历史评估与冻结批准各自保留快照版本与判定
    evals = client.get(f"/api/v1/plans/{plan_id}/evaluations").json()["items"]
    assert [e["crl_snapshot_version"] for e in evals] == ["s-clean", "s-revoked"]
    assert [e["has_gaps"] for e in evals] == [False, True]
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert len(approvals) == 1
    assert approvals[0]["superseded"] is True
    assert approvals[0]["crl_snapshot_version"] == "s-clean"
    assert approvals[0]["verdict"]["has_gaps"] is False

    # 换一个干净的快照复核 → 无断档后可再次批准
    _snapshot(client, "s-clean-2",
              crl_pem(make_crl(ca, ca_key, this_update="2026-01-01")))
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": "s-clean-2"})
    assert r.json()["has_gaps"] is False
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200
    approvals = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"]
    assert [a["crl_snapshot_version"] for a in approvals] == ["s-clean", "s-clean-2"]
    assert [a["superseded"] for a in approvals] == [True, False]


def test_evaluate_with_same_snapshot_keeps_approved(client, root):
    """重评未切换快照 → 不触发待复核。"""
    ca, ca_key = root
    fp = _import(client, _make_leaf(ca, ca_key))
    _window(client, fp)
    _snapshot(client, "s1", crl_pem(make_crl(ca, ca_key)))
    plan_id = _plan(client, snapshot="s1").json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200

    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": "s1"})
    assert r.json()["has_gaps"] is False
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "approved"
    # 不传快照字段 → 沿用计划当前快照
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate", json={})
    assert r.json()["crl_snapshot_version"] == "s1"
    assert client.get(f"/api/v1/plans/{plan_id}").json()["status"] == "approved"


def test_plan_without_snapshot_keeps_original_semantics(client, root):
    """未选择快照的计划：评估与响应语义与引入 CRL 前一致。"""
    ca, ca_key = root
    fp = _import(client, _make_leaf(ca, ca_key))
    _window(client, fp)
    _snapshot(client, "s1", crl_pem(make_crl(ca, ca_key)))  # 快照存在但未被选择

    r = _plan(client)
    assert r.status_code == 201, r.text
    assert r.json()["plan"]["crl_snapshot_version"] is None
    ev = r.json()["evaluation"]
    assert ev["has_gaps"] is False
    assert "crl_snapshot_version" not in ev
    assert "crl_checks" not in ev["certificates"][0]

    plan_id = r.json()["plan"]["id"]
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200
    approval = client.get(f"/api/v1/plans/{plan_id}/approvals").json()["items"][0]
    assert approval["crl_snapshot_version"] is None
    assert "crl_snapshot_version" not in approval["verdict"]


def test_evaluate_adopts_snapshot_on_legacy_plan(client, root):
    """既有无快照计划可在重评时选择快照；已批准则先转待复核。"""
    ca, ca_key = root
    leaf = _make_leaf(ca, ca_key)
    fp = _import(client, leaf)
    _window(client, fp)
    plan_id = _plan(client).json()["plan"]["id"]  # 未选择快照
    assert client.post(f"/api/v1/plans/{plan_id}/approve").status_code == 200

    crl = make_crl(ca, ca_key, revoked=[(leaf.serial_number, "2026-06-01")])
    _snapshot(client, "s1", crl_pem(crl))
    r = client.post(f"/api/v1/plans/{plan_id}/evaluate",
                    json={"crl_snapshot_version": "s1"})
    assert r.json()["has_gaps"] is True
    assert r.json()["crl_snapshot_version"] == "s1"
    plan = client.get(f"/api/v1/plans/{plan_id}").json()
    assert plan["status"] == "pending_review"
    assert plan["crl_snapshot_version"] == "s1"
