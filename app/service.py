"""业务逻辑：信任根版本、证书链、服务窗口、评估计划与批准。"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

from cryptography import x509

from . import certutils, coverage, db


class ApiError(Exception):
    """转换为 HTTP 响应的业务错误。"""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


_write_lock = threading.RLock()


# ---------------------------------------------------------------------------
# 时间工具
# ---------------------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    """UTC ISO-8601，固定毫秒宽度，可按字典序排序比较。"""
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# 序列化
# ---------------------------------------------------------------------------

def _trust_root_dict(row) -> dict:
    return {
        "version": row["version"],
        "cert_count": row["cert_count"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
    }


def _cert_dict(row) -> dict:
    return {
        "fingerprint_sha256": row["fingerprint_sha256"],
        "label": row["label"],
        "subject": row["subject"],
        "issuer": row["issuer"],
        "san_dns": json.loads(row["san_dns"]),
        "not_before": row["not_before"],
        "not_after": row["not_after"],
        "created_at": row["created_at"],
    }


def _window_dict(row) -> dict:
    return {
        "id": row["id"],
        "domain": row["domain"],
        "certificate_fingerprint": row["certificate_fingerprint"],
        "role": row["role"],
        "start": row["start_utc"],
        "end": row["end_utc"],
        "created_at": row["created_at"],
    }


def _plan_dict(row) -> dict:
    return {
        "id": row["id"],
        "domain": row["domain"],
        "eval_start": row["eval_start"],
        "eval_end": row["eval_end"],
        "trust_root_version": row["trust_root_version"],
        "crl_snapshot_version": row["crl_snapshot_version"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _approval_dict(row) -> dict:
    return {
        "id": row["id"],
        "plan_id": row["plan_id"],
        "trust_root_version": row["trust_root_version"],
        "crl_snapshot_version": row["crl_snapshot_version"],
        "cert_fingerprints": json.loads(row["cert_fingerprints"]),
        "verdict": json.loads(row["verdict_json"]),
        "superseded": bool(row["superseded"]),
        "created_at": row["created_at"],
    }


# ---------------------------------------------------------------------------
# 待复核标记（历史判定保留，仅置 superseded）
# ---------------------------------------------------------------------------

def _mark_plans_pending_review(conn, query: str, params: tuple) -> int:
    ids = [r["id"] for r in conn.execute(query, params).fetchall()]
    ts = iso_z(now_utc())
    for pid in ids:
        conn.execute(
            "UPDATE plans SET status = 'pending_review', updated_at = ? WHERE id = ?",
            (ts, pid),
        )
        conn.execute(
            "UPDATE approvals SET superseded = 1 WHERE plan_id = ? AND superseded = 0",
            (pid,),
        )
    return len(ids)


def _mark_domain_plans_pending_review(conn, domain: str) -> int:
    return _mark_plans_pending_review(
        conn,
        "SELECT id FROM plans WHERE status = 'approved' AND domain = ?",
        (domain,),
    )


# ---------------------------------------------------------------------------
# 信任根版本
# ---------------------------------------------------------------------------

def import_trust_root(version: str, pem: str) -> dict:
    try:
        roots = certutils.parse_pem_chain(pem)
    except certutils.PemParseError as exc:
        raise ApiError(400, f"invalid trust root PEM bundle: {exc}") from exc
    subjects = sorted({c.subject.rfc4514_string() for c in roots})
    ts = iso_z(now_utc())
    with _write_lock, db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (version,)
        ).fetchone():
            raise ApiError(409, f"trust root version '{version}' already exists")
        is_first = (
            conn.execute("SELECT COUNT(*) AS c FROM trust_roots").fetchone()["c"] == 0
        )
        conn.execute(
            "INSERT INTO trust_roots (version, pem, cert_count, is_active, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (version, pem, len(roots), 1 if is_first else 0, ts),
        )
    return {
        "version": version,
        "cert_count": len(roots),
        "subjects": subjects,
        "is_active": is_first,
        "created_at": ts,
    }


def list_trust_roots() -> list[dict]:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT * FROM trust_roots ORDER BY id"
        ).fetchall()
    return [_trust_root_dict(r) for r in rows]


def activate_trust_root(version: str) -> dict:
    """切换在用的信任根版本；与冻结版本不一致的已批准计划转为待复核。"""
    with _write_lock, db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM trust_roots WHERE version = ?", (version,)
        ).fetchone()
        if row is None:
            raise ApiError(404, f"unknown trust root version '{version}'")
        if row["is_active"]:
            return {
                "version": version,
                "is_active": True,
                "plans_marked_pending_review": 0,
            }
        conn.execute("UPDATE trust_roots SET is_active = 0")
        conn.execute(
            "UPDATE trust_roots SET is_active = 1 WHERE version = ?", (version,)
        )
        affected = _mark_plans_pending_review(
            conn,
            "SELECT id FROM plans WHERE status = 'approved' AND id IN ("
            "  SELECT plan_id FROM approvals"
            "  WHERE superseded = 0 AND trust_root_version != ?"
            ")",
            (version,),
        )
    return {
        "version": version,
        "is_active": True,
        "plans_marked_pending_review": affected,
    }


def _active_version(conn) -> str | None:
    row = conn.execute(
        "SELECT version FROM trust_roots WHERE is_active = 1 ORDER BY id LIMIT 1"
    ).fetchone()
    return row["version"] if row else None


# ---------------------------------------------------------------------------
# CRL 撤销快照（不可变，按版本导入）
# ---------------------------------------------------------------------------

def _known_ca_certs(conn) -> list:
    """全部已知 CA 候选：所有信任根版本的根证书 + 已导入证书链中的 CA 证书。"""
    certs, seen = [], set()
    rows = conn.execute("SELECT pem FROM trust_roots").fetchall()
    rows += conn.execute("SELECT chain_pem AS pem FROM certificates").fetchall()
    for row in rows:
        for cert in certutils.parse_pem_chain(row["pem"]):
            fp = certutils.fingerprint_sha256(cert)
            if fp not in seen and _is_ca(cert):
                seen.add(fp)
                certs.append(cert)
    return certs


def _is_ca(cert) -> bool:
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return bool(ext.value.ca)


def _validate_snapshot_crls(crls, known_cas) -> None:
    """导入期校验：同一签发者冲突、签名可验证、有效期区间完整。"""
    seen_issuers: set[str] = set()
    for crl in crls:
        issuer = crl.issuer.rfc4514_string()
        if issuer in seen_issuers:
            raise ApiError(
                409,
                f"conflicting CRLs for issuer '{issuer}' in the same snapshot",
            )
        seen_issuers.add(issuer)
        candidates = [c for c in known_cas if c.subject == crl.issuer]
        if not candidates:
            raise ApiError(
                400,
                f"CRL issuer '{issuer}' is not a known CA; import the issuing"
                " CA certificate (trust root or chain) before the CRL snapshot",
            )
        if not any(certutils.verify_crl_signature(crl, c) for c in candidates):
            raise ApiError(
                400, f"CRL issued by '{issuer}' failed signature verification"
            )
        this_update, next_update = crl.last_update_utc, crl.next_update_utc
        if next_update is None:
            raise ApiError(
                400,
                f"CRL issued by '{issuer}' has no nextUpdate; offline snapshots"
                " require a bounded validity interval",
            )
        if this_update >= next_update:
            raise ApiError(
                400,
                f"CRL issued by '{issuer}' has thisUpdate {iso_z(this_update)}"
                f" not before nextUpdate {iso_z(next_update)}",
            )


def import_crl_snapshot(version: str, pem: str) -> dict:
    try:
        crls = certutils.parse_pem_crls(pem)
    except certutils.PemParseError as exc:
        raise ApiError(400, f"invalid CRL snapshot PEM payload: {exc}") from exc
    ts = iso_z(now_utc())
    with _write_lock, db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM crl_snapshots WHERE version = ?", (version,)
        ).fetchone():
            raise ApiError(409, f"CRL snapshot version '{version}' already exists")
        _validate_snapshot_crls(crls, _known_ca_certs(conn))
        conn.execute(
            "INSERT INTO crl_snapshots (version, pem, crl_count, created_at)"
            " VALUES (?, ?, ?, ?)",
            (version, pem, len(crls), ts),
        )
    return {
        "version": version,
        "crl_count": len(crls),
        "issuers": sorted({c.issuer.rfc4514_string() for c in crls}),
        "created_at": ts,
    }


def _crl_entry_dict(crl) -> dict:
    return {
        "issuer": crl.issuer.rfc4514_string(),
        "this_update": iso_z(crl.last_update_utc),
        "next_update": iso_z(crl.next_update_utc),
        "revoked_count": len(crl),
    }


def list_crl_snapshots() -> list[dict]:
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM crl_snapshots ORDER BY id").fetchall()
    return [
        {
            "version": r["version"],
            "crl_count": r["crl_count"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def get_crl_snapshot(version: str) -> dict:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM crl_snapshots WHERE version = ?", (version,)
        ).fetchone()
    if row is None:
        raise ApiError(404, f"unknown CRL snapshot version '{version}'")
    crls = certutils.parse_pem_crls(row["pem"])
    return {
        "version": row["version"],
        "crl_count": row["crl_count"],
        "created_at": row["created_at"],
        "entries": [_crl_entry_dict(c) for c in crls],
    }


def _load_snapshot_crls(conn, version: str) -> dict[str, object]:
    """加载快照并按签发者名称索引（导入时已保证每个签发者至多一条）。"""
    row = conn.execute(
        "SELECT * FROM crl_snapshots WHERE version = ?", (version,)
    ).fetchone()
    if row is None:
        raise ApiError(404, f"unknown CRL snapshot version '{version}'")
    return {
        crl.issuer.rfc4514_string(): crl
        for crl in certutils.parse_pem_crls(row["pem"])
    }


# ---------------------------------------------------------------------------
# 证书链导入
# ---------------------------------------------------------------------------

def import_certificate(pem: str, label: str | None) -> dict:
    try:
        chain = certutils.parse_pem_chain(pem)
    except certutils.PemParseError as exc:
        raise ApiError(400, f"invalid certificate PEM chain: {exc}") from exc
    leaf = chain[0]
    fp = certutils.fingerprint_sha256(leaf)
    ts = iso_z(now_utc())
    with _write_lock, db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM certificates WHERE fingerprint_sha256 = ?", (fp,)
        ).fetchone():
            raise ApiError(
                409, f"certificate with fingerprint {fp} already imported"
            )
        conn.execute(
            "INSERT INTO certificates (fingerprint_sha256, label, subject, issuer,"
            " san_dns, not_before, not_after, leaf_pem, chain_pem, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fp,
                label,
                leaf.subject.rfc4514_string(),
                leaf.issuer.rfc4514_string(),
                json.dumps(certutils.san_dns_names(leaf)),
                iso_z(leaf.not_valid_before_utc),
                iso_z(leaf.not_valid_after_utc),
                certutils.to_pem(leaf),
                pem,
                ts,
            ),
        )
    return {
        "fingerprint_sha256": fp,
        "label": label,
        "subject": leaf.subject.rfc4514_string(),
        "issuer": leaf.issuer.rfc4514_string(),
        "san_dns": certutils.san_dns_names(leaf),
        "not_before": iso_z(leaf.not_valid_before_utc),
        "not_after": iso_z(leaf.not_valid_after_utc),
        "chain_length": len(chain),
        "created_at": ts,
    }


def list_certificates() -> list[dict]:
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM certificates ORDER BY id").fetchall()
    return [_cert_dict(r) for r in rows]


def get_certificate(fingerprint: str) -> dict:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM certificates WHERE fingerprint_sha256 = ?", (fingerprint,)
        ).fetchone()
    if row is None:
        raise ApiError(404, f"unknown certificate fingerprint '{fingerprint}'")
    result = _cert_dict(row)
    result["chain_pem"] = row["chain_pem"]
    return result


# ---------------------------------------------------------------------------
# 服务窗口
# ---------------------------------------------------------------------------

def create_window(
    domain: str, fingerprint: str, role: str, start: datetime, end: datetime
) -> dict:
    if start >= end:
        raise ApiError(
            400,
            "invalid time window: start "
            f"{iso_z(start)} must be before end {iso_z(end)}",
        )
    with _write_lock, db.connect() as conn:
        if not conn.execute(
            "SELECT 1 FROM certificates WHERE fingerprint_sha256 = ?", (fingerprint,)
        ).fetchone():
            raise ApiError(404, f"unknown certificate fingerprint '{fingerprint}'")
        ts = iso_z(now_utc())
        cur = conn.execute(
            "INSERT INTO service_windows"
            " (domain, certificate_fingerprint, role, start_utc, end_utc, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (domain, fingerprint, role, iso_z(start), iso_z(end), ts),
        )
        affected = _mark_domain_plans_pending_review(conn, domain)
        row = conn.execute(
            "SELECT * FROM service_windows WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
    result = _window_dict(row)
    result["plans_marked_pending_review"] = affected
    return result


def list_windows(domain: str | None) -> list[dict]:
    with db.connect() as conn:
        if domain:
            rows = conn.execute(
                "SELECT * FROM service_windows WHERE domain = ? ORDER BY start_utc, id",
                (domain,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM service_windows ORDER BY domain, start_utc, id"
            ).fetchall()
    return [_window_dict(r) for r in rows]


def delete_window(window_id: int) -> dict:
    with _write_lock, db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM service_windows WHERE id = ?", (window_id,)
        ).fetchone()
        if row is None:
            raise ApiError(404, f"unknown service window id {window_id}")
        conn.execute("DELETE FROM service_windows WHERE id = ?", (window_id,))
        affected = _mark_domain_plans_pending_review(conn, row["domain"])
    return {"deleted": _window_dict(row), "plans_marked_pending_review": affected}


# ---------------------------------------------------------------------------
# 评估
# ---------------------------------------------------------------------------

def _assess_window(window, cert_row, roots, domain, eval_start, eval_end,
                   crls=None, snapshot_version=None):
    """评估单个服务窗口：返回 (报告, 可用区间列表)。

    可用区间 = 窗口 ∩ 评估区间 ∩ 证书链有效期，且证书须通过全部 X.509 校验。
    选择 CRL 快照时，还须为链上每张非根证书找到其签发者签署的 CRL，
    可用区间再与撤销可用段 [thisUpdate, min(nextUpdate, 撤销生效时刻)) 求交；
    缺失或验签失败的 CRL 使该窗口完全不可用。
    """
    w_start = max(parse_ts(window["start_utc"]), eval_start)
    w_end = min(parse_ts(window["end_utc"]), eval_end)
    reasons: list[str] = []
    intervals: list[tuple[datetime, datetime]] = []
    sans: list[str] = json.loads(cert_row["san_dns"]) if cert_row else []
    crl_checks: list[dict] = []

    if cert_row is None:
        reasons.append(
            f"certificate {window['certificate_fingerprint']} not found in inventory"
        )
    else:
        try:
            certs = certutils.parse_pem_chain(cert_row["chain_pem"])
            leaf, intermediates = certs[0], certs[1:]
            sans = certutils.san_dns_names(leaf)
            if not sans:
                raise certutils.ChainValidationError(
                    "leaf certificate has no DNS subjectAltName"
                )
            if not certutils.san_matches(sans, domain):
                raise certutils.ChainValidationError(
                    f"SAN {sans} does not match domain '{domain}'"
                )
            chain = certutils.build_chain(leaf, intermediates, roots)
        except certutils.PemParseError as exc:
            reasons.append(f"stored certificate PEM unreadable: {exc}")
        except certutils.ChainValidationError as exc:
            reasons.append(str(exc))
        else:
            if w_start >= w_end:
                reasons.append("service window does not overlap the evaluation interval")
            else:
                nb, na = certutils.chain_validity_interval(chain)
                s, e = max(w_start, nb), min(w_end, na)
                if crls is not None:
                    s, e = _apply_crl_constraints(
                        chain, crls, snapshot_version, w_start, w_end, s, e,
                        reasons, crl_checks,
                    )
                if s < e:
                    intervals.append((s, e))
                if nb > w_start:
                    reasons.append(
                        f"certificate chain not valid until {iso_z(nb)},"
                        f" after window start {iso_z(w_start)}"
                    )
                if na < w_end:
                    reasons.append(
                        f"certificate chain expires at {iso_z(na)},"
                        f" before window end {iso_z(w_end)}"
                    )
                if not intervals and not reasons:
                    reasons.append(
                        "certificate validity does not overlap the service window"
                    )

    report = {
        "window_id": window["id"],
        "fingerprint": window["certificate_fingerprint"],
        "role": window["role"],
        "window": {"start": window["start_utc"], "end": window["end_utc"]},
        "subject": cert_row["subject"] if cert_row else None,
        "sans": sans,
        "usable_intervals": [
            {"start": iso_z(s), "end": iso_z(e)} for s, e in intervals
        ],
        "reasons": reasons,
    }
    if crls is not None:
        report["crl_checks"] = crl_checks
    return report, intervals


def _apply_crl_constraints(chain, crls, snapshot_version, w_start, w_end,
                           s, e, reasons, crl_checks):
    """对链上每张非根证书应用 CRL 约束，返回收紧后的可用区间 (s, e)。

    任一非根证书缺失 CRL 或 CRL 验签失败 → 撤销证据不完整，窗口完全不可用。
    否则可用区间与每条 CRL 的 [thisUpdate, min(nextUpdate, 撤销生效时刻)) 求交。
    """
    for idx, cert in enumerate(chain[:-1]):
        issuer_cert = chain[idx + 1]
        issuer = issuer_cert.subject.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        kind = "certificate" if idx == 0 else "CA certificate"
        check = {"subject": subject, "issuer": issuer}
        crl = crls.get(issuer)
        if crl is None:
            reasons.append(
                f"no CRL issued by '{issuer}' found in CRL snapshot"
                f" '{snapshot_version}' for {kind} '{subject}'"
            )
            check["error"] = "crl_missing"
            crl_checks.append(check)
            continue
        check["this_update"] = iso_z(crl.last_update_utc)
        check["next_update"] = iso_z(crl.next_update_utc)
        if not certutils.verify_crl_signature(crl, issuer_cert):
            reasons.append(
                f"CRL issued by '{issuer}' for {kind} '{subject}' failed"
                " signature verification against the chain issuer"
            )
            check["error"] = "crl_signature_invalid"
            crl_checks.append(check)
            continue
        this_update, next_update = crl.last_update_utc, crl.next_update_utc
        usable_end = next_update
        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked is not None:
            rev_at = revoked.revocation_date_utc
            check["revoked"] = True
            check["revocation_date"] = iso_z(rev_at)
            usable_end = min(usable_end, rev_at)
            if rev_at < w_end:
                reasons.append(
                    f"{kind} '{subject}' revoked by '{issuer}'"
                    f" effective {iso_z(rev_at)}"
                )
        else:
            check["revoked"] = False
        crl_checks.append(check)
        if this_update > w_start:
            reasons.append(
                f"CRL issued by '{issuer}' not valid until {iso_z(this_update)},"
                f" after window start {iso_z(w_start)}"
            )
        if next_update < w_end:
            reasons.append(
                f"CRL issued by '{issuer}' expired at {iso_z(next_update)},"
                f" before window end {iso_z(w_end)}"
            )
        s, e = max(s, this_update), min(e, usable_end)
    if any("error" in c for c in crl_checks):
        return s, s  # 撤销证据不完整：不得判为可用
    return s, e


def _evaluate(conn, plan_id, domain, eval_start, eval_end, version,
              snapshot_version=None) -> dict:
    root_row = conn.execute(
        "SELECT * FROM trust_roots WHERE version = ?", (version,)
    ).fetchone()
    if root_row is None:
        raise ApiError(404, f"unknown trust root version '{version}'")
    roots = certutils.parse_pem_chain(root_row["pem"])
    crls = None
    if snapshot_version is not None:
        crls = _load_snapshot_crls(conn, snapshot_version)
    windows = conn.execute(
        "SELECT * FROM service_windows WHERE domain = ? ORDER BY start_utc, id",
        (domain,),
    ).fetchall()

    usable: list[tuple[datetime, datetime]] = []
    reports = []
    for w in windows:
        cert_row = conn.execute(
            "SELECT * FROM certificates WHERE fingerprint_sha256 = ?",
            (w["certificate_fingerprint"],),
        ).fetchone()
        report, intervals = _assess_window(
            w, cert_row, roots, domain, eval_start, eval_end,
            crls=crls, snapshot_version=snapshot_version,
        )
        usable.extend(intervals)
        reports.append(report)

    gaps = coverage.compute_gaps(eval_start, eval_end, usable)
    result = {
        "domain": domain,
        "eval_start": iso_z(eval_start),
        "eval_end": iso_z(eval_end),
        "trust_root_version": version,
        "has_gaps": bool(gaps),
        "gaps": [{"start": iso_z(s), "end": iso_z(e)} for s, e in gaps],
        "certificates": reports,
        "evaluated_at": iso_z(now_utc()),
    }
    if snapshot_version is not None:
        result["crl_snapshot_version"] = snapshot_version
    conn.execute(
        "INSERT INTO evaluations (plan_id, trust_root_version, crl_snapshot_version,"
        " has_gaps, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (plan_id, version, snapshot_version, 1 if gaps else 0,
         json.dumps(result), iso_z(now_utc())),
    )
    conn.execute(
        "UPDATE plans SET updated_at = ? WHERE id = ?", (iso_z(now_utc()), plan_id)
    )
    return result


# ---------------------------------------------------------------------------
# 计划与批准
# ---------------------------------------------------------------------------

def _get_plan(conn, plan_id: int):
    row = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
    if row is None:
        raise ApiError(404, f"unknown plan id {plan_id}")
    return row


def create_plan(
    domain: str,
    eval_start: datetime,
    eval_end: datetime,
    trust_root_version: str | None,
    crl_snapshot_version: str | None = None,
) -> dict:
    if eval_start >= eval_end:
        raise ApiError(
            400,
            "invalid evaluation interval: eval_start "
            f"{iso_z(eval_start)} must be before eval_end {iso_z(eval_end)}",
        )
    with _write_lock, db.connect() as conn:
        version = trust_root_version or _active_version(conn)
        if version is None:
            raise ApiError(
                400,
                "no trust root version specified and no trust root version is active",
            )
        if not conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (version,)
        ).fetchone():
            raise ApiError(404, f"unknown trust root version '{version}'")
        if crl_snapshot_version is not None and not conn.execute(
            "SELECT 1 FROM crl_snapshots WHERE version = ?", (crl_snapshot_version,)
        ).fetchone():
            raise ApiError(
                404, f"unknown CRL snapshot version '{crl_snapshot_version}'"
            )
        ts = iso_z(now_utc())
        cur = conn.execute(
            "INSERT INTO plans (domain, eval_start, eval_end, trust_root_version,"
            " crl_snapshot_version, status, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
            (domain, iso_z(eval_start), iso_z(eval_end), version,
             crl_snapshot_version, ts, ts),
        )
        plan_id = cur.lastrowid
        evaluation = _evaluate(conn, plan_id, domain, eval_start, eval_end, version,
                               crl_snapshot_version)
        plan = _get_plan(conn, plan_id)
    return {"plan": _plan_dict(plan), "evaluation": evaluation}


def evaluate_plan(
    plan_id: int,
    trust_root_version: str | None,
    crl_snapshot_version: str | None = None,
) -> dict:
    with _write_lock, db.connect() as conn:
        plan = _get_plan(conn, plan_id)
        version = trust_root_version or plan["trust_root_version"]
        if not conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (version,)
        ).fetchone():
            raise ApiError(404, f"unknown trust root version '{version}'")
        if version != plan["trust_root_version"]:
            conn.execute(
                "UPDATE plans SET trust_root_version = ?, updated_at = ? WHERE id = ?",
                (version, iso_z(now_utc()), plan_id),
            )
        snapshot = plan["crl_snapshot_version"]
        if crl_snapshot_version is not None and crl_snapshot_version != snapshot:
            if not conn.execute(
                "SELECT 1 FROM crl_snapshots WHERE version = ?",
                (crl_snapshot_version,),
            ).fetchone():
                raise ApiError(
                    404, f"unknown CRL snapshot version '{crl_snapshot_version}'"
                )
            # 切换快照属于判定依据变更：已批准计划先转待复核（历史批准置为被取代）
            _mark_plans_pending_review(
                conn,
                "SELECT id FROM plans WHERE id = ? AND status = 'approved'",
                (plan_id,),
            )
            conn.execute(
                "UPDATE plans SET crl_snapshot_version = ?, updated_at = ?"
                " WHERE id = ?",
                (crl_snapshot_version, iso_z(now_utc()), plan_id),
            )
            snapshot = crl_snapshot_version
        result = _evaluate(
            conn,
            plan_id,
            plan["domain"],
            parse_ts(plan["eval_start"]),
            parse_ts(plan["eval_end"]),
            version,
            snapshot,
        )
    result["plan_id"] = plan_id
    return result


def approve_plan(plan_id: int) -> dict:
    """批准计划：仅无断档时可批准，并冻结证书指纹、信任根版本与判定。"""
    with _write_lock, db.connect() as conn:
        plan = _get_plan(conn, plan_id)
        if plan["status"] == "approved":
            raise ApiError(409, "plan is already approved")
        ev = conn.execute(
            "SELECT * FROM evaluations WHERE plan_id = ? ORDER BY id DESC LIMIT 1",
            (plan_id,),
        ).fetchone()
        if ev is None:
            raise ApiError(409, "plan has no evaluation; run evaluate first")
        verdict = json.loads(ev["result_json"])
        if verdict["has_gaps"]:
            raise ApiError(
                409,
                f"plan has {len(verdict['gaps'])} coverage gap(s);"
                " only gap-free plans can be approved",
            )
        fps = sorted(
            {
                r["certificate_fingerprint"]
                for r in conn.execute(
                    "SELECT DISTINCT certificate_fingerprint FROM service_windows"
                    " WHERE domain = ?",
                    (plan["domain"],),
                ).fetchall()
            }
        )
        ts = iso_z(now_utc())
        cur = conn.execute(
            "INSERT INTO approvals (plan_id, trust_root_version, crl_snapshot_version,"
            " cert_fingerprints, verdict_json, superseded, created_at)"
            " VALUES (?, ?, ?, ?, ?, 0, ?)",
            (plan_id, ev["trust_root_version"], ev["crl_snapshot_version"],
             json.dumps(fps), ev["result_json"], ts),
        )
        conn.execute(
            "UPDATE plans SET status = 'approved', updated_at = ? WHERE id = ?",
            (ts, plan_id),
        )
        approval = conn.execute(
            "SELECT * FROM approvals WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        plan = _get_plan(conn, plan_id)
    return {"plan": _plan_dict(plan), "approval": _approval_dict(approval)}


def get_plan(plan_id: int) -> dict:
    with db.connect() as conn:
        plan = _get_plan(conn, plan_id)
        ev = conn.execute(
            "SELECT * FROM evaluations WHERE plan_id = ? ORDER BY id DESC LIMIT 1",
            (plan_id,),
        ).fetchone()
        approvals = conn.execute(
            "SELECT * FROM approvals WHERE plan_id = ? ORDER BY id", (plan_id,)
        ).fetchall()
    result = _plan_dict(plan)
    result["latest_evaluation"] = json.loads(ev["result_json"]) if ev else None
    result["approvals"] = [_approval_dict(a) for a in approvals]
    return result


def list_plans(domain: str | None, status: str | None) -> list[dict]:
    sql = "SELECT * FROM plans"
    clauses, params = [], []
    if domain:
        clauses.append("domain = ?")
        params.append(domain)
    if status:
        clauses.append("status = ?")
        params.append(status)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id"
    with db.connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_plan_dict(r) for r in rows]


def list_evaluations(plan_id: int) -> list[dict]:
    with db.connect() as conn:
        _get_plan(conn, plan_id)
        rows = conn.execute(
            "SELECT * FROM evaluations WHERE plan_id = ? ORDER BY id", (plan_id,)
        ).fetchall()
    return [
        {
            "id": r["id"],
            "plan_id": r["plan_id"],
            "trust_root_version": r["trust_root_version"],
            "crl_snapshot_version": r["crl_snapshot_version"],
            "has_gaps": bool(r["has_gaps"]),
            "result": json.loads(r["result_json"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def list_approvals(plan_id: int) -> list[dict]:
    with db.connect() as conn:
        _get_plan(conn, plan_id)
        rows = conn.execute(
            "SELECT * FROM approvals WHERE plan_id = ? ORDER BY id", (plan_id,)
        ).fetchall()
    return [_approval_dict(r) for r in rows]
