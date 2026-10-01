"""离线生成演示用 CA 与证书，并初始化一份完整的演示数据：

- 信任根版本 demo-root-v1（自动激活）
- demo.example.com：现用 + 拟启用证书，窗口首尾相接，无断档 → 计划创建并批准
- demo-gap.example.com：两窗口之间留有 14 天断档 → 计划保持 pending，演示断档报告
- demo-crl.example.com：绑定 CRL 快照 demo-crl-v1（无撤销）的计划 → 无断档并批准；
  另导入撤销了拟启用证书的快照 demo-crl-v2，演示快照切换 → 待复核 → 断档；
  同时在数据库目录写入 demo-crl-v3.pem（撤销现用证书），供 demo.sh 演示导入

幂等：若 demo-root-v1 已存在则跳过。
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app import db, service

UTC = timezone.utc
ROOT_VERSION = "demo-root-v1"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_root_ca(cn: str, nb: datetime, na: datetime):
    key = _key()
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ops Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_leaf(ca_cert, ca_key, domain: str, nb: datetime, na: datetime):
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ops Demo"),
                    x509.NameAttribute(NameOID.COMMON_NAME, domain),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def make_crl(ca_cert, ca_key, this_update: datetime, next_update: datetime,
             revoked=()):
    """离线签发 CRL。revoked: [(serial_number, revocation_date), ...]"""
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(this_update)
        .next_update(next_update)
    )
    for serial, rev_at in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(rev_at)
            .build()
        )
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def crl_pem(crl) -> str:
    return crl.public_bytes(serialization.Encoding.PEM).decode("ascii")


def t(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def main() -> None:
    db.init_db()
    with db.connect() as conn:
        if conn.execute(
            "SELECT 1 FROM trust_roots WHERE version = ?", (ROOT_VERSION,)
        ).fetchone():
            print(f"[seed] trust root '{ROOT_VERSION}' already exists, skip seeding")
            return

    root, root_key = make_root_ca("Demo Root CA", t("2025-01-01"), t("2035-01-01"))
    service.import_trust_root(ROOT_VERSION, pem(root))
    print(f"[seed] trust root '{ROOT_VERSION}' imported and activated")

    scenarios = [
        # (域名, 现用窗口, 拟启用窗口, 现用证书有效期, 拟启用证书有效期)
        (
            "demo.example.com",
            ("2026-01-01", "2026-07-01"),
            ("2026-07-01", "2027-01-01"),
            ("2026-01-01", "2026-08-01"),
            ("2026-06-01", "2027-02-01"),
        ),
        (
            "demo-gap.example.com",
            ("2026-01-01", "2026-06-01"),
            ("2026-06-15", "2027-01-01"),
            ("2026-01-01", "2026-07-01"),
            ("2026-06-10", "2027-02-01"),
        ),
    ]

    for domain, cur_win, plan_win, cur_val, plan_val in scenarios:
        cur_cert, _ = make_leaf(root, root_key, domain, t(cur_val[0]), t(cur_val[1]))
        plan_cert, _ = make_leaf(root, root_key, domain, t(plan_val[0]), t(plan_val[1]))
        cur_fp = service.import_certificate(pem(cur_cert), f"{domain}-current")[
            "fingerprint_sha256"
        ]
        plan_fp = service.import_certificate(pem(plan_cert), f"{domain}-planned")[
            "fingerprint_sha256"
        ]
        service.create_window(domain, cur_fp, "current", t(cur_win[0]), t(cur_win[1]))
        service.create_window(domain, plan_fp, "planned", t(plan_win[0]), t(plan_win[1]))
        created = service.create_plan(domain, t("2026-01-01"), t("2027-01-01"), None)
        plan_id = created["plan"]["id"]
        has_gaps = created["evaluation"]["has_gaps"]
        print(
            f"[seed] {domain}: plan #{plan_id} evaluated, has_gaps={has_gaps},"
            f" gaps={created['evaluation']['gaps']}"
        )
        if not has_gaps:
            service.approve_plan(plan_id)
            print(f"[seed] {domain}: plan #{plan_id} approved")
        else:
            print(f"[seed] {domain}: plan #{plan_id} left pending (gaps exist)")

    # ---- CRL 撤销快照演示：demo-crl.example.com ----
    crl_domain = "demo-crl.example.com"
    cur_cert, _ = make_leaf(root, root_key, crl_domain, t("2026-01-01"), t("2026-08-01"))
    plan_cert, _ = make_leaf(root, root_key, crl_domain, t("2026-06-01"), t("2027-02-01"))
    cur_fp = service.import_certificate(pem(cur_cert), f"{crl_domain}-current")[
        "fingerprint_sha256"
    ]
    plan_fp = service.import_certificate(pem(plan_cert), f"{crl_domain}-planned")[
        "fingerprint_sha256"
    ]
    service.create_window(crl_domain, cur_fp, "current", t("2026-01-01"), t("2026-07-01"))
    service.create_window(crl_domain, plan_fp, "planned", t("2026-07-01"), t("2027-01-01"))

    crl_v1 = make_crl(root, root_key, t("2026-01-01"), t("2027-01-01"))
    crl_v2 = make_crl(
        root, root_key, t("2026-01-01"), t("2027-01-01"),
        revoked=[(plan_cert.serial_number, t("2026-09-01"))],
    )
    crl_v3 = make_crl(
        root, root_key, t("2026-01-01"), t("2027-01-01"),
        revoked=[(cur_cert.serial_number, t("2026-03-01"))],
    )
    service.import_crl_snapshot("demo-crl-v1", crl_pem(crl_v1))
    service.import_crl_snapshot("demo-crl-v2", crl_pem(crl_v2))
    print("[seed] CRL snapshots 'demo-crl-v1' (clean) and 'demo-crl-v2'"
          " (revokes planned cert effective 2026-09-01) imported")

    created = service.create_plan(
        crl_domain, t("2026-01-01"), t("2027-01-01"), None, "demo-crl-v1"
    )
    plan_id = created["plan"]["id"]
    if not created["evaluation"]["has_gaps"]:
        service.approve_plan(plan_id)
        print(f"[seed] {crl_domain}: plan #{plan_id} approved"
              " (bound to CRL snapshot demo-crl-v1)")

    # 供 scripts/demo.sh 演示“导入新快照”的离线 CRL 文件（与数据库同目录）
    data_dir = os.path.dirname(os.path.abspath(db.DB_PATH))
    for version, crl in (("demo-crl-v1", crl_v1), ("demo-crl-v2", crl_v2),
                         ("demo-crl-v3", crl_v3)):
        path = os.path.join(data_dir, f"{version}.pem")
        with open(path, "w", encoding="ascii") as fh:
            fh.write(crl_pem(crl))
    print(f"[seed] demo CRL PEM files written to {data_dir}"
          " (demo-crl-v3 revokes the current cert effective 2026-03-01)")

    print("[seed] done")


if __name__ == "__main__":
    main()
