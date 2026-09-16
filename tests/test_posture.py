"""セキュリティ実施状況評価（posture.py / posture_report.py）の検証。

確認すること:
1. ダミー inventory で全チェックが `CheckResult` を返すこと
2. 空 dict `{}` で例外を出さず、全件が `判定不能` になること
3. **「わざと違反させたフィクスチャ」と「わざと準拠させたフィクスチャ」の両方**で、
   代表的なチェック（NET-01 / NET-06 / ENC-01 / LOG-06 / IAM-07）が正しく反転すること
   （片方向だけのテストは不可）
4. 追加したコレクタ項目の API 呼び出しが `guard.is_allowed()` をすべて通ること（変更系ゼロ）
5. **機微情報（アクセスキーID全体・シークレット値）が出力に混ざらないこと**
6. `render_posture_markdown` が Markdown を生成できること

実行:
    python3 -m pytest tests/test_posture.py -v
"""
from __future__ import annotations

import copy
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from awsprobe import posture  # noqa: E402
from awsprobe.posture import (  # noqa: E402
    CHECKS,
    DOMAINS,
    DONE,
    NOT_APPLICABLE,
    NOT_DONE,
    PARTIAL,
    SEVERITIES,
    STATUSES,
    UNKNOWN,
    CheckResult,
    evaluate,
    score,
    top_priority,
)
from awsprobe.posture_report import (  # noqa: E402
    render_posture_markdown,
    render_posture_summary,
)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "inventory_example.json")


def _load() -> dict:
    with open(FIXTURE, encoding="utf-8") as fp:
        return json.load(fp)


def _by_cid(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {r.cid: r for r in results}


# ---------------------------------------------------------------------------
# 反転テスト用のフィクスチャ
# ---------------------------------------------------------------------------


def _violating_inventory() -> dict:
    """**わざと違反させた** inventory（代表チェックがすべて失格になる形）。"""
    return {
        "meta": {"account_id": "210987654321", "region": "ap-northeast-1"},
        "errors": [],
        "network": {
            "security_groups": [
                {
                    "GroupId": "sg-bad",
                    "GroupName": "bad-sg",
                    "VpcId": "vpc-1",
                    # NET-01: SSH と MySQL を 0.0.0.0/0 に開放
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        },
                        {
                            "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        },
                    ],
                    "IpPermissionsEgress": [],
                }
            ],
        },
        "compute": {
            "instances": [
                {
                    "InstanceId": "i-bad",
                    "State": {"Name": "running"},
                    "Placement": {"AvailabilityZone": "ap-northeast-1a"},
                    # NET-06: IMDSv1 が使える
                    "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"},
                    "Tags": [{"Key": "Name", "Value": "bad"}],
                }
            ],
        },
        "database": {
            "db_instances": [
                {
                    "DBInstanceIdentifier": "bad-db",
                    "Engine": "mysql",
                    "EngineVersion": "8.0.35",
                    # ENC-01: 保管時暗号化なし
                    "StorageEncrypted": False,
                }
            ],
        },
        "edge": {
            "load_balancers": [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:ap-northeast-1:210987654321:loadbalancer/app/bad/1",
                    "LoadBalancerName": "bad-alb",
                    "Type": "application",
                    "Scheme": "internet-facing",
                    # LOG-06: アクセスログ無効
                    "Attributes": [{"Key": "access_logs.s3.enabled", "Value": "false"}],
                }
            ],
        },
        "security": {
            "iam": {
                "roles": [
                    {
                        "RoleName": "VendorRole",
                        # IAM-07: 外部アカウント信頼・ExternalId 条件なし
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    }
                ],
            },
        },
    }


def _compliant_inventory() -> dict:
    """**わざと準拠させた** inventory（代表チェックがすべて合格になる形）。"""
    return {
        "meta": {"account_id": "210987654321", "region": "ap-northeast-1"},
        "errors": [],
        "network": {
            "security_groups": [
                {
                    "GroupId": "sg-good",
                    "GroupName": "good-sg",
                    "VpcId": "vpc-1",
                    # NET-01: 443 のみ全世界開放（許容）＋ 22 は保守拠点限定
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        },
                        {
                            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                            "IpRanges": [{"CidrIp": "203.0.113.16/28"}],
                        },
                    ],
                    "IpPermissionsEgress": [],
                }
            ],
        },
        "compute": {
            "instances": [
                {
                    "InstanceId": "i-good",
                    "State": {"Name": "running"},
                    "Placement": {"AvailabilityZone": "ap-northeast-1a"},
                    # NET-06: IMDSv2 必須
                    "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
                    "Tags": [{"Key": "Name", "Value": "good"}],
                }
            ],
        },
        "database": {
            "db_instances": [
                {
                    "DBInstanceIdentifier": "good-db",
                    "Engine": "mysql",
                    "EngineVersion": "8.0.35",
                    # ENC-01: 暗号化済み
                    "StorageEncrypted": True,
                }
            ],
        },
        "edge": {
            "load_balancers": [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:ap-northeast-1:210987654321:loadbalancer/app/good/1",
                    "LoadBalancerName": "good-alb",
                    "Type": "application",
                    "Scheme": "internet-facing",
                    # LOG-06: アクセスログ有効
                    "Attributes": [
                        {"Key": "access_logs.s3.enabled", "Value": "true"},
                        {"Key": "access_logs.s3.bucket", "Value": "log-good-alb"},
                    ],
                }
            ],
        },
        "security": {
            "iam": {
                "roles": [
                    {
                        "RoleName": "VendorRole",
                        # IAM-07: 外部アカウント信頼だが ExternalId 条件あり
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
                                    "Action": "sts:AssumeRole",
                                    "Condition": {
                                        "StringEquals": {"sts:ExternalId": "ex-vendormonitor"}
                                    },
                                }
                            ],
                        },
                    }
                ],
            },
        },
    }


# ---------------------------------------------------------------------------
# 1. 基本契約
# ---------------------------------------------------------------------------


class PostureContractTest(unittest.TestCase):
    """チェック定義と評価結果の基本契約。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = _load()
        cls.results = evaluate(cls.inventory)

    def test_all_checks_return_check_result(self) -> None:
        """全チェックが CheckResult を返し、CHECKS と 1:1 で対応すること。"""
        self.assertEqual(len(CHECKS), len(self.results))
        self.assertTrue(self.results, "チェックが1件も定義されていない")
        for result in self.results:
            with self.subTest(cid=result.cid):
                self.assertIsInstance(result, CheckResult)
                self.assertIn(result.status, STATUSES)
                self.assertTrue(result.summary.strip(), "summary が空")
                self.assertIsInstance(result.passed, list)
                self.assertIsInstance(result.failed, list)
                self.assertIsInstance(result.evidence, list)
                self.assertIsInstance(result.notes, list)
        self.assertEqual(
            [c.cid for c in CHECKS], [r.cid for r in self.results],
            "CHECKS の定義順と評価結果の順序が一致していない",
        )

    def test_check_definitions_are_well_formed(self) -> None:
        """Check の各フィールドが契約どおり埋まっていること。"""
        seen: set[str] = set()
        for check in CHECKS:
            with self.subTest(cid=check.cid):
                self.assertRegex(check.cid, r"^[A-Z]{3}-\d{2}$")
                self.assertNotIn(check.cid, seen, "cid が重複している")
                seen.add(check.cid)
                self.assertIn(check.domain, DOMAINS)
                self.assertIn(check.severity, SEVERITIES)
                self.assertTrue(check.title.strip())
                self.assertTrue(check.why.strip())
                self.assertTrue(check.reference.strip())
                # cid の接頭辞とドメインが対応していること
                self.assertEqual(
                    posture.DOMAIN_BY_PREFIX[check.cid.split("-")[0]], check.domain
                )

    def test_all_ten_domains_are_covered(self) -> None:
        """10 ドメインすべてにチェックが定義されていること。"""
        domains = {c.domain for c in CHECKS}
        for domain in DOMAINS:
            self.assertIn(domain, domains, f"ドメイン {domain} のチェックが無い")

    def test_required_check_ids_exist(self) -> None:
        """仕様で最低限求められているチェック ID がすべて存在すること。"""
        required = (
            [f"ENC-0{i}" for i in range(1, 9)]
            + [f"PUB-0{i}" for i in range(1, 8)]
            + [f"NET-0{i}" for i in range(1, 10)] + ["NET-10", "NET-11"]
            + [f"IAM-0{i}" for i in range(1, 10)]
            + [f"LOG-0{i}" for i in range(1, 10)]
            + [f"DET-0{i}" for i in range(1, 6)]
            + [f"BCP-0{i}" for i in range(1, 9)]
            + [f"KEY-0{i}" for i in range(1, 6)]
            + [f"PAT-0{i}" for i in range(1, 6)]
            + [f"GOV-0{i}" for i in range(1, 6)]
        )
        defined = {c.cid for c in CHECKS}
        for cid in required:
            self.assertIn(cid, defined, f"{cid} が未実装")

    def test_partial_fills_both_lists(self) -> None:
        """`一部実施` のときは passed と failed の両方が埋まっていること。"""
        for result in self.results:
            with self.subTest(cid=result.cid):
                if result.status == PARTIAL:
                    self.assertTrue(result.passed, "一部実施なのに passed が空")
                    self.assertTrue(result.failed, "一部実施なのに failed が空")
                elif result.status == DONE:
                    self.assertFalse(result.failed, "実施済なのに failed が埋まっている")
                elif result.status == NOT_DONE:
                    self.assertTrue(result.failed, "未実施なのに failed が空")

    def test_open_results_have_remediation(self) -> None:
        """未実施・一部実施には是正方針が必ず付くこと。"""
        for result in self.results:
            if result.is_open:
                with self.subTest(cid=result.cid):
                    self.assertTrue(
                        result.remediation.strip(), "是正方針が空"
                    )

    def test_score_aggregates_by_domain_and_severity(self) -> None:
        """score() がドメイン別・深刻度別の集計を返すこと。"""
        summary = score(self.results)
        self.assertEqual(len(self.results), summary["total"])
        self.assertEqual(
            len(self.results), sum(summary["by_status"].values())
        )
        for domain, bucket in summary["by_domain"].items():
            with self.subTest(domain=domain):
                self.assertIn(domain, DOMAINS)
                self.assertEqual(
                    bucket["total"],
                    sum(bucket[s] for s in STATUSES),
                )
                self.assertGreaterEqual(bucket["rate"], 0.0)
                self.assertLessEqual(bucket["rate"], 100.0)
        for severity in summary["by_severity"]:
            self.assertIn(severity, SEVERITIES)

    def test_top_priority_orders_by_severity_and_impact(self) -> None:
        """今すぐ直すべき上位は、未対応のものだけが深刻度順に並ぶこと。"""
        top = top_priority(self.results, limit=10)
        self.assertLessEqual(len(top), 10)
        for result in top:
            self.assertTrue(result.is_open)
        scores = [r.priority for r in top]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_posture_does_not_import_boto3(self) -> None:
        """posture.py が boto3 を import していないこと（AWS API を呼ばない契約）。"""
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "awsprobe", "posture.py",
        )
        with open(path, encoding="utf-8") as fp:
            source = fp.read()
        self.assertNotIn("import boto3", source)
        self.assertNotIn("botocore", source)
        self.assertIsNone(
            getattr(posture, "boto3", None), "posture 名前空間に boto3 が居る"
        )


# ---------------------------------------------------------------------------
# 2. 空・壊れた inventory
# ---------------------------------------------------------------------------


class PostureEmptyInventoryTest(unittest.TestCase):
    """データが無くても例外を出さないこと。"""

    def test_empty_dict_is_all_unknown(self) -> None:
        results = evaluate({})
        self.assertEqual(len(CHECKS), len(results))
        for result in results:
            with self.subTest(cid=result.cid):
                self.assertEqual(UNKNOWN, result.status)
                self.assertTrue(result.summary.strip())

    def test_none_and_garbage_do_not_raise(self) -> None:
        for bad in (None, {"network": "文字列"}, {"errors": "リストではない"}, {"meta": 1}):
            with self.subTest(inventory=bad):
                results = evaluate(bad)  # type: ignore[arg-type]
                self.assertEqual(len(CHECKS), len(results))
                for result in results:
                    self.assertIn(result.status, STATUSES)

    def test_sections_present_but_empty(self) -> None:
        """セクションはあるが中身が空でも落ちず、該当なし／未実施に振り分けられること。"""
        inventory = {name: {} for name in posture.SECTION_NAMES}
        inventory["meta"] = {"region": "ap-northeast-1"}
        inventory["errors"] = []
        results = evaluate(inventory)
        self.assertEqual(len(CHECKS), len(results))
        statuses = {r.status for r in results}
        self.assertTrue(statuses <= set(STATUSES))
        # 「セクションが無い」ではなく「リソースが0件」と判定できていること
        self.assertIn(NOT_APPLICABLE, statuses)

    def test_access_denied_is_mentioned_in_summary(self) -> None:
        """errors に AccessDenied があれば、判定不能の summary に明記されること。"""
        inventory = _load()
        inventory["security"] = {"iam": {}}
        inventory["errors"] = [
            {
                "service": "iam",
                "operation": "get_account_summary",
                "code": "AccessDenied",
                "message": "not authorized",
                "context": "アカウントサマリ",
            }
        ]
        result = _by_cid(evaluate(inventory))["IAM-01"]
        self.assertEqual(UNKNOWN, result.status)
        self.assertIn("権限不足", result.summary)
        self.assertIn("get_account_summary", result.summary)


# ---------------------------------------------------------------------------
# 3. 反転テスト（違反 ⇄ 準拠の両方向）
# ---------------------------------------------------------------------------


class PostureFlipTest(unittest.TestCase):
    """代表的なチェックが、違反／準拠のフィクスチャで**正しく反転する**こと。

    片方向だけでは「常に failed を返す実装」でも通ってしまうため、
    同じチェックについて両方向を必ず確認する。
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.bad = _by_cid(evaluate(_violating_inventory()))
        cls.good = _by_cid(evaluate(_compliant_inventory()))

    def _assert_flips(self, cid: str) -> None:
        bad, good = self.bad[cid], self.good[cid]
        self.assertEqual(
            NOT_DONE, bad.status, f"{cid}: 違反フィクスチャで未実施にならない（{bad.summary}）"
        )
        self.assertTrue(bad.failed, f"{cid}: 違反フィクスチャで failed が空")
        self.assertEqual(
            DONE, good.status, f"{cid}: 準拠フィクスチャで実施済にならない（{good.summary}）"
        )
        self.assertTrue(good.passed, f"{cid}: 準拠フィクスチャで passed が空")
        self.assertFalse(good.failed, f"{cid}: 準拠フィクスチャで failed が残っている")

    def test_net01_security_group_world_open_flips(self) -> None:
        """NET-01: 22/3306 の 0.0.0.0/0 開放 ⇄ 443 のみ開放。"""
        self._assert_flips("NET-01")
        self.assertIn("22(SSH)", " ".join(self.bad["NET-01"].failed))
        # 80/443 の全世界開放は failed ではなく注記に回ること
        self.assertTrue(
            any("443" in note for note in self.good["NET-01"].notes),
            "443 の全世界開放が注記されていない",
        )

    def test_net06_imdsv2_flips(self) -> None:
        """NET-06: HttpTokens=optional ⇄ required。"""
        self._assert_flips("NET-06")
        self.assertIn("IMDSv1", " ".join(self.bad["NET-06"].failed))

    def test_enc01_rds_encryption_flips(self) -> None:
        """ENC-01: StorageEncrypted=False ⇄ True。"""
        self._assert_flips("ENC-01")
        self.assertIn("bad-db", " ".join(self.bad["ENC-01"].failed))
        self.assertIn("good-db", " ".join(self.good["ENC-01"].passed))

    def test_log06_alb_access_logs_flips(self) -> None:
        """LOG-06: access_logs.s3.enabled=false ⇄ true。"""
        self._assert_flips("LOG-06")
        self.assertIn("bad-alb", " ".join(self.bad["LOG-06"].failed))
        self.assertIn("log-good-alb", " ".join(self.good["LOG-06"].passed))

    def test_iam07_external_trust_flips(self) -> None:
        """IAM-07: ExternalId 条件なし ⇄ あり（どちらも外部アカウントを信頼）。"""
        self._assert_flips("IAM-07")
        self.assertIn("999888777666", " ".join(self.bad["IAM-07"].failed))
        self.assertIn("ExternalId", " ".join(self.good["IAM-07"].passed))

    def test_iam07_is_not_applicable_without_external_trust(self) -> None:
        """外部信頼ロールが無い場合は `該当なし`（違反でも実施済でもない）。"""
        inventory = _compliant_inventory()
        inventory["security"]["iam"]["roles"] = [
            {
                "RoleName": "InternalRole",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
            }
        ]
        result = _by_cid(evaluate(inventory))["IAM-07"]
        self.assertEqual(NOT_APPLICABLE, result.status)

    def test_partial_when_mixed(self) -> None:
        """違反と準拠を混ぜたら `一部実施` になること（3値が区別できていること）。"""
        inventory = _violating_inventory()
        good = _compliant_inventory()
        inventory["database"]["db_instances"].extend(good["database"]["db_instances"])
        inventory["compute"]["instances"].extend(good["compute"]["instances"])
        inventory["edge"]["load_balancers"].extend(good["edge"]["load_balancers"])
        results = _by_cid(evaluate(inventory))
        for cid in ("ENC-01", "NET-06", "LOG-06"):
            with self.subTest(cid=cid):
                self.assertEqual(PARTIAL, results[cid].status)
                self.assertTrue(results[cid].passed)
                self.assertTrue(results[cid].failed)


# ---------------------------------------------------------------------------
# 4. フィクスチャに対する既知の判定
# ---------------------------------------------------------------------------


class PostureFixtureTest(unittest.TestCase):
    """ダミー inventory（Example 想定）に対する判定の妥当性。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = _load()
        cls.results = _by_cid(evaluate(cls.inventory))

    def test_website_bucket_is_noted_not_failed(self) -> None:
        """PUB-03: Website 設定のある公開バケットは failed ではなく注記になること。"""
        result = self.results["PUB-03"]
        joined_failed = " ".join(result.failed)
        joined_notes = " ".join(result.notes)
        for name in ("home.example.com", "partner.example.com"):
            self.assertNotIn(name, joined_failed, f"{name} が failed に入っている")
            self.assertIn(name, joined_notes, f"{name} が注記に入っていない")

    def test_net01_separates_web_ports_from_admin_ports(self) -> None:
        """NET-01: 443 のみ開放の SG は passed、22 を開放した SG は failed。"""
        result = self.results["NET-01"]
        self.assertIn("sg-prod-elb", " ".join(result.passed))
        self.assertIn("sg-stg-ec2", " ".join(result.failed))

    def test_unknown_results_explain_why(self) -> None:
        """判定不能には必ず理由が書かれていること。"""
        for cid, result in self.results.items():
            if result.status == UNKNOWN:
                with self.subTest(cid=cid):
                    self.assertIn("判定不能", result.summary)

    def test_inspector_unknown_mentions_access_denied(self) -> None:
        """DET-03: errors の AccessDenied が summary に明記されること。"""
        result = self.results["DET-03"]
        self.assertEqual(UNKNOWN, result.status)
        self.assertIn("権限不足", result.summary)
        self.assertIn("inspector2", result.summary)

    def test_evidence_paths_look_like_json_paths(self) -> None:
        """evidence が inventory の JSON パス表記になっていること。"""
        for cid, result in self.results.items():
            for path in result.evidence:
                with self.subTest(cid=cid, path=path):
                    self.assertRegex(path, r"^[a-z_]+(\.|\[|$)")


# ---------------------------------------------------------------------------
# 5. 機微情報が出力に混ざらないこと
# ---------------------------------------------------------------------------

#: 出力に現れてはならないパターン
_SECRET_PATTERNS = (
    (r"\b(?:AKIA|ASIA|AIDA|AROA|ANPA|ABIA|ACCA)[0-9A-Z]{16}\b", "IAM アクセスキーID／一意ID"),
    (r"(?i)\baws_secret_access_key\b", "シークレットアクセスキーの環境変数名"),
    (r"(?i)\"SecretString\"", "Secrets Manager の値"),
    (r"(?i)\bBase32StringSeed\b", "仮想 MFA のシード"),
    (r"(?i)\bQRCodePNG\b", "仮想 MFA の QR コード"),
    (r"(?i)\bPasswordData\b", "Windows のパスワードデータ"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "秘密鍵の PEM"),
)


class PostureSecretLeakTest(unittest.TestCase):
    """アクセスキーID・シークレット値が評価結果とレポートに混ざらないこと。"""

    def _scan(self, text: str, where: str) -> None:
        for pattern, label in _SECRET_PATTERNS:
            found = re.search(pattern, text)
            self.assertIsNone(
                found,
                f"{where} に{label}らしき文字列が含まれている: "
                f"{found.group(0) if found else ''}",
            )

    def test_fixture_results_contain_no_secrets(self) -> None:
        inventory = _load()
        results = evaluate(inventory)
        payload = json.dumps([r.to_dict() for r in results], ensure_ascii=False)
        self._scan(payload, "CheckResult")

    def test_markdown_contains_no_secrets(self) -> None:
        inventory = _load()
        markdown = render_posture_markdown(evaluate(inventory), inventory, redacted=False)
        self._scan(markdown, "Markdown レポート")

    def test_masked_access_keys_survive_evaluation(self) -> None:
        """アクセスキーを含む inventory を評価しても、出力はマスク済み表記のままであること。

        コレクタは `****XXXX` 形式でしか残さない契約。ここでは
        **生のキーIDが混じった inventory を渡しても出力に出ない**ことを確かめる。
        """
        inventory = _load()
        inventory["security"]["iam"]["access_keys"] = [
            {
                "UserName": "deploy-ci",
                "AccessKeyId": "****MPLE",  # コレクタがマスク済みの形
                "Status": "Active",
                "CreateDate": "2021-11-15T00:00:00+00:00",
                "LastUsedDate": None,
                "ServiceName": "s3",
            }
        ]
        results = evaluate(inventory)
        payload = json.dumps([r.to_dict() for r in results], ensure_ascii=False)
        self._scan(payload, "CheckResult（アクセスキーあり）")
        self.assertIn("****MPLE", payload, "マスク済みキーの表示自体は残ること")

        markdown = render_posture_markdown(results, inventory, redacted=False)
        self._scan(markdown, "Markdown（アクセスキーあり）")

    def test_ssm_parameter_values_are_never_referenced(self) -> None:
        """SSM パラメータの値（Value）は評価にも出力にも使わないこと。"""
        inventory = _load()
        inventory["security"]["ssm_parameters_meta"] = [
            {"Name": "/dn/prod/db_password", "Type": "String"},
            {"Name": "/dn/prod/api_token", "Type": "SecureString"},
        ]
        result = _by_cid(evaluate(inventory))["KEY-03"]
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn("Value", payload)
        self.assertIn("/dn/prod/db_password", payload, "平文パラメータ名は指摘されること")


# ---------------------------------------------------------------------------
# 6. Markdown レポート
# ---------------------------------------------------------------------------


class PostureReportTest(unittest.TestCase):
    """render_posture_markdown の体裁。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = _load()
        cls.results = evaluate(cls.inventory)
        cls.markdown = render_posture_markdown(
            cls.results, cls.inventory,
            title="テスト用 セキュリティ実施状況レポート", redacted=False,
        )

    def test_has_required_sections(self) -> None:
        for heading in (
            "# テスト用 セキュリティ実施状況レポート",
            "## 1. サマリ",
            "**ドメイン別スコア**",
            "## 2. critical / high の未対応項目",
            "この環境で今すぐ直すべき上位10件",
            "意図的な設定として除外すべきものの注記",
            "判定不能の項目と理由",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, self.markdown)

    def test_every_check_appears(self) -> None:
        for check in CHECKS:
            with self.subTest(cid=check.cid):
                self.assertIn(f"### {check.cid} {check.title}", self.markdown)

    def test_domain_rows_are_present(self) -> None:
        for domain in DOMAINS:
            self.assertIn(f"| {domain} |", self.markdown)

    def test_redacted_masks_account_id(self) -> None:
        markdown = render_posture_markdown(self.results, self.inventory, redacted=True)
        self.assertIn("＜マスク済み＞", markdown)
        self.assertNotIn("| アカウント | 210987654321 |", markdown)

    def test_renders_with_empty_inventory(self) -> None:
        markdown = render_posture_markdown(evaluate({}), {})
        self.assertIn("## 1. サマリ", markdown)
        self.assertIn("判定不能", markdown)

    def test_summary_line(self) -> None:
        line = render_posture_summary(self.results)
        for token in ("実施済", "一部", "未実施", "該当なし", "判定不能", "実施率"):
            self.assertIn(token, line)

    def test_markdown_tables_are_well_formed(self) -> None:
        """表の行がヘッダと同じ列数であること（レンダリング崩れの防止）。"""
        lines = self.markdown.splitlines()
        i = 0
        checked = 0
        while i < len(lines) - 1:
            if lines[i].startswith("|") and set(lines[i + 1].replace("|", "").strip()) <= {"-", " "}:
                width = lines[i].count("|")
                j = i + 2
                while j < len(lines) and lines[j].startswith("|"):
                    self.assertEqual(
                        width, lines[j].count("|"),
                        f"{j + 1} 行目の列数がヘッダと違う: {lines[j][:80]}",
                    )
                    j += 1
                checked += 1
                i = j
            else:
                i += 1
        self.assertGreater(checked, 5, "表がほとんど生成されていない")


# ---------------------------------------------------------------------------
# 7. 判定が inventory を書き換えないこと
# ---------------------------------------------------------------------------


class PostureImmutabilityTest(unittest.TestCase):
    """evaluate() が入力 inventory を書き換えないこと。"""

    def test_inventory_is_not_mutated(self) -> None:
        inventory = _load()
        snapshot = copy.deepcopy(inventory)
        evaluate(inventory)
        render_posture_markdown(evaluate(inventory), inventory)
        self.assertEqual(snapshot, inventory, "評価が inventory を書き換えている")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


# ---------------------------------------------------------------------------
# 8. 追加したコレクタ項目が読み取り専用ガードを通ること
# ---------------------------------------------------------------------------


class PostureCollectorGuardTest(unittest.TestCase):
    """posture.py のために追加した収集項目が、変更系 API を1つも呼ばないこと。

    moto 上でコレクタを実行し、ガードが記録した**全呼び出し**を
    `guard.is_allowed()` に通して確認する（moto が未実装の API は
    errors に記録されるだけで、呼び出し自体はガードを通過している）。
    """

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import boto3
            from moto import mock_aws
        except ImportError:  # pragma: no cover - moto 未導入環境
            raise unittest.SkipTest("moto / boto3 が導入されていない")

        from awsprobe.collectors.base import REGISTRY
        from awsprobe.collectors import compute as _compute  # noqa: F401
        from awsprobe.collectors import edge as _edge  # noqa: F401
        from awsprobe.collectors import logging_ as _logging  # noqa: F401
        from awsprobe.collectors import security as _security  # noqa: F401
        from awsprobe.guard import ReadOnlyGuard
        from awsprobe.session import Context

        for key, value in (
            ("AWS_ACCESS_KEY_ID", "testing"),
            ("AWS_SECRET_ACCESS_KEY", "testing"),
            ("AWS_SECURITY_TOKEN", "testing"),
            ("AWS_SESSION_TOKEN", "testing"),
            ("AWS_DEFAULT_REGION", "ap-northeast-1"),
        ):
            os.environ.setdefault(key, value)

        cls._mock = mock_aws()
        cls._mock.start()

        region = "ap-northeast-1"
        session = boto3.Session(region_name=region)
        ec2 = session.client("ec2", region_name=region)
        # T 系インスタンスを 1 台だけ作る（バースト設定の収集経路を通すため）
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        azs = ec2.describe_availability_zones()["AvailabilityZones"]
        subnet = ec2.create_subnet(
            VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24",
            AvailabilityZone=azs[0]["ZoneName"],
        )["Subnet"]
        image_id = ec2.describe_images()["Images"][0]["ImageId"]
        ec2.run_instances(
            ImageId=image_id, MinCount=1, MaxCount=1,
            InstanceType="t3.micro", SubnetId=subnet["SubnetId"],
        )
        # IAM ユーザーとロールを1件ずつ作る
        # （アクセスキー・MFA・インラインポリシーの収集経路を通すため）
        iam = session.client("iam")
        iam.create_user(UserName="awsprobe-test-user")
        iam.create_access_key(UserName="awsprobe-test-user")
        iam.create_role(
            RoleName="VendorMonitorTestRole",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )

        probe_session = boto3.Session(region_name=region)
        cls.guard = ReadOnlyGuard()
        cls.guard.attach(probe_session)
        cls.ctx = Context(
            session=probe_session, region=region, account_id="123456789012",
            guard=cls.guard,
        )

        cls.compute = REGISTRY["compute"]().collect(cls.ctx)
        cls.security = REGISTRY["security"]().collect(cls.ctx)
        cls.logging = REGISTRY["logging"]().collect(cls.ctx)
        cls.edge = REGISTRY["edge"]().collect(cls.ctx)
        cls.operations = cls.guard.summary()["operations"]

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_mock"):
            cls._mock.stop()

    def test_every_call_passes_the_read_only_guard(self) -> None:
        """記録された全呼び出しが is_allowed() を通ること（＝変更系ゼロ）。"""
        self.assertTrue(self.guard.calls, "API 呼び出しが1件も記録されていない")
        for service, operation in self.guard.calls:
            with self.subTest(operation=f"{service}:{operation}"):
                allowed, reason = self.guard.is_allowed(service, operation)
                self.assertTrue(allowed, f"{service}:{operation} が拒否された（{reason}）")

    def test_no_mutating_operation_prefixes(self) -> None:
        """Create / Put / Update / Delete 等の接頭辞が1つも現れないこと。"""
        forbidden_prefixes = (
            "Create", "Put", "Update", "Delete", "Modify", "Attach", "Detach",
            "Start", "Stop", "Reboot", "Terminate", "Run", "Send", "Enable",
            "Disable", "Associate", "Disassociate", "Authorize", "Revoke",
            "Register", "Deregister", "Tag", "Untag", "Import", "Export",
            "Copy", "Restore", "Reset", "Set", "Add", "Remove", "Assume",
        )
        for service, operation in self.guard.calls:
            with self.subTest(operation=f"{service}:{operation}"):
                self.assertFalse(
                    operation.startswith(forbidden_prefixes),
                    f"変更系らしき API を呼んでいる: {service}:{operation}",
                )

    def test_sensitive_operations_are_never_called(self) -> None:
        """値・秘密を引く API を1つも呼んでいないこと。"""
        for forbidden in (
            "secretsmanager:GetSecretValue",
            "ssm:GetParameter",
            "ssm:GetParameters",
            "ssm:GetParametersByPath",
            "ec2:GetPasswordData",
            "cloudtrail:LookupEvents",
            "iam:GetCredentialReport",
            "iam:GenerateCredentialReport",
        ):
            with self.subTest(operation=forbidden):
                self.assertNotIn(forbidden, self.operations)

    def test_new_read_operations_are_attempted(self) -> None:
        """posture 用に追加した読み取り API が実際に呼ばれていること。

        moto が未実装で失敗しても、ガードには呼び出しとして記録される。
        """
        for operation in (
            "ec2:GetEbsEncryptionByDefault",
            "ec2:GetEbsDefaultKmsKeyId",
            "ec2:DescribeInstanceCreditSpecifications",
            "ec2:DescribeInstanceConnectEndpoints",
            "iam:ListAccessKeys",
            "iam:GetAccessKeyLastUsed",
            "iam:ListMFADevices",
            "iam:ListVirtualMFADevices",
            "iam:ListServerCertificates",
            "iam:ListRolePolicies",
            "kms:ListKeys",
            "secretsmanager:ListSecrets",
            "ssm:DescribeParameters",
            # s3control クライアントの endpointPrefix は "s3-control"
            "s3-control:GetPublicAccessBlock",
        ):
            with self.subTest(operation=operation):
                self.assertIn(
                    operation, self.operations, f"{operation} が呼ばれていない"
                )

    def test_new_inventory_keys_exist(self) -> None:
        """追加した inventory キーが（空でも）必ず存在すること。"""
        for key in (
            "ebs_encryption_by_default", "ebs_default_kms_key_id",
            "instance_credit_specifications", "instance_connect_endpoints",
        ):
            self.assertIn(key, self.compute)
        for key in (
            "kms_keys", "secrets", "ssm_parameters_meta",
            "account_public_access_block", "securityhub_standards_controls",
            "organizations_policies",
        ):
            self.assertIn(key, self.security)
        for key in (
            "role_inline_policies", "role_attached_policy_documents",
            "access_keys", "mfa_devices", "server_certificates",
        ):
            self.assertIn(key, self.security["iam"])
        self.assertIn("log_group_kms", self.logging)

    def test_cloudtrail_and_listener_keys_are_guaranteed(self) -> None:
        """証跡とリスナーの評価用キーが必ず存在すること（欠けても None で残る）。"""
        for trail in self.logging["cloudtrail_trails"]:
            for key in (
                "LogFileValidationEnabled", "KmsKeyId",
                "IsMultiRegionTrail", "IsOrganizationTrail",
            ):
                self.assertIn(key, trail, f"cloudtrail_trails に {key} が無い")
        for listener in self.edge["listeners"]:
            self.assertIn("SslPolicy", listener)

    def test_access_key_ids_are_masked_in_collector_output(self) -> None:
        """コレクタが出力するアクセスキーIDがマスクされていること。"""
        payload = json.dumps(self.security, ensure_ascii=False, default=str)
        found = re.search(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", payload)
        self.assertIsNone(
            found,
            f"生のアクセスキーIDが出力されている: {found.group(0) if found else ''}",
        )
        for entry in self.security["iam"]["access_keys"]:
            with self.subTest(user=entry.get("UserName")):
                self.assertTrue(str(entry.get("AccessKeyId", "")).startswith("****"))

    def test_collector_output_is_json_serializable(self) -> None:
        """追加分を含めて json.dumps が通ること（datetime が ISO 文字列化されている）。"""
        for name, data in (
            ("compute", self.compute), ("security", self.security),
            ("logging", self.logging), ("edge", self.edge),
        ):
            with self.subTest(collector=name):
                json.dumps(data, ensure_ascii=False)

    def test_collected_inventory_can_be_evaluated(self) -> None:
        """moto から集めた inventory をそのまま evaluate() に渡せること。"""
        inventory = {
            "meta": {"account_id": "123456789012", "region": "ap-northeast-1"},
            "errors": self.ctx.error_dicts(),
            "compute": self.compute,
            "security": self.security,
            "logging": self.logging,
            "edge": self.edge,
        }
        results = evaluate(inventory)
        self.assertEqual(len(CHECKS), len(results))
        for result in results:
            self.assertIn(result.status, STATUSES)
