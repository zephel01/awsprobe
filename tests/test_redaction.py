"""マスキングと「収集できていないこと」の扱いに関する回帰テスト。

検証レポートで見つかった 4 つの欠陥が二度と再発しないことを固定する。

- **C-1**: 既定のマスキングが critical チェック IAM-07 を無言で無効化していた。
  マスク前とマスク後で判定結果が一致することを、生データとの突合で検証する。
- **C-2**: `--dry-run` の生成物が本物と区別できず、確定的な誤判定を生んでいた。
  `meta.dry_run` が立った inventory は判定側が終了コード 2 で拒否することを検証する。
- **I-5**: 下流生成器が `redact()` を呼んでおらず、生値の inventory から作った
  Markdown / Excel / TSV にアカウントID とグローバルIP が素通りしていた。
- **I-6**: スロットリング・期限切れが「リソースが存在しない」と同義になっていた。
  該当サービスに `fatal` なエラーがあるチェックが `該当なし` ではなく
  `判定不能` になることを検証する。

実行:
    python3 -m pytest tests/test_redaction.py -v
"""
from __future__ import annotations

import copy
import json
import os
import re
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from awsprobe.cli import main  # noqa: E402
from awsprobe.guard import (  # noqa: E402
    ACCOUNT_TOKEN_RE,
    SELF_ACCOUNT_TOKEN,
    account_token,
    is_account_token,
    mask_secret_values,
    redact,
)
from awsprobe.posture import (  # noqa: E402
    NOT_APPLICABLE,
    UNKNOWN,
    evaluate,
)

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "inventory_example.json")

#: 生の 12 桁アカウントID（リソースID の一部は拾わない）
ACCOUNT_RE = re.compile(r"(?<![\w.-])\d{12}(?![\w.-])")
#: フィクスチャに入っているグローバルIP（TEST-NET-2 / TEST-NET-3）
GLOBAL_IP_RE = re.compile(r"(?<![\w.-])(?:198\.51\.100|203\.0\.113)\.\d{1,3}(?![\w.-])")


def _load_fixture() -> dict:
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


def _by_cid(results) -> dict:
    return {r.cid: r for r in results}


def _text_of(path: str) -> str:
    """成果物の中身をテキストとして読む（xlsx は XML を結合する）。"""
    if path.endswith(".xlsx"):
        with zipfile.ZipFile(path) as zf:
            return "".join(
                zf.read(name).decode("utf-8", errors="ignore")
                for name in zf.namelist()
                if name.endswith(".xml")
            )
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


# ===========================================================================
# C-1: マスキングが判定を壊さないこと
# ===========================================================================


class MaskedEvaluationMatchesRawTest(unittest.TestCase):
    """**本修正の核心**。マスク済み inventory でも外部アカウント信頼を検出できること。

    `redact()` はアカウントIDを消さずに擬似化する（同じIDは同じトークン、
    自アカウントは `＜自アカウント＞`）。したがって「外部アカウントを信頼して
    いるか」という判定はマスク後も成立しなければならない。
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = _load_fixture()
        cls.account_id = cls.raw["meta"]["account_id"]
        cls.masked = redact(cls.raw, {cls.account_id})
        cls.raw_results = _by_cid(evaluate(cls.raw))
        cls.masked_results = _by_cid(evaluate(cls.masked))

    def test_fixture_is_unmasked(self) -> None:
        """前提: フィクスチャは生値であること（テストが無意味化していないか）。"""
        self.assertFalse(self.raw["meta"]["redacted"])
        self.assertRegex(self.account_id, r"^\d{12}$")

    def test_meta_account_id_becomes_self_token(self) -> None:
        self.assertEqual(SELF_ACCOUNT_TOKEN, self.masked["meta"]["account_id"])

    def test_iam07_status_matches(self) -> None:
        """IAM-07（critical）: マスク前後で status が一致すること。"""
        self.assertEqual(
            self.raw_results["IAM-07"].status,
            self.masked_results["IAM-07"].status,
            "マスクすると外部信頼ロールが検出できなくなっている（C-1 の再発）",
        )
        # 「該当なし」同士で一致してしまうと検証にならないので、
        # フィクスチャに外部信頼ロールが実在することも固定する。
        self.assertNotEqual(NOT_APPLICABLE, self.raw_results["IAM-07"].status)

    def test_gov05_status_matches(self) -> None:
        """GOV-05（StackSet の権限モデル）も同様に一致すること。"""
        self.assertEqual(
            self.raw_results["GOV-05"].status,
            self.masked_results["GOV-05"].status,
            "マスクすると外部アカウント管理の StackSet が検出できなくなっている",
        )

    def test_all_checks_have_identical_status(self) -> None:
        """72 件すべてで status が一致すること（他に同じ前提を置いた箇所が無いか）。"""
        mismatched = [
            (cid, self.raw_results[cid].status, self.masked_results[cid].status)
            for cid in self.raw_results
            if self.raw_results[cid].status != self.masked_results[cid].status
        ]
        self.assertEqual([], mismatched, f"マスクで判定が変わるチェックがある: {mismatched}")

    def test_external_account_is_still_identifiable(self) -> None:
        """信頼先が「外部の誰か」として読めること（トークンが残っていること）。"""
        failed = " ".join(self.masked_results["IAM-07"].failed)
        self.assertRegex(failed, ACCOUNT_TOKEN_RE.pattern)
        self.assertNotIn(SELF_ACCOUNT_TOKEN, failed)

    def test_same_external_account_shares_one_token(self) -> None:
        """IAM-07 と GOV-05 が指す外部アカウントが同一だと分かること。"""
        iam = ACCOUNT_TOKEN_RE.findall(" ".join(self.masked_results["IAM-07"].failed))
        gov = ACCOUNT_TOKEN_RE.findall(" ".join(self.masked_results["GOV-05"].failed))
        self.assertTrue(iam and gov)
        self.assertEqual(set(iam), set(gov))


# ===========================================================================
# C-2: --dry-run の成果物で判定させないこと
# ===========================================================================


class DryRunInventoryIsRejectedTest(unittest.TestCase):
    """`meta.dry_run: true` の inventory は判定側が終了コード 2 で拒否すること。"""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="awsprobe-dryrun-")
        inv = _load_fixture()
        inv["meta"]["dry_run"] = True
        inv["meta"]["collectors_run"] = []
        self.path = os.path.join(self.tmp, "inventory.json")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(inv, fh, ensure_ascii=False)

    def test_answer_posture_excel_are_rejected(self) -> None:
        for command in ("answer", "posture", "excel"):
            with self.subTest(command=command):
                rc = main([command, "--inventory", self.path, "--out", self.tmp])
                self.assertEqual(2, rc)

    def test_diagram_data_is_rejected(self) -> None:
        rc = main(["diagram-data", "--inventory", self.path, "--out", self.tmp])
        self.assertEqual(2, rc)

    def test_no_report_is_written(self) -> None:
        """拒否したときに中途半端な成果物を残さないこと。"""
        main(["posture", "--inventory", self.path, "--out", self.tmp])
        self.assertFalse(
            os.path.exists(os.path.join(self.tmp, "セキュリティ設定_実施状況.md"))
        )

    def test_normal_inventory_is_accepted(self) -> None:
        """dry_run が無い（または false）なら従来どおり通ること。"""
        rc = main(["posture", "--inventory", FIXTURE, "--out", self.tmp])
        self.assertEqual(0, rc)


# ===========================================================================
# I-6: 取れなかったものを「無い」と言わないこと
# ===========================================================================


class FatalErrorMakesChecksUnknownTest(unittest.TestCase):
    """スロットリングで一覧が空になった場合、`該当なし` ではなく `判定不能`。"""

    @classmethod
    def setUpClass(cls) -> None:
        base = _load_fixture()
        # storage セクションを空にして「対象リソース 0 件」を作る
        empty = copy.deepcopy(base)
        empty["storage"] = {
            "buckets": [], "efs_file_systems": [], "efs_mount_targets": [],
            "efs_access_points": [], "efs_policies": [], "efs_backup_policies": [],
            "fsx_file_systems": [], "backup_plans": [], "backup_selections": [],
            "backup_vaults": [], "backup_protected_resources": [],
        }
        cls.without_error = _by_cid(evaluate(empty))

        throttled = copy.deepcopy(empty)
        throttled["errors"].append({
            "service": "s3", "operation": "list_buckets",
            "code": "ThrottlingException", "message": "Rate exceeded",
            "context": "バケット一覧", "fatal": True,
        })
        cls.with_error = _by_cid(evaluate(throttled))

        cls.demoted = [
            cid for cid in cls.without_error
            if cls.without_error[cid].status == NOT_APPLICABLE
            and cls.with_error[cid].status == UNKNOWN
        ]

    def test_some_checks_are_demoted(self) -> None:
        """S3 関連の `該当なし` が `判定不能` に倒れること。"""
        self.assertTrue(
            self.demoted,
            "ThrottlingException があっても `該当なし` のまま。I-6 が再発している",
        )

    def test_no_s3_check_stays_not_applicable(self) -> None:
        """storage を requires に持つチェックに `該当なし` が残っていないこと。"""
        remaining = [
            cid for cid, r in self.with_error.items()
            if r.status == NOT_APPLICABLE
            and self.without_error[cid].status == NOT_APPLICABLE
            and "storage" in " ".join(self.without_error[cid].evidence)
        ]
        self.assertEqual([], remaining)

    def test_summary_explains_why(self) -> None:
        """『存在しない』と断定していないことが summary から読めること。"""
        result = self.with_error[self.demoted[0]]
        self.assertIn("収集が失敗している", result.summary)
        self.assertIn("ThrottlingException", result.summary)
        self.assertTrue(result.remediation)

    def test_non_fatal_error_does_not_demote(self) -> None:
        """AccessDenied（＝見えない）は従来どおり `該当なし` を倒さないこと。

        `fatal` が立っていないエラーまで倒すと、権限を絞った調査で
        判定不能だらけになり使い物にならなくなる。
        """
        soft = copy.deepcopy(_load_fixture())
        soft["storage"] = {"buckets": []}
        soft["errors"].append({
            "service": "s3", "operation": "list_buckets",
            "code": "AccessDenied", "message": "denied", "context": "",
            "fatal": False,
        })
        results = _by_cid(evaluate(soft))
        self.assertIn(NOT_APPLICABLE, {r.status for r in results.values()})

    def test_collect_error_marks_fatal_from_code(self) -> None:
        """`CollectError` が code から fatal を自動判定すること。"""
        from awsprobe.session import CollectError

        for code in ("ThrottlingException", "SlowDown", "ExpiredToken",
                     "RequestLimitExceeded", "ServiceUnavailable"):
            with self.subTest(code=code):
                self.assertTrue(CollectError("s3", "op", code, "m").fatal)
        for code in ("AccessDenied", "NoSuchBucket", "ResourceNotFoundException"):
            with self.subTest(code=code):
                self.assertFalse(CollectError("s3", "op", code, "m").fatal)


# ===========================================================================
# I-5: 生値の inventory から作った成果物にも生値を出さないこと
# ===========================================================================


class OutputsAreRedactedTest(unittest.TestCase):
    """`meta.redacted: false` の inventory からでも、出力はマスクされること。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp(prefix="awsprobe-redact-out-")
        # フィクスチャは meta.redacted=false（＝ --no-redact 相当）
        for command in ("answer", "posture", "excel", "diagram-data"):
            main([command, "--inventory", FIXTURE, "--out", cls.tmp])
        cls.artifacts = [
            os.path.join(root, name)
            for root, _dirs, files in os.walk(cls.tmp)
            for name in files
        ]

    def test_artifacts_were_produced(self) -> None:
        self.assertGreaterEqual(len(self.artifacts), 6)

    def test_no_raw_account_id(self) -> None:
        for path in self.artifacts:
            with self.subTest(file=os.path.basename(path)):
                found = sorted(set(ACCOUNT_RE.findall(_text_of(path))))
                self.assertEqual([], found, f"生のアカウントIDが出力に残っている: {found}")

    def test_no_global_ip(self) -> None:
        for path in self.artifacts:
            with self.subTest(file=os.path.basename(path)):
                found = sorted(set(GLOBAL_IP_RE.findall(_text_of(path))))
                self.assertEqual([], found, f"グローバルIPが出力に残っている: {found}")

    def test_account_tokens_are_present_instead(self) -> None:
        """消すのではなく擬似化していること（外部/自分の区別が残ること）。"""
        posture = _text_of(os.path.join(self.tmp, "セキュリティ設定_実施状況.md"))
        self.assertRegex(posture, ACCOUNT_TOKEN_RE.pattern)

    def test_no_redact_output_keeps_raw_values(self) -> None:
        """`--no-redact-output` を明示したときだけ生値が出ること。"""
        with tempfile.TemporaryDirectory() as tmp:
            main(["posture", "--inventory", FIXTURE, "--out", tmp,
                  "--no-redact-output"])
            text = _text_of(os.path.join(tmp, "セキュリティ設定_実施状況.md"))
            self.assertTrue(ACCOUNT_RE.search(text))


class HostSectionIsRedactedTest(unittest.TestCase):
    """`host` セクションも inventory に書き込む前にマスクされること。"""

    def test_host_section_is_masked(self) -> None:
        from awsprobe.cli import _redact_host_section

        inv = {
            "meta": {"account_id": "210987654321", "redacted": True},
            "host": {
                "instances": {
                    "i-0123456789abcdef0": {
                        "public_ip": "203.0.113.16",
                        "role_arn": "arn:aws:iam::999888777666:role/Vendor",
                        "private_ip": "10.0.1.20",
                    }
                }
            },
        }
        out = _redact_host_section(inv)
        blob = json.dumps(out["host"], ensure_ascii=False)
        self.assertNotIn("203.0.113.16", blob)
        self.assertNotIn("999888777666", blob)
        self.assertIn("10.0.1.20", blob)        # 私設アドレスは残す
        self.assertRegex(blob, ACCOUNT_TOKEN_RE.pattern)


# ===========================================================================
# マスキングそのものの単体テスト
# ===========================================================================


class RedactUnitTest(unittest.TestCase):
    """`guard.redact()` の境界条件。"""

    def test_resource_id_with_12_digits_survives(self) -> None:
        """`vol-123456789012` の12桁はアカウントIDではないので壊さない。"""
        for value in ("vol-123456789012", "snap-123456789012",
                      "subnet-123456789012", "i-123456789012"):
            with self.subTest(value=value):
                self.assertEqual(value, redact(value, {"210987654321"}))

    def test_account_id_is_pseudonymised_not_erased(self) -> None:
        out = redact("arn:aws:iam::999888777666:role/Vendor", {"210987654321"})
        self.assertNotIn("999888777666", out)
        self.assertRegex(out, ACCOUNT_TOKEN_RE.pattern)
        # ARN の形は保たれる（判定側が構造を読めること）
        self.assertTrue(out.startswith("arn:aws:iam::"))
        self.assertTrue(out.endswith(":role/Vendor"))

    def test_self_account_is_distinguishable(self) -> None:
        out = redact("arn:aws:iam::210987654321:root", {"210987654321"})
        self.assertIn(SELF_ACCOUNT_TOKEN, out)

    def test_same_account_always_same_token(self) -> None:
        a = redact("999888777666", set())
        b = redact("勝手に別の文脈 999888777666 です", set())
        self.assertEqual(account_token("999888777666"), a)
        self.assertIn(a, b)

    def test_different_accounts_get_different_tokens(self) -> None:
        self.assertNotEqual(
            account_token("999888777666"), account_token("123456789012")
        )
        tokens = {account_token(f"{n:012d}") for n in range(1, 200)}
        self.assertGreater(len(tokens), 150, "トークンの衝突が多すぎる")

    def test_is_account_token(self) -> None:
        self.assertTrue(is_account_token(account_token("999888777666")))
        self.assertTrue(is_account_token(SELF_ACCOUNT_TOKEN))
        self.assertFalse(is_account_token("999888777666"))

    def test_global_ipv6_is_masked(self) -> None:
        out = redact("2001:db8:1234:5678::1", set())
        self.assertNotIn("5678", out)
        self.assertTrue(out.startswith("2001:db8:"))

    def test_unique_local_and_link_local_ipv6_survive(self) -> None:
        for value in ("fd00::1", "fd12:3456::abcd", "fe80::1", "fe80::a1b2:c3d4"):
            with self.subTest(value=value):
                self.assertEqual(value, redact(value, set()))

    def test_time_of_day_is_not_treated_as_ipv6(self) -> None:
        """`12:34:56` を IPv6 と誤認して壊さないこと。"""
        for value in ("12:34:56", "2026-09-16T12:34:56+09:00",
                      "収集日時 2026-09-16 23:59:59"):
            with self.subTest(value=value):
                self.assertEqual(value, redact(value, set()))

    def test_private_ipv4_survives(self) -> None:
        for value in ("10.0.1.20", "172.16.3.4", "192.168.0.1", "0.0.0.0/0"):
            with self.subTest(value=value):
                self.assertEqual(value, redact(value, set()))

    def test_global_ipv4_is_masked(self) -> None:
        out = redact("203.0.113.16", set())
        self.assertEqual("203.0.x.x", out)

    def test_nested_structures(self) -> None:
        payload = {"a": ["arn:aws:iam::999888777666:root", {"b": "203.0.113.16"}]}
        out = redact(payload, {"210987654321"})
        self.assertNotIn("999888777666", json.dumps(out))
        self.assertNotIn("203.0.113.16", json.dumps(out))


class MaskSecretValuesTest(unittest.TestCase):
    """`mask_secret_values()`（機微な設定値そのもののマスク）。"""

    def test_cloudfront_custom_header_value_is_dropped(self) -> None:
        config = {
            "Origins": {"Items": [{
                "Id": "alb-origin",
                "DomainName": "alb.example.com",
                "CustomHeaders": {"Items": [
                    {"HeaderName": "X-Origin-Verify", "HeaderValue": "s3cr3t-shared-key"}
                ]},
            }]}
        }
        out = mask_secret_values(config)
        blob = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("s3cr3t-shared-key", blob)
        # キー名は構成判断に必要なので残る
        self.assertIn("X-Origin-Verify", blob)
        self.assertIn("alb.example.com", blob)

    def test_sns_subscription_endpoint_is_dropped(self) -> None:
        subs = [
            {"Protocol": "email", "Endpoint": "ops@example.co.jp", "SubscriptionArn": "arn:x"},
            {"Protocol": "sms", "Endpoint": "+81901234567", "SubscriptionArn": "arn:y"},
        ]
        out = mask_secret_values(subs)
        blob = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("ops@example.co.jp", blob)
        self.assertNotIn("+81901234567", blob)
        # 通知経路の把握に必要な Protocol は残る
        self.assertIn("email", blob)
        self.assertIn("sms", blob)

    def test_dict_endpoint_is_not_flattened(self) -> None:
        """RDS の `Endpoint` は dict なので構造ごと残ること。"""
        out = mask_secret_values({"Endpoint": {"Address": "db.internal", "Port": 5432}})
        self.assertEqual({"Address": "db.internal", "Port": 5432}, out["Endpoint"])


class BucketLimitTest(unittest.TestCase):
    """`--max-buckets` の上限（I-6 の 5 番）。"""

    def _ctx(self, limit: int):
        from awsprobe.session import Context

        class _NoSession:
            def client(self, *a, **k):  # pragma: no cover - 呼ばれない想定
                raise AssertionError("上限超過後にクライアントを作ってはいけない")

        return Context(session=_NoSession(), region="ap-northeast-1",
                       account_id="210987654321", max_buckets=limit)

    def test_calls_beyond_limit_are_skipped(self) -> None:
        ctx = self._ctx(3)
        allowed = [ctx._bucket_allowed("s3", {"Bucket": f"b-{n}"}) for n in range(6)]
        self.assertEqual([True, True, True, False, False, False], allowed)

    def test_same_bucket_is_counted_once(self) -> None:
        """1 バケットあたり 11 コール発行されるので、2 本目以降も通ること。"""
        ctx = self._ctx(1)
        self.assertTrue(ctx._bucket_allowed("s3", {"Bucket": "only"}))
        for _ in range(10):
            self.assertTrue(ctx._bucket_allowed("s3", {"Bucket": "only"}))
        self.assertFalse(ctx._bucket_allowed("s3", {"Bucket": "other"}))

    def test_truncation_is_recorded_as_fatal(self) -> None:
        """打ち切りが `fatal` として残り、判定側が「無い」と誤読しないこと。"""
        ctx = self._ctx(1)
        ctx._bucket_allowed("s3", {"Bucket": "a"})
        ctx._bucket_allowed("s3", {"Bucket": "b"})
        fatal = ctx.fatal_errors()
        self.assertEqual(1, len(fatal))
        self.assertEqual("CollectionTruncated", fatal[0].code)
        self.assertIn("--max-buckets", fatal[0].message)

    def test_list_buckets_and_other_services_are_unaffected(self) -> None:
        ctx = self._ctx(1)
        ctx._bucket_allowed("s3", {"Bucket": "a"})
        self.assertTrue(ctx._bucket_allowed("s3", {}))
        self.assertTrue(ctx._bucket_allowed("ec2", {"Bucket": "a"}))

    def test_zero_means_unlimited(self) -> None:
        ctx = self._ctx(0)
        self.assertTrue(all(
            ctx._bucket_allowed("s3", {"Bucket": f"b-{n}"}) for n in range(500)
        ))
        self.assertEqual([], ctx.fatal_errors())


class CollectorMaskingTest(unittest.TestCase):
    """コレクタが保存前にマスクを掛けていること（ソース上の契約）。"""

    def test_edge_masks_distribution_config(self) -> None:
        source = open(
            os.path.join(ROOT, "awsprobe", "collectors", "edge.py"), encoding="utf-8"
        ).read()
        self.assertIn("mask_secret_values(config)", source)

    def test_serverless_masks_subscriptions(self) -> None:
        source = open(
            os.path.join(ROOT, "awsprobe", "collectors", "serverless.py"),
            encoding="utf-8",
        ).read()
        self.assertIn("mask_secret_values(subs)", source)


if __name__ == "__main__":
    unittest.main()
