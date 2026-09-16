"""未確認事項レゾルバ（questions.py）と Markdown レポート（report.py）の検証。

確認すること:
1. Q1〜Q42 が漏れなく 42 件返ること（設問文とカテゴリが埋まっていること）
2. Example の実構成を模したフィクスチャに対する status の分布が妥当なこと
3. **CIDR 重複検出（Q37）** が、重複が無いときは「無し」、
   重複させたときは「検出」と、両方向で正しく効くこと
4. **NAT クロスAZ判定（Q38）** が、クロスAZ構成で検出され、
   NAT を各AZに置いた構成では検出されないこと
5. inventory が空 dict `{}` でも例外を出さず全件 `no_data` になること
6. AWS API を呼んでいないこと（boto3 を import していないこと）
7. render_markdown が全設問を含む Markdown を返すこと

実行:
    python3 -m pytest tests/test_questions.py -v
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from awsprobe import questions as q  # noqa: E402
from awsprobe.report import render_markdown  # noqa: E402

FIXTURE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "inventory_example.json"
)


def load_fixture() -> dict:
    """Example を模したダミー inventory を読み込む。"""
    with open(FIXTURE, encoding="utf-8") as fh:
        return json.load(fh)


def answers_by_id(answers) -> dict:
    return {a.qid: a for a in answers}


class TestResolveAllCoverage(unittest.TestCase):
    """Q1〜Q42 が漏れなく返ることの確認。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = load_fixture()
        cls.answers = q.resolve_all(cls.inventory)

    def test_42_questions_returned(self) -> None:
        """設問がちょうど 42 件、Q1〜Q42 が漏れなく返る。"""
        self.assertEqual(len(self.answers), 42)
        self.assertEqual(
            [a.qid for a in self.answers], [f"Q{i}" for i in range(1, 43)]
        )

    def test_resolvers_registry_matches(self) -> None:
        """RESOLVERS の登録も 42 件で、重複が無い。"""
        self.assertEqual(len(q.RESOLVERS), 42)
        self.assertEqual(sorted(q.RESOLVERS), sorted(q.QUESTION_META))

    def test_every_answer_is_well_formed(self) -> None:
        """全設問で title / category / status / summary が埋まっている。"""
        for answer in self.answers:
            with self.subTest(qid=answer.qid):
                self.assertTrue(answer.title, "設問文が空")
                self.assertIn(answer.category, q.CATEGORIES)
                self.assertIn(answer.status, q.STATUSES)
                self.assertTrue(answer.summary.strip(), "結論が空")
                self.assertIsInstance(answer.details, list)
                self.assertIsInstance(answer.evidence, list)

    def test_needs_manual_always_has_manual_steps(self) -> None:
        """needs_manual には必ず manual_steps が埋まっている（契約）。"""
        for answer in self.answers:
            if answer.status == q.NEEDS_MANUAL:
                with self.subTest(qid=answer.qid):
                    self.assertTrue(
                        (answer.manual_steps or "").strip(),
                        f"{answer.qid} に manual_steps が無い",
                    )

    def test_top_priority_nine(self) -> None:
        """最優先カテゴリはちょうど 9 件で、確認事項一覧 の設問番号と一致する。"""
        top = [a.qid for a in self.answers if a.category == q.CAT_TOP]
        self.assertEqual(
            sorted(top, key=lambda x: int(x[1:])),
            sorted(["Q1", "Q8", "Q9", "Q23", "Q27", "Q33", "Q36", "Q37", "Q38"],
                   key=lambda x: int(x[1:])),
        )

    def test_to_dict_is_json_serializable(self) -> None:
        """Answer.to_dict() が JSON 化できる。"""
        payload = [a.to_dict() for a in self.answers]
        json.dumps(payload, ensure_ascii=False)


class TestStatusDistribution(unittest.TestCase):
    """フィクスチャに対する status 分布が妥当であることの確認。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = load_fixture()
        cls.answers = q.resolve_all(cls.inventory)
        cls.by_id = answers_by_id(cls.answers)
        cls.counts = q.status_counts(cls.answers)

    def test_no_no_data_on_full_inventory(self) -> None:
        """全セクションが揃った inventory では no_data が出ない。"""
        no_data = [a.qid for a in self.answers if a.status == q.NO_DATA]
        self.assertEqual(no_data, [], f"想定外の no_data: {no_data}")

    def test_distribution_is_reasonable(self) -> None:
        """answered が過半に近く、needs_manual が一定数ある。"""
        self.assertEqual(sum(self.counts.values()), 42)
        self.assertGreaterEqual(self.counts[q.ANSWERED], 15)
        self.assertGreaterEqual(self.counts[q.PARTIAL], 10)
        self.assertGreaterEqual(self.counts[q.NEEDS_MANUAL], 4)

    def test_pure_hearing_questions_are_needs_manual(self) -> None:
        """人・契約・文書にしか答えが無い設問は needs_manual になる。"""
        for qid in ("Q19", "Q20", "Q22", "Q31", "Q32", "Q36"):
            with self.subTest(qid=qid):
                self.assertEqual(self.by_id[qid].status, q.NEEDS_MANUAL)

    def test_api_answerable_questions_are_answered(self) -> None:
        """API だけで確定できる設問は answered になる。"""
        for qid in ("Q1", "Q4", "Q5", "Q7", "Q10", "Q16", "Q17",
                    "Q23", "Q25", "Q28", "Q33", "Q35", "Q37", "Q38", "Q41", "Q42"):
            with self.subTest(qid=qid):
                self.assertEqual(self.by_id[qid].status, q.ANSWERED)

    def test_q9_is_partial_without_host_section(self) -> None:
        """Q9（authorized_keys）は host セクションが無ければ partial。"""
        answer = self.by_id["Q9"]
        self.assertEqual(answer.status, q.PARTIAL)
        self.assertIn("authorized_keys", answer.summary)
        self.assertTrue(answer.manual_steps)

    def test_q1_detects_absence_of_waf(self) -> None:
        """Q1: WAF が 1 件も無いことを確定的に答える。"""
        answer = self.by_id["Q1"]
        self.assertEqual(answer.status, q.ANSWERED)
        self.assertIn("WAF は導入されていない", answer.summary)

    def test_q23_finds_global_accelerator_target(self) -> None:
        """Q23: Global Accelerator の向き先が本番 ALB だと特定できる。"""
        answer = self.by_id["Q23"]
        self.assertEqual(answer.status, q.ANSWERED)
        self.assertIn("本番経路上である", answer.summary)
        self.assertTrue(
            any("prod-web-elb" in line for line in answer.details),
            "向き先 ALB 名が details に出ていない",
        )

    def test_q8_flags_world_open_ssh(self) -> None:
        """Q8: 0.0.0.0/0 からの SSH 許可を強調する。"""
        answer = self.by_id["Q8"]
        self.assertEqual(answer.status, q.PARTIAL)
        self.assertIn("全世界開放", answer.summary)
        self.assertTrue(any("0.0.0.0/0（全世界に開放）" in line for line in answer.details))

    def test_q5_flags_vpc_wide_rds_rule(self) -> None:
        """Q5: VPC CIDR 全体から DB ポートを許可しているルールを検出する。"""
        answer = self.by_id["Q5"]
        self.assertIn("過剰開放", answer.summary)
        self.assertTrue(any("VPC CIDR 全体を許可" in line for line in answer.details))

    def test_q24_flags_eol_lambda_runtimes(self) -> None:
        """Q24: EOL ランタイム（python3.7 / go1.x など）を警告する。"""
        answer = self.by_id["Q24"]
        joined = "\n".join(answer.details)
        self.assertIn("サポート終了済みランタイム", joined)
        self.assertIn("ex-ses-bounce-handler", joined)  # python3.7

    def test_q33_detects_az_name_mismatch(self) -> None:
        """Q33: 名前が -1c なのに実際は 1d のサブネットを検出する。"""
        answer = self.by_id["Q33"]
        self.assertIn("食い違っている", answer.summary)
        self.assertIn("ex-stg-private-subnet-1c", answer.summary)

    def test_q42_flags_disabled_alb_access_logs(self) -> None:
        """Q42: 本番以外の ALB でアクセスログが無効なことを検出する。"""
        answer = self.by_id["Q42"]
        self.assertEqual(answer.status, q.ANSWERED)
        self.assertIn("アクセスログ有効な LB は 1/6 本", answer.summary)
        self.assertIn("是正が必要な項目", answer.summary)

    def test_q16_flags_zero_retention(self) -> None:
        """Q16: バックアップ保持0日の DB を強調する。"""
        answer = self.by_id["Q16"]
        self.assertIn("バックアップ無効", answer.summary)
        self.assertTrue(any("バックアップ無効" in line for line in answer.details))

    def test_q7_confirms_efs_separation(self) -> None:
        """Q7: 本番と check が別ファイルシステムだと確定判定する。"""
        answer = self.by_id["Q7"]
        self.assertEqual(answer.status, q.ANSWERED)
        self.assertIn("物理的に別ファイルシステム", answer.summary)

    def test_q27_finds_external_trust(self) -> None:
        """Q27: 外部アカウントを信頼する IAM ロールを列挙する。"""
        answer = self.by_id["Q27"]
        joined = "\n".join(answer.details)
        self.assertIn("StackSetVendorMonitorStackSet", joined)
        self.assertIn("999888777666", joined)
        self.assertTrue(answer.manual_steps)

    def test_q41_identifies_service_types(self) -> None:
        """Q41: 3 リソースのサービス種別を EventBridge / SNS と確定する。"""
        answer = self.by_id["Q41"]
        joined = "\n".join(answer.details)
        self.assertIn("RdsAutoStopNotify", joined)
        self.assertIn("EventBridge ルール", joined)
        self.assertIn("SNS トピック", joined)


class TestCidrOverlapDetection(unittest.TestCase):
    """Q37 の CIDR 重複検出が両方向で効くことの確認。"""

    def test_no_overlap_in_realistic_fixture(self) -> None:
        """重複の無い（実在しうる）構成では「重複なし」と判定する。"""
        answer = answers_by_id(q.resolve_all(load_fixture()))["Q37"]
        self.assertEqual(answer.status, q.ANSWERED)
        self.assertIn("重複は存在しない", answer.summary)
        self.assertTrue(any("重複は検出されなかった" in line for line in answer.details))

    def test_overlap_is_detected(self) -> None:
        """/20 のデフォルトサブネットと重なる /24 を入れると検出される。"""
        inventory = load_fixture()
        subnets = inventory["network"]["subnets"]
        # 172.31.0.0/20（デフォルトサブネット）の内側に /24 を追加する
        subnets.append(
            {
                "SubnetId": "subnet-0overlap",
                "VpcId": inventory["network"]["vpcs"][0]["VpcId"],
                "CidrBlock": "172.31.4.0/24",
                "AvailabilityZone": "ap-northeast-1a",
                "AvailabilityZoneId": "apne1-az4",
                "DefaultForAz": False,
                "MapPublicIpOnLaunch": False,
                "State": "available",
                "Tags": [{"Key": "Name", "Value": "ex-overlap-subnet-1a"}],
            }
        )
        answer = answers_by_id(q.resolve_all(inventory))["Q37"]
        self.assertIn("アドレス範囲の重複が 1 ペアある", answer.summary)
        joined = "\n".join(answer.details)
        self.assertIn("ex-overlap-subnet-1a", joined)
        self.assertIn("172.31.0.0/20", joined)
        self.assertIn("包含", joined)

    def test_exact_duplicate_is_detected(self) -> None:
        """完全に同じ CIDR の2本も「完全一致」として検出される。"""
        inventory = load_fixture()
        original = inventory["network"]["subnets"][0]
        clone = copy.deepcopy(original)
        clone["SubnetId"] = "subnet-0clone"
        clone["Tags"] = [{"Key": "Name", "Value": "ex-clone-subnet-1a"}]
        inventory["network"]["subnets"].append(clone)
        answer = answers_by_id(q.resolve_all(inventory))["Q37"]
        self.assertIn("重複が 1 ペアある", answer.summary)
        self.assertTrue(any("完全一致" in line for line in answer.details))

    def test_broken_cidr_does_not_crash(self) -> None:
        """CIDR が壊れていても例外を出さない。"""
        inventory = load_fixture()
        inventory["network"]["subnets"][0]["CidrBlock"] = "これはCIDRではない"
        inventory["network"]["subnets"][1]["CidrBlock"] = None
        answer = answers_by_id(q.resolve_all(inventory))["Q37"]
        self.assertEqual(answer.status, q.ANSWERED)


class TestNatCrossAzDetection(unittest.TestCase):
    """Q38 の NAT クロスAZ判定が効くことの確認。"""

    def test_cross_az_detected_with_single_nat(self) -> None:
        """NAT 1 台（1a）に 1c / 1d のサブネットが向いている構成を検出する。"""
        answer = answers_by_id(q.resolve_all(load_fixture()))["Q38"]
        self.assertEqual(answer.status, q.ANSWERED)
        self.assertIn("NAT Gateway は 1 台", answer.summary)
        self.assertIn("クロスAZ通信", answer.summary)
        joined = "\n".join(answer.details)
        self.assertIn("クロスAZ（ap-northeast-1c → ap-northeast-1a）", joined)
        self.assertIn("クロスAZ（ap-northeast-1d → ap-northeast-1a）", joined)
        # 同一AZ（1a のサブネット → 1a の NAT）も正しく同一AZ判定される
        self.assertIn("同一AZ", joined)

    def test_no_cross_az_when_nat_per_az(self) -> None:
        """AZ ごとに NAT を置き、ルートを張り替えるとクロスAZが消える。"""
        inventory = load_fixture()
        network = inventory["network"]
        # 1c / 1d にも NAT を追加する
        network["nat_gateways"].extend(
            [
                {
                    "NatGatewayId": "nat-0c1c1c1c",
                    "SubnetId": "subnet-0a12",  # ap-northeast-1c のパブリック
                    "VpcId": network["vpcs"][0]["VpcId"],
                    "State": "available",
                    "NatGatewayAddresses": [{"PublicIp": "198.51.100.11"}],
                    "Tags": [{"Key": "Name", "Value": "ex-natgw-1c"}],
                },
                {
                    "NatGatewayId": "nat-0d1d1d1d",
                    "SubnetId": "subnet-0a13",  # ap-northeast-1d のパブリック
                    "VpcId": network["vpcs"][0]["VpcId"],
                    "State": "available",
                    "NatGatewayAddresses": [{"PublicIp": "198.51.100.12"}],
                    "Tags": [{"Key": "Name", "Value": "ex-natgw-1d"}],
                },
            ]
        )
        # 各プライベートサブネットを、同一AZ の NAT に向けたルートテーブルへ張り替える
        by_id = {rt["RouteTableId"]: rt for rt in network["route_tables"]}
        by_id["rtb-prodpri"]["Associations"] = [
            {"RouteTableAssociationId": "a1", "SubnetId": "subnet-0a21", "Main": False}
        ]
        network["route_tables"].extend(
            [
                {
                    "RouteTableId": "rtb-prodpri-1c",
                    "VpcId": network["vpcs"][0]["VpcId"],
                    "Tags": [{"Key": "Name", "Value": "ex-prod-private-rtb-1c"}],
                    "Associations": [
                        {"RouteTableAssociationId": "a2", "SubnetId": "subnet-0a22", "Main": False}
                    ],
                    "Routes": [
                        {"DestinationCidrBlock": "0.0.0.0/0",
                         "NatGatewayId": "nat-0c1c1c1c", "State": "active"}
                    ],
                },
                {
                    "RouteTableId": "rtb-prodpri-1d",
                    "VpcId": network["vpcs"][0]["VpcId"],
                    "Tags": [{"Key": "Name", "Value": "ex-prod-private-rtb-1d"}],
                    "Associations": [
                        {"RouteTableAssociationId": "a3", "SubnetId": "subnet-0a23", "Main": False}
                    ],
                    "Routes": [
                        {"DestinationCidrBlock": "0.0.0.0/0",
                         "NatGatewayId": "nat-0d1d1d1d", "State": "active"}
                    ],
                },
            ]
        )
        by_id["rtb-demopri"]["Routes"] = [
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0c1c1c1c", "State": "active"}
        ]
        by_id["rtb-stgpri"]["Routes"] = [
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0d1d1d1d", "State": "active"}
        ]

        answer = answers_by_id(q.resolve_all(inventory))["Q38"]
        self.assertIn("NAT Gateway は 3 台", answer.summary)
        self.assertIn("クロスAZの NAT 利用は検出されなかった", answer.summary)
        self.assertNotIn("クロスAZ（", "\n".join(answer.details))

    def test_missing_subnet_does_not_crash(self) -> None:
        """NAT が未知のサブネットにいても落ちず、判定不可として扱う。"""
        inventory = load_fixture()
        inventory["network"]["nat_gateways"][0]["SubnetId"] = "subnet-unknown"
        answer = answers_by_id(q.resolve_all(inventory))["Q38"]
        self.assertEqual(answer.status, q.ANSWERED)
        self.assertIn("判定不可", "\n".join(answer.details))


class TestEmptyAndBrokenInventory(unittest.TestCase):
    """欠損した inventory でも落ちないことの確認。"""

    def test_empty_dict_yields_all_no_data(self) -> None:
        """空 dict では例外を出さず、全 42 件が no_data になる。"""
        answers = q.resolve_all({})
        self.assertEqual(len(answers), 42)
        for answer in answers:
            with self.subTest(qid=answer.qid):
                self.assertEqual(answer.status, q.NO_DATA)
                self.assertTrue(answer.summary.strip())

    def test_none_inventory_does_not_crash(self) -> None:
        """None を渡しても落ちない。"""
        answers = q.resolve_all(None)  # type: ignore[arg-type]
        self.assertEqual(len(answers), 42)

    def test_sections_present_but_empty(self) -> None:
        """セクションだけあって中身が空でも落ちない。"""
        inventory = {name: {} for name in q.SECTION_NAMES}
        inventory["errors"] = []
        answers = q.resolve_all(inventory)
        self.assertEqual(len(answers), 42)
        for answer in answers:
            with self.subTest(qid=answer.qid):
                self.assertIn(answer.status, q.STATUSES)

    def test_wrong_types_do_not_crash(self) -> None:
        """リストのはずが文字列、dict のはずが数値でも落ちない。"""
        inventory = {
            "meta": "こわれている",
            "errors": "こわれている",
            "network": {"subnets": "こわれている", "security_groups": 123,
                        "route_tables": None, "nat_gateways": [None, "x"]},
            "compute": {"instances": [{"InstanceId": None}]},
            "database": {"db_instances": [{}]},
            "storage": {"buckets": [{"Name": None}]},
            "edge": {"load_balancers": [{}], "wafv2_web_acls": [{}]},
            "serverless": {"lambda_functions": [{}]},
            "logging": {"config_recorders": [{}]},
            "security": {"iam": "こわれている"},
        }
        answers = q.resolve_all(inventory)
        self.assertEqual(len(answers), 42)
        for answer in answers:
            with self.subTest(qid=answer.qid):
                self.assertIn(answer.status, q.STATUSES)

    def test_access_denied_becomes_no_data(self) -> None:
        """権限不足で空になったセクションは no_data になり、errors が summary に載る。"""
        inventory = load_fixture()
        inventory["network"]["security_groups"] = []
        inventory["errors"].append(
            {"service": "ec2", "operation": "describe_security_groups",
             "code": "UnauthorizedOperation", "message": "権限がありません", "context": ""}
        )
        answer = answers_by_id(q.resolve_all(inventory))["Q8"]
        self.assertEqual(answer.status, q.NO_DATA)
        self.assertIn("権限不足", answer.summary)
        self.assertIn("UnauthorizedOperation", answer.summary)


class TestNoAwsCalls(unittest.TestCase):
    """AWS API を呼んでいないこと（読み取り専用の前提）の確認。"""

    def test_questions_does_not_import_boto3(self) -> None:
        """questions.py / report.py が boto3 を import していない。"""
        for module in ("questions.py", "report.py"):
            path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "awsprobe", module,
            )
            with open(path, encoding="utf-8") as fh:
                # コメント中の言及は無視し、実際の import 文だけを見る
                imports = [
                    line.strip()
                    for line in fh
                    if line.lstrip().startswith(("import ", "from "))
                ]
            with self.subTest(module=module):
                for line in imports:
                    self.assertNotIn("boto3", line, f"boto3 を import している: {line}")
                    self.assertNotIn("botocore", line, f"botocore を import している: {line}")
                    self.assertNotIn("requests", line, f"HTTP クライアントを import している: {line}")

    def test_resolve_all_loads_no_aws_module(self) -> None:
        """判定の実行で boto3 / botocore が新たに読み込まれない。

        （同一プロセス内の他テストが先に boto3 を読み込んでいる場合があるため、
        「新たに増えたか」で判定する）
        """
        before = set(sys.modules)
        q.resolve_all(load_fixture())
        added = {
            name for name in set(sys.modules) - before
            if name.split(".")[0] in ("boto3", "botocore", "urllib3", "requests")
        }
        self.assertEqual(added, set(), f"判定中に AWS SDK が読み込まれた: {added}")

    def test_fresh_interpreter_does_not_load_boto3(self) -> None:
        """新しいインタプリタで questions / report を import しても boto3 が入らない。"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = (
            "import sys; sys.path.insert(0, %r);"
            "from awsprobe import questions, report;"
            "questions.resolve_all({});"
            "print('boto3' in sys.modules or 'botocore' in sys.modules)" % root
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, check=True
        )
        self.assertEqual(result.stdout.strip(), "False", result.stderr)


class TestRenderMarkdown(unittest.TestCase):
    """Markdown レポート生成の確認。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = load_fixture()
        cls.answers = q.resolve_all(cls.inventory)
        cls.markdown = render_markdown(
            cls.answers, cls.inventory, title="テストレポート", redacted=True
        )

    def test_contains_all_questions(self) -> None:
        """全 42 設問が見出しとして出てくる。"""
        for answer in self.answers:
            with self.subTest(qid=answer.qid):
                self.assertIn(f"### {answer.qid} ", self.markdown)

    def test_has_required_sections(self) -> None:
        """指定された構成（サマリ／最優先／質問票／エラー／更新対応表）がある。"""
        for heading in (
            "# テストレポート",
            "## 1. サマリ",
            "## 2. 最優先",
            "要ヒアリング事項のチェックリスト",
            "収集エラー一覧",
            "設計資料の更新対応表",
        ):
            with self.subTest(heading=heading):
                self.assertIn(heading, self.markdown)

    def test_redacted_hides_account_id(self) -> None:
        """redacted=True ならアカウントIDを出さない。"""
        self.assertIn("＜マスク済み＞", self.markdown)

    def test_error_table_splits_denied_and_others(self) -> None:
        """収集エラーが権限不足とそれ以外に分かれている。"""
        self.assertIn("権限不足（判定に影響する）", self.markdown)
        self.assertIn("その他（未設定・未導入・サービス未使用など）", self.markdown)
        self.assertIn("AccessDeniedException", self.markdown)
        self.assertIn("NoSuchBucketPolicy", self.markdown)

    def test_markdown_tables_are_well_formed(self) -> None:
        """表のヘッダ行に対して必ず区切り行が続く。"""
        lines = self.markdown.splitlines()
        for i, line in enumerate(lines):
            if not line.startswith("| "):
                continue
            previous = lines[i - 1] if i else ""
            following = lines[i + 1] if i + 1 < len(lines) else ""
            is_separator = set(line.replace(" ", "")) <= set("|-")
            if not is_separator and not previous.startswith("|"):
                with self.subTest(line=i):
                    self.assertTrue(
                        set(following.replace(" ", "")) <= set("|-") and following,
                        f"{i} 行目の表にヘッダ区切りが無い: {line[:60]}",
                    )

    def test_no_double_blank_lines(self) -> None:
        """空行が2本続かない（Markdown の余白が崩れない）。"""
        lines = self.markdown.splitlines()
        for i in range(1, len(lines)):
            if not lines[i].strip() and not lines[i - 1].strip():
                self.fail(f"{i} 行目付近で空行が連続している")

    def test_render_with_empty_inventory(self) -> None:
        """空 inventory でもレポートが生成できる。"""
        markdown = render_markdown(q.resolve_all({}), {})
        self.assertIn("## 1. サマリ", markdown)
        self.assertIn("データ無し（no_data）", markdown)

    def test_summary_counts_match(self) -> None:
        """サマリの「自動で解消した件数」が status_counts と一致する。"""
        counts = q.status_counts(self.answers)
        self.assertIn(
            f"**設問 42 件のうち、{counts[q.ANSWERED]} 件を自動で確定させた",
            self.markdown,
        )


# ===========================================================================
# 回帰テスト: マスク済み inventory / State / 名前と実態の食い違い
# ===========================================================================


class TestQ27SurvivesRedaction(unittest.TestCase):
    """Q27: マスク済み inventory でも外部信頼ロールを見失わないこと。

    `awsprobe all` の既定動線では `guard.redact()` を通した inventory が
    判定に渡る。`redact()` はアカウントIDを消さずに擬似化する
    （自分は `＜自アカウント＞`、他人は `＜アカウント:xxxx＞`）ので、
    12桁だけを見る実装のままだと外部信頼が **0 件に化ける**。
    """

    @classmethod
    def setUpClass(cls) -> None:
        from awsprobe.guard import redact

        cls.raw = load_fixture()
        account_id = cls.raw["meta"]["account_id"]
        cls.masked = redact(load_fixture(), {account_id})
        cls.raw_answer = answers_by_id(q.resolve_all(cls.raw))["Q27"]
        cls.masked_answer = answers_by_id(q.resolve_all(cls.masked))["Q27"]

    @staticmethod
    def _external_rows(answer) -> list[str]:
        """「外部アカウントを信頼している IAM ロール」表の本文行を取り出す。"""
        lines = answer.details
        try:
            start = next(
                i for i, l in enumerate(lines)
                if "外部アカウントを信頼している IAM ロール" in l
            )
        except StopIteration:
            return []
        rows: list[str] = []
        # 表は「見出し行 / 区切り行 / 本文行...」の順に並ぶ
        for line in lines[start + 3:]:
            if not line.startswith("|"):
                break
            rows.append(line)
        return rows

    def test_fixture_precondition(self) -> None:
        """前提: フィクスチャは生値で、マスク後は自アカウントがトークンになる。"""
        from awsprobe.guard import SELF_ACCOUNT_TOKEN

        self.assertRegex(self.raw["meta"]["account_id"], r"^\d{12}$")
        self.assertEqual(SELF_ACCOUNT_TOKEN, self.masked["meta"]["account_id"])

    def test_external_role_count_matches(self) -> None:
        """★ 生値とマスク済みで、検出した外部信頼ロールの件数が一致すること。"""
        raw_rows = self._external_rows(self.raw_answer)
        masked_rows = self._external_rows(self.masked_answer)
        self.assertTrue(raw_rows, "フィクスチャに外部信頼ロールが無く検証にならない")
        self.assertEqual(
            len(raw_rows), len(masked_rows),
            "マスクすると外部信頼ロールが検出できなくなっている（Q27 の再発）",
        )

    def test_summary_count_matches(self) -> None:
        """summary に出る本数も一致すること（「0 本」に化けない）。"""
        pattern = r"外部アカウントを信頼する IAM ロール (\d+) 本"
        raw = re.search(pattern, self.raw_answer.summary)
        masked = re.search(pattern, self.masked_answer.summary)
        self.assertIsNotNone(raw, f"生値の summary が想定と違う: {self.raw_answer.summary}")
        self.assertIsNotNone(
            masked, f"マスク後の summary が想定と違う: {self.masked_answer.summary}"
        )
        self.assertEqual(raw.group(1), masked.group(1))
        self.assertNotEqual("0", raw.group(1))

    def test_masked_external_account_is_still_identifiable(self) -> None:
        """マスク後も「外部の誰か」として読めること（自アカウントと混ざらない）。"""
        from awsprobe.guard import ACCOUNT_TOKEN_RE, SELF_ACCOUNT_TOKEN

        joined = "\n".join(self._external_rows(self.masked_answer))
        self.assertRegex(joined, ACCOUNT_TOKEN_RE.pattern)
        self.assertNotIn(SELF_ACCOUNT_TOKEN, joined)

    def test_status_matches(self) -> None:
        self.assertEqual(self.raw_answer.status, self.masked_answer.status)


class TestQ38IgnoresDeletedNat(unittest.TestCase):
    """Q38: State を見て、実稼働していない NAT を台数に入れないこと。"""

    @staticmethod
    def _extra_nat(nat_id: str, state: str) -> dict:
        return {
            "NatGatewayId": nat_id,
            "SubnetId": "subnet-0a11",
            "VpcId": "vpc-52e30834",
            "State": state,
            "NatGatewayAddresses": [{"PublicIp": "198.51.100.90"}],
            "Tags": [{"Key": "Name", "Value": f"ex-natgw-{state}"}],
        }

    def test_deleted_and_failed_are_not_counted(self) -> None:
        """deleting / deleted / failed を 3 台混ぜても「1 台」と答えること。

        `describe_nat_gateways` は削除後およそ1時間 `deleted` を返し続ける。
        State を無視すると「自動生成図1台 vs 手描き図4台」の確定を誤る。
        """
        inventory = load_fixture()
        inventory["network"]["nat_gateways"].extend(
            [
                self._extra_nat("nat-0deleting", "deleting"),
                self._extra_nat("nat-0deleted", "deleted"),
                self._extra_nat("nat-0failed", "failed"),
            ]
        )
        answer = answers_by_id(q.resolve_all(inventory))["Q38"]
        self.assertIn("NAT Gateway は 1 台", answer.summary)
        self.assertNotIn("4 台", answer.summary)
        joined = "\n".join(answer.details)
        # 消えたものも「存在しない NAT」として可視化はする
        self.assertIn("既に存在しない NAT Gateway", joined)
        self.assertIn("nat-0deleted", joined)

    def test_all_deleted_means_zero(self) -> None:
        """稼働中が 0 台なら 0 台と答えること（レコードの数で答えない）。"""
        inventory = load_fixture()
        inventory["network"]["nat_gateways"][0]["State"] = "deleted"
        answer = answers_by_id(q.resolve_all(inventory))["Q38"]
        self.assertIn("NAT Gateway は 0 台", answer.summary)

    def test_transitional_state_drops_to_partial(self) -> None:
        """pending / deleting があるうちは台数が確定しないので partial にすること。"""
        inventory = load_fixture()
        inventory["network"]["nat_gateways"].append(self._extra_nat("nat-0pending", "pending"))
        answer = answers_by_id(q.resolve_all(inventory))["Q38"]
        self.assertEqual(answer.status, q.PARTIAL)
        self.assertIn("確定していない", answer.summary)
        # 遷移中のものは稼働台数には入れない
        self.assertIn("NAT Gateway は 1 台", answer.summary)

    def test_deleted_only_fixture_is_still_answered(self) -> None:
        """deleted だけなら（遷移中が無いので）確定として答えること。"""
        inventory = load_fixture()
        inventory["network"]["nat_gateways"].append(self._extra_nat("nat-0gone", "deleted"))
        answer = answers_by_id(q.resolve_all(inventory))["Q38"]
        self.assertEqual(answer.status, q.ANSWERED)


class TestQ33AzNameMatching(unittest.TestCase):
    """Q33: 照合できた件数を分母にし、照合できなければ断定しないこと。"""

    @staticmethod
    def _rename_all(inventory: dict, template: str) -> None:
        for i, subnet in enumerate(inventory["network"]["subnets"]):
            subnet["Tags"] = [{"Key": "Name", "Value": template.format(i=i)}]

    def test_no_az_notation_is_partial_not_answered(self) -> None:
        """AZ 表記が無いとき「全本一致」と断言せず partial にすること。"""
        inventory = load_fixture()
        self._rename_all(inventory, "subnet-{i:02d}")
        answer = answers_by_id(q.resolve_all(inventory))["Q33"]
        self.assertEqual(answer.status, q.PARTIAL)
        self.assertNotIn("すべてで", answer.summary)
        self.assertIn("照合できなかった", answer.summary)

    def test_uppercase_name_mismatch_is_detected(self) -> None:
        """大文字の命名（PROD-1A-APP）でも不一致を見逃さないこと。"""
        inventory = load_fixture()
        # 実 AZ が ap-northeast-1c のサブネットに、1A と名乗らせる
        target = next(
            s for s in inventory["network"]["subnets"]
            if s.get("AvailabilityZone") == "ap-northeast-1c"
        )
        target["Tags"] = [{"Key": "Name", "Value": "PROD-1A-APP"}]
        answer = answers_by_id(q.resolve_all(inventory))["Q33"]
        self.assertIn("食い違っている", answer.summary)
        self.assertIn("PROD-1A-APP", answer.summary)

    def test_all_matching_names_report_the_comparable_count(self) -> None:
        """一致しているときは「照合できた N 本すべてで一致」と書くこと。"""
        inventory = load_fixture()
        for subnet in inventory["network"]["subnets"]:
            az = subnet.get("AvailabilityZone") or "ap-northeast-1a"
            subnet["Tags"] = [
                {"Key": "Name", "Value": f"ex-{subnet['SubnetId']}-1{az[-1]}"}
            ]
        answer = answers_by_id(q.resolve_all(inventory))["Q33"]
        self.assertEqual(answer.status, q.ANSWERED)
        total = len(inventory["network"]["subnets"])
        # 全本に AZ 表記を付けたので、照合できた件数＝全件になる
        self.assertIn(f"{total} 本すべてで", answer.summary)
        self.assertIn("一致している", answer.summary)

    def test_1d_claim_is_conditional(self) -> None:
        """1d のサブネットが実在するときは「1d は現況と異なる」と書かないこと。"""
        inventory = load_fixture()
        answer = answers_by_id(q.resolve_all(inventory))["Q33"]
        has_1d = any(
            str(s.get("AvailabilityZone", "")).endswith("d")
            for s in inventory["network"]["subnets"]
        )
        self.assertTrue(has_1d, "前提: フィクスチャに 1d のサブネットがある")
        self.assertNotIn("手描き図の 1d という記載は現況と異なる", answer.summary)


class TestQ37VpcScopeAndIpv6(unittest.TestCase):
    """Q37: 重複判定は VPC 内で閉じること、IPv6 も一覧に出ること。"""

    def test_same_cidr_in_another_vpc_is_not_an_overlap(self) -> None:
        """別 VPC に同一 CIDR があっても偽陽性を出さないこと。"""
        inventory = load_fixture()
        network = inventory["network"]
        original = network["subnets"][0]
        network["vpcs"].append(
            {
                "VpcId": "vpc-OTHER",
                "CidrBlock": "172.31.0.0/16",
                "IsDefault": False,
                "State": "available",
                "CidrBlockAssociationSet": [
                    {"CidrBlock": "172.31.0.0/16", "CidrBlockState": {"State": "associated"}}
                ],
                "Tags": [{"Key": "Name", "Value": "ex-other-vpc"}],
            }
        )
        clone = copy.deepcopy(original)
        clone["SubnetId"] = "subnet-other01"
        clone["VpcId"] = "vpc-OTHER"          # ★ 別 VPC・同一 CIDR（正常な独立構成）
        clone["Tags"] = [{"Key": "Name", "Value": "ex-other-subnet-1a"}]
        network["subnets"].append(clone)

        answer = answers_by_id(q.resolve_all(inventory))["Q37"]
        self.assertIn("重複は存在しない", answer.summary)
        joined = "\n".join(answer.details)
        self.assertIn("VPC ごとの重複件数", joined)
        self.assertIn("vpc-OTHER", joined)

    def test_overlap_inside_one_vpc_is_still_detected(self) -> None:
        """同一 VPC 内の重複は、別 VPC を足しても引き続き検出されること。"""
        inventory = load_fixture()
        network = inventory["network"]
        vpc_id = network["vpcs"][0]["VpcId"]
        network["subnets"].append(
            {
                "SubnetId": "subnet-0overlap",
                "VpcId": vpc_id,
                "CidrBlock": "172.31.4.0/24",   # 172.31.0.0/20 の内側
                "AvailabilityZone": "ap-northeast-1a",
                "DefaultForAz": False,
                "State": "available",
                "Tags": [{"Key": "Name", "Value": "ex-overlap-subnet-1a"}],
            }
        )
        answer = answers_by_id(q.resolve_all(inventory))["Q37"]
        self.assertIn("重複が 1 ペアある", answer.summary)
        self.assertIn(vpc_id, "\n".join(answer.details))

    def test_ipv6_cidr_appears_in_details(self) -> None:
        """IPv6 専用サブネットの CIDR が一覧に現れること。"""
        inventory = load_fixture()
        inventory["network"]["subnets"].append(
            {
                "SubnetId": "subnet-0v6only",
                "VpcId": inventory["network"]["vpcs"][0]["VpcId"],
                "CidrBlock": None,
                "Ipv6CidrBlockAssociationSet": [
                    {
                        "AssociationId": "subnet-cidr-assoc-v6",
                        "Ipv6CidrBlock": "2406:da14:1::/64",
                        "Ipv6CidrBlockState": {"State": "associated"},
                    }
                ],
                "AvailabilityZone": "ap-northeast-1a",
                "DefaultForAz": False,
                "State": "available",
                "Tags": [{"Key": "Name", "Value": "ex-v6-only-subnet-1a"}],
            }
        )
        answer = answers_by_id(q.resolve_all(inventory))["Q37"]
        joined = "\n".join(answer.details)
        self.assertIn("2406:da14:1::/64", joined)
        self.assertIn("IPv6 CIDR を持つサブネット: **1 本**", joined)
        self.assertIn("IPv6 を持つもの 1 本", answer.summary)

    def test_ipv6_overlap_is_detected(self) -> None:
        """IPv6 どうしの重複も検出されること（IPv4 だけを見ていない）。"""
        inventory = load_fixture()
        vpc_id = inventory["network"]["vpcs"][0]["VpcId"]
        for suffix in ("a", "b"):
            inventory["network"]["subnets"].append(
                {
                    "SubnetId": f"subnet-0v6{suffix}",
                    "VpcId": vpc_id,
                    "CidrBlock": None,
                    "Ipv6CidrBlockAssociationSet": [
                        {"Ipv6CidrBlock": "2406:da14:1::/64"}
                    ],
                    "AvailabilityZone": "ap-northeast-1a",
                    "DefaultForAz": False,
                    "State": "available",
                    "Tags": [{"Key": "Name", "Value": f"ex-v6-{suffix}-1a"}],
                }
            )
        answer = answers_by_id(q.resolve_all(inventory))["Q37"]
        self.assertIn("重複が 1 ペアある", answer.summary)
        self.assertIn("完全一致", "\n".join(answer.details))

    def test_no_unconditional_design_doc_claim(self) -> None:
        """「設計資料 §5-2 の矛盾は解消した」を無条件に書かないこと。"""
        answer = answers_by_id(q.resolve_all(load_fixture()))["Q37"]
        self.assertNotIn("§5-2", answer.summary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
