"""出力モジュール（excel.py / diagram.py / gen_iam_policy.py）の検証。

確認すること:
1. `build_workbook` を fixture inventory に対して実行し、生成された xlsx を
   openpyxl で開き直して全シートの行数・列数・見出しを確認する
2. 空 dict `{}` でも例外を出さずファイルが生成されること
3. `build_diagram_data` の全出力ファイルが生成され、TSV の列数が
   行ごとに一致すること
4. `gen_iam_policy.py` が有効な JSON を出し、全コレクタの `iam_actions` が
   漏れなく含まれること
5. 機微情報（AKIA/ASIA で始まる完全なキーID、`SecretString`）が
   出力に混ざらないことの正規表現スキャン

実行:
    python3 -m pytest tests/test_outputs.py -v
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import openpyxl  # noqa: E402

from awsprobe.excel import build_workbook  # noqa: E402
from awsprobe.diagram import build_diagram_data  # noqa: E402
from awsprobe.questions import resolve_all  # noqa: E402
from awsprobe.posture import evaluate as posture_evaluate  # noqa: E402
from awsprobe.gen_iam_policy import (  # noqa: E402
    build_policy,
    collect_actions,
    actions_by_service,
)
from awsprobe.collectors.base import REGISTRY  # noqa: E402
from awsprobe.collectors import (  # noqa: E402,F401
    compute, database, edge, logging_, network, security, serverless, storage,
)

_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "inventory_example.json")

#: 完全なアクセスキーID（AKIA/ASIA + 16文字）を検出する正規表現
_AKID_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
#: マスク済みキー表記（"****ABCD"）は許容する。これは誤検出しないよう別途除外する。


def _load_inventory() -> dict:
    with open(_FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def _iter_cell_texts(xlsx_path: str):
    wb = openpyxl.load_workbook(xlsx_path)
    for name in wb.sheetnames:
        ws = wb[name]
        for row in ws.iter_rows():
            for cell in row:
                if cell.value is not None:
                    yield str(cell.value)


class BuildWorkbookTest(unittest.TestCase):
    """`build_workbook` の検証。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.inv = _load_inventory()
        cls.answers = resolve_all(cls.inv)
        cls.posture_results = posture_evaluate(cls.inv)
        cls.tmpdir = tempfile.mkdtemp(prefix="awsprobe-test-")
        cls.out_path = os.path.join(cls.tmpdir, "test.xlsx")
        build_workbook(
            cls.inv, cls.out_path,
            posture_results=cls.posture_results, answers=cls.answers,
        )
        cls.wb = openpyxl.load_workbook(cls.out_path)

    def test_file_created(self) -> None:
        self.assertTrue(os.path.exists(self.out_path))
        self.assertGreater(os.path.getsize(self.out_path), 0)

    def test_summary_sheet_is_first(self) -> None:
        self.assertEqual(self.wb.sheetnames[0], "サマリ")

    def test_all_expected_sheets_present(self) -> None:
        # fixture には posture_results / answers も渡しているため、
        # 15種すべて（サマリを除く）が作られているはず。
        expected = {
            "VPC・サブネット", "ルートテーブル", "セキュリティグループ", "ネットワークACL",
            "EC2", "RDS", "ロードバランサ", "S3", "EFS", "Lambda・EventBridge",
            "ログ・証跡", "IAM", "セキュリティ設定評価", "未確認事項の判定", "収集エラー",
        }
        self.assertTrue(expected.issubset(set(self.wb.sheetnames)))

    def test_sheet_dimensions_and_headers(self) -> None:
        """各シートが1行以上のヘッダーと1行以上のデータを持つこと（サマリ除く）。"""
        for name in self.wb.sheetnames:
            if name == "サマリ":
                continue
            with self.subTest(sheet=name):
                ws = self.wb[name]
                self.assertGreaterEqual(ws.max_row, 2, f"{name} にデータ行が無い")
                self.assertGreaterEqual(ws.max_column, 2, f"{name} の列数が少なすぎる")
                # 先頭ブロックの見出し行を探す（濃紺の実データヘッダー、または表題行）
                header_texts = [c.value for c in ws[1] if c.value]
                self.assertTrue(header_texts, f"{name} の1行目に見出しが無い")

    def test_security_group_sheet_highlights_open_world(self) -> None:
        ws = self.wb["セキュリティグループ"]
        headers = [c.value for c in ws[1]]
        world_col = headers.index("全世界公開(0.0.0.0/0)")
        found_red = False
        for row in ws.iter_rows(min_row=2):
            if row[world_col].value == "はい":
                fill = row[0].fill
                self.assertEqual(fill.patternType, "solid")
                self.assertEqual(str(fill.fgColor.rgb), "FFFFC7CE")
                found_red = True
        self.assertTrue(found_red, "0.0.0.0/0 の行が1件も見つからなかった（fixture 側の想定違い）")

    def test_posture_sheet_highlights_not_done_and_partial(self) -> None:
        ws = self.wb["セキュリティ設定評価"]
        headers = [c.value for c in ws[1]]
        status_col = headers.index("実施状況")
        seen = {"未実施": False, "一部実施": False}
        for row in ws.iter_rows(min_row=2):
            status = row[status_col].value
            if status in seen:
                fill = row[0].fill
                expected_rgb = "FFFFC7CE" if status == "未実施" else "FFFFEB9C"
                self.assertEqual(str(fill.fgColor.rgb), expected_rgb, status)
                seen[status] = True
        self.assertTrue(all(seen.values()), f"見つからなかった状態がある: {seen}")

    def test_freeze_panes_and_autofilter_set(self) -> None:
        for name in self.wb.sheetnames:
            ws = self.wb[name]
            if name == "サマリ":
                continue  # サマリは複数表を積むためフリーズ対象外
            with self.subTest(sheet=name):
                self.assertIsNotNone(ws.freeze_panes, f"{name} にフリーズペインが無い")
                self.assertTrue(ws.auto_filter.ref, f"{name} にオートフィルタが無い")

    def test_no_sensitive_data_leaks(self) -> None:
        for text in _iter_cell_texts(self.out_path):
            self.assertNotRegex(text, _AKID_RE, "完全なアクセスキーIDが出力に含まれている")
            self.assertNotIn("SecretString", text)


class BuildWorkbookEmptyTest(unittest.TestCase):
    """空 dict でも例外を出さずファイルが生成されること。"""

    def test_empty_dict(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            out_path = os.path.join(d, "empty.xlsx")
            result = build_workbook({}, out_path)
            self.assertEqual(result, out_path)
            self.assertTrue(os.path.exists(out_path))
            wb = openpyxl.load_workbook(out_path)
            self.assertEqual(wb.sheetnames, ["サマリ"])

    def test_none_like_missing_keys(self) -> None:
        """一部のキーだけ欠けた inventory でも落ちないこと。"""
        with tempfile.TemporaryDirectory() as d:
            out_path = os.path.join(d, "partial.xlsx")
            partial = {"network": {"vpcs": [{"VpcId": "vpc-1"}]}}
            build_workbook(partial, out_path)
            self.assertTrue(os.path.exists(out_path))


class BuildDiagramDataTest(unittest.TestCase):
    """`build_diagram_data` の検証。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.inv = _load_inventory()
        cls.tmpdir = tempfile.mkdtemp(prefix="awsprobe-diagram-")
        cls.paths = build_diagram_data(cls.inv, cls.tmpdir)

    def test_all_files_written(self) -> None:
        expected_names = {
            "diagram_subnets.tsv", "diagram_instances.tsv", "diagram_databases.tsv",
            "diagram_loadbalancers.tsv", "diagram_edges.tsv", "diagram_regional.tsv",
            "diagram_data.json",
        }
        actual_names = {os.path.basename(p) for p in self.paths}
        self.assertEqual(actual_names, expected_names)
        for p in self.paths:
            self.assertTrue(os.path.exists(p))
            self.assertGreater(os.path.getsize(p), 0)

    def test_tsv_column_counts_consistent(self) -> None:
        for p in self.paths:
            if not p.endswith(".tsv"):
                continue
            with self.subTest(file=os.path.basename(p)):
                with open(p, encoding="utf-8") as f:
                    lines = [line.rstrip("\n") for line in f if line.strip("\n") != ""]
                self.assertGreaterEqual(len(lines), 1)
                ncols = len(lines[0].split("\t"))
                for line in lines[1:]:
                    self.assertEqual(len(line.split("\t")), ncols, f"{p}: 列数不一致 -> {line!r}")

    def test_json_is_valid_and_has_all_sections(self) -> None:
        json_path = [p for p in self.paths if p.endswith(".json")][0]
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        for key in ("subnets", "instances", "databases", "load_balancers", "edges", "regional_services"):
            self.assertIn(key, data)
            self.assertIsInstance(data[key], list)

    def test_edges_derived(self) -> None:
        json_path = [p for p in self.paths if p.endswith(".json")][0]
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        kinds = {e["kind"] for e in data["edges"]}
        # SG ルール・ルーティング・ロードバランシング・DB接続推定が最低限出ること
        self.assertTrue({"SG許可", "ルーティング", "ロードバランシング"}.issubset(kinds))

    def test_empty_inventory_does_not_raise(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            paths = build_diagram_data({}, d)
            self.assertEqual(len(paths), 7)
            for p in paths:
                self.assertTrue(os.path.exists(p))

    def test_no_sensitive_data_leaks(self) -> None:
        for p in self.paths:
            with open(p, encoding="utf-8") as f:
                text = f.read()
            self.assertNotRegex(text, _AKID_RE)
            self.assertNotIn("SecretString", text)


class GenIamPolicyTest(unittest.TestCase):
    """`gen_iam_policy.py` の検証。"""

    def test_collect_actions_not_hardcoded_matches_registry(self) -> None:
        expected: set[str] = set()
        for cls in REGISTRY.values():
            expected.update(cls.iam_actions or ())
        actual = set(collect_actions())
        self.assertEqual(actual, expected)
        self.assertGreater(len(actual), 0)

    def test_build_policy_is_valid_json_shape(self) -> None:
        policy = build_policy()
        self.assertEqual(policy["Version"], "2012-10-17")
        self.assertEqual(len(policy["Statement"]), 2)

        main_stmt, ssm_stmt = policy["Statement"]
        self.assertEqual(main_stmt["Effect"], "Allow")
        self.assertEqual(main_stmt["Resource"], "*")
        self.assertGreater(len(main_stmt["Action"]), 0)

        self.assertEqual(ssm_stmt["Effect"], "Deny")
        self.assertIn("ssm:SendCommand", ssm_stmt["Action"])

        # JSON に往復できること（実際に生成した JSON 文字列としても壊れていないこと）
        text = json.dumps(policy, ensure_ascii=False)
        reparsed = json.loads(text)
        self.assertEqual(reparsed, policy)

    def test_all_collector_actions_included(self) -> None:
        policy = build_policy()
        main_actions = set(policy["Statement"][0]["Action"])
        for cls in REGISTRY.values():
            for action in cls.iam_actions or ():
                self.assertIn(action, main_actions, f"{cls.name} の {action} が漏れている")

    def test_actions_grouped_by_service_and_sorted(self) -> None:
        policy = build_policy()
        actions = policy["Statement"][0]["Action"]
        services = [a.split(":", 1)[0] for a in actions]
        # サービスごとにグループ化されている（同じサービスが連続する）ことを、
        # 「一度離れたサービスに再度戻らない」ことで確認する。
        seen = []
        for s in services:
            if not seen or seen[-1] != s:
                seen.append(s)
        self.assertEqual(len(seen), len(set(services)), "同じサービスのアクションが分散している")
        self.assertEqual(seen, sorted(seen))

    def test_docs_json_file_matches_generator(self) -> None:
        """リポジトリに同梱の docs/iam-policy-readonly.json が最新の生成結果と一致すること。"""
        doc_path = os.path.join(os.path.dirname(__file__), "..", "docs", "iam-policy-readonly.json")
        doc_path = os.path.abspath(doc_path)
        if not os.path.exists(doc_path):
            self.skipTest("docs/iam-policy-readonly.json が未生成")
        with open(doc_path, encoding="utf-8") as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk, build_policy())

    def test_no_sensitive_data_leaks(self) -> None:
        policy_text = json.dumps(build_policy(), ensure_ascii=False)
        self.assertNotRegex(policy_text, _AKID_RE)
        self.assertNotIn("SecretString", policy_text)


if __name__ == "__main__":
    unittest.main()
