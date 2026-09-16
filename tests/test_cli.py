"""CLI の通し検証。

確認すること:
1. 全サブコマンドが `--help` で落ちないこと
2. フィクスチャを inventory として与えると answer / posture / excel /
   diagram-data / iam-policy がすべて成果物を生成すること（実 AWS 不要）
3. **AWS 認証情報が無い状態でも doctor と host-probe が例外で落ちず、
   利用者に次の一手を示して正常終了すること**
4. **host-probe が `--enable-ssm` 無しでは ssm:SendCommand を1度も発行しないこと**
5. コレクタが REGISTRY に漏れなく登録されていること
6. 成果物に機微情報（完全なアクセスキーID・秘密鍵）が混ざらないこと

実行:
    python3 -m pytest tests/test_cli.py -v
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from awsprobe.cli import build_parser, main  # noqa: E402
from awsprobe.collectors import DEFAULT_ORDER, REGISTRY  # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "inventory_example.json")

SUBCOMMANDS = (
    "doctor", "collect", "answer", "posture",
    "excel", "diagram-data", "iam-policy", "host-probe", "all",
)

#: 成果物に混ざってはいけないもの
SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bssh-(?:rsa|ed25519|dss) AAAA[0-9A-Za-z+/=]{20,}"),
)

#: 認証情報を完全に無効化した環境変数（実 AWS を絶対に触らせない）
NO_AWS_ENV = {
    "AWS_ACCESS_KEY_ID": "",
    "AWS_SECRET_ACCESS_KEY": "",
    "AWS_SESSION_TOKEN": "",
    "AWS_PROFILE": "",
    "AWS_DEFAULT_PROFILE": "",
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_EC2_METADATA_DISABLED": "true",
    "AWS_METADATA_SERVICE_TIMEOUT": "0",
    "AWS_METADATA_SERVICE_NUM_ATTEMPTS": "1",
}


def run_cli(*argv: str, timeout: int = 180) -> subprocess.CompletedProcess:
    """`python -m awsprobe` を別プロセスで、AWS 認証情報なしで実行する。"""
    env = dict(os.environ)
    env.update(NO_AWS_ENV)
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "awsprobe", *argv],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout,
    )


class ParserTest(unittest.TestCase):
    """サブコマンドの定義が壊れていないこと。"""

    def test_all_subcommands_have_help(self):
        parser = build_parser()
        for cmd in SUBCOMMANDS:
            with self.subTest(cmd=cmd):
                proc = run_cli(cmd, "--help", timeout=60)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(cmd.split("-")[0], proc.stdout + proc.stderr)
        self.assertIsNotNone(parser)

    def test_collectors_are_registered(self):
        self.assertEqual(set(DEFAULT_ORDER), set(REGISTRY))
        self.assertGreaterEqual(len(REGISTRY), 8)
        for name, cls in REGISTRY.items():
            with self.subTest(collector=name):
                self.assertEqual(cls.name, name)
                self.assertTrue(cls.iam_actions, f"{name} に iam_actions が無い")


class OfflinePipelineTest(unittest.TestCase):
    """実 AWS 無しで、フィクスチャから全成果物が作れること。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="awsprobe-cli-")
        shutil.copy(FIXTURE, os.path.join(cls.tmp, "inventory.json"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_answer(self):
        rc = main(["answer", "--out", self.tmp])
        self.assertEqual(rc, 0)
        path = os.path.join(self.tmp, "未確認事項_突合レポート.md")
        self.assertTrue(os.path.exists(path))
        text = open(path, encoding="utf-8").read()
        for qid in ("Q1", "Q9", "Q23", "Q37", "Q38", "Q42"):
            with self.subTest(qid=qid):
                self.assertIn(qid, text)
        self.assertGreater(len(text), 10_000)

    def test_posture(self):
        rc = main(["posture", "--out", self.tmp])
        self.assertEqual(rc, 0)
        path = os.path.join(self.tmp, "セキュリティ設定_実施状況.md")
        self.assertTrue(os.path.exists(path))
        text = open(path, encoding="utf-8").read()
        for cid in ("ENC-01", "NET-01", "NET-06", "IAM-07", "LOG-06"):
            with self.subTest(cid=cid):
                self.assertIn(cid, text)

    def test_excel(self):
        rc = main(["excel", "--out", self.tmp])
        self.assertEqual(rc, 0)
        path = os.path.join(self.tmp, "AWS実査_棚卸し.xlsx")
        self.assertTrue(os.path.exists(path))
        import openpyxl
        wb = openpyxl.load_workbook(path)
        self.assertIn("サマリ", wb.sheetnames)
        self.assertGreaterEqual(len(wb.sheetnames), 10)

    def test_diagram_data(self):
        rc = main(["diagram-data", "--out", self.tmp])
        self.assertEqual(rc, 0)
        out = os.path.join(self.tmp, "diagram")
        for name in ("diagram_subnets.tsv", "diagram_instances.tsv",
                     "diagram_edges.tsv", "diagram_data.json"):
            with self.subTest(name=name):
                self.assertTrue(os.path.exists(os.path.join(out, name)))
        with open(os.path.join(out, "diagram_data.json"), encoding="utf-8") as fh:
            json.load(fh)   # 壊れた JSON でないこと

    def test_iam_policy(self):
        path = os.path.join(self.tmp, "iam-policy.json")
        rc = main(["iam-policy", "--out", path])
        self.assertEqual(rc, 0)
        with open(path, encoding="utf-8") as fh:
            policy = json.load(fh)
        self.assertEqual(policy.get("Version"), "2012-10-17")
        actions = {a for st in policy["Statement"] for a in st.get("Action", [])}
        self.assertGreater(len(actions), 100)
        # 変更系アクションが混ざっていないこと（SSM RunCommand は Deny 文に隔離されている）
        allow_actions = {
            a for st in policy["Statement"] if st.get("Effect") == "Allow"
            for a in st.get("Action", [])
        }
        for action in allow_actions:
            with self.subTest(action=action):
                verb = action.split(":", 1)[1]
                self.assertTrue(
                    # apigateway だけは IAM アクションが HTTP 動詞（GET/HEAD）になっている
                    verb in {"GET", "HEAD"}
                    or verb.startswith(("Describe", "List", "Get", "Head", "Lookup",
                                        "Search", "BatchGet", "Simulate")),
                    f"Allow に読み取り系でないアクションがある: {action}",
                )

    def test_missing_inventory_is_a_clear_error(self):
        proc = run_cli("answer", "--out", os.path.join(self.tmp, "nowhere"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("inventory が見つかりません", proc.stdout + proc.stderr)

    def test_outputs_have_no_secrets(self):
        for fn in ("answer", "posture", "excel", "diagram-data"):
            main([fn, "--out", self.tmp])
        for root, _dirs, files in os.walk(self.tmp):
            for name in files:
                path = os.path.join(root, name)
                with open(path, "rb") as fh:
                    blob = fh.read().decode("utf-8", errors="ignore")
                for pattern in SECRET_PATTERNS:
                    with self.subTest(file=name, pattern=pattern.pattern):
                        self.assertIsNone(pattern.search(blob))


class NoCredentialsTest(unittest.TestCase):
    """認証情報が無くても利用者に次の一手を示して正常終了すること。"""

    def test_doctor_without_credentials(self):
        proc = run_cli("doctor")
        out = proc.stdout + proc.stderr
        self.assertNotIn("Traceback", out)
        self.assertIn("認証情報が無効", out)
        self.assertIn("aws sso login", out)

    def test_collect_without_credentials_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_cli("collect", "--out", tmp)
            out = proc.stdout + proc.stderr
            self.assertNotIn("Traceback", out)
            self.assertIn("doctor", out)


class HostProbeSafetyTest(unittest.TestCase):
    """host-probe が既定で SSM コマンドを発行しないこと。"""

    def test_manual_fallback_without_enable_ssm(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(FIXTURE, os.path.join(tmp, "inventory.json"))
            doc = os.path.join(tmp, "manual.md")
            proc = run_cli("host-probe", "--out", tmp, "--manual-doc", doc)
            out = proc.stdout + proc.stderr
            self.assertNotIn("Traceback", out)
            self.assertIn("SSM 経由での調査は行いませんでした", out)
            self.assertIn("--enable-ssm", out)
            self.assertTrue(os.path.exists(doc))
            text = open(doc, encoding="utf-8").read()
            self.assertIn("読み取りのみ", text)

    def test_enable_ssm_without_yes_only_shows_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(FIXTURE, os.path.join(tmp, "inventory.json"))
            proc = run_cli("host-probe", "--out", tmp, "--enable-ssm")
            out = proc.stdout + proc.stderr
            self.assertNotIn("Traceback", out)
            self.assertIn("--yes", out)
            # 実行計画にスクリプト全文が出ていること
            self.assertIn("PROBE:", out)


if __name__ == "__main__":
    unittest.main()
