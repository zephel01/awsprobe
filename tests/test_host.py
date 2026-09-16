"""EC2 内部調査（host-probe）の検証。

**このテストの主目的は機能確認ではなく安全性の担保**である。確認すること:

1. `allow_ssm_command=False` の Context では **SendCommand が 1 度も発行されない**
   （ガードの呼び出し実績 `guard.calls` で確認する）。戻り値は `method="manual"`。
2. `allow_ssm_command=True` でも `confirm=False` なら SendCommand は発行されない。
3. **PROBES のコマンドに書き込み系が 1 つも含まれていない**
   （rm / mv / chmod / chown / systemctl start|stop|restart / yum install /
     apt install / curl / wget / 出力リダイレクト）。**これが最重要**。
4. 出力マスクが公開鍵本体・秘密鍵・アクセスキー・パスワードを落とすこと。
5. `render_manual_doc` が全プローブと Q 番号対応表を含む Markdown を作ること。
6. `import_manual_results` が `===== PROBE:x =====` 区切りを正しく解くこと。
7. インスタンス ID の検証が不正値を弾くこと。
8. moto で `ssm:DescribeInstanceInformation` が未実装でも落ちないこと。

実行:
    python3 -m pytest tests/test_host.py -v
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest

import boto3
from moto import mock_aws

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from awsprobe import host as host_mod  # noqa: E402
from awsprobe.guard import ReadOnlyGuard, ReadOnlyViolation  # noqa: E402
from awsprobe.session import Context  # noqa: E402

REGION = "ap-northeast-1"


def _fake_credentials() -> None:
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
    os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)


def _context(*, allow_ssm_command: bool) -> Context:
    """ガード付きの Context を作る（moto 内で使う）。"""
    session = boto3.Session(region_name=REGION)
    guard = ReadOnlyGuard(allow_ssm_command=allow_ssm_command)
    guard.attach(session)
    return Context(
        session=session,
        region=REGION,
        account_id="123456789012",
        guard=guard,
    )


# ===========================================================================
# 1. 書き込み系コマンドの静的検査（最重要）
# ===========================================================================

#: 例外的に許可する「ファイルを作らない」リダイレクト。
#: これらを先に取り除いてから `>` の有無を検査する。
ALLOWED_REDIRECTS = (
    ">/dev/null 2>&1",
    "2>/dev/null",
    ">/dev/null",
    "2>&1",
    "</dev/null",
)

#: 禁止コマンド。値は「検出する正規表現」と「なぜ危険か」。
#: 単語境界は `(?<![\w/.-])` / `(?![\w-])` で取る。
#: 例) `rpm` の "rm" や `format` の "rm" を誤検出しないため。
FORBIDDEN_PATTERNS: dict[str, tuple[str, str]] = {
    "rm": (r"(?<![\w/.-])rm(?![\w-])", "ファイル削除"),
    "rmdir": (r"(?<![\w/.-])rmdir(?![\w-])", "ディレクトリ削除"),
    "unlink": (r"(?<![\w/.-])unlink(?![\w-])", "ファイル削除"),
    "mv": (r"(?<![\w/.-])mv(?![\w-])", "ファイル移動"),
    "cp": (r"(?<![\w/.-])cp(?![\w-])", "ファイル複製（書き込み）"),
    "dd": (r"(?<![\w/.-])dd(?![\w-])", "ブロック書き込み"),
    "chmod": (r"(?<![\w/.-])chmod(?![\w-])", "権限変更"),
    "chown": (r"(?<![\w/.-])chown(?![\w-])", "所有者変更"),
    "chgrp": (r"(?<![\w/.-])chgrp(?![\w-])", "グループ変更"),
    "touch": (r"(?<![\w/.-])touch(?![\w-])", "ファイル作成"),
    "mkdir": (r"(?<![\w/.-])mkdir(?![\w-])", "ディレクトリ作成"),
    "tee": (r"(?<![\w/.-])tee(?![\w-])", "ファイル書き込み"),
    "truncate": (r"(?<![\w/.-])truncate(?![\w-])", "ファイル切り詰め"),
    "ln": (r"(?<![\w/.-])ln(?![\w-])", "リンク作成"),
    "curl": (r"(?<![\w/.-])curl(?![\w-])", "外部通信・ダウンロード"),
    "wget": (r"(?<![\w/.-])wget(?![\w-])", "外部通信・ダウンロード"),
    "nc": (r"(?<![\w/.-])nc(?![\w-])", "外部通信"),
    "kill": (r"(?<![\w/.-])kill(?![\w-])", "プロセス停止"),
    "pkill": (r"(?<![\w/.-])pkill(?![\w-])", "プロセス停止"),
    "reboot": (r"(?<![\w/.-])reboot(?![\w-])", "再起動"),
    "shutdown": (r"(?<![\w/.-])shutdown(?![\w-])", "停止"),
    "mkfs": (r"(?<![\w/.-])mkfs(?![\w-])", "フォーマット"),
    "sed -i": (r"(?<![\w/.-])sed\s+[^|;]*-i", "インプレース書き換え"),
    "systemctl 変更系": (
        r"systemctl\s+(?:--\S+\s+)*"
        r"(start|stop|restart|reload|enable|disable|mask|unmask|set-\S+|daemon-reload)\b",
        "サービス操作",
    ),
    "パッケージ導入": (
        r"\b(yum|dnf|apt|apt-get|pip|pip3|npm|gem|cargo|snap)\s+(?:-\S+\s+)*"
        r"(install|update|upgrade|remove|erase)\b",
        "パッケージ導入・更新",
    ),
    "crontab の -l なし": (
        # `crontab` は -l が無いと標準入力を読んで crontab を「上書き」する。
        # SSH で `bash -s` に流すと事故になるため、-l 必須を静的に強制する。
        # `/etc/crontab`（ファイルパス）は対象外にするため `(?<![\w/.-])` を付ける。
        r"(?<![\w/.-])crontab\b(?!\s+-[a-z]*l)",
        "crontab の上書き",
    ),
}


def strip_allowed_redirects(text: str) -> str:
    """許可済みリダイレクトを取り除く（残った `>` は書き込みとみなす）。"""
    out = text
    for token in ALLOWED_REDIRECTS:
        out = out.replace(token, " ")
    return out


#: 組み立て後のスクリプトでのみ例外的に許す `kill`（I-8 のウォッチドッグ）。
#:
#: `SendCommand` の `TimeoutSeconds` は**配信**のタイムアウトであって実行時間の
#: 上限ではなく、awsprobe が待つのをやめてもコマンドは本番サーバー上で root の
#: まま走り続ける（`ssm:CancelCommand` はガードに弾かれて呼べない）。そのため
#: スクリプト自身に自己終了の仕掛けを入れる必要があり、そこだけ `kill` を使う。
#:
#: 許すのは **自分自身・自分のプロセスグループ・自分の直下の子・自分が起動した
#: ウォッチドッグへのシグナル送出だけ**。リテラルの PID やプロセス名を指定する
#: `kill` は従来どおり検出される（下の test_watchdog_kill_allowlist_is_narrow）。
ALLOWED_KILL_RE = re.compile(
    r'kill (?:-TERM )?"-?\$'
    r'(?:AWSPROBE_MAIN_PID|AWSPROBE_MAIN_PGID|AWSPROBE_WATCHDOG|awsprobe_child)"'
)


def strip_allowed_kills(text: str) -> str:
    """ウォッチドッグの `kill` だけを取り除く。"""
    return ALLOWED_KILL_RE.sub(" ", text)


class ProbeCommandSafetyTest(unittest.TestCase):
    """PROBES のコマンド文字列に書き込み系が混入していないことを静的検査する。"""

    def test_no_write_commands_in_probes(self) -> None:
        """全プローブのコマンドに禁止コマンドが 1 つも含まれないこと。"""
        violations: list[str] = []
        for probe in host_mod.PROBES:
            for label, (pattern, why) in FORBIDDEN_PATTERNS.items():
                found = re.search(pattern, probe.command)
                if found:
                    violations.append(
                        f"{probe.name}: 禁止コマンド {label}（{why}）を検出 "
                        f"-> ...{probe.command[max(0, found.start() - 30):found.end() + 30]}..."
                    )
        self.assertEqual(violations, [], "書き込み系コマンドを検出:\n" + "\n".join(violations))

    def test_no_output_redirection_in_probes(self) -> None:
        """`>` / `>>` によるファイル出力が無いこと。

        `2>/dev/null` `>/dev/null` `2>&1` `</dev/null` の 4 つだけを
        例外として取り除いてから検査する（いずれもファイルを作らない）。
        """
        for probe in host_mod.PROBES:
            residue = strip_allowed_redirects(probe.command)
            self.assertNotIn(
                ">", residue,
                f"{probe.name}: 許可外の出力リダイレクトがある -> {probe.command}",
            )

    def test_assembled_script_is_also_clean(self) -> None:
        """組み立て後のスクリプト全文にも禁止コマンドが無いこと。

        **I-8 の対応で例外が 1 つだけ増えた**: 自己終了のウォッチドッグが使う
        `kill`。`ALLOWED_KILL_RE` に完全一致する「自分自身と自分のウォッチドッグ
        へのシグナル送出」だけを取り除いてから、従来どおり全パターンを検査する。
        これを許さないとホスト側スクリプトに実行時間の上限を掛けられず、
        本番サーバーで `du` などが無制限に走り続ける事故を防げないため。
        """
        script = host_mod.script_text()
        residue = strip_allowed_redirects(script)
        self.assertNotIn(">", residue)
        scannable = strip_allowed_kills(script)
        for label, (pattern, _why) in FORBIDDEN_PATTERNS.items():
            self.assertIsNone(
                re.search(pattern, scannable),
                f"組み立て後のスクリプトに {label} が混入している",
            )

    def test_watchdog_kill_allowlist_is_narrow(self) -> None:
        """ウォッチドッグ以外の `kill` は依然として検出されること（例外の穴を塞ぐ）。"""
        # 許可対象はこの 2 形だけ（置換後に kill が残らない）
        stripped = strip_allowed_kills(
            'kill -TERM "$AWSPROBE_MAIN_PID" kill "$AWSPROBE_WATCHDOG"'
        )
        self.assertNotIn("kill", stripped)
        # 他プロセスを止める kill は残り、禁止パターンに引っかかる
        for sample in ("kill -9 1234", "kill $(pgrep nginx)", "pkill nginx"):
            residue = strip_allowed_kills(sample)
            hit = re.search(FORBIDDEN_PATTERNS["kill"][0], residue) or re.search(
                FORBIDDEN_PATTERNS["pkill"][0], residue
            )
            self.assertIsNotNone(hit, f"{sample!r} が検出されていない")

    def test_every_kill_is_on_the_allowlist(self) -> None:
        """スクリプト中の `kill` が 1 つ残らず許可形であること。"""
        script = host_mod.script_text()
        total = len(re.findall(r"(?<![\w/.-])kill(?![\w-])", script))
        allowed = len(ALLOWED_KILL_RE.findall(script))
        self.assertGreater(total, 0, "ウォッチドッグの kill が消えている")
        self.assertEqual(
            total, allowed, "許可形でない kill がスクリプトに混入している"
        )

    def test_forbidden_patterns_actually_detect(self) -> None:
        """検査ロジック自体が機能していることの確認（偽陰性の検出）。

        わざと危険なコマンドを与えて、必ず検出できることを確かめる。
        """
        samples = {
            "rm": "rm -rf /tmp/x",
            "mv": "mv a b",
            "chmod": "chmod 777 /etc/passwd",
            "chown": "chown root /etc/passwd",
            "curl": "curl https://example.invalid/x.sh",
            "wget": "wget https://example.invalid/x.sh",
            "systemctl 変更系": "systemctl restart nginx",
            "パッケージ導入": "yum install -y httpd",
            "crontab の -l なし": "crontab /tmp/new",
        }
        for label, sample in samples.items():
            pattern = FORBIDDEN_PATTERNS[label][0]
            self.assertIsNotNone(
                re.search(pattern, sample), f"{label} の検査が {sample!r} を検出できていない"
            )

    def test_redirect_check_actually_detects(self) -> None:
        """リダイレクト検査が実際の書き込みを検出すること。"""
        self.assertIn(">", strip_allowed_redirects("cat /etc/passwd > /tmp/out"))
        self.assertIn(">", strip_allowed_redirects("echo x >> /tmp/out"))
        # 許可済みのものは残らない
        self.assertNotIn(">", strip_allowed_redirects("cat /etc/x 2>/dev/null"))
        self.assertNotIn(">", strip_allowed_redirects("command -v go >/dev/null 2>&1"))

    def test_probes_are_a_frozen_whitelist(self) -> None:
        """PROBES がタプルで、要素が frozen dataclass であること。"""
        self.assertIsInstance(host_mod.PROBES, tuple)
        for probe in host_mod.PROBES:
            self.assertIsInstance(probe, host_mod.Probe)
            with self.assertRaises(Exception):
                probe.command = "rm -rf /"  # frozen なので代入できない

    def test_probe_names_are_safe_tokens(self) -> None:
        """プローブ名がシェルへ埋め込んでも安全な字種だけであること。"""
        for probe in host_mod.PROBES:
            self.assertRegex(probe.name, r"^[a-z0-9_]+$")
            self.assertTrue(probe.title)
            self.assertTrue(probe.why)

    def test_resolve_probes_rejects_foreign_probe(self) -> None:
        """外部で作った Probe（＝任意コマンド）は採用しない。"""
        evil = host_mod.Probe("os_release", "偽", "rm -rf /", ("Q14",), "悪意")
        with self.assertRaises(ValueError):
            host_mod.resolve_probes([evil])
        with self.assertRaises(ValueError):
            host_mod.resolve_probes(["not_a_probe"])
        self.assertEqual(host_mod.resolve_probes(None), host_mod.PROBES)
        self.assertEqual(
            [p.name for p in host_mod.resolve_probes(["os_release", "mounts"])],
            ["os_release", "mounts"],
        )

    def test_forbidden_patterns_do_not_false_positive(self) -> None:
        """正当なコマンド断片を誤検出しないこと（`rpm` の rm など）。"""
        benign = "rpm -qa | sort; printf '%s' x; getent passwd"
        for label, (pattern, _why) in FORBIDDEN_PATTERNS.items():
            if label == "crontab の -l なし":
                continue
            self.assertIsNone(re.search(pattern, benign), f"{label} が誤検出した")


# ===========================================================================
# 2. ガード連携（SendCommand を出さないこと）
# ===========================================================================


class GuardIntegrationTest(unittest.TestCase):
    """ガードが SSM コマンドを許可していないときの挙動。"""

    @classmethod
    def setUpClass(cls) -> None:
        _fake_credentials()
        cls._mock = mock_aws()
        cls._mock.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._mock.stop()

    @staticmethod
    def _send_command_calls(ctx: Context) -> list[tuple[str, str]]:
        return [c for c in (ctx.guard.calls if ctx.guard else []) if c[1] == "SendCommand"]

    def test_disabled_guard_never_sends_command(self) -> None:
        """allow_ssm_command=False なら SendCommand を 1 度も発行せず manual を返す。"""
        ctx = _context(allow_ssm_command=False)
        result = host_mod.probe_hosts(ctx, confirm=True)

        self.assertEqual(result["method"], "manual")
        self.assertEqual(result["reason"], "ssm_command_disabled")
        # ガードの呼び出し実績に SendCommand が 1 件も無いこと（＝試みてすらいない）
        self.assertEqual(self._send_command_calls(ctx), [])
        # 例外も送出していないこと（ReadOnlyViolation を踏んでいない）
        self.assertNotIn("SendCommand", [op for _svc, op in ctx.guard.calls])

    def test_disabled_guard_does_not_raise(self) -> None:
        """ガード違反例外が漏れないこと。"""
        ctx = _context(allow_ssm_command=False)
        try:
            host_mod.probe_hosts(ctx, confirm=True)
        except ReadOnlyViolation as exc:  # pragma: no cover
            self.fail(f"ガード違反例外が漏れた: {exc}")

    def test_enabled_but_unconfirmed_never_sends(self) -> None:
        """allow_ssm_command=True でも confirm=False なら送信しない。"""
        ctx = _context(allow_ssm_command=True)
        result = host_mod.probe_hosts(ctx, confirm=False)

        self.assertEqual(result["method"], "manual")
        self.assertEqual(result["reason"], "not_confirmed")
        self.assertEqual(self._send_command_calls(ctx), [])
        self.assertIn("送信するスクリプト全文", result["plan"])

    def test_dry_run_never_sends(self) -> None:
        """dry_run=True なら confirm=True でも送信しない。"""
        ctx = _context(allow_ssm_command=True)
        result = host_mod.probe_hosts(ctx, confirm=True, dry_run=True)
        self.assertEqual(result["reason"], "dry_run")
        self.assertEqual(self._send_command_calls(ctx), [])

    def test_guard_blocks_send_command_at_boto_level(self) -> None:
        """念のため: ガードが False のとき boto3 レベルでも SendCommand が弾かれること。"""
        ctx = _context(allow_ssm_command=False)
        client = ctx.client("ssm")
        with self.assertRaises(ReadOnlyViolation):
            client.send_command(
                InstanceIds=["i-0123456789abcdef0"],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": ["uname -a"]},
            )

    def test_describe_instance_information_is_safe_on_moto(self) -> None:
        """moto が SSM の当該 API を未実装でも落ちず、errors に記録されること。"""
        ctx = _context(allow_ssm_command=False)
        managed = host_mod.reachable_instances(ctx)
        self.assertIsInstance(managed, list)   # 例外にならないことが本題
        self.assertEqual(host_mod.online_instance_ids(managed), [])

    def test_probe_hosts_survives_missing_ssm(self) -> None:
        """SSM が引けない環境でも probe_hosts が dict を返すこと。"""
        ctx = _context(allow_ssm_command=True)
        result = host_mod.probe_hosts(ctx, confirm=True)
        self.assertIn(result["method"], ("ssm", "manual"))
        self.assertIsInstance(result["instances"], dict)


class _FakeSsmClient:
    """SSM の最小スタブ。SendCommand / GetCommandInvocation の呼び出しを記録する。

    ガードは boto3 の before-call フックなので、このスタブは通らない。
    ここで見たいのは「許可されたときに正しく 1 台 1 回で回収できるか」だけ。
    """

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.send_calls: list[dict] = []
        self.get_calls: list[dict] = []

    def can_paginate(self, _operation: str) -> bool:
        return False

    def describe_instance_information(self, **_kwargs):
        return {
            "InstanceInformationList": [
                {"InstanceId": "i-0123456789abcdef0", "PingStatus": "Online"},
                {"InstanceId": "i-0fedcba987654321a", "PingStatus": "ConnectionLost"},
            ]
        }

    def send_command(self, **kwargs):
        self.send_calls.append(kwargs)
        return {"Command": {"CommandId": "cmd-1"}}

    def get_command_invocation(self, **kwargs):
        self.get_calls.append(kwargs)
        return {
            "Status": "Success",
            "StandardOutputContent": self.stdout,
            "StandardErrorContent": "",
        }


class SsmExecutionPathTest(unittest.TestCase):
    """allow_ssm_command=True かつ confirm=True のときの実行経路。"""

    def _ctx_with_fake(self, stdout: str) -> tuple[Context, _FakeSsmClient]:
        _fake_credentials()
        with mock_aws():
            ctx = _context(allow_ssm_command=True)
        fake = _FakeSsmClient(stdout)
        ctx.client = lambda service, region=None: fake   # type: ignore[assignment]
        return ctx, fake

    def test_sends_once_per_batch_and_parses(self) -> None:
        """1 台につき **バッチ数ぶん** SendCommand を発行し、結果を統合すること。

        以前は「1 台につき 1 回」だったが、`StandardOutputContent` が 24,000 字で
        打ち切られると後半 7 プローブ（`authorized_keys` を含む）が黙って
        欠落するため、複数バッチに分けて送るよう変更した（I-7）。
        送信先・ドキュメント・スクリプト内容が固定であることは従来どおり検証する。
        """
        stdout = (
            "===== PROBE:os_release =====\n"
            'PRETTY_NAME="Amazon Linux 2"\n'
            "===== PROBE:authorized_keys =====\n"
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABleakedbody0123456789 alice@example\n"
            "===== PROBE:__end__ =====\n"
        )
        ctx, fake = self._ctx_with_fake(stdout)
        result = host_mod.probe_hosts(ctx, confirm=True, poll_interval=0)

        self.assertEqual(result["method"], "ssm")
        batches = host_mod.build_batches()
        # PingStatus=Online の 1 台にだけ、バッチ数ぶんだけ送っている
        self.assertEqual(len(fake.send_calls), len(batches))
        for call, batch in zip(fake.send_calls, batches):
            self.assertEqual(call["InstanceIds"], ["i-0123456789abcdef0"])
            self.assertEqual(call["DocumentName"], "AWS-RunShellScript")
            # 送ったスクリプトは PROBES から組み立てたものと完全一致する
            self.assertEqual(
                call["Parameters"]["commands"],
                host_mod.build_script(batch, max_seconds=call["TimeoutSeconds"]),
            )
        # 全プローブが漏れなくどこかのバッチに入っている（16 件・重複なし）
        sent = [p.name for batch in batches for p in batch]
        self.assertEqual(sorted(sent), sorted(p.name for p in host_mod.PROBES))
        # authorized_keys は最初のバッチの先頭（打ち切られても残る位置）
        self.assertEqual("authorized_keys", batches[0][0].name)

        entry = result["instances"]["i-0123456789abcdef0"]
        self.assertTrue(entry["ssm_reachable"])
        self.assertIn("Amazon Linux 2", entry["results"]["os_release"]["stdout"])
        # ★ 鍵本体は回収後のマスクで落ちている
        self.assertNotIn("AAAAB3NzaC1yc2E", entry["results"]["authorized_keys"]["stdout"])
        # 出力の無かったプローブも欠けずにキーが立つ
        for probe in host_mod.PROBES:
            self.assertIn(probe.name, entry["results"])

    def test_explicit_instance_filter(self) -> None:
        ctx, fake = self._ctx_with_fake("===== PROBE:end =====\n")
        result = host_mod.probe_hosts(
            ctx, ["i-0fedcba987654321a"], confirm=True, poll_interval=0
        )
        # ConnectionLost のインスタンスには送らない
        self.assertEqual(fake.send_calls, [])
        self.assertEqual(result["requested_but_unreachable"], ["i-0fedcba987654321a"])

    def test_subset_of_probes(self) -> None:
        ctx, fake = self._ctx_with_fake("===== PROBE:end =====\n")
        host_mod.probe_hosts(ctx, probes=["mounts"], confirm=True, poll_interval=0)
        sent = "\n".join(fake.send_calls[0]["Parameters"]["commands"])
        self.assertIn("PROBE:mounts", sent)
        self.assertNotIn("PROBE:authorized_keys", sent)


# ===========================================================================
# 3. インスタンス ID の検証
# ===========================================================================


class InstanceIdValidationTest(unittest.TestCase):
    def test_accepts_valid_ids(self) -> None:
        for good in ("i-0123456789abcdef0", "i-12345678", "i-abcdef0123456789a"):
            self.assertTrue(host_mod.valid_instance_id(good), good)

    def test_rejects_invalid_ids(self) -> None:
        bad_values = [
            "i-0123",                       # 短すぎる
            "i-0123456789ABCDEF0",          # 大文字は不可
            "i-0123456789abcdef01234",      # 長すぎる
            "mi-0123456789abcdef0",         # マネージドインスタンス ID
            "i-0123456789abcdef0; rm -rf /",  # コマンド注入
            "i-0123456789abcdef0\nuname -a",  # 改行注入
            "",
            None,
            123,
            ["i-0123456789abcdef0"],
        ]
        for bad in bad_values:
            self.assertFalse(host_mod.valid_instance_id(bad), repr(bad))
            with self.assertRaises(ValueError):
                host_mod.validate_instance_ids([bad])

    def test_validate_deduplicates(self) -> None:
        got = host_mod.validate_instance_ids(
            ["i-0123456789abcdef0", "i-0123456789abcdef0", "i-00000000"]
        )
        self.assertEqual(got, ["i-0123456789abcdef0", "i-00000000"])

    def test_injected_id_never_reaches_api(self) -> None:
        """不正 ID を渡すと API へ到達する前に ValueError になること。"""
        _fake_credentials()
        with mock_aws():
            ctx = _context(allow_ssm_command=True)
            with self.assertRaises(ValueError):
                host_mod.probe_hosts(ctx, ["i-1; curl http://evil"], confirm=True)
            self.assertEqual(ctx.guard.calls, [])   # API を 1 度も叩いていない


# ===========================================================================
# 4. 出力マスク
# ===========================================================================


class MaskSecretsTest(unittest.TestCase):
    def test_masks_rsa_public_key_body(self) -> None:
        text = (
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDexampleexampleexample"
            "EXAMPLEbodyDATA1234567890 alice@example\n"
        )
        masked = host_mod.mask_secrets(text)
        self.assertNotIn("AAAAB3NzaC1yc2E", masked)
        self.assertIn(host_mod.PUBKEY_MASK_LABEL, masked)
        # 鍵種別とコメントは残す（誰の鍵かの手掛かりになるため）
        self.assertIn("ssh-rsa", masked)
        self.assertIn("alice@example", masked)

    def test_masks_ed25519_and_ecdsa(self) -> None:
        for line in (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleBodyHere1234 vendor@vendor-a",
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbm example@host",
        ):
            masked = host_mod.mask_secrets(line)
            self.assertNotIn("AAAA", masked, line)
            self.assertIn(host_mod.PUBKEY_MASK_LABEL, masked)

    def test_masks_key_body_even_with_options_prefix(self) -> None:
        """`command="..."` が前置された行でも鍵本体が残らないこと。"""
        line = (
            'command="/usr/bin/backup",no-pty ssh-ed25519 '
            "AAAAC3NzaC1lZDI1NTE5AAAAIExampleBodyHere1234 batch@vendor-b"
        )
        masked = host_mod.mask_secrets(line)
        self.assertNotIn("AAAAC3NzaC1lZDI1NTE5", masked)

    def test_masks_private_key_pem(self) -> None:
        pem = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        masked = host_mod.mask_secrets(pem)
        self.assertNotIn("b3BlbnNzaC1rZXktdjEA", masked)
        self.assertIn(host_mod.MASK_LABEL, masked)

    def test_masks_access_key_and_password(self) -> None:
        masked = host_mod.mask_secrets("AKIAIOSFODNN7EXAMPLE DB_PASSWORD=hunter2 token: abc123")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", masked)
        self.assertNotIn("hunter2", masked)
        self.assertNotIn("abc123", masked)

    def test_keeps_ordinary_output(self) -> None:
        text = "nginx version: nginx/1.24.0\nlines=3\nperm=600 owner=ec2-user"
        self.assertEqual(host_mod.mask_secrets(text), text)

    def test_handles_none_and_non_string(self) -> None:
        self.assertEqual(host_mod.mask_secrets(None), "")
        self.assertEqual(host_mod.mask_secrets(""), "")

    def test_parse_output_applies_mask(self) -> None:
        """パース経路でも必ずマスクが掛かること。"""
        raw = (
            "===== PROBE:authorized_keys =====\n"
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDleakedleakedleaked user@x\n"
            "===== PROBE:end =====\n"
        )
        results = host_mod.parse_probe_output(raw)
        self.assertNotIn("AAAAB3NzaC1yc2E", results["authorized_keys"]["stdout"])


# ===========================================================================
# 5. スクリプト組み立て・計画表示・パース
# ===========================================================================


class ScriptAndParseTest(unittest.TestCase):
    def test_script_contains_every_probe_delimiter(self) -> None:
        script = host_mod.script_text()
        for probe in host_mod.PROBES:
            self.assertIn(f"===== PROBE:{probe.name} =====", script)

    def test_render_plan_shows_targets_and_script(self) -> None:
        plan = host_mod.render_plan(["i-0123456789abcdef0"], host_mod.PROBES)
        self.assertIn("i-0123456789abcdef0", plan)
        self.assertIn("送信するスクリプト全文", plan)
        self.assertIn("--yes", plan)
        for probe in host_mod.PROBES:
            self.assertIn(probe.name, plan)

    def test_parse_probe_output_splits_sections(self) -> None:
        raw = (
            "===== PROBE:os_release =====\n"
            'PRETTY_NAME="Amazon Linux 2"\n'
            "===== PROBE:mounts =====\n"
            "fs-0123.efs.ap-northeast-1.amazonaws.com:/ on /mnt/efs type nfs4\n"
            "===== PROBE:end =====\n"
        )
        results = host_mod.parse_probe_output(raw)
        self.assertEqual(sorted(results), ["mounts", "os_release"])
        self.assertIn("Amazon Linux 2", results["os_release"]["stdout"])
        self.assertIn("nfs4", results["mounts"]["stdout"])
        self.assertEqual(results["os_release"]["status"], "Success")
        self.assertNotIn("end", results)

    def test_parse_handles_noise_before_first_delimiter(self) -> None:
        raw = "起動時の雑多な出力\n===== PROBE:users =====\nroot uid=0\n"
        results = host_mod.parse_probe_output(raw)
        self.assertEqual(list(results), ["users"])
        self.assertNotIn("雑多", results["users"]["stdout"])

    def test_parse_empty_returns_empty(self) -> None:
        self.assertEqual(host_mod.parse_probe_output(""), {})


# ===========================================================================
# 6. 手順書生成
# ===========================================================================

SAMPLE_INVENTORY = {
    "errors": [],
    "compute": {
        "instances": [
            {
                "InstanceId": "i-0123456789abcdef0",
                "PrivateIpAddress": "10.0.1.10",
                "SubnetId": "subnet-aaa",
                "State": {"Name": "running"},
                "Tags": [{"Key": "Name", "Value": "ex-prod-web-01"}],
            },
            {
                "InstanceId": "i-0fedcba987654321a",
                "PrivateIpAddress": "10.0.1.11",
                "SubnetId": "subnet-aaa",
                "State": {"Name": "running"},
                "Tags": [{"Key": "Name", "Value": "ex-prod-web-02"}],
                "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/ssm"},
            },
        ],
        "ssm_managed_instances": [],
    },
    "network": {
        "subnets": [{"SubnetId": "subnet-aaa", "VpcId": "vpc-1"}],
        "route_tables": [
            {
                "VpcId": "vpc-1",
                "Associations": [{"Main": True}],
                "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}],
            }
        ],
        "vpc_endpoints": [],
    },
}


class ManualDocTest(unittest.TestCase):
    def test_contains_all_probes_and_question_map(self) -> None:
        doc = host_mod.render_manual_doc(
            None, out_path=None, inventory=SAMPLE_INVENTORY, allow_ssm_command=False
        )
        # 全プローブが掲載されていること（対応表・スクリプト両方）
        for probe in host_mod.PROBES:
            self.assertIn(probe.name, doc, probe.name)
            self.assertIn(probe.title, doc, probe.title)
            self.assertIn(probe.why, doc, probe.why)
        # Q 番号の対応表
        self.assertIn("## 4. 各コマンドが解消する設問", doc)
        for qid in ("Q7", "Q9", "Q14", "Q31", "Q32", "Q36"):
            self.assertIn(qid, doc, qid)

    def test_contains_required_sections(self) -> None:
        doc = host_mod.render_manual_doc(
            None, out_path=None, inventory=SAMPLE_INVENTORY, allow_ssm_command=False
        )
        for heading in (
            "## 1. SSM が使えなかった理由",
            "## 2. 対象インスタンス",
            "## 3. 実行するスクリプト",
            "## 4. 各コマンドが解消する設問",
            "## 5. 結果を awsprobe に取り込む",
            "## 6. 実行時の注意",
        ):
            self.assertIn(heading, doc, heading)
        # 取り込み導線
        self.assertIn("host_manual_", doc)
        self.assertIn("--import-dir", doc)
        # 注意書き
        self.assertIn("本番サーバー", doc)
        self.assertIn("鍵本体を出さない", doc)
        self.assertIn("読み取りのみ", doc)

    def test_instance_table_has_columns(self) -> None:
        doc = host_mod.render_manual_doc(
            None, out_path=None, inventory=SAMPLE_INVENTORY, allow_ssm_command=False
        )
        self.assertIn("| インスタンスID | Name タグ | プライベートIP | サブネット |", doc)
        self.assertIn("ex-prod-web-01", doc)
        self.assertIn("10.0.1.10", doc)
        self.assertIn("subnet-aaa", doc)

    def test_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "docs", "manual-ssh-commands.md")
            text = host_mod.render_manual_doc(
                None, out_path=path, inventory=SAMPLE_INVENTORY, allow_ssm_command=False
            )
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), text)

    def test_doc_is_japanese(self) -> None:
        doc = host_mod.render_manual_doc(None, out_path=None, inventory=SAMPLE_INVENTORY)
        self.assertIn("実行", doc)
        self.assertIn("注意", doc)


# ===========================================================================
# 7. SSM 不可の原因自動判定
# ===========================================================================


class DiagnoseTest(unittest.TestCase):
    def test_not_enabled_takes_precedence(self) -> None:
        diag = host_mod.diagnose_ssm_unavailable(SAMPLE_INVENTORY, allow_ssm_command=False)
        self.assertEqual(diag["cause"], host_mod.CAUSE_NOT_ENABLED)

    def test_permission_error(self) -> None:
        inv = dict(SAMPLE_INVENTORY)
        inv["errors"] = [
            {
                "service": "ssm",
                "operation": "describe_instance_information",
                "code": "AccessDeniedException",
                "message": "...",
            }
        ]
        diag = host_mod.diagnose_ssm_unavailable(inv, allow_ssm_command=True)
        self.assertEqual(diag["cause"], host_mod.CAUSE_NO_PERMISSION)

    def test_no_iam_role(self) -> None:
        inv = {
            "errors": [],
            "compute": {
                "instances": [
                    {"InstanceId": "i-0123456789abcdef0", "SubnetId": "subnet-aaa"},
                    {"InstanceId": "i-0123456789abcdef1", "SubnetId": "subnet-aaa"},
                ],
                "ssm_managed_instances": [],
            },
            "network": SAMPLE_INVENTORY["network"],
        }
        diag = host_mod.diagnose_ssm_unavailable(inv, allow_ssm_command=True)
        self.assertEqual(diag["cause"], host_mod.CAUSE_NO_ROLE)

    def test_no_endpoint_when_no_default_route(self) -> None:
        inv = {
            "errors": [],
            "compute": {
                "instances": [
                    {
                        "InstanceId": "i-0123456789abcdef0",
                        "SubnetId": "subnet-aaa",
                        "IamInstanceProfile": {"Arn": "arn:...:instance-profile/ssm"},
                    }
                ],
                "ssm_managed_instances": [],
            },
            "network": SAMPLE_INVENTORY["network"],   # 既定経路なし・エンドポイントなし
        }
        diag = host_mod.diagnose_ssm_unavailable(inv, allow_ssm_command=True)
        self.assertEqual(diag["cause"], host_mod.CAUSE_NO_ENDPOINT)

    def test_agent_missing_when_route_exists(self) -> None:
        inv = {
            "errors": [],
            "compute": {
                "instances": [
                    {
                        "InstanceId": "i-0123456789abcdef0",
                        "SubnetId": "subnet-aaa",
                        "IamInstanceProfile": {"Arn": "arn:...:instance-profile/ssm"},
                    }
                ],
                "ssm_managed_instances": [],
            },
            "network": {
                "subnets": [{"SubnetId": "subnet-aaa", "VpcId": "vpc-1"}],
                "route_tables": [
                    {
                        "VpcId": "vpc-1",
                        "Associations": [{"Main": True, "SubnetId": "subnet-aaa"}],
                        "Routes": [
                            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}
                        ],
                    }
                ],
                "vpc_endpoints": [],
            },
        }
        diag = host_mod.diagnose_ssm_unavailable(inv, allow_ssm_command=True)
        self.assertEqual(diag["cause"], host_mod.CAUSE_NO_AGENT)

    def test_all_online_returns_empty_cause(self) -> None:
        inv = {
            "errors": [],
            "compute": {
                "instances": [
                    {
                        "InstanceId": "i-0123456789abcdef0",
                        "SubnetId": "subnet-aaa",
                        "IamInstanceProfile": {"Arn": "arn:...:instance-profile/ssm"},
                    }
                ],
                "ssm_managed_instances": [
                    {"InstanceId": "i-0123456789abcdef0", "PingStatus": "Online"}
                ],
            },
            "network": SAMPLE_INVENTORY["network"],
        }
        diag = host_mod.diagnose_ssm_unavailable(inv, allow_ssm_command=True)
        self.assertEqual(diag["cause"], "")

    def test_no_instances(self) -> None:
        diag = host_mod.diagnose_ssm_unavailable({}, allow_ssm_command=True)
        self.assertEqual(diag["cause"], host_mod.CAUSE_UNKNOWN)


# ===========================================================================
# 8. 手動結果の取り込み
# ===========================================================================

MANUAL_SAMPLE = """起動メッセージ
===== PROBE:os_release =====
PRETTY_NAME="Amazon Linux 2"
VERSION_ID="2"
===== PROBE:authorized_keys =====
--- /home/ec2-user/.ssh/authorized_keys
    lines=3
      - [ssh-rsa] alice@example
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABleakedbody1234567890 leaked@example
===== PROBE:cron_jobs =====
0 3 * * * root /opt/app/batch.sh
===== PROBE:end =====
"""


class ImportManualResultsTest(unittest.TestCase):
    def test_parses_delimited_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "host_manual_i-0123456789abcdef0.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(MANUAL_SAMPLE)

            section = host_mod.import_manual_results([path])

        self.assertEqual(section["method"], "manual")
        instances = section["instances"]
        self.assertIn("i-0123456789abcdef0", instances)
        results = instances["i-0123456789abcdef0"]["results"]
        self.assertEqual(sorted(results), ["authorized_keys", "cron_jobs", "os_release"])
        self.assertIn("Amazon Linux 2", results["os_release"]["stdout"])
        self.assertIn("batch.sh", results["cron_jobs"]["stdout"])
        # 取り込み時にもマスクが掛かる
        self.assertNotIn("AAAAB3NzaC1yc2E", results["authorized_keys"]["stdout"])

    def test_accepts_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for iid in ("i-0123456789abcdef0", "i-0fedcba987654321a"):
                with open(
                    os.path.join(tmp, f"host_manual_{iid}.txt"), "w", encoding="utf-8"
                ) as handle:
                    handle.write(MANUAL_SAMPLE)
            section = host_mod.import_manual_results([tmp])
        self.assertEqual(len(section["instances"]), 2)

    def test_skips_file_without_instance_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "notes.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(MANUAL_SAMPLE)
            section = host_mod.import_manual_results([path])
        self.assertEqual(section["instances"], {})
        self.assertEqual(len(section["skipped_files"]), 1)

    def test_skips_file_without_delimiters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "host_manual_i-0123456789abcdef0.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("区切りの無いただのテキスト")
            section = host_mod.import_manual_results([path])
        self.assertEqual(section["instances"], {})
        self.assertEqual(len(section["skipped_files"]), 1)

    def test_structure_matches_ssm_path(self) -> None:
        """SSM 経由と同じ構造（questions.py が読める形）であること。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "host_manual_i-0123456789abcdef0.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(MANUAL_SAMPLE)
            section = host_mod.import_manual_results([path])
        entry = section["instances"]["i-0123456789abcdef0"]
        self.assertIn("ssm_reachable", entry)
        self.assertIn("results", entry)
        for res in entry["results"].values():
            self.assertEqual(sorted(res), sorted(["status", "stdout", "stderr"]))

    def test_merge_into_inventory(self) -> None:
        section = {
            "method": "manual",
            "instances": {
                "i-0123456789abcdef0": {
                    "ssm_reachable": False,
                    "results": {"os_release": {"status": "Success", "stdout": "x", "stderr": ""}},
                }
            },
        }
        inv = {"compute": {}}
        merged = host_mod.merge_into_inventory(inv, section)
        self.assertEqual(merged["host"]["method"], "manual")
        self.assertIn("i-0123456789abcdef0", merged["host"]["instances"])
        self.assertNotIn("host", inv)   # 元の dict は壊さない


# ===========================================================================
# 9. I-7: SSM stdout の 24,000 字打ち切り
# ===========================================================================


def _fake_probe_output(
    probes, *, filler: int = host_mod.PROBE_OUTPUT_LIMIT, sentinel: bool = True
) -> str:
    """実機の出力を模した文字列を作る（プローブごとに上限いっぱいまで出す）。"""
    parts: list[str] = []
    for probe in probes:
        parts.append(host_mod.DELIM_FORMAT.format(name=probe.name))
        parts.append(f"{probe.name}-" + "x" * max(0, filler - len(probe.name) - 1))
    if sentinel:
        parts.append(host_mod.DELIM_FORMAT.format(name=host_mod.END_SENTINEL))
    return "\n".join(parts) + "\n"


class _TruncatingSsmClient(_FakeSsmClient):
    """`StandardOutputContent` を 24,000 文字で打ち切る、本物に近いスタブ。

    実機の `GetCommandInvocation` はこの上限を超えた分を**何の印も無く捨てる**。
    """

    def __init__(self) -> None:
        super().__init__("")
        self.raw_lengths: list[int] = []

    def get_command_invocation(self, **kwargs):
        self.get_calls.append(kwargs)
        # 直前に送られたスクリプトから、実行対象のプローブを読み取って出力を作る
        commands = "\n".join(self.send_calls[-1]["Parameters"]["commands"])
        names = [
            m.group(1)
            for m in re.finditer(r"PROBE:([a-z0-9_]+) =====", commands)
            if m.group(1) != host_mod.END_SENTINEL
        ]
        probes = [host_mod.PROBES_BY_NAME[n] for n in names]
        raw = _fake_probe_output(probes)
        self.raw_lengths.append(len(raw))
        return {
            "Status": "Success",
            # ★ ここが実機の挙動: 24,000 字で黙って切られる
            "StandardOutputContent": raw[: host_mod.SSM_STDOUT_LIMIT],
            "StandardErrorContent": "",
        }


class StdoutTruncationTest(unittest.TestCase):
    """I-7: 24,000 字の打ち切りで最重要プローブが静かに消えないこと。"""

    def test_unbounded_probes_in_definition_order_lose_authorized_keys(self) -> None:
        """**修正前の欠陥の再現**: 出力上限なし・PROBES 定義順だと Q9 が消える。

        `cron_jobs` / `vendor_agent_files` / `systemd_units` には上限が無く、実機では
        数千文字になる。`authorized_keys` は定義順で 10 番目なので、
        1 本のスクリプトで流すと 24,000 字の壁の向こう側に落ちる。
        この回帰テストは「上限」と「分割」の両方が必要な理由を固定する。
        """
        heavy = {"vendor_agent_files", "systemd_units", "cron_jobs", "processes", "packages"}
        parts: list[str] = []
        for probe in host_mod.PROBES:          # ★ 分割も並べ替えもしない定義順
            parts.append(host_mod.DELIM_FORMAT.format(name=probe.name))
            parts.append("x" * (6000 if probe.name in heavy else 400))
        raw = "\n".join(parts) + "\n"

        self.assertGreater(len(raw), host_mod.SSM_STDOUT_LIMIT)
        cut = raw[: host_mod.SSM_STDOUT_LIMIT]
        lost = [p.name for p in host_mod.PROBES if f"PROBE:{p.name} =====" not in cut]
        self.assertIn(
            "authorized_keys", lost,
            "上限なし・定義順でも authorized_keys が残っており、前提が変わっている",
        )

    def test_capped_output_for_all_probes_still_needs_batching(self) -> None:
        """上限を掛けても 16 プローブ分は 24,000 字に収まらないこと。

        `head -c` だけでは足りず、バッチ分割が必要であることの根拠。
        """
        raw = _fake_probe_output(host_mod.PROBES)
        self.assertGreater(
            len(raw), host_mod.SSM_STDOUT_LIMIT,
            "16 プローブ分の出力が 24,000 字に収まっており、前提が変わっている",
        )

    def test_each_batch_fits_in_the_limit(self) -> None:
        """バッチごとなら 24,000 字に収まること。"""
        for batch in host_mod.build_batches():
            with self.subTest(batch=[p.name for p in batch]):
                raw = _fake_probe_output(batch)
                self.assertLess(len(raw), host_mod.SSM_STDOUT_LIMIT)

    def test_parse_marks_missing_probes_as_truncated(self) -> None:
        """番兵が無ければ打ち切りと判定し、欠落プローブを Truncated にすること。"""
        probes = host_mod.PROBES
        raw = _fake_probe_output(probes, sentinel=False)
        cut = raw[: host_mod.SSM_STDOUT_LIMIT]
        results = host_mod.parse_probe_output(cut, probes)

        self.assertIn(host_mod.TRUNCATION_KEY, results)
        truncated = [
            name for name, r in results.items()
            if r.get("status") in ("Truncated", "PartiallyTruncated")
        ]
        self.assertTrue(truncated, "Truncated と印を付けられたプローブが無い")
        # 全プローブのキーは欠けない（NoOutput にすり替わらない）
        for probe in probes:
            self.assertIn(probe.name, results)
            self.assertNotEqual(
                "NoOutput", results[probe.name]["status"],
                f"{probe.name}: 打ち切りなのに NoOutput になっている",
            )

    def test_complete_output_is_not_flagged(self) -> None:
        """番兵があれば打ち切り扱いにしないこと（誤検知の防止）。"""
        probes = host_mod.build_batches()[0]
        results = host_mod.parse_probe_output(_fake_probe_output(probes), probes)
        self.assertNotIn(host_mod.TRUNCATION_KEY, results)
        for probe in probes:
            self.assertEqual("Success", results[probe.name]["status"])

    def test_authorized_keys_survives_the_limit(self) -> None:
        """★ 打ち切りが起きても `authorized_keys`（Q9）は必ず取れること。"""
        _fake_credentials()
        with mock_aws():
            ctx = _context(allow_ssm_command=True)
        fake = _TruncatingSsmClient()
        ctx.client = lambda service, region=None: fake   # type: ignore[assignment]

        result = host_mod.probe_hosts(ctx, confirm=True, poll_interval=0)
        entry = result["instances"]["i-0123456789abcdef0"]
        results = entry["results"]

        self.assertEqual("Success", results["authorized_keys"]["status"])
        self.assertIn("authorized_keys-", results["authorized_keys"]["stdout"])
        # 分割送信により、16 プローブすべてが打ち切られずに取れている
        for probe in host_mod.PROBES:
            with self.subTest(probe=probe.name):
                self.assertEqual("Success", results[probe.name]["status"])
        self.assertFalse(entry["truncated"])
        self.assertFalse(result["truncated"])

    def test_truncated_flag_is_raised_on_host_section(self) -> None:
        """打ち切りが起きたら host セクションに truncated: true が立つこと。"""
        _fake_credentials()
        with mock_aws():
            ctx = _context(allow_ssm_command=True)

        class _NoSentinel(_TruncatingSsmClient):
            def get_command_invocation(self, **kwargs):
                resp = super().get_command_invocation(**kwargs)
                # 番兵ごと切り落とされた状況を作る
                resp["StandardOutputContent"] = resp["StandardOutputContent"].replace(
                    host_mod.DELIM_FORMAT.format(name=host_mod.END_SENTINEL), ""
                )
                return resp

        fake = _NoSentinel()
        ctx.client = lambda service, region=None: fake   # type: ignore[assignment]
        result = host_mod.probe_hosts(ctx, confirm=True, poll_interval=0)

        self.assertTrue(result["truncated"])
        entry = result["instances"]["i-0123456789abcdef0"]
        self.assertTrue(entry["truncated"])
        self.assertTrue(entry["truncated_probes"])

    def test_import_manual_results_flags_missing_sentinel(self) -> None:
        """手動採取ファイルでも番兵が無ければ truncated が立つこと。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "host_manual_i-0123456789abcdef0.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("===== PROBE:os_release =====\nAmazon Linux 2\n")
            section = host_mod.import_manual_results([path])
        self.assertTrue(section["truncated"])
        entry = section["instances"]["i-0123456789abcdef0"]
        self.assertTrue(entry["truncated"])
        self.assertIn(host_mod.TRUNCATION_KEY, entry["results"])


# ===========================================================================
# 10. I-8: ホスト側スクリプトの実行時間の上限
# ===========================================================================


class ScriptRuntimeLimitTest(unittest.TestCase):
    """I-8: 生成スクリプトが構文的に正しく、自己終了の仕掛けを持つこと。"""

    def _scripts(self) -> dict[str, str]:
        out = {"all": host_mod.script_text()}
        for i, batch in enumerate(host_mod.build_batches(), start=1):
            out[f"batch{i}"] = host_mod.script_text(batch)
        return out

    def test_script_is_valid_in_sh_bash_and_dash(self) -> None:
        """`sh -n` / `bash -n` / `dash -n` すべてで構文エラーにならないこと。

        SSM の AWS-RunShellScript は `/bin/sh` で、手順書は `bash -s` で実行するため、
        両方で通ることを固定する。
        """
        import shutil
        import subprocess

        checked = 0
        for shell in ("sh", "bash", "dash"):
            binary = shutil.which(shell)
            if not binary:
                continue
            for name, text in self._scripts().items():
                with self.subTest(shell=shell, script=name):
                    proc = subprocess.run(
                        [binary, "-n"], input=text, text=True,
                        capture_output=True, timeout=30,
                    )
                    self.assertEqual(
                        0, proc.returncode,
                        f"{shell} -n が失敗した: {proc.stderr}",
                    )
                    checked += 1
        self.assertGreater(checked, 0, "検査できたシェルが 1 つも無い")

    def test_watchdog_is_present(self) -> None:
        """自己終了のウォッチドッグが入っていること。"""
        script = host_mod.script_text()
        self.assertIn("AWSPROBE_MAIN_PID=$$", script)
        self.assertIn("AWSPROBE_WATCHDOG=$!", script)
        self.assertIn(f"sleep {host_mod.SCRIPT_MAX_SECONDS}", script)
        # 上限を渡せること、下限より短くはならないこと
        self.assertIn("sleep 90", host_mod.script_text(max_seconds=90))
        self.assertIn(
            f"sleep {host_mod.SCRIPT_MIN_SECONDS}", host_mod.script_text(max_seconds=1)
        )

    def test_watchdog_is_stopped_before_the_sentinel(self) -> None:
        """正常終了時はウォッチドッグを止めてから番兵を出すこと（取り残さない）。"""
        lines = host_mod.build_script()
        kill_at = max(i for i, l in enumerate(lines) if "AWSPROBE_WATCHDOG\"" in l)
        end_at = max(
            i for i, l in enumerate(lines)
            if host_mod.DELIM_FORMAT.format(name=host_mod.END_SENTINEL) in l
        )
        self.assertLess(kill_at, end_at)

    def test_du_is_skipped_without_timeout_command(self) -> None:
        """`timeout` が無い環境では `du` を実行しないこと。

        以前は `else` 節で **上限の無い `du -x /`** が走っていた。
        awsprobe が待つのをやめても、本番サーバー上では root のまま走り続ける。
        """
        command = host_mod.PROBES_BY_NAME["disk_usage"].command
        # `else` 以降（timeout が無い場合の分岐）に du が現れないこと
        fallback = command.split("else", 1)[1]
        self.assertNotIn("du ", fallback)
        self.assertIn("timeout コマンドが無いため", fallback)
        # timeout がある場合も 30 秒・対象ディレクトリ限定
        self.assertIn("timeout 30 du", command)
        self.assertNotIn("--max-depth=1 / ", command)

    def test_cron_user_scan_is_capped(self) -> None:
        """`cron_jobs` のユーザー走査がローカル定義かつ 50 件で打ち切られること。"""
        command = host_mod.PROBES_BY_NAME["cron_jobs"].command
        self.assertIn("/etc/passwd", command)
        self.assertIn("head -50", command)
        # LDAP/AD を引く getent passwd でユーザーを列挙していないこと
        self.assertNotIn("for u in $(getent passwd", command)

    def test_every_probe_output_is_capped(self) -> None:
        """各プローブの出力に `head -c` の上限が掛かっていること。"""
        script = host_mod.script_text()
        caps = script.count(f"| head -c {host_mod.PROBE_OUTPUT_LIMIT}")
        self.assertEqual(len(host_mod.PROBES), caps)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
