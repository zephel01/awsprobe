"""EC2 内部調査（host-probe）。

AWS API では原理的に取得できない「OS の中身」を、**読み取りだけ**で確認する。

解消したい未確認事項:

==========  ==========================================================
設問        内容
==========  ==========================================================
Q9          各 EC2 の ``~/.ssh/authorized_keys`` に誰の鍵が入っているか
Q14         OS とミドルウェアのバージョン・EOL
Q36         ベンダー製監視エージェント ``vendor-agent`` の常駐実態
Q31         cron の定義（本番2台での二重実行防止）
Q7          EFS のマウント状況
Q32         アプリのデプロイ先が Laravel かどうか
==========  ==========================================================

安全設計（この順番で多層防御している）:

1. **コマンドは固定**。:data:`PROBES` はモジュール定数のタプルで、
   ユーザー入力からシェルコマンドを組み立てる経路は存在しない。
2. **ガードで既定拒否**。``ssm:SendCommand`` は :mod:`awsprobe.guard` の
   ``SSM_COMMAND_OPERATIONS`` に入っており、``allow_ssm_command=True``
   （CLI の ``--enable-ssm``）でなければ boto3 の before-call で弾かれる。
   本モジュールは False のとき **SendCommand を試みずに** ``method="manual"``
   を返す（ガードに例外を投げさせない）。
3. **実行前に全文を提示**。:func:`render_plan` が送信するスクリプト全文と
   対象インスタンスを表示し、``confirm=True``（CLI の ``--yes``）でなければ
   送信しない。
4. **回収後にマスク**。:func:`mask_secrets` で公開鍵本体・秘密鍵 PEM・
   アクセスキー・パスワードらしき文字列を正規表現で落とす。

**このモジュールが絶対にやらないこと**（プローブを追加する際も厳守）:

- 秘密鍵、``authorized_keys`` の**鍵本体**、``.env`` の中身、
  設定ファイル内の認証情報を**読まない**
  （``authorized_keys`` は行数・コメント欄・指紋・mtime のみ。
  ``.env`` は**存在と mtime のみ**でパスしか出さない）
- ``/var/log`` の**中身を読まない**（個人情報が入りうる）
- アプリのソースコードやデータベースの中身を**読まない**
- 書き込み・インストール・サービス再起動を**一切行わない**
  （``systemctl`` は ``list-units`` のみ、``sshd -T`` は設定の表示のみで
  デーモンを起動しない、``crontab`` は必ず ``-l`` かつ標準入力を
  ``/dev/null`` に固定して**誤って crontab を上書きしない**ようにする）

標準ライブラリと boto3 のみを使う。boto3 は直接 import せず、
必ず ``ctx.client("ssm")`` / ``ctx.call`` 経由で呼ぶ。
"""
from __future__ import annotations

import datetime as _dt
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .collectors._safe import safe_call, safe_paginate
from .session import Context

# ---------------------------------------------------------------------------
# 基本定数
# ---------------------------------------------------------------------------

#: プローブ出力の区切り。SSM の stdout と手動実行のテキストで共通。
DELIM_FORMAT = "===== PROBE:{name} ====="
#: 区切り行を認識する正規表現（前後の空白は許容する）。
DELIM_RE = re.compile(r"^=====\s*PROBE:([A-Za-z0-9_]+)\s*=====\s*$")

#: スクリプト末尾に出す番兵の名前。**これが出力に無ければ打ち切られている。**
END_SENTINEL = "__end__"
#: 番兵として認める名前。``end`` は旧版のスクリプト・既存の手動採取結果との互換用。
END_SENTINEL_NAMES = (END_SENTINEL, "end")

#: ``GetCommandInvocation.StandardOutputContent`` が返す stdout の上限（AWS 仕様）。
#: これを超えた分は **黙って捨てられる**（切り詰めた旨の印も付かない）。
SSM_STDOUT_LIMIT = 24000
#: 1 プローブあたりの出力上限（バイト）。各プローブの末尾に `head -c` を掛ける。
PROBE_OUTPUT_LIMIT = 1500
#: 1 回の SendCommand に載せるプローブ数。
#: 16 プローブ × 1,500 バイトは 24,000 字に届いてしまうため、
#: 複数回に分けて送り、**バッチごとに 24,000 字の枠を使う**。
PROBES_PER_BATCH = 6
#: 最初のバッチの先頭に必ず置くプローブ。
#: Q9（ベンダー鍵の棚卸し）は host-probe の主目的であり、
#: 万一打ち切られても残るように最優先で流す。
PRIORITY_PROBE_NAMES = ("authorized_keys",)

#: ホスト側スクリプトの実行時間の上限（秒）。
#: SendCommand の ``TimeoutSeconds`` は **配信** のタイムアウトであって
#: 実行時間の上限ではない。awsprobe が待つのをやめても、コマンドは本番
#: サーバー上で root として走り続ける（`ssm:CancelCommand` はガードに
#: 弾かれて呼べない）。そのため **スクリプト自身に自己終了の仕掛けを持たせる**。
SCRIPT_MAX_SECONDS = 240
#: ウォッチドッグの下限（短すぎると正常な採取まで殺してしまう）。
SCRIPT_MIN_SECONDS = 60

#: インスタンス ID の形式。これ以外は一切 API に渡さない。
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")

#: SSM RunCommand で使うドキュメント（AWS 管理の固定ドキュメント）。
SSM_DOCUMENT = "AWS-RunShellScript"

#: GetCommandInvocation をポーリングする間隔（秒）と最大回数。
POLL_INTERVAL = 3.0
MAX_POLLS = 60

#: SendCommand の TimeoutSeconds の下限（AWS 仕様）。
_SSM_MIN_TIMEOUT = 30

#: 終端とみなす Command Invocation の Status。
_TERMINAL_STATUSES = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}


# ---------------------------------------------------------------------------
# プローブ定義
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Probe:
    """1 つの調査項目。

    Attributes:
        name: プローブ名（区切り行と結果 dict のキーになる。``[a-z0-9_]+``）。
        title: 日本語の表題（手順書と計画表示に出る）。
        command: 実行する読み取り専用のシェルコマンド（1 項目 1 文字列）。
        answers: 解消する設問 ID のタプル。例 ``("Q14",)``
        why: 何のために取るか（日本語1文）。
    """

    name: str
    title: str
    command: str
    answers: tuple[str, ...]
    why: str


# 注意: 以下のコマンドは **すべて読み取り専用**でなければならない。
# tests/test_host.py が書き込み系コマンド（rm / mv / chmod / chown /
# systemctl start|stop|restart / yum install / apt install / curl / wget /
# 出力リダイレクト）を正規表現で検査しており、違反すると CI が落ちる。
# 例外的に許可しているのは `2>/dev/null` `>/dev/null` `2>&1` `</dev/null`
# の 4 つだけ（いずれもファイルを作らない）。
PROBES: tuple[Probe, ...] = (
    Probe(
        name="os_release",
        title="OS 種別とバージョン",
        command="cat /etc/os-release 2>/dev/null; uname -a 2>/dev/null",
        answers=("Q14",),
        why="OS ディストリビューションとカーネル版数を確定し、EOL 判定の土台にするため。",
    ),
    Probe(
        name="os_eol_hint",
        title="OS サポート期限の手掛かり",
        command=(
            "cat /etc/system-release 2>/dev/null; "
            "hostnamectl 2>/dev/null | head -20; "
            "cat /etc/debian_version 2>/dev/null"
        ),
        answers=("Q14",),
        why="Amazon Linux 2 / 2023 など、os-release だけでは分からない世代を特定するため。",
    ),
    Probe(
        name="packages",
        title="ミドルウェアのパッケージ版数",
        # 全パッケージ一覧は数千行になるため、関心のある 7 種に grep で絞る。
        command=(
            "if command -v rpm >/dev/null 2>&1; then "
            "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null "
            "| grep -Ei '^(nginx|php|httpd|mysql|mariadb|golang|go|nodejs|node|postfix)' "
            "| sort; "
            "elif command -v dpkg-query >/dev/null 2>&1; then "
            "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null "
            "| grep -Ei '^(nginx|php|apache2|httpd|mysql|mariadb|golang|go|nodejs|node|postfix)' "
            "| sort; "
            "else echo '(rpm / dpkg のどちらも見つかりません)'; fi"
        ),
        answers=("Q14",),
        why="nginx / php / httpd / mysql / go / node / postfix の実バージョンを押さえ、EOL を判定するため。",
    ),
    Probe(
        name="runtime_versions",
        title="ランタイムの実行バージョン",
        # パッケージ管理外（tarball 配置やバージョン管理ツール）の実体を拾う。
        # 未導入でも落ちないよう command -v で存在確認してから実行する。
        command=(
            "for c in nginx php httpd mysql node npm python3; do "
            "if command -v \"$c\" >/dev/null 2>&1; then "
            "printf '%s: ' \"$c\"; "
            "{ \"$c\" --version 2>&1 || \"$c\" -v 2>&1; } | head -2; "
            "else printf '%s: (未導入)\\n' \"$c\"; fi; done; "
            "if command -v go >/dev/null 2>&1; then go version 2>&1; "
            "else echo 'go: (未導入)'; fi"
        ),
        answers=("Q14",),
        why="パッケージ管理に載っていないランタイムも含め、実際に動いている版数を確認するため。",
    ),
    Probe(
        name="listening_ports",
        title="待ち受けポートとプロセス",
        command=(
            "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null "
            "|| echo '(ss / netstat のどちらも見つかりません)'"
        ),
        answers=("Q14", "Q36"),
        why="どのプロセスがどのポートを持っているかを把握し、構成図と実機の差分を見るため。",
    ),
    Probe(
        name="processes",
        title="常駐プロセス（監視エージェント・Web・cron）",
        # ps auxww の全量はコマンドライン引数に認証情報が乗る恐れがあるため取らない。
        # 関心のある名前に絞ってから出す。
        command=(
            "ps auxww 2>/dev/null "
            "| grep -Ei 'vendor|agent|nginx|php-fpm|node|cron' "
            "| grep -vw grep | head -60"
        ),
        answers=("Q36",),
        why="ベンダー製監視エージェントが実際に常駐しているかを確認するため（Q36 の中核）。",
    ),
    Probe(
        name="vendor_agent_files",
        title="vendor-agent 関連ファイルの所在（パスのみ）",
        # **中身は読まない。** パスとサイズと更新日時だけを出す。
        command=(
            "find /opt /usr/local /etc /lib/systemd/system /etc/systemd/system "
            "-maxdepth 4 -iname '*vendor-agent*' 2>/dev/null | head -100; "
            "echo '--- systemd unit files'; "
            "systemctl list-unit-files --no-pager --no-legend 2>/dev/null "
            "| grep -Ei 'vendor|agent' | head -20"
        ),
        answers=("Q36",),
        why="vendor-agent の導入先ディレクトリと systemd ユニットの所在を特定するため（設定内容は開示要求の対象）。",
    ),
    Probe(
        name="systemd_units",
        title="稼働中の systemd サービス",
        command=(
            "systemctl list-units --type=service --state=running "
            "--no-pager --no-legend 2>/dev/null | head -80 "
            "|| echo '(systemd ではない、または権限がありません)'"
        ),
        answers=("Q14", "Q36"),
        why="常駐サービスの一覧から、AWS 標準以外の第三者エージェントの有無を見るため。",
    ),
    Probe(
        name="cron_jobs",
        title="cron の定義（システム・ユーザー）",
        # crontab は **必ず -l を付け、標準入力を /dev/null に固定する**。
        # -l を落とすと標準入力を読んで crontab を「上書き」してしまうため、
        # SSH で `bash -s` に流す使い方でも事故が起きないようにしている。
        command=(
            "echo '--- /etc/crontab'; cat /etc/crontab 2>/dev/null; "
            "echo '--- /etc/cron.d'; ls -la /etc/cron.d/ 2>/dev/null; "
            "for f in /etc/cron.d/*; do "
            "if [ -f \"$f\" ]; then echo \"--- $f\"; cat \"$f\" 2>/dev/null; fi; done; "
            "echo '--- cron.hourly / daily / weekly'; "
            "ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly 2>/dev/null; "
            "echo '--- user crontabs'; "
            # **ユーザー走査には必ず上限を掛ける（I-8）。**
            # `getent passwd` は LDAP / AD / SSSD 参加ホストで数千件返り、
            # そのぶん `crontab -l -u` のプロセスが起動して本番サーバーに
            # 負荷を掛ける。ローカル定義（/etc/passwd）のユーザーに絞り、
            # さらに先頭 50 件で打ち切る。
            "printf '（/etc/passwd のローカルユーザー %s 名中、先頭50名のみ走査）\\n' "
            "\"$(awk -F: 'END {print NR}' /etc/passwd 2>/dev/null)\"; "
            "for u in $(awk -F: '{print $1}' /etc/passwd 2>/dev/null | head -50); do "
            "out=$(crontab -l -u \"$u\" </dev/null 2>/dev/null); "
            "if [ -n \"$out\" ]; then echo \"--- user cron: $u\"; echo \"$out\"; fi; done; "
            "echo '--- systemd timers'; "
            "systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -20"
        ),
        answers=("Q31",),
        why="本番2台でバッチが二重実行されないための仕掛け（片系のみ定義／排他制御）を確認するため。",
    ),
    Probe(
        name="authorized_keys",
        title="authorized_keys の実測（鍵本体は出さない）",
        # ★最重要かつ最も慎重を要するプローブ。
        # 出すのは「行数 / コメント欄 / 指紋 / mtime / パーミッション」だけで、
        # **鍵本体（base64 部分）は絶対に出力しない。**
        # awk は鍵種別トークンの位置を特定し、その次のフィールド（＝鍵本体）を
        # 飛ばしてコメント欄だけを出す。options 付きの行でも本体が漏れない。
        # さらに回収後に mask_secrets() を通す二重防御になっている。
        command=(
            # ホームディレクトリの走査にも上限を掛ける（I-8 と同じ理由）。
            # LDAP 参加ホストでは `getent passwd` が数千件返りうるため 50 件で打ち切る。
            "for h in $(getent passwd 2>/dev/null | awk -F: '{print $6}' "
            "| sort -u | head -50) /root; do "
            "f=\"$h/.ssh/authorized_keys\"; "
            "if [ -f \"$f\" ]; then "
            "echo \"--- $f\"; "
            "stat -c '    perm=%a owner=%U group=%G mtime=%y' \"$f\" 2>/dev/null; "
            "printf '    lines=%s\\n' \"$(grep -c '[^[:space:]]' \"$f\" 2>/dev/null)\"; "
            "echo '    comments:'; "
            "awk '{ t=0; "
            "for (i=1;i<=NF;i++) "
            "if ($i ~ /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-[A-Za-z0-9-]+|sk-[A-Za-z0-9.@-]+)$/) "
            "{ t=i; break } "
            "if (t==0) { print \"      - (鍵行として解析できない行)\"; next } "
            "c=\"\"; for (i=t+2;i<=NF;i++) c=c\" \"$i; "
            "if (c==\"\") c=\" (コメント欄なし)\"; "
            "print \"      - [\" $t \"]\" c }' \"$f\" 2>/dev/null; "
            "echo '    fingerprints:'; "
            "ssh-keygen -lf \"$f\" 2>/dev/null "
            "| awk '{ print \"      - \" $1 \" \" $2 \" \" $NF }'; "
            "fi; done"
        ),
        answers=("Q9",),
        why="切離し時にベンダーの鍵が残らないよう、鍵の本数・ラベル・指紋を控えて保有者と突合するため。",
    ),
    Probe(
        name="sshd_config",
        title="sshd の実効設定",
        # `sshd -T` は設定の妥当性検査＋実効値表示モード。デーモンは起動しない。
        command=(
            "{ sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null; } "
            "| grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication"
            "|allowusers|allowgroups|port|kbdinteractiveauthentication"
            "|challengeresponseauthentication|permitemptypasswords)' "
            "|| grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication"
            "|PubkeyAuthentication|AllowUsers|AllowGroups|Port|PermitEmptyPasswords)' "
            "/etc/ssh/sshd_config 2>/dev/null"
        ),
        answers=("Q9",),
        why="パスワード認証や root 直ログインが開いていないかを確認し、鍵の棚卸しと併せて評価するため。",
    ),
    Probe(
        name="users",
        title="ログイン可能なユーザーと特権グループ",
        # getent passwd はパスワードハッシュを含まない（shadow は参照しない）。
        # シェルが `sh` で終わるものだけを残す（bash/zsh/sh/ksh/csh/fish）。
        # nologin / false / 各種デーモン用アカウントはこれで落ちる。
        command=(
            "getent passwd "
            "| awk -F: '$7 ~ /sh$/ "
            "{ printf \"%s uid=%s gid=%s home=%s shell=%s\\n\", $1,$3,$4,$6,$7 }'; "
            "echo '--- 特権グループ'; getent group wheel sudo adm 2>/dev/null; "
            "echo '--- sudoers.d のファイル名のみ'; ls -la /etc/sudoers.d/ 2>/dev/null"
        ),
        answers=("Q9",),
        why="鍵の持ち主候補となるローカルユーザーと特権付与の実態を把握するため。",
    ),
    Probe(
        name="mounts",
        title="ファイルシステムと EFS/NFS マウント",
        command=(
            "df -hT 2>/dev/null; "
            "echo '--- nfs / efs マウント'; mount 2>/dev/null | grep -Ei 'nfs|efs'; "
            "echo '--- fstab の nfs/efs 行'; "
            "grep -Ei 'efs|nfs' /etc/fstab 2>/dev/null"
        ),
        answers=("Q7",),
        why="EFS が実際にどのパスへどのオプションでマウントされているかを確定するため。",
    ),
    Probe(
        name="disk_usage",
        title="ディスク使用量と大きいディレクトリ",
        # **`du` には必ず時間の上限を掛ける（I-8）。**
        # 以前は `timeout` が無い環境で `else` 節が **無制限の du -x /** を
        # 走らせていた。awsprobe 側が待つのをやめても本番サーバー上では
        # root のまま走り続けるため、`timeout` が無ければ **du は実行しない**。
        # 対象も `/` 全体ではなくアプリのデプロイ先候補に限定し、上限は 30 秒。
        command=(
            "df -h 2>/dev/null; "
            "echo '--- 使用量の大きいディレクトリ（上位20）'; "
            "if command -v timeout >/dev/null 2>&1; then "
            "timeout 30 du -xh --max-depth=1 "
            "/var /opt /srv /home /usr/local /tmp 2>/dev/null "
            "| sort -rh | head -20; "
            "else echo '(timeout コマンドが無いため、ディスク使用量の詳細は採取しませんでした"
            "／df の結果のみ)'; fi"
        ),
        answers=("Q7", "Q14"),
        why="容量逼迫の有無と、移行時にコピーが必要なデータの所在・規模を見積もるため。",
    ),
    Probe(
        name="app_layout",
        title="アプリのデプロイ先の構造（中身は読まない）",
        # ディレクトリ構造と目印ファイルの **存在・サイズ・mtime のみ**。
        # composer.json / package.json / .env の **中身は絶対に読まない**。
        command=(
            "for d in /var/www /var/www/html /usr/share/nginx/html /opt/app /opt/code "
            "/srv /var/app; do "
            "if [ -d \"$d\" ]; then echo \"--- $d\"; "
            "ls -la \"$d\" 2>/dev/null | head -40; fi; done; "
            "echo '--- 目印ファイル（存在と mtime のみ / 中身は読まない）'; "
            "find /var/www /opt /srv /home -maxdepth 4 "
            "\\( -name node_modules -o -name vendor -o -name .git -o -name .cache \\) -prune "
            "-o \\( -name composer.json -o -name package.json -o -name artisan "
            "-o -name go.mod -o -name .env \\) "
            "-printf '%TY-%Tm-%Td %TH:%TM %10s %p\\n' 2>/dev/null | head -40"
        ),
        answers=("Q32",),
        why="`code` が Laravel かどうか（artisan / composer.json の有無）と、.env の所在を中身を見ずに判定するため。",
    ),
    Probe(
        name="time_sync",
        title="時刻同期の状態",
        command=(
            "timedatectl 2>/dev/null; "
            "echo '--- chrony'; chronyc sources 2>/dev/null | head -10; "
            "echo '--- ntpstat'; ntpstat 2>/dev/null"
        ),
        answers=("Q31",),
        why="cron の実行時刻とログの時刻が信頼できるか（NTP 同期の有無）を確認するため。",
    ),
)

#: プローブ名 → Probe の索引。
PROBES_BY_NAME: dict[str, Probe] = {p.name: p for p in PROBES}


# ---------------------------------------------------------------------------
# 出力マスキング（二重防御）
# ---------------------------------------------------------------------------

#: 公開鍵本体（`ssh-rsa AAAA...`）。鍵種別は残し、base64 部分だけ落とす。
_PUBKEY_RE = re.compile(
    r"\b(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-[A-Za-z0-9-]+|sk-[A-Za-z0-9.@-]+)"
    r"(\s+)([A-Za-z0-9+/]{20,}={0,3})"
)
#: 鍵種別が取れていなくても、長い base64 塊は落とす（AAAA で始まる SSH 鍵の本体）。
_BARE_BLOB_RE = re.compile(r"\bAAAA[A-Za-z0-9+/]{16,}={0,3}")
#: PEM 形式の秘密鍵ブロック。万が一混ざったら丸ごと落とす。
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
#: AWS アクセスキー ID。
_AKID_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b")
#: `DB_PASSWORD=...` / `token: ...` のような代入形式。値だけを落とす。
#: `DB_` のような接頭辞も拾えるよう単語境界ではなく文字クラスで前後を取る。
#: `/etc/passwd` のようなパス名は `(?<!/)` で除外する。
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)(?<!/)([A-Za-z0-9_.-]*"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential)"
    r"[A-Za-z0-9_.-]*)(\s*[=:]\s*)(\S+)"
)

MASK_LABEL = "＜マスク済み＞"
PUBKEY_MASK_LABEL = "＜公開鍵本体マスク済み＞"


def mask_secrets(text: str) -> str:
    """プローブ出力から機微な文字列を落とす（回収後に必ず通す）。

    プローブのコマンド自体が鍵本体を出さない作りになっているが、
    想定外の行（``command="..."`` 付きの authorized_keys など）で
    漏れることを防ぐための**二重防御**。

    Args:
        text: プローブの標準出力／標準エラー。

    Returns:
        マスク済みの文字列。``None`` や非文字列は空文字にする。
    """
    if not isinstance(text, str) or not text:
        return "" if text is None else str(text or "")
    out = _PEM_RE.sub(f"-----BEGIN PRIVATE KEY-----{MASK_LABEL}-----END PRIVATE KEY-----", text)
    out = _PUBKEY_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{PUBKEY_MASK_LABEL}", out)
    out = _BARE_BLOB_RE.sub(PUBKEY_MASK_LABEL, out)
    out = _AKID_RE.sub(MASK_LABEL, out)
    out = _SECRET_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK_LABEL}", out)
    return out


# ---------------------------------------------------------------------------
# 入力の検証とスクリプト組み立て
# ---------------------------------------------------------------------------


def valid_instance_id(instance_id: Any) -> bool:
    """``i-0123456789abcdef0`` 形式かどうか。"""
    return isinstance(instance_id, str) and bool(INSTANCE_ID_RE.match(instance_id))


def validate_instance_ids(instance_ids: Iterable[Any]) -> list[str]:
    """インスタンス ID を検証して重複を除いた一覧を返す。

    Raises:
        ValueError: 形式に合わないものが 1 つでも含まれる場合。
                    （不正な値を握り潰して API に渡さないため、ここは例外にする）
    """
    out: list[str] = []
    bad: list[str] = []
    for raw in instance_ids or []:
        if valid_instance_id(raw):
            if raw not in out:
                out.append(raw)
        else:
            bad.append(repr(raw))
    if bad:
        raise ValueError(
            "インスタンス ID の形式が不正です（^i-[0-9a-f]{8,17}$ のみ許可）: " + ", ".join(bad)
        )
    return out


def resolve_probes(probes: Sequence[str] | Sequence[Probe] | None) -> tuple[Probe, ...]:
    """プローブ指定を :data:`PROBES` の要素へ解決する。

    **名前による選択しかできない。** 外部から任意のコマンドを持つ Probe を
    渡されても採用しない（固定ホワイトリスト外は ValueError）。
    """
    if probes is None:
        return PROBES
    out: list[Probe] = []
    for item in probes:
        name = item.name if isinstance(item, Probe) else str(item)
        probe = PROBES_BY_NAME.get(name)
        if probe is None:
            raise ValueError(
                f"未知のプローブ名です: {name!r}（許可されているのは "
                + ", ".join(PROBES_BY_NAME) + "）"
            )
        if isinstance(item, Probe) and item is not probe:
            raise ValueError(
                f"プローブ {name!r} の定義が PROBES と異なります。"
                "コマンドは固定であり、外部から差し替えられません。"
            )
        if probe not in out:
            out.append(probe)
    return tuple(out)


def order_probes(probes: Sequence[Probe] | None = None) -> tuple[Probe, ...]:
    """送信順にプローブを並べ替える。

    :data:`PRIORITY_PROBE_NAMES`（既定では ``authorized_keys``）を先頭に出す。
    Q9 はベンダー鍵の棚卸しで host-probe の主目的なので、
    **万一出力が打ち切られても残るように最初に流す**。
    :data:`PROBES` の定義そのものは並べ替えない（件数・内容は不変）。
    """
    selected = tuple(probes) if probes else PROBES
    head = [p for p in selected if p.name in PRIORITY_PROBE_NAMES]
    tail = [p for p in selected if p.name not in PRIORITY_PROBE_NAMES]
    return tuple(head + tail)


def build_batches(
    probes: Sequence[Probe] | None = None, size: int = PROBES_PER_BATCH
) -> tuple[tuple[Probe, ...], ...]:
    """プローブを SendCommand 1 回分ずつのバッチに分ける。

    ``GetCommandInvocation.StandardOutputContent`` は :data:`SSM_STDOUT_LIMIT`
    文字で打ち切られ、**超えた分は何の印も無く消える**。16 プローブを 1 本の
    スクリプトで流すと、前半の ``vendor_agent_files`` / ``systemd_units`` /
    ``cron_jobs`` だけで上限に達し、``authorized_keys`` 以降が丸ごと
    欠落しうる（I-7）。バッチごとに 24,000 字の枠を使えるよう分割する。

    ``--probes`` で絞り込まれたときは、そのぶんだけを分割して返す。
    """
    ordered = order_probes(probes)
    if not ordered:
        return ()
    step = max(1, int(size))
    return tuple(
        tuple(ordered[i : i + step]) for i in range(0, len(ordered), step)
    )


def build_script(
    probes: Sequence[Probe] | None = None, *, max_seconds: int = SCRIPT_MAX_SECONDS
) -> list[str]:
    """プローブを 1 本のシェルスクリプトにまとめて行のリストで返す。

    プローブごとに ``===== PROBE:<name> =====`` を挟んで連結し、
    末尾に番兵 ``===== PROBE:__end__ =====`` を出す。

    安全のための仕掛けが 2 つ入っている:

    1. **自己終了のウォッチドッグ**（I-8）。``SendCommand`` の
       ``TimeoutSeconds`` は配信のタイムアウトであって実行時間の上限ではなく、
       awsprobe が待つのをやめてもコマンドは本番サーバー上で走り続ける。
       スクリプト自身が ``max_seconds`` 後に自分へ SIGTERM を送って止まる。
    2. **プローブごとの出力上限**（I-7）。各プローブの出力を
       :data:`PROBE_OUTPUT_LIMIT` バイトで打ち切り、stdout 全体が
       SSM の 24,000 字上限に達しないようにする。

    ``sh`` / ``bash`` / ``dash`` のいずれでも構文が通る書き方にしてある
    （``tests/test_host.py`` が ``-n`` で検査する）。
    """
    selected = tuple(probes) if probes else PROBES
    limit = max(SCRIPT_MIN_SECONDS, int(max_seconds))
    lines: list[str] = [
        "# awsprobe host-probe: 読み取り専用の内部調査スクリプト（自動生成・編集不可）",
        "# 書き込み・インストール・サービス操作は一切行わない。",
        "set +e",
        "export LC_ALL=C",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "export PATH",
        "",
        f"# --- 自己終了のウォッチドッグ（最長 {limit} 秒） ---",
        "# $$ はこのスクリプト自身の PID。サブシェル内で $$ を書くと",
        "# 「親シェルの PID」という紛らわしい仕様に頼ることになるため、",
        "# 先に変数へ退避してから参照する。",
        "AWSPROBE_MAIN_PID=$$",
        "AWSPROBE_MAIN_PGID=$(ps -o pgid= -p \"$AWSPROBE_MAIN_PID\" 2>/dev/null | tr -d ' ')",
        "(",
        f"  sleep {limit}",
        "  # bash は前面ジョブの実行中に受けた SIGTERM を、その子プロセスが",
        "  # 終わるまで処理しない。シェルだけに送っても長い du 等は止まらないので、",
        "  # **自分がプロセスグループのリーダーのときだけ** グループごと止める。",
        "  # リーダーでなければ他人のグループを巻き込む恐れがあるため、",
        "  # シェル本体と自分の直下の子プロセスだけに送る。",
        "  if [ -n \"$AWSPROBE_MAIN_PGID\" ] "
        "&& [ \"$AWSPROBE_MAIN_PGID\" = \"$AWSPROBE_MAIN_PID\" ]; then",
        "    kill -TERM \"-$AWSPROBE_MAIN_PGID\"",
        "  else",
        "    kill -TERM \"$AWSPROBE_MAIN_PID\"",
        "    for awsprobe_child in "
        "$(ps -o pid= --ppid \"$AWSPROBE_MAIN_PID\" 2>/dev/null); do",
        "      kill -TERM \"$awsprobe_child\"",
        "    done",
        "  fi",
        ") >/dev/null 2>&1 &",
        "AWSPROBE_WATCHDOG=$!",
        "",
    ]
    for probe in selected:
        lines.append(f"printf '%s\\n' '{DELIM_FORMAT.format(name=probe.name)}'")
        # head -c は途中で切れると行末の改行が落ちるため、必ず改行を足す
        # （次の区切り行が同じ行に続いてしまうとパースできなくなる）。
        lines.append(
            f"{{ {probe.command} ; }} 2>&1 | head -c {PROBE_OUTPUT_LIMIT}; printf '\\n'"
        )
    lines.append("")
    lines.append("# --- ウォッチドッグを止めてから番兵を出す ---")
    lines.append("kill \"$AWSPROBE_WATCHDOG\" >/dev/null 2>&1")
    lines.append(f"printf '%s\\n' '{DELIM_FORMAT.format(name=END_SENTINEL)}'")
    return lines


def script_text(
    probes: Sequence[Probe] | None = None, *, max_seconds: int = SCRIPT_MAX_SECONDS
) -> str:
    """:func:`build_script` の結果を 1 つの文字列にする。"""
    return "\n".join(build_script(probes, max_seconds=max_seconds))


def output_is_complete(text: str) -> bool:
    """出力の末尾に番兵があるか（＝打ち切られていないか）。"""
    for line in (text or "").splitlines():
        matched = DELIM_RE.match(line)
        if matched and matched.group(1) in END_SENTINEL_NAMES:
            return True
    return False


#: 打ち切りを検出したときに結果 dict へ立てる印（``_stderr`` と同じ扱いの meta キー）。
TRUNCATION_KEY = "_truncated"


def parse_probe_output(text: str, probes: Sequence[Probe] | None = None) -> dict[str, dict]:
    """``===== PROBE:<name> =====`` 区切りの出力をプローブ名ごとに分解する。

    Args:
        text: SSM の stdout、または手動採取したテキスト。
        probes: 実行したはずのプローブ。渡すと **番兵の欠如から打ち切りを
            検出**し、取れなかったプローブを ``status="Truncated"`` として
            明示する（I-7）。``None`` のときは打ち切り判定を行わない。

    Returns:
        ``{probe_name: {"status": ..., "stdout": ..., "stderr": ""}}``。
        stdout は必ず :func:`mask_secrets` を通したものになる。
        打ち切られていた場合は :data:`TRUNCATION_KEY` のエントリが増える。
    """
    buckets: dict[str, list[str]] = {}
    order: list[str] = []
    current: str | None = None
    for line in (text or "").splitlines():
        matched = DELIM_RE.match(line)
        if matched:
            name = matched.group(1)
            if name in END_SENTINEL_NAMES:  # build_script が末尾に置く番兵
                current = None
                continue
            current = name
            if name not in buckets:
                buckets[name] = []
                order.append(name)
            continue
        if current is not None:
            if current not in buckets:
                buckets[current] = []
                order.append(current)
            buckets[current].append(line)

    complete = output_is_complete(text)

    results: dict[str, dict] = {}
    for name, body in buckets.items():
        stdout = mask_secrets("\n".join(body).strip())
        results[name] = {
            "status": "Success" if stdout else "Empty",
            "stdout": stdout,
            "stderr": "",
        }

    if probes is None:
        return results

    # 番兵が無い＝ SSM の 24,000 字上限で切られている。
    # 「出力が空だった」と「そもそも届かなかった」を区別できるようにする。
    missing = [p.name for p in probes if p.name not in results]
    if not complete:
        # 最後に現れたプローブの本文も途中で切れている可能性が高い。
        if order:
            last = order[-1]
            results[last]["status"] = "PartiallyTruncated"
        for name in missing:
            results[name] = {"status": "Truncated", "stdout": "", "stderr": ""}
        results[TRUNCATION_KEY] = {
            "status": "Truncated",
            "stdout": (
                f"出力が打ち切られている（末尾の番兵 "
                f"'{DELIM_FORMAT.format(name=END_SENTINEL)}' が無い）。"
                f"SSM の StandardOutputContent は {SSM_STDOUT_LIMIT} 文字で切られる。"
                + (f"取得できなかったプローブ: {', '.join(missing)}" if missing else "")
            ),
            "stderr": "",
        }
    else:
        for name in missing:
            results[name] = {"status": "NoOutput", "stdout": "", "stderr": ""}
    return results


# ---------------------------------------------------------------------------
# 実行前の計画表示
# ---------------------------------------------------------------------------


def render_plan(instance_ids: Sequence[str], probes: Sequence[Probe] | None = None) -> str:
    """SendCommand を発行する前に表示する内容（対象一覧＋スクリプト全文）。

    CLI はこれを標準出力に出し、``--yes``（confirm=True）が無ければ送信しない。
    """
    selected = tuple(probes) if probes else PROBES
    lines = [
        "=" * 72,
        "awsprobe host-probe 実行計画（読み取り専用）",
        "=" * 72,
        "",
        f"対象インスタンス: {len(instance_ids)} 台",
    ]
    for iid in instance_ids:
        lines.append(f"  - {iid}")
    if not instance_ids:
        lines.append("  （SSM 到達可能なインスタンスがありません）")
    lines.append("")
    lines.append(f"実行するプローブ: {len(selected)} 件")
    for probe in selected:
        answers = ", ".join(probe.answers) or "—"
        lines.append(f"  - {probe.name:<18} [{answers}] {probe.title}")
    lines.append("")
    batches = build_batches(selected)
    lines.append(
        f"送信回数: インスタンス 1 台につき {len(batches)} 回"
        f"（SSM の stdout は {SSM_STDOUT_LIMIT} 文字で打ち切られるため分割して送ります）"
    )
    lines.append("")
    lines.append("送信するスクリプト全文:")
    lines.append("-" * 72)
    for index, batch in enumerate(batches, start=1):
        lines.append(
            f"--- バッチ {index}/{len(batches)}: "
            + ", ".join(p.name for p in batch)
        )
        lines.extend(build_script(batch))
        lines.append("")
    lines.append("-" * 72)
    lines.append("")
    lines.append(
        "このスクリプトは読み取りのみで、ファイルの作成・変更・削除、"
        "パッケージ導入、サービス操作を一切行いません。"
    )
    lines.append(
        f"実行時間には上限（既定 {SCRIPT_MAX_SECONDS} 秒）を掛けており、"
        "超えた場合はスクリプト自身が停止します。"
    )
    lines.append("実行するには --yes を付けて再実行してください。")
    lines.append("=" * 72)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SSM 到達性とその原因診断
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def reachable_instances(ctx: Context) -> list[dict]:
    """``ssm:DescribeInstanceInformation`` で SSM 管理下のインスタンスを取る。

    ``Describe`` 接頭辞なのでガードは常に通す。moto のように未実装の環境でも
    ``safe_paginate`` が空リストを返すため落ちない。
    """
    return safe_paginate(
        ctx,
        "ssm",
        "describe_instance_information",
        "InstanceInformationList",
        context="host-probe: SSM 到達性の判定",
    )


def online_instance_ids(managed: Sequence[dict]) -> list[str]:
    """``PingStatus == "Online"`` かつ ID 形式が正しいものだけを返す。"""
    out: list[str] = []
    for item in managed or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("PingStatus") or "") != "Online":
            continue
        iid = item.get("InstanceId")
        if valid_instance_id(iid) and iid not in out:
            out.append(iid)
    return out


#: SSM が使えない原因の分類。
CAUSE_NOT_ENABLED = "--enable-ssm 未指定"
CAUSE_NO_PERMISSION = "権限不足"
CAUSE_NO_ROLE = "IAM ロール未付与"
CAUSE_NO_ENDPOINT = "VPC エンドポイント未設定"
CAUSE_NO_AGENT = "SSM エージェント未導入または停止"
CAUSE_UNKNOWN = "原因不明"

_SSM_DENIED_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "AuthorizationError", "Forbidden",
}
_SSM_ENDPOINT_SERVICES = ("ssm", "ssmmessages", "ec2messages")

#: host-probe に必須の SSM オペレーション（boto3 のメソッド名）。
#: これらが AccessDenied のときだけ「権限不足」と判定する。
_SSM_REQUIRED_OPERATIONS = {
    "describe_instance_information",
    "send_command",
    "get_command_invocation",
    "list_command_invocations",
}


def diagnose_ssm_unavailable(inventory: dict | None, *, allow_ssm_command: bool = True) -> dict:
    """SSM が使えない原因を inventory から自動判定する。

    判定の順序（先に当たったものを採用する）:

    1. ``allow_ssm_command`` が False → ``--enable-ssm 未指定``
       （これは環境の問題ではなく実行方法の問題なので最初に見る）
    2. ``errors`` に ssm の AccessDenied 系がある → ``権限不足``
    3. EC2 に ``IamInstanceProfile`` が無い → ``IAM ロール未付与``
       （SSM Agent が居ても認証情報が無いので必ず登録されない）
    4. ロールはあるが ``ssm_managed_instances`` に居ない。さらに
       サブネットに 0.0.0.0/0 の経路（IGW / NAT）が無く、
       ssm / ssmmessages / ec2messages の VPC エンドポイントも無い
       → ``VPC エンドポイント未設定``（経路が無いので Agent が繋がれない）
    5. 上記以外で登録されていない → ``SSM エージェント未導入または停止``
       （``PingStatus`` が ``ConnectionLost`` の場合もここ）

    Returns:
        ``{"cause": str, "detail": str, "evidence": [str], "per_instance": {...}}``
    """
    inv = inventory if isinstance(inventory, dict) else {}
    compute = inv.get("compute") if isinstance(inv.get("compute"), dict) else {}
    network = inv.get("network") if isinstance(inv.get("network"), dict) else {}
    errors = inv.get("errors") if isinstance(inv.get("errors"), list) else []

    instances = [i for i in (compute.get("instances") or []) if isinstance(i, dict)]
    managed = [m for m in (compute.get("ssm_managed_instances") or []) if isinstance(m, dict)]
    managed_by_id = {m.get("InstanceId"): m for m in managed}

    evidence: list[str] = []

    if not allow_ssm_command:
        # 環境側の状況（インスタンス別の到達性）は同じ手順で出せるので、
        # 許可されている前提で一度診断してから cause だけ差し替える。
        env = diagnose_ssm_unavailable(inv, allow_ssm_command=True)
        return {
            "cause": CAUSE_NOT_ENABLED,
            "detail": (
                "`ssm:SendCommand` は awsprobe の読み取り専用ガードで既定拒否されている。"
                "実行するには `--enable-ssm --yes` を明示的に付ける必要がある。"
                + ("　なお環境側にも別の課題がある: " + env["detail"] if env.get("cause") else "")
            ),
            "evidence": ["guard.allow_ssm_command=False"] + list(env.get("evidence") or []),
            "per_instance": env.get("per_instance") or {},
        }

    # host-probe に**実際に必要な**オペレーションの拒否だけを見る。
    # ssm:ListInventoryEntries などの補助 API が拒否されていても host-probe は動くため、
    # それを「権限不足」と結論づけない（誤診断の原因になる）。
    denied = [
        e for e in errors
        if isinstance(e, dict)
        and str(e.get("service")) == "ssm"
        and str(e.get("operation")) in _SSM_REQUIRED_OPERATIONS
        and str(e.get("code")) in _SSM_DENIED_CODES
    ]
    if denied:
        ops = sorted({str(e.get("operation")) for e in denied})
        return {
            "cause": CAUSE_NO_PERMISSION,
            "detail": (
                "調査に使っている IAM プリンシパルに SSM の権限が無い"
                f"（拒否されたオペレーション: {', '.join(ops)}）。"
                "`ssm:DescribeInstanceInformation` と `ssm:SendCommand` /"
                "`ssm:GetCommandInvocation` の付与が必要。"
            ),
            "evidence": [f"errors[].ssm:{op}" for op in ops],
            "per_instance": {},
        }

    # VPC エンドポイントの有無（サービス名の末尾で判定）
    endpoint_services: set[str] = set()
    for ep in network.get("vpc_endpoints") or []:
        if not isinstance(ep, dict):
            continue
        name = str(ep.get("ServiceName") or "")
        tail = name.rsplit(".", 1)[-1]
        if tail in _SSM_ENDPOINT_SERVICES:
            endpoint_services.add(tail)

    # サブネット → 0.0.0.0/0 の経路があるか
    routed_subnets = _subnets_with_default_route(network)

    per_instance: dict[str, dict] = {}
    causes: list[str] = []
    for ins in instances:
        # ここは inventory を読むだけで API を呼ばないため、ID の厳密検証はしない
        # （検証は SendCommand に渡す経路 = validate_instance_ids で行う）。
        iid = str(ins.get("InstanceId") or "")
        if not iid:
            continue
        has_role = bool(ins.get("IamInstanceProfile"))
        entry = managed_by_id.get(iid)
        ping = str(entry.get("PingStatus")) if isinstance(entry, dict) else ""
        subnet = str(ins.get("SubnetId") or "")
        has_egress = subnet in routed_subnets
        has_endpoints = bool(endpoint_services)

        if entry is not None and ping == "Online":
            cause = ""
        elif not has_role:
            cause = CAUSE_NO_ROLE
        elif entry is None and not has_egress and not has_endpoints:
            cause = CAUSE_NO_ENDPOINT
        else:
            cause = CAUSE_NO_AGENT

        per_instance[iid] = {
            "cause": cause,
            "iam_instance_profile": has_role,
            "ping_status": ping or "（SSM に未登録）",
            "subnet_has_default_route": has_egress,
            "ssm_vpc_endpoints": sorted(endpoint_services),
        }
        if cause:
            causes.append(cause)
            evidence.append(f"compute.instances[].InstanceId={iid}")

    if not instances:
        return {
            "cause": CAUSE_UNKNOWN,
            "detail": (
                "inventory に EC2 インスタンスが 1 台も無いため原因を自動判定できない。"
                "`awsprobe collect` を先に実行すること。"
            ),
            "evidence": ["compute.instances"],
            "per_instance": {},
        }
    if not causes:
        return {
            "cause": "",
            "detail": "全インスタンスが SSM 到達可能（PingStatus=Online）。",
            "evidence": ["compute.ssm_managed_instances"],
            "per_instance": per_instance,
        }

    # 最も多い原因を代表にする
    top = max(set(causes), key=causes.count)
    detail = {
        CAUSE_NO_ROLE: (
            "EC2 に IAM インスタンスプロファイルが付いていない。"
            "`AmazonSSMManagedInstanceCore` を含むロールを付与すると SSM 管理下に入る。"
        ),
        CAUSE_NO_ENDPOINT: (
            "サブネットに 0.0.0.0/0 の経路（IGW / NAT）が無く、"
            "ssm / ssmmessages / ec2messages の VPC エンドポイントも無い。"
            "SSM Agent が AWS 側へ接続する経路が存在しない。"
        ),
        CAUSE_NO_AGENT: (
            "IAM ロールと通信経路はあるのに SSM に登録されていない（または PingStatus が Online でない）。"
            "SSM Agent が未導入・停止・旧版である可能性が高い。"
        ),
    }.get(top, "原因を特定できなかった。")
    return {
        "cause": top,
        "detail": detail,
        "evidence": sorted(set(evidence)) or ["compute.instances"],
        "per_instance": per_instance,
    }


def _subnets_with_default_route(network: dict) -> set[str]:
    """0.0.0.0/0 の経路を持つサブネット ID の集合を返す。

    明示的関連付けが無いサブネットは VPC のメインルートテーブルに従う。
    """
    main_by_vpc: dict[str, dict] = {}
    explicit: dict[str, dict] = {}
    tables = [t for t in (network.get("route_tables") or []) if isinstance(t, dict)]
    for table in tables:
        vpc = str(table.get("VpcId") or "")
        for assoc in table.get("Associations") or []:
            if not isinstance(assoc, dict):
                continue
            if assoc.get("Main"):
                main_by_vpc[vpc] = table
            subnet = assoc.get("SubnetId")
            if subnet:
                explicit[str(subnet)] = table

    def _has_default(table: dict) -> bool:
        for route in table.get("Routes") or []:
            if not isinstance(route, dict):
                continue
            if str(route.get("DestinationCidrBlock") or "") != "0.0.0.0/0":
                continue
            if str(route.get("State") or "active") != "active":
                continue
            if route.get("GatewayId") or route.get("NatGatewayId") or route.get(
                "TransitGatewayId"
            ):
                return True
        return False

    out = {sid for sid, table in explicit.items() if _has_default(table)}
    for subnet in network.get("subnets") or []:
        if not isinstance(subnet, dict):
            continue
        sid = str(subnet.get("SubnetId") or "")
        if not sid or sid in explicit:
            continue
        table = main_by_vpc.get(str(subnet.get("VpcId") or ""))
        if table and _has_default(table):
            out.add(sid)
    return out


# ---------------------------------------------------------------------------
# 本体
# ---------------------------------------------------------------------------


def probe_hosts(
    ctx: Context,
    instance_ids: Sequence[str] | None = None,
    *,
    probes: Sequence[str] | Sequence[Probe] | None = None,
    timeout: int = 120,
    dry_run: bool = False,
    confirm: bool = False,
    inventory: dict | None = None,
    poll_interval: float = POLL_INTERVAL,
    max_polls: int = MAX_POLLS,
) -> dict:
    """EC2 の内部調査を実行し、inventory の ``host`` セクションを返す。

    Args:
        ctx: :func:`awsprobe.session.build_context` が返す実行コンテキスト。
        instance_ids: 対象インスタンス。未指定なら SSM 到達可能な全台。
        probes: プローブ名の一覧。未指定なら :data:`PROBES` 全件。
        timeout: SendCommand の ``TimeoutSeconds`` と結果待ちの上限（秒）。
        dry_run: True なら計画だけ返して SendCommand を発行しない。
        confirm: **CLI の ``--yes`` に対応**。False なら SendCommand を発行しない。
        inventory: SSM 不可の原因診断に使う（``awsprobe collect`` の結果）。
        poll_interval: GetCommandInvocation のポーリング間隔（秒）。
        max_polls: ポーリングの最大回数。

    Returns:
        ``docs/INVENTORY_SCHEMA.md`` の ``host`` セクション。
        ``method`` は ``"ssm"``（実行した）か ``"manual"``（手順書に回す）。

    Notes:
        ``ctx.guard.allow_ssm_command`` が False のときは **SendCommand を
        試みずに** ``method="manual"`` を返す。ガードに例外を投げさせない
        （= 呼び出し実績を残さない）のが仕様。
    """
    selected = resolve_probes(probes)
    requested = validate_instance_ids(instance_ids) if instance_ids else []

    managed = reachable_instances(ctx)
    online = online_instance_ids(managed)
    targets = [i for i in requested if i in online] if requested else list(online)
    unreachable = [i for i in requested if i not in online]

    base: dict[str, Any] = {
        "method": "manual",
        "collected_at": _now_iso(),
        "instances": {},
        "manual_doc": DEFAULT_MANUAL_DOC,
        "probes_run": [p.name for p in selected],
        "ssm_online": online,
        "requested_but_unreachable": unreachable,
        "plan": render_plan(targets, selected),
        "confirmed": bool(confirm),
        # SSM の stdout が 24,000 字で打ち切られたかどうか（I-7）。
        # 実行しなかった経路では常に False。
        "truncated": False,
    }

    allow = bool(getattr(ctx.guard, "allow_ssm_command", False)) if ctx.guard else False

    # --- (3) ガードが SSM コマンドを許していない → 送らずに手順書へ ---------
    if not allow:
        diag = diagnose_ssm_unavailable(inventory, allow_ssm_command=False)
        base["reason"] = "ssm_command_disabled"
        base["reason_detail"] = diag["detail"]
        base["diagnosis"] = diag
        base["instances"] = _manual_placeholders(targets or online, selected)
        return base

    if dry_run or not confirm:
        base["reason"] = "dry_run" if dry_run else "not_confirmed"
        base["reason_detail"] = (
            "--dry-run のため SendCommand を発行していない。"
            if dry_run
            else "確認（--yes）が無いため SendCommand を発行していない。実行計画のみ提示する。"
        )
        base["instances"] = _manual_placeholders(targets or online, selected)
        return base

    if not targets:
        diag = diagnose_ssm_unavailable(inventory, allow_ssm_command=True)
        # reason コードは cli.py の説明表（_REASON_LABELS）と綴りを合わせること（L-4）。
        base["reason"] = "no_reachable_instances"
        base["reason_detail"] = (
            "SSM 到達可能（PingStatus=Online）なインスタンスが 1 台も無い。" + diag["detail"]
        )
        base["diagnosis"] = diag
        return base

    # --- (4)(5)(6)(7) 実行 --------------------------------------------------
    # stdout の 24,000 字上限で後半のプローブが黙って消えないよう、
    # プローブを複数バッチに分けて送る（I-7）。
    batches = build_batches(selected)
    send_timeout = max(_SSM_MIN_TIMEOUT, int(timeout))
    results: dict[str, dict] = {}
    for instance_id in targets:
        results[instance_id] = _probe_one(
            ctx,
            instance_id,
            batches,
            send_timeout=send_timeout,
            poll_interval=poll_interval,
            max_polls=max_polls,
        )

    base["method"] = "ssm"
    base["instances"] = results
    base["reason"] = ""
    base["reason_detail"] = ""
    base["batches"] = [[p.name for p in batch] for batch in batches]
    # どれか 1 台でも打ち切られていたら host セクション全体に印を立てる。
    base["truncated"] = any(
        bool(entry.get("truncated")) for entry in results.values() if isinstance(entry, dict)
    )
    for iid in unreachable:
        base["instances"].setdefault(
            iid,
            {"ssm_reachable": False, "results": {}, "note": "SSM 到達不可のため未実行"},
        )
    return base


def _probe_one(
    ctx: Context,
    instance_id: str,
    batches: Sequence[Sequence[Probe]],
    *,
    send_timeout: int,
    poll_interval: float,
    max_polls: int,
) -> dict:
    """1 台に対して、バッチごとに SendCommand → GetCommandInvocation を行う。

    ``GetCommandInvocation.StandardOutputContent`` は 24,000 字で打ち切られ、
    超えた分は何の印も無く消える。**バッチごとに 24,000 字の枠を使う**ことで
    ``authorized_keys`` 以降のプローブが黙って欠落するのを防ぐ（I-7）。

    打ち切りが起きた場合は、取れなかったプローブを ``status="Truncated"``
    として残し、戻り値に ``truncated: True`` を立てる。
    """
    if not valid_instance_id(instance_id):  # 二重チェック（ここまで来ないはず）
        return {"ssm_reachable": False, "results": {}, "note": "インスタンス ID が不正"}

    results: dict[str, dict] = {}
    command_ids: list[str] = []
    statuses: list[str] = []
    notes: list[str] = []
    truncated_probes: list[str] = []

    for index, batch in enumerate(batches, start=1):
        probes = tuple(batch)
        if not probes:
            continue
        label = f"host-probe: {instance_id} (バッチ {index}/{len(batches)})"
        script = build_script(probes, max_seconds=send_timeout)
        resp = safe_call(
            ctx,
            "ssm",
            "send_command",
            context=label,
            InstanceIds=[instance_id],
            DocumentName=SSM_DOCUMENT,
            Comment="awsprobe host-probe (read-only)",
            TimeoutSeconds=send_timeout,
            Parameters={"commands": script},
        )
        command_id = ""
        if isinstance(resp, dict):
            command_id = str((resp.get("Command") or {}).get("CommandId") or "")
        if not command_id:
            notes.append(f"バッチ {index}: SendCommand が失敗した（errors を参照）")
            for probe in probes:
                results.setdefault(
                    probe.name, {"status": "NotSent", "stdout": "", "stderr": ""}
                )
            continue
        command_ids.append(command_id)

        invocation = _poll_invocation(
            ctx,
            command_id,
            instance_id,
            poll_interval=poll_interval,
            max_polls=max_polls,
            # SendCommand の TimeoutSeconds に猶予 30 秒を足した壁時計上限。
            # 回数と時間の両方で打ち切り、無限待ちにならないようにする。
            deadline=time.monotonic() + send_timeout + 30,
        )
        if invocation is None:
            notes.append(f"バッチ {index}: 結果の取得がタイムアウトした")
            for probe in probes:
                results.setdefault(
                    probe.name, {"status": "PollTimeout", "stdout": "", "stderr": ""}
                )
            continue

        status = str(invocation.get("Status") or "Unknown")
        statuses.append(status)
        stdout = mask_secrets(str(invocation.get("StandardOutputContent") or ""))
        stderr = mask_secrets(str(invocation.get("StandardErrorContent") or ""))
        parsed = parse_probe_output(stdout, probes)

        # このバッチで送ったプローブぶんだけを取り込む
        # （他バッチの結果を空で上書きしないようにする）。
        for probe in probes:
            entry = parsed.get(probe.name) or {
                "status": "NoOutput", "stdout": "", "stderr": "",
            }
            results[probe.name] = entry
            if entry.get("status") in ("Truncated", "PartiallyTruncated"):
                truncated_probes.append(probe.name)
        if TRUNCATION_KEY in parsed:
            results[TRUNCATION_KEY] = parsed[TRUNCATION_KEY]
        if stderr:
            # stderr はバッチ全体のもの。どのプローブか特定できないため別枠で残す。
            key = "_stderr" if len(batches) == 1 else f"_stderr_batch{index}"
            results[key] = {"status": status, "stdout": "", "stderr": stderr}

    out: dict[str, Any] = {
        "ssm_reachable": True,
        "command_id": command_ids[0] if command_ids else "",
        "command_ids": command_ids,
        "status": statuses[-1] if statuses else "Unknown",
        "results": results,
        "truncated": bool(truncated_probes),
    }
    if truncated_probes:
        out["truncated_probes"] = sorted(set(truncated_probes))
    if notes:
        out["note"] = " / ".join(notes)
    return out


def _poll_invocation(
    ctx: Context,
    command_id: str,
    instance_id: str,
    *,
    poll_interval: float,
    max_polls: int,
    deadline: float | None = None,
) -> dict | None:
    """GetCommandInvocation を終端状態になるまでポーリングする。

    最大回数（``max_polls``）と壁時計の期限（``deadline``、``time.monotonic()``
    基準）の**どちらか早い方**で打ち切る。
    """
    last: dict | None = None
    for attempt in range(max(1, int(max_polls))):
        if attempt:
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(max(0.0, float(poll_interval)))
        resp = safe_call(
            ctx,
            "ssm",
            "get_command_invocation",
            context=f"host-probe: {instance_id} / {command_id}",
            CommandId=command_id,
            InstanceId=instance_id,
        )
        if not isinstance(resp, dict):
            continue
        last = resp
        if str(resp.get("Status") or "") in _TERMINAL_STATUSES:
            return resp
    return last


def _manual_placeholders(instance_ids: Sequence[str], probes: Sequence[Probe]) -> dict:
    """SSM を実行しなかったときの空の instances 構造を作る。"""
    return {
        iid: {
            "ssm_reachable": True,
            "results": {},
            "note": "SSM 実行は行っていない（手順書での手動採取が必要）",
        }
        for iid in instance_ids
        if valid_instance_id(iid)
    }


# ---------------------------------------------------------------------------
# 手動実行の手順書生成
# ---------------------------------------------------------------------------

DEFAULT_MANUAL_DOC = "docs/manual-ssh-commands.md"


def _tag_name(instance: dict) -> str:
    for tag in instance.get("Tags") or []:
        if isinstance(tag, dict) and tag.get("Key") == "Name":
            return str(tag.get("Value") or "")
    return ""


def normalize_instances(
    instances: Sequence[dict] | None, managed: Sequence[dict] | None = None
) -> list[dict]:
    """EC2 の生レスポンス／簡略 dict のどちらでも受けて手順書用に正規化する。"""
    online = {
        m.get("InstanceId")
        for m in (managed or [])
        if isinstance(m, dict) and str(m.get("PingStatus") or "") == "Online"
    }
    out: list[dict] = []
    for ins in instances or []:
        if not isinstance(ins, dict):
            continue
        iid = ins.get("InstanceId") or ins.get("instance_id") or ""
        out.append(
            {
                "InstanceId": str(iid),
                "Name": ins.get("Name") or _tag_name(ins) or "—",
                "PrivateIpAddress": ins.get("PrivateIpAddress") or "—",
                "SubnetId": ins.get("SubnetId") or "—",
                "State": (ins.get("State") or {}).get("Name")
                if isinstance(ins.get("State"), dict)
                else (ins.get("State") or "—"),
                "ssm_reachable": bool(ins.get("ssm_reachable")) or iid in online,
            }
        )
    return out


def instances_from_inventory(inventory: dict | None) -> list[dict]:
    """inventory の ``compute`` から手順書用のインスタンス一覧を作る。"""
    inv = inventory if isinstance(inventory, dict) else {}
    compute = inv.get("compute") if isinstance(inv.get("compute"), dict) else {}
    return normalize_instances(
        compute.get("instances") or [], compute.get("ssm_managed_instances") or []
    )


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> list[str]:
    """report.py と同じ体裁の Markdown 表を作る。"""
    if not rows:
        return []
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]
    for row in rows:
        cells = [
            "—" if c is None else str(c).replace("|", "\\|").replace("\n", " ").strip() or "—"
            for c in row
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return lines


def render_manual_doc(
    instances: Sequence[dict] | None,
    probes: Sequence[Probe] | None = None,
    *,
    out_path: str | None = DEFAULT_MANUAL_DOC,
    inventory: dict | None = None,
    allow_ssm_command: bool = False,
    reason: str | None = None,
) -> str:
    """SSM が使えない場合の手動調査手順書（Markdown）を生成して書き出す。

    Args:
        instances: 対象インスタンス（EC2 の生レスポンスでも正規化済みでも可）。
        probes: 掲載するプローブ。未指定なら全件。
        out_path: 書き出し先。``None`` なら書き出さず文字列だけ返す。
        inventory: SSM 不可の原因自動判定に使う。
        allow_ssm_command: 実行時にガードが SSM を許可していたか。
        reason: 原因を手で指定する場合（未指定なら自動判定）。

    Returns:
        生成した Markdown 全文。
    """
    selected = tuple(probes) if probes else PROBES
    rows_src = normalize_instances(instances) if instances else instances_from_inventory(inventory)
    diag = diagnose_ssm_unavailable(inventory, allow_ssm_command=allow_ssm_command)
    cause = reason or diag.get("cause") or CAUSE_UNKNOWN

    lines: list[str] = []
    lines.append("# EC2 内部調査 手動実行手順（SSM が使えない場合）")
    lines.append("")
    lines.append(
        f"*生成日時: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M')} ／ "
        "`awsprobe host-probe` が自動生成。**この手順は読み取りのみで、"
        "サーバーに一切変更を加えない。***"
    )
    lines.append("")

    # -- 1. なぜ SSM が使えないか -------------------------------------------
    lines.append("## 1. SSM が使えなかった理由")
    lines.append("")
    lines.append(f"**判定: {cause}**")
    lines.append("")
    lines.append(diag.get("detail") or "—")
    lines.append("")
    lines.extend(
        _md_table(
            ["原因の候補", "該当", "解消方法"],
            [
                [
                    CAUSE_NOT_ENABLED,
                    "✓" if cause == CAUSE_NOT_ENABLED else "",
                    "`awsprobe host-probe --enable-ssm --yes` を付けて再実行する",
                ],
                [
                    CAUSE_NO_PERMISSION,
                    "✓" if cause == CAUSE_NO_PERMISSION else "",
                    "調査用 IAM に `ssm:SendCommand` / `ssm:GetCommandInvocation` を付与する",
                ],
                [
                    CAUSE_NO_ROLE,
                    "✓" if cause == CAUSE_NO_ROLE else "",
                    "EC2 に `AmazonSSMManagedInstanceCore` を含むインスタンスプロファイルを付ける",
                ],
                [
                    CAUSE_NO_ENDPOINT,
                    "✓" if cause == CAUSE_NO_ENDPOINT else "",
                    "ssm / ssmmessages / ec2messages の VPC エンドポイントを作る（または NAT 経路を通す）",
                ],
                [
                    CAUSE_NO_AGENT,
                    "✓" if cause == CAUSE_NO_AGENT else "",
                    "SSM Agent の導入・起動状況を確認する（本手順書で `systemd_units` を採取すれば分かる）",
                ],
            ],
        )
    )
    lines.append("")
    per_instance = diag.get("per_instance") or {}
    if per_instance:
        lines.append("**インスタンス別の判定**")
        lines.append("")
        lines.extend(
            _md_table(
                ["インスタンスID", "IAM ロール", "SSM 登録状態", "サブネットの既定経路", "判定"],
                [
                    [
                        iid,
                        "あり" if info.get("iam_instance_profile") else "**なし**",
                        info.get("ping_status"),
                        "あり" if info.get("subnet_has_default_route") else "なし",
                        info.get("cause") or "到達可能",
                    ]
                    for iid, info in sorted(per_instance.items())
                ],
            )
        )
        lines.append("")

    # -- 2. 対象インスタンス -------------------------------------------------
    lines.append("## 2. 対象インスタンス")
    lines.append("")
    if rows_src:
        lines.extend(
            _md_table(
                ["インスタンスID", "Name タグ", "プライベートIP", "サブネット", "状態", "SSM 到達性"],
                [
                    [
                        ins["InstanceId"],
                        ins["Name"],
                        ins["PrivateIpAddress"],
                        ins["SubnetId"],
                        ins["State"],
                        "到達可" if ins["ssm_reachable"] else "**到達不可**",
                    ]
                    for ins in rows_src
                ],
            )
        )
    else:
        lines.append("inventory にインスタンスが見つからなかった。`awsprobe collect` を先に実行すること。")
    lines.append("")

    # -- 3. 実行スクリプト ---------------------------------------------------
    lines.append("## 3. 実行するスクリプト（このままコピペ可）")
    lines.append("")
    lines.append(
        "踏み台（bastion）等から対象サーバーへ SSH できる端末で、以下をそのまま実行する。"
        "ヒアドキュメントでローカルにスクリプトを作り、SSH の標準入力へ流す形にしてある"
        "（**リモート側にはファイルを一切作らない**）。"
    )
    lines.append("")
    lines.append("```bash")
    lines.append("# 1) ローカルに調査スクリプトを作る（リモートには置かない）")
    lines.append("cat > awsprobe-host-probe.sh <<'AWSPROBE_EOF'")
    lines.extend(build_script(selected))
    lines.append("AWSPROBE_EOF")
    lines.append("")
    lines.append("# 2) 対象サーバーごとに実行して結果を保存する")
    lines.append("#    <instance-id> は「2. 対象インスタンス」の表の値に置き換える")
    targets = [ins for ins in rows_src if ins.get("InstanceId")] or [
        {"InstanceId": "i-xxxxxxxxxxxxxxxxx", "PrivateIpAddress": "10.0.0.10", "Name": "—"}
    ]
    for ins in targets:
        host = ins.get("PrivateIpAddress") or ""
        if not host or host == "—":
            # inventory に IP が無い場合は、どのインスタンスの IP かを明示する
            host = f"＜{ins['InstanceId']} のプライベートIP＞"
        lines.append(f"# {ins.get('Name') or '—'}")
        lines.append(
            f"ssh ec2-user@{host} 'sudo bash -s' "
            f"< awsprobe-host-probe.sh | tee host_manual_{ins['InstanceId']}.txt"
        )
    lines.append("```")
    lines.append("")
    lines.append(
        "> `sudo` は `crontab -l -u <user>` と `sshd -T` と他ユーザーの `authorized_keys` の"
        "参照に必要。sudo が使えない場合はそのまま `bash -s` で実行してよい"
        "（採取できる範囲が狭まるだけで、手順は変わらない）。"
    )
    lines.append("")

    # -- 4. 設問対応表 -------------------------------------------------------
    lines.append("## 4. 各コマンドが解消する設問")
    lines.append("")
    lines.extend(
        _md_table(
            ["プローブ名", "解消する設問", "内容", "何のために取るか"],
            [[p.name, ", ".join(p.answers) or "—", p.title, p.why] for p in selected],
        )
    )
    lines.append("")

    # -- 5. 取り込み手順 -----------------------------------------------------
    lines.append("## 5. 結果を awsprobe に取り込む")
    lines.append("")
    lines.append(
        "出力は `===== PROBE:<name> =====` 区切りになっている。"
        "**ファイル名を `host_manual_<instance-id>.txt` にしておくこと**"
        "（インスタンス ID をファイル名から復元するため）。"
    )
    lines.append("")
    lines.append(
        f"最終行に番兵 `{DELIM_FORMAT.format(name=END_SENTINEL)}` が出ていれば、"
        "出力は途中で切れていない。**この行が無いファイルは途中で切れている**ので、"
        "取り込む前に採取をやり直すこと。"
    )
    lines.append("")
    lines.append("```bash")
    lines.append("# 採取したファイルを1つのディレクトリに集める")
    lines.append("ls manual-results/")
    lines.append("#   host_manual_i-0123456789abcdef0.txt")
    lines.append("#   host_manual_i-0fedcba9876543210.txt")
    lines.append("")
    lines.append("# inventory.json の host セクションへマージする")
    lines.append("awsprobe host-probe --import-dir manual-results/")
    lines.append("```")
    lines.append("")
    lines.append(
        "マージ後に `awsprobe report` を再実行すると、Q9 / Q14 / Q31 / Q36 などの判定に"
        "実測値が反映される。"
    )
    lines.append("")

    # -- 6. 注意書き ---------------------------------------------------------
    lines.append("## 6. 実行時の注意")
    lines.append("")
    lines.append(
        "- **本番サーバーで実行すること。** ステージングでは authorized_keys も cron も"
        "本番と異なるため、切離しの判断材料にならない。"
    )
    lines.append(
        "- **読み取りのみで副作用は無い。** ファイルの作成・変更・削除、パッケージ導入、"
        "サービスの起動・停止・再起動は一切行わない。"
        "`systemctl` は一覧表示のみ、`sshd -T` は設定表示のみ（デーモンは起動しない）、"
        "`crontab` は必ず `-l` を付け標準入力を `/dev/null` に固定してある"
        "（誤って crontab を上書きしないため）。"
    )
    lines.append(
        "- **`authorized_keys` は鍵本体を出さない形にしてある。** 出力されるのは"
        "行数・コメント欄（末尾のラベル）・指紋（`ssh-keygen -lf`）・mtime・パーミッションのみ。"
        "取り込み時にも正規表現で鍵本体らしき文字列をマスクする二重防御が入っている。"
    )
    lines.append(
        "- **読まないもの**: 秘密鍵、`.env` の中身、`/var/log` の中身、"
        "アプリのソースコード、データベースの中身。"
        "`.env` と `composer.json` は**存在と更新日時だけ**を確認する。"
    )
    lines.append(
        f"- **スクリプト自身に実行時間の上限（{SCRIPT_MAX_SECONDS} 秒）が入っている。**"
        "冒頭でウォッチドッグを起動し、上限を過ぎたら自分自身へ SIGTERM を送って停止する"
        "（自分がプロセスグループのリーダーのときはグループごと停止する）。"
        "手元で Ctrl-C しても、サーバー側でコマンドが走り続けることはない。"
    )
    lines.append(
        "- `disk_usage` の `du` は **`timeout` コマンドがある環境でのみ**、"
        "`/var /opt /srv /home /usr/local /tmp` に限定して最長 30 秒で実行する。"
        "`timeout` が無い環境では `du` を**実行せず**、その旨だけを出力する"
        "（上限の無い `du -x /` が本番サーバーで走り続けるのを防ぐため）。"
    )
    lines.append(
        "- `cron_jobs` と `authorized_keys` のユーザー走査は **50 件で打ち切る**。"
        "LDAP / AD / SSSD 参加ホストでは `getent passwd` が数千件返り、"
        "そのぶんプロセスを起動してしまうため（`cron_jobs` はローカル定義の "
        "`/etc/passwd` のみを対象にする）。"
    )
    lines.append(
        f"- 各プローブの出力は **{PROBE_OUTPUT_LIMIT} バイトで打ち切る**"
        "（`head -c`）。SSM 経由では stdout 全体が "
        f"{SSM_STDOUT_LIMIT} 文字で切られるため、その対策がそのまま入っている。"
        "手動実行では全バッチを 1 本のスクリプトで流してよい（ファイルに保存するので上限は無い）。"
    )
    lines.append(
        "- 採取結果には社内のユーザー名・ホスト名・鍵のラベルが含まれる。"
        "**取扱いは社外秘**とし、共有先を限定すること。"
    )
    lines.append("")

    text = "\n".join(lines) + "\n"
    if out_path:
        directory = os.path.dirname(os.path.abspath(out_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(text)
    return text


# ---------------------------------------------------------------------------
# 手動結果の取り込み
# ---------------------------------------------------------------------------

_FILE_INSTANCE_RE = re.compile(r"(i-[0-9a-f]{8,17})")


def import_manual_results(paths: Sequence[str]) -> dict:
    """手動採取したテキストを読み、SSM 経由と同じ ``host`` セクションに戻す。

    Args:
        paths: ``host_manual_<instance-id>.txt`` のパス一覧。
               ディレクトリを渡した場合はその直下の ``.txt`` を対象にする。

    Returns:
        ``docs/INVENTORY_SCHEMA.md`` の ``host`` セクション（``method="manual"``）。
    """
    files: list[str] = []
    for path in paths or []:
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if name.lower().endswith((".txt", ".log", ".out")):
                    files.append(os.path.join(path, name))
        elif os.path.isfile(path):
            files.append(path)

    instances: dict[str, dict] = {}
    skipped: list[dict] = []
    for path in files:
        basename = os.path.basename(path)
        matched = _FILE_INSTANCE_RE.search(basename)
        if not matched or not valid_instance_id(matched.group(1)):
            skipped.append(
                {"file": basename, "reason": "ファイル名からインスタンス ID を復元できない"}
            )
            continue
        instance_id = matched.group(1)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                raw = handle.read()
        except OSError as exc:  # noqa: PERF203 - 1 ファイルの失敗で全体を止めない
            skipped.append({"file": basename, "reason": f"読み込み失敗: {exc}"})
            continue
        results = parse_probe_output(raw)
        if not results:
            skipped.append(
                {"file": basename, "reason": "'===== PROBE:<name> =====' 区切りが見つからない"}
            )
            continue
        # 番兵が無いファイルは途中で切れている（SSH の切断・コピペ漏れ等）。
        # 取り込めた分はそのまま使いつつ、**切れていることを必ず残す**（I-7）。
        complete = output_is_complete(raw)
        entry: dict[str, Any] = {
            "ssm_reachable": False,
            "results": results,
            "source_file": basename,
            "truncated": not complete,
        }
        if not complete:
            results[TRUNCATION_KEY] = {
                "status": "Truncated",
                "stdout": (
                    f"末尾の番兵 '{DELIM_FORMAT.format(name=END_SENTINEL)}' が無い。"
                    "採取の途中で出力が切れている可能性が高いため、採取をやり直すこと。"
                ),
                "stderr": "",
            }
        instances[instance_id] = entry

    return {
        "method": "manual",
        "truncated": any(
            bool(e.get("truncated")) for e in instances.values()
        ),
        "collected_at": _now_iso(),
        "instances": instances,
        "manual_doc": DEFAULT_MANUAL_DOC,
        "imported_files": [os.path.basename(f) for f in files],
        "skipped_files": skipped,
    }


def merge_into_inventory(inventory: dict, host: dict) -> dict:
    """inventory に ``host`` セクションを差し込んだ dict を返す（破壊的変更なし）。"""
    out = dict(inventory or {})
    existing = out.get("host") if isinstance(out.get("host"), dict) else {}
    merged_instances = dict(existing.get("instances") or {})
    for iid, data in (host.get("instances") or {}).items():
        current = dict(merged_instances.get(iid) or {})
        current.update(data)
        # results は既存を残しつつ新しい方で上書きする
        results = dict((merged_instances.get(iid) or {}).get("results") or {})
        results.update(data.get("results") or {})
        current["results"] = results
        merged_instances[iid] = current
    new_host = dict(existing)
    new_host.update(host)
    new_host["instances"] = merged_instances
    out["host"] = new_host
    return out
