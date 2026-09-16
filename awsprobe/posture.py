"""セキュリティ設定の実施状況評価（CIS AWS Foundations v3.0 / AWS FSBP）。

`awsprobe collect` が出力した inventory dict だけを見て、
**チェック項目ごとに「どこまで実施されているか」** を判定する。

厳守事項:
- **AWS API を呼ばない。boto3 を import しない。** 入力は inventory dict のみ。
- 標準ライブラリのみを使う（`questions.py` の共通ヘルパーは同じ制約下にあるので再利用する）。
- inventory のキーが欠けていても KeyError で落ちない（`.get()` を徹底する）。
- **アクセスキーID・シークレット・パラメータ値は絶対に出力しない。**

status の使い分け:
- ``実施済``   … 対象リソースすべてが条件を満たす
- ``一部実施`` … 一部のリソースのみ満たす（`passed` と `failed` の両方が埋まる）
- ``未実施``   … 対象リソースが存在するがどれも満たさない
- ``該当なし`` … 対象リソースがそもそも存在しない（Aurora が無い環境の Aurora 向けチェック等）
- ``判定不能`` … データが取れていない。`errors` に該当する AccessDenied があれば summary に明記する
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from .guard import ACCOUNT_TOKEN_RE, SELF_ACCOUNT_TOKEN
from .questions import (
    _dicts,
    _lst,
    _map,
    _sect,
    _tag,
    denied_for,
    errors_for,
    errors_of,
    format_errors,
    is_open_to_world,
    parse_dt,
    perm_covers_port,
    perm_sources,
    port_label,
)

# `guard.py` は標準ライブラリしか import しないので、本モジュールの
# 「boto3 を import しない」という制約は守られている。

# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------

#: status の取りうる値
DONE = "実施済"
PARTIAL = "一部実施"
NOT_DONE = "未実施"
NOT_APPLICABLE = "該当なし"
UNKNOWN = "判定不能"

STATUSES = (DONE, PARTIAL, NOT_DONE, NOT_APPLICABLE, UNKNOWN)

#: 実施率の分母に入れる status（該当なし・判定不能は分母から外す）
SCORED_STATUSES = (DONE, PARTIAL, NOT_DONE)

#: 評価する10ドメイン
ENC = "暗号化"
PUB = "公開範囲"
NET = "ネットワーク"
IAM = "IAM・認証"
LOG = "ログ・証跡"
DET = "脅威検知"
BCP = "バックアップ・可用性"
KEY = "鍵・シークレット"
PAT = "パッチ・構成管理"
GOV = "統制"

DOMAINS = (ENC, PUB, NET, IAM, LOG, DET, BCP, KEY, PAT, GOV)

#: ドメイン ID の接頭辞 → ドメイン名
DOMAIN_BY_PREFIX = {
    "ENC": ENC, "PUB": PUB, "NET": NET, "IAM": IAM, "LOG": LOG,
    "DET": DET, "BCP": BCP, "KEY": KEY, "PAT": PAT, "GOV": GOV,
}

#: 深刻度
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW)

#: 深刻度の重み（「今すぐ直すべき上位10件」の並べ替えに使う）
SEVERITY_WEIGHT = {CRITICAL: 100, HIGH: 40, MEDIUM: 10, LOW: 3}

#: inventory が持ちうるリソースセクション名（meta / errors / host を除く）
SECTION_NAMES = (
    "network", "compute", "database", "storage",
    "edge", "serverless", "logging", "security",
)

#: 0.0.0.0/0 に開けてはならない管理・データベースポート
ADMIN_PORTS: dict[int, str] = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    135: "MSRPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 445: "SMB",
    1433: "SQL Server", 1521: "Oracle", 2049: "NFS", 3306: "MySQL/MariaDB",
    3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5984: "CouchDB",
    6379: "Redis", 8020: "HDFS", 9200: "Elasticsearch", 9300: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
}

#: 全世界開放が許容されうる公開ポート（Web サービスの入口）
WEB_PORTS: dict[int, str] = {80: "HTTP", 443: "HTTPS"}

#: 現行世代とみなす ALB/NLB の TLS ポリシー（TLS 1.2 以上を強制するもの）
MODERN_SSL_POLICIES = frozenset(
    {
        "ELBSecurityPolicy-TLS13-1-2-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
        "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
        "ELBSecurityPolicy-TLS13-1-3-2021-06",
        "ELBSecurityPolicy-TLS-1-2-2017-01",
        "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
        "ELBSecurityPolicy-FS-1-2-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2020-10",
    }
)

#: TLS 1.0 / 1.1 を許容してしまう旧世代ポリシー（明示的に不合格とする）
LEGACY_SSL_POLICIES = frozenset(
    {
        "ELBSecurityPolicy-2015-05",
        "ELBSecurityPolicy-2016-08",
        "ELBSecurityPolicy-TLS-1-0-2015-04",
        "ELBSecurityPolicy-TLS-1-1-2017-01",
        "ELBSecurityPolicy-FS-2018-06",
        "ELBSecurityPolicy-FS-1-1-2019-08",
    }
)

#: サポート終了（またはサポート終了間近）の Lambda ランタイム
EOL_LAMBDA_RUNTIMES = frozenset(
    {
        "python2.7", "python3.6", "python3.7", "python3.8",
        "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10",
        "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
        "go1.x", "ruby2.5", "ruby2.7",
        "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
        "java8",
    }
)

#: サポート終了（または延長サポート扱い）の RDS エンジンバージョン接頭辞
EOL_ENGINE_PREFIXES = (
    ("mysql", ("5.5", "5.6", "5.7")),
    ("mariadb", ("10.2", "10.3", "10.4", "10.5")),
    ("postgres", ("9.", "10.", "11.", "12.")),
    ("aurora-mysql", ("5.6", "5.7")),
    ("aurora-postgresql", ("9.", "10.", "11.", "12.")),
    ("oracle", ("12.", "18.", "19.0")),
    ("sqlserver", ("12.", "13.")),
)

#: アクセスキーのローテーション期限（CIS 1.14）
ACCESS_KEY_MAX_AGE_DAYS = 90
#: 未使用とみなす日数（CIS 1.12 は 45 日だが、調査用途では 90 日で一次選別する）
UNUSED_CREDENTIAL_DAYS = 90
#: 証明書の期限切れ警告日数
CERT_EXPIRY_WARN_DAYS = 30
#: EBS スナップショットの鮮度基準
SNAPSHOT_FRESH_DAYS = 30
#: AMI が古いとみなす日数
AMI_STALE_DAYS = 365
#: パスワードの最小長（CIS 1.8）
MIN_PASSWORD_LENGTH = 14

#: 判定基準日
_TODAY = _dt.date.today()

#: ログ用バケットとみなす名前のキーワード
_LOG_BUCKET_KEYWORDS = ("log", "logs", "cloudtrail", "config", "audit", "flowlog")

#: ルートログイン・IAM 変更・コンソール認証失敗の検知アラームを探すキーワード
_DETECTION_ALARM_KEYWORDS = (
    "root", "iam", "console", "signin", "sign-in", "unauthorized",
    "authentication", "authfail", "policy", "cloudtrail", "mfa",
)


# ---------------------------------------------------------------------------
# Check / CheckResult
# ---------------------------------------------------------------------------


@dataclass
class Check:
    """チェック項目の定義（判定結果とは独立した静的な情報）。"""

    #: チェック ID（"ENC-01" 形式）
    cid: str
    #: ドメイン（DOMAINS のいずれか）
    domain: str
    #: 日本語のチェック名
    title: str
    #: なぜ重要か（1文）
    why: str
    #: 根拠となる基準（"CIS AWS Foundations v3.0 2.1.1" など）
    reference: str
    #: critical / high / medium / low
    severity: str

    def to_dict(self) -> dict:
        """JSON 化しやすい dict に変換する。"""
        return asdict(self)

    @property
    def number(self) -> int:
        """"ENC-01" → 1。ドメイン内の並べ替え用。"""
        m = re.search(r"\d+", self.cid or "")
        return int(m.group()) if m else 0


@dataclass
class CheckResult:
    """チェック項目1件に対する判定結果。"""

    #: 対象のチェック定義
    check: Check
    #: 実施済 / 一部実施 / 未実施 / 該当なし / 判定不能
    status: str
    #: 結論を1文で（日本語）
    summary: str
    #: 条件を満たしたリソース
    passed: list[str] = field(default_factory=list)
    #: 条件を満たさなかったリソース
    failed: list[str] = field(default_factory=list)
    #: 根拠となった inventory の JSON パス
    evidence: list[str] = field(default_factory=list)
    #: 未実施／一部実施の場合の是正方針（1〜2文）
    remediation: str = ""
    #: 意図的な設定の可能性がある等、failed に入れるべきでない注記
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """JSON 化しやすい dict に変換する。"""
        return asdict(self)

    # -- 便利プロパティ --------------------------------------------------
    @property
    def cid(self) -> str:
        return self.check.cid

    @property
    def domain(self) -> str:
        return self.check.domain

    @property
    def severity(self) -> str:
        return self.check.severity

    @property
    def is_open(self) -> bool:
        """対応が必要な状態か（未実施または一部実施）。"""
        return self.status in (NOT_DONE, PARTIAL)

    @property
    def priority(self) -> tuple:
        """「今すぐ直すべき上位10件」の並べ替えキー（降順で使う）。

        深刻度の重み × (影響リソース数 + 1) を主キーにし、
        未実施を一部実施より前に出す。
        """
        weight = SEVERITY_WEIGHT.get(self.severity, 1)
        impact = len(self.failed) + 1
        return (weight * impact, 1 if self.status == NOT_DONE else 0, weight)


# ---------------------------------------------------------------------------
# レゾルバ登録
# ---------------------------------------------------------------------------

#: 定義済みチェック一覧（登録順 = レポートの並び順）
CHECKS: list[Check] = []

#: cid -> inventory dict を受けて CheckResult を返す関数
RESOLVERS: dict[str, Callable[[dict], CheckResult]] = {}

#: レゾルバが CheckResult を組み立てるときの仮の Check（デコレータが差し替える）
_PLACEHOLDER = Check("", "", "", "", "", LOW)


def _has_section(inventory: dict, name: str) -> bool:
    """セクションが dict として存在するか（空 dict でも「収集した」とみなす）。"""
    return isinstance((inventory or {}).get(name), dict)


# ---------------------------------------------------------------------------
# 収集の欠損（I-6）
# ---------------------------------------------------------------------------
#
# スロットリング・資格情報の期限切れ・AWS 側の一時障害が起きると、
# `ctx.call` / `ctx.paginate` は None / [] を返す。判定側から見ると
# 「リソースが 0 件」と区別が付かず、**「該当なし＝問題なし」**に化ける。
# `session.CollectError.fatal` が立っているエラーがそのセクションにあれば、
# `該当なし` は信用できないので `判定不能` に倒す。

#: inventory のセクション名 → そのセクションを埋める AWS サービス識別子
SECTION_SERVICES: dict[str, tuple[str, ...]] = {
    "network": ("ec2",),
    "compute": ("ec2", "autoscaling", "ssm"),
    "database": ("rds",),
    "storage": ("s3", "efs", "fsx", "backup"),
    "edge": ("cloudfront", "elb", "elbv2", "acm", "wafv2", "shield",
             "route53", "globalaccelerator"),
    "serverless": ("lambda", "apigateway", "apigatewayv2", "dynamodb", "sns",
                   "sqs", "events", "stepfunctions", "cognito-idp"),
    "logging": ("cloudtrail", "logs", "cloudwatch", "config", "ec2"),
    "security": ("iam", "kms", "guardduty", "securityhub", "inspector2",
                 "accessanalyzer", "organizations", "cloudformation",
                 "secretsmanager", "ssm", "s3control", "sso-admin"),
}


def fatal_errors_of(inv: dict, services: tuple[str, ...] = ()) -> list[dict]:
    """`fatal` が立っている収集エラー（＝取れなかった）を返す。

    `services` を指定するとそのサービスのものだけに絞る。
    """
    out = [e for e in errors_of(inv) if e.get("fatal")]
    if services:
        out = [e for e in out if e.get("service") in services]
    return out


def _services_for(sections: tuple[str, ...]) -> tuple[str, ...]:
    """セクション名の組から、対応する AWS サービス識別子を集める。"""
    services: list[str] = []
    for section in sections:
        for svc in SECTION_SERVICES.get(section, ()):
            if svc not in services:
                services.append(svc)
    return tuple(services)


def _has_fatal_error(inv: dict, services: tuple[str, ...] = ()) -> list[dict]:
    """該当サービスに「取れなかった」エラーがあれば、そのエラー一覧を返す。

    セクション名を渡された場合（`requires` の値）はサービス名に展開する。
    `services` が空なら inventory 全体の fatal エラーを見る。
    """
    expanded = _services_for(services) if services else ()
    if services and not expanded:
        # SECTION_SERVICES に無い名前＝サービス識別子そのものとして扱う
        expanded = services
    return fatal_errors_of(inv, expanded)


def check(
    cid: str,
    domain: str,
    title: str,
    why: str,
    reference: str,
    severity: str,
    requires: tuple[str, ...] = (),
):
    """レゾルバを RESOLVERS に登録するデコレータ。

    `requires` に挙げたセクションが inventory に1つも無い場合は、
    判定関数を呼ばずに `判定不能` を返す（コレクタ未実行・権限不足の切り分け）。
    判定関数が想定外の例外で落ちても、評価全体を止めないよう
    `判定不能` の CheckResult に変換する（KeyError 等の最終防衛線）。
    """

    spec = Check(cid, domain, title, why, reference, severity)
    CHECKS.append(spec)

    def decorator(fn: Callable[[dict], CheckResult]) -> Callable[[dict], CheckResult]:
        def wrapper(inventory: dict | None) -> CheckResult:
            inv = inventory if isinstance(inventory, dict) else {}

            # inventory にリソースセクションが1つも無い＝そもそも収集できていない
            if not any(_has_section(inv, s) for s in SECTION_NAMES):
                errors = errors_for(inv)
                result = _res(
                    UNKNOWN,
                    "inventory にリソースセクションが1つも存在しないため判定できない"
                    "（`awsprobe collect` が未実行、または全コレクタが失敗している）。"
                    + (f" 収集エラー: {format_errors(errors)}。" if errors else ""),
                    remediation="`awsprobe collect` を実行して inventory.json を生成すること。",
                )
            elif requires and not any(_has_section(inv, s) for s in requires):
                result = _unknown(
                    f"判定に必要なセクション（{'／'.join(requires)}）",
                    inv,
                    evidence=list(requires),
                    remediation="不足しているコレクタを有効にして再収集すること。",
                )
            else:
                try:
                    result = fn(inv)
                except Exception as exc:  # noqa: BLE001 - 判定は絶対に止めない
                    result = _res(
                        UNKNOWN,
                        f"判定中に想定外のエラーが発生したため判定できなかった"
                        f"（{type(exc).__name__}: {exc}）。",
                    )

            # 「対象リソースが 0 件だから該当なし」は、収集が欠損していると
            # 成立しない。fatal なエラーがあれば判定不能に倒す（I-6）。
            if result.status == NOT_APPLICABLE:
                result = _demote_na_on_fatal(result, inv, requires)

            # レゾルバ側の書き間違いを防ぐため、識別情報は必ず上書きする。
            result.check = spec
            if result.status not in STATUSES:
                result.status = UNKNOWN
            return result

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        RESOLVERS[cid] = wrapper
        return wrapper

    return decorator


def _demote_na_on_fatal(
    result: CheckResult, inv: dict, requires: tuple[str, ...]
) -> CheckResult:
    """`該当なし` を、収集欠損があるときだけ `判定不能` に差し替える。

    スロットリングや資格情報の期限切れで一覧が空になっただけなのに
    「対象リソースが存在しない＝問題なし」と報告してしまうのを防ぐ。
    """
    fatal = _has_fatal_error(inv, requires)
    if not fatal:
        return result
    return _res(
        UNKNOWN,
        "対象リソースが 1 件も見つからなかったが、**収集が失敗している**ため"
        "「存在しない」と断定できず判定不能。"
        f"該当エラー: {format_errors(fatal)}。",
        evidence=list(result.evidence),
        remediation="収集が落ち着いた時間帯に `awsprobe collect` を再実行し、"
        "`errors` に fatal なエラーが無い状態で判定し直すこと。",
        notes=list(result.notes) + [
            "スロットリング・資格情報の期限切れ・AWS 側の一時障害のいずれかで"
            "一覧が取得できていない。この項目を「問題なし」と読んではならない。"
        ],
    )


def evaluate(inventory: dict) -> list[CheckResult]:
    """全チェック項目を判定し、CHECKS の定義順で CheckResult 一覧を返す。

    inventory が空 dict `{}` でも例外を出さず、全件が `判定不能` になる。
    """
    inv = inventory if isinstance(inventory, dict) else {}
    return [RESOLVERS[spec.cid](inv) for spec in CHECKS if spec.cid in RESOLVERS]


def status_counts(results: list[CheckResult]) -> dict[str, int]:
    """status ごとの件数を返す（0 件の status もキーを持つ）。"""
    counts = {s: 0 for s in STATUSES}
    for result in results or []:
        counts[result.status] = counts.get(result.status, 0) + 1
    return counts


def _rate(counts: dict[str, int]) -> float:
    """実施率（%）。該当なし・判定不能は分母から外す。一部実施は 0.5 件として数える。"""
    denominator = sum(counts.get(s, 0) for s in SCORED_STATUSES)
    if not denominator:
        return 0.0
    numerator = counts.get(DONE, 0) + counts.get(PARTIAL, 0) * 0.5
    return round(numerator * 100.0 / denominator, 1)


def _strict_rate(counts: dict[str, int]) -> float:
    """実施率（%）の厳格版。一部実施を実施済に数えない。"""
    denominator = sum(counts.get(s, 0) for s in SCORED_STATUSES)
    if not denominator:
        return 0.0
    return round(counts.get(DONE, 0) * 100.0 / denominator, 1)


def score(results: list[CheckResult]) -> dict:
    """ドメイン別・深刻度別の集計を返す。

    戻り値::

        {
          "total": 72,
          "by_status": {"実施済": 20, ...},
          "rate": 41.2,          # 一部実施を 0.5 件として数えた実施率(%)
          "strict_rate": 27.8,   # 一部実施を数えない実施率(%)
          "scored": 60,          # 実施率の分母（該当なし・判定不能を除いた件数）
          "by_domain": {"暗号化": {"total":8, "実施済":3, ..., "rate":50.0}, ...},
          "by_severity": {"critical": {...}, ...},
          "open_critical": 5,    # critical で未実施・一部実施の件数
          "open_high": 9,
        }
    """
    results = list(results or [])
    counts = status_counts(results)

    def bucket(subset: list[CheckResult]) -> dict:
        sub_counts = status_counts(subset)
        out: dict[str, Any] = {"total": len(subset)}
        out.update(sub_counts)
        out["scored"] = sum(sub_counts.get(s, 0) for s in SCORED_STATUSES)
        out["rate"] = _rate(sub_counts)
        out["strict_rate"] = _strict_rate(sub_counts)
        return out

    by_domain = {
        domain: bucket([r for r in results if r.domain == domain])
        for domain in DOMAINS
        if any(r.domain == domain for r in results)
    }
    by_severity = {
        severity: bucket([r for r in results if r.severity == severity])
        for severity in SEVERITIES
        if any(r.severity == severity for r in results)
    }

    return {
        "total": len(results),
        "by_status": counts,
        "scored": sum(counts.get(s, 0) for s in SCORED_STATUSES),
        "rate": _rate(counts),
        "strict_rate": _strict_rate(counts),
        "by_domain": by_domain,
        "by_severity": by_severity,
        "open_critical": sum(
            1 for r in results if r.severity == CRITICAL and r.is_open
        ),
        "open_high": sum(1 for r in results if r.severity == HIGH and r.is_open),
    }


def top_priority(results: list[CheckResult], limit: int = 10) -> list[CheckResult]:
    """「今すぐ直すべき」順（深刻度 × 影響リソース数）に未実施・一部実施を並べる。"""
    open_results = [r for r in (results or []) if r.is_open]
    open_results.sort(key=lambda r: (r.priority, r.cid), reverse=True)
    return open_results[:limit]


# ---------------------------------------------------------------------------
# 結果組み立ての共通ヘルパー
# ---------------------------------------------------------------------------


def _res(
    status: str,
    summary: str,
    *,
    passed: list[str] | None = None,
    failed: list[str] | None = None,
    evidence: list[str] | None = None,
    remediation: str = "",
    notes: list[str] | None = None,
) -> CheckResult:
    """CheckResult を組み立てる（check はデコレータが差し替える）。"""
    return CheckResult(
        check=_PLACEHOLDER,
        status=status,
        summary=summary,
        passed=list(passed or []),
        failed=list(failed or []),
        evidence=list(evidence or []),
        remediation=remediation,
        notes=list(notes or []),
    )


def _judge(passed: list[str], failed: list[str]) -> str:
    """passed / failed の埋まり方から status を決める。"""
    if not passed and not failed:
        return NOT_APPLICABLE
    if failed and passed:
        return PARTIAL
    if failed:
        return NOT_DONE
    return DONE


def _summarize(
    status: str,
    label: str,
    passed: list[str],
    failed: list[str],
    *,
    na_text: str = "",
    extra: str = "",
) -> str:
    """status に応じた結論の1文を組み立てる（レポート全体で表現を揃えるため）。"""
    total = len(passed) + len(failed)
    if status == NOT_APPLICABLE:
        return na_text or f"{label}の対象リソースが存在しないため、評価対象外。"
    if status == DONE:
        return f"**{label}は対象 {total} 件すべてが条件を満たしている。**" + extra
    if status == PARTIAL:
        return (
            f"{label}は対象 {total} 件中 {len(passed)} 件のみが条件を満たし、"
            f"**{len(failed)} 件が未対応**。" + extra
        )
    return f"**{label}は対象 {total} 件すべてが条件を満たしていない。**" + extra


def _finish(
    label: str,
    passed: list[str],
    failed: list[str],
    evidence: list[str],
    remediation: str,
    *,
    notes: list[str] | None = None,
    na_text: str = "",
    extra: str = "",
) -> CheckResult:
    """判定 → 結論文 → CheckResult までを一息で作る（各チェックの定型部分）。"""
    status = _judge(passed, failed)
    return _res(
        status,
        _summarize(status, label, passed, failed, na_text=na_text, extra=extra),
        passed=passed,
        failed=failed,
        evidence=evidence,
        remediation=remediation if status in (NOT_DONE, PARTIAL) else "",
        notes=notes,
    )


def _unknown(
    what: str,
    inv: dict,
    services: tuple[str, ...] = (),
    *,
    evidence: list[str] | tuple[str, ...] = (),
    remediation: str = "",
    notes: list[str] | None = None,
) -> CheckResult:
    """`判定不能` の CheckResult を作る。

    権限不足エラーがあれば summary に必ず明記する（契約どおり）。
    """
    denied = denied_for(inv, services)
    if denied:
        summary = (
            f"{what}が取得できていないため**判定不能**（権限不足）。"
            f"該当エラー: {format_errors(denied)}。"
        )
    else:
        others = errors_for(inv, services=services)
        if others:
            summary = (
                f"{what}が取得できていないため**判定不能**。"
                f"収集時のエラー: {format_errors(others)}。"
            )
        else:
            summary = (
                f"{what}が inventory に存在しないため**判定不能**"
                "（コレクタ未実行か、当該 API を収集対象にしていない）。"
            )
    return _res(
        UNKNOWN,
        summary,
        evidence=list(evidence),
        remediation=remediation,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# ドメイン補助
# ---------------------------------------------------------------------------


def _iam(inv: dict) -> dict:
    """security.iam を dict として取り出す。"""
    return _map(inv, "security", "iam")


def _iam_list(inv: dict, key: str) -> list[dict]:
    """security.iam[key] を dict のリストとして取り出す。"""
    value = _iam(inv).get(key)
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _account_id(inv: dict) -> str:
    """meta.account_id（redact 済みなら空文字相当）。"""
    return str(_sect(inv, "meta").get("account_id") or "")


def _days_old(value: Any) -> int | None:
    """ISO 日時から今日までの経過日数（未来なら負の値）。"""
    parsed = parse_dt(value)
    if parsed is None:
        return None
    return (_TODAY - parsed.date()).days


def _instance_label(instance: dict) -> str:
    """EC2 を「Name (i-xxxx)」形式で表す。"""
    return f"{_tag(instance) or '(名前なし)'} ({instance.get('InstanceId')})"


def _lb_name(lb: dict) -> str:
    """ロードバランサ名（無ければ ARN）。"""
    return str(lb.get("LoadBalancerName") or lb.get("LoadBalancerArn") or "(不明なLB)")


def _attr(resource: dict, key: str) -> str | None:
    """`Attributes`（[{Key, Value}] 形式）から値を取り出す。"""
    for item in resource.get("Attributes") or []:
        if isinstance(item, dict) and item.get("Key") == key:
            return item.get("Value")
    return None


def _is_log_bucket(name: str) -> bool:
    """名前からログ保管用バケットらしさを判定する。"""
    lowered = str(name or "").lower()
    return any(keyword in lowered for keyword in _LOG_BUCKET_KEYWORDS)


def _subnet_az(inv: dict) -> dict[str, str]:
    """SubnetId -> AvailabilityZone の索引。"""
    return {
        str(s.get("SubnetId")): str(s.get("AvailabilityZone") or "")
        for s in _dicts(inv, "network", "subnets")
        if s.get("SubnetId")
    }


def _statements(document: Any) -> list[dict]:
    """ポリシードキュメント（dict / JSON 文字列）から Statement の配列を取り出す。"""
    if isinstance(document, str):
        import json

        try:
            document = json.loads(document)
        except ValueError:
            return []
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    return [s for s in statements or [] if isinstance(s, dict)]


def _as_list(value: Any) -> list:
    """スカラーも配列も同じように扱えるようにする。"""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_full_admin(document: Any) -> bool:
    """`"Effect": "Allow"` かつ Action が `*`、Resource も `*` の文が含まれるか。"""
    for statement in _statements(document):
        if statement.get("Effect") != "Allow":
            continue
        actions = [str(a) for a in _as_list(statement.get("Action"))]
        resources = [str(r) for r in _as_list(statement.get("Resource"))]
        if any(a == "*" or a == "*:*" for a in actions) and any(
            r == "*" for r in resources
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# アカウント参照の解釈（生値／マスク済みトークンの両対応）
# ---------------------------------------------------------------------------
#
# `guard.redact()` はアカウントIDを消さずに擬似化する:
#   自アカウント   → ＜自アカウント＞
#   それ以外       → ＜アカウント:f428＞（同じ ID は常に同じトークン）
#
# 12桁だけを見る実装のままだと、マスク済み inventory では外部信頼が
# **1件も見つからず** critical チェック（IAM-07）が「該当なし＝問題なし」に
# 化ける。以下のパターンは生値とトークンの両方を拾う。

#: ARN のアカウント位置に現れうる表記
_ACCOUNT_FIELD = r"(?:\d{12}|＜自アカウント＞|＜アカウント:[0-9a-f]{4}＞)"
#: `arn:aws:iam::<アカウント>:...` からアカウント部分を取り出す
_ARN_ACCOUNT_RE = re.compile(r"arn:aws[\w-]*:(?:iam|sts)::(" + _ACCOUNT_FIELD + r"):")
#: ARN ではなく単体のアカウント表記（Principal に直接書かれた形）
_BARE_ACCOUNT_RE = re.compile(_ACCOUNT_FIELD)
#: 任意の ARN のアカウント位置（サービス名は問わない）
_ANY_ARN_ACCOUNT_RE = re.compile(r"::(" + _ACCOUNT_FIELD + r"):")


def _is_self_account(ref: str, account_id: str) -> bool:
    """アカウント参照 `ref` が自アカウントを指すか。

    - ``＜自アカウント＞``            … 自アカウント（マスク済み inventory）
    - ``＜アカウント:xxxx＞``         … **外部アカウント**。マスク時に自分は
      必ず ``＜自アカウント＞`` になるので、このトークンは自分ではありえない。
    - 生の12桁                       … 従来どおり `meta.account_id` と比較
    """
    if ref == SELF_ACCOUNT_TOKEN:
        return True
    if ACCOUNT_TOKEN_RE.fullmatch(ref):
        return False
    return bool(account_id) and ref == account_id


def _external_account_in(text: str, account_id: str) -> str:
    """ARN 文字列から「外部アカウントの参照」を取り出す（無ければ空文字）。"""
    found = _ANY_ARN_ACCOUNT_RE.search(str(text or ""))
    if not found:
        return ""
    ref = found.group(1)
    return "" if _is_self_account(ref, account_id) else ref


def _trusted_external(document: Any, account_id: str) -> tuple[set[str], bool]:
    """信頼している外部アカウントの集合と、ExternalId 条件の有無を返す。

    アカウントは生の12桁でもマスク済みトークンでも同じように扱う。
    戻り値の集合には **表記そのもの**（12桁 または ``＜アカウント:xxxx＞``）が入る。
    """
    accounts: set[str] = set()
    has_external_id = False
    for statement in _statements(document):
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        for value in _as_list(principal.get("AWS")):
            text = str(value)
            found = _ARN_ACCOUNT_RE.search(text)
            if found:
                accounts.add(found.group(1))
            elif _BARE_ACCOUNT_RE.fullmatch(text):
                accounts.add(text)
        condition = statement.get("Condition")
        if isinstance(condition, dict) and "sts:ExternalId" in str(condition):
            has_external_id = True
    return (
        {a for a in accounts if a and not _is_self_account(a, account_id)},
        has_external_id,
    )


# ===========================================================================
# 1. 暗号化（ENC）
# ===========================================================================


@check(
    "ENC-01", ENC, "RDS の保管時暗号化",
    "暗号化されていない DB はスナップショット流出やディスク廃棄時にそのまま読める。",
    "CIS AWS Foundations v3.0 2.3.1", HIGH, requires=("database",),
)
def enc01_rds_encryption(inv: dict) -> CheckResult:
    """db_instances / db_clusters の `StorageEncrypted` を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []

    for i, db in enumerate(_dicts(inv, "database", "db_instances")):
        label = f"RDS {db.get('DBInstanceIdentifier')}（{db.get('Engine')} {db.get('EngineVersion')}）"
        (passed if db.get("StorageEncrypted") else failed).append(label)
        evidence.append(f"database.db_instances[{i}].StorageEncrypted")
    for i, cluster in enumerate(_dicts(inv, "database", "db_clusters")):
        label = f"Aurora クラスタ {cluster.get('DBClusterIdentifier')}"
        (passed if cluster.get("StorageEncrypted") else failed).append(label)
        evidence.append(f"database.db_clusters[{i}].StorageEncrypted")

    return _finish(
        "RDS の保管時暗号化", passed, failed, evidence,
        "暗号化は既存インスタンスに後付けできない。暗号化済みスナップショットからの"
        "リストアで作り直すか、暗号化した新インスタンスへ論理レプリケーションで移行すること。",
        na_text="RDS インスタンス・Aurora クラスタが存在しないため、評価対象外。",
    )


@check(
    "ENC-02", ENC, "EBS ボリュームの暗号化",
    "平文ボリュームはスナップショット共有やディスク廃棄時に内容が読み出せる。",
    "CIS AWS Foundations v3.0 2.2.1", HIGH, requires=("compute",),
)
def enc02_ebs_volumes(inv: dict) -> CheckResult:
    """volumes[].Encrypted を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, volume in enumerate(_dicts(inv, "compute", "volumes")):
        label = (
            f"{volume.get('VolumeId')}（{volume.get('VolumeType')} "
            f"{volume.get('Size')}GiB / {volume.get('State')}）"
        )
        (passed if volume.get("Encrypted") else failed).append(label)
        evidence.append(f"compute.volumes[{i}].Encrypted")

    return _finish(
        "EBS ボリュームの暗号化", passed, failed, evidence,
        "平文ボリュームは暗号化スナップショット経由で作り直す（スナップショット取得 → "
        "暗号化コピー → ボリューム作成 → 付け替え）。停止を伴うため計画停止に合わせること。",
        na_text="EBS ボリュームが存在しないため、評価対象外。",
    )


@check(
    "ENC-03", ENC, "EBS のアカウント既定暗号化",
    "既定暗号化が無効だと、今後作られるボリュームが平文のままになり再発する。",
    "CIS AWS Foundations v3.0 2.2.1 / AWS FSBP EC2.7", HIGH, requires=("compute",),
)
def enc03_ebs_default(inv: dict) -> CheckResult:
    """compute.ebs_encryption_by_default を見る（アカウント×リージョン単位の設定）。"""
    setting = _map(inv, "compute", "ebs_encryption_by_default")
    if not setting or "EbsEncryptionByDefault" not in setting:
        return _unknown(
            "EBS のアカウント既定暗号化設定（ec2:GetEbsEncryptionByDefault）", inv, ("ec2",),
            evidence=["compute.ebs_encryption_by_default"],
            remediation="コレクタを更新して再収集すること。",
        )

    region = _sect(inv, "meta").get("region") or "（リージョン不明）"
    kms = _map(inv, "compute", "ebs_default_kms_key_id").get("KmsKeyId")
    enabled = bool(setting.get("EbsEncryptionByDefault"))
    label = f"アカウント既定暗号化（{region}）"
    notes = []
    if kms:
        notes.append(f"既定の KMS キー: `{kms}`（AWS 管理キー `alias/aws/ebs` かどうかを確認すること）")

    return _finish(
        "EBS のアカウント既定暗号化",
        [label] if enabled else [],
        [] if enabled else [label],
        ["compute.ebs_encryption_by_default", "compute.ebs_default_kms_key_id"],
        "EC2 コンソールの「データ保護とセキュリティ」→「EBS の暗号化」でリージョンごとに"
        "既定暗号化を有効化する。既存ボリュームには影響しないため、ENC-02 の是正とは別に行う。",
        notes=notes,
    )


@check(
    "ENC-04", ENC, "EFS の暗号化",
    "EFS は共有ファイル置き場になりやすく、平文だと広範囲のデータが露出する。",
    "AWS FSBP EFS.1", HIGH, requires=("storage",),
)
def enc04_efs(inv: dict) -> CheckResult:
    """efs_file_systems[].Encrypted を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, fs in enumerate(_dicts(inv, "storage", "efs_file_systems")):
        label = f"{fs.get('Name') or '(名前なし)'} ({fs.get('FileSystemId')})"
        (passed if fs.get("Encrypted") else failed).append(label)
        evidence.append(f"storage.efs_file_systems[{i}].Encrypted")

    return _finish(
        "EFS の暗号化", passed, failed, evidence,
        "EFS の暗号化は作成時にしか指定できない。暗号化済みの新ファイルシステムを作り、"
        "AWS DataSync でコピーしてマウント先を切り替えること。",
        na_text="EFS ファイルシステムが存在しないため、評価対象外。",
    )


@check(
    "ENC-05", ENC, "S3 のデフォルト暗号化",
    "デフォルト暗号化が無いバケットは、暗号化指定なしで put されたオブジェクトが平文で残る。",
    "CIS AWS Foundations v3.0 2.1.1", MEDIUM, requires=("storage",),
)
def enc05_s3_encryption(inv: dict) -> CheckResult:
    """buckets[].Encryption を見る。SSE-S3（AES256）と SSE-KMS を区別する。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []
    sse_s3_only: list[str] = []

    for i, bucket in enumerate(_dicts(inv, "storage", "buckets")):
        name = str(bucket.get("Name"))
        evidence.append(f"storage.buckets[{i}].Encryption")
        rules = (bucket.get("Encryption") or {}).get("Rules") or []
        algorithms = {
            str(
                (rule.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm")
            )
            for rule in rules
            if isinstance(rule, dict)
        } - {"None"}
        if not algorithms:
            failed.append(f"{name}（デフォルト暗号化なし）")
            continue
        algorithm = "／".join(sorted(algorithms))
        passed.append(f"{name}（{algorithm}）")
        if algorithms == {"AES256"}:
            sse_s3_only.append(name)

    if sse_s3_only:
        notes.append(
            f"SSE-S3（AES256）のみのバケットが {len(sse_s3_only)} 件ある: "
            + "、".join(sse_s3_only[:10])
            + "。鍵の利用ログ（CloudTrail）と鍵単位のアクセス制御が要る場合は SSE-KMS へ切り替えること。"
        )

    return _finish(
        "S3 のデフォルト暗号化", passed, failed, evidence,
        "各バケットの「デフォルト暗号化」を SSE-S3 以上で有効化する"
        "（2023年以降の新規バケットは既定で SSE-S3 が有効）。",
        notes=notes,
        na_text="S3 バケットが存在しないため、評価対象外。",
    )


@check(
    "ENC-06", ENC, "CloudTrail ログの KMS 暗号化",
    "証跡は最も機微なログであり、KMS 暗号化しないと閲覧権限を鍵で絞れない。",
    "CIS AWS Foundations v3.0 3.5", MEDIUM, requires=("logging",),
)
def enc06_cloudtrail_kms(inv: dict) -> CheckResult:
    """cloudtrail_trails[].KmsKeyId を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, trail in enumerate(_dicts(inv, "logging", "cloudtrail_trails")):
        label = f"証跡 {trail.get('Name')}"
        (passed if trail.get("KmsKeyId") else failed).append(label)
        evidence.append(f"logging.cloudtrail_trails[{i}].KmsKeyId")

    return _finish(
        "CloudTrail ログの KMS 暗号化", passed, failed, evidence,
        "カスタマー管理 KMS キーを作り、証跡の設定で「SSE-KMS で暗号化」を指定する。"
        "キーポリシーで CloudTrail からの `kms:GenerateDataKey*` を許可すること。",
        na_text="CloudTrail 証跡が存在しないため、評価対象外（LOG-01 を参照）。",
    )


@check(
    "ENC-07", ENC, "SNS トピック / SQS キューの暗号化",
    "通知やジョブの本文に個人情報が載ることがあり、保管時に平文だと漏えい面が広がる。",
    "AWS FSBP SNS.1 / SQS.1", MEDIUM, requires=("serverless",),
)
def enc07_sns_sqs(inv: dict) -> CheckResult:
    """sns_topics / sqs_queues の Attributes に KmsMasterKeyId があるか見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []

    for i, topic in enumerate(_dicts(inv, "serverless", "sns_topics")):
        attributes = topic.get("Attributes") or {}
        arn = str(topic.get("TopicArn") or "")
        label = f"SNS {arn.rsplit(':', 1)[-1] or arn}"
        (passed if attributes.get("KmsMasterKeyId") else failed).append(label)
        evidence.append(f"serverless.sns_topics[{i}].Attributes.KmsMasterKeyId")

    for i, queue in enumerate(_dicts(inv, "serverless", "sqs_queues")):
        attributes = queue.get("Attributes") or {}
        url = str(queue.get("QueueUrl") or "")
        label = f"SQS {url.rsplit('/', 1)[-1] or url}"
        encrypted = bool(attributes.get("KmsMasterKeyId")) or str(
            attributes.get("SqsManagedSseEnabled")
        ).lower() == "true"
        (passed if encrypted else failed).append(label)
        evidence.append(f"serverless.sqs_queues[{i}].Attributes.KmsMasterKeyId")

    return _finish(
        "SNS / SQS の保管時暗号化", passed, failed, evidence,
        "SQS は「SQS 管理の暗号化（SSE-SQS）」を有効にすれば追加費用なしで対応できる。"
        "SNS は KMS キーを指定し、発行元サービスに `kms:GenerateDataKey*` を許可すること。",
        na_text="SNS トピック・SQS キューが存在しないため、評価対象外。",
    )


@check(
    "ENC-08", ENC, "EBS / RDS スナップショットの暗号化",
    "スナップショットは他アカウントへ共有できるため、平文だと共有事故が即座に漏えいになる。",
    "AWS FSBP EC2.3 / RDS.4", MEDIUM, requires=("compute", "database"),
)
def enc08_snapshots(inv: dict) -> CheckResult:
    """snapshots[].Encrypted と db_snapshots[].Encrypted を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    unknown: list[str] = []
    evidence: list[str] = []

    for i, snapshot in enumerate(_dicts(inv, "compute", "snapshots")):
        label = f"EBS スナップショット {snapshot.get('SnapshotId')}"
        evidence.append(f"compute.snapshots[{i}].Encrypted")
        if "Encrypted" not in snapshot:
            unknown.append(label)
        else:
            (passed if snapshot.get("Encrypted") else failed).append(label)

    for i, snapshot in enumerate(_dicts(inv, "database", "db_snapshots")):
        label = (
            f"RDS スナップショット {snapshot.get('DBSnapshotIdentifier')}"
            f"（{snapshot.get('SnapshotType')}）"
        )
        evidence.append(f"database.db_snapshots[{i}].Encrypted")
        if "Encrypted" not in snapshot:
            unknown.append(label)
        else:
            (passed if snapshot.get("Encrypted") else failed).append(label)

    if unknown and not passed and not failed:
        return _res(
            UNKNOWN,
            f"スナップショット {len(unknown)} 件に `Encrypted` フィールドが含まれておらず**判定不能**。"
            "収集時のレスポンスに暗号化状態が入っていない（コレクタの再実行が必要）。",
            evidence=evidence,
            remediation="`awsprobe collect` を再実行し、describe_snapshots / describe_db_snapshots の"
            "レスポンスをそのまま保存すること。",
            notes=[f"暗号化状態が不明なスナップショット: {len(unknown)} 件"],
        )

    notes = (
        [f"暗号化状態が取得できていないスナップショットが {len(unknown)} 件ある: "
         + "、".join(unknown[:5])]
        if unknown else []
    )
    return _finish(
        "スナップショットの暗号化", passed, failed, evidence,
        "平文スナップショットは暗号化コピーを作成したうえで元を削除する。"
        "ENC-02 / ENC-01 でボリューム・DB 本体を暗号化すれば、以後のスナップショットは自動で暗号化される。",
        notes=notes,
        na_text="スナップショットが存在しないため、評価対象外。",
    )


# ===========================================================================
# 2. 公開範囲（PUB）
# ===========================================================================


@check(
    "PUB-01", PUB, "S3 アカウントレベルのパブリックアクセスブロック",
    "アカウントレベルでブロックしておけば、個別バケットの設定ミスが公開事故に直結しない。",
    "CIS AWS Foundations v3.0 2.1.4", HIGH, requires=("security",),
)
def pub01_account_pab(inv: dict) -> CheckResult:
    """security.account_public_access_block の4項目すべてが true か見る。"""
    config = _sect(inv, "security").get("account_public_access_block")
    keys = (
        "BlockPublicAcls", "IgnorePublicAcls",
        "BlockPublicPolicy", "RestrictPublicBuckets",
    )
    if not isinstance(config, dict):
        denied = denied_for(inv, ("s3control", "s3"))
        if denied:
            return _unknown(
                "アカウントレベルのパブリックアクセスブロック", inv, ("s3control", "s3"),
                evidence=["security.account_public_access_block"],
            )
        # 未設定（NoSuchPublicAccessBlockConfiguration）も「未実施」として扱う
        return _res(
            NOT_DONE,
            "**アカウントレベルの S3 パブリックアクセスブロックが設定されていない。**"
            "各バケットの設定ミスがそのまま公開事故になる状態。",
            failed=["アカウント全体（未設定）"],
            evidence=["security.account_public_access_block"],
            remediation="S3 コンソールの「このアカウントのパブリックアクセスをブロック」で"
            "4項目すべてを有効にする。公開バケット（PUB-03 の注記）がある場合は"
            "CloudFront + OAC へ切り替えてからブロックすること。",
        )

    missing = [k for k in keys if not config.get(k)]
    enabled = [k for k in keys if config.get(k)]
    label = "アカウント全体"
    if not missing:
        return _finish(
            "アカウントレベルのパブリックアクセスブロック", [f"{label}（4項目すべて有効）"], [],
            ["security.account_public_access_block"], "",
        )
    return _res(
        PARTIAL if enabled else NOT_DONE,
        f"アカウントレベルのパブリックアクセスブロックは4項目中 {len(enabled)} 項目のみ有効で、"
        f"**{'、'.join(missing)} が無効**。",
        passed=[f"{label}: {', '.join(enabled)}"] if enabled else [],
        failed=[f"{label}: {', '.join(missing)} が無効"],
        evidence=["security.account_public_access_block"],
        remediation="S3 コンソールの「このアカウントのパブリックアクセスをブロック」で"
        "4項目すべてを有効にすること。",
    )


@check(
    "PUB-02", PUB, "S3 バケット単位のパブリックアクセスブロック",
    "バケット単位のブロックが無いと、ACL やポリシーの1行で全世界公開になる。",
    "CIS AWS Foundations v3.0 2.1.4", HIGH, requires=("storage",),
)
def pub02_bucket_pab(inv: dict) -> CheckResult:
    """buckets[].PublicAccessBlock の4項目を見る。Website 設定があるものは注記に回す。"""
    keys = (
        "BlockPublicAcls", "IgnorePublicAcls",
        "BlockPublicPolicy", "RestrictPublicBuckets",
    )
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, bucket in enumerate(_dicts(inv, "storage", "buckets")):
        name = str(bucket.get("Name"))
        evidence.append(f"storage.buckets[{i}].PublicAccessBlock")
        config = bucket.get("PublicAccessBlock")
        intentional = bool(bucket.get("Website"))
        if not isinstance(config, dict):
            if intentional:
                notes.append(
                    f"{name}: 静的ウェブサイトホスティングが有効なため、"
                    "パブリックアクセスブロック未設定は**意図的な公開の可能性**がある（要確認）"
                )
                continue
            failed.append(f"{name}（パブリックアクセスブロック未設定）")
            continue
        missing = [k for k in keys if not config.get(k)]
        if missing:
            if intentional:
                notes.append(
                    f"{name}: 静的ウェブサイト用バケットで {', '.join(missing)} が無効"
                    "（**意図的な公開の可能性**・要確認）"
                )
                continue
            failed.append(f"{name}（{', '.join(missing)} が無効）")
        else:
            passed.append(name)

    return _finish(
        "S3 バケット単位のパブリックアクセスブロック", passed, failed, evidence,
        "公開が不要なバケットは4項目すべてを有効にする。意図的に公開しているバケットは"
        "CloudFront + OAC 経由に切り替え、バケット自体は非公開にすること。",
        notes=notes,
        na_text="S3 バケットが存在しないため、評価対象外。",
    )


@check(
    "PUB-03", PUB, "バケットポリシーによる公開",
    "ポリシーで公開されたバケットは、誰でも一覧・取得できる状態にある。",
    "AWS FSBP S3.2 / S3.6", CRITICAL, requires=("storage",),
)
def pub03_bucket_policy_public(inv: dict) -> CheckResult:
    """buckets[].PolicyStatus.IsPublic を見る。Website 設定があるものは failed に入れない。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, bucket in enumerate(_dicts(inv, "storage", "buckets")):
        name = str(bucket.get("Name"))
        evidence.append(f"storage.buckets[{i}].PolicyStatus")
        status = bucket.get("PolicyStatus")
        is_public = bool(isinstance(status, dict) and status.get("IsPublic"))
        if not is_public:
            passed.append(name)
            continue
        if bucket.get("Website"):
            notes.append(
                f"{name}: **静的ウェブサイトホスティングが有効なバケットがポリシーで公開されている**。"
                "意図的な公開の可能性が高いため failed には数えないが、"
                "「本当に全世界に公開してよい内容か」「CloudFront + OAC に移せないか」を必ず確認すること。"
            )
            continue
        failed.append(f"{name}（バケットポリシーで公開）")

    return _finish(
        "バケットポリシーによる公開", passed, failed, evidence,
        "公開が不要なバケットは公開ポリシーを削除し、パブリックアクセスブロックを有効にする。"
        "配信が必要な場合は CloudFront + OAC に切り替えること。",
        notes=notes,
        na_text="S3 バケットが存在しないため、評価対象外。",
    )


@check(
    "PUB-04", PUB, "RDS の PubliclyAccessible",
    "パブリックアクセス可能な DB はインターネットから直接到達でき、総当たり攻撃を受ける。",
    "CIS AWS Foundations v3.0 2.3.3", CRITICAL, requires=("database",),
)
def pub04_rds_public(inv: dict) -> CheckResult:
    """db_instances[].PubliclyAccessible を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, db in enumerate(_dicts(inv, "database", "db_instances")):
        label = f"RDS {db.get('DBInstanceIdentifier')}"
        if db.get("PubliclyAccessible"):
            failed.append(f"{label}（PubliclyAccessible=true）")
        else:
            passed.append(label)
        evidence.append(f"database.db_instances[{i}].PubliclyAccessible")

    return _finish(
        "RDS のパブリックアクセス禁止", passed, failed, evidence,
        "対象インスタンスの「パブリックアクセス可能」を「なし」に変更する"
        "（再起動なしで適用可能）。踏み台または VPN 経由の接続に切り替えること。",
        na_text="RDS インスタンスが存在しないため、評価対象外。",
    )


@check(
    "PUB-05", PUB, "EC2 のパブリック IP 付与",
    "パブリック IP を持つ EC2 はセキュリティグループだけが唯一の防壁になる。",
    "AWS FSBP EC2.9", HIGH, requires=("compute",),
)
def pub05_ec2_public_ip(inv: dict) -> CheckResult:
    """instances[].PublicIpAddress の有無を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, instance in enumerate(_dicts(inv, "compute", "instances")):
        if str((instance.get("State") or {}).get("Name")) == "terminated":
            continue
        label = _instance_label(instance)
        public_ip = instance.get("PublicIpAddress")
        if public_ip:
            failed.append(f"{label} パブリックIP付与あり")
        else:
            passed.append(label)
        evidence.append(f"compute.instances[{i}].PublicIpAddress")

    return _finish(
        "EC2 のパブリック IP 非付与", passed, failed, evidence,
        "プライベートサブネットへ移し、外向き通信は NAT Gateway 経由にする。"
        "管理接続は SSM Session Manager または EC2 Instance Connect Endpoint に切り替えること。",
        na_text="EC2 インスタンスが存在しないため、評価対象外。",
    )


@check(
    "PUB-06", PUB, "EBS / RDS スナップショットの公開共有",
    "公開共有されたスナップショットは誰でも復元でき、DB の中身がそのまま渡る。",
    "AWS FSBP EC2.1 / RDS.1", CRITICAL, requires=("compute", "database"),
)
def pub06_snapshot_sharing(inv: dict) -> CheckResult:
    """スナップショットの公開共有状態を見る（収集されていなければ判定不能）。"""
    passed: list[str] = []
    failed: list[str] = []
    unknown: list[str] = []
    evidence: list[str] = []

    for i, snapshot in enumerate(_dicts(inv, "compute", "snapshots")):
        label = f"EBS スナップショット {snapshot.get('SnapshotId')}"
        evidence.append(f"compute.snapshots[{i}]")
        permissions = snapshot.get("CreateVolumePermissions")
        if "Public" in snapshot:
            (failed if snapshot.get("Public") else passed).append(label)
        elif isinstance(permissions, list):
            shared = any(
                isinstance(p, dict) and p.get("Group") == "all" for p in permissions
            )
            (failed if shared else passed).append(label)
        else:
            unknown.append(label)

    for i, snapshot in enumerate(_dicts(inv, "database", "db_snapshots")):
        label = f"RDS スナップショット {snapshot.get('DBSnapshotIdentifier')}"
        evidence.append(f"database.db_snapshots[{i}]")
        if "_IsPublic" in snapshot:
            (failed if snapshot.get("_IsPublic") else passed).append(label)
        else:
            unknown.append(label)

    if unknown and not passed and not failed:
        return _res(
            UNKNOWN,
            f"スナップショット {len(unknown)} 件について公開共有状態が収集されておらず**判定不能**。"
            "`ec2:DescribeSnapshotAttribute`（createVolumePermission）と "
            "`rds:DescribeDBSnapshotAttributes` はどちらも現行のコレクタでは呼んでいない。",
            evidence=evidence,
            remediation="公開共有の有無はスナップショット単位の追加 API が必要。"
            "コレクタに DescribeSnapshotAttribute / DescribeDBSnapshotAttributes を追加するか、"
            "AWS Config ルール（`ebs-snapshot-public-restorable-check`）で継続監視すること。",
            notes=[f"公開共有状態が不明なスナップショット: {len(unknown)} 件"],
        )

    notes = (
        [f"公開共有状態が取得できていないスナップショットが {len(unknown)} 件ある"]
        if unknown else []
    )
    return _finish(
        "スナップショットの公開共有禁止", passed, failed, evidence,
        "公開共有を直ちに解除する（`ModifySnapshotAttribute` で `all` グループを削除）。"
        "AWS Config ルールで再発を監視すること。",
        notes=notes,
        na_text="スナップショットが存在しないため、評価対象外。",
    )


@check(
    "PUB-07", PUB, "AMI の公開共有",
    "公開 AMI にはアプリのコードや埋め込み認証情報がそのまま含まれていることがある。",
    "AWS Foundational Security Best Practices（AMI を公開しない）", HIGH,
    requires=("compute",),
)
def pub07_ami_public(inv: dict) -> CheckResult:
    """images[].Public を見る（自アカウント所有 AMI が対象）。"""
    account_id = _account_id(inv)
    passed: list[str] = []
    failed: list[str] = []
    unknown: list[str] = []
    evidence: list[str] = []

    for i, image in enumerate(_dicts(inv, "compute", "images")):
        owner = str(image.get("OwnerId") or "")
        if account_id and owner and owner != account_id:
            continue  # 他アカウント／Amazon 所有の AMI は自分では直せないため対象外
        label = f"{image.get('Name') or '(名前なし)'} ({image.get('ImageId')})"
        evidence.append(f"compute.images[{i}].Public")
        if "Public" not in image:
            unknown.append(label)
        else:
            (failed if image.get("Public") else passed).append(label)

    if unknown and not passed and not failed:
        return _res(
            UNKNOWN,
            f"自アカウント所有 AMI {len(unknown)} 件に `Public` フィールドが含まれておらず**判定不能**。"
            "`describe_images` のレスポンスに公開状態が入っていない。",
            evidence=evidence,
            remediation="`awsprobe collect` を再実行して describe_images のレスポンスを"
            "そのまま保存すること。",
            notes=[f"公開状態が不明な AMI: {len(unknown)} 件"],
        )

    notes = [f"公開状態が取得できていない AMI が {len(unknown)} 件ある"] if unknown else []
    return _finish(
        "AMI の公開共有禁止", passed, failed, evidence,
        "公開されている AMI の launchPermission から `all` を削除する。"
        "削除前に、その AMI がどこで使われているか（他アカウント含む）を確認すること。",
        notes=notes,
        na_text="自アカウント所有の AMI が存在しないため、評価対象外。",
    )


# ===========================================================================
# 3. ネットワーク（NET）
# ===========================================================================


def _world_open_ports(sg: dict) -> tuple[list[str], list[str], list[str], bool]:
    """SG の ingress のうち 0.0.0.0/0（::/0）に開いているものをポート種別に分ける。

    戻り値: (管理・DBポート, Webポート, その他ポート, 全ポート開放か)
    """
    admin: list[str] = []
    web: list[str] = []
    other: list[str] = []
    all_ports = False

    for perm in sg.get("IpPermissions") or []:
        if not isinstance(perm, dict):
            continue
        if not any(is_open_to_world(s) for s in perm_sources(perm)):
            continue
        protocol = str(perm.get("IpProtocol"))
        if protocol == "-1" or (
            perm.get("FromPort") is None and perm.get("ToPort") is None
        ):
            all_ports = True
            continue
        matched = False
        for port, name in ADMIN_PORTS.items():
            if perm_covers_port(perm, port):
                admin.append(f"{port}({name})")
                matched = True
        for port, name in WEB_PORTS.items():
            if perm_covers_port(perm, port):
                web.append(f"{port}({name})")
                matched = True
        if not matched:
            other.append(port_label(perm))

    return (sorted(set(admin)), sorted(set(web)), sorted(set(other)), all_ports)


@check(
    "NET-01", NET, "セキュリティグループの 0.0.0.0/0 開放（管理・DB ポート）",
    "SSH・RDP・DB ポートの全世界開放は、総当たり攻撃と既知脆弱性の入口になる。",
    "CIS AWS Foundations v3.0 5.2 / 5.3", CRITICAL, requires=("network",),
)
def net01_sg_world_open(inv: dict) -> CheckResult:
    """SG ごとに 0.0.0.0/0 開放をポート別に評価する。

    管理・DB ポート（22/3389/3306/5432/1433/27017/6379 等）と全ポート開放は失格。
    80/443 のみの開放は Web サービスの入口として許容し、注記に回す。
    """
    groups = _dicts(inv, "network", "security_groups")
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    web_only: list[str] = []
    for i, sg in enumerate(groups):
        label = f"{sg.get('GroupName') or '(名前なし)'} ({sg.get('GroupId')})"
        evidence.append(f"network.security_groups[{i}].IpPermissions")
        admin, web, other, all_ports = _world_open_ports(sg)
        if all_ports:
            failed.append(f"{label}: **全プロトコル/全ポートを 0.0.0.0/0 に開放**")
            continue
        if admin:
            failed.append(f"{label}: 管理・DBポート {', '.join(admin)} を 0.0.0.0/0 に開放")
            continue
        passed.append(label)
        if web:
            web_only.append(f"{label}: {', '.join(web)}")
        if other:
            notes.append(
                f"{label}: 管理ポートではないが {', '.join(other)} を 0.0.0.0/0 に開放している"
                "（用途を確認すること）"
            )

    if web_only:
        notes.insert(
            0,
            "**意図的な公開として許容**した 80/443 のみの全世界開放: "
            + "／".join(web_only[:10])
            + "。Web サービスの入口として妥当かは WAF（NET-10）と併せて判断すること。",
        )

    return _finish(
        "セキュリティグループの管理・DB ポート全世界開放", passed, failed, evidence,
        "0.0.0.0/0 からの SSH/RDP/DB 接続を削除し、送信元を保守拠点の固定 IP か"
        "プレフィックスリストに限定する。恒久対策は SSM Session Manager への移行。",
        notes=notes,
        na_text="セキュリティグループが存在しないため、評価対象外。",
    )


@check(
    "NET-02", NET, "デフォルトセキュリティグループの未使用化",
    "デフォルト SG は「同じ SG 内なら全通信許可」で、使い続けると意図しない横移動を許す。",
    "CIS AWS Foundations v3.0 5.4", MEDIUM, requires=("network",),
)
def net02_default_sg(inv: dict) -> CheckResult:
    """GroupName == "default" の SG がルールを持たず、どこからも参照されていないか見る。"""
    groups = [
        (i, sg)
        for i, sg in enumerate(_dicts(inv, "network", "security_groups"))
        if str(sg.get("GroupName")) == "default"
    ]
    if not groups:
        return _res(
            NOT_APPLICABLE,
            "デフォルトセキュリティグループが収集結果に含まれていないため、評価対象外。",
            evidence=["network.security_groups"],
        )

    attached: set[str] = set()
    for eni in _dicts(inv, "network", "network_interfaces"):
        for group in eni.get("Groups") or []:
            if isinstance(group, dict) and group.get("GroupId"):
                attached.add(str(group["GroupId"]))
    for instance in _dicts(inv, "compute", "instances"):
        for group in instance.get("SecurityGroups") or []:
            if isinstance(group, dict) and group.get("GroupId"):
                attached.add(str(group["GroupId"]))

    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, sg in groups:
        group_id = str(sg.get("GroupId"))
        label = f"デフォルト SG {group_id}（VPC {sg.get('VpcId')}）"
        evidence.append(f"network.security_groups[{i}]")
        reasons: list[str] = []
        if sg.get("IpPermissions"):
            reasons.append("インバウンドルールが残っている")
        if sg.get("IpPermissionsEgress"):
            reasons.append("アウトバウンドルールが残っている")
        if group_id in attached:
            reasons.append("リソースに割り当てられている")
        if reasons:
            failed.append(f"{label}: {'／'.join(reasons)}")
        else:
            passed.append(label)

    return _finish(
        "デフォルトセキュリティグループの未使用化", passed, failed, evidence,
        "デフォルト SG の全インバウンド・アウトバウンドルールを削除し、"
        "割り当て済みリソースは用途別の SG へ付け替えること。",
    )


@check(
    "NET-03", NET, "ネットワーク ACL の全許可",
    "NACL がサブネット全体の最後の砦であり、全許可のままだと多層防御が1層しかない。",
    "CIS AWS Foundations v3.0 5.1", LOW, requires=("network",),
)
def net03_nacl(inv: dict) -> CheckResult:
    """NACL の ingress に 0.0.0.0/0 からの全許可エントリがあるか見る。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, nacl in enumerate(_dicts(inv, "network", "network_acls")):
        label = f"NACL {nacl.get('NetworkAclId')}"
        if nacl.get("IsDefault"):
            label += "（デフォルト）"
        evidence.append(f"network.network_acls[{i}].Entries")
        open_entries = [
            entry
            for entry in nacl.get("Entries") or []
            if isinstance(entry, dict)
            and not entry.get("Egress")
            and entry.get("RuleAction") == "allow"
            and str(entry.get("CidrBlock") or entry.get("Ipv6CidrBlock") or "")
            in ("0.0.0.0/0", "::/0")
            and str(entry.get("Protocol")) == "-1"
        ]
        if open_entries:
            failed.append(
                f"{label}: 0.0.0.0/0 からの全プロトコル許可エントリが "
                f"{len(open_entries)} 件（関連サブネット {len(nacl.get('Associations') or [])} 本）"
            )
            if nacl.get("IsDefault"):
                notes.append(
                    f"{label} は AWS 既定で全許可。**NACL を絞るかどうかは設計判断**であり、"
                    "セキュリティグループ（NET-01）で制御できていれば直ちに危険とは限らない。"
                )
        else:
            passed.append(label)

    return _finish(
        "ネットワーク ACL の全許可の見直し", passed, failed, evidence,
        "最低限、管理ポート（22/3389）への 0.0.0.0/0 からの ingress を deny するエントリを"
        "追加する。ステートレスな評価のため、戻りの一時ポートを塞がないよう注意すること。",
        notes=notes,
        na_text="ネットワーク ACL が存在しないため、評価対象外。",
    )


@check(
    "NET-04", NET, "VPC フローログの有効化",
    "フローログが無いと、侵害後にどこから何が通信したかを一切追跡できない。",
    "CIS AWS Foundations v3.0 3.7", HIGH, requires=("network", "logging"),
)
def net04_flow_logs(inv: dict) -> CheckResult:
    """VPC ごとにフローログが有効か見る。"""
    flow_logs = _dicts(inv, "logging", "flow_logs")
    active_resources = {
        str(fl.get("ResourceId"))
        for fl in flow_logs
        if str(fl.get("FlowLogStatus") or "").upper() == "ACTIVE"
    }
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = ["logging.flow_logs"]

    for i, vpc in enumerate(_dicts(inv, "network", "vpcs")):
        vpc_id = str(vpc.get("VpcId"))
        label = f"{_tag(vpc) or 'VPC'} ({vpc_id})"
        (passed if vpc_id in active_resources else failed).append(label)
        evidence.append(f"network.vpcs[{i}].VpcId")

    return _finish(
        "VPC フローログの有効化", passed, failed, evidence,
        "各 VPC でフローログを有効化し、S3 または CloudWatch Logs に出力する。"
        "保持期間とライフサイクル（LOG-09）も併せて設定すること。",
        na_text="VPC が存在しないため、評価対象外。",
    )


@check(
    "NET-05", NET, "未使用のセキュリティグループ・EIP・ENI",
    "未使用資源は棚卸し漏れの温床で、誤って再利用されると想定外の経路ができる。",
    "AWS FSBP EC2.12 / EC2.22", LOW, requires=("network",),
)
def net05_unused(inv: dict) -> CheckResult:
    """どこからも参照されていない SG、未関連付けの EIP、available 状態の ENI を洗い出す。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence = [
        "network.security_groups", "network.elastic_ips", "network.network_interfaces",
    ]

    # -- 参照されている SG を集める --------------------------------------
    referenced: set[str] = set()
    for eni in _dicts(inv, "network", "network_interfaces"):
        for group in eni.get("Groups") or []:
            if isinstance(group, dict) and group.get("GroupId"):
                referenced.add(str(group["GroupId"]))
    for instance in _dicts(inv, "compute", "instances"):
        for group in instance.get("SecurityGroups") or []:
            if isinstance(group, dict) and group.get("GroupId"):
                referenced.add(str(group["GroupId"]))
    for db in _dicts(inv, "database", "db_instances"):
        for group in db.get("VpcSecurityGroups") or []:
            if isinstance(group, dict) and group.get("VpcSecurityGroupId"):
                referenced.add(str(group["VpcSecurityGroupId"]))
    for lb in _dicts(inv, "edge", "load_balancers"):
        for group_id in lb.get("SecurityGroups") or []:
            referenced.add(str(group_id))
    for function in _dicts(inv, "serverless", "lambda_functions"):
        for group_id in (function.get("VpcConfig") or {}).get("SecurityGroupIds") or []:
            referenced.add(str(group_id))
    # 他の SG のルールから参照されているものも「使用中」とみなす
    for sg in _dicts(inv, "network", "security_groups"):
        for key in ("IpPermissions", "IpPermissionsEgress"):
            for perm in sg.get(key) or []:
                if not isinstance(perm, dict):
                    continue
                for pair in perm.get("UserIdGroupPairs") or []:
                    if isinstance(pair, dict) and pair.get("GroupId"):
                        referenced.add(str(pair["GroupId"]))

    for sg in _dicts(inv, "network", "security_groups"):
        group_id = str(sg.get("GroupId"))
        label = f"SG {sg.get('GroupName') or '(名前なし)'} ({group_id})"
        if group_id in referenced:
            passed.append(label)
        else:
            failed.append(f"{label}: どこからも参照されていない")

    for eip in _dicts(inv, "network", "elastic_ips"):
        label = f"EIP {eip.get('PublicIp')} ({eip.get('AllocationId')})"
        in_use = bool(
            eip.get("AssociationId") or eip.get("NetworkInterfaceId") or eip.get("InstanceId")
        )
        if in_use:
            passed.append(label)
        else:
            failed.append(f"{label}: 未関連付け（課金のみ発生）")

    for eni in _dicts(inv, "network", "network_interfaces"):
        label = f"ENI {eni.get('NetworkInterfaceId')}（{eni.get('Description') or '説明なし'}）"
        if str(eni.get("Status")) == "available":
            failed.append(f"{label}: 未接続のまま残っている")
        else:
            passed.append(label)

    return _finish(
        "未使用のセキュリティグループ・EIP・ENI の棚卸し", passed, failed, evidence,
        "未使用リソースは用途を確認のうえ削除する。特に未関連付けの EIP は課金が続くため"
        "優先して解放すること（削除前に DNS 参照が無いことを確認する）。",
        na_text="対象となるネットワークリソースが存在しないため、評価対象外。",
    )


@check(
    "NET-06", NET, "EC2 の IMDSv2 必須化",
    "IMDSv1 が有効だと SSRF 一発でインスタンスロールの一時認証情報が盗まれる。",
    "CIS AWS Foundations v3.0 5.6 / AWS FSBP EC2.8", CRITICAL, requires=("compute",),
)
def net06_imdsv2(inv: dict) -> CheckResult:
    """instances[].MetadataOptions.HttpTokens == "required" を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, instance in enumerate(_dicts(inv, "compute", "instances")):
        if str((instance.get("State") or {}).get("Name")) == "terminated":
            continue
        options = instance.get("MetadataOptions") or {}
        label = _instance_label(instance)
        evidence.append(f"compute.instances[{i}].MetadataOptions.HttpTokens")
        tokens = str(options.get("HttpTokens") or "")
        if str(options.get("HttpEndpoint")) == "disabled":
            passed.append(f"{label}: IMDS 自体が無効")
            continue
        if tokens == "required":
            passed.append(label)
        elif tokens:
            failed.append(f"{label}: HttpTokens={tokens}（IMDSv1 が使える）")
        else:
            failed.append(f"{label}: MetadataOptions が未取得／未設定")
        if options.get("HttpPutResponseHopLimit") not in (None, 1) and tokens == "required":
            notes.append(
                f"{label}: HopLimit={options.get('HttpPutResponseHopLimit')}。"
                "コンテナから IMDS に届く設定なので、必要が無ければ 1 に戻すこと。"
            )

    return _finish(
        "EC2 の IMDSv2 必須化", passed, failed, evidence,
        "`modify-instance-metadata-options --http-tokens required` で再起動なしに切り替えられる。"
        "古い SDK / メタデータ取得スクリプトが IMDSv1 を使っていないか、"
        "CloudWatch の `MetadataNoToken` メトリクスで事前確認すること。",
        notes=notes,
        na_text="EC2 インスタンスが存在しないため、評価対象外。",
    )


@check(
    "NET-07", NET, "ALB リスナーの TLS ポリシー世代",
    "旧世代ポリシーは TLS 1.0/1.1 を許容し、PCI DSS 等の基準を満たさない。",
    "AWS FSBP ELB.8 / ELB.17", MEDIUM, requires=("edge",),
)
def net07_tls_policy(inv: dict) -> CheckResult:
    """HTTPS/TLS リスナーの SslPolicy を現行世代と突き合わせる。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, listener in enumerate(_dicts(inv, "edge", "listeners")):
        protocol = str(listener.get("Protocol") or "").upper()
        if protocol not in ("HTTPS", "TLS"):
            continue
        arn = str(listener.get("LoadBalancerArn") or "")
        label = f"{arn.rsplit('/', 2)[-2] if '/' in arn else arn}:{listener.get('Port')}"
        policy = listener.get("SslPolicy")
        evidence.append(f"edge.listeners[{i}].SslPolicy")
        if not policy:
            notes.append(f"{label}: SslPolicy が未取得のため世代を判定できない")
            continue
        policy = str(policy)
        if policy in MODERN_SSL_POLICIES:
            passed.append(f"{label}（{policy}）")
        elif policy in LEGACY_SSL_POLICIES:
            failed.append(f"{label}: **旧世代ポリシー {policy}**（TLS 1.0/1.1 を許容）")
        else:
            passed.append(f"{label}（{policy}・一覧未収載）")
            notes.append(
                f"{label}: `{policy}` は本ツールの現行世代一覧に無い。"
                "AWS のドキュメントで対応プロトコルを確認すること。"
            )

    return _finish(
        "ALB リスナーの TLS ポリシー世代", passed, failed, evidence,
        "リスナーのセキュリティポリシーを `ELBSecurityPolicy-TLS13-1-2-2021-06` 等の"
        "現行世代へ変更する。古い端末からの接続実績を ALB アクセスログで確認してから切り替えること。",
        notes=notes,
        na_text="HTTPS/TLS リスナーが存在しないため、評価対象外。",
    )


@check(
    "NET-08", NET, "ALB の HTTP → HTTPS リダイレクト",
    "80 番が素通しだと、平文で送られた Cookie やトークンが盗聴される。",
    "AWS FSBP ELB.1", MEDIUM, requires=("edge",),
)
def net08_http_redirect(inv: dict) -> CheckResult:
    """ポート80のリスナーの DefaultActions が redirect（HTTPS 宛）か見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []

    for i, listener in enumerate(_dicts(inv, "edge", "listeners")):
        if listener.get("Port") != 80 and str(listener.get("Protocol") or "").upper() != "HTTP":
            continue
        if listener.get("Port") != 80:
            continue
        arn = str(listener.get("LoadBalancerArn") or "")
        label = f"{arn.rsplit('/', 2)[-2] if '/' in arn else arn}:80"
        evidence.append(f"edge.listeners[{i}].DefaultActions")
        actions = [a for a in listener.get("DefaultActions") or [] if isinstance(a, dict)]
        redirect = next((a for a in actions if a.get("Type") == "redirect"), None)
        if redirect is None:
            types = "、".join(sorted({str(a.get("Type")) for a in actions})) or "アクションなし"
            failed.append(f"{label}: 既定アクションが {types}（リダイレクトではない）")
            continue
        config = redirect.get("RedirectConfig") or {}
        if str(config.get("Protocol") or "").upper() in ("HTTPS", "#{PROTOCOL}", ""):
            passed.append(f"{label}（{config.get('StatusCode') or 'HTTP_301'} リダイレクト）")
        else:
            failed.append(f"{label}: リダイレクト先が {config.get('Protocol')}")

    return _finish(
        "ALB の HTTP → HTTPS リダイレクト", passed, failed, evidence,
        "80 番リスナーの既定アクションを「HTTPS:443 へ HTTP_301 リダイレクト」に変更する。"
        "HSTS ヘッダの付与もアプリ側で併せて検討すること。",
        na_text="ポート80のリスナーが存在しないため、評価対象外（そもそも平文の入口が無い）。",
    )


@check(
    "NET-09", NET, "ALB の削除保護",
    "削除保護が無いと、誤操作ひとつで本番の入口が消えてサービスが止まる。",
    "AWS FSBP ELB.6", LOW, requires=("edge",),
)
def net09_deletion_protection(inv: dict) -> CheckResult:
    """load_balancers[].Attributes の deletion_protection.enabled を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, lb in enumerate(_dicts(inv, "edge", "load_balancers")):
        label = f"{_lb_name(lb)}（{lb.get('Type')}／{lb.get('Scheme')}）"
        evidence.append(f"edge.load_balancers[{i}].Attributes")
        value = _attr(lb, "deletion_protection.enabled")
        if str(value).lower() == "true":
            passed.append(label)
        else:
            failed.append(f"{label}: deletion_protection.enabled={value or '未設定'}")

    return _finish(
        "ALB の削除保護", passed, failed, evidence,
        "本番系のロードバランサは削除保護を有効にする。"
        "検証・一時利用のものは対象外としてよいが、その判断を台帳に残すこと。",
        na_text="ロードバランサが存在しないため、評価対象外。",
    )


@check(
    "NET-10", NET, "WAF の関連付け（ALB / CloudFront）",
    "公開エンドポイントに WAF が無いと、SQLi や大量リクエストをアプリ層で受け切ることになる。",
    "AWS FSBP CloudFront.6 / WAF（ALB 関連付け）", HIGH, requires=("edge",),
)
def net10_waf(inv: dict) -> CheckResult:
    """WAFv2 Web ACL の関連付けをインターネット向け ALB と CloudFront で見る。"""
    associated: set[str] = set()
    for acl in _dicts(inv, "edge", "wafv2_web_acls"):
        for arn in acl.get("AssociatedResourceArns") or []:
            if isinstance(arn, str):
                associated.add(arn)

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = ["edge.wafv2_web_acls"]

    for i, lb in enumerate(_dicts(inv, "edge", "load_balancers")):
        if str(lb.get("Type")) != "application":
            continue
        if str(lb.get("Scheme")) != "internet-facing":
            continue
        arn = str(lb.get("LoadBalancerArn") or "")
        label = f"ALB {_lb_name(lb)}"
        evidence.append(f"edge.load_balancers[{i}].LoadBalancerArn")
        (passed if arn in associated else failed).append(label)

    for i, dist in enumerate(_dicts(inv, "edge", "cloudfront_distributions")):
        aliases = (dist.get("Aliases") or {}).get("Items") or []
        label = f"CloudFront {dist.get('Id')}（{', '.join(str(a) for a in aliases) or dist.get('DomainName')}）"
        evidence.append(f"edge.cloudfront_distributions[{i}].WebACLId")
        (passed if dist.get("WebACLId") else failed).append(label)

    if not _dicts(inv, "edge", "wafv2_web_acls") and (passed or failed):
        notes.append(
            "WAFv2 Web ACL がこのアカウントに1件も存在しない。"
            "CLOUDFRONT スコープの関連付けは `cloudfront_distributions[].WebACLId` で判定している。"
        )

    return _finish(
        "WAF の関連付け", passed, failed, evidence,
        "AWS マネージドルール（Core rule set / Known bad inputs）を有効にした Web ACL を作り、"
        "インターネット向け ALB と CloudFront に関連付ける。まず COUNT モードで誤検知を確認すること。",
        notes=notes,
        na_text="インターネット向け ALB も CloudFront も存在しないため、評価対象外。",
    )


@check(
    "NET-11", NET, "CloudFront の Viewer Protocol Policy と最小 TLS バージョン",
    "HTTP を許可したままの配信は、経路上でコンテンツを改ざん・盗聴されうる。",
    "AWS FSBP CloudFront.3 / CloudFront.10", MEDIUM, requires=("edge",),
)
def net11_cloudfront_tls(inv: dict) -> CheckResult:
    """DefaultCacheBehavior.ViewerProtocolPolicy と ViewerCertificate.MinimumProtocolVersion を見る。"""
    distributions = _dicts(inv, "edge", "cloudfront_distributions")
    if not distributions:
        return _res(
            NOT_APPLICABLE,
            "CloudFront ディストリビューションが存在しないため、評価対象外。",
            evidence=["edge.cloudfront_distributions"],
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []
    unknown: list[str] = []

    for i, dist in enumerate(distributions):
        label = f"CloudFront {dist.get('Id')}"
        evidence.append(f"edge.cloudfront_distributions[{i}].DefaultCacheBehavior")
        config = dist.get("DistributionConfig") if isinstance(dist.get("DistributionConfig"), dict) else {}
        behavior = dist.get("DefaultCacheBehavior") or config.get("DefaultCacheBehavior") or {}
        certificate = dist.get("ViewerCertificate") or config.get("ViewerCertificate") or {}
        policy = str((behavior or {}).get("ViewerProtocolPolicy") or "")
        minimum = str((certificate or {}).get("MinimumProtocolVersion") or "")

        if not policy and not minimum:
            unknown.append(label)
            continue
        reasons: list[str] = []
        if policy and policy not in ("redirect-to-https", "https-only"):
            reasons.append(f"ViewerProtocolPolicy={policy}")
        if minimum and not re.search(r"TLSv1\.2|TLSv1\.3", minimum):
            reasons.append(f"MinimumProtocolVersion={minimum}")
        if reasons:
            failed.append(f"{label}: {'／'.join(reasons)}")
        else:
            passed.append(f"{label}（{policy or '取得なし'}／{minimum or '取得なし'}）")

    if unknown and not passed and not failed:
        return _res(
            UNKNOWN,
            f"CloudFront {len(unknown)} 本について `DefaultCacheBehavior` / `ViewerCertificate` が"
            "収集されておらず**判定不能**。`cloudfront:GetDistributionConfig` の結果に"
            "これらが含まれていない。",
            evidence=evidence,
            remediation="コレクタで GetDistributionConfig のレスポンス（DistributionConfig 全体）を"
            "保存するよう変更して再収集すること。",
            notes=[f"設定が取得できていないディストリビューション: {len(unknown)} 本"],
        )

    if unknown:
        notes.append(f"設定が取得できていないディストリビューションが {len(unknown)} 本ある")

    return _finish(
        "CloudFront の HTTPS 強制", passed, failed, evidence,
        "Viewer Protocol Policy を `redirect-to-https` にし、最小 TLS バージョンを"
        "`TLSv1.2_2021` に引き上げること。",
        notes=notes,
    )


# ===========================================================================
# 4. IAM・認証（IAM）
# ===========================================================================


def _summary_flag(inv: dict, key: str) -> Any:
    """iam.account_summary の値を取り出す（未収集なら None）。"""
    return _iam(inv).get("account_summary", {}).get(key) if isinstance(
        _iam(inv).get("account_summary"), dict
    ) else None


@check(
    "IAM-01", IAM, "ルートユーザーの MFA",
    "ルートは全権限を持ち、MFA が無いとパスワード漏えいだけでアカウントを乗っ取られる。",
    "CIS AWS Foundations v3.0 1.5", CRITICAL, requires=("security",),
)
def iam01_root_mfa(inv: dict) -> CheckResult:
    """account_summary.AccountMFAEnabled を見る。"""
    value = _summary_flag(inv, "AccountMFAEnabled")
    if value is None:
        return _unknown(
            "ルートユーザーの MFA 有効状況（iam:GetAccountSummary の AccountMFAEnabled）",
            inv, ("iam",),
            evidence=["security.iam.account_summary.AccountMFAEnabled"],
            remediation="`iam:GetAccountSummary` の権限を付けて再収集すること。",
        )
    enabled = bool(value)
    label = "ルートユーザー"
    return _finish(
        "ルートユーザーの MFA", [label] if enabled else [], [] if enabled else [label],
        ["security.iam.account_summary.AccountMFAEnabled"],
        "ルートでサインインし、ハードウェア MFA（推奨）または仮想 MFA を登録する。"
        "登録後はルート認証情報を金庫等に封印し、日常運用では使わないこと。",
    )


@check(
    "IAM-02", IAM, "ルートユーザーのアクセスキー",
    "ルートのアクセスキーは失効も権限縮小もできず、漏えいすれば即座に全権限が渡る。",
    "CIS AWS Foundations v3.0 1.4", CRITICAL, requires=("security",),
)
def iam02_root_keys(inv: dict) -> CheckResult:
    """account_summary.AccountAccessKeysPresent を見る（0 が正常）。"""
    value = _summary_flag(inv, "AccountAccessKeysPresent")
    if value is None:
        return _unknown(
            "ルートユーザーのアクセスキー有無（iam:GetAccountSummary の AccountAccessKeysPresent）",
            inv, ("iam",),
            evidence=["security.iam.account_summary.AccountAccessKeysPresent"],
            remediation="`iam:GetAccountSummary` の権限を付けて再収集すること。",
        )
    present = bool(value)
    label = "ルートユーザーのアクセスキー"
    return _finish(
        "ルートユーザーのアクセスキー不使用",
        [] if present else [f"{label}: 存在しない"],
        [f"{label}: **存在する**"] if present else [],
        ["security.iam.account_summary.AccountAccessKeysPresent"],
        "ルートのアクセスキーを直ちに削除する。利用箇所がある場合は、"
        "必要最小限の権限を持つ IAM ロール／ユーザーへ置き換えてから削除すること。",
    )


@check(
    "IAM-03", IAM, "パスワードポリシー",
    "弱いパスワードポリシーは、総当たりとパスワード使い回しによる侵入を許す。",
    "CIS AWS Foundations v3.0 1.8 / 1.9", MEDIUM, requires=("security",),
)
def iam03_password_policy(inv: dict) -> CheckResult:
    """password_policy の最小長・再利用防止・有効期限を見る。"""
    policy = _iam(inv).get("password_policy")
    evidence = ["security.iam.password_policy"]
    if policy is None:
        denied = denied_for(inv, ("iam",))
        if denied:
            return _unknown("パスワードポリシー", inv, ("iam",), evidence=evidence)
        return _res(
            NOT_DONE,
            "**アカウントのパスワードポリシーが設定されていない**（AWS 既定の最小構成のまま）。",
            failed=["パスワードポリシー未設定"],
            evidence=evidence,
            remediation=f"最小長 {MIN_PASSWORD_LENGTH} 文字以上、記号・数字・大小英字を必須にし、"
            "直近24回の再利用を禁止するポリシーを設定すること。",
        )
    if not isinstance(policy, dict):
        return _unknown("パスワードポリシー", inv, ("iam",), evidence=evidence)

    passed: list[str] = []
    failed: list[str] = []
    length = policy.get("MinimumPasswordLength")
    if isinstance(length, int) and length >= MIN_PASSWORD_LENGTH:
        passed.append(f"最小長 {length} 文字")
    else:
        failed.append(f"最小長 {length or '未設定'} 文字（{MIN_PASSWORD_LENGTH} 文字以上が必要）")

    reuse = policy.get("PasswordReusePrevention")
    if isinstance(reuse, int) and reuse >= 24:
        passed.append(f"再利用防止 {reuse} 世代")
    else:
        failed.append(f"再利用防止 {reuse or '未設定'}（24 世代以上が必要）")

    for key, label in (
        ("RequireUppercase", "大文字必須"),
        ("RequireLowercase", "小文字必須"),
        ("RequireNumbers", "数字必須"),
        ("RequireSymbols", "記号必須"),
    ):
        (passed if policy.get(key) else failed).append(
            f"{label}{'' if policy.get(key) else '（無効）'}"
        )

    notes = []
    max_age = policy.get("MaxPasswordAge")
    if max_age:
        notes.append(
            f"有効期限は {max_age} 日に設定されている。"
            "定期変更の強制は最新の NIST ガイドラインでは非推奨で、"
            "MFA 必須化（IAM-04）の方が効果が大きい。"
        )

    return _finish(
        "パスワードポリシー", passed, failed, evidence,
        f"最小長を {MIN_PASSWORD_LENGTH} 文字以上にし、再利用防止を 24 世代に設定する。"
        "IAM Identity Center を使う場合はそちら側のポリシーも併せて確認すること。",
        notes=notes,
    )


@check(
    "IAM-04", IAM, "IAM ユーザーの MFA",
    "コンソールにログインできるユーザーの MFA が無いと、認証情報の漏えいが直接侵入になる。",
    "CIS AWS Foundations v3.0 1.10", HIGH, requires=("security",),
)
def iam04_user_mfa(inv: dict) -> CheckResult:
    """iam.mfa_devices.UserDevices をユーザーごとに見る。"""
    users = _iam_list(inv, "users")
    devices = _iam(inv).get("mfa_devices")
    evidence = ["security.iam.mfa_devices.UserDevices", "security.iam.users"]

    if not isinstance(devices, dict):
        return _unknown(
            "IAM ユーザーの MFA デバイス（iam:ListMFADevices）", inv, ("iam",),
            evidence=evidence,
            remediation="`iam:ListMFADevices` の権限を付けて再収集すること。",
        )
    if not users:
        return _res(
            NOT_APPLICABLE,
            "IAM ユーザーが存在しないため、評価対象外（IAM Identity Center 運用なら望ましい形）。",
            evidence=evidence,
        )

    user_devices = devices.get("UserDevices")
    user_devices = user_devices if isinstance(user_devices, dict) else {}
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []

    for user in users:
        name = str(user.get("UserName"))
        registered = user_devices.get(name)
        if not isinstance(registered, list):
            notes.append(f"{name}: MFA デバイスの一覧が取得できていない")
            continue
        if registered:
            passed.append(f"{name}（MFA {len(registered)} 台）")
        else:
            console = "コンソール利用実績あり" if user.get("PasswordLastUsed") else "コンソール利用実績なし"
            failed.append(f"{name}: MFA 未登録（{console}）")

    unassigned = [
        d for d in devices.get("VirtualDevices") or []
        if isinstance(d, dict) and not (d.get("User") or {}).get("UserName")
    ]
    if unassigned:
        notes.append(
            f"未割り当ての仮想 MFA デバイスが {len(unassigned)} 件残っている（棚卸し対象）"
        )

    return _finish(
        "IAM ユーザーの MFA", passed, failed, evidence,
        "全 IAM ユーザーに MFA を登録する。プログラム専用ユーザーはコンソールログインを無効化し、"
        "恒久的にはユーザーを廃止して IAM ロール／Identity Center へ移行すること。",
        notes=notes,
    )


@check(
    "IAM-05", IAM, "アクセスキーの経過日数と未使用キー",
    "長期間ローテーションされないキーと未使用キーは、漏えいに気付けないまま残り続ける。",
    "CIS AWS Foundations v3.0 1.14 / 1.12", HIGH, requires=("security",),
)
def iam05_access_keys(inv: dict) -> CheckResult:
    """iam.access_keys の CreateDate / LastUsedDate を見る（キー ID はマスク済み）。"""
    keys = _iam(inv).get("access_keys")
    evidence = ["security.iam.access_keys"]
    if not isinstance(keys, list):
        return _unknown(
            "IAM アクセスキーの一覧（iam:ListAccessKeys / GetAccessKeyLastUsed）",
            inv, ("iam",), evidence=evidence,
            remediation="`iam:ListAccessKeys` と `iam:GetAccessKeyLastUsed` の権限を付けて再収集すること。",
        )
    entries = [k for k in keys if isinstance(k, dict)]
    if not entries:
        return _res(
            NOT_APPLICABLE,
            "IAM ユーザーのアクセスキーが1本も存在しないため、評価対象外"
            "（長期認証情報を使っていない望ましい状態）。",
            evidence=evidence,
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    for entry in entries:
        # AccessKeyId はコレクタ側でマスク済み（"****XXXX"）。そのまま表示してよい。
        label = f"{entry.get('UserName')} のキー {entry.get('AccessKeyId')}"
        if str(entry.get("Status")) != "Active":
            notes.append(f"{label}: Inactive のまま残っている（削除候補）")
            continue
        age = _days_old(entry.get("CreateDate"))
        last_used_age = _days_old(entry.get("LastUsedDate"))
        reasons: list[str] = []
        if age is not None and age > ACCESS_KEY_MAX_AGE_DAYS:
            reasons.append(f"作成から {age} 日（{ACCESS_KEY_MAX_AGE_DAYS} 日超）")
        if entry.get("LastUsedDate") is None:
            reasons.append("一度も使われていない")
        elif last_used_age is not None and last_used_age > UNUSED_CREDENTIAL_DAYS:
            reasons.append(f"最終使用から {last_used_age} 日")
        if reasons:
            failed.append(f"{label}: {'／'.join(reasons)}")
        else:
            service = entry.get("ServiceName") or "利用サービス不明"
            passed.append(f"{label}（{service}・{age if age is not None else '?'}日経過）")

    return _finish(
        "アクセスキーのローテーションと未使用キーの整理", passed, failed, evidence,
        "未使用キーは削除し、使用中のキーは新キー発行 → 切り替え → 旧キー無効化 → 削除の順で"
        "ローテーションする。恒久対策は IAM ロール／OIDC フェデレーションへの移行。",
        notes=notes,
    )


@check(
    "IAM-06", IAM, "フルアクセス権限（Action:* / Resource:*）を持つポリシー",
    "`*:*` を許可するポリシーは最小権限の原則に反し、1つの侵害が全権限に直結する。",
    "CIS AWS Foundations v3.0 1.16", HIGH, requires=("security",),
)
def iam06_full_admin_policies(inv: dict) -> CheckResult:
    """カスタマー管理ポリシーとインラインポリシーの本文を走査する。

    本文が未収集の場合は、`policies_attached_summary` の AWS 管理ポリシー名
    （AdministratorAccess 等）から一次判定し、その旨を注記する。
    """
    iam = _iam(inv)
    documents = iam.get("role_attached_policy_documents")
    inline = iam.get("role_inline_policies")
    evidence = [
        "security.iam.role_attached_policy_documents",
        "security.iam.role_inline_policies",
        "security.iam.policies_attached_summary",
    ]
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []

    has_documents = isinstance(documents, dict) or isinstance(inline, dict)

    if isinstance(documents, dict):
        for arn, entry in documents.items():
            if not isinstance(entry, dict):
                continue
            name = entry.get("PolicyName") or arn
            label = f"カスタマー管理ポリシー {name}"
            if entry.get("Document") is None:
                notes.append(f"{label}: 本文が取得できていない")
                continue
            if _is_full_admin(entry.get("Document")):
                failed.append(f"{label}: **Action:* / Resource:* を許可**")
            else:
                passed.append(label)

    if isinstance(inline, dict):
        for role_name, policies in inline.items():
            if not isinstance(policies, dict):
                continue
            for policy_name, document in policies.items():
                label = f"ロール {role_name} のインラインポリシー {policy_name}"
                if _is_full_admin(document):
                    failed.append(f"{label}: **Action:* / Resource:* を許可**")
                else:
                    passed.append(label)

    # 本文が無い／足りない場合は AWS 管理ポリシー名で補う
    admin_names = {"AdministratorAccess", "IAMFullAccess"}
    for entry in _iam_list(inv, "policies_attached_summary"):
        principal = f"{entry.get('PrincipalType')} {entry.get('Name')}"
        for policy in entry.get("AttachedPolicies") or []:
            if not isinstance(policy, dict):
                continue
            policy_name = str(policy.get("PolicyName"))
            if policy_name in admin_names:
                failed.append(
                    f"{principal}: AWS 管理ポリシー **{policy_name}** がアタッチされている"
                )
            elif policy_name == "PowerUserAccess":
                notes.append(
                    f"{principal}: `PowerUserAccess`（IAM 以外の全権限）がアタッチされている。"
                    "`*:*` ではないが実質的にほぼ全権限であり、縮小を検討すること。"
                )

    if not has_documents:
        notes.append(
            "**カスタマー管理ポリシーの本文とインラインポリシーが未収集**のため、"
            "AWS 管理ポリシー名（AdministratorAccess 等）からの一次判定にとどまる。"
            "`iam:GetPolicyVersion` / `iam:GetRolePolicy` を付けて再収集すること。"
        )
        if not failed and not passed:
            return _unknown(
                "IAM ポリシーの本文（iam:GetPolicyVersion / GetRolePolicy）", inv, ("iam",),
                evidence=evidence,
                remediation="ポリシー本文を収集できるよう権限を追加して再収集すること。",
            )

    return _finish(
        "フルアクセス権限を持つポリシーの排除", passed, failed, evidence,
        "`AdministratorAccess` は緊急用ロール（MFA 必須・使用時にアラート）に限定し、"
        "日常運用のロールは実際に使っている API だけを許可するポリシーへ置き換えること。",
        notes=notes,
        na_text="評価対象のポリシーが存在しないため、評価対象外。",
    )


@check(
    "IAM-07", IAM, "外部アカウントを信頼する IAM ロール",
    "外部アカウントに渡した権限は、相手側の管理体制がそのまま自社のリスクになる。",
    "AWS Foundational Security Best Practices（クロスアカウント信頼の最小化）",
    CRITICAL, requires=("security",),
)
def iam07_external_trust(inv: dict) -> CheckResult:
    """AssumeRolePolicyDocument の Principal に外部アカウントがあるロールを洗い出す。

    ExternalId 条件がある（混乱した代理人問題への対策済み）ものを passed、
    条件が無いものを failed とする。**ベンダーに与えている権限の可視化が主目的**。
    """
    account_id = _account_id(inv)
    roles = _iam_list(inv, "roles")
    evidence: list[str] = []
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []

    if not roles:
        return _unknown(
            "IAM ロールの一覧（iam:ListRoles）", inv, ("iam",),
            evidence=["security.iam.roles"],
        )

    attached_by_role: dict[str, list[str]] = {}
    for entry in _iam_list(inv, "policies_attached_summary"):
        if entry.get("PrincipalType") != "role":
            continue
        attached_by_role[str(entry.get("Name"))] = [
            str(p.get("PolicyName"))
            for p in entry.get("AttachedPolicies") or []
            if isinstance(p, dict) and p.get("PolicyName")
        ]

    for i, role in enumerate(roles):
        external, has_external_id = _trusted_external(
            role.get("AssumeRolePolicyDocument"), account_id
        )
        if not external:
            continue
        name = str(role.get("RoleName"))
        evidence.append(f"security.iam.roles[{i}].AssumeRolePolicyDocument")
        policies = attached_by_role.get(name) or []
        policy_text = "、".join(policies) or "管理ポリシー無し（インラインのみの可能性）"
        label = (
            f"{name}: 信頼先 {'、'.join(sorted(external))} / 付与ポリシー {policy_text}"
        )
        if has_external_id:
            passed.append(f"{label}（ExternalId 条件あり）")
        else:
            failed.append(f"{label}（**ExternalId 条件なし**）")
        if "AdministratorAccess" in policies:
            notes.append(
                f"**{name} は外部アカウントに AdministratorAccess を与えている**。"
                "委託契約の範囲と実際の作業内容に照らして妥当か、最優先で確認すること。"
            )

    if not passed and not failed:
        return _res(
            NOT_APPLICABLE,
            "外部アカウント（自アカウント以外のアカウント）を信頼する IAM ロールは存在しないため、"
            "評価対象外。",
            evidence=["security.iam.roles"],
        )

    return _finish(
        "外部アカウントを信頼するロールの統制", passed, failed, evidence,
        "信頼ポリシーに `sts:ExternalId` 条件を追加し、付与ポリシーを実作業に必要な範囲まで"
        "縮小する。ベンダーには (1) 引き受け元アカウントID (2) 実施作業 (3) 取得データを"
        "書面で開示させ、契約終了時にロールを削除する運用を決めること。",
        notes=notes,
    )


@check(
    "IAM-08", IAM, "EC2 インスタンスプロファイルの権限",
    "インスタンスプロファイルの権限が広いと、EC2 の1台侵害がアカウント全体に波及する。",
    "AWS Foundational Security Best Practices（EC2 への最小権限付与）",
    HIGH, requires=("compute", "security"),
)
def iam08_instance_profile(inv: dict) -> CheckResult:
    """インスタンスプロファイルの有無と、そのロールに付いた管理ポリシーの広さを見る。"""
    attached_by_role: dict[str, list[str]] = {}
    for entry in _iam_list(inv, "policies_attached_summary"):
        if entry.get("PrincipalType") != "role":
            continue
        attached_by_role[str(entry.get("Name"))] = [
            str(p.get("PolicyName"))
            for p in entry.get("AttachedPolicies") or []
            if isinstance(p, dict) and p.get("PolicyName")
        ]

    broad = {"AdministratorAccess", "PowerUserAccess", "IAMFullAccess"}
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, instance in enumerate(_dicts(inv, "compute", "instances")):
        if str((instance.get("State") or {}).get("Name")) == "terminated":
            continue
        label = _instance_label(instance)
        evidence.append(f"compute.instances[{i}].IamInstanceProfile")
        profile = instance.get("IamInstanceProfile")
        if not isinstance(profile, dict) or not profile.get("Arn"):
            failed.append(f"{label}: インスタンスプロファイル未割り当て")
            continue
        role_name = str(profile.get("Arn")).rsplit("/", 1)[-1]
        policies = attached_by_role.get(role_name) or []
        wide = sorted(set(policies) & broad)
        if wide:
            failed.append(
                f"{label}: ロール {role_name} に広範な権限 {'、'.join(wide)} が付いている"
            )
        else:
            passed.append(
                f"{label}: ロール {role_name}（{'、'.join(policies) or '管理ポリシー無し'}）"
            )

    if not attached_by_role:
        notes.append(
            "ロールに付いた管理ポリシーの一覧が未収集のため、権限の広さは判定できていない"
            "（プロファイルの有無のみで評価した）。"
        )
    notes.append(
        "管理ポリシーのみで判定しており、**インラインポリシーで足された権限は IAM-06 を参照**すること。"
    )

    return _finish(
        "EC2 インスタンスプロファイルの権限", passed, failed, evidence,
        "インスタンスプロファイル未割り当ての EC2 には最小構成（`AmazonSSMManagedInstanceCore` 等）を"
        "割り当て、広範な権限が付いているものは実際に使っている API まで絞り込むこと。",
        notes=notes,
        na_text="EC2 インスタンスが存在しないため、評価対象外。",
    )


@check(
    "IAM-09", IAM, "未使用の IAM ユーザー・ロール",
    "使われていない認証情報は監視の目が届かず、退職者や終了案件の置き土産になりやすい。",
    "CIS AWS Foundations v3.0 1.12", MEDIUM, requires=("security",),
)
def iam09_unused_principals(inv: dict) -> CheckResult:
    """ユーザーの PasswordLastUsed とロールの RoleLastUsed を見る。"""
    users = _iam_list(inv, "users")
    roles = _iam_list(inv, "roles")
    access_keys = _iam(inv).get("access_keys")
    evidence = ["security.iam.users", "security.iam.roles"]
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []

    if not users and not roles:
        return _unknown(
            "IAM ユーザー／ロールの一覧", inv, ("iam",), evidence=evidence,
        )

    # ユーザーごとに、アクセスキーの最終使用も併せて見る
    key_last_used: dict[str, list[int | None]] = {}
    if isinstance(access_keys, list):
        for entry in access_keys:
            if isinstance(entry, dict):
                key_last_used.setdefault(str(entry.get("UserName")), []).append(
                    _days_old(entry.get("LastUsedDate"))
                )

    for user in users:
        name = str(user.get("UserName"))
        console_age = _days_old(user.get("PasswordLastUsed"))
        key_ages = [a for a in key_last_used.get(name, []) if a is not None]
        recent = [a for a in ([console_age] if console_age is not None else []) + key_ages
                  if a <= UNUSED_CREDENTIAL_DAYS]
        if recent:
            passed.append(f"ユーザー {name}（最終利用 {min(recent)} 日前）")
            continue
        if console_age is None and name not in key_last_used:
            notes.append(
                f"ユーザー {name}: コンソール利用実績もアクセスキー情報も無く、"
                "利用状況を判定できない（IAM-05 の再収集で確定する）"
            )
            continue
        ages = ([console_age] if console_age is not None else []) + key_ages
        detail = f"最終利用 {min(ages)} 日前" if ages else "利用実績なし"
        failed.append(f"ユーザー {name}: {detail}（{UNUSED_CREDENTIAL_DAYS} 日以上未使用）")

    for role in roles:
        name = str(role.get("RoleName"))
        if "/aws-service-role/" in str(role.get("Path") or ""):
            continue  # AWS サービスリンクロールは利用者が消せないため対象外
        last_used = role.get("RoleLastUsed")
        if not isinstance(last_used, dict):
            notes.append(f"ロール {name}: `RoleLastUsed` が未収集で利用状況を判定できない")
            continue
        age = _days_old(last_used.get("LastUsedDate"))
        if age is None:
            failed.append(f"ロール {name}: 一度も引き受けられていない")
        elif age > UNUSED_CREDENTIAL_DAYS:
            failed.append(f"ロール {name}: 最終利用 {age} 日前")
        else:
            passed.append(f"ロール {name}（最終利用 {age} 日前）")

    if not passed and not failed:
        return _unknown(
            "IAM ユーザー・ロールの利用実績（PasswordLastUsed / RoleLastUsed）",
            inv, ("iam",), evidence=evidence,
            remediation="`iam:ListRoles` のレスポンスに RoleLastUsed を含め、"
            "アクセスキーの最終使用（IAM-05）も併せて収集すること。",
            notes=notes,
        )

    return _finish(
        "未使用の IAM ユーザー・ロールの整理", passed, failed, evidence,
        "未使用のユーザー・ロールは所有者に確認のうえ、まず無効化（キー Inactive 化・"
        "信頼ポリシー削除）し、一定期間問題が出なければ削除すること。",
        notes=notes,
    )


# ===========================================================================
# 5. ログ・証跡（LOG）
# ===========================================================================


@check(
    "LOG-01", LOG, "CloudTrail の有効化と全リージョン証跡",
    "証跡が無い／止まっていると、誰が何をしたかを後から一切追えない。",
    "CIS AWS Foundations v3.0 3.1", CRITICAL, requires=("logging",),
)
def log01_cloudtrail(inv: dict) -> CheckResult:
    """cloudtrail_trails の IsMultiRegionTrail かつ IsLogging を見る。"""
    trails = _dicts(inv, "logging", "cloudtrail_trails")
    evidence = ["logging.cloudtrail_trails"]
    if not trails:
        denied = denied_for(inv, ("cloudtrail",))
        if denied:
            return _unknown("CloudTrail 証跡の一覧", inv, ("cloudtrail",), evidence=evidence)
        return _res(
            NOT_DONE,
            "**CloudTrail の証跡が1本も存在しない。** API 操作の記録が残っていない状態。",
            failed=["証跡 0 本"],
            evidence=evidence,
            remediation="全リージョン対象・管理イベント有効の証跡を作成し、"
            "ログファイル検証（LOG-02）と KMS 暗号化（ENC-06）も同時に有効化すること。",
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    for i, trail in enumerate(trails):
        name = str(trail.get("Name"))
        evidence.append(f"logging.cloudtrail_trails[{i}].IsMultiRegionTrail")
        reasons: list[str] = []
        if not trail.get("IsMultiRegionTrail"):
            reasons.append("全リージョン証跡ではない")
        if trail.get("IsLogging") is False:
            reasons.append("**記録が停止している**")
        elif trail.get("IsLogging") is None:
            reasons.append("記録状態が取得できていない")
        status = trail.get("Status") or {}
        if isinstance(status, dict) and status.get("LatestDeliveryError"):
            reasons.append(f"最新の配信でエラー: {status.get('LatestDeliveryError')}")
        if trail.get("IsOrganizationTrail"):
            notes.append(f"証跡 {name} は組織証跡（管理アカウント側で管理されている）")
        if reasons:
            failed.append(f"証跡 {name}: {'／'.join(reasons)}")
        else:
            latest = (status or {}).get("LatestDeliveryTime")
            passed.append(f"証跡 {name}（最終配信 {latest or '不明'}）")

    return _finish(
        "CloudTrail の有効化と全リージョン証跡", passed, failed, evidence,
        "証跡を「すべてのリージョンに適用」に変更し、記録が止まっているものは再開する。"
        "配信エラーは配信先バケットのポリシーを確認すること。",
        notes=notes,
    )


@check(
    "LOG-02", LOG, "CloudTrail のログファイル検証",
    "ログファイル検証が無いと、侵入者にログを改ざん・削除されても検出できない。",
    "CIS AWS Foundations v3.0 3.2", HIGH, requires=("logging",),
)
def log02_log_file_validation(inv: dict) -> CheckResult:
    """cloudtrail_trails[].LogFileValidationEnabled を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, trail in enumerate(_dicts(inv, "logging", "cloudtrail_trails")):
        label = f"証跡 {trail.get('Name')}"
        evidence.append(f"logging.cloudtrail_trails[{i}].LogFileValidationEnabled")
        (passed if trail.get("LogFileValidationEnabled") else failed).append(label)

    return _finish(
        "CloudTrail のログファイル検証", passed, failed, evidence,
        "証跡の設定で「ログファイルの検証」を有効にする（追加費用なし）。"
        "検証は `aws cloudtrail validate-logs` で実施できる。",
        na_text="CloudTrail 証跡が存在しないため、評価対象外（LOG-01 を参照）。",
    )


@check(
    "LOG-03", LOG, "CloudTrail 用 S3 バケットの保護",
    "証跡バケットが公開・無監査だと、ログの持ち出しや削除に気付けない。",
    "CIS AWS Foundations v3.0 3.4 / AWS FSBP S3.2", HIGH,
    requires=("logging", "storage"),
)
def log03_trail_bucket(inv: dict) -> CheckResult:
    """証跡の配信先バケットが非公開で、サーバーアクセスログが有効か見る。"""
    buckets = {str(b.get("Name")): b for b in _dicts(inv, "storage", "buckets")}
    trails = _dicts(inv, "logging", "cloudtrail_trails")
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence = ["logging.cloudtrail_trails[].S3BucketName"]

    targets = sorted({str(t.get("S3BucketName")) for t in trails if t.get("S3BucketName")})
    if not targets:
        return _res(
            NOT_APPLICABLE,
            "CloudTrail の配信先バケットが特定できないため、評価対象外（LOG-01 を参照）。",
            evidence=evidence,
        )

    for name in targets:
        bucket = buckets.get(name)
        if bucket is None:
            notes.append(
                f"{name}: 証跡の配信先だが `storage.buckets` に存在しない"
                "（別アカウント／別リージョンのバケットの可能性）"
            )
            continue
        evidence.append(f"storage.buckets[].Name=={name}")
        reasons: list[str] = []
        pab = bucket.get("PublicAccessBlock")
        keys = (
            "BlockPublicAcls", "IgnorePublicAcls",
            "BlockPublicPolicy", "RestrictPublicBuckets",
        )
        if not isinstance(pab, dict) or any(not pab.get(k) for k in keys):
            reasons.append("パブリックアクセスブロックが不完全")
        status = bucket.get("PolicyStatus")
        if isinstance(status, dict) and status.get("IsPublic"):
            reasons.append("**バケットポリシーで公開されている**")
        if not bucket.get("Logging"):
            reasons.append("サーバーアクセスログが無効")
        if reasons:
            failed.append(f"{name}: {'／'.join(reasons)}")
        else:
            passed.append(name)

    return _finish(
        "CloudTrail 用 S3 バケットの保護", passed, failed, evidence,
        "証跡バケットはパブリックアクセスブロックを4項目すべて有効にし、"
        "別のログ用バケットへサーバーアクセスログを出力する。"
        "オブジェクトロック（コンプライアンスモード）も併せて検討すること。",
        notes=notes,
    )


@check(
    "LOG-04", LOG, "AWS Config の有効化",
    "Config が無いと、設定がいつ誰に変えられたかの履歴が残らず原因追跡ができない。",
    "CIS AWS Foundations v3.0 3.3", HIGH, requires=("logging",),
)
def log04_config(inv: dict) -> CheckResult:
    """config_recorders[].Status.recording が true か見る。"""
    recorders = _dicts(inv, "logging", "config_recorders")
    evidence = ["logging.config_recorders"]
    if not recorders:
        denied = denied_for(inv, ("config",))
        if denied:
            return _unknown("AWS Config レコーダ", inv, ("config",), evidence=evidence)
        return _res(
            NOT_DONE,
            "**AWS Config の設定レコーダが存在しない。** 構成変更の履歴が残っていない状態。",
            failed=["設定レコーダ 0 本"],
            evidence=evidence,
            remediation="全リソースタイプ（グローバルリソース含む）を対象に設定レコーダを作成し、"
            "配信チャネル（S3 バケット）を設定すること。",
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    for i, recorder in enumerate(recorders):
        name = str(recorder.get("name"))
        evidence.append(f"logging.config_recorders[{i}].Status.recording")
        status = recorder.get("Status")
        if not isinstance(status, dict):
            failed.append(f"レコーダ {name}: 稼働状況が取得できていない")
            continue
        if not status.get("recording"):
            failed.append(f"レコーダ {name}: **記録が停止している**")
        elif str(status.get("lastStatus") or "").upper() not in ("SUCCESS", ""):
            failed.append(
                f"レコーダ {name}: 記録中だが最新の配信が {status.get('lastStatus')}"
                f"（{status.get('lastErrorMessage') or 'エラー詳細なし'}）"
            )
        else:
            passed.append(f"レコーダ {name}（{status.get('lastStatus')}）")
        group = recorder.get("recordingGroup") or {}
        if not group.get("allSupported"):
            notes.append(f"レコーダ {name}: 全リソースタイプを対象にしていない（記録漏れの可能性）")

    if not _lst(inv, "logging", "config_delivery_channels"):
        notes.append("配信チャネルが設定されていない（記録していても S3 に残らない）")

    return _finish(
        "AWS Config の有効化", passed, failed, evidence,
        "設定レコーダを開始し、配信チャネルの S3 バケットポリシーを確認する。"
        "併せて CIS 準拠パックの Config ルールを適用すると継続監視ができる。",
        notes=notes,
    )


@check(
    "LOG-05", LOG, "VPC フローログの保存先とステータス",
    "フローログは設定しただけでは足りず、配信が成功していなければ証跡として使えない。",
    "CIS AWS Foundations v3.0 3.7", MEDIUM, requires=("logging",),
)
def log05_flow_log_delivery(inv: dict) -> CheckResult:
    """flow_logs のステータスと配信先を見る（NET-04 は VPC 網羅性、こちらは配信の健全性）。"""
    flow_logs = _dicts(inv, "logging", "flow_logs")
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, fl in enumerate(flow_logs):
        label = f"{fl.get('FlowLogId')}（対象 {fl.get('ResourceId')}）"
        evidence.append(f"logging.flow_logs[{i}].FlowLogStatus")
        reasons: list[str] = []
        if str(fl.get("FlowLogStatus") or "").upper() != "ACTIVE":
            reasons.append(f"ステータスが {fl.get('FlowLogStatus')}")
        if str(fl.get("DeliverLogsStatus") or "SUCCESS").upper() != "SUCCESS":
            reasons.append(
                f"配信が {fl.get('DeliverLogsStatus')}"
                f"（{fl.get('DeliverLogsErrorMessage') or '詳細なし'}）"
            )
        if not fl.get("LogDestination"):
            reasons.append("配信先が取得できていない")
        if str(fl.get("TrafficType") or "").upper() not in ("ALL", ""):
            notes.append(
                f"{label}: TrafficType={fl.get('TrafficType')}。"
                "拒否パケットだけ／許可パケットだけでは調査時に片側しか見えない。"
            )
        if reasons:
            failed.append(f"{label}: {'／'.join(reasons)}")
        else:
            passed.append(
                f"{label} → {fl.get('LogDestinationType')} `{fl.get('LogDestination')}`"
            )

    return _finish(
        "VPC フローログの配信", passed, failed, evidence,
        "配信に失敗しているフローログは、配信先（S3 バケットポリシー／CloudWatch Logs の"
        "IAM ロール）を確認して復旧させること。",
        notes=notes,
        na_text="VPC フローログが1件も存在しないため、評価対象外（NET-04 を参照）。",
    )


@check(
    "LOG-06", LOG, "ALB アクセスログ",
    "アクセスログが無いと、攻撃の痕跡も障害時のリクエスト内容も後から確認できない。",
    "AWS FSBP ELB.5", HIGH, requires=("edge",),
)
def log06_alb_access_logs(inv: dict) -> CheckResult:
    """load_balancers[].Attributes の access_logs.s3.enabled を全本について見る。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, lb in enumerate(_dicts(inv, "edge", "load_balancers")):
        label = f"{_lb_name(lb)}（{lb.get('Type')}／{lb.get('Scheme')}）"
        evidence.append(f"edge.load_balancers[{i}].Attributes")
        attributes = lb.get("Attributes")
        if not isinstance(attributes, list) or not attributes:
            notes.append(f"{label}: Attributes が未収集でアクセスログの有無を判定できない")
            continue
        enabled = str(_attr(lb, "access_logs.s3.enabled") or "").lower() == "true"
        bucket = _attr(lb, "access_logs.s3.bucket")
        if enabled and bucket:
            passed.append(f"{label} → `{bucket}`")
        elif enabled:
            failed.append(f"{label}: 有効だが配信先バケットが設定されていない")
        else:
            failed.append(f"{label}: アクセスログ無効")

    return _finish(
        "ALB アクセスログ", passed, failed, evidence,
        "各ロードバランサの属性でアクセスログを有効化し、"
        "専用のログバケット（ライフサイクル設定済み・LOG-09）へ出力すること。",
        notes=notes,
        na_text="ロードバランサが存在しないため、評価対象外。",
    )


@check(
    "LOG-07", LOG, "CloudWatch Logs の保持期間",
    "保持期間未設定のロググループは無期限に課金され、逆に短すぎると調査に使えない。",
    "AWS FSBP CloudWatch.16", LOW, requires=("logging",),
)
def log07_log_retention(inv: dict) -> CheckResult:
    """cloudwatch_log_groups の retentionInDays（未設定＝無期限）を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, group in enumerate(_dicts(inv, "logging", "cloudwatch_log_groups")):
        name = str(group.get("logGroupName") or group.get("LogGroupName"))
        evidence.append(f"logging.cloudwatch_log_groups[{i}].retentionInDays")
        # logs API のレスポンスは camelCase。大文字始まりの表記にも一応対応する。
        retention = group.get("retentionInDays", group.get("RetentionInDays"))
        if retention:
            passed.append(f"{name}（{retention} 日）")
        else:
            failed.append(f"{name}: 保持期間未設定（無期限保持）")

    return _finish(
        "CloudWatch Logs の保持期間", passed, failed, evidence,
        "ロググループごとに保持期間を設定する（監査対象は 365 日以上、"
        "アプリログは 30〜90 日が目安）。長期保管が要るものは S3 へエクスポートすること。",
        na_text="CloudWatch ロググループが存在しないため、評価対象外。",
    )


@check(
    "LOG-08", LOG, "S3 バケットのサーバーアクセスログ",
    "オブジェクトへのアクセス記録が無いと、情報持ち出しの有無を後から確認できない。",
    "AWS FSBP S3.9", LOW, requires=("storage",),
)
def log08_s3_access_logs(inv: dict) -> CheckResult:
    """buckets[].Logging を見る。ログ保管用バケット自身は注記に回す。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, bucket in enumerate(_dicts(inv, "storage", "buckets")):
        name = str(bucket.get("Name"))
        evidence.append(f"storage.buckets[{i}].Logging")
        if bucket.get("Logging"):
            passed.append(name)
        elif _is_log_bucket(name):
            notes.append(
                f"{name}: ログ保管用バケットとみられるため failed に数えていない"
                "（ログのログを取るかは設計判断）"
            )
        else:
            failed.append(f"{name}: サーバーアクセスログ無効")

    return _finish(
        "S3 バケットのサーバーアクセスログ", passed, failed, evidence,
        "個人情報や業務データを置くバケットではサーバーアクセスログ"
        "（または CloudTrail データイベント）を有効にすること。"
        "全バケットで有効にすると費用が嵩むため、重要度で優先順位を付ける。",
        notes=notes,
        na_text="S3 バケットが存在しないため、評価対象外。",
    )


@check(
    "LOG-09", LOG, "ログ用バケットのライフサイクルルール",
    "ライフサイクルが無いログバケットは際限なく増え続け、費用と削除リスクの両方を抱える。",
    "AWS FSBP S3.13", LOW, requires=("storage",),
)
def log09_log_lifecycle(inv: dict) -> CheckResult:
    """名前からログ用と判断できるバケットの Lifecycle を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []

    for i, bucket in enumerate(_dicts(inv, "storage", "buckets")):
        name = str(bucket.get("Name"))
        if not _is_log_bucket(name):
            continue
        evidence.append(f"storage.buckets[{i}].Lifecycle")
        rules = bucket.get("Lifecycle")
        enabled = [
            r for r in (rules or [])
            if isinstance(r, dict) and str(r.get("Status")) == "Enabled"
        ]
        if enabled:
            passed.append(f"{name}（有効なルール {len(enabled)} 件）")
        else:
            failed.append(f"{name}: ライフサイクルルール無し（無期限に増加）")

    return _finish(
        "ログ用バケットのライフサイクルルール", passed, failed, evidence,
        "ログバケットに「N 日後に Glacier Instant Retrieval へ移行、M 日後に削除」の"
        "ライフサイクルを設定する。保存年限は監査要件から逆算すること。",
        na_text="名前からログ用と判断できるバケットが存在しないため、評価対象外。",
    )


# ===========================================================================
# 6. 脅威検知（DET）
# ===========================================================================


@check(
    "DET-01", DET, "GuardDuty の有効化と保護機能",
    "GuardDuty は不正な API 利用やマルウェア通信を検知する最後の網であり、"
    "有効化していないと侵害に気付けない。",
    "AWS FSBP GuardDuty.1", HIGH, requires=("security",),
)
def det01_guardduty(inv: dict) -> CheckResult:
    """検出器の Status と Features（S3 / EKS / Malware / RDS 保護）を見る。"""
    detectors = _dicts(inv, "security", "guardduty_detectors")
    evidence = ["security.guardduty_detectors"]
    if not detectors:
        denied = denied_for(inv, ("guardduty",))
        if denied:
            return _unknown("GuardDuty 検出器", inv, ("guardduty",), evidence=evidence)
        return _res(
            NOT_DONE,
            "**GuardDuty が有効化されていない**（検出器 0 件）。"
            "不正 API 利用・暗号通貨マイニング・既知の悪性 IP との通信を検知できない。",
            failed=["GuardDuty 検出器 0 件"],
            evidence=evidence,
            remediation="GuardDuty を有効化し、S3 保護・Malware Protection・RDS 保護も"
            "併せて有効にすること（30 日間の無料トライアルで費用感を確認できる）。",
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    for i, detector in enumerate(detectors):
        detector_id = str(detector.get("DetectorId"))
        evidence.append(f"security.guardduty_detectors[{i}].Features")
        if str(detector.get("Status")) != "ENABLED":
            failed.append(f"検出器 {detector_id}: Status={detector.get('Status')}")
            continue
        features = detector.get("Features")
        if not isinstance(features, list) or not features:
            passed.append(f"検出器 {detector_id}（有効）")
            notes.append(
                f"検出器 {detector_id}: `Features` が空で、S3 保護・EKS・Malware・RDS 保護の"
                "個別の有効状況までは判定できていない。"
            )
            continue
        disabled = sorted(
            str(f.get("Name"))
            for f in features
            if isinstance(f, dict) and str(f.get("Status")) != "ENABLED"
        )
        enabled = sorted(
            str(f.get("Name"))
            for f in features
            if isinstance(f, dict) and str(f.get("Status")) == "ENABLED"
        )
        if disabled:
            failed.append(
                f"検出器 {detector_id}: 有効だが保護機能 {'、'.join(disabled)} が無効"
            )
        else:
            passed.append(f"検出器 {detector_id}（保護機能 {'、'.join(enabled)} すべて有効）")

    return _finish(
        "GuardDuty の有効化と保護機能", passed, failed, evidence,
        "無効な保護機能（S3 / EKS 監査ログ / Malware Protection / RDS ログイン保護）を有効にし、"
        "検出結果を SNS または Security Hub 経由で通知する導線を作ること。",
        notes=notes,
    )


@check(
    "DET-02", DET, "Security Hub の有効化と標準",
    "Security Hub が無いと、各種チェックの結果が一元化されず対応漏れが起きる。",
    "AWS FSBP SecurityHub.1", MEDIUM, requires=("security",),
)
def det02_securityhub(inv: dict) -> CheckResult:
    """securityhub.Hub と EnabledStandards、コントロールの有効件数を見る。"""
    hub_section = _map(inv, "security", "securityhub")
    evidence = ["security.securityhub", "security.securityhub_standards_controls"]
    hub = hub_section.get("Hub")
    standards = [s for s in hub_section.get("EnabledStandards") or [] if isinstance(s, dict)]

    if not hub and not standards:
        denied = denied_for(inv, ("securityhub",))
        if denied:
            return _unknown("Security Hub の状況", inv, ("securityhub",), evidence=evidence)
        return _res(
            NOT_DONE,
            "**Security Hub が有効化されていない。** 各サービスの検出結果が一元化されていない状態。",
            failed=["Security Hub 未有効化"],
            evidence=evidence,
            remediation="Security Hub を有効化し、「AWS 基礎セキュリティのベストプラクティス」と"
            "「CIS AWS Foundations Benchmark v3.0」の標準を有効にすること。",
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    controls_by_arn = {
        str(entry.get("StandardsSubscriptionArn")): entry
        for entry in _dicts(inv, "security", "securityhub_standards_controls")
    }

    for standard in standards:
        arn = str(standard.get("StandardsArn") or "")
        name = arn.rsplit("/", 3)[-3] if arn.count("/") >= 3 else arn
        label = f"標準 {name or arn}"
        state = str(standard.get("StandardsStatus") or "")
        controls = controls_by_arn.get(str(standard.get("StandardsSubscriptionArn")))
        detail = ""
        if controls:
            items = [c for c in controls.get("Controls") or [] if isinstance(c, dict)]
            enabled = sum(1 for c in items if str(c.get("ControlStatus")) == "ENABLED")
            detail = f"（コントロール {enabled}/{len(items)} 件が有効）"
            if items and enabled < len(items):
                notes.append(
                    f"{label}: {len(items) - enabled} 件のコントロールが無効化されている。"
                    "無効化の理由（DisabledReason）が妥当か確認すること。"
                )
        else:
            notes.append(f"{label}: コントロールの内訳が未収集で有効件数を確認できない")
        if state in ("READY", "PENDING"):
            passed.append(f"{label}: {state}{detail}")
        else:
            failed.append(f"{label}: {state or '状態不明'}{detail}")

    if not standards:
        failed.append("有効な標準が 0 件（Security Hub を有効にしただけの状態）")

    # 古い標準しか有効になっていないケースを拾う
    if any("cis-aws-foundations-benchmark/v/1." in str(s.get("StandardsArn")) for s in standards):
        notes.append(
            "有効な CIS 標準が v1.x 世代。**v3.0 が公開済み**なので切り替えを検討すること。"
        )

    return _finish(
        "Security Hub の有効化と標準", passed, failed, evidence,
        "「AWS 基礎セキュリティのベストプラクティス」と CIS v3.0 を有効にし、"
        "無効化したコントロールには理由を記録すること。",
        notes=notes,
    )


@check(
    "DET-03", DET, "Amazon Inspector の有効化",
    "Inspector が無いと、EC2 / ECR / Lambda に残る既知脆弱性を継続的に把握できない。",
    "AWS FSBP Inspector.1 / Inspector.2 / Inspector.3", MEDIUM, requires=("security",),
)
def det03_inspector(inv: dict) -> CheckResult:
    """inspector2.accounts[].resourceState の EC2 / ECR / Lambda を見る。"""
    section = _map(inv, "security", "inspector2")
    evidence = ["security.inspector2"]
    accounts = [a for a in section.get("accounts") or [] if isinstance(a, dict)]
    if not section or not accounts:
        return _unknown(
            "Amazon Inspector の有効状況（inspector2:BatchGetAccountStatus）",
            inv, ("inspector2",), evidence=evidence,
            remediation="`inspector2:BatchGetAccountStatus` の権限を付けて再収集すること。"
            "権限を付けても空になる場合は、そのリージョンで Inspector が未導入。",
        )

    passed: list[str] = []
    failed: list[str] = []
    for account in accounts:
        state = account.get("resourceState") or {}
        for key, label in (("ec2", "EC2"), ("ecr", "ECR"), ("lambda", "Lambda")):
            status = str((state.get(key) or {}).get("status") or "UNKNOWN")
            target = f"{label} スキャン"
            if status == "ENABLED":
                passed.append(target)
            else:
                failed.append(f"{target}: {status}")

    return _finish(
        "Amazon Inspector の有効化", passed, failed, evidence,
        "Inspector を有効化し、EC2（SSM 管理下が前提・PAT-01 参照）・ECR・Lambda の"
        "スキャンをすべて有効にすること。",
    )


@check(
    "DET-04", DET, "IAM Access Analyzer",
    "外部に公開されたリソース（S3・ロール・KMS 等）を機械的に洗い出す唯一の仕組み。",
    "CIS AWS Foundations v3.0 1.20", MEDIUM, requires=("security",),
)
def det04_access_analyzer(inv: dict) -> CheckResult:
    """access_analyzer の一覧を見る。"""
    analyzers = _dicts(inv, "security", "access_analyzer")
    evidence = ["security.access_analyzer"]
    if not analyzers:
        denied = denied_for(inv, ("accessanalyzer", "access-analyzer"))
        if denied:
            return _unknown(
                "IAM Access Analyzer", inv, ("accessanalyzer", "access-analyzer"),
                evidence=evidence,
            )
        return _res(
            NOT_DONE,
            "**IAM Access Analyzer が有効化されていない**（アナライザ 0 件）。"
            "外部公開されているリソースの自動検出ができていない。",
            failed=["アナライザ 0 件"],
            evidence=evidence,
            remediation="アカウントまたは組織スコープの外部アクセスアナライザを作成する"
            "（追加費用なし）。検出結果は Security Hub に集約できる。",
        )

    passed: list[str] = []
    failed: list[str] = []
    for i, analyzer in enumerate(analyzers):
        label = f"{analyzer.get('name')}（{analyzer.get('type')}）"
        evidence.append(f"security.access_analyzer[{i}].status")
        if str(analyzer.get("status")) == "ACTIVE":
            passed.append(label)
        else:
            failed.append(f"{label}: status={analyzer.get('status')}")

    return _finish(
        "IAM Access Analyzer", passed, failed, evidence,
        "停止しているアナライザを再作成し、検出結果を定期的にレビューする運用を決めること。",
    )


@check(
    "DET-05", DET, "重要イベントの検知アラーム",
    "ルートログインや IAM 変更に気付けないと、権限奪取後の行動を止められない。",
    "CIS AWS Foundations v3.0 4.3 / 4.4 / 4.6", MEDIUM, requires=("logging",),
)
def det05_detection_alarms(inv: dict) -> CheckResult:
    """CloudWatch アラーム名・メトリクス名から検知アラームらしきものを探す。"""
    alarms = _dicts(inv, "logging", "cloudwatch_alarms")
    evidence = ["logging.cloudwatch_alarms"]
    if not alarms:
        return _res(
            NOT_DONE,
            "**CloudWatch アラームが1件も存在しない。** ルートログイン・IAM 変更・"
            "コンソール認証失敗のいずれも検知できない。",
            failed=["検知アラーム 0 件"],
            evidence=evidence,
            remediation="CloudTrail を CloudWatch Logs に連携し、ルートログイン・IAM ポリシー変更・"
            "コンソール認証失敗のメトリクスフィルタとアラームを作成して SNS で通知すること。",
        )

    wanted = {
        "ルートユーザーの利用": ("root",),
        "IAM ポリシー変更": ("iam", "policy"),
        "コンソール認証失敗": ("console", "signin", "sign-in", "authentication", "authfail"),
        "不正な API 呼び出し": ("unauthorized",),
    }
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []

    haystack = [
        (
            str(alarm.get("AlarmName") or "").lower()
            + " "
            + str(alarm.get("MetricName") or "").lower()
            + " "
            + str(alarm.get("AlarmDescription") or "").lower(),
            alarm,
        )
        for alarm in alarms
    ]

    for label, keywords in wanted.items():
        hit = next(
            (a for text, a in haystack if any(k in text for k in keywords)), None
        )
        if hit is None:
            failed.append(f"{label}: 該当するアラームが見つからない")
        else:
            actions = hit.get("AlarmActions") or []
            if actions:
                passed.append(f"{label}: `{hit.get('AlarmName')}`")
            else:
                failed.append(
                    f"{label}: `{hit.get('AlarmName')}` はあるが通知先（AlarmActions）が空"
                )

    without_action = [
        str(a.get("AlarmName")) for a in alarms if not (a.get("AlarmActions") or [])
    ]
    if without_action:
        notes.append(
            f"通知先が設定されていないアラームが {len(without_action)} 件ある: "
            + "、".join(without_action[:5])
        )
    notes.append(
        "アラーム名とメトリクス名のキーワード一致で判定しているため、"
        "命名が異なる場合は取りこぼす可能性がある（メトリクスフィルタの定義までは収集していない）。"
    )

    return _finish(
        "重要イベントの検知アラーム", passed, failed, evidence,
        "CloudTrail を CloudWatch Logs に連携し、CIS 4.x のメトリクスフィルタ"
        "（ルート利用・IAM 変更・認証失敗・不正 API）とアラームを作成して"
        "SNS 経由でオンコールに通知すること。",
        notes=notes,
    )


# ===========================================================================
# 7. バックアップ・可用性（BCP）
# ===========================================================================


@check(
    "BCP-01", BCP, "RDS の自動バックアップ保持期間",
    "保持期間 0 日は自動バックアップ無効で、障害時にポイントインタイム復旧ができない。",
    "AWS FSBP RDS.11", CRITICAL, requires=("database",),
)
def bcp01_rds_backup(inv: dict) -> CheckResult:
    """db_instances[].BackupRetentionPeriod を見る（本番相当は 7 日以上）。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, db in enumerate(_dicts(inv, "database", "db_instances")):
        identifier = str(db.get("DBInstanceIdentifier"))
        evidence.append(f"database.db_instances[{i}].BackupRetentionPeriod")
        retention = db.get("BackupRetentionPeriod")
        if not isinstance(retention, int) or retention < 1:
            failed.append(f"RDS {identifier}: **自動バックアップ無効（保持 0 日）**")
            continue
        passed.append(f"RDS {identifier}（保持 {retention} 日）")
        if retention < 7:
            notes.append(
                f"RDS {identifier}: 保持 {retention} 日。"
                "本番用途なら 7 日以上を推奨（週明けに気付く障害に間に合わない）。"
            )

    return _finish(
        "RDS の自動バックアップ", passed, failed, evidence,
        "バックアップ保持期間を 1 日以上（本番は 7 日以上）に設定する。"
        "0 → 1 以上への変更は再起動を伴うため、計画停止に合わせること。",
        notes=notes,
        na_text="RDS インスタンスが存在しないため、評価対象外。",
    )


@check(
    "BCP-02", BCP, "RDS の Multi-AZ",
    "Single-AZ の DB は AZ 障害でそのまま停止し、復旧にリストア時間がかかる。",
    "AWS FSBP RDS.5", MEDIUM, requires=("database",),
)
def bcp02_rds_multiaz(inv: dict) -> CheckResult:
    """db_instances[].MultiAZ を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, db in enumerate(_dicts(inv, "database", "db_instances")):
        identifier = str(db.get("DBInstanceIdentifier"))
        evidence.append(f"database.db_instances[{i}].MultiAZ")
        if db.get("MultiAZ"):
            passed.append(f"RDS {identifier}（{db.get('AvailabilityZone')} / "
                          f"{db.get('SecondaryAvailabilityZone')}）")
        else:
            failed.append(f"RDS {identifier}: Single-AZ（{db.get('AvailabilityZone')}）")

    return _finish(
        "RDS の Multi-AZ 構成", passed, failed, evidence,
        "本番相当の DB は Multi-AZ に変更する（ダウンタイムはフェイルオーバー時の数十秒程度）。"
        "検証環境は費用対効果から Single-AZ のままでよいが、その判断を台帳に残すこと。",
        na_text="RDS インスタンスが存在しないため、評価対象外。",
    )


@check(
    "BCP-03", BCP, "RDS の削除保護",
    "削除保護が無いと、誤操作やスクリプト事故で本番 DB が消える。",
    "AWS FSBP RDS.8", MEDIUM, requires=("database",),
)
def bcp03_rds_deletion_protection(inv: dict) -> CheckResult:
    """db_instances[].DeletionProtection を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    for i, db in enumerate(_dicts(inv, "database", "db_instances")):
        identifier = str(db.get("DBInstanceIdentifier"))
        evidence.append(f"database.db_instances[{i}].DeletionProtection")
        (passed if db.get("DeletionProtection") else failed).append(
            f"RDS {identifier}" + ("" if db.get("DeletionProtection") else ": 削除保護なし")
        )

    return _finish(
        "RDS の削除保護", passed, failed, evidence,
        "本番相当の DB は削除保護を有効にする（即時反映・ダウンタイムなし）。",
        na_text="RDS インスタンスが存在しないため、評価対象外。",
    )


@check(
    "BCP-04", BCP, "EFS のバックアップポリシー",
    "EFS はスナップショット機能が無く、バックアップポリシーが唯一の自動復旧手段。",
    "AWS FSBP EFS.2", HIGH, requires=("storage",),
)
def bcp04_efs_backup(inv: dict) -> CheckResult:
    """efs_backup_policies の Status が ENABLED か見る。"""
    policies = _map(inv, "storage", "efs_backup_policies")
    filesystems = _dicts(inv, "storage", "efs_file_systems")
    evidence = ["storage.efs_backup_policies"]
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []

    for fs in filesystems:
        fs_id = str(fs.get("FileSystemId"))
        label = f"{fs.get('Name') or '(名前なし)'} ({fs_id})"
        policy = policies.get(fs_id)
        if not isinstance(policy, dict):
            notes.append(f"{label}: バックアップポリシーが取得できていない")
            continue
        status = str(policy.get("Status") or "")
        if status == "ENABLED":
            passed.append(label)
        else:
            failed.append(f"{label}: バックアップポリシー {status or '未設定'}")

    if not passed and not failed and notes:
        return _unknown(
            "EFS のバックアップポリシー", inv, ("efs",), evidence=evidence, notes=notes,
        )

    return _finish(
        "EFS のバックアップポリシー", passed, failed, evidence,
        "EFS コンソールの「自動バックアップ」を有効にする（AWS Backup の日次バックアップが"
        "自動作成される）。保持期間は既定 35 日のため、要件に合わせて調整すること。",
        notes=notes,
        na_text="EFS ファイルシステムが存在しないため、評価対象外。",
    )


@check(
    "BCP-05", BCP, "AWS Backup のプランと対象",
    "バックアップが各サービス任せだと、取得漏れと復旧手順のばらつきが避けられない。",
    "AWS FSBP Backup.1", MEDIUM, requires=("storage",),
)
def bcp05_aws_backup(inv: dict) -> CheckResult:
    """backup_plans / backup_selections / backup_protected_resources を見る。"""
    plans = _dicts(inv, "storage", "backup_plans")
    selections = _dicts(inv, "storage", "backup_selections")
    protected = _dicts(inv, "storage", "backup_protected_resources")
    evidence = [
        "storage.backup_plans", "storage.backup_selections",
        "storage.backup_protected_resources",
    ]

    if not plans:
        denied = denied_for(inv, ("backup",))
        if denied:
            return _unknown("AWS Backup のプラン", inv, ("backup",), evidence=evidence)
        return _res(
            NOT_DONE,
            "**AWS Backup のバックアップブランが1件も存在しない。**"
            "バックアップは各サービス個別の設定（RDS 自動バックアップ・EFS ポリシー）に"
            "依存しており、一元的な取得保証と復旧テストの仕組みが無い。",
            failed=["バックアップブラン 0 件"],
            evidence=evidence,
            remediation="日次・週次のバックアップブランを作り、タグベースのリソース選択で"
            "EC2 / RDS / EFS を対象に含める。別リージョンまたは別アカウントの"
            "バックアップボールトへのコピーも設定すること。",
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    selection_by_plan: dict[str, int] = {}
    for selection in selections:
        plan_id = str(selection.get("BackupPlanId") or "")
        selection_by_plan[plan_id] = selection_by_plan.get(plan_id, 0) + 1

    for i, plan in enumerate(plans):
        plan_id = str(plan.get("BackupPlanId") or "")
        name = str(plan.get("BackupPlanName") or plan_id)
        evidence.append(f"storage.backup_plans[{i}]")
        count = selection_by_plan.get(plan_id, 0)
        if count:
            passed.append(f"プラン {name}（対象選択 {count} 件）")
        else:
            failed.append(f"プラン {name}: 対象リソースの選択が 0 件（何もバックアップされない）")

    notes.append(f"AWS Backup が保護中のリソース: {len(protected)} 件")

    return _finish(
        "AWS Backup のプランと対象", passed, failed, evidence,
        "対象選択が空のプランにリソース割り当て（タグベース推奨）を追加し、"
        "復旧テストを定期的に実施すること。",
        notes=notes,
    )


@check(
    "BCP-06", BCP, "EBS スナップショットの取得実績",
    "直近のスナップショットが無いと、EBS 障害や誤削除から戻せる時点が存在しない。",
    "AWS Well-Architected 信頼性の柱（定期バックアップ）", MEDIUM, requires=("compute",),
)
def bcp06_ebs_snapshots(inv: dict) -> CheckResult:
    """使用中ボリュームごとに、直近 SNAPSHOT_FRESH_DAYS 日以内のスナップショットがあるか見る。"""
    snapshots = _dicts(inv, "compute", "snapshots")
    volumes = _dicts(inv, "compute", "volumes")
    evidence = ["compute.snapshots", "compute.volumes"]

    latest: dict[str, int] = {}
    for snapshot in snapshots:
        volume_id = str(snapshot.get("VolumeId") or "")
        age = _days_old(snapshot.get("StartTime"))
        if not volume_id or age is None:
            continue
        latest[volume_id] = min(latest.get(volume_id, age), age)

    passed: list[str] = []
    failed: list[str] = []
    for volume in volumes:
        volume_id = str(volume.get("VolumeId"))
        label = f"{volume_id}（{volume.get('Size')}GiB）"
        age = latest.get(volume_id)
        if age is None:
            failed.append(f"{label}: スナップショットが1件も無い")
        elif age > SNAPSHOT_FRESH_DAYS:
            failed.append(f"{label}: 最新スナップショットが {age} 日前")
        else:
            passed.append(f"{label}（{age} 日前）")

    notes = []
    if _dicts(inv, "storage", "backup_plans"):
        notes.append(
            "AWS Backup のプランが存在するため、一部のボリュームはそちらで保護されている"
            "可能性がある（BCP-05 と併せて確認すること）。"
        )

    return _finish(
        "EBS スナップショットの取得実績", passed, failed, evidence,
        "Data Lifecycle Manager または AWS Backup で日次スナップショットを自動取得し、"
        "世代管理（保持期間）を設定すること。",
        notes=notes,
        na_text="EBS ボリュームが存在しないため、評価対象外。",
    )


@check(
    "BCP-07", BCP, "ALB 配下のターゲットの AZ 冗長",
    "ターゲットが単一 AZ に偏っていると、AZ 障害でサービスが完全に停止する。",
    "AWS FSBP ELB.13（複数 AZ 配置）", MEDIUM, requires=("edge",),
)
def bcp07_target_az(inv: dict) -> CheckResult:
    """ターゲットグループのターゲットが複数 AZ にまたがっているか見る。"""
    instance_az = {
        str(i.get("InstanceId")): str((i.get("Placement") or {}).get("AvailabilityZone") or "")
        for i in _dicts(inv, "compute", "instances")
        if i.get("InstanceId")
    }
    lb_by_arn = {
        str(lb.get("LoadBalancerArn")): lb for lb in _dicts(inv, "edge", "load_balancers")
    }
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, group in enumerate(_dicts(inv, "edge", "target_groups")):
        name = str(group.get("TargetGroupName"))
        arns = [str(a) for a in group.get("LoadBalancerArns") or []]
        lb_names = "、".join(
            _lb_name(lb_by_arn[a]) for a in arns if a in lb_by_arn
        ) or "（LB 未関連付け）"
        evidence.append(f"edge.target_groups[{i}].Targets")
        targets = [t for t in group.get("Targets") or [] if isinstance(t, dict)]
        if not targets:
            failed.append(f"ターゲットグループ {name}（{lb_names}）: ターゲット 0 台")
            continue
        zones: set[str] = set()
        unknown = 0
        for target in targets:
            target_id = str((target.get("Target") or {}).get("Id") or "")
            zone = instance_az.get(target_id) or str(
                (target.get("Target") or {}).get("AvailabilityZone") or ""
            )
            if zone:
                zones.add(zone)
            else:
                unknown += 1
        label = f"ターゲットグループ {name}（{lb_names}／ターゲット {len(targets)} 台）"
        if unknown:
            notes.append(f"{label}: {unknown} 台の AZ を特定できなかった")
        if len(zones) >= 2:
            passed.append(f"{label}: {'、'.join(sorted(zones))}")
        elif zones:
            failed.append(f"{label}: **{'、'.join(zones)} の単一 AZ に偏っている**")
        else:
            failed.append(f"{label}: ターゲットの AZ を特定できず冗長性を確認できない")

    return _finish(
        "ALB 配下のターゲットの AZ 冗長", passed, failed, evidence,
        "各ターゲットグループに 2 つ以上の AZ のターゲットを登録する。"
        "Auto Scaling グループを使えば AZ 分散が自動で維持される。",
        notes=notes,
        na_text="ターゲットグループが存在しないため、評価対象外。",
    )


@check(
    "BCP-08", BCP, "NAT Gateway の AZ 冗長",
    "NAT Gateway が1つの AZ にしか無いと、その AZ 障害で全 AZ の外向き通信が止まる。",
    "AWS Well-Architected 信頼性の柱（NAT Gateway の AZ 冗長）", MEDIUM,
    requires=("network",),
)
def bcp08_nat_redundancy(inv: dict) -> CheckResult:
    """NAT Gateway の配置 AZ 数と、VPC が使っている AZ 数を比べる。"""
    gateways = [
        gw for gw in _dicts(inv, "network", "nat_gateways")
        if str(gw.get("State")) not in ("deleted", "deleting")
    ]
    evidence = ["network.nat_gateways", "network.subnets"]
    if not gateways:
        return _res(
            NOT_APPLICABLE,
            "NAT Gateway が存在しないため、評価対象外"
            "（プライベートサブネットからの外向き通信が無いか、別方式を使っている）。",
            evidence=evidence,
        )

    subnet_az = _subnet_az(inv)
    nat_zones = {
        subnet_az.get(str(gw.get("SubnetId")), "")
        for gw in gateways
    } - {""}
    # インスタンス・RDS が実際に使っている AZ（＝外向き通信が必要な AZ）
    used_zones = {
        str((i.get("Placement") or {}).get("AvailabilityZone") or "")
        for i in _dicts(inv, "compute", "instances")
    } - {""}
    used_zones |= {
        str(db.get("AvailabilityZone") or "") for db in _dicts(inv, "database", "db_instances")
    } - {""}

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    label = f"NAT Gateway {len(gateways)} 台（配置 AZ: {'、'.join(sorted(nat_zones)) or '不明'}）"

    if len(nat_zones) >= 2:
        passed.append(label)
    else:
        failed.append(
            f"{label}: **単一 AZ にのみ配置**。ワークロードは "
            f"{'、'.join(sorted(used_zones)) or '不明'} の AZ にある。"
        )
    missing = sorted(used_zones - nat_zones)
    if missing:
        notes.append(
            f"NAT Gateway が無い AZ にワークロードがある: {'、'.join(missing)}。"
            "クロス AZ 通信の費用も発生している。"
        )

    return _finish(
        "NAT Gateway の AZ 冗長", passed, failed, evidence,
        "ワークロードを配置している AZ ごとに NAT Gateway を作り、"
        "各 AZ のプライベートルートテーブルを自 AZ の NAT に向けること"
        "（可用性とクロス AZ 通信費用の両方が改善する）。",
        notes=notes,
    )


# ===========================================================================
# 8. 鍵・シークレット（KEY）
# ===========================================================================


@check(
    "KEY-01", KEY, "KMS カスタマー管理キーの自動ローテーション",
    "長期間同じ鍵を使い続けると、鍵が漏れた場合の影響範囲が際限なく広がる。",
    "CIS AWS Foundations v3.0 3.6", MEDIUM, requires=("security",),
)
def key01_kms_rotation(inv: dict) -> CheckResult:
    """kms_keys（カスタマー管理キーのみ）の RotationEnabled を見る。"""
    keys = _dicts(inv, "security", "kms_keys")
    evidence = ["security.kms_keys"]
    if "kms_keys" not in _sect(inv, "security"):
        return _unknown(
            "KMS キーの一覧（kms:ListKeys / DescribeKey / GetKeyRotationStatus）",
            inv, ("kms",), evidence=evidence,
            remediation="KMS の読み取り権限を付けて再収集すること。",
        )
    if not keys:
        return _res(
            NOT_APPLICABLE,
            "カスタマー管理の KMS キーが存在しないため、評価対象外"
            "（AWS 管理キーは AWS 側で自動ローテーションされる）。",
            evidence=evidence,
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    for i, key in enumerate(keys):
        key_id = str(key.get("KeyId"))
        label = f"{key.get('Description') or '(説明なし)'} ({key_id})"
        evidence.append(f"security.kms_keys[{i}].RotationEnabled")
        state = str(key.get("KeyState") or "")
        if state in ("PendingDeletion", "PendingReplicaDeletion"):
            notes.append(f"{label}: {state}（削除待ちのため評価対象外）")
            continue
        if str(key.get("KeySpec") or key.get("CustomerMasterKeySpec") or "").startswith(
            ("RSA", "ECC", "SM2", "HMAC")
        ):
            notes.append(f"{label}: 非対称／HMAC キーのため自動ローテーション対象外")
            continue
        rotation = key.get("RotationEnabled")
        if rotation is None:
            notes.append(f"{label}: ローテーション状態が取得できていない")
        elif rotation:
            passed.append(label)
        else:
            failed.append(f"{label}: 自動ローテーション無効")

    if not passed and not failed:
        return _res(
            NOT_APPLICABLE,
            "自動ローテーションの対象となる対称キーが存在しないため、評価対象外。",
            evidence=evidence,
            notes=notes,
        )

    return _finish(
        "KMS カスタマー管理キーの自動ローテーション", passed, failed, evidence,
        "対称キーは自動ローテーション（既定 1 年）を有効にする。"
        "過去の暗号文は古い鍵バージョンで復号され続けるため、既存データへの影響は無い。",
        notes=notes,
    )


@check(
    "KEY-02", KEY, "Secrets Manager のローテーション設定",
    "ローテーションされない資格情報は、漏えい時に無期限で有効なままになる。",
    "AWS FSBP SecretsManager.1", MEDIUM, requires=("security",),
)
def key02_secret_rotation(inv: dict) -> CheckResult:
    """secrets の RotationEnabled / LastRotatedDate を見る（**値は取得していない**）。"""
    secrets = _dicts(inv, "security", "secrets")
    evidence = ["security.secrets"]
    if "secrets" not in _sect(inv, "security"):
        return _unknown(
            "Secrets Manager のシークレット一覧（secretsmanager:ListSecrets）",
            inv, ("secretsmanager",), evidence=evidence,
            remediation="`secretsmanager:ListSecrets` の権限を付けて再収集すること"
            "（値の取得 GetSecretValue はガードが拒否するため実施しない）。",
        )
    if not secrets:
        return _res(
            NOT_APPLICABLE,
            "Secrets Manager のシークレットが存在しないため、評価対象外。",
            evidence=evidence,
            notes=[
                "シークレットが 0 件ということは、DB のパスワード等が"
                "環境変数・設定ファイル・SSM の平文パラメータ（KEY-03）に置かれている可能性がある。"
            ],
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    for i, secret in enumerate(secrets):
        name = str(secret.get("Name"))
        evidence.append(f"security.secrets[{i}].RotationEnabled")
        if secret.get("RotationEnabled"):
            age = _days_old(secret.get("LastRotatedDate"))
            passed.append(
                f"{name}（最終ローテーション {age if age is not None else '未実施'} 日前）"
            )
            if age is not None and age > 365:
                notes.append(f"{name}: ローテーション有効だが最後に回ったのは {age} 日前")
        else:
            failed.append(f"{name}: ローテーション無効")

    return _finish(
        "Secrets Manager のローテーション設定", passed, failed, evidence,
        "RDS 等のマネージドなローテーションは AWS 提供の Lambda で自動化できる。"
        "アプリ側が複数バージョン（AWSCURRENT / AWSPREVIOUS）を扱えることを確認してから有効化すること。",
        notes=notes,
    )


@check(
    "KEY-03", KEY, "SSM Parameter Store の SecureString 使用状況",
    "平文の String パラメータに資格情報を置くと、閲覧権限のある全員に見える。",
    "AWS Foundational Security Best Practices（SSM パラメータの SecureString 化）",
    MEDIUM, requires=("security",),
)
def key03_ssm_securestring(inv: dict) -> CheckResult:
    """ssm_parameters_meta の Type を見る（**値は取得していない**）。

    名前に secret / password / key / token 等を含む平文パラメータを不合格とする。
    """
    params = _dicts(inv, "security", "ssm_parameters_meta")
    evidence = ["security.ssm_parameters_meta"]
    if "ssm_parameters_meta" not in _sect(inv, "security"):
        return _unknown(
            "SSM パラメータのメタ情報（ssm:DescribeParameters）", inv, ("ssm",),
            evidence=evidence,
            remediation="`ssm:DescribeParameters` の権限を付けて再収集すること"
            "（値の取得 GetParameter 系はガードが拒否するため実施しない）。",
        )
    if not params:
        return _res(
            NOT_APPLICABLE,
            "SSM パラメータが存在しないため、評価対象外。",
            evidence=evidence,
        )

    sensitive_words = (
        "secret", "password", "passwd", "pwd", "token", "credential",
        "apikey", "api_key", "private", "cert", "auth",
    )
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    plain_count = 0

    for i, param in enumerate(params):
        name = str(param.get("Name"))
        evidence.append(f"security.ssm_parameters_meta[{i}].Type")
        param_type = str(param.get("Type") or "")
        lowered = name.lower()
        if param_type == "SecureString":
            passed.append(f"{name}（SecureString）")
            continue
        plain_count += 1
        if any(word in lowered for word in sensitive_words):
            failed.append(f"{name}: **{param_type} のまま**（名前から機微情報の可能性が高い）")

    if plain_count and not failed:
        notes.append(
            f"平文（String / StringList）のパラメータが {plain_count} 件あるが、"
            "名前からは機微情報とは判断できなかった。**値そのものは収集していない**ため、"
            "実際に秘密が入っていないかは別途確認すること。"
        )
    if not passed and not failed:
        return _res(
            NOT_DONE if plain_count else NOT_APPLICABLE,
            f"SecureString のパラメータが 1 件も無く、{plain_count} 件すべてが平文。"
            if plain_count else "評価対象のパラメータが存在しない。",
            failed=[f"平文パラメータ {plain_count} 件"] if plain_count else [],
            evidence=evidence,
            remediation="資格情報は SecureString（KMS 暗号化）か Secrets Manager に移すこと。",
            notes=notes,
        )

    return _finish(
        "SSM Parameter Store の SecureString 使用", passed, failed, evidence,
        "機微なパラメータは SecureString として作り直し（Type は変更できないため新規作成 → "
        "参照先の切り替え → 旧パラメータ削除）、KMS キーで暗号化すること。",
        notes=notes,
    )


@check(
    "KEY-04", KEY, "EC2 キーペアの棚卸し",
    "使われていないキーペアは、秘密鍵の保有者が不明なまま残り退職者経由の侵入口になる。",
    "AWS Well-Architected セキュリティの柱（鍵の棚卸し）", MEDIUM, requires=("compute",),
)
def key04_key_pairs(inv: dict) -> CheckResult:
    """key_pairs のうち、どのインスタンスからも参照されていないものを洗い出す。"""
    key_pairs = _dicts(inv, "compute", "key_pairs")
    evidence = ["compute.key_pairs", "compute.instances[].KeyName"]
    if not key_pairs:
        return _res(
            NOT_APPLICABLE,
            "登録済みの EC2 キーペアが存在しないため、評価対象外。",
            evidence=evidence,
        )

    in_use: dict[str, list[str]] = {}
    for instance in _dicts(inv, "compute", "instances"):
        name = instance.get("KeyName")
        if name:
            in_use.setdefault(str(name), []).append(str(instance.get("InstanceId")))
    for template in _dicts(inv, "compute", "launch_templates"):
        data = template.get("LaunchTemplateData") or {}
        if data.get("KeyName"):
            in_use.setdefault(str(data["KeyName"]), []).append(
                f"起動テンプレート {template.get('LaunchTemplateName')}"
            )

    passed: list[str] = []
    failed: list[str] = []
    for key_pair in key_pairs:
        name = str(key_pair.get("KeyName"))
        age = _days_old(key_pair.get("CreateTime"))
        users = in_use.get(name)
        label = f"{name}（作成 {age if age is not None else '?'} 日前）"
        if users:
            passed.append(f"{label}: {len(users)} 台で使用中")
        else:
            failed.append(f"{label}: どのインスタンス・起動テンプレートからも参照されていない")

    notes = [
        "**起動後に `~/.ssh/authorized_keys` へ追記された鍵は AWS API では見えない。**"
        "実際の鍵の本数と秘密鍵の保有者は EC2 内部調査とヒアリングが必要（questions.py Q9 を参照）。"
    ]

    return _finish(
        "EC2 キーペアの棚卸し", passed, failed, evidence,
        "未使用のキーペアは AWS から削除する（削除してもインスタンス内の authorized_keys は"
        "消えないため、併せてインスタンス側の鍵も整理すること）。"
        "恒久対策は SSM Session Manager への移行による鍵の全廃。",
        notes=notes,
    )


@check(
    "KEY-05", KEY, "ACM 証明書の有効期限",
    "証明書が切れると全ユーザーがブラウザ警告で弾かれ、実質的なサービス停止になる。",
    "CIS AWS Foundations v3.0 1.19 / AWS FSBP ACM.1", HIGH, requires=("edge",),
)
def key05_acm_expiry(inv: dict) -> CheckResult:
    """acm_certificates の NotAfter と RenewalEligibility を見る。"""
    certificates = _dicts(inv, "edge", "acm_certificates")
    evidence: list[str] = ["edge.acm_certificates"]
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []

    for i, certificate in enumerate(certificates):
        domain = str(certificate.get("DomainName"))
        in_use = certificate.get("InUseBy") or []
        label = f"{domain}（{certificate.get('_Region') or 'リージョン不明'}／使用先 {len(in_use)} 件）"
        evidence.append(f"edge.acm_certificates[{i}].NotAfter")
        if str(certificate.get("Status")) != "ISSUED":
            failed.append(f"{label}: Status={certificate.get('Status')}")
            continue
        remaining = _days_old(certificate.get("NotAfter"))
        remaining = -remaining if remaining is not None else None
        if remaining is None:
            notes.append(f"{label}: NotAfter が取得できていない")
            continue
        if remaining < 0:
            failed.append(f"{label}: **{-remaining} 日前に期限切れ**")
        elif remaining <= CERT_EXPIRY_WARN_DAYS:
            failed.append(f"{label}: 残り {remaining} 日で期限切れ")
        else:
            passed.append(f"{label}: 残り {remaining} 日")
        if str(certificate.get("RenewalEligibility")) == "INELIGIBLE":
            notes.append(
                f"{label}: **RenewalEligibility=INELIGIBLE**（自動更新されない）。"
                "インポート証明書か、DNS 検証が外れている可能性がある。"
            )
        if not in_use:
            notes.append(f"{label}: どのリソースにも関連付けられていない（棚卸し対象）")

    return _finish(
        "ACM 証明書の有効期限", passed, failed, evidence,
        f"残り {CERT_EXPIRY_WARN_DAYS} 日以内の証明書は更新状況を確認する。"
        "DNS 検証の CNAME が残っていれば ACM が自動更新するため、"
        "Route 53 のレコードが消えていないか確認すること。",
        notes=notes,
        na_text="ACM 証明書が存在しないため、評価対象外。",
    )


# ===========================================================================
# 9. パッチ・構成管理（PAT）
# ===========================================================================


@check(
    "PAT-01", PAT, "SSM 管理下のインスタンス比率",
    "**SSM 非管理のインスタンスはパッチ適用も緊急対応もできない。**"
    "脆弱性が公表されても、中に入る手段が SSH しか無い状態になる。",
    "AWS FSBP SSM.1", HIGH, requires=("compute",),
)
def pat01_ssm_managed(inv: dict) -> CheckResult:
    """instances と ssm_managed_instances を突き合わせる。"""
    instances = [
        i for i in _dicts(inv, "compute", "instances")
        if str((i.get("State") or {}).get("Name")) not in ("terminated", "shutting-down")
    ]
    managed = {
        str(m.get("InstanceId")): m for m in _dicts(inv, "compute", "ssm_managed_instances")
    }
    evidence = ["compute.instances", "compute.ssm_managed_instances"]
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []

    for instance in instances:
        instance_id = str(instance.get("InstanceId"))
        label = _instance_label(instance)
        info = managed.get(instance_id)
        if info is None:
            failed.append(f"{label}: SSM 管理外")
            continue
        ping = str(info.get("PingStatus") or "")
        if ping == "Online":
            passed.append(f"{label}（エージェント {info.get('AgentVersion') or '不明'}）")
        else:
            failed.append(f"{label}: PingStatus={ping or '不明'}")

    orphans = sorted(set(managed) - {str(i.get("InstanceId")) for i in instances})
    if orphans:
        notes.append(
            f"EC2 側に存在しないのに SSM が認識しているインスタンスが {len(orphans)} 件ある"
            "（オンプレ登録またはハイブリッドアクティベーションの可能性）"
        )

    return _finish(
        "SSM 管理下のインスタンス比率", passed, failed, evidence,
        "SSM Agent の導入・起動、インスタンスプロファイルへの `AmazonSSMManagedInstanceCore` 付与、"
        "SSM エンドポイントへの経路（NAT または VPC エンドポイント）の3点を確認すること。"
        "SSM 管理下に入れば Session Manager・Patch Manager・Inspector がまとめて使えるようになる。",
        notes=notes,
        na_text="EC2 インスタンスが存在しないため、評価対象外。",
    )


@check(
    "PAT-02", PAT, "SSM パッチコンプライアンス",
    "未適用の重要パッチが残っていると、公開済みの脆弱性をそのまま突かれる。",
    "AWS FSBP SSM.2 / SSM.3", HIGH, requires=("compute",),
)
def pat02_patch_compliance(inv: dict) -> CheckResult:
    """ssm_patch_states の MissingCount / FailedCount を見る。"""
    states = _dicts(inv, "compute", "ssm_patch_states")
    managed = _dicts(inv, "compute", "ssm_managed_instances")
    evidence = ["compute.ssm_patch_states"]

    if not states:
        if not managed:
            return _res(
                NOT_APPLICABLE,
                "SSM 管理下のインスタンスが無いためパッチ状態を評価できない"
                "（まず PAT-01 の是正が必要）。",
                evidence=evidence,
            )
        return _unknown(
            "SSM のパッチ適用状況（ssm:DescribeInstancePatchStates）", inv, ("ssm",),
            evidence=evidence,
            remediation="Patch Manager のパッチベースラインとメンテナンスウィンドウを設定し、"
            "スキャンを実行すること（一度もスキャンしていないとパッチ状態は空になる）。",
            notes=[
                f"SSM 管理下のインスタンスは {len(managed)} 台あるが、"
                "パッチ状態のレコードが 1 件も無い（Patch Manager 未使用の可能性が高い）"
            ],
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    for i, state in enumerate(states):
        instance_id = str(state.get("InstanceId"))
        evidence.append(f"compute.ssm_patch_states[{i}]")
        missing = state.get("MissingCount") or 0
        failed_count = state.get("FailedCount") or 0
        baseline = state.get("BaselineId") or "ベースライン不明"
        scanned = _days_old(state.get("OperationEndTime"))
        label = f"{instance_id}（{baseline}）"
        reasons: list[str] = []
        if missing:
            reasons.append(f"未適用 {missing} 件")
        if failed_count:
            reasons.append(f"適用失敗 {failed_count} 件")
        if scanned is not None and scanned > 30:
            reasons.append(f"最終スキャン {scanned} 日前")
        if reasons:
            failed.append(f"{label}: {'／'.join(reasons)}")
        else:
            passed.append(f"{label}: 未適用 0 件")

    unscanned = len(managed) - len(states)
    if unscanned > 0:
        notes.append(
            f"SSM 管理下 {len(managed)} 台のうち {unscanned} 台はパッチ状態のレコードが無い"
            "（スキャン対象に含まれていない）"
        )

    return _finish(
        "SSM パッチコンプライアンス", passed, failed, evidence,
        "Patch Manager のメンテナンスウィンドウで定期スキャンと適用を自動化する。"
        "適用失敗があるインスタンスは個別にログ（`/var/log/amazon/ssm/`）を確認すること。",
        notes=notes,
    )


@check(
    "PAT-03", PAT, "AMI の鮮度",
    "古い AMI から起動したインスタンスは、初回起動時点で既知脆弱性を大量に抱える。",
    "AWS Well-Architected（AMI の鮮度と廃止予定の管理）", MEDIUM, requires=("compute",),
)
def pat03_ami_freshness(inv: dict) -> CheckResult:
    """使用中の AMI の CreationDate と DeprecationTime を見る。"""
    images = {str(img.get("ImageId")): img for img in _dicts(inv, "compute", "images")}
    instances = _dicts(inv, "compute", "instances")
    evidence = ["compute.images", "compute.instances[].ImageId"]

    in_use: dict[str, list[str]] = {}
    for instance in instances:
        image_id = str(instance.get("ImageId") or "")
        if image_id:
            in_use.setdefault(image_id, []).append(_instance_label(instance))

    if not in_use:
        return _res(
            NOT_APPLICABLE,
            "インスタンスが参照している AMI が無いため、評価対象外。",
            evidence=evidence,
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    for image_id, users in sorted(in_use.items()):
        image = images.get(image_id)
        if image is None:
            failed.append(
                f"{image_id}: **AMI が既に存在しない**（{len(users)} 台が使用中・再起動で再作成できない）"
            )
            continue
        name = str(image.get("Name") or image_id)
        age = _days_old(image.get("CreationDate"))
        label = f"{name} ({image_id}／{len(users)} 台が使用中)"
        reasons: list[str] = []
        if age is not None and age > AMI_STALE_DAYS:
            reasons.append(f"作成から {age} 日")
        deprecation = _days_old(image.get("DeprecationTime"))
        if deprecation is not None and deprecation >= 0:
            reasons.append(f"**廃止予定日を {deprecation} 日超過**")
        elif deprecation is not None:
            notes.append(f"{label}: あと {-deprecation} 日で廃止予定")
        if reasons:
            failed.append(f"{label}: {'／'.join(reasons)}")
        else:
            passed.append(f"{label}（作成 {age if age is not None else '?'} 日前）")

    return _finish(
        "AMI の鮮度", passed, failed, evidence,
        "EC2 Image Builder 等で定期的にベース AMI を作り直し、"
        "起動テンプレートの AMI ID を更新する。当面はインスタンス側で"
        "パッチ適用（PAT-02）して差分を埋めること。",
        notes=notes,
    )


@check(
    "PAT-04", PAT, "RDS エンジンバージョンと自動マイナーバージョンアップ",
    "EOL エンジンはセキュリティパッチが出ず、延長サポート料金も発生する。",
    "CIS AWS Foundations v3.0 2.3.2 / AWS FSBP RDS.13", HIGH, requires=("database",),
)
def pat04_rds_engine(inv: dict) -> CheckResult:
    """db_instances の Engine / EngineVersion / AutoMinorVersionUpgrade を見る。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, db in enumerate(_dicts(inv, "database", "db_instances")):
        identifier = str(db.get("DBInstanceIdentifier"))
        engine = str(db.get("Engine") or "")
        version = str(db.get("EngineVersion") or "")
        evidence.append(f"database.db_instances[{i}].EngineVersion")
        label = f"RDS {identifier}（{engine} {version}）"
        reasons: list[str] = []
        for engine_prefix, eol_versions in EOL_ENGINE_PREFIXES:
            if engine.startswith(engine_prefix) and version.startswith(eol_versions):
                reasons.append("**サポート終了（または延長サポート）バージョン**")
                break
        if not db.get("AutoMinorVersionUpgrade"):
            reasons.append("自動マイナーバージョンアップが無効")
        if reasons:
            failed.append(f"{label}: {'／'.join(reasons)}")
        else:
            passed.append(label)

    versions = _dicts(inv, "database", "db_engine_versions")
    if versions:
        notes.append(
            "アップグレード先の候補は `database.db_engine_versions` の "
            "`ValidUpgradeTarget` を参照すること。"
        )
    notes.append(
        "EOL 判定は本ツール内蔵のバージョン表による一次判定。"
        "正確な終了日は AWS のドキュメント（RDS のリリースカレンダー）で確認すること。"
    )

    return _finish(
        "RDS エンジンバージョンの維持", passed, failed, evidence,
        "EOL エンジンはサポート対象バージョンへアップグレードする"
        "（スナップショットからの検証環境で互換性確認 → 計画停止で本番適用）。"
        "自動マイナーバージョンアップはメンテナンスウィンドウを設定したうえで有効化すること。",
        notes=notes,
        na_text="RDS インスタンスが存在しないため、評価対象外。",
    )


@check(
    "PAT-05", PAT, "Lambda ランタイムのサポート状況",
    "EOL ランタイムはセキュリティ更新が止まり、いずれ関数の更新自体ができなくなる。",
    "AWS FSBP Lambda.2", MEDIUM, requires=("serverless",),
)
def pat05_lambda_runtime(inv: dict) -> CheckResult:
    """lambda_functions[].Runtime を EOL 一覧と突き合わせる。"""
    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    evidence: list[str] = []

    for i, function in enumerate(_dicts(inv, "serverless", "lambda_functions")):
        name = str(function.get("FunctionName"))
        runtime = str(function.get("Runtime") or "")
        evidence.append(f"serverless.lambda_functions[{i}].Runtime")
        if not runtime:
            notes.append(f"{name}: ランタイム未取得（コンテナイメージ形式の可能性）")
            continue
        if runtime in EOL_LAMBDA_RUNTIMES:
            failed.append(f"{name}: **{runtime}（サポート終了）**")
        else:
            passed.append(f"{name}（{runtime}）")

    notes.append(
        "EOL 判定は本ツール内蔵の一覧による一次判定。"
        "最新の状況は AWS Lambda のランタイムサポートポリシーで確認すること。"
    )

    return _finish(
        "Lambda ランタイムのサポート状況", passed, failed, evidence,
        "サポート中のランタイム（python3.12 / nodejs20.x / provided.al2023 等）へ"
        "移行する。go1.x は provided.al2023 への移行が必要で、ビルド方法も変わる点に注意。",
        notes=notes,
        na_text="Lambda 関数が存在しないため、評価対象外。",
    )


# ===========================================================================
# 10. 統制（GOV）
# ===========================================================================


@check(
    "GOV-01", GOV, "Organizations 配下の統制と SCP",
    "SCP が無いと、アカウント内の管理者権限を誰も止められない（ガードレールが無い）。",
    "AWS Organizations / CIS AWS Foundations v3.0（組織による統制）", MEDIUM,
    requires=("security",),
)
def gov01_organizations(inv: dict) -> CheckResult:
    """organizations と organizations_policies を見る。"""
    organizations = _map(inv, "security", "organizations")
    evidence = ["security.organizations", "security.organizations_policies"]
    if not organizations or not organizations.get("Organization"):
        denied = denied_for(inv, ("organizations",))
        if denied:
            return _unknown("組織情報", inv, ("organizations",), evidence=evidence)
        return _res(
            NOT_DONE,
            "**このアカウントは AWS Organizations 配下にない**（スタンドアロン運用）。"
            "SCP による予防的ガードレールが一切効いていない状態。",
            failed=["Organizations 未使用"],
            evidence=evidence,
            remediation="組織を作成してアカウントを招待し、リージョン制限・"
            "ルートユーザー操作の禁止・CloudTrail 停止の禁止などの SCP を適用すること。",
        )

    organization = organizations.get("Organization") or {}
    parents = organizations.get("Parents") or []
    policies = _dicts(inv, "security", "organizations_policies")
    fallback = [
        p for p in organizations.get("ServiceControlPolicies") or [] if isinstance(p, dict)
    ]
    entries = policies or fallback

    passed: list[str] = [
        f"組織 {organization.get('Id')}（FeatureSet={organization.get('FeatureSet')}）"
    ]
    failed: list[str] = []
    notes: list[str] = []

    if str(organization.get("FeatureSet")) != "ALL":
        failed.append(
            f"組織の FeatureSet が {organization.get('FeatureSet')}（SCP を使うには ALL が必要）"
        )
    if parents:
        notes.append(
            "所属 OU: "
            + "、".join(
                f"{p.get('Id')}（{p.get('Type')}）" for p in parents if isinstance(p, dict)
            )
        )

    restrictive = [
        p for p in entries
        if str(p.get("Name")) != "FullAWSAccess" and not p.get("AwsManaged")
    ]
    if not entries:
        failed.append("このアカウントに適用されている SCP が 0 件")
    elif not restrictive:
        failed.append(
            f"適用されている SCP は AWS 既定の FullAWSAccess のみ"
            f"（{len(entries)} 件）。**実質的な制限が何も掛かっていない**"
        )
    else:
        passed.append(
            f"制限型 SCP {len(restrictive)} 件: "
            + "、".join(str(p.get("Name")) for p in restrictive[:5])
        )
        if not policies:
            notes.append(
                "SCP の**本文が未収集**のため、実際に何が禁止されているかは確認できていない"
                "（`organizations:DescribePolicy` を付けて再収集すること）。"
            )

    return _finish(
        "Organizations 配下の統制と SCP", passed, failed, evidence,
        "利用リージョンの制限、ルートユーザーの操作禁止、CloudTrail / Config / GuardDuty の"
        "無効化禁止を最低限の SCP として適用すること。まず監査用 OU で影響を確認してから展開する。",
        notes=notes,
    )


@check(
    "GOV-02", GOV, "IAM Identity Center の利用",
    "IAM ユーザーの直接運用は、入退社時の棚卸しとパスワード管理を人力に頼ることになる。",
    "CIS AWS Foundations v3.0 1.21", MEDIUM, requires=("security",),
)
def gov02_identity_center(inv: dict) -> CheckResult:
    """identity_center.Instances と IAM ユーザー数を突き合わせる。"""
    instances = [
        i for i in (_map(inv, "security", "identity_center").get("Instances") or [])
        if isinstance(i, dict)
    ]
    users = _iam_list(inv, "users")
    evidence = ["security.identity_center.Instances", "security.iam.users"]
    notes: list[str] = []

    if instances:
        passed = [
            f"Identity Center インスタンス {i.get('InstanceArn') or i.get('IdentityStoreId')}"
            for i in instances
        ]
        failed: list[str] = []
        if users:
            failed.append(
                f"Identity Center を使いつつ IAM ユーザーも {len(users)} 人残っている"
                f"（{'、'.join(str(u.get('UserName')) for u in users[:5])}）"
            )
        return _finish(
            "IAM Identity Center への集約", passed, failed, evidence,
            "残っている IAM ユーザーを Identity Center の権限セットへ移行し、"
            "移行後にユーザーとアクセスキーを削除すること。",
            notes=notes,
        )

    if not users:
        return _res(
            DONE,
            "**IAM ユーザーが 0 人**であり、人の認証情報をアカウント内に持っていない"
            "（Identity Center または外部 IdP からのロール引き受け運用とみられる）。",
            passed=["IAM ユーザー 0 人"],
            evidence=evidence,
            notes=["Identity Center のインスタンスは検出されなかったため、"
                   "実際の認証基盤が何かは別途確認すること。"],
        )

    return _res(
        NOT_DONE,
        f"**IAM Identity Center を使っておらず、IAM ユーザー {len(users)} 人を直接運用している。**"
        "入退社時の棚卸しと長期認証情報の管理が人力に依存している状態。",
        failed=[
            f"IAM ユーザー {u.get('UserName')}" for u in users
        ],
        evidence=evidence,
        remediation="IAM Identity Center を有効化し、権限セットでアクセスを付与する運用へ移行する。"
        "移行後は IAM ユーザーとアクセスキー（IAM-05）を削除すること。",
    )


@check(
    "GOV-03", GOV, "タグ付けの一貫性",
    "Name タグが無いリソースは、棚卸し・費用配賦・障害時の特定がすべて手作業になる。",
    "AWS Well-Architected（タグ付け戦略）", LOW, requires=("network", "compute"),
)
def gov03_tagging(inv: dict) -> CheckResult:
    """主要リソースの Name タグの有無を集計する。"""
    targets = (
        ("EC2", "compute", "instances", "InstanceId"),
        ("EBS ボリューム", "compute", "volumes", "VolumeId"),
        ("セキュリティグループ", "network", "security_groups", "GroupId"),
        ("サブネット", "network", "subnets", "SubnetId"),
        ("NAT Gateway", "network", "nat_gateways", "NatGatewayId"),
        ("Elastic IP", "network", "elastic_ips", "AllocationId"),
    )
    passed: list[str] = []
    failed: list[str] = []
    evidence: list[str] = []
    notes: list[str] = []

    for label, section, key, id_key in targets:
        items = _dicts(inv, section, key)
        if not items:
            continue
        evidence.append(f"{section}.{key}[].Tags")
        untagged = [str(item.get(id_key)) for item in items if not _tag(item)]
        if untagged:
            ratio = round(len(untagged) * 100.0 / len(items))
            failed.append(
                f"{label}: {len(untagged)}/{len(items)} 件（{ratio}%）に Name タグが無い"
                f" — {'、'.join(untagged[:5])}"
            )
        else:
            passed.append(f"{label}: {len(items)} 件すべてに Name タグあり")

    notes.append(
        "Name タグの有無のみを見ている。Environment / Owner / CostCenter 等の"
        "運用タグの方針は別途定めること。"
    )

    return _finish(
        "タグ付けの一貫性", passed, failed, evidence,
        "最低限 Name と Environment を必須タグとして定め、AWS Config の"
        "`required-tags` ルールまたはタグポリシーで継続的に検査すること。",
        notes=notes,
        na_text="タグ評価の対象リソースが存在しないため、評価対象外。",
    )


@check(
    "GOV-04", GOV, "利用リージョンの絞り込み",
    "使っていないリージョンにリソースが残ると、監視も証跡も届かない死角になる。",
    "CIS AWS Foundations v3.0（全リージョンへの適用が前提）", LOW,
)
def gov04_region_scope(inv: dict) -> CheckResult:
    """本ツールは単一リージョンしか収集しないため、原理的に判定できない。"""
    meta = _sect(inv, "meta")
    region = meta.get("region") or "（リージョン不明）"
    trails = _dicts(inv, "logging", "cloudtrail_trails")
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    notes = [
        f"収集対象リージョン: `{region}` の1つのみ。"
        "他リージョンにリソースが存在するかは、このデータからは分からない。",
    ]
    if multi_region:
        notes.append(
            f"全リージョン証跡が {len(multi_region)} 本あるため、"
            "他リージョンでの操作は CloudTrail には記録されている"
            "（イベント本体は収集していない）。"
        )
    return _res(
        UNKNOWN,
        f"**判定不能。** awsprobe は単一リージョン（`{region}`）しか収集しないため、"
        "他リージョンのリソース有無は原理的に判定できない。",
        evidence=["meta.region", "logging.cloudtrail_trails[].IsMultiRegionTrail"],
        remediation="AWS Config のアグリゲータ、Resource Explorer、または "
        "`--region` を変えた awsprobe の再実行で全リージョンを棚卸しし、"
        "未使用リージョンは SCP（GOV-01）で禁止すること。",
        notes=notes,
    )


@check(
    "GOV-05", GOV, "CloudFormation のドリフトと StackSet の権限モデル",
    "ドリフトしたスタックは IaC と実態が乖離し、StackSet の権限モデル次第では"
    "外部アカウントが常時強い権限を持つ。",
    "AWS FSBP CloudFormation.1", MEDIUM, requires=("security",),
)
def gov05_cloudformation(inv: dict) -> CheckResult:
    """スタックの DriftInformation と StackSet の PermissionModel を見る。"""
    stacks = _dicts(inv, "security", "cloudformation_stacks")
    stack_sets = _dicts(inv, "security", "cloudformation_stack_sets")
    evidence = ["security.cloudformation_stacks", "security.cloudformation_stack_sets"]
    if not stacks and not stack_sets:
        return _res(
            NOT_APPLICABLE,
            "CloudFormation スタック・StackSet が存在しないため、評価対象外。",
            evidence=evidence,
        )

    passed: list[str] = []
    failed: list[str] = []
    notes: list[str] = []
    drift_unknown = 0

    for i, stack in enumerate(stacks):
        name = str(stack.get("StackName"))
        evidence.append(f"security.cloudformation_stacks[{i}].DriftInformation")
        status = str(stack.get("StackStatus") or "")
        if status.endswith(("_FAILED", "_ROLLBACK_COMPLETE")):
            failed.append(f"スタック {name}: StackStatus={status}")
            continue
        drift = (stack.get("DriftInformation") or {}).get("StackDriftStatus")
        if drift is None:
            drift_unknown += 1
            passed.append(f"スタック {name}（{status}／ドリフト未検出）")
        elif str(drift) == "DRIFTED":
            failed.append(f"スタック {name}: **ドリフトあり**（テンプレートと実態が乖離）")
        else:
            passed.append(f"スタック {name}（{status}／{drift}）")

    account_id = _account_id(inv)
    for i, stack_set in enumerate(stack_sets):
        name = str(stack_set.get("StackSetName"))
        evidence.append(f"security.cloudformation_stack_sets[{i}].PermissionModel")
        model = str(stack_set.get("PermissionModel") or "不明")
        admin_arn = str(stack_set.get("AdministrationRoleARN") or "")
        # マスク済み inventory では 12桁が ＜アカウント:xxxx＞ になっているため、
        # 両表記を解釈できる `_external_account_in` を使う（C-1）。
        external_account = _external_account_in(admin_arn, account_id)
        label = f"StackSet {name}（{model}）"
        if external_account:
            failed.append(
                f"{label}: 管理ロールが**外部アカウント {external_account}** のもの"
                f"（実行ロール {stack_set.get('ExecutionRoleName')}）"
            )
            notes.append(
                f"{name}: 外部アカウントからのデプロイ経路。実行ロールに付いている権限は "
                "IAM-06 / IAM-07 と併せて確認すること。"
            )
        elif model == "SELF_MANAGED":
            passed.append(f"{label}: 自アカウント管理")
        else:
            passed.append(label)

    if drift_unknown:
        notes.append(
            f"{drift_unknown} 件のスタックはドリフト検出が未実行"
            "（`DriftInformation` が未収集か、一度も検出していない）。"
        )

    return _finish(
        "CloudFormation のドリフトと StackSet の権限モデル", passed, failed, evidence,
        "ドリフト検出を定期実行し、乖離があればテンプレート側に反映する。"
        "外部アカウントが管理する StackSet は、配信元・実行ロールの権限・"
        "取得データを書面で開示させること。",
        notes=notes,
    )
