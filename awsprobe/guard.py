"""読み取り専用ガード。

boto3 が実際に発行する API オペレーションを before-call フックで検査し、
allowlist に載っていないものは例外で即停止する。
「うっかり変更系 API を呼ぶ」ことを構造的に不可能にするのが目的。
"""
from __future__ import annotations

import re
import threading

# 読み取り系とみなす接頭辞。これ以外は原則すべて拒否する。
READ_PREFIXES = (
    "Describe",
    "List",
    "Get",
    "Head",
    "Lookup",
    "BatchGet",
)
# 外した接頭辞と理由（戻すときは必ず DENY_OPERATIONS も見直すこと）:
#   Select / Query / Scan  … データ本体を読み出す（DynamoDB・S3 Select）
#   Retrieve / Preview     … 同上
#   Estimate               … Cost Explorer 等、1リクエスト課金
#   Simulate               … IAM ポリシーシミュレータ。副作用は無いが不要
#   Check / Test / Validate… apigateway:TestInvokeMethod はバックエンドを実際に叩く、
#                            dms:TestConnection は状態を作る、
#                            license-manager:CheckoutLicense はライセンスを消費する
#                            elastictranscoder:TestRole は SNS へ publish する


# 接頭辞が読み取り系に見えるのに実際は変更を伴う、または副作用が大きいもの。
# 明示的に拒否する。
DENY_OPERATIONS = {
    # 一時認証情報・トークンの発行
    ("sts", "GetFederationToken"),
    ("sts", "GetSessionToken"),
    ("ecr", "GetAuthorizationToken"),
    ("codeartifact", "GetAuthorizationToken"),
    ("elasticmapreduce", "GetClusterSessionCredentials"),
    ("connect", "GetFederationToken"),
    ("redshift", "GetClusterCredentials"),        # AutoCreate=true で DB ユーザーを作る
    ("quicksight", "GetDashboardEmbedUrl"),
    # パスワード・鍵・シークレットの実体
    ("ec2", "GetPasswordData"),
    ("secretsmanager", "GetSecretValue"),
    ("secretsmanager", "BatchGetSecretValue"),
    ("ssm", "GetParameter"),
    ("ssm", "GetParameters"),
    ("ssm", "GetParametersByPath"),
    ("ssm", "GetParameterHistory"),               # SecureString の値を返す
    ("iam", "GetCredentialReport"),
    ("iam", "GenerateCredentialReport"),
    # 業務データそのもの
    ("dynamodb", "GetItem"),
    ("dynamodb", "BatchGetItem"),
    ("dynamodb", "Scan"),
    ("dynamodb", "Query"),
    ("s3", "GetObject"),
    ("s3", "SelectObjectContent"),
    ("logs", "GetLogEvents"),
    ("logs", "FilterLogEvents"),
    ("cloudtrail", "LookupEvents"),
    # EC2 の UserData には認証情報が入っていることが多い
    ("ec2", "DescribeInstanceAttribute"),
    # 1リクエスト課金
    ("ce", "GetCostAndUsage"),
    ("ce", "GetCostForecast"),
    ("ce", "GetCostAndUsageWithResources"),
    # 実行時に副作用が出る
    ("ssm", "GetDeployablePatchSnapshotForInstance"),
}


# SSM RunCommand 系は「変更系」だが host-probe でのみ使う。
# 既定は拒否。ReadOnlyGuard(allow_ssm_command=True) で明示的に解禁する。
SSM_COMMAND_OPERATIONS = {
    ("ssm", "SendCommand"),
    ("ssm", "GetCommandInvocation"),
    ("ssm", "ListCommandInvocations"),
    ("ssm", "ListCommands"),
}


class ReadOnlyViolation(RuntimeError):
    """読み取り専用ガードに違反する API 呼び出しが行われた。"""


class ReadOnlyGuard:
    """boto3 Session に取り付ける読み取り専用ガード。

    使い方::

        guard = ReadOnlyGuard()
        guard.attach(session)

    `allow_ssm_command=True` のときだけ ssm:SendCommand 系を通す。
    """

    _EVENT = "before-call.*.*"

    def __init__(self, allow_ssm_command: bool = False, dry_run: bool = False):
        self.allow_ssm_command = allow_ssm_command
        self.dry_run = dry_run
        self._lock = threading.Lock()
        self.calls: list[tuple[str, str]] = []   # (service, Operation) の実績

    # -- 判定 ------------------------------------------------------------
    def is_allowed(self, service: str, operation: str) -> tuple[bool, str]:
        key = (service, operation)
        if key in DENY_OPERATIONS:
            return False, "明示的な拒否リストに含まれる（機微データ取得または高コスト）"
        if key in SSM_COMMAND_OPERATIONS:
            if self.allow_ssm_command:
                return True, "SSM コマンド実行が --enable-ssm で明示的に許可されている"
            return False, "SSM コマンド実行は既定で無効（--enable-ssm が必要）"
        if operation.startswith(READ_PREFIXES):
            return True, "読み取り系の接頭辞"
        return False, f"読み取り系の接頭辞に一致しない（{operation}）"

    # -- boto3 フック ----------------------------------------------------
    def _before_call(self, model, params, **kwargs):  # noqa: ANN001
        service = _service_id(model)
        operation = model.name
        ok, reason = self.is_allowed(service, operation)
        with self._lock:
            self.calls.append((service, operation))
        if not ok:
            raise ReadOnlyViolation(
                f"読み取り専用ガード違反: {service}:{operation} は実行できません。理由: {reason}"
            )
        if self.dry_run:
            raise _DryRunSkip(f"{service}:{operation}")

    def attach(self, session) -> None:  # noqa: ANN001
        session.events.register(self._EVENT, self._before_call, unique_id="awsprobe-readonly-guard")

    def summary(self) -> dict:
        with self._lock:
            calls = list(self.calls)
        counts: dict[str, int] = {}
        for svc, op in calls:
            counts[f"{svc}:{op}"] = counts.get(f"{svc}:{op}", 0) + 1
        return {
            "total_calls": len(calls),
            "distinct_operations": len(counts),
            "operations": dict(sorted(counts.items())),
        }


class _DryRunSkip(Exception):
    """--dry-run のとき、実際の送信直前に投げて呼び出しを止める内部例外。"""


def _service_id(model) -> str:  # noqa: ANN001
    """OperationModel からサービス識別子（'ec2' 等）を取り出す。"""
    meta = model.service_model.metadata
    for key in ("endpointPrefix", "serviceId", "signingName"):
        value = meta.get(key)
        if value:
            return str(value).lower().replace(" ", "-")
    return "unknown"


# --------------------------------------------------------------------------
# マスキング
# --------------------------------------------------------------------------

_ACCOUNT_RE = re.compile(r"(?<![\w.-])\d{12}(?![\w.-])")
_ENI_RE = re.compile(r"\beni-[0-9a-f]{8,}\b")
_PRIVATE_NET_RE = re.compile(
    r"^(10\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|"
    r"172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0$)"
)
_IPV4_RE = re.compile(r"(?<![\w.-])(?:\d{1,3}\.){3}\d{1,3}(?![\w.-])")
#: IPv6。`::` を含む省略形か、コロン7個の完全形だけを拾う。
#: 時刻表記（12:34:56）を誤って拾わないよう、この2形式に限定している。
_IPV6_RE = re.compile(
    r"(?<![\w:.])("
    r"(?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{1,4}){0,6}::"
    r"(?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{1,4}){0,6}"
    r"|(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r")(?:/\d{1,3})?(?![\w:.])"
)
#: EIP 由来の DNS 名（ec2-203-0-113-25.ap-northeast-1.compute.amazonaws.com）
_EIP_DNS_RE = re.compile(r"\bec2-(\d{1,3})-(\d{1,3})-\d{1,3}-\d{1,3}\b")

#: 12桁 ID をこの形に置き換える。**アカウントの同一性・別性は保たれる**ため、
#: 「外部アカウントを信頼しているか」といった判定はマスク後も成立する。
ACCOUNT_TOKEN_TEMPLATE = "＜アカウント:{}＞"
SELF_ACCOUNT_TOKEN = "＜自アカウント＞"
#: マスク済み文字列からアカウントを識別するための正規表現（判定ロジック側が使う）
ACCOUNT_TOKEN_RE = re.compile(r"＜アカウント:[0-9a-f]{4}＞")
SELF_ACCOUNT_TOKEN_RE = re.compile(r"＜自アカウント＞")

#: 12桁だが AWS アカウントID ではないもの（誤マスクを避ける）
_NOT_ACCOUNT_PREFIX = re.compile(
    r"(?:vol|snap|ami|eni|sg|subnet|vpc|rtb|acl|igw|nat|eipalloc|i|pl|tgw|dopt)-$"
)


def account_token(account_id: str) -> str:
    """アカウントIDを、同一性が保たれる短いトークンに変換する。"""
    import hashlib

    digest = hashlib.sha256(f"awsprobe:{account_id}".encode()).hexdigest()[:4]
    return ACCOUNT_TOKEN_TEMPLATE.format(digest)


def is_account_token(text: str) -> bool:
    """マスク済みのアカウント表現かどうか。"""
    return bool(ACCOUNT_TOKEN_RE.fullmatch(text) or SELF_ACCOUNT_TOKEN_RE.fullmatch(text))


def redact(obj, account_ids: set[str] | None = None, *, skip_keys: tuple[str, ...] = ()):
    """アカウントID・ENI ID・グローバルIPをマスクした複製を返す。

    設計上の要点:

    - **アカウントIDは消さずに擬似化する。** 同じアカウントは同じトークン、違う
      アカウントは違うトークンになるので、「外部アカウントを信頼しているか」
      （IAM-07 / Q27）のような判定はマスク後も成立する。自アカウントは
      `＜自アカウント＞` になるので、自分か他人かの区別も残る。
    - VPC 内部の私設アドレス（10 / 172.16-31 / 192.168 / 100.64-127）と
      `0.0.0.0` はネットワーク設計の判断に必要なので残す。
    - `vol-123456789012` のようなリソースIDの12桁は誤ってマスクしない。

    Args:
        obj: マスク対象（dict / list / str の入れ子）。
        account_ids: 自アカウントとして扱う ID の集合。
        skip_keys: この名前のキーの値は再帰せずそのまま残す（通常は使わない）。
    """
    account_ids = {a for a in (account_ids or set()) if a}
    return _redact_value(obj, account_ids, skip_keys)


def _redact_value(value, account_ids: set[str], skip_keys: tuple[str, ...] = ()):
    if isinstance(value, dict):
        return {
            k: (v if k in skip_keys else _redact_value(v, account_ids, skip_keys))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(v, account_ids, skip_keys) for v in value]
    if isinstance(value, str):
        return _redact_str(value, account_ids)
    return value


def _redact_str(text: str, account_ids: set[str]) -> str:
    def _acct(m: re.Match) -> str:
        # 直前が `vol-` `snap-` 等ならリソースIDなのでそのまま残す
        head = text[: m.start()]
        if _NOT_ACCOUNT_PREFIX.search(head):
            return m.group(0)
        value = m.group(0)
        if value in account_ids:
            return SELF_ACCOUNT_TOKEN
        return account_token(value)

    def _ip(m: re.Match) -> str:
        ip = m.group(0)
        if _PRIVATE_NET_RE.match(ip):
            return ip
        octets = ip.split(".")
        if len(octets) == 4 and all(o.isdigit() and int(o) < 256 for o in octets):
            return f"{octets[0]}.{octets[1]}.x.x"
        return ip

    def _ip6(m: re.Match) -> str:
        value = m.group(0)
        head = value.split("/")[0]
        low = head.lower()
        # ユニークローカル (fd00::/8) とリンクローカル (fe80::/10) は内部アドレスなので残す
        if low.startswith(("fc", "fd", "fe8", "fe9", "fea", "feb", "::")):
            return value
        parts = head.split(":")
        return ":".join(parts[:2]) + ":x:x" + (("/" + value.split("/")[1]) if "/" in value else "")

    text = _EIP_DNS_RE.sub(lambda m: f"ec2-{m.group(1)}-{m.group(2)}-x-x", text)
    text = _ACCOUNT_RE.sub(_acct, text)
    text = _ENI_RE.sub("＜ENI-ID＞", text)
    text = _IPV4_RE.sub(_ip, text)
    text = _IPV6_RE.sub(_ip6, text)
    return text


# --------------------------------------------------------------------------
# 機微な設定値そのもののマスク（アカウントIDとは別系統）
# --------------------------------------------------------------------------

#: 値の中身が秘密になりうるキー。キー名だけ残して値を落とす。
SECRET_VALUE_KEYS = (
    "HeaderValue",        # CloudFront のオリジンカスタムヘッダ（共有シークレット）
    "Endpoint",           # SNS サブスクリプション（メールアドレス・電話番号）
    "SecretString",
    "Password",
    "PrivateKey",
    "AuthorizationToken",
)


def mask_secret_values(obj, keys: tuple[str, ...] = SECRET_VALUE_KEYS):
    """指定キーの値を `＜マスク済み＞` に置き換えた複製を返す。"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in keys and isinstance(v, str) and v:
                out[k] = "＜マスク済み＞"
            else:
                out[k] = mask_secret_values(v, keys)
        return out
    if isinstance(obj, list):
        return [mask_secret_values(v, keys) for v in obj]
    return obj
