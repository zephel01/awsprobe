"""AWS セッションの組み立てと、コレクタに渡す実行コンテキスト。"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

from .guard import ReadOnlyGuard, ReadOnlyViolation, _DryRunSkip

LOG = logging.getLogger("awsprobe")

DEFAULT_REGION = "ap-northeast-1"

#: バケット単位の追加取得を行う S3 バケット数の既定上限。
#: バケット 1 本につき GetBucketLocation + 詳細 10 本 = 11 コール発行される。
DEFAULT_MAX_BUCKETS = 200

#: リトライ回数。スロットリングを「リソースが無い」に化けさせないため、
#: まずリトライで吸収しきることを優先して 10 回に上げている。
RETRY_MAX_ATTEMPTS = 10


class CredentialsUnavailable(RuntimeError):
    """AWS の認証情報が用意できていない（プロファイル不在・期限切れ等）。"""

# 権限不足・未導入サービスなど「調査対象がそもそも無い/見えない」ことを示すエラー。
# 収集は止めず、errors に記録して続行する。
SOFT_ERROR_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "AuthorizationError", "AuthFailure", "Forbidden",
    "InvalidClientTokenId", "SubscriptionRequiredException",
    "OptInRequired", "UnrecognizedClientException",
    "NoSuchEntity", "NoSuchBucket", "NoSuchBucketPolicy", "NoSuchLifecycleConfiguration",
    "NoSuchWebsiteConfiguration", "NoSuchCORSConfiguration", "NoSuchTagSet",
    "NoSuchPublicAccessBlockConfiguration", "ServerSideEncryptionConfigurationNotFoundError",
    "ResourceNotFoundException", "ResourceNotFound", "NotFoundException", "NotFound",
    "InvalidRequestException", "BadRequestException",
    "AWSOrganizationsNotInUseException",
    "ValidationException",
    "InvalidAction", "InvalidParameterValue",
    "DBInstanceNotFound", "FileSystemNotFound",
    "WAFNonexistentItemException",
    "AccessDeniedFault",
}

# 「リソースが無い」ではなく「取れなかった」ことを示すエラー。
# スロットリング・資格情報の期限切れ・AWS 側の一時障害がここに入る。
# これらが起きたセクションは *収集が欠損している* ので、判定側は
# 「該当なし（＝問題なし）」ではなく「判定不能」にしなければならない。
HARD_ERROR_CODES = {
    # スロットリング（S3 500 バケットで 5,500 コール規模になるため現実に起きる）
    "Throttling", "ThrottlingException", "TooManyRequestsException",
    "RequestLimitExceeded", "SlowDown", "RequestThrottled",
    "RequestThrottledException",
    # 資格情報の期限切れ（長時間の収集で起きる）
    "ExpiredToken", "ExpiredTokenException", "RequestExpired",
    # AWS 側の一時障害
    "InternalError", "ServiceUnavailable", "InternalFailure", "RequestTimeout",
    # awsprobe 自身が収集を打ち切ったことを示す内部コード（--max-buckets）
    "CollectionTruncated",
}


@dataclass
class CollectError:
    service: str
    operation: str
    code: str
    message: str
    context: str = ""
    #: True なら「取れなかった」＝収集が不完全。判定側は該当なしにしてはならない。
    #: 明示指定が無くても code が HARD_ERROR_CODES にあれば自動で True になる。
    fatal: bool = False

    def __post_init__(self) -> None:
        # `_safe.py` など positional でしか渡さない経路でも必ず分類されるよう、
        # code からの自動判定をここに集約する。
        if not self.fatal and self.code in HARD_ERROR_CODES:
            self.fatal = True

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "operation": self.operation,
            "code": self.code,
            "message": self.message,
            "context": self.context,
            "fatal": self.fatal,
        }


@dataclass
class Context:
    """コレクタに渡す実行コンテキスト。

    コレクタは boto3 を直接触らず、必ず `ctx.client()` / `ctx.call()` /
    `ctx.paginate()` を経由すること。エラー処理とガードがここに集約されている。
    """

    session: boto3.Session
    region: str
    account_id: str
    account_alias: str = ""
    caller_arn: str = ""
    guard: ReadOnlyGuard | None = None
    dry_run: bool = False
    #: バケット単位の追加取得を行う S3 バケットの上限（0 以下で無制限）。
    #: バケット 1 本につき 11 コール発行されるため、500 バケットで 5,500 コールになる。
    max_buckets: int = DEFAULT_MAX_BUCKETS
    errors: list[CollectError] = field(default_factory=list)
    _clients: dict[str, Any] = field(default_factory=dict, repr=False)
    #: 追加取得を行うと決めたバケット名（登場順）。上限判定に使う。
    _buckets_seen: list[str] = field(default_factory=list, repr=False)
    #: 上限超過を記録した CollectError（件数を随時書き換える）
    _bucket_limit_error: CollectError | None = field(default=None, repr=False)

    # -- 収集の完全性 ----------------------------------------------------
    def fatal_errors(self) -> list[CollectError]:
        """「取れなかった」エラー（スロットリング・期限切れ・打ち切り）の一覧。"""
        return [e for e in self.errors if e.fatal]

    # -- S3 バケット上限 --------------------------------------------------
    def _bucket_allowed(self, service: str, kwargs: dict) -> bool:
        """S3 のバケット単位呼び出しが `max_buckets` の範囲内か判定する。

        範囲外なら False を返し、打ち切りを `errors` に fatal として記録する。
        記録しておかないと「詳細が取れていないバケット」が判定側で
        「設定されていないバケット」に化けてしまう。
        """
        if service != "s3" or self.max_buckets <= 0:
            return True
        name = kwargs.get("Bucket")
        if not name:
            return True                      # list_buckets 等は対象外
        if name in self._buckets_seen:
            return True
        if len(self._buckets_seen) < self.max_buckets:
            self._buckets_seen.append(name)
            return True
        if self._bucket_limit_error is None:
            self._bucket_limit_error = CollectError(
                "s3", "get_bucket_*", "CollectionTruncated",
                "", "バケット詳細の取得上限", fatal=True,
            )
            self.errors.append(self._bucket_limit_error)
        self._bucket_limit_error.message = (
            f"--max-buckets={self.max_buckets} に達したため、"
            f"{self.max_buckets} 本を超えるバケットの詳細取得を打ち切った。"
            f"S3 の判定は不完全である。"
        )
        return False

    # -- クライアント ----------------------------------------------------
    def client(self, service: str, region: str | None = None):
        """サービスクライアントを取得する（キャッシュあり）。

        CloudFront / Route 53 / WAFv2(CLOUDFRONT) / Global Accelerator など
        グローバルサービスは region を明示的に渡すこと（通常 us-east-1）。
        """
        key = f"{service}@{region or self.region}"
        if key not in self._clients:
            self._clients[key] = self.session.client(
                service,
                region_name=region or self.region,
                config=Config(
                    retries={"max_attempts": RETRY_MAX_ATTEMPTS, "mode": "adaptive"},
                    user_agent_extra="awsprobe/1.0 (read-only survey)",
                ),
            )
        return self._clients[key]

    # -- 単発呼び出し ----------------------------------------------------
    def call(self, service: str, operation: str, *, region: str | None = None,
             context: str = "", **kwargs) -> dict | None:
        """API を1回呼ぶ。権限不足・未設定は None を返し errors に記録する。

        operation は boto3 のメソッド名（snake_case）で渡す。例: "describe_vpcs"
        """
        if not self._bucket_allowed(service, kwargs):
            return None
        client = self.client(service, region)
        try:
            return getattr(client, operation)(**kwargs)
        except _DryRunSkip:
            return None
        except ReadOnlyViolation:
            raise
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            msg = exc.response.get("Error", {}).get("Message", str(exc))
            self.errors.append(CollectError(service, operation, code, msg, context))
            self._log_client_error(service, operation, code, msg)
            return None
        except BotoCoreError as exc:
            self.errors.append(CollectError(service, operation, "BotoCoreError", str(exc), context))
            LOG.warning("%s:%s が失敗しました: %s", service, operation, exc)
            return None
        except Exception as exc:  # noqa: BLE001
            # botocore が知らないオペレーション（AttributeError）や、
            # moto の NotImplementedError で収集全体を落とさない。
            self.errors.append(
                CollectError(service, operation, type(exc).__name__, str(exc), context)
            )
            LOG.warning("%s:%s が失敗しました (%s): %s", service, operation, type(exc).__name__, exc)
            return None

    # -- ページネーション ------------------------------------------------
    def paginate(self, service: str, operation: str, result_key: str, *,
                 region: str | None = None, context: str = "", **kwargs) -> list:
        """ページネーション対応の一覧取得。失敗時は空リストを返す。

        result_key: レスポンス内の配列キー。例: "Vpcs"
        """
        if not self._bucket_allowed(service, kwargs):
            return []
        client = self.client(service, region)
        out: list = []
        try:
            if client.can_paginate(operation):
                paginator = client.get_paginator(operation)
                for page in paginator.paginate(**kwargs):
                    out.extend(page.get(result_key) or [])
                return out
            resp = getattr(client, operation)(**kwargs)
            return list(resp.get(result_key) or [])
        except _DryRunSkip:
            return []
        except ReadOnlyViolation:
            raise
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            msg = exc.response.get("Error", {}).get("Message", str(exc))
            self.errors.append(CollectError(service, operation, code, msg, context))
            self._log_client_error(service, operation, code, msg)
            return []
        except BotoCoreError as exc:
            self.errors.append(CollectError(service, operation, "BotoCoreError", str(exc), context))
            LOG.warning("%s:%s が失敗しました: %s", service, operation, exc)
            return []
        except Exception as exc:  # noqa: BLE001
            self.errors.append(
                CollectError(service, operation, type(exc).__name__, str(exc), context)
            )
            LOG.warning("%s:%s が失敗しました (%s): %s", service, operation, type(exc).__name__, exc)
            return []

    def _log_client_error(self, service: str, operation: str, code: str, msg: str) -> None:
        """ClientError のログ出力。収集欠損（fatal）は特に強く警告する。"""
        if code in HARD_ERROR_CODES:
            LOG.error(
                "%s:%s が失敗しました (%s): %s"
                " ← 収集が欠損します。この結果で判定してはいけません。",
                service, operation, code, msg,
            )
        elif code not in SOFT_ERROR_CODES:
            LOG.warning("%s:%s が失敗しました (%s): %s", service, operation, code, msg)

    def error_dicts(self) -> list[dict]:
        return [e.to_dict() for e in self.errors]


def build_context(
    profile: str | None = None,
    region: str = DEFAULT_REGION,
    assume_role_arn: str | None = None,
    external_id: str | None = None,
    account_alias: str = "",
    allow_ssm_command: bool = False,
    dry_run: bool = False,
    max_buckets: int = DEFAULT_MAX_BUCKETS,
) -> Context:
    """プロファイル／AssumeRole からガード付きの Context を組み立てる。

    8環境へ広げるときは assume_role_arn を差し替えるだけでよい。

    `dry_run=True` のときは **AWS へ一切送信しない**。AssumeRole も行わない
    （sts:AssumeRole はガードより手前で走るため、ここで止めないと
    「送信しない」という約束が破られる）。
    """
    # 環境変数が空文字で入っていると botocore が ProfileNotFound を投げる。
    # 利用者にとっては「プロファイル未指定」と同じ意味なので None に正規化する。
    profile = (profile or "").strip() or None
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if os.environ.get(key, None) == "":
            os.environ.pop(key, None)

    try:
        base = boto3.Session(profile_name=profile) if profile else boto3.Session()
    except ProfileNotFound as exc:
        raise CredentialsUnavailable(
            f"AWS プロファイル '{profile or os.environ.get('AWS_PROFILE', '')}' が見つかりません。"
            f"`aws configure list-profiles` で名前を確認してください。（{exc}）"
        ) from exc

    if assume_role_arn and dry_run:
        # --dry-run は「1バイトも送信しない」ことが唯一の価値なので、
        # ガードの手前で走る AssumeRole もここで明示的に握り潰す。
        LOG.info(
            "--dry-run のため AssumeRole を実行しませんでした（%s）。"
            "呼ぶ予定の API を並べるだけのダミー Context を返します。",
            assume_role_arn,
        )
        session = base
    elif assume_role_arn:
        # AssumeRole 自体はガードを付ける前の素のセッションで行う
        # （sts:AssumeRole は "Assume" 接頭辞でガードに弾かれるため）。
        #
        # 静的な鍵をコピーすると 1 時間で期限切れになり、7,000 コール規模の
        # 収集が途中から ExpiredToken だらけになる。botocore の
        # DeferredRefreshableCredentials に載せて自動更新させる。
        session = _assume_role_session(base, assume_role_arn, external_id, region)
    else:
        session = base

    guard = ReadOnlyGuard(allow_ssm_command=allow_ssm_command, dry_run=dry_run)
    guard.attach(session)

    account_id, caller_arn = "", ""
    try:
        ident = session.client("sts", region_name=region).get_caller_identity()
        account_id = ident.get("Account", "")
        caller_arn = ident.get("Arn", "")
    except _DryRunSkip:
        pass
    except CredentialsUnavailable:
        # AssumeRole の失敗は遅延解決されるため、ここで初めて表に出てくる。
        # 「呼び出し元が分からない」で丸めず、理由をそのまま利用者に見せる。
        raise
    except Exception as exc:  # noqa: BLE001
        LOG.warning("呼び出し元の特定に失敗しました: %s", exc)

    return Context(
        session=session,
        region=region,
        account_id=account_id,
        # 括弧が無いと `(account_alias or account_id[-4:]) if account_id else ""` と
        # 解釈され、account_id が空のとき利用者指定の別名が捨てられていた（L-3）。
        account_alias=account_alias or (account_id[-4:] if account_id else ""),
        caller_arn=caller_arn,
        guard=guard,
        dry_run=dry_run,
        max_buckets=max_buckets,
    )


def _assume_role_session(
    base: boto3.Session,
    assume_role_arn: str,
    external_id: str | None,
    region: str,
) -> boto3.Session:
    """AssumeRole の結果を「自動更新される資格情報」として boto3.Session に載せる。

    `DurationSeconds` の期限が来ると botocore が勝手に再 AssumeRole するため、
    収集が 1 時間を超えても ExpiredToken にならない。
    """
    from botocore.credentials import DeferredRefreshableCredentials
    from botocore.session import Session as BotocoreSession

    sts = base.client("sts", region_name=region)
    params: dict[str, Any] = {
        "RoleArn": assume_role_arn,
        "RoleSessionName": "awsprobe-readonly",
        "DurationSeconds": 3600,
    }
    if external_id:
        params["ExternalId"] = external_id

    def _refresh() -> dict:
        """期限が近づくたびに botocore から呼ばれる。"""
        try:
            creds = sts.assume_role(**params)["Credentials"]
        except (ClientError, BotoCoreError) as exc:
            raise CredentialsUnavailable(
                f"AssumeRole に失敗しました: {assume_role_arn}\n  {exc}"
            ) from exc
        expiry = creds["Expiration"]
        return {
            "access_key": creds["AccessKeyId"],
            "secret_key": creds["SecretAccessKey"],
            "token": creds["SessionToken"],
            "expiry_time": expiry.isoformat() if hasattr(expiry, "isoformat") else str(expiry),
        }

    # 引き受け先の資格情報だけを持つ新しい botocore セッションを作る
    # （base のプロファイル資格情報を上書きしてしまわないため）。
    botocore_session = BotocoreSession()
    botocore_session._credentials = DeferredRefreshableCredentials(  # noqa: SLF001
        refresh_using=_refresh, method="sts-assume-role",
    )
    botocore_session.set_config_variable("region", region)
    return boto3.Session(botocore_session=botocore_session, region_name=region)
