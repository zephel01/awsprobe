"""ストレージ（S3 / EFS / FSx / AWS Backup）コレクタ。

`docs/INVENTORY_SCHEMA.md` の `storage` セクションを埋める。

収集の狙い（未確認事項の解消）:
- バケットが公開されていないか／暗号化・バージョニング・ライフサイクルが
  設定されているかを確定させる
  → `buckets` の `PublicAccessBlock` / `PolicyStatus` / `Encryption` /
    `Versioning` / `Lifecycle` / `Policy`
- **EFS が何本あり、どの AZ にマウントされているか**を確定させる
  → `efs_mount_targets`（FS ごとの `describe_mount_targets` を平坦化）が最重要
- EFS のスループットモードとバックアップ有無
  → `efs_file_systems` の `ThroughputMode`、`efs_backup_policies`
- バックアップが AWS Backup で取られているか、対象は何か
  → `backup_plans` / `backup_selections` / `backup_protected_resources`

未設定と取得失敗の区別:
バケットごとの追加取得は「未設定」でも「権限不足」でも値は `None` になるが、
`ctx.errors` に `NoSuchBucketPolicy` 等（未設定）と `AccessDenied`（取得失敗）が
コードで区別できる形で残る。キー自体は常に存在させる（判定ロジックが
`no_data` と「設定なし」を取り違えないようにするため）。
"""
from __future__ import annotations

import json
from typing import Any, Callable

from ..session import Context
from ._safe import safe_call, safe_paginate
from .base import Collector, jsonable, register

#: バケット 1 本あたりに発行する追加 API の上限（LocationConstraint を除く）。
#: バケット数 × この数だけ呼び出しが増えるため、実装契約として 10 に固定する。
_MAX_BUCKET_DETAIL_CALLS = 10

#: GetBucketLocation が返す LocationConstraint の特殊値 → 実リージョン
_LOCATION_ALIASES = {
    None: "us-east-1",
    "": "us-east-1",
    "EU": "eu-west-1",
}


def _strip_meta(resp: dict | None) -> dict:
    """レスポンスから ResponseMetadata を落とす。"""
    if not resp:
        return {}
    return {k: v for k, v in resp.items() if k != "ResponseMetadata"}


def _parse_policy(raw: Any) -> Any:
    """JSON 文字列のポリシーを dict に直す（壊れていれば文字列のまま返す）。"""
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def _pick(resp: dict | None, key: str) -> Any:
    """レスポンスから 1 キーを取り出す（無ければ None）。"""
    return (resp or {}).get(key)


def _versioning(resp: dict | None) -> Any:
    """バージョニング設定。一度も設定していないバケットは空応答なので None。"""
    body = _strip_meta(resp)
    if not body.get("Status") and not body.get("MFADelete"):
        return None
    return body


def _acl(resp: dict | None) -> Any:
    """ACL は Owner と Grants のみ（他アカウントへの付与を見るため）。"""
    body = _strip_meta(resp)
    if not body:
        return None
    return {"Owner": body.get("Owner"), "Grants": body.get("Grants") or []}


def _website(resp: dict | None) -> Any:
    body = _strip_meta(resp)
    return body or None


#: (出力キー, boto3 オペレーション, レスポンス変換) の表。
#: ここに載っている数がそのまま「バケットごとの追加 API 数」になる。
_BUCKET_DETAILS: tuple[tuple[str, str, Callable[[dict | None], Any]], ...] = (
    ("Policy", "get_bucket_policy", lambda r: _parse_policy(_pick(r, "Policy"))),
    ("PublicAccessBlock", "get_public_access_block",
     lambda r: _pick(r, "PublicAccessBlockConfiguration")),
    ("PolicyStatus", "get_bucket_policy_status", lambda r: _pick(r, "PolicyStatus")),
    ("Encryption", "get_bucket_encryption",
     lambda r: _pick(r, "ServerSideEncryptionConfiguration")),
    ("Versioning", "get_bucket_versioning", _versioning),
    ("Lifecycle", "get_bucket_lifecycle_configuration", lambda r: _pick(r, "Rules")),
    ("Website", "get_bucket_website", _website),
    # LoggingEnabled が無い＝アクセスログ未設定（None で表現する）
    ("Logging", "get_bucket_logging", lambda r: _pick(r, "LoggingEnabled")),
    ("Acl", "get_bucket_acl", _acl),
    ("Tagging", "get_bucket_tagging", lambda r: _pick(r, "TagSet")),
)

assert len(_BUCKET_DETAILS) <= _MAX_BUCKET_DETAIL_CALLS, "バケットごとの追加取得が多すぎる"


@register
class StorageCollector(Collector):
    """S3 バケット・EFS・FSx・AWS Backup の構成を収集する。"""

    name = "storage"

    iam_actions = (
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketWebsite",
        "s3:GetBucketLogging",
        "s3:GetBucketAcl",
        "s3:GetBucketTagging",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeFileSystemPolicy",
        "elasticfilesystem:DescribeBackupPolicy",
        "fsx:DescribeFileSystems",
        "backup:ListBackupPlans",
        "backup:GetBackupPlan",
        "backup:ListBackupSelections",
        "backup:GetBackupSelection",
        "backup:ListBackupVaults",
        "backup:ListProtectedResources",
    )

    def collect(self, ctx: Context) -> dict:
        data: dict = {}

        # -- S3 -------------------------------------------------------------
        data["buckets"] = self._collect_buckets(ctx)

        # -- EFS ------------------------------------------------------------
        file_systems = safe_paginate(
            ctx, "efs", "describe_file_systems", "FileSystems",
            context="EFS ファイルシステム一覧",
        )
        # ThroughputMode / PerformanceMode / ProvisionedThroughputInMibps /
        # Encrypted / SizeInBytes / Name / NumberOfMountTargets を素のまま残す。
        data["efs_file_systems"] = file_systems

        fs_ids = [fs.get("FileSystemId") for fs in file_systems if fs.get("FileSystemId")]

        # マウントターゲット: EFS が「どの AZ / どのサブネットに口を出しているか」の確定に直結。
        data["efs_mount_targets"] = self._collect_mount_targets(ctx, fs_ids)

        # アクセスポイント: RootDirectory.Path でコンテナ側のマウント範囲が分かる。
        data["efs_access_points"] = safe_paginate(
            ctx, "efs", "describe_access_points", "AccessPoints",
            context="EFS アクセスポイント一覧",
        )

        data["efs_policies"] = self._collect_fs_policies(ctx, fs_ids)
        data["efs_backup_policies"] = self._collect_fs_backup_policies(ctx, fs_ids)

        # -- FSx ------------------------------------------------------------
        data["fsx_file_systems"] = safe_paginate(
            ctx, "fsx", "describe_file_systems", "FileSystems",
            context="FSx ファイルシステム一覧",
        )

        # -- AWS Backup -----------------------------------------------------
        plans = self._collect_backup_plans(ctx)
        data["backup_plans"] = plans
        data["backup_selections"] = self._collect_backup_selections(ctx, plans)
        data["backup_vaults"] = safe_paginate(
            ctx, "backup", "list_backup_vaults", "BackupVaultList",
            context="バックアップボールト一覧",
        )
        # 「実際に何が守られているか」。プラン定義と突き合わせて漏れを見る。
        data["backup_protected_resources"] = safe_paginate(
            ctx, "backup", "list_protected_resources", "Results",
            context="保護対象リソース一覧",
        )

        return jsonable(data)

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------
    def _collect_buckets(self, ctx: Context) -> list[dict]:
        """ListBuckets の各要素にバケット単位の設定を足す。

        リージョンが異なるバケットを ctx.region のクライアントで引くと
        `PermanentRedirect` になるため、必ず GetBucketLocation の結果の
        リージョンでクライアントを取り直してから以降を引く。
        """
        resp = safe_call(ctx, "s3", "list_buckets", context="バケット一覧")
        buckets = list((resp or {}).get("Buckets") or [])

        out: list[dict] = []
        for bucket in buckets:
            name = bucket.get("Name")
            if not name:
                continue
            item = dict(bucket)
            region = self._bucket_region(ctx, name)
            item["Region"] = region

            for key, operation, extract in _BUCKET_DETAILS:
                detail = safe_call(
                    ctx, "s3", operation,
                    region=region,
                    context=f"バケット {name}",
                    Bucket=name,
                )
                # 未設定でも取得失敗でも None。理由は ctx.errors の code で区別する。
                item[key] = extract(detail) if detail is not None else None

            # スキーマ上のキーだが、バケットごとの追加取得を 10 本に抑えるため
            # GetBucketReplication は発行しない（常に None）。
            # レプリケーションの有無は Policy / Tagging からは分からないので、
            # 必要になった時点で _BUCKET_DETAILS に追加する。
            item["ReplicationStatus"] = None

            out.append(item)
        return out

    def _bucket_region(self, ctx: Context, name: str) -> str:
        """GetBucketLocation からバケットの実リージョンを決める。"""
        resp = safe_call(
            ctx, "s3", "get_bucket_location",
            context=f"バケット {name} のリージョン", Bucket=name,
        )
        if resp is None:
            # 引けなければ既定リージョンで続行する（少なくとも同一リージョン分は取れる）
            return ctx.region
        constraint = resp.get("LocationConstraint")
        return _LOCATION_ALIASES.get(constraint, constraint) or ctx.region

    # ------------------------------------------------------------------
    # EFS
    # ------------------------------------------------------------------
    def _collect_mount_targets(self, ctx: Context, fs_ids: list[str]) -> list[dict]:
        """FS ごとの describe_mount_targets を 1 本の配列に平坦化する。

        `FileSystemId` / `SubnetId` / `AvailabilityZoneName` / `IpAddress` /
        `NetworkInterfaceId` をそのまま残す（レスポンスに含まれる）。
        """
        out: list[dict] = []
        for fs_id in fs_ids:
            out.extend(
                safe_paginate(
                    ctx, "efs", "describe_mount_targets", "MountTargets",
                    context=f"EFS {fs_id} のマウントターゲット",
                    FileSystemId=fs_id,
                )
            )
        return out

    def _collect_fs_policies(self, ctx: Context, fs_ids: list[str]) -> dict:
        """FS ごとのファイルシステムポリシー。未設定は None。"""
        policies: dict[str, Any] = {}
        for fs_id in fs_ids:
            resp = safe_call(
                ctx, "efs", "describe_file_system_policy",
                context=f"EFS {fs_id} のポリシー", FileSystemId=fs_id,
            )
            policies[fs_id] = _parse_policy(_pick(resp, "Policy")) if resp else None
        return policies

    def _collect_fs_backup_policies(self, ctx: Context, fs_ids: list[str]) -> dict:
        """FS ごとの自動バックアップ設定（ENABLED / DISABLED）。"""
        policies: dict[str, Any] = {}
        for fs_id in fs_ids:
            resp = safe_call(
                ctx, "efs", "describe_backup_policy",
                context=f"EFS {fs_id} のバックアップポリシー", FileSystemId=fs_id,
            )
            policies[fs_id] = _pick(resp, "BackupPolicy") if resp else None
        return policies

    # ------------------------------------------------------------------
    # AWS Backup
    # ------------------------------------------------------------------
    def _collect_backup_plans(self, ctx: Context) -> list[dict]:
        """バックアッププラン一覧に GetBackupPlan の定義（Rules）を足す。"""
        summaries = safe_paginate(
            ctx, "backup", "list_backup_plans", "BackupPlansList",
            context="バックアッププラン一覧",
        )
        out: list[dict] = []
        for summary in summaries:
            item = dict(summary)
            plan_id = summary.get("BackupPlanId")
            if plan_id:
                resp = safe_call(
                    ctx, "backup", "get_backup_plan",
                    context=f"バックアッププラン {plan_id}", BackupPlanId=plan_id,
                )
                # Rules に「どの頻度で・どのボールトに・何日保持するか」が入る。
                item["BackupPlan"] = _pick(resp, "BackupPlan") if resp else None
            out.append(item)
        return out

    def _collect_backup_selections(self, ctx: Context, plans: list[dict]) -> list[dict]:
        """プランごとの選択（何をバックアップ対象にしているか）を平坦化する。"""
        out: list[dict] = []
        for plan in plans:
            plan_id = plan.get("BackupPlanId")
            if not plan_id:
                continue
            for summary in safe_paginate(
                ctx, "backup", "list_backup_selections", "BackupSelectionsList",
                context=f"バックアッププラン {plan_id} の選択", BackupPlanId=plan_id,
            ):
                item = dict(summary)
                selection_id = summary.get("SelectionId")
                if selection_id:
                    resp = safe_call(
                        ctx, "backup", "get_backup_selection",
                        context=f"バックアップ選択 {selection_id}",
                        BackupPlanId=plan_id, SelectionId=selection_id,
                    )
                    # Resources / ListOfTags に対象の指定方法が入る。
                    item["BackupSelection"] = _pick(resp, "BackupSelection") if resp else None
                out.append(item)
        return out
