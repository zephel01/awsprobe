"""データベース（RDS）コレクタ。

`docs/INVENTORY_SCHEMA.md` の `database` セクションを埋める。

収集の狙い（未確認事項の解消）:
- 可用性・バックアップ・暗号化の実態を確定させる
  → `db_instances` の MultiAZ / BackupRetentionPeriod / StorageEncrypted など
- 監査ログ（general_log / slow_query_log / pgaudit 等）が有効かどうか
  → `db_parameters`（使用中パラメータグループの **非デフォルト値のみ**）
- 使用中エンジンバージョンの EOL が近いかどうか
  → `db_engine_versions`（**使用中の (Engine, EngineVersion) のみ**に絞って取得）

`describe_db_engine_versions` を無条件に引くと全エンジン全バージョンが返り
出力が巨大になるため、必ず使用中の組み合わせだけに絞ること。
"""
from __future__ import annotations

from ..session import Context
from ._safe import safe_paginate
from .base import Collector, jsonable, register

#: エンジンバージョン情報のうち、EOL 判断に無関係で件数が極端に多いキー。
#: （Oracle / SQL Server では数千件になるため落とす。落とした事実は "_pruned" に残す）
_BULKY_ENGINE_VERSION_KEYS = (
    "SupportedCharacterSets",
    "SupportedNcharCharacterSets",
    "SupportedTimezones",
)


@register
class DatabaseCollector(Collector):
    """RDS インスタンス・パラメータ・スナップショット・エンジンバージョンを収集する。"""

    name = "database"

    iam_actions = (
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBParameterGroups",
        "rds:DescribeDBParameters",
        "rds:DescribeDBClusterParameters",
        "rds:DescribeDBSubnetGroups",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBEngineVersions",
        "rds:DescribeEventSubscriptions",
    )

    def collect(self, ctx: Context) -> dict:
        data: dict = {}

        # -- DB インスタンス -------------------------------------------------
        # Engine / EngineVersion / MultiAZ / BackupRetentionPeriod /
        # PreferredBackupWindow / AutoMinorVersionUpgrade / StorageEncrypted /
        # KmsKeyId / VpcSecurityGroups / DBSubnetGroup / DBParameterGroups /
        # DBInstanceClass / AvailabilityZone / SecondaryAvailabilityZone /
        # PubliclyAccessible / DeletionProtection / EnabledCloudwatchLogsExports
        # をすべて素のまま残す。
        db_instances = safe_paginate(ctx, "rds", "describe_db_instances", "DBInstances")
        data["db_instances"] = db_instances

        # -- Aurora クラスタ（対象アカウントでは空のはず） --------------------------
        db_clusters = safe_paginate(ctx, "rds", "describe_db_clusters", "DBClusters")
        data["db_clusters"] = db_clusters

        # -- パラメータグループ一覧 -------------------------------------------
        data["db_parameter_groups"] = safe_paginate(
            ctx, "rds", "describe_db_parameter_groups", "DBParameterGroups"
        )

        # -- 使用中パラメータグループの非デフォルト値 --------------------------
        data["db_parameters"] = self._collect_parameters(ctx, db_instances, db_clusters)

        # -- サブネットグループ ------------------------------------------------
        data["db_subnet_groups"] = safe_paginate(
            ctx, "rds", "describe_db_subnet_groups", "DBSubnetGroups"
        )

        # -- スナップショット（手動・自動の両方） --------------------------------
        snapshots: list[dict] = []
        for snapshot_type in ("manual", "automated"):
            snapshots.extend(
                safe_paginate(
                    ctx,
                    "rds",
                    "describe_db_snapshots",
                    "DBSnapshots",
                    SnapshotType=snapshot_type,
                    context=f"SnapshotType={snapshot_type}",
                )
            )
        data["db_snapshots"] = snapshots

        # -- 使用中エンジンバージョンのみ ---------------------------------------
        data["db_engine_versions"] = self._collect_engine_versions(
            ctx, db_instances, db_clusters
        )

        # -- イベントサブスクリプション ------------------------------------------
        data["event_subscriptions"] = safe_paginate(
            ctx, "rds", "describe_event_subscriptions", "EventSubscriptionsList"
        )

        return jsonable(data)

    # ------------------------------------------------------------------
    # 個別収集
    # ------------------------------------------------------------------
    def _collect_parameters(
        self, ctx: Context, db_instances: list[dict], db_clusters: list[dict]
    ) -> dict:
        """使用中パラメータグループの **非デフォルト値のみ** を集める。

        `Source='user'` を指定することで、明示的に変更されたパラメータだけが返る。
        全パラメータ（既定値込み）は 1 グループあたり数百件になるため引かない。
        監査ログ（general_log / slow_query_log / pgaudit.* 等）が有効かどうかを
        ここで確定させる。

        戻り値は `{パラメータグループ名: [パラメータ...]}`。
        Aurora のクラスタパラメータグループも同じ辞書に、同じ形で入れる。
        """
        params: dict[str, list] = {}

        # インスタンスに紐づく DB パラメータグループ
        instance_groups = {
            group.get("DBParameterGroupName")
            for db in db_instances
            for group in db.get("DBParameterGroups") or []
            if group.get("DBParameterGroupName")
        }
        for name in sorted(instance_groups):
            params[name] = safe_paginate(
                ctx,
                "rds",
                "describe_db_parameters",
                "Parameters",
                DBParameterGroupName=name,
                Source="user",
                context=f"パラメータグループ {name} の非デフォルト値",
            )

        # クラスタに紐づくクラスタパラメータグループ（Aurora がある場合のみ）
        cluster_groups = {
            db.get("DBClusterParameterGroup")
            for db in db_clusters
            if db.get("DBClusterParameterGroup")
        }
        for name in sorted(cluster_groups - instance_groups):
            params[name] = safe_paginate(
                ctx,
                "rds",
                "describe_db_cluster_parameters",
                "Parameters",
                DBClusterParameterGroupName=name,
                Source="user",
                context=f"クラスタパラメータグループ {name} の非デフォルト値",
            )

        return params

    def _collect_engine_versions(
        self, ctx: Context, db_instances: list[dict], db_clusters: list[dict]
    ) -> list[dict]:
        """使用中の (Engine, EngineVersion) の組み合わせだけを引く。

        `Status`（available / deprecated）と `SupportedEngineLifecycleSupport`、
        `ValidUpgradeTarget` から EOL と移行先を判断できるようにする。
        絞り込みを外すと全バージョンが返って出力が巨大になるため、必ず個別指定する。
        """
        pairs = {
            (db.get("Engine"), db.get("EngineVersion"))
            for db in list(db_instances) + list(db_clusters)
            if db.get("Engine") and db.get("EngineVersion")
        }

        versions: list[dict] = []
        for engine, version in sorted(pairs):
            found = safe_paginate(
                ctx,
                "rds",
                "describe_db_engine_versions",
                "DBEngineVersions",
                Engine=engine,
                EngineVersion=version,
                context=f"{engine} {version}",
            )
            for item in found:
                versions.append(_prune_engine_version(item))
        return versions


def _prune_engine_version(item: dict) -> dict:
    """エンジンバージョン情報から件数の多い付随情報を落とす。

    EOL 判断に必要な Status / SupportedEngineLifecycleSupport /
    ValidUpgradeTarget 等は残す。落としたキーは "_pruned" に記録するので、
    「取っていない」のか「元から無い」のかを後段で区別できる。
    """
    pruned = [k for k in _BULKY_ENGINE_VERSION_KEYS if k in item]
    if not pruned:
        return item
    trimmed = {k: v for k, v in item.items() if k not in _BULKY_ENGINE_VERSION_KEYS}
    trimmed["_pruned"] = pruned
    return trimmed
