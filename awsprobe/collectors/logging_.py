"""監査・ログ（CloudTrail / Config / VPC Flow Logs / CloudWatch）コレクタ。

`docs/INVENTORY_SCHEMA.md` の `logging` セクションを埋める。
モジュール名が `logging_` なのは標準ライブラリの `logging` と衝突させないため
（コレクタ名は `"logging"`）。

収集の狙い（未確認事項の解消）:
- **証跡が本当に記録されているか**（作っただけで止まっている証跡が多い）
  → `cloudtrail_trails` の `IsLogging` と `Status.LatestDeliveryTime`
- **AWS Config が本当に有効か**
  → `config_recorders` の `Status.recording` / `lastStatus`
- **VPC フローログが本当に有効か**
  → `flow_logs` の `FlowLogStatus` / `ResourceId` / `LogDestination`
- ログが無期限に溜まっていないか
  → `cloudwatch_log_groups` の `RetentionInDays`（キーが無い＝無期限）
- 障害に気付ける状態か
  → `cloudwatch_alarms` の `AlarmActions` / `StateValue`
- **証跡が改ざん検知・暗号化・全リージョン化されているか**（CIS 3.1 / 3.2 / 3.5）
  → `cloudtrail_trails` の `LogFileValidationEnabled` / `KmsKeyId` /
    `IsMultiRegionTrail` / `IsOrganizationTrail`。いずれも `describe_trails` の
    レスポンスに含まれるため追加 API は不要だが、判定側が「キーが無い」と
    「無効」を区別できるよう、欠けている場合は明示的に None を入れて残す。
- ログの保管時暗号化
  → `log_group_kms`（`{ロググループ名: kmsKeyId|None}`）。
    `describe_log_groups` の結果から組み立てるだけで追加 API は呼ばない。

CloudTrail のイベント本体（LookupEvents）は取得しない（ガードでも拒否済み）。
"""
from __future__ import annotations

from ..session import Context
from ._safe import safe_call, safe_paginate
from .base import Collector, jsonable, register


@register
class LoggingCollector(Collector):
    """CloudTrail・Config・フローログ・CloudWatch の有効性を収集する。"""

    name = "logging"

    iam_actions = (
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels",
        "config:DescribeConfigRules",
        "ec2:DescribeFlowLogs",
        "logs:DescribeLogGroups",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListDashboards",
    )

    def collect(self, ctx: Context) -> dict:
        data: dict = {}

        data["cloudtrail_trails"] = self._collect_trails(ctx)
        data["config_recorders"] = self._collect_config_recorders(ctx)

        # 配信先 S3 バケットと配信頻度（記録していても配信できていない事故がある）
        data["config_delivery_channels"] = safe_paginate(
            ctx, "config", "describe_delivery_channels", "DeliveryChannels",
            context="Config 配信チャネル",
        )
        data["config_rules"] = safe_paginate(
            ctx, "config", "describe_config_rules", "ConfigRules", context="Config ルール",
        )

        # -- VPC フローログ ---------------------------------------------------
        # ResourceId（VPC/サブネット/ENI のどれに付いているか）、LogDestination、
        # TrafficType、FlowLogStatus をそのまま残す。
        data["flow_logs"] = safe_paginate(
            ctx, "ec2", "describe_flow_logs", "FlowLogs", context="VPC フローログ",
        )

        # -- CloudWatch Logs ---------------------------------------------------
        # RetentionInDays が無いロググループは「無期限保持」（コスト増の原因）。
        log_groups = safe_paginate(
            ctx, "logs", "describe_log_groups", "logGroups", context="ロググループ一覧",
        )
        data["cloudwatch_log_groups"] = log_groups
        # ロググループの保管時暗号化。describe_log_groups の `kmsKeyId` を
        # 名前で引ける形に組み替えるだけ（追加の API 呼び出しは行わない）。
        data["log_group_kms"] = {
            str(group.get("logGroupName")): group.get("kmsKeyId")
            for group in log_groups
            if isinstance(group, dict) and group.get("logGroupName")
        }

        data["cloudwatch_alarms"] = self._collect_alarms(ctx)
        data["cloudwatch_dashboards"] = safe_paginate(
            ctx, "cloudwatch", "list_dashboards", "DashboardEntries",
            context="ダッシュボード一覧",
        )

        return jsonable(data)

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------
    def _collect_trails(self, ctx: Context) -> list[dict]:
        """証跡定義に稼働状況とイベントセレクタを足す。

        追加キー:
        - `Status` … get_trail_status の全体（LatestDeliveryTime / LatestDeliveryError）
        - `IsLogging` … 記録中かどうか（**作っただけで止まっている証跡の検出**）
        - `EventSelectors` / `AdvancedEventSelectors` … データイベントを取っているか

        `describe_trails` が返す `LogFileValidationEnabled` / `KmsKeyId` /
        `IsMultiRegionTrail` / `IsOrganizationTrail` は改ざん検知・暗号化・
        全リージョン化の判定に直結するため、レスポンスに含まれない場合も
        キー自体は None で残す（判定側が「未収集」と「無効」を取り違えないように）。

        別リージョンの証跡（シャドウトレイル）も返るため、`Name` ではなく
        ARN を渡して問い合わせる。
        """
        trails = safe_paginate(
            ctx, "cloudtrail", "describe_trails", "trailList", context="証跡一覧",
        )
        out: list[dict] = []
        for trail in trails:
            item = dict(trail)
            # describe_trails のレスポンス由来。欠けていても判定側が
            # KeyError にならないようキーを保証する（値は None のまま）。
            for key in (
                "LogFileValidationEnabled",
                "KmsKeyId",
                "IsMultiRegionTrail",
                "IsOrganizationTrail",
            ):
                item.setdefault(key, None)
            identifier = trail.get("TrailARN") or trail.get("Name")
            if not identifier:
                item["Status"] = None
                item["IsLogging"] = None
                item["EventSelectors"] = []
                item["AdvancedEventSelectors"] = []
                out.append(item)
                continue

            status = safe_call(
                ctx, "cloudtrail", "get_trail_status",
                context=f"証跡 {trail.get('Name')}", Name=identifier,
            )
            body = (
                {k: v for k, v in status.items() if k != "ResponseMetadata"}
                if status else None
            )
            item["Status"] = body
            item["IsLogging"] = (body or {}).get("IsLogging")

            selectors = safe_call(
                ctx, "cloudtrail", "get_event_selectors",
                context=f"証跡 {trail.get('Name')} のイベントセレクタ",
                TrailName=identifier,
            )
            item["EventSelectors"] = (selectors or {}).get("EventSelectors") or []
            item["AdvancedEventSelectors"] = (
                (selectors or {}).get("AdvancedEventSelectors") or []
            )
            out.append(item)
        return out

    # ------------------------------------------------------------------
    # AWS Config
    # ------------------------------------------------------------------
    def _collect_config_recorders(self, ctx: Context) -> list[dict]:
        """レコーダ定義に稼働状況（"Status"）を突き合わせて足す。

        定義が存在することと記録されていることは別なので、
        describe_configuration_recorder_status を名前で突き合わせる。
        """
        recorders = safe_paginate(
            ctx, "config", "describe_configuration_recorders", "ConfigurationRecorders",
            context="Config レコーダ",
        )
        statuses = safe_paginate(
            ctx, "config", "describe_configuration_recorder_status",
            "ConfigurationRecordersStatus", context="Config レコーダの稼働状況",
        )
        by_name = {s.get("name"): s for s in statuses if s.get("name")}

        out: list[dict] = []
        for recorder in recorders:
            item = dict(recorder)
            # recording / lastStatus / lastErrorMessage で実際に動いているかが分かる。
            item["Status"] = by_name.get(recorder.get("name"))
            out.append(item)
        return out

    # ------------------------------------------------------------------
    # CloudWatch
    # ------------------------------------------------------------------
    def _collect_alarms(self, ctx: Context) -> list[dict]:
        """メトリクスアラームと複合アラームの両方を 1 本の配列に集める。

        判定側で種別が分かるよう `"_AlarmType"` を足す
        （複合アラームには MetricName / Namespace が無いため）。
        """
        out: list[dict] = []
        for alarm_type, result_key in (
            ("MetricAlarm", "MetricAlarms"),
            ("CompositeAlarm", "CompositeAlarms"),
        ):
            alarms = safe_paginate(
                ctx, "cloudwatch", "describe_alarms", result_key,
                context=f"{alarm_type} 一覧", AlarmTypes=[alarm_type],
            )
            for alarm in alarms:
                item = dict(alarm)
                item["_AlarmType"] = alarm_type
                out.append(item)
        return out
