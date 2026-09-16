"""サーバーレス（Lambda / EventBridge / Step Functions / DynamoDB / SQS / SNS /
Cognito / API Gateway）コレクタ。

`docs/INVENTORY_SCHEMA.md` の `serverless` セクションを埋める。

収集の狙い（未確認事項の解消）:
- 「誰も存在を把握していない Lambda」が何をトリガに動いているか
  → `lambda_functions` の `EventSourceMappings` / `Policy`（リソースポリシー）/ `UrlConfig`
- 定期実行の正体
  → `eventbridge_rules` の `ScheduleExpression` / `EventPattern` / `State` と `Targets`
- 外部に口が開いていないか
  → Lambda 関数 URL（`UrlConfig.AuthType`）と API Gateway

機微データは取得しない:
- Lambda の環境変数は **キー名のみ**（`{"_keys": [...]}` に置換する）
- DynamoDB は `describe_table` のみ。項目データは取得しない
- Cognito はユーザープールの設定のみ。ユーザーは取得しない
- Step Functions の `definition` は巨大なので長さと先頭 500 文字だけ残す
"""
from __future__ import annotations

import json
from typing import Any

from ..guard import mask_secret_values
from ..session import Context
from ._safe import safe_call, safe_paginate
from .base import Collector, jsonable, register

#: ステートマシン定義の保持長（全文は巨大かつ機微情報が混ざりうる）
_DEFINITION_HEAD = 500
#: list_user_pools の 1 ページ上限（API 仕様の最大値）
_USER_POOL_PAGE = 60


def _parse_policy(raw: Any) -> Any:
    """JSON 文字列のポリシーを dict に直す（壊れていれば文字列のまま返す）。"""
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


def _mask_environment(env: dict | None) -> dict | None:
    """Lambda の環境変数を **キー名のみ** に落とす。

    値には DB のパスワードや API キーが入っていることが多いため、
    `{"_keys": ["DB_HOST", ...]}` に置換して値は一切保持しない。
    """
    if not env:
        return None
    masked: dict[str, Any] = {"_keys": sorted((env.get("Variables") or {}).keys())}
    if env.get("Error"):
        # 復号失敗などのエラー情報は設定不備の手掛かりになるので残す（値は含まない）。
        masked["Error"] = env["Error"]
    return masked


@register
class ServerlessCollector(Collector):
    """Lambda・EventBridge・Step Functions・DynamoDB・SQS/SNS などを収集する。"""

    name = "serverless"

    iam_actions = (
        "lambda:ListFunctions",
        "lambda:ListEventSourceMappings",
        "lambda:GetPolicy",
        "lambda:GetFunctionUrlConfig",
        "lambda:ListTags",
        "events:ListEventBuses",
        "events:ListRules",
        "events:ListTargetsByRule",
        "states:ListStateMachines",
        "states:DescribeStateMachine",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "sns:ListTopics",
        "sns:GetTopicAttributes",
        "sns:ListSubscriptionsByTopic",
        "cognito-idp:ListUserPools",
        "cognito-idp:DescribeUserPool",
        "apigateway:GET",
    )

    def collect(self, ctx: Context) -> dict:
        data: dict = {}

        data["lambda_functions"] = self._collect_functions(ctx)

        buses = safe_paginate(
            ctx, "events", "list_event_buses", "EventBuses", context="イベントバス一覧",
        )
        data["eventbridge_buses"] = buses
        data["eventbridge_rules"] = self._collect_rules(ctx, buses)

        data["stepfunctions_state_machines"] = self._collect_state_machines(ctx)
        data["dynamodb_tables"] = self._collect_dynamodb_tables(ctx)
        data["sqs_queues"] = self._collect_queues(ctx)
        data["sns_topics"] = self._collect_topics(ctx)
        data["cognito_user_pools"] = self._collect_user_pools(ctx)

        # -- API Gateway ------------------------------------------------------
        # REST（v1）と HTTP/WebSocket（v2）は別 API なので両方引く。
        data["apigateway_rest_apis"] = safe_paginate(
            ctx, "apigateway", "get_rest_apis", "items", context="REST API 一覧",
        )
        data["apigatewayv2_apis"] = safe_paginate(
            ctx, "apigatewayv2", "get_apis", "Items", context="HTTP/WebSocket API 一覧",
        )

        return jsonable(data)

    # ------------------------------------------------------------------
    # Lambda
    # ------------------------------------------------------------------
    def _collect_functions(self, ctx: Context) -> list[dict]:
        """関数一覧に、トリガと公開状況を確定させる情報を足す。

        追加キー:
        - `EventSourceMappings` … SQS / DynamoDB Streams / Kinesis からの起動設定
        - `Policy` … リソースポリシー（誰が Invoke できるか。JSON をパースした dict）
        - `UrlConfig` … 関数 URL（`AuthType == "NONE"` なら完全公開）
        - `Tags` … 所有者・用途の手掛かり

        `Environment` は値を捨てキー名のみに置換する。
        `Runtime` / `LastModified` / `Handler` はそのまま残す（EOL 判定に使う）。
        """
        functions = safe_paginate(
            ctx, "lambda", "list_functions", "Functions", context="Lambda 関数一覧",
        )
        out: list[dict] = []
        for function in functions:
            item = dict(function)
            name = function.get("FunctionName")
            arn = function.get("FunctionArn")

            # 環境変数は値を持ち出さない（キー名だけで「何に繋がっているか」は判る）
            item["Environment"] = _mask_environment(function.get("Environment"))

            if not name:
                item["EventSourceMappings"] = []
                item["Policy"] = None
                item["UrlConfig"] = None
                item["Tags"] = None
                out.append(item)
                continue

            item["EventSourceMappings"] = safe_paginate(
                ctx, "lambda", "list_event_source_mappings", "EventSourceMappings",
                context=f"Lambda {name} のイベントソース", FunctionName=name,
            )

            policy = safe_call(
                ctx, "lambda", "get_policy",
                context=f"Lambda {name} のリソースポリシー", FunctionName=name,
            )
            # ポリシー未設定なら ResourceNotFoundException → None（errors に理由が残る）
            item["Policy"] = _parse_policy((policy or {}).get("Policy")) if policy else None

            url_config = safe_call(
                ctx, "lambda", "get_function_url_config",
                context=f"Lambda {name} の関数 URL", FunctionName=name,
            )
            item["UrlConfig"] = (
                {k: v for k, v in url_config.items() if k != "ResponseMetadata"}
                if url_config else None
            )

            tags = safe_call(
                ctx, "lambda", "list_tags",
                context=f"Lambda {name} のタグ", Resource=arn,
            ) if arn else None
            item["Tags"] = (tags or {}).get("Tags") if tags else None

            out.append(item)
        return out

    # ------------------------------------------------------------------
    # EventBridge
    # ------------------------------------------------------------------
    def _collect_rules(self, ctx: Context, buses: list[dict]) -> list[dict]:
        """全イベントバスのルールを平坦化し、各ルールに Targets を足す。

        既定バス以外にルールが隠れていることがあるため、`list_event_buses` の
        結果を必ず全部走査する（バスが 1 つも取れなければ "default" を試す）。
        """
        bus_names = [b.get("Name") for b in buses if b.get("Name")] or ["default"]
        out: list[dict] = []
        for bus_name in bus_names:
            for rule in safe_paginate(
                ctx, "events", "list_rules", "Rules",
                context=f"イベントバス {bus_name} のルール", EventBusName=bus_name,
            ):
                item = dict(rule)
                item["EventBusName"] = rule.get("EventBusName") or bus_name
                rule_name = rule.get("Name")
                # Targets で「その定期実行が何を叩いているか」が確定する。
                item["Targets"] = (
                    safe_paginate(
                        ctx, "events", "list_targets_by_rule", "Targets",
                        context=f"ルール {rule_name} のターゲット",
                        Rule=rule_name, EventBusName=bus_name,
                    )
                    if rule_name else []
                )
                out.append(item)
        return out

    # ------------------------------------------------------------------
    # Step Functions
    # ------------------------------------------------------------------
    def _collect_state_machines(self, ctx: Context) -> list[dict]:
        """ステートマシン一覧に describe_state_machine の結果を足す。

        `definition` は数十 KB になることがあり、かつ ARN やパラメータが
        そのまま書かれているため、長さ（`_definition_length`）と
        先頭 500 文字（`_definition_head`）だけを残して本体は捨てる。
        """
        machines = safe_paginate(
            ctx, "stepfunctions", "list_state_machines", "stateMachines",
            context="ステートマシン一覧",
        )
        out: list[dict] = []
        for machine in machines:
            item = dict(machine)
            arn = machine.get("stateMachineArn")
            if arn:
                detail = safe_call(
                    ctx, "stepfunctions", "describe_state_machine",
                    context=f"ステートマシン {machine.get('name') or arn}",
                    stateMachineArn=arn,
                )
                if detail:
                    body = {k: v for k, v in detail.items() if k != "ResponseMetadata"}
                    definition = body.pop("definition", "") or ""
                    body["_definition_length"] = len(definition)
                    body["_definition_head"] = definition[:_DEFINITION_HEAD]
                    item.update(body)
            out.append(item)
        return out

    # ------------------------------------------------------------------
    # DynamoDB
    # ------------------------------------------------------------------
    def _collect_dynamodb_tables(self, ctx: Context) -> list[dict]:
        """テーブル定義のみを集める。**項目データは絶対に取得しない**。

        （ガードでも dynamodb:Scan / Query を明示的に拒否している）
        """
        names = safe_paginate(
            ctx, "dynamodb", "list_tables", "TableNames", context="DynamoDB テーブル一覧",
        )
        out: list[dict] = []
        for name in names:
            resp = safe_call(
                ctx, "dynamodb", "describe_table",
                context=f"テーブル {name}", TableName=name,
            )
            table = (resp or {}).get("Table")
            if table:
                out.append(table)
        return out

    # ------------------------------------------------------------------
    # SQS / SNS
    # ------------------------------------------------------------------
    def _collect_queues(self, ctx: Context) -> list[dict]:
        """キュー URL と属性（DLQ 設定・暗号化・ポリシー）のみ。メッセージは読まない。"""
        urls = safe_paginate(ctx, "sqs", "list_queues", "QueueUrls", context="SQS キュー一覧")
        out: list[dict] = []
        for url in urls:
            resp = safe_call(
                ctx, "sqs", "get_queue_attributes",
                context=f"キュー {url}", QueueUrl=url, AttributeNames=["All"],
            )
            out.append({"QueueUrl": url, "Attributes": (resp or {}).get("Attributes") or {}})
        return out

    def _collect_topics(self, ctx: Context) -> list[dict]:
        """トピックの属性と購読先（誰に通知が飛んでいるか）を集める。"""
        topics = safe_paginate(ctx, "sns", "list_topics", "Topics", context="SNS トピック一覧")
        out: list[dict] = []
        for topic in topics:
            arn = topic.get("TopicArn")
            if not arn:
                continue
            attrs = safe_call(
                ctx, "sns", "get_topic_attributes", context=f"トピック {arn}", TopicArn=arn,
            )
            subs = safe_paginate(
                ctx, "sns", "list_subscriptions_by_topic", "Subscriptions",
                context=f"トピック {arn} の購読", TopicArn=arn,
            )
            out.append(
                {
                    "TopicArn": arn,
                    "Attributes": (attrs or {}).get("Attributes") or {},
                    # Subscriptions[].Endpoint には運用担当者のメールアドレスや
                    # 電話番号が入る。Protocol（email / sms / lambda 等）と件数は
                    # 通知経路の把握に必要なので残し、宛先の値だけ落とす。
                    "Subscriptions": mask_secret_values(subs),
                }
            )
        return out

    # ------------------------------------------------------------------
    # Cognito
    # ------------------------------------------------------------------
    def _collect_user_pools(self, ctx: Context) -> list[dict]:
        """ユーザープールの設定のみ。**ユーザーは絶対に取得しない**。"""
        pools = safe_paginate(
            ctx, "cognito-idp", "list_user_pools", "UserPools",
            context="Cognito ユーザープール一覧", MaxResults=_USER_POOL_PAGE,
        )
        out: list[dict] = []
        for pool in pools:
            item = dict(pool)
            pool_id = pool.get("Id")
            if pool_id:
                resp = safe_call(
                    ctx, "cognito-idp", "describe_user_pool",
                    context=f"ユーザープール {pool_id}", UserPoolId=pool_id,
                )
                detail = (resp or {}).get("UserPool")
                if detail:
                    # MfaConfiguration / Policies / AdminCreateUserConfig 等の設定のみ
                    item.update(detail)
            out.append(item)
        return out
