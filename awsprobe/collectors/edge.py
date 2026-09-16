"""エッジ（ELB / ACM / CloudFront / Global Accelerator / Route 53 / WAF）コレクタ。

`docs/INVENTORY_SCHEMA.md` の `edge` セクションを埋める。

収集の狙い（未確認事項の解消）:
- **WAF があるのか無いのか**を確定させる
  → `wafv2_web_acls` を REGIONAL と CLOUDFRONT の両スコープで引き、
    各要素に `AssociatedResourceArns` を足す
- **ALB のアクセスログが実際に有効か**を確定させる
  → `load_balancers` の `Attributes`（`access_logs.s3.enabled` の実値）
- **Global Accelerator がどの ALB を向いているか**を確定させる
  → `global_accelerators` の `Listeners[].EndpointGroups[].EndpointDescriptions`
- 証明書の期限と使用先
  → `acm_certificates` の `NotAfter` / `InUseBy`（CloudFront 用は us-east-1）
- DNS がどこを向いているか
  → `route53_record_sets` の `AliasTarget`

リージョン固定が必要なもの:
- CloudFront / WAFv2(CLOUDFRONT スコープ) / Shield … us-east-1
- Global Accelerator … us-west-2
- ACM … 調査リージョンと us-east-1 の両方
"""
from __future__ import annotations

from typing import Any

from ..guard import mask_secret_values
from ..session import Context
from ._safe import safe_call, safe_paginate
from .base import Collector, jsonable, register

#: グローバルサービス用の固定リージョン
_US_EAST_1 = "us-east-1"
#: Global Accelerator のコントロールプレーンは us-west-2 のみ
_GA_REGION = "us-west-2"
#: 手動ページングの安全弁（無限ループ防止）
_MAX_PAGES = 50


def _zone_id(raw: str) -> str:
    """"/hostedzone/Z123" 形式を "Z123" に正規化する。"""
    return (raw or "").rsplit("/", 1)[-1]


@register
class EdgeCollector(Collector):
    """ロードバランサ・証明書・CDN・DNS・WAF といった入口側の構成を収集する。"""

    name = "edge"

    iam_actions = (
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetGroupAttributes",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeRules",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "cloudfront:ListDistributions",
        "cloudfront:GetDistributionConfig",
        "globalaccelerator:ListAccelerators",
        "globalaccelerator:ListListeners",
        "globalaccelerator:ListEndpointGroups",
        "route53:ListHostedZones",
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "wafv2:ListWebACLs",
        "wafv2:ListResourcesForWebACL",
        "shield:DescribeSubscription",
    )

    def collect(self, ctx: Context) -> dict:
        data: dict = {}

        # -- ALB / NLB ------------------------------------------------------
        load_balancers = self._collect_load_balancers(ctx)
        data["load_balancers"] = load_balancers
        data["target_groups"] = self._collect_target_groups(ctx)

        listeners = self._collect_listeners(ctx, load_balancers)
        data["listeners"] = listeners
        data["listener_rules"] = self._collect_listener_rules(ctx, listeners)

        # -- Classic ELB -----------------------------------------------------
        # 残存している旧世代 LB の有無を確定させる。
        data["classic_load_balancers"] = safe_paginate(
            ctx, "elb", "describe_load_balancers", "LoadBalancerDescriptions",
            context="Classic ELB 一覧",
        )

        # -- 証明書 ----------------------------------------------------------
        data["acm_certificates"] = self._collect_certificates(ctx)

        # -- CloudFront ------------------------------------------------------
        data["cloudfront_distributions"] = self._collect_distributions(ctx)

        # -- Global Accelerator ----------------------------------------------
        data["global_accelerators"] = self._collect_accelerators(ctx)

        # -- Route 53 ---------------------------------------------------------
        zones = self._collect_hosted_zones(ctx)
        data["route53_hosted_zones"] = zones
        data["route53_record_sets"] = self._collect_record_sets(ctx, zones)

        # -- WAF --------------------------------------------------------------
        data["wafv2_web_acls"] = self._collect_web_acls(ctx)

        # -- Shield ------------------------------------------------------------
        # Shield Advanced を契約しているかどうか（未契約なら None）。
        subscription = safe_call(
            ctx, "shield", "describe_subscription",
            region=_US_EAST_1, context="Shield Advanced の契約状況",
        )
        data["shield_subscription"] = (subscription or {}).get("Subscription")

        return jsonable(data)

    # ------------------------------------------------------------------
    # ELBv2
    # ------------------------------------------------------------------
    def _collect_load_balancers(self, ctx: Context) -> list[dict]:
        """LB 一覧に describe_load_balancer_attributes を "Attributes" として足す。

        `access_logs.s3.enabled` / `deletion_protection.enabled` /
        `routing.http.drop_invalid_header_fields.enabled` などの実値がここで分かる。
        """
        load_balancers = safe_paginate(
            ctx, "elbv2", "describe_load_balancers", "LoadBalancers",
            context="ALB/NLB 一覧",
        )
        out: list[dict] = []
        for lb in load_balancers:
            item = dict(lb)
            arn = lb.get("LoadBalancerArn")
            if arn:
                resp = safe_call(
                    ctx, "elbv2", "describe_load_balancer_attributes",
                    context=f"LB {lb.get('LoadBalancerName') or arn} の属性",
                    LoadBalancerArn=arn,
                )
                item["Attributes"] = (resp or {}).get("Attributes") or []
            else:
                item["Attributes"] = []
            out.append(item)
        return out

    def _collect_target_groups(self, ctx: Context) -> list[dict]:
        """ターゲットグループに "Targets"（健全性）と "Attributes" を足す。"""
        groups = safe_paginate(
            ctx, "elbv2", "describe_target_groups", "TargetGroups",
            context="ターゲットグループ一覧",
        )
        out: list[dict] = []
        for group in groups:
            item = dict(group)
            arn = group.get("TargetGroupArn")
            if not arn:
                item["Targets"] = []
                item["Attributes"] = []
                out.append(item)
                continue

            health = safe_call(
                ctx, "elbv2", "describe_target_health",
                context=f"ターゲットグループ {group.get('TargetGroupName') or arn} の健全性",
                TargetGroupArn=arn,
            )
            # 何が実際にぶら下がっているか（インスタンス / IP / Lambda）が分かる。
            item["Targets"] = (health or {}).get("TargetHealthDescriptions") or []

            attrs = safe_call(
                ctx, "elbv2", "describe_target_group_attributes",
                context=f"ターゲットグループ {group.get('TargetGroupName') or arn} の属性",
                TargetGroupArn=arn,
            )
            # stickiness / deregistration_delay などの実値。
            item["Attributes"] = (attrs or {}).get("Attributes") or []
            out.append(item)
        return out

    def _collect_listeners(self, ctx: Context, load_balancers: list[dict]) -> list[dict]:
        """全 LB のリスナーを 1 本の配列に平坦化する。

        `Certificates` / `DefaultActions` / `SslPolicy` / `Protocol` / `Port` は
        レスポンスのまま残し、どの LB のものか分かるよう `LoadBalancerArn` を保証する。

        `SslPolicy` は TLS ポリシーの世代評価（`ELBSecurityPolicy-2016-08` のような
        旧世代が残っていないか）に直結する。HTTP リスナーには元から存在しない
        キーなので、判定側が「未収集」と「TLS 不要」を取り違えないよう
        欠けている場合は None で残す。
        """
        out: list[dict] = []
        for lb in load_balancers:
            arn = lb.get("LoadBalancerArn")
            if not arn:
                continue
            for listener in safe_paginate(
                ctx, "elbv2", "describe_listeners", "Listeners",
                context=f"LB {lb.get('LoadBalancerName') or arn} のリスナー",
                LoadBalancerArn=arn,
            ):
                item = dict(listener)
                item.setdefault("LoadBalancerArn", arn)
                item.setdefault("SslPolicy", None)
                out.append(item)
        return out

    def _collect_listener_rules(self, ctx: Context, listeners: list[dict]) -> list[dict]:
        """リスナールール（ホスト/パス条件での振り分け）を平坦化する。"""
        out: list[dict] = []
        for listener in listeners:
            listener_arn = listener.get("ListenerArn")
            if not listener_arn:
                continue
            for rule in safe_paginate(
                ctx, "elbv2", "describe_rules", "Rules",
                context=f"リスナー {listener_arn} のルール",
                ListenerArn=listener_arn,
            ):
                item = dict(rule)
                item["ListenerArn"] = listener_arn
                item["LoadBalancerArn"] = listener.get("LoadBalancerArn")
                out.append(item)
        return out

    # ------------------------------------------------------------------
    # ACM
    # ------------------------------------------------------------------
    def _collect_certificates(self, ctx: Context) -> list[dict]:
        """調査リージョンと us-east-1 の両方から証明書を集める。

        CloudFront に紐付く証明書は us-east-1 にしか存在しないため、
        片方だけを引くと「証明書が無い」と誤判定する。
        各要素にどちらで見つかったかを `"_Region"` として足す。
        """
        out: list[dict] = []
        for region in dict.fromkeys([ctx.region, _US_EAST_1]):
            summaries = safe_paginate(
                ctx, "acm", "list_certificates", "CertificateSummaryList",
                region=region, context=f"ACM 証明書一覧 ({region})",
            )
            for summary in summaries:
                arn = summary.get("CertificateArn")
                item = dict(summary)
                if arn:
                    resp = safe_call(
                        ctx, "acm", "describe_certificate",
                        region=region, context=f"証明書 {arn}",
                        CertificateArn=arn,
                    )
                    # DomainName / SubjectAlternativeNames / InUseBy / Status /
                    # NotAfter / Type / RenewalEligibility を含む素のまま。
                    detail = (resp or {}).get("Certificate")
                    if detail:
                        item.update(detail)
                item["_Region"] = region
                out.append(item)
        return out

    # ------------------------------------------------------------------
    # CloudFront
    # ------------------------------------------------------------------
    def _collect_distributions(self, ctx: Context) -> list[dict]:
        """CloudFront ディストリビューションと、その設定（Logging 等）を集める。

        `list_distributions` のレスポンスは `DistributionList.Items` と入れ子で、
        botocore のページネータのキー指定（ドット付き）が `ctx.paginate` では
        扱えないため、Marker で手動ページングする。
        """
        items: list[dict] = []
        marker: str | None = None
        for _ in range(_MAX_PAGES):
            kwargs: dict[str, Any] = {"Marker": marker} if marker else {}
            resp = safe_call(
                ctx, "cloudfront", "list_distributions",
                region=_US_EAST_1, context="CloudFront ディストリビューション一覧",
                **kwargs,
            )
            if not resp:
                break
            listing = resp.get("DistributionList") or {}
            items.extend(listing.get("Items") or [])
            if not listing.get("IsTruncated"):
                break
            marker = listing.get("NextMarker")
            if not marker:
                break

        out: list[dict] = []
        for dist in items:
            item = dict(dist)
            dist_id = dist.get("Id")
            if dist_id:
                resp = safe_call(
                    ctx, "cloudfront", "get_distribution_config",
                    region=_US_EAST_1, context=f"ディストリビューション {dist_id}",
                    Id=dist_id,
                )
                config = (resp or {}).get("DistributionConfig") or {}
                # Origins[].CustomHeaders[].HeaderValue には、ALB を CloudFront
                # 経由に限定するための**共有シークレット**が入る。キー名は
                # 構成の判断に必要なので残し、値だけ落とす。
                config = mask_secret_values(config)
                item["DistributionConfig"] = config or None
                # 一覧側には Logging が含まれないため、設定側から昇格させる
                # （標準アクセスログの有無の確定に直結）。
                item["Logging"] = config.get("Logging")
            else:
                item["DistributionConfig"] = None
                item["Logging"] = None
            out.append(item)
        return out

    # ------------------------------------------------------------------
    # Global Accelerator
    # ------------------------------------------------------------------
    def _collect_accelerators(self, ctx: Context) -> list[dict]:
        """アクセラレータ → リスナー → エンドポイントグループを入れ子で集める。

        エンドポイントグループの `EndpointDescriptions[].EndpointId` に
        ALB の ARN が入るため、「どの ALB を向いているか」がここで確定する。
        """
        accelerators = safe_paginate(
            ctx, "globalaccelerator", "list_accelerators", "Accelerators",
            region=_GA_REGION, context="Global Accelerator 一覧",
        )
        out: list[dict] = []
        for accelerator in accelerators:
            item = dict(accelerator)
            acc_arn = accelerator.get("AcceleratorArn")
            listeners: list[dict] = []
            if acc_arn:
                for listener in safe_paginate(
                    ctx, "globalaccelerator", "list_listeners", "Listeners",
                    region=_GA_REGION, context=f"アクセラレータ {acc_arn} のリスナー",
                    AcceleratorArn=acc_arn,
                ):
                    listener_item = dict(listener)
                    listener_arn = listener.get("ListenerArn")
                    listener_item["EndpointGroups"] = (
                        safe_paginate(
                            ctx, "globalaccelerator", "list_endpoint_groups",
                            "EndpointGroups",
                            region=_GA_REGION,
                            context=f"リスナー {listener_arn} のエンドポイントグループ",
                            ListenerArn=listener_arn,
                        )
                        if listener_arn else []
                    )
                    listeners.append(listener_item)
            item["Listeners"] = listeners
            out.append(item)
        return out

    # ------------------------------------------------------------------
    # Route 53
    # ------------------------------------------------------------------
    def _collect_hosted_zones(self, ctx: Context) -> list[dict]:
        """ホストゾーン一覧。プライベートゾーンには "VPCs" を足す。"""
        zones = safe_paginate(
            ctx, "route53", "list_hosted_zones", "HostedZones",
            region=_US_EAST_1, context="ホストゾーン一覧",
        )
        out: list[dict] = []
        for zone in zones:
            item = dict(zone)
            is_private = bool((zone.get("Config") or {}).get("PrivateZone"))
            if is_private and zone.get("Id"):
                resp = safe_call(
                    ctx, "route53", "get_hosted_zone",
                    region=_US_EAST_1, context=f"プライベートゾーン {zone.get('Name')}",
                    Id=zone["Id"],
                )
                # どの VPC に関連付いているか（VPC 間の名前解決の確定に使う）。
                item["VPCs"] = (resp or {}).get("VPCs") or []
            out.append(item)
        return out

    def _collect_record_sets(self, ctx: Context, zones: list[dict]) -> dict:
        """ゾーンごとのレコードセットを {ZoneId: [...]} で返す。

        キーは "/hostedzone/" を除いた素のゾーン ID。
        A / AAAA / CNAME の `AliasTarget`（ALB・CloudFront・S3 への向き先）を
        そのまま残す。
        """
        records: dict[str, list] = {}
        for zone in zones:
            raw_id = zone.get("Id")
            if not raw_id:
                continue
            records[_zone_id(raw_id)] = safe_paginate(
                ctx, "route53", "list_resource_record_sets", "ResourceRecordSets",
                region=_US_EAST_1, context=f"ゾーン {zone.get('Name')} のレコード",
                HostedZoneId=raw_id,
            )
        return records

    # ------------------------------------------------------------------
    # WAFv2
    # ------------------------------------------------------------------
    def _collect_web_acls(self, ctx: Context) -> list[dict]:
        """REGIONAL と CLOUDFRONT の両スコープで Web ACL を集める。

        「WAF があるのか無いのか」を確定させるため、片方が権限不足で
        引けなくてももう片方は必ず試す（結果は errors に残る）。

        CLOUDFRONT スコープでは `ListResourcesForWebACL` が使えない
        （REGIONAL 専用 API）ため `AssociatedResourceArns` は空配列になる。
        CloudFront 側の関連付けは `cloudfront_distributions[].WebACLId` で確認する。
        """
        out: list[dict] = []
        for scope, region in (("REGIONAL", ctx.region), ("CLOUDFRONT", _US_EAST_1)):
            for acl in self._list_web_acls(ctx, scope, region):
                item = dict(acl)
                item["Scope"] = scope
                arn = acl.get("ARN")
                if scope == "REGIONAL" and arn:
                    resp = safe_call(
                        ctx, "wafv2", "list_resources_for_web_acl",
                        region=region, context=f"Web ACL {acl.get('Name')} の関連リソース",
                        WebACLArn=arn,
                    )
                    item["AssociatedResourceArns"] = (resp or {}).get("ResourceArns") or []
                else:
                    item["AssociatedResourceArns"] = []
                out.append(item)
        return out

    def _list_web_acls(self, ctx: Context, scope: str, region: str) -> list[dict]:
        """ListWebACLs は NextMarker 方式のため手動でページングする。"""
        acls: list[dict] = []
        marker: str | None = None
        for _ in range(_MAX_PAGES):
            kwargs: dict[str, Any] = {"Scope": scope, "Limit": 100}
            if marker:
                kwargs["NextMarker"] = marker
            resp = safe_call(
                ctx, "wafv2", "list_web_acls",
                region=region, context=f"scope={scope}", **kwargs,
            )
            if not resp:
                break
            acls.extend(resp.get("WebACLs") or [])
            marker = resp.get("NextMarker")
            if not marker or not resp.get("WebACLs"):
                break
        return acls
