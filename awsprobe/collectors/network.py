"""ネットワーク（VPC 周辺）コレクタ。

`docs/INVENTORY_SCHEMA.md` の `network` セクションを埋める。

収集の狙い（未確認事項の解消）:
- デフォルト VPC 由来のサブネットかどうか、CIDR が重複していないかを確定させる
  → `subnets` の `DefaultForAz` / `CidrBlock` / `AvailabilityZoneId`、`vpcs` の `IsDefault`
- 「誰も用途を知らない ENI」の正体を特定する
  → `network_interfaces` の `Description` / `InterfaceType` / `RequesterId`
    （例: Global Accelerator の ENI は Description から判別できる）
- アカウント間で AZ 名がずれる問題の確認
  → `availability_zones` の `ZoneName` と `ZoneId` の対応

API 呼び出しは `_safe.safe_paginate`（中身は `ctx.paginate`）を通すため、
権限不足で1つ落ちても残りの収集は続行される（失敗は ctx.errors に記録される）。
"""
from __future__ import annotations

from ..session import Context
from ._safe import safe_paginate
from .base import Collector, jsonable, register


@register
class NetworkCollector(Collector):
    """VPC・サブネット・ルーティング・SG・ENI などのネットワーク構成を収集する。"""

    name = "network"

    iam_actions = (
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeEgressOnlyInternetGateways",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeTransitGatewayVpcAttachments",
        "ec2:DescribeAddresses",
        "ec2:DescribeManagedPrefixLists",
        "ec2:DescribeAvailabilityZones",
    )

    def collect(self, ctx: Context) -> dict:
        data: dict = {}

        # -- VPC 本体 -----------------------------------------------------
        # IsDefault と CidrBlockAssociationSet（セカンダリ CIDR）をそのまま残す。
        data["vpcs"] = safe_paginate(ctx, "ec2", "describe_vpcs", "Vpcs")

        # -- サブネット ---------------------------------------------------
        # AvailabilityZone / AvailabilityZoneId / CidrBlock /
        # AvailableIpAddressCount / DefaultForAz / MapPublicIpOnLaunch を含む素のまま。
        data["subnets"] = safe_paginate(ctx, "ec2", "describe_subnets", "Subnets")

        # -- ルーティング -------------------------------------------------
        # Routes（0.0.0.0/0 の向き先）と Associations（Main フラグ）を必ず含める。
        data["route_tables"] = safe_paginate(ctx, "ec2", "describe_route_tables", "RouteTables")

        # -- ネットワーク ACL ---------------------------------------------
        # Entries（許可/拒否ルール）と Associations（どのサブネットに付いているか）。
        data["network_acls"] = safe_paginate(ctx, "ec2", "describe_network_acls", "NetworkAcls")

        # -- ゲートウェイ類 -----------------------------------------------
        data["internet_gateways"] = safe_paginate(
            ctx, "ec2", "describe_internet_gateways", "InternetGateways"
        )

        # NAT ゲートウェイは削除済みのものも返ってくるため、State == "deleted" を除外する。
        # （"deleting" は課金・経路が残るため意図的に残す）
        nat_gateways = safe_paginate(ctx, "ec2", "describe_nat_gateways", "NatGateways")
        data["nat_gateways"] = [
            ngw for ngw in nat_gateways if (ngw.get("State") or "").lower() != "deleted"
        ]

        data["egress_only_internet_gateways"] = safe_paginate(
            ctx,
            "ec2",
            "describe_egress_only_internet_gateways",
            "EgressOnlyInternetGateways",
        )

        # -- ENI ----------------------------------------------------------
        # 用途不明 ENI の正体を特定するため、Description / InterfaceType /
        # Attachment / Groups / RequesterId / RequesterManaged をそのまま残す。
        data["network_interfaces"] = safe_paginate(
            ctx, "ec2", "describe_network_interfaces", "NetworkInterfaces"
        )

        # -- セキュリティグループ -----------------------------------------
        # IpPermissions / IpPermissionsEgress を素のまま
        # （UserIdGroupPairs と IpRanges の両方を判定ロジックが見る）。
        data["security_groups"] = safe_paginate(
            ctx, "ec2", "describe_security_groups", "SecurityGroups"
        )

        # -- VPC 間接続 ---------------------------------------------------
        data["vpc_peering_connections"] = safe_paginate(
            ctx, "ec2", "describe_vpc_peering_connections", "VpcPeeringConnections"
        )
        data["vpc_endpoints"] = safe_paginate(ctx, "ec2", "describe_vpc_endpoints", "VpcEndpoints")
        data["transit_gateway_vpc_attachments"] = safe_paginate(
            ctx,
            "ec2",
            "describe_transit_gateway_vpc_attachments",
            "TransitGatewayVpcAttachments",
        )

        # -- EIP ----------------------------------------------------------
        # describe_addresses はページネーション非対応だが、ctx.paginate が
        # can_paginate を見て単発呼び出しにフォールバックする。
        data["elastic_ips"] = safe_paginate(ctx, "ec2", "describe_addresses", "Addresses")

        # -- プレフィックスリスト -----------------------------------------
        # SG ルールの PrefixListIds を人間が読める形に解決するために使う（任意）。
        data["prefix_lists"] = safe_paginate(
            ctx, "ec2", "describe_managed_prefix_lists", "PrefixLists"
        )

        # -- AZ 名と AZ ID の対応 ------------------------------------------
        # アカウントごとに ZoneName ↔ ZoneId のマッピングが異なるため、
        # 複数アカウントを並べて比較するときの基準として必ず取る。
        data["availability_zones"] = safe_paginate(
            ctx, "ec2", "describe_availability_zones", "AvailabilityZones"
        )

        return jsonable(data)
