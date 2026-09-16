"""コンピュート（EC2 / Auto Scaling / SSM）コレクタ。

`docs/INVENTORY_SCHEMA.md` の `compute` セクションを埋める。

収集の狙い（未確認事項の解消）:
- 各インスタンスの素性（OS・AMI・IAM プロファイル・IMDS 設定）を確定させる
  → `instances` を素のまま残す
- 退役予定イベント（システム再起動・リタイア通知）の有無
  → `instance_statuses` を `IncludeAllInstances=True` で取得し `Events` を見る
- 使用中 AMI が廃止予定かどうか
  → `images` の `CreationDate` / `DeprecationTime`
- **AMI / EBS スナップショットの定期取得が仕組みとして存在するか**
  → `dlm_lifecycle_policies`（Data Lifecycle Manager のポリシーとスケジュール）
- **SSM で EC2 の中を調べられるか**（host-probe を SSM 経由にできるかの判定）
  → `ssm_managed_instances`（ssm:DescribeInstanceInformation）が最重要
- **EBS のアカウント既定暗号化が効いているか**（新規ボリュームが自動で暗号化されるか）
  → `ebs_encryption_by_default` / `ebs_default_kms_key_id`
- T 系インスタンスのバースト設定（`unlimited` は課金が跳ねる／`standard` は性能劣化）
  → `instance_credit_specifications`
- SSH 鍵を配らずに接続できる経路があるか
  → `instance_connect_endpoints`（EC2 Instance Connect Endpoint）

API 呼び出しは `_safe.safe_paginate` / `_safe.safe_call`（中身は `ctx.paginate` /
`ctx.call`）を通すため、SSM の権限が無くても errors に記録されるだけで
EC2 側の収集は続行される。
"""
from __future__ import annotations

from typing import Iterator

from ..session import Context
from ._safe import safe_call, safe_paginate
from .base import Collector, jsonable, register

#: describe_images に一度に渡す ImageId の最大数（API 制限を避けるための自主上限）
_IMAGE_BATCH = 50
#: describe_instance_patch_states の InstanceIds 上限（AWS 仕様で 50 件）
_PATCH_BATCH = 50
#: ListInventoryEntries を引くマネージドインスタンスの上限
#: （インスタンス数 × API 呼び出しになるため、調査用途では十分な数で打ち切る）
_INVENTORY_LIMIT = 50
#: describe_instance_credit_specifications の InstanceIds 上限（自主上限）
_CREDIT_BATCH = 50
#: 詳細（スケジュール・保持世代）を引く DLM ポリシーの上限
_DLM_POLICY_LIMIT = 50
#: バースト可能インスタンスファミリの接頭辞。
#: describe_instance_credit_specifications は T 系以外を渡すとエラーになるため、
#: あらかじめ絞り込んでから呼ぶ。
_BURSTABLE_PREFIXES = ("t1.", "t2.", "t3.", "t3a.", "t4g.")


def _chunked(items: list, size: int) -> Iterator[list]:
    """リストを size 件ずつに分割する。"""
    for i in range(0, len(items), size):
        yield items[i : i + size]


@register
class ComputeCollector(Collector):
    """EC2 インスタンス・ボリューム・AMI・ASG・SSM 管理状況を収集する。"""

    name = "compute"

    iam_actions = (
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeImages",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeLaunchTemplates",
        "autoscaling:DescribeAutoScalingGroups",
        "ssm:DescribeInstanceInformation",
        "ssm:DescribeInstancePatchStates",
        "ssm:ListInventoryEntries",
        # 以下はセキュリティ実施状況評価（posture.py）のために追加した読み取り系
        "ec2:GetEbsEncryptionByDefault",
        "ec2:GetEbsDefaultKmsKeyId",
        "ec2:DescribeInstanceCreditSpecifications",
        "ec2:DescribeInstanceConnectEndpoints",
        # AMI / スナップショットの定期取得が仕組みとして有るかの確認
        "dlm:GetLifecyclePolicies",
        "dlm:GetLifecyclePolicy",
    )

    def collect(self, ctx: Context) -> dict:
        data: dict = {}

        # -- インスタンス ---------------------------------------------------
        instances = self._collect_instances(ctx)
        data["instances"] = instances

        # -- インスタンスの状態とイベント -----------------------------------
        # IncludeAllInstances=True で停止中のものも含める。
        # Events に「retirement scheduled」「system reboot」等が入る。
        data["instance_statuses"] = safe_paginate(
            ctx,
            "ec2",
            "describe_instance_status",
            "InstanceStatuses",
            IncludeAllInstances=True,
        )

        # -- AMI ------------------------------------------------------------
        data["images"] = self._collect_images(ctx, instances)

        # -- ストレージ ------------------------------------------------------
        data["volumes"] = safe_paginate(ctx, "ec2", "describe_volumes", "Volumes")
        # 自アカウント所有のスナップショットのみ（public/amazon 所有を引くと数万件になる）。
        data["snapshots"] = safe_paginate(
            ctx, "ec2", "describe_snapshots", "Snapshots", OwnerIds=["self"]
        )

        # -- Auto Scaling / 起動テンプレート ----------------------------------
        data["auto_scaling_groups"] = safe_paginate(
            ctx, "autoscaling", "describe_auto_scaling_groups", "AutoScalingGroups"
        )
        data["launch_templates"] = safe_paginate(
            ctx, "ec2", "describe_launch_templates", "LaunchTemplates"
        )

        # -- キーペア（公開鍵の実体は API からは取得しない） --------------------
        data["key_pairs"] = safe_paginate(ctx, "ec2", "describe_key_pairs", "KeyPairs")

        # -- SSM -------------------------------------------------------------
        # SSM 経由で EC2 の中を調べられるかの判定に直結する最重要項目。
        # 権限が無い／SSM Agent が居ない場合は空配列 + errors になる。
        managed = safe_paginate(
            ctx,
            "ssm",
            "describe_instance_information",
            "InstanceInformationList",
            context="SSM 到達性の判定",
        )
        data["ssm_managed_instances"] = managed

        # インスタンス ID は「EC2 側にあるもの」と「SSM 側が知っているもの」を併せる。
        # （SSM のみに居るオンプレ登録インスタンスも拾えるようにする）
        instance_ids = sorted(
            {i.get("InstanceId") for i in instances if i.get("InstanceId")}
            | {m.get("InstanceId") for m in managed if m.get("InstanceId")}
        )

        data["ssm_patch_states"] = self._collect_patch_states(ctx, instance_ids)
        data["ssm_inventory"] = self._collect_inventory(ctx, managed)

        # -- EBS のアカウント既定暗号化 ----------------------------------------
        # ボリューム個別の Encrypted が全部 true でも、既定暗号化が off なら
        # 「次に作られるボリュームは平文」になる。両方を見ないと実施状況は判定できない。
        data["ebs_encryption_by_default"] = self._collect_ebs_encryption_default(ctx)
        data["ebs_default_kms_key_id"] = self._collect_ebs_default_kms_key(ctx)

        # -- T 系インスタンスのバースト設定 ------------------------------------
        data["instance_credit_specifications"] = self._collect_credit_specifications(
            ctx, instances
        )

        # -- EC2 Instance Connect Endpoint ------------------------------------
        # SSH 鍵を配らずに接続できる経路。あれば鍵配布の廃止根拠になる。
        data["dlm_lifecycle_policies"] = self._collect_dlm_policies(ctx)

        data["instance_connect_endpoints"] = safe_paginate(
            ctx, "ec2", "describe_instance_connect_endpoints",
            "InstanceConnectEndpoints", context="Instance Connect Endpoint 一覧",
        )

        return jsonable(data)

    # ------------------------------------------------------------------
    # 個別収集
    # ------------------------------------------------------------------
    def _collect_instances(self, ctx: Context) -> list[dict]:
        """describe_instances の Reservations を平坦化する。

        各 Instance に予約 ID を `"_reservation_id"` として足す
        （どのインスタンスが同時に起動されたかの手掛かりになる）。
        レスポンス要素そのものは加工せず、Platform / PlatformDetails /
        ImageId / InstanceType / Placement / SubnetId / VpcId /
        SecurityGroups / IamInstanceProfile / KeyName / BlockDeviceMappings /
        MetadataOptions / Monitoring / CpuOptions / Tags / State / LaunchTime
        をそのまま残す。
        """
        reservations = safe_paginate(ctx, "ec2", "describe_instances", "Reservations")
        flattened: list[dict] = []
        for reservation in reservations:
            reservation_id = reservation.get("ReservationId", "")
            for instance in reservation.get("Instances") or []:
                item = dict(instance)
                item["_reservation_id"] = reservation_id
                flattened.append(item)
        return flattened

    def _collect_images(self, ctx: Context, instances: list[dict]) -> list[dict]:
        """稼働中インスタンスが使う AMI と、自アカウント所有 AMI の両方を集める。

        他アカウント／Amazon 所有の AMI は `Owners=['self']` では取れないため、
        インスタンスの ImageId を明示的に引いて補う（AMI が既に削除されていて
        引けない場合は errors に残るだけで続行する）。
        """
        images: dict[str, dict] = {}

        # 自アカウント所有 AMI
        for image in safe_paginate(ctx, "ec2", "describe_images", "Images", Owners=["self"]):
            image_id = image.get("ImageId")
            if image_id:
                images[image_id] = image

        # 稼働中インスタンスが参照している AMI（自己所有でないものを補う）
        wanted = sorted(
            {i.get("ImageId") for i in instances if i.get("ImageId")} - set(images)
        )
        for batch in _chunked(wanted, _IMAGE_BATCH):
            found = safe_paginate(
                ctx,
                "ec2",
                "describe_images",
                "Images",
                ImageIds=batch,
                context=f"インスタンス使用中 AMI {len(batch)} 件",
            )
            if not found and len(batch) > 1:
                # バッチ内に削除済み AMI が 1 つでもあると API 全体が失敗するため、
                # 1 件ずつ引き直して取れるものだけ拾う。
                for image_id in batch:
                    found.extend(
                        safe_paginate(
                            ctx,
                            "ec2",
                            "describe_images",
                            "Images",
                            ImageIds=[image_id],
                            context=f"AMI {image_id}",
                        )
                    )
            for image in found:
                image_id = image.get("ImageId")
                if image_id:
                    images.setdefault(image_id, image)

        return [images[k] for k in sorted(images)]

    def _collect_patch_states(self, ctx: Context, instance_ids: list[str]) -> list[dict]:
        """SSM のパッチ適用状況（任意）。失敗しても続行する。"""
        if not instance_ids:
            return []
        states: list[dict] = []
        for batch in _chunked(instance_ids, _PATCH_BATCH):
            states.extend(
                safe_paginate(
                    ctx,
                    "ssm",
                    "describe_instance_patch_states",
                    "InstancePatchStates",
                    InstanceIds=batch,
                    context=f"{len(batch)} 件のパッチ状態",
                )
            )
        return states

    def _collect_ebs_encryption_default(self, ctx: Context) -> dict:
        """EBS のアカウント既定暗号化（`ec2:GetEbsEncryptionByDefault`）。

        戻り値は `{"EbsEncryptionByDefault": true|false}`。
        権限不足や未対応リージョンでは空 dict を返す（errors に理由が残る）。
        """
        resp = safe_call(
            ctx, "ec2", "get_ebs_encryption_by_default",
            context="EBS アカウント既定暗号化",
        )
        if not resp:
            return {}
        return {k: v for k, v in resp.items() if k != "ResponseMetadata"}

    def _collect_ebs_default_kms_key(self, ctx: Context) -> dict:
        """EBS 既定暗号化に使われる KMS キー（`ec2:GetEbsDefaultKmsKeyId`）。

        既定暗号化が off でも「どのキーが既定か」は引けるため常に取得する。
        AWS 管理キー（alias/aws/ebs）か、カスタマー管理キーかの判別に使う。
        """
        resp = safe_call(
            ctx, "ec2", "get_ebs_default_kms_key_id",
            context="EBS 既定 KMS キー",
        )
        if not resp:
            return {}
        return {k: v for k, v in resp.items() if k != "ResponseMetadata"}

    def _collect_dlm_policies(self, ctx: Context) -> list[dict]:
        """Data Lifecycle Manager のポリシー一覧に、各ポリシーの詳細を足す。

        「AMI やスナップショットが定期取得されているか」は、
        取得された成果物（`images` / `snapshots`）からは
        *仕組みとして* 動いているのか手動なのかを判別できない。
        DLM のポリシーが存在すれば、スケジュールと保持世代まで確定する。

        `get_lifecycle_policies` はページネータを持たないので `safe_call` を使う。
        一覧は要約（`PolicyId` / `State` / `Description`）しか返さないため、
        スケジュールと保持世代は `get_lifecycle_policy` で 1 件ずつ引く。
        """
        body = safe_call(ctx, "dlm", "get_lifecycle_policies", context="DLM ポリシー一覧")
        summaries = (body or {}).get("Policies") or []
        out: list[dict] = []
        for summary in summaries[:_DLM_POLICY_LIMIT]:
            if not isinstance(summary, dict):
                continue
            item = dict(summary)
            policy_id = summary.get("PolicyId")
            if policy_id:
                detail = safe_call(
                    ctx, "dlm", "get_lifecycle_policy",
                    context=f"DLM ポリシー {policy_id}", PolicyId=policy_id,
                )
                policy = (detail or {}).get("Policy") if detail else None
                if isinstance(policy, dict):
                    item.update({k: v for k, v in policy.items() if k != "PolicyId"})
            out.append(item)
        return out

    def _collect_credit_specifications(
        self, ctx: Context, instances: list[dict]
    ) -> list[dict]:
        """T 系インスタンスのバースト設定（`unlimited` / `standard`）。

        `describe_instance_credit_specifications` は T 系以外の InstanceId を
        渡すと `InvalidInstanceID.Malformed` 系のエラーになるため、
        `InstanceType` が T 系のものだけに絞ってから `_CREDIT_BATCH` 件ずつ引く。
        T 系が 1 台も無ければ API を呼ばずに空リストを返す。
        """
        targets = sorted(
            {
                instance.get("InstanceId")
                for instance in instances
                if instance.get("InstanceId")
                and str(instance.get("InstanceType") or "").startswith(_BURSTABLE_PREFIXES)
            }
        )
        if not targets:
            return []

        out: list[dict] = []
        for batch in _chunked(targets, _CREDIT_BATCH):
            out.extend(
                safe_paginate(
                    ctx,
                    "ec2",
                    "describe_instance_credit_specifications",
                    "InstanceCreditSpecifications",
                    InstanceIds=batch,
                    context=f"T 系インスタンス {len(batch)} 台のバースト設定",
                )
            )
        return out

    def _collect_inventory(self, ctx: Context, managed: list[dict]) -> list[dict]:
        """SSM インベントリ（導入ソフトウェア一覧・任意）。失敗しても続行する。

        インスタンス単位の API のため、マネージドインスタンスに限り、
        かつ `_INVENTORY_LIMIT` 件で打ち切る。
        """
        out: list[dict] = []
        targets = [m.get("InstanceId") for m in managed if m.get("InstanceId")]
        for instance_id in targets[:_INVENTORY_LIMIT]:
            resp = safe_call(
                ctx,
                "ssm",
                "list_inventory_entries",
                InstanceId=instance_id,
                TypeName="AWS:Application",
                context=f"インベントリ {instance_id}",
            )
            if not resp:
                continue
            out.append(
                {
                    "InstanceId": instance_id,
                    "TypeName": resp.get("TypeName", "AWS:Application"),
                    "SchemaVersion": resp.get("SchemaVersion"),
                    "CaptureTime": resp.get("CaptureTime"),
                    "Entries": resp.get("Entries") or [],
                }
            )
        return out
