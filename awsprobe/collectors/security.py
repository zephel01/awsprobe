"""セキュリティ・統制（GuardDuty / Security Hub / Inspector / IAM /
Organizations / CloudFormation）コレクタ。

`docs/INVENTORY_SCHEMA.md` の `security` セクションを埋める。

収集の狙い（未確認事項の解消）:
- 脅威検知が有効かどうか（有効化したつもりで止まっている例が多い）
  → `guardduty_detectors` の `Status` / `FindingPublishingFrequency`、`securityhub`、`inspector2`
- **ベンダーに与えているクロスアカウント信頼関係の特定**
  → `iam.roles[].AssumeRolePolicyDocument`（Principal に他アカウントが入っていないか）
- 組織による統制（SCP）が効いているか
  → `organizations` の `Parents` と `ServiceControlPolicies`
- **出所不明の StackSet（StackSetVendorMonitorStackSet-* 等）の実体と権限モデルの確認**
  → `cloudformation_stack_sets` の `PermissionModel` / `AdministrationRoleARN` /
    `ExecutionRoleName` / `Capabilities` と `stack_instances`

- セキュリティ実施状況（posture.py）の判定材料
  → `kms_keys`（カスタマー管理キーのローテーション）、`secrets`（ローテーション設定）、
    `ssm_parameters_meta`（SecureString 化の状況）、`account_public_access_block`、
    `securityhub_standards_controls`（有効コントロール数）、`organizations_policies`（SCP 本文）、
    `iam.access_keys` / `iam.mfa_devices` / `iam.server_certificates`、
    `iam.role_inline_policies` / `iam.role_attached_policy_documents`（権限の広さ）

機微データは取得しない:
- IAM のクレデンシャルレポートは取得しない（`credential_report_meta` は常に None）
- Security Hub / GuardDuty / Inspector の Findings 本体は取得しない
- CloudFormation の `Parameters` / `Outputs` は **キー名のみ**、
  StackSet の `TemplateBody` は長さのみ
- **Secrets Manager の値（GetSecretValue）は絶対に取得しない**（ガードが拒否する）。
  ローテーション設定のメタ情報だけを見る
- **SSM パラメータの値（GetParameter 系）も取得しない**（ガードが拒否する）。
  `Type` が SecureString かどうかと名前だけを見る
- **IAM アクセスキー ID は末尾 4 文字を除いてマスクする**（`****ABCD` 形式）。
  経過日数と最終使用日は残すが、キー ID の全体は inventory に出さない
"""
from __future__ import annotations

import re
from typing import Any

from ..session import Context
from ._safe import safe_call, safe_paginate
from .base import Collector, jsonable, register

#: 付与ポリシーを引く IAM プリンシパルの上限
#: （プリンシパル 1 件につき 1 回の API になるため、調査用途で十分な数で打ち切る）
_IAM_PRINCIPAL_LIMIT = 200

#: list_users で残す要約キー（アクセスキーやパスワード情報は取得しない）
_USER_SUMMARY_KEYS = (
    "UserName", "UserId", "Arn", "Path", "CreateDate", "PasswordLastUsed", "Tags",
)

#: インラインポリシーを引くロール数の上限（ロール数 × 2 回以上の API になるため）
_INLINE_ROLE_LIMIT = 50
#: 本文を引くカスタマー管理ポリシーの上限（1 件につき GetPolicy + GetPolicyVersion）
_POLICY_DOCUMENT_LIMIT = 50
#: アクセスキー／MFA を引く IAM ユーザーの上限
_USER_DETAIL_LIMIT = 100
#: DescribeKey / GetKeyRotationStatus を引く KMS キーの上限
_KMS_KEY_LIMIT = 200
#: SCP 本文を辿る親 OU の最大段数（循環と深追いの防止）
_ORG_PARENT_DEPTH = 5

#: インラインポリシーを優先的に引くロール名のキーワード（小文字で比較する）。
#: 外部委託先が置いていったロールと、権限が広くなりがちなロールを先に見る。
_PRIORITY_ROLE_KEYWORDS = (
    "stackset", "service", "admin", "vendor", "monitoring",
    "cross", "external", "monitor", "backup", "deploy",
)

#: AWS 管理ポリシーの ARN 接頭辞。これ以外＝カスタマー管理ポリシー。
_AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"

#: list_secrets から残すキー（値に関わるものは一切残さない）
_SECRET_KEYS = (
    "Name", "ARN", "Description", "RotationEnabled", "RotationRules",
    "RotationLambdaARN", "LastRotatedDate", "LastChangedDate", "KmsKeyId", "CreatedDate",
)

#: describe_parameters から残すキー（**値は API 上もそもそも返らない**）
_SSM_PARAM_KEYS = (
    "Name", "Type", "KeyId", "LastModifiedDate", "Tier", "DataType", "Version",
)

#: describe_standards_controls から残すキー（本文の長い説明・手順は落とす）
_CONTROL_KEYS = (
    "StandardsControlArn", "ControlId", "ControlStatus", "SeverityRating",
    "Title", "ControlStatusUpdatedAt", "DisabledReason",
)


def _keys_only(items: list[dict] | None, key_name: str) -> dict:
    """[{"ParameterKey": "x", "ParameterValue": "秘密"}] → {"_keys": ["x"]}。

    値に接続文字列やパスワードが入っていることがあるため、キー名だけを残す。
    """
    return {"_keys": sorted({i.get(key_name) for i in (items or []) if i.get(key_name)})}


def _mask_access_key(access_key_id: Any) -> str:
    """アクセスキー ID を末尾 4 文字だけ残してマスクする。

    `"AKIAIOSFODNN7EXAMPLE"` → `"****AMPLE"` ではなく `"****MPLE"`（末尾 4 文字）。
    **inventory にキー ID の全体を書き出さないための最後の砦**なので、
    想定外の型が来ても必ず文字列を返す。
    """
    text = str(access_key_id or "")
    if len(text) <= 4:
        return "****" if not text else f"****{text}"
    return f"****{text[-4:]}"


def _external_accounts(document: Any, account_id: str) -> set[str]:
    """AssumeRolePolicyDocument から自アカウント以外の 12 桁アカウント ID を拾う。

    botocore は dict にデコードして返すが、文字列のまま入っている場合にも備える。
    インラインポリシーを引く優先順位づけにしか使わないため、精度より頑健性を優先する。
    """
    found: set[str] = set()
    if document is None:
        return found
    text = document if isinstance(document, str) else str(document)
    found.update(re.findall(r"arn:aws[\w-]*:(?:iam|sts)::(\d{12}):", text))
    found.update(re.findall(r"['\"]AWS['\"]\s*:\s*['\"](\d{12})['\"]", text))
    return {a for a in found if a and a != account_id}


@register
class SecurityCollector(Collector):
    """脅威検知・IAM・組織統制・CloudFormation の状況を収集する。"""

    name = "security"

    iam_actions = (
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListMembers",
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "inspector2:BatchGetAccountStatus",
        "access-analyzer:ListAnalyzers",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:ListAccountAliases",
        "organizations:DescribeOrganization",
        "organizations:ListParents",
        "organizations:ListPoliciesForTarget",
        "sso:ListInstances",
        "cloudformation:DescribeStacks",
        "cloudformation:ListStackSets",
        "cloudformation:DescribeStackSet",
        "cloudformation:ListStackInstances",
        # 以下はセキュリティ実施状況評価（posture.py）のために追加した読み取り系
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ListServerCertificates",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "secretsmanager:ListSecrets",
        "ssm:DescribeParameters",
        "s3:GetAccountPublicAccessBlock",
        "securityhub:DescribeStandardsControls",
        "organizations:DescribePolicy",
        "organizations:ListPoliciesForTarget",
    )

    def collect(self, ctx: Context) -> dict:
        data: dict = {}

        data["guardduty_detectors"] = self._collect_guardduty(ctx)
        data["securityhub"] = self._collect_securityhub(ctx)
        data["inspector2"] = self._collect_inspector(ctx)

        # 外部からアクセス可能なリソースの検出器（有効化されていれば）
        data["access_analyzer"] = safe_paginate(
            ctx, "accessanalyzer", "list_analyzers", "analyzers",
            context="IAM Access Analyzer 一覧",
        )

        # Security Hub で「何件のコントロールが有効か」まで見る（Findings は取らない）
        data["securityhub_standards_controls"] = self._collect_standards_controls(
            ctx, data["securityhub"]
        )

        data["iam"] = self._collect_iam(ctx)
        data["organizations"] = self._collect_organizations(ctx)
        # SCP の本文（継承分を含む）。どの操作が禁じられているかは本文を見ないと分からない。
        data["organizations_policies"] = self._collect_organizations_policies(ctx)

        # -- 鍵・シークレット -------------------------------------------------
        data["kms_keys"] = self._collect_kms_keys(ctx)
        data["secrets"] = self._collect_secrets(ctx)
        data["ssm_parameters_meta"] = self._collect_ssm_parameters(ctx)

        # -- S3 アカウントレベルのパブリックアクセスブロック -------------------
        data["account_public_access_block"] = self._collect_account_pab(ctx)

        # IAM Identity Center（旧 AWS SSO）を使っているか
        data["identity_center"] = {
            "Instances": safe_paginate(
                ctx, "sso-admin", "list_instances", "Instances",
                context="Identity Center インスタンス",
            )
        }

        data["cloudformation_stacks"] = self._collect_stacks(ctx)
        stack_sets = self._collect_stack_sets(ctx)
        data["cloudformation_stack_sets"] = stack_sets
        data["stack_instances"] = self._collect_stack_instances(ctx, stack_sets)

        return jsonable(data)

    # ------------------------------------------------------------------
    # 脅威検知
    # ------------------------------------------------------------------
    def _collect_guardduty(self, ctx: Context) -> list[dict]:
        """検出器の設定とメンバーアカウント。**Findings は取得しない**。"""
        detector_ids = safe_paginate(
            ctx, "guardduty", "list_detectors", "DetectorIds", context="GuardDuty 検出器一覧",
        )
        out: list[dict] = []
        for detector_id in detector_ids:
            resp = safe_call(
                ctx, "guardduty", "get_detector",
                context=f"検出器 {detector_id}", DetectorId=detector_id,
            )
            item: dict[str, Any] = {"DetectorId": detector_id}
            if resp:
                # Status / FindingPublishingFrequency / DataSources / Features
                item.update({k: v for k, v in resp.items() if k != "ResponseMetadata"})
            # S3 保護・EKS 監査ログ・Malware Protection・RDS ログイン保護の有効状況は
            # `Features`（新形式）か `DataSources`（旧形式）のどちらかに入る。
            # 判定側が「未収集」と「無効」を区別できるよう、キー自体は必ず残す。
            item.setdefault("Features", [])
            item.setdefault("DataSources", {})
            item["Members"] = safe_paginate(
                ctx, "guardduty", "list_members", "Members",
                context=f"検出器 {detector_id} のメンバー", DetectorId=detector_id,
            )
            out.append(item)
        return out

    def _collect_securityhub(self, ctx: Context) -> dict:
        """Security Hub の有効状況と有効な標準。**Findings は取得しない**。"""
        hub = safe_call(ctx, "securityhub", "describe_hub", context="Security Hub の状況")
        return {
            "Hub": (
                {k: v for k, v in hub.items() if k != "ResponseMetadata"} if hub else None
            ),
            "EnabledStandards": safe_paginate(
                ctx, "securityhub", "get_enabled_standards", "StandardsSubscriptions",
                context="有効な標準",
            ),
        }

    def _collect_inspector(self, ctx: Context) -> dict:
        """Inspector v2 のアカウント単位の有効状況（EC2 / ECR / Lambda 別）。"""
        kwargs = {"accountIds": [ctx.account_id]} if ctx.account_id else {}
        resp = safe_call(
            ctx, "inspector2", "batch_get_account_status",
            context="Inspector の有効状況", **kwargs,
        )
        if not resp:
            return {}
        return {k: v for k, v in resp.items() if k != "ResponseMetadata"}

    # ------------------------------------------------------------------
    # IAM
    # ------------------------------------------------------------------
    def _collect_iam(self, ctx: Context) -> dict:
        """IAM の概要。**クレデンシャルレポートは取得しない**。"""
        users = [
            {k: v for k, v in user.items() if k in _USER_SUMMARY_KEYS}
            for user in safe_paginate(ctx, "iam", "list_users", "Users", context="IAM ユーザー一覧")
        ]

        # AssumeRolePolicyDocument は botocore が dict にデコードして返す。
        # ベンダー等に渡しているクロスアカウント信頼関係の特定に使うため必ず残す。
        roles = safe_paginate(ctx, "iam", "list_roles", "Roles", context="IAM ロール一覧")

        password_policy = safe_call(
            ctx, "iam", "get_account_password_policy", context="パスワードポリシー",
        )
        summary = safe_call(ctx, "iam", "get_account_summary", context="アカウントサマリ")

        attached = self._collect_attached_policies(ctx, users, roles)

        return {
            "users": users,
            "roles": roles,
            "policies_attached_summary": attached,
            "account_summary": (summary or {}).get("SummaryMap") or {},
            # 未設定なら NoSuchEntity → None（errors に理由が残る）
            "password_policy": (password_policy or {}).get("PasswordPolicy"),
            # 機微情報のため実体は取得しない（契約上 None 固定）
            "credential_report_meta": None,
            "account_aliases": safe_paginate(
                ctx, "iam", "list_account_aliases", "AccountAliases", context="アカウント別名",
            ),
            # -- ここから下はセキュリティ実施状況の判定に使う追加項目 ----------
            "role_inline_policies": self._collect_role_inline_policies(ctx, roles),
            "role_attached_policy_documents": self._collect_policy_documents(ctx, attached),
            "access_keys": self._collect_access_keys(ctx, users),
            "mfa_devices": self._collect_mfa_devices(ctx, users),
            "server_certificates": safe_paginate(
                ctx, "iam", "list_server_certificates", "ServerCertificateMetadataList",
                context="IAM サーバー証明書",
            ),
        }

    # ------------------------------------------------------------------
    # IAM（権限の広さ）
    # ------------------------------------------------------------------
    def _prioritized_roles(self, ctx: Context, roles: list[dict]) -> list[dict]:
        """インラインポリシーを引く順にロールを並べ替える。

        1. 外部アカウントを信頼しているロール（ベンダーに渡した権限の可視化が主目的）
        2. 名前に StackSet / Service / Vendor 等を含むロール
        3. その他

        AWS サービスリンクロール（`/aws-service-role/` 配下）は AWS 側が管理していて
        書き換えられないため最後に回す。
        """
        def sort_key(role: dict) -> tuple:
            name = str(role.get("RoleName") or "")
            lowered = name.lower()
            external = bool(
                _external_accounts(role.get("AssumeRolePolicyDocument"), ctx.account_id)
            )
            keyworded = any(k in lowered for k in _PRIORITY_ROLE_KEYWORDS)
            service_linked = "/aws-service-role/" in str(role.get("Path") or "")
            # False < True なので、優先したいものを False 側に倒す
            return (service_linked, not external, not keyworded, name)

        return sorted([r for r in roles if r.get("RoleName")], key=sort_key)

    def _collect_role_inline_policies(self, ctx: Context, roles: list[dict]) -> dict:
        """ロールのインラインポリシー本文（`{ロール名: {ポリシー名: ドキュメント}}`）。

        管理ポリシーが ReadOnly でも、インラインで広い権限が足されている例があるため
        本文まで見る。ロール 1 件につき `ListRolePolicies` + ポリシー数分の
        `GetRolePolicy` になるので、`_prioritized_roles` の順に `_INLINE_ROLE_LIMIT`
        件で打ち切る（呼び出し爆発の防止）。

        インラインポリシーが 0 件のロールも空 dict で残す。
        「調べた結果 0 件」と「そもそも調べていない」を判定側が区別できるようにするため。
        """
        out: dict[str, dict] = {}
        for role in self._prioritized_roles(ctx, roles)[:_INLINE_ROLE_LIMIT]:
            name = str(role.get("RoleName"))
            policy_names = safe_paginate(
                ctx, "iam", "list_role_policies", "PolicyNames",
                context=f"ロール {name} のインラインポリシー名", RoleName=name,
            )
            documents: dict[str, Any] = {}
            for policy_name in policy_names:
                resp = safe_call(
                    ctx, "iam", "get_role_policy",
                    context=f"ロール {name} のインラインポリシー {policy_name}",
                    RoleName=name, PolicyName=str(policy_name),
                )
                if resp:
                    documents[str(policy_name)] = resp.get("PolicyDocument")
            out[name] = documents
        return out

    def _collect_policy_documents(self, ctx: Context, attached: list[dict]) -> dict:
        """アタッチ済み**カスタマー管理**ポリシーの本文（`{PolicyArn: {...}}`）。

        AWS 管理ポリシー（`arn:aws:iam::aws:policy/` 配下）は内容が公開されていて
        変更もできないため除外する。1 件につき `GetPolicy` + `GetPolicyVersion` の
        2 回になるので `_POLICY_DOCUMENT_LIMIT` 件で打ち切る。
        """
        wanted: dict[str, str] = {}
        for entry in attached:
            for policy in entry.get("AttachedPolicies") or []:
                if not isinstance(policy, dict):
                    continue
                arn = str(policy.get("PolicyArn") or "")
                if not arn or arn.startswith(_AWS_MANAGED_PREFIX):
                    continue
                wanted.setdefault(arn, str(policy.get("PolicyName") or ""))

        out: dict[str, dict] = {}
        for arn in sorted(wanted)[:_POLICY_DOCUMENT_LIMIT]:
            meta = safe_call(
                ctx, "iam", "get_policy",
                context=f"カスタマー管理ポリシー {wanted[arn] or arn}", PolicyArn=arn,
            )
            policy = (meta or {}).get("Policy") or {}
            version_id = policy.get("DefaultVersionId")
            document = None
            if version_id:
                version = safe_call(
                    ctx, "iam", "get_policy_version",
                    context=f"ポリシー {wanted[arn] or arn} の本文",
                    PolicyArn=arn, VersionId=str(version_id),
                )
                document = ((version or {}).get("PolicyVersion") or {}).get("Document")
            out[arn] = {
                "PolicyName": policy.get("PolicyName") or wanted[arn],
                "Arn": arn,
                "DefaultVersionId": version_id,
                "AttachmentCount": policy.get("AttachmentCount"),
                "UpdateDate": policy.get("UpdateDate"),
                "Document": document,
            }
        return out

    # ------------------------------------------------------------------
    # IAM（認証情報）
    # ------------------------------------------------------------------
    def _collect_access_keys(self, ctx: Context, users: list[dict]) -> list[dict]:
        """アクセスキーの作成日・状態・最終使用（**キー ID はマスクする**）。

        経過日数（90 日超のローテーション漏れ）と未使用キーの検出に使う。
        `AccessKeyId` は API 呼び出しには実体が要るが、**inventory に残すのは
        末尾 4 文字だけ**（`_mask_access_key`）。シークレットアクセスキーは
        AWS の API からはそもそも取得できない。
        """
        out: list[dict] = []
        for user in users[:_USER_DETAIL_LIMIT]:
            user_name = user.get("UserName")
            if not user_name:
                continue
            for key in safe_paginate(
                ctx, "iam", "list_access_keys", "AccessKeyMetadata",
                context=f"ユーザー {user_name} のアクセスキー", UserName=str(user_name),
            ):
                if not isinstance(key, dict):
                    continue
                key_id = key.get("AccessKeyId")
                last_used = safe_call(
                    ctx, "iam", "get_access_key_last_used",
                    context=f"ユーザー {user_name} のアクセスキー最終使用",
                    AccessKeyId=str(key_id),
                ) if key_id else None
                info = (last_used or {}).get("AccessKeyLastUsed") or {}
                out.append(
                    {
                        "UserName": key.get("UserName") or user_name,
                        # 生のキー ID は絶対に残さない
                        "AccessKeyId": _mask_access_key(key_id),
                        "Status": key.get("Status"),
                        "CreateDate": key.get("CreateDate"),
                        "LastUsedDate": info.get("LastUsedDate"),
                        "ServiceName": info.get("ServiceName"),
                        "Region": info.get("Region"),
                    }
                )
        return out

    def _collect_mfa_devices(self, ctx: Context, users: list[dict]) -> dict:
        """MFA デバイスの登録状況。

        - `UserDevices` … `{ユーザー名: [デバイス]}`（`iam:ListMFADevices`）
        - `VirtualDevices` … 仮想 MFA の一覧（`iam:ListVirtualMFADevices`）。
          **未割り当ての仮想 MFA が残っていないか**の確認にも使う。

        `SerialNumber` は ARN またはハードウェアの製造番号で、秘密情報ではない。
        """
        devices: dict[str, list] = {}
        for user in users[:_USER_DETAIL_LIMIT]:
            user_name = user.get("UserName")
            if not user_name:
                continue
            devices[str(user_name)] = safe_paginate(
                ctx, "iam", "list_mfa_devices", "MFADevices",
                context=f"ユーザー {user_name} の MFA デバイス", UserName=str(user_name),
            )
        return {
            "UserDevices": devices,
            "VirtualDevices": safe_paginate(
                ctx, "iam", "list_virtual_mfa_devices", "VirtualMFADevices",
                context="仮想 MFA デバイス一覧",
            ),
        }

    def _collect_attached_policies(
        self, ctx: Context, users: list[dict], roles: list[dict]
    ) -> list[dict]:
        """ロール／ユーザーに付いている管理ポリシーの一覧（名前のみ）。

        プリンシパル 1 件につき 1 回の API になるため `_IAM_PRINCIPAL_LIMIT` で打ち切る。
        ポリシー本文は取得しない（必要になったら別途 GetPolicyVersion を足す）。
        """
        out: list[dict] = []
        targets: list[tuple[str, str, str, str]] = []
        for role in roles:
            if role.get("RoleName"):
                targets.append(
                    ("role", role["RoleName"], "list_attached_role_policies", "RoleName")
                )
        for user in users:
            if user.get("UserName"):
                targets.append(
                    ("user", user["UserName"], "list_attached_user_policies", "UserName")
                )

        for kind, name, operation, param in targets[:_IAM_PRINCIPAL_LIMIT]:
            policies = safe_paginate(
                ctx, "iam", operation, "AttachedPolicies",
                context=f"{kind} {name} の付与ポリシー", **{param: name},
            )
            out.append({"PrincipalType": kind, "Name": name, "AttachedPolicies": policies})
        return out

    # ------------------------------------------------------------------
    # Organizations
    # ------------------------------------------------------------------
    def _collect_organizations(self, ctx: Context) -> dict:
        """組織情報と自アカウントに効いている SCP。組織未使用なら空 dict。"""
        resp = safe_call(
            ctx, "organizations", "describe_organization", context="組織情報",
        )
        if not resp or not resp.get("Organization"):
            # AWSOrganizationsNotInUseException は errors に記録済み
            return {}

        out: dict[str, Any] = {"Organization": resp["Organization"]}
        if ctx.account_id:
            # 自アカウントがどの OU にぶら下がっているか
            out["Parents"] = safe_paginate(
                ctx, "organizations", "list_parents", "Parents",
                context="自アカウントの親", ChildId=ctx.account_id,
            )
            # 直接アタッチされている SCP（継承分は OU 側を辿る必要がある）
            out["ServiceControlPolicies"] = safe_paginate(
                ctx, "organizations", "list_policies_for_target", "Policies",
                context="自アカウントの SCP",
                TargetId=ctx.account_id, Filter="SERVICE_CONTROL_POLICY",
            )
        return out

    def _collect_organizations_policies(self, ctx: Context) -> list[dict]:
        """自アカウントに効いている SCP の**本文**（継承分を含む）。

        `list_policies_for_target` はそのターゲットに直接アタッチされた SCP しか
        返さない。実際に効いているのは「アカウント + 親 OU + ルート」に付いた
        SCP の積なので、`list_parents` を `_ORG_PARENT_DEPTH` 段まで辿って
        それぞれのターゲットの SCP を集め、`describe_policy` で本文を引く。

        同じポリシーが複数のターゲットに付いている場合は、本文の取得は 1 回に
        まとめ、`AttachedTo` にターゲットを積む。組織未使用なら空リスト。
        """
        if not ctx.account_id:
            return []

        # 自アカウント → 親 OU → ルート の順にターゲットを辿る
        targets: list[tuple[str, str]] = [(ctx.account_id, "ACCOUNT")]
        seen_targets = {ctx.account_id}
        child_id = ctx.account_id
        for _ in range(_ORG_PARENT_DEPTH):
            parents = safe_paginate(
                ctx, "organizations", "list_parents", "Parents",
                context=f"{child_id} の親", ChildId=child_id,
            )
            parent = next((p for p in parents if isinstance(p, dict) and p.get("Id")), None)
            if not parent or parent["Id"] in seen_targets:
                break
            targets.append((str(parent["Id"]), str(parent.get("Type") or "")))
            seen_targets.add(str(parent["Id"]))
            child_id = str(parent["Id"])

        collected: dict[str, dict] = {}
        for target_id, target_type in targets:
            for policy in safe_paginate(
                ctx, "organizations", "list_policies_for_target", "Policies",
                context=f"{target_id} の SCP",
                TargetId=target_id, Filter="SERVICE_CONTROL_POLICY",
            ):
                if not isinstance(policy, dict) or not policy.get("Id"):
                    continue
                policy_id = str(policy["Id"])
                entry = collected.get(policy_id)
                if entry is None:
                    detail = safe_call(
                        ctx, "organizations", "describe_policy",
                        context=f"SCP {policy.get('Name') or policy_id} の本文",
                        PolicyId=policy_id,
                    )
                    body = (detail or {}).get("Policy") or {}
                    entry = {
                        "Id": policy_id,
                        "Name": policy.get("Name"),
                        "Type": policy.get("Type"),
                        "AwsManaged": policy.get("AwsManaged"),
                        "Description": policy.get("Description"),
                        # SCP の本文は「何を禁じているか」そのもので、機微情報ではない
                        "Content": body.get("Content"),
                        "AttachedTo": [],
                    }
                    collected[policy_id] = entry
                entry["AttachedTo"].append({"TargetId": target_id, "TargetType": target_type})
        return [collected[k] for k in sorted(collected)]

    # ------------------------------------------------------------------
    # Security Hub のコントロール
    # ------------------------------------------------------------------
    def _collect_standards_controls(self, ctx: Context, securityhub: dict) -> list[dict]:
        """有効な標準ごとのコントロール一覧（**Findings は取得しない**）。

        「Security Hub を有効にした」だけで、個別コントロールを大量に無効化して
        いる例があるため、`ControlStatus` の内訳まで見る。
        説明文・是正手順は長大なので `_CONTROL_KEYS` に絞る。
        """
        out: list[dict] = []
        for subscription in (securityhub or {}).get("EnabledStandards") or []:
            if not isinstance(subscription, dict):
                continue
            arn = subscription.get("StandardsSubscriptionArn")
            if not arn:
                continue
            controls = safe_paginate(
                ctx, "securityhub", "describe_standards_controls", "Controls",
                context=f"標準 {subscription.get('StandardsArn') or arn} のコントロール",
                StandardsSubscriptionArn=str(arn),
            )
            out.append(
                {
                    "StandardsSubscriptionArn": arn,
                    "StandardsArn": subscription.get("StandardsArn"),
                    "StandardsStatus": subscription.get("StandardsStatus"),
                    "Controls": [
                        {k: v for k, v in control.items() if k in _CONTROL_KEYS}
                        for control in controls
                        if isinstance(control, dict)
                    ],
                }
            )
        return out

    # ------------------------------------------------------------------
    # 鍵・シークレット（**値は一切取得しない**）
    # ------------------------------------------------------------------
    def _collect_kms_keys(self, ctx: Context) -> list[dict]:
        """**カスタマー管理**の KMS キーとその自動ローテーション状態。

        `list_keys` は AWS 管理キー（`aws/ebs` 等）も返すが、それらは AWS が
        3 年周期で自動ローテーションしていて利用者側に責任が無いため、
        `KeyManager == "CUSTOMER"` のものだけを残す。

        非対称キーやシークレットインポート済みキーでは
        `GetKeyRotationStatus` が `UnsupportedOperationException` になるが、
        `safe_call` が errors に記録するだけで収集は続行する。
        """
        key_ids = [
            str(k.get("KeyId"))
            for k in safe_paginate(ctx, "kms", "list_keys", "Keys", context="KMS キー一覧")
            if isinstance(k, dict) and k.get("KeyId")
        ]
        out: list[dict] = []
        for key_id in key_ids[:_KMS_KEY_LIMIT]:
            resp = safe_call(
                ctx, "kms", "describe_key", context=f"KMS キー {key_id}", KeyId=key_id,
            )
            metadata = (resp or {}).get("KeyMetadata") or {}
            if metadata.get("KeyManager") != "CUSTOMER":
                continue  # AWS 管理キーは評価対象外
            item = dict(metadata)
            rotation = safe_call(
                ctx, "kms", "get_key_rotation_status",
                context=f"KMS キー {key_id} のローテーション状態", KeyId=key_id,
            )
            # 取得できなかった場合は None（「無効」と区別できるようにする）
            item["RotationEnabled"] = (
                rotation.get("KeyRotationEnabled") if rotation else None
            )
            item["RotationPeriodInDays"] = (
                rotation.get("RotationPeriodInDays") if rotation else None
            )
            out.append(item)
        return out

    def _collect_secrets(self, ctx: Context) -> list[dict]:
        """Secrets Manager のシークレット**メタ情報のみ**。

        **`secretsmanager:GetSecretValue` は呼ばない**（ガードの拒否リストにも
        載っている）。ローテーションが設定されているか、最後にいつ回ったかだけを見る。
        """
        return [
            {k: v for k, v in secret.items() if k in _SECRET_KEYS}
            for secret in safe_paginate(
                ctx, "secretsmanager", "list_secrets", "SecretList",
                context="シークレット一覧",
            )
            if isinstance(secret, dict)
        ]

    def _collect_ssm_parameters(self, ctx: Context) -> list[dict]:
        """SSM パラメータストアの**メタ情報のみ**（`Type` と `Name`）。

        **`ssm:GetParameter` 系は呼ばない**（ガードの拒否リストに載っている）。
        `describe_parameters` は仕様上そもそも値を返さないので、
        平文の `String` に秘密が入っていないかを名前から推し量るための材料になる。
        """
        return [
            {k: v for k, v in param.items() if k in _SSM_PARAM_KEYS}
            for param in safe_paginate(
                ctx, "ssm", "describe_parameters", "Parameters",
                context="SSM パラメータ一覧",
            )
            if isinstance(param, dict)
        ]

    # ------------------------------------------------------------------
    # S3 アカウントレベルのパブリックアクセスブロック
    # ------------------------------------------------------------------
    def _collect_account_pab(self, ctx: Context) -> dict | None:
        """アカウント全体の S3 パブリックアクセスブロック（`s3control`）。

        バケット個別の設定より優先して効く「最後の砦」。`AccountId` が必須のため、
        呼び出し元アカウントが特定できていない場合は None を返す。
        未設定なら `NoSuchPublicAccessBlockConfiguration` になり errors に残る。
        """
        if not ctx.account_id:
            return None
        resp = safe_call(
            ctx, "s3control", "get_public_access_block",
            context="アカウントレベルのパブリックアクセスブロック",
            AccountId=ctx.account_id,
        )
        if not resp:
            return None
        return resp.get("PublicAccessBlockConfiguration")

    # ------------------------------------------------------------------
    # CloudFormation
    # ------------------------------------------------------------------
    def _collect_stacks(self, ctx: Context) -> list[dict]:
        """スタック一覧。Parameters / Outputs は値を捨ててキー名のみにする。"""
        stacks = safe_paginate(
            ctx, "cloudformation", "describe_stacks", "Stacks", context="スタック一覧",
        )
        out: list[dict] = []
        for stack in stacks:
            item = dict(stack)
            # 値に接続文字列・パスワード・鍵が入りうるため、キー名だけ残す
            item["Parameters"] = _keys_only(stack.get("Parameters"), "ParameterKey")
            item["Outputs"] = _keys_only(stack.get("Outputs"), "OutputKey")
            out.append(item)
        return out

    def _collect_stack_sets(self, ctx: Context) -> list[dict]:
        """StackSet 一覧に describe_stack_set の詳細を足す。

        出所不明の StackSet（監視ベンダー等が作った StackSetVendorMonitorStackSet-* など）の
        実体確認に直結する。`PermissionModel` / `AdministrationRoleARN` /
        `ExecutionRoleName` / `Capabilities` は必ず残す。
        `TemplateBody` は巨大なので長さのみ（`_TemplateBodyLength`）。
        """
        summaries = safe_paginate(
            ctx, "cloudformation", "list_stack_sets", "Summaries", context="StackSet 一覧",
        )
        out: list[dict] = []
        for summary in summaries:
            item = dict(summary)
            name = summary.get("StackSetName")
            if name:
                resp = safe_call(
                    ctx, "cloudformation", "describe_stack_set",
                    context=f"StackSet {name}", StackSetName=name,
                )
                detail = (resp or {}).get("StackSet")
                if detail:
                    body = dict(detail)
                    template = body.pop("TemplateBody", "") or ""
                    body["_TemplateBodyLength"] = len(template)
                    body["Parameters"] = _keys_only(detail.get("Parameters"), "ParameterKey")
                    item.update(body)
            out.append(item)
        return out

    def _collect_stack_instances(self, ctx: Context, stack_sets: list[dict]) -> list[dict]:
        """StackSet ごとのインスタンス（どのアカウント／リージョンに展開済みか）。"""
        out: list[dict] = []
        for stack_set in stack_sets:
            name = stack_set.get("StackSetName")
            if not name:
                continue
            for instance in safe_paginate(
                ctx, "cloudformation", "list_stack_instances", "Summaries",
                context=f"StackSet {name} のインスタンス", StackSetName=name,
            ):
                item = dict(instance)
                item.setdefault("StackSetName", name)
                out.append(item)
        return out
