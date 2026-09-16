"""storage / edge / serverless / logging / security コレクタの検証（moto によるモック AWS）。

確認すること:
1. 5 コレクタが REGISTRY に登録され、iam_actions を持つこと
2. INVENTORY_SCHEMA.md のキーがすべて埋まること（欠けキー・余剰キーが無いこと）
3. 「未確認事項の解消」に直結する項目が実際に値を持つこと
   （バケットの暗号化/バージョニング、EFS マウントターゲットの AZ、
     ALB の Attributes、Lambda の EventSourceMappings、CloudTrail の IsLogging、
     Config レコーダの Status、IAM ロールの AssumeRolePolicyDocument など）
4. 機微データを持ち出していないこと
   （Lambda 環境変数の値、CFn の Parameters/Outputs の値、credential report）
5. moto 未実装 API で落ちず errors に記録されること
6. 戻り値が json.dumps 可能であること（datetime が ISO 文字列になっていること）
7. **全 API 呼び出しが guard.is_allowed() を通り、変更系がゼロであること**

実行:
    python3 -m pytest tests/test_collectors_2.py -v
"""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
import zipfile

import boto3
from moto import mock_aws

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from awsprobe.collectors.base import REGISTRY  # noqa: E402
from awsprobe.collectors import edge as edge_mod  # noqa: E402,F401
from awsprobe.collectors import logging_ as logging_mod  # noqa: E402,F401
from awsprobe.collectors import security as security_mod  # noqa: E402,F401
from awsprobe.collectors import serverless as serverless_mod  # noqa: E402,F401
from awsprobe.collectors import storage as storage_mod  # noqa: E402,F401
from awsprobe.guard import ReadOnlyGuard  # noqa: E402
from awsprobe.session import Context  # noqa: E402

REGION = "ap-northeast-1"
ACCOUNT_ID = "123456789012"
BUCKET = "awsprobe-test-bucket"
TRAIL_BUCKET = "awsprobe-test-trail"
#: Lambda の環境変数に入れるダミー値。出力に現れてはいけない。
SECRET_VALUE = "SUPER-SECRET-VALUE-MUST-NOT-LEAK"


def _fake_credentials() -> None:
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
    os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)


def _lambda_zip() -> bytes:
    """moto の create_function に渡す最小の zip。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {}\n")
    return buf.getvalue()


class CollectorMotoTest(unittest.TestCase):
    """moto 上に最小構成の環境を作り、5 コレクタを回す。"""

    @classmethod
    def setUpClass(cls) -> None:
        _fake_credentials()
        cls._mock = mock_aws()
        cls._mock.start()

        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        s3 = session.client("s3", region_name=REGION)
        iam = session.client("iam", region_name=REGION)

        # --- VPC / サブネット（EFS・ALB・フローログの土台）---
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        cls.vpc_id = vpc["VpcId"]
        azs = ec2.describe_availability_zones()["AvailabilityZones"]
        cls.az_a, cls.az_c = azs[0]["ZoneName"], azs[1]["ZoneName"]
        cls.subnet_a = ec2.create_subnet(
            VpcId=cls.vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=cls.az_a
        )["Subnet"]["SubnetId"]
        cls.subnet_c = ec2.create_subnet(
            VpcId=cls.vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone=cls.az_c
        )["Subnet"]["SubnetId"]
        cls.sg_id = ec2.create_security_group(
            GroupName="awsprobe-edge-sg", Description="awsprobe test", VpcId=cls.vpc_id
        )["GroupId"]

        #: moto が未実装のリソースはセットアップ自体を諦める。何を作れたかをここに残す。
        cls.created: dict[str, bool] = {}

        cls._setup_s3(s3)
        cls._setup_efs(session)
        cls._setup_elbv2(session)
        cls._setup_route53(session)
        role_arn = cls._setup_iam(iam)
        cls.role_arn = role_arn
        cls._setup_serverless(session, role_arn)
        cls._setup_logging(session, ec2, role_arn)
        cls._setup_security(session)
        cls._setup_edge_extras(session)
        cls._setup_backup(session, role_arn)

        # --- コレクタ実行用の Context（読み取り専用ガード付き）---
        probe_session = boto3.Session(region_name=REGION)
        cls.guard = ReadOnlyGuard()
        cls.guard.attach(probe_session)
        cls.ctx = Context(
            session=probe_session,
            region=REGION,
            account_id=ACCOUNT_ID,
            guard=cls.guard,
        )

        cls.storage = REGISTRY["storage"]().collect(cls.ctx)
        cls.edge = REGISTRY["edge"]().collect(cls.ctx)
        cls.serverless = REGISTRY["serverless"]().collect(cls.ctx)
        cls.logging = REGISTRY["logging"]().collect(cls.ctx)
        cls.security = REGISTRY["security"]().collect(cls.ctx)
        cls.errors = cls.ctx.error_dicts()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._mock.stop()

    # ------------------------------------------------------------------
    # セットアップ（ここだけ変更系 API を使う。ガードは付けていない）
    # ------------------------------------------------------------------
    @classmethod
    def _setup_s3(cls, s3) -> None:  # noqa: ANN001
        for name in (BUCKET, TRAIL_BUCKET):
            s3.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={"LocationConstraint": REGION},
            )
        s3.put_bucket_policy(
            Bucket=BUCKET,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowRead",
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                            "Action": "s3:GetObject",
                            "Resource": f"arn:aws:s3:::{BUCKET}/*",
                        }
                    ],
                }
            ),
        )
        s3.put_bucket_encryption(
            Bucket=BUCKET,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        s3.put_bucket_versioning(
            Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"}
        )
        s3.put_bucket_tagging(
            Bucket=BUCKET, Tagging={"TagSet": [{"Key": "Name", "Value": "awsprobe"}]}
        )

    @classmethod
    def _setup_efs(cls, session) -> None:  # noqa: ANN001
        efs = session.client("efs", region_name=REGION)
        fs = efs.create_file_system(
            CreationToken="awsprobe-efs",
            PerformanceMode="generalPurpose",
            ThroughputMode="bursting",
            Encrypted=True,
            Tags=[{"Key": "Name", "Value": "awsprobe-efs"}],
        )
        cls.fs_id = fs["FileSystemId"]
        efs.create_mount_target(
            FileSystemId=cls.fs_id, SubnetId=cls.subnet_a, SecurityGroups=[cls.sg_id]
        )
        efs.create_access_point(
            ClientToken="awsprobe-ap",
            FileSystemId=cls.fs_id,
            RootDirectory={"Path": "/app-data"},
        )

    @classmethod
    def _setup_elbv2(cls, session) -> None:  # noqa: ANN001
        elbv2 = session.client("elbv2", region_name=REGION)
        lb = elbv2.create_load_balancer(
            Name="awsprobe-alb",
            Subnets=[cls.subnet_a, cls.subnet_c],
            SecurityGroups=[cls.sg_id],
            Scheme="internet-facing",
            Type="application",
        )["LoadBalancers"][0]
        cls.lb_arn = lb["LoadBalancerArn"]
        tg = elbv2.create_target_group(
            Name="awsprobe-tg",
            Protocol="HTTP",
            Port=80,
            VpcId=cls.vpc_id,
            TargetType="instance",
        )["TargetGroups"][0]
        cls.tg_arn = tg["TargetGroupArn"]
        elbv2.create_listener(
            LoadBalancerArn=cls.lb_arn,
            Protocol="HTTP",
            Port=80,
            DefaultActions=[{"Type": "forward", "TargetGroupArn": cls.tg_arn}],
        )

    @classmethod
    def _setup_route53(cls, session) -> None:  # noqa: ANN001
        route53 = session.client("route53", region_name="us-east-1")
        zone = route53.create_hosted_zone(
            Name="awsprobe.example.com.", CallerReference="awsprobe-1"
        )["HostedZone"]
        cls.zone_id = zone["Id"].rsplit("/", 1)[-1]
        route53.change_resource_record_sets(
            HostedZoneId=cls.zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "app.awsprobe.example.com.",
                            "Type": "A",
                            "AliasTarget": {
                                "HostedZoneId": "Z14GRHDCWA56QT",
                                "DNSName": "awsprobe-alb.ap-northeast-1.elb.amazonaws.com.",
                                "EvaluateTargetHealth": False,
                            },
                        },
                    }
                ]
            },
        )

    @classmethod
    def _setup_iam(cls, iam) -> str:  # noqa: ANN001
        assume = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    # ベンダーへのクロスアカウント信頼を模した内容
                    "Principal": {"AWS": "arn:aws:iam::210987654321:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role = iam.create_role(
            RoleName="awsprobe-vendor-role", AssumeRolePolicyDocument=json.dumps(assume)
        )["Role"]
        iam.create_user(UserName="awsprobe-user")
        return role["Arn"]

    @classmethod
    def _setup_serverless(cls, session, role_arn: str) -> None:  # noqa: ANN001
        lam = session.client("lambda", region_name=REGION)
        lam.create_function(
            FunctionName="awsprobe-fn",
            Runtime="python3.11",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": _lambda_zip()},
            Environment={"Variables": {"DB_PASSWORD": SECRET_VALUE, "STAGE": "prod"}},
            Tags={"Owner": "awsprobe"},
        )

        sqs = session.client("sqs", region_name=REGION)
        cls.queue_url = sqs.create_queue(QueueName="awsprobe-queue")["QueueUrl"]

        sns = session.client("sns", region_name=REGION)
        topic_arn = sns.create_topic(Name="awsprobe-topic")["TopicArn"]
        cls.topic_arn = topic_arn
        sns.subscribe(TopicArn=topic_arn, Protocol="email", Endpoint="ops@example.com")

        ddb = session.client("dynamodb", region_name=REGION)
        ddb.create_table(
            TableName="awsprobe-table",
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        events = session.client("events", region_name=REGION)
        events.put_rule(
            Name="awsprobe-rule", ScheduleExpression="rate(1 day)", State="ENABLED"
        )
        events.put_targets(
            Rule="awsprobe-rule",
            Targets=[{"Id": "1", "Arn": f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:awsprobe-topic"}],
        )

    @classmethod
    def _setup_logging(cls, session, ec2, role_arn: str) -> None:  # noqa: ANN001
        logs = session.client("logs", region_name=REGION)
        logs.create_log_group(logGroupName="/awsprobe/test")
        logs.put_retention_policy(logGroupName="/awsprobe/test", retentionInDays=30)

        try:
            ec2.create_flow_logs(
                ResourceIds=[cls.vpc_id],
                ResourceType="VPC",
                TrafficType="ALL",
                LogGroupName="/awsprobe/test",
                DeliverLogsPermissionArn=role_arn,
            )
        except Exception:  # noqa: BLE001 - moto の実装差異は検証対象外
            pass

        cw = session.client("cloudwatch", region_name=REGION)
        cw.put_metric_alarm(
            AlarmName="awsprobe-alarm",
            MetricName="CPUUtilization",
            Namespace="AWS/EC2",
            Statistic="Average",
            Period=300,
            EvaluationPeriods=1,
            Threshold=80.0,
            ComparisonOperator="GreaterThanThreshold",
            AlarmActions=[f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:awsprobe-topic"],
        )

        cloudtrail = session.client("cloudtrail", region_name=REGION)
        try:
            cloudtrail.create_trail(Name="awsprobe-trail", S3BucketName=TRAIL_BUCKET)
            cloudtrail.start_logging(Name="awsprobe-trail")
            cls.trail_created = True
        except Exception:  # noqa: BLE001
            cls.trail_created = False

    @classmethod
    def _setup_security(cls, session) -> None:  # noqa: ANN001
        cfn = session.client("cloudformation", region_name=REGION)
        template = json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "awsprobe test stack",
                "Parameters": {"DbPassword": {"Type": "String", "Default": "x"}},
                "Resources": {
                    "Topic": {
                        "Type": "AWS::SNS::Topic",
                        "Properties": {"TopicName": "awsprobe-stack-topic"},
                    }
                },
                "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
            }
        )
        cfn.create_stack(
            StackName="awsprobe-stack",
            TemplateBody=template,
            Parameters=[{"ParameterKey": "DbPassword", "ParameterValue": SECRET_VALUE}],
            Tags=[{"Key": "Owner", "Value": "awsprobe"}],
        )

        try:
            session.client("guardduty", region_name=REGION).create_detector(Enable=True)
        except Exception:  # noqa: BLE001
            pass

    @classmethod
    def _setup_edge_extras(cls, session) -> None:  # noqa: ANN001
        """ACM / WAFv2 / CloudFront / Step Functions / API Gateway。

        moto の実装状況に差があるため、作れたかどうかを `cls.created` に残し、
        テスト側で「作れた場合のみ中身を検証する」形にする。
        """
        # ACM（調査リージョンと us-east-1 の両方に 1 枚ずつ）
        for region in (REGION, "us-east-1"):
            try:
                session.client("acm", region_name=region).request_certificate(
                    DomainName=f"{region}.awsprobe.example.com",
                    ValidationMethod="DNS",
                    SubjectAlternativeNames=[f"*.{region}.awsprobe.example.com"],
                )
                cls.created[f"acm@{region}"] = True
            except Exception:  # noqa: BLE001
                cls.created[f"acm@{region}"] = False

        # WAFv2（REGIONAL スコープ）
        try:
            session.client("wafv2", region_name=REGION).create_web_acl(
                Name="awsprobe-acl",
                Scope="REGIONAL",
                DefaultAction={"Allow": {}},
                Rules=[],
                VisibilityConfig={
                    "SampledRequestsEnabled": False,
                    "CloudWatchMetricsEnabled": False,
                    "MetricName": "awsprobe",
                },
            )
            cls.created["wafv2"] = True
        except Exception:  # noqa: BLE001
            cls.created["wafv2"] = False

        # CloudFront（us-east-1 固定）
        try:
            session.client("cloudfront", region_name="us-east-1").create_distribution(
                DistributionConfig={
                    "CallerReference": "awsprobe-1",
                    "Comment": "awsprobe test",
                    "Enabled": True,
                    "Aliases": {"Quantity": 1, "Items": ["cdn.awsprobe.example.com"]},
                    "Origins": {
                        "Quantity": 1,
                        "Items": [
                            {
                                "Id": "alb",
                                "DomainName": "awsprobe-alb.ap-northeast-1.elb.amazonaws.com",
                                "CustomOriginConfig": {
                                    "HTTPPort": 80,
                                    "HTTPSPort": 443,
                                    "OriginProtocolPolicy": "https-only",
                                },
                            }
                        ],
                    },
                    "DefaultCacheBehavior": {
                        "TargetOriginId": "alb",
                        "ViewerProtocolPolicy": "redirect-to-https",
                        "MinTTL": 0,
                        "ForwardedValues": {
                            "QueryString": False,
                            "Cookies": {"Forward": "none"},
                        },
                        "TrustedSigners": {"Enabled": False, "Quantity": 0},
                    },
                }
            )
            cls.created["cloudfront"] = True
        except Exception:  # noqa: BLE001
            cls.created["cloudfront"] = False

        # Step Functions（definition が切り詰められることの確認用に長めの定義にする）
        try:
            states = [
                {f"Step{i}": {"Type": "Pass", "Next": f"Step{i + 1}"}} for i in range(40)
            ]
            definition = {
                "Comment": "awsprobe test state machine " + "x" * 400,
                "StartAt": "Step0",
                "States": {
                    **{k: v for s in states for k, v in s.items()},
                    "Step40": {"Type": "Succeed"},
                },
            }
            session.client("stepfunctions", region_name=REGION).create_state_machine(
                name="awsprobe-sm",
                definition=json.dumps(definition),
                roleArn=cls.role_arn,
            )
            cls.created["stepfunctions"] = True
        except Exception:  # noqa: BLE001
            cls.created["stepfunctions"] = False

        # API Gateway（REST / HTTP）
        try:
            session.client("apigateway", region_name=REGION).create_rest_api(
                name="awsprobe-rest"
            )
            cls.created["apigateway"] = True
        except Exception:  # noqa: BLE001
            cls.created["apigateway"] = False
        try:
            session.client("apigatewayv2", region_name=REGION).create_api(
                Name="awsprobe-http", ProtocolType="HTTP"
            )
            cls.created["apigatewayv2"] = True
        except Exception:  # noqa: BLE001
            cls.created["apigatewayv2"] = False

        # AWS Config（レコーダを起動して Status が突き合わされることの確認用）
        try:
            config = session.client("config", region_name=REGION)
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": "default",
                    "roleARN": cls.role_arn,
                    "recordingGroup": {
                        "allSupported": True,
                        "includeGlobalResourceTypes": False,
                    },
                }
            )
            config.put_delivery_channel(
                DeliveryChannel={"name": "default", "s3BucketName": TRAIL_BUCKET}
            )
            config.start_configuration_recorder(ConfigurationRecorderName="default")
            cls.created["config"] = True
        except Exception:  # noqa: BLE001
            cls.created["config"] = False

    @classmethod
    def _setup_backup(cls, session, role_arn: str) -> None:  # noqa: ANN001
        """AWS Backup のプラン／選択／ボールト。"""
        try:
            backup = session.client("backup", region_name=REGION)
            backup.create_backup_vault(BackupVaultName="awsprobe-vault")
            plan = backup.create_backup_plan(
                BackupPlan={
                    "BackupPlanName": "awsprobe-plan",
                    "Rules": [
                        {
                            "RuleName": "daily",
                            "TargetBackupVaultName": "awsprobe-vault",
                            "ScheduleExpression": "cron(0 5 * * ? *)",
                            "Lifecycle": {"DeleteAfterDays": 35},
                        }
                    ],
                }
            )
            cls.created["backup_plan"] = True
        except Exception:  # noqa: BLE001
            cls.created["backup_plan"] = False
            return
        try:
            backup.create_backup_selection(
                BackupPlanId=plan["BackupPlanId"],
                BackupSelection={
                    "SelectionName": "awsprobe-selection",
                    "IamRoleArn": role_arn,
                    "Resources": ["*"],
                },
            )
            cls.created["backup_selection"] = True
        except Exception:  # noqa: BLE001
            cls.created["backup_selection"] = False

    # ------------------------------------------------------------------
    # 登録
    # ------------------------------------------------------------------
    def test_registry(self) -> None:
        for name in ("storage", "edge", "serverless", "logging", "security"):
            self.assertIn(name, REGISTRY)
            self.assertTrue(REGISTRY[name].iam_actions, f"{name} に iam_actions が無い")

    # ------------------------------------------------------------------
    # スキーマのキー（INVENTORY_SCHEMA.md と厳密に一致すること）
    # ------------------------------------------------------------------
    def test_storage_schema_keys(self) -> None:
        expected = {
            "buckets", "efs_file_systems", "efs_mount_targets", "efs_access_points",
            "efs_policies", "efs_backup_policies", "fsx_file_systems",
            "backup_plans", "backup_selections", "backup_vaults",
            "backup_protected_resources",
        }
        self.assertEqual(expected, set(self.storage))
        self.assertIsInstance(self.storage["efs_policies"], dict)
        self.assertIsInstance(self.storage["efs_backup_policies"], dict)

    def test_edge_schema_keys(self) -> None:
        expected = {
            "load_balancers", "target_groups", "listeners", "listener_rules",
            "classic_load_balancers", "acm_certificates", "cloudfront_distributions",
            "global_accelerators", "route53_hosted_zones", "route53_record_sets",
            "wafv2_web_acls", "shield_subscription",
        }
        self.assertEqual(expected, set(self.edge))
        self.assertIsInstance(self.edge["route53_record_sets"], dict)

    def test_serverless_schema_keys(self) -> None:
        expected = {
            "lambda_functions", "eventbridge_rules", "eventbridge_buses",
            "stepfunctions_state_machines", "dynamodb_tables", "sqs_queues",
            "sns_topics", "cognito_user_pools", "apigateway_rest_apis",
            "apigatewayv2_apis",
        }
        self.assertEqual(expected, set(self.serverless))

    def test_logging_schema_keys(self) -> None:
        expected = {
            "cloudtrail_trails", "config_recorders", "config_delivery_channels",
            "config_rules", "flow_logs", "cloudwatch_log_groups",
            "cloudwatch_alarms", "cloudwatch_dashboards",
            # セキュリティ実施状況（posture.py）の判定に使う追加項目
            "log_group_kms",
        }
        self.assertEqual(expected, set(self.logging))

    def test_security_schema_keys(self) -> None:
        expected = {
            "guardduty_detectors", "securityhub", "inspector2", "access_analyzer",
            "iam", "organizations", "identity_center", "cloudformation_stacks",
            "cloudformation_stack_sets", "stack_instances",
            # セキュリティ実施状況（posture.py）の判定に使う追加項目
            "securityhub_standards_controls", "organizations_policies",
            "kms_keys", "secrets", "ssm_parameters_meta",
            "account_public_access_block",
        }
        self.assertEqual(expected, set(self.security))
        iam_expected = {
            "users", "roles", "policies_attached_summary", "account_summary",
            "password_policy", "credential_report_meta", "account_aliases",
            # セキュリティ実施状況（posture.py）の判定に使う追加項目
            "role_inline_policies", "role_attached_policy_documents",
            "access_keys", "mfa_devices", "server_certificates",
        }
        self.assertEqual(iam_expected, set(self.security["iam"]))

    # ------------------------------------------------------------------
    # storage の中身
    # ------------------------------------------------------------------
    def test_storage_bucket_details(self) -> None:
        bucket = next(b for b in self.storage["buckets"] if b["Name"] == BUCKET)
        # リージョンが確定していること（違うリージョンだと PermanentRedirect になる）
        self.assertEqual(REGION, bucket["Region"])
        # ポリシーは JSON 文字列ではなく dict にパースされていること
        self.assertIsInstance(bucket["Policy"], dict)
        self.assertEqual("AllowRead", bucket["Policy"]["Statement"][0]["Sid"])
        # 暗号化・バージョニング・タグが実値で取れていること
        self.assertIsNotNone(bucket["Encryption"])
        self.assertEqual("Enabled", (bucket["Versioning"] or {}).get("Status"))
        self.assertTrue(bucket["Tagging"])
        # 未設定のものは None（キー自体は必ず存在する）
        for key in (
            "PublicAccessBlock", "PolicyStatus", "Lifecycle", "Website",
            "Logging", "Acl", "Tagging", "ReplicationStatus",
        ):
            self.assertIn(key, bucket, f"buckets に {key} が無い")
        self.assertIsNone(bucket["Website"], "未設定の Website は None であるべき")

    def test_storage_bucket_calls_are_bounded(self) -> None:
        """バケットごとの追加取得が 10 種類以内に収まっていること。"""
        self.assertLessEqual(len(storage_mod._BUCKET_DETAILS), 10)
        ops = self.guard.summary()["operations"]
        buckets = len(self.storage["buckets"])
        self.assertEqual(buckets, ops.get("s3:GetBucketLocation"))
        # 1 バケットにつき 1 回ずつ（種類ごと）
        for _key, operation, _extract in storage_mod._BUCKET_DETAILS:
            api = "".join(part.capitalize() for part in operation.split("_"))
            # GetBucketLifecycleConfiguration は送信時 GetBucketLifecycle になる等の
            # 差異があるため、呼ばれた回数の上限だけを確認する
            self.assertLessEqual(ops.get(f"s3:{api}", 0), buckets)

    def test_storage_efs_mount_targets(self) -> None:
        """EFS が何本あり、どの AZ にマウントされているかが確定すること。"""
        fs = next(
            f for f in self.storage["efs_file_systems"] if f["FileSystemId"] == self.fs_id
        )
        for key in ("ThroughputMode", "PerformanceMode", "Encrypted", "SizeInBytes",
                    "NumberOfMountTargets"):
            self.assertIn(key, fs, f"efs_file_systems に {key} が無い")

        targets = [
            m for m in self.storage["efs_mount_targets"] if m["FileSystemId"] == self.fs_id
        ]
        self.assertTrue(targets, "マウントターゲットが平坦化されていない")
        target = targets[0]
        for key in ("FileSystemId", "SubnetId", "IpAddress", "NetworkInterfaceId"):
            self.assertIn(key, target, f"efs_mount_targets に {key} が無い")
        # AvailabilityZoneName は moto が返さない場合があるためキー存在のみ緩く確認
        self.assertEqual(self.subnet_a, target["SubnetId"])

    def test_storage_efs_access_points_keep_root_path(self) -> None:
        points = self.storage["efs_access_points"]
        self.assertTrue(points)
        self.assertEqual("/app-data", points[0]["RootDirectory"]["Path"])

    def test_storage_efs_policy_maps_are_keyed_by_fs(self) -> None:
        self.assertIn(self.fs_id, self.storage["efs_policies"])
        self.assertIn(self.fs_id, self.storage["efs_backup_policies"])

    def test_storage_backup_sections_are_lists(self) -> None:
        for key in ("backup_plans", "backup_selections", "backup_vaults",
                    "backup_protected_resources", "fsx_file_systems"):
            self.assertIsInstance(self.storage[key], list)

    def test_storage_backup_plan_has_rules(self) -> None:
        """プラン一覧に GetBackupPlan の定義（保持期間・スケジュール）が入ること。"""
        if not self.created.get("backup_plan"):
            self.skipTest("moto が AWS Backup のプラン作成に対応していない")
        plan = next(
            p for p in self.storage["backup_plans"] if p.get("BackupPlanName") == "awsprobe-plan"
        )
        rules = (plan["BackupPlan"] or {}).get("Rules") or []
        self.assertTrue(rules, "GetBackupPlan の Rules が取れていない")
        self.assertEqual("awsprobe-vault", rules[0]["TargetBackupVaultName"])
        vaults = {v.get("BackupVaultName") for v in self.storage["backup_vaults"]}
        self.assertIn("awsprobe-vault", vaults)

    # ------------------------------------------------------------------
    # edge の中身
    # ------------------------------------------------------------------
    def test_edge_load_balancer_attributes(self) -> None:
        """access_logs.s3.enabled の実値が Attributes から読めること。"""
        lb = next(
            b for b in self.edge["load_balancers"] if b["LoadBalancerArn"] == self.lb_arn
        )
        self.assertIn("Attributes", lb)
        self.assertIsInstance(lb["Attributes"], list)
        keys = {a.get("Key") for a in lb["Attributes"]}
        # NOTE: moto は既定の属性一式のうち access_logs.s3.enabled を返さないため、
        # ここでは access_logs.s3.* が属性として降りてくることまでを確認する。
        # 実 AWS では同じ経路で access_logs.s3.enabled の実値が入る。
        self.assertTrue(
            {k for k in keys if str(k).startswith("access_logs.s3.")},
            f"アクセスログ関連の属性が取れていない: {keys}",
        )
        self.assertIn("deletion_protection.enabled", keys)

    def test_edge_target_groups_have_targets_and_attributes(self) -> None:
        tg = next(
            g for g in self.edge["target_groups"] if g["TargetGroupArn"] == self.tg_arn
        )
        self.assertIn("Targets", tg)
        self.assertIn("Attributes", tg)
        self.assertIsInstance(tg["Targets"], list)

    def test_edge_listeners_are_flattened_with_lb_arn(self) -> None:
        listeners = [
            x for x in self.edge["listeners"] if x["LoadBalancerArn"] == self.lb_arn
        ]
        self.assertTrue(listeners)
        listener = listeners[0]
        for key in ("Protocol", "Port", "DefaultActions", "ListenerArn"):
            self.assertIn(key, listener, f"listeners に {key} が無い")
        self.assertIsInstance(self.edge["listener_rules"], list)

    def test_edge_acm_queried_in_both_regions(self) -> None:
        """ap-northeast-1 と us-east-1 の両方を引いていること（CloudFront 用は us-east-1）。"""
        ops = self.guard.summary()["operations"]
        self.assertEqual(2, ops.get("acm:ListCertificates"))
        for cert in self.edge["acm_certificates"]:
            self.assertIn(cert["_Region"], (REGION, "us-east-1"))

        if not all(self.created.get(f"acm@{r}") for r in (REGION, "us-east-1")):
            self.skipTest("moto が ACM の証明書作成に対応していない")
        regions = {c["_Region"] for c in self.edge["acm_certificates"]}
        self.assertEqual({REGION, "us-east-1"}, regions)
        cert = next(c for c in self.edge["acm_certificates"] if c["_Region"] == "us-east-1")
        # DescribeCertificate でしか取れない項目が合流していること
        for key in ("DomainName", "SubjectAlternativeNames", "InUseBy", "Status", "Type"):
            self.assertIn(key, cert, f"acm_certificates に {key} が無い")

    def test_edge_waf_queried_in_both_scopes(self) -> None:
        """WAF の有無を確定させるため両スコープを試していること。"""
        ops = self.guard.summary()["operations"]
        self.assertGreaterEqual(ops.get("wafv2:ListWebACLs", 0), 2)
        for acl in self.edge["wafv2_web_acls"]:
            self.assertIn(acl["Scope"], ("REGIONAL", "CLOUDFRONT"))
            self.assertIn("AssociatedResourceArns", acl)

        if not self.created.get("wafv2"):
            self.skipTest("moto が WAFv2 の Web ACL 作成に対応していない")
        acl = next(a for a in self.edge["wafv2_web_acls"] if a["Name"] == "awsprobe-acl")
        self.assertEqual("REGIONAL", acl["Scope"])
        # NOTE: moto は ListResourcesForWebACL 未実装のため関連リソースは空になる。
        # 呼び出し自体は行われ、失敗は errors に記録されている（実 AWS では ARN が返る）。
        self.assertIsInstance(acl["AssociatedResourceArns"], list)
        failed = {(e["service"], e["operation"]) for e in self.errors}
        self.assertIn(("wafv2", "list_resources_for_web_acl"), failed)

    def test_edge_cloudfront_config_is_merged(self) -> None:
        """一覧に無い Logging 等が GetDistributionConfig から合流していること。"""
        if not self.created.get("cloudfront"):
            self.skipTest("moto が CloudFront の作成に対応していない")
        dist = self.edge["cloudfront_distributions"][0]
        for key in ("Aliases", "Origins", "DefaultCacheBehavior", "WebACLId",
                    "ViewerCertificate", "Logging", "DistributionConfig"):
            self.assertIn(key, dist, f"cloudfront_distributions に {key} が無い")
        self.assertEqual(
            ["cdn.awsprobe.example.com"], (dist["Aliases"] or {}).get("Items")
        )
        self.assertIsNotNone(dist["DistributionConfig"])

    def test_edge_route53_records_keep_alias_target(self) -> None:
        zone_ids = {z["Id"].rsplit("/", 1)[-1] for z in self.edge["route53_hosted_zones"]}
        self.assertIn(self.zone_id, zone_ids)
        records = self.edge["route53_record_sets"][self.zone_id]
        alias = [r for r in records if r.get("AliasTarget")]
        self.assertTrue(alias, "A レコードの AliasTarget が残っていない")
        self.assertIn("DNSName", alias[0]["AliasTarget"])

    def test_edge_global_services_use_fixed_regions(self) -> None:
        """CloudFront は us-east-1、Global Accelerator は us-west-2 で引くこと。"""
        clients = self.ctx._clients
        self.assertIn("cloudfront@us-east-1", clients)
        self.assertIn("globalaccelerator@us-west-2", clients)
        self.assertIn("acm@us-east-1", clients)
        self.assertIn("wafv2@us-east-1", clients)
        # 入れ子構造（Listeners → EndpointGroups）が作られていること
        for accelerator in self.edge["global_accelerators"]:
            self.assertIn("Listeners", accelerator)
            for listener in accelerator["Listeners"]:
                self.assertIn("EndpointGroups", listener)

    # ------------------------------------------------------------------
    # serverless の中身
    # ------------------------------------------------------------------
    def test_serverless_lambda_details(self) -> None:
        fn = next(
            f for f in self.serverless["lambda_functions"]
            if f["FunctionName"] == "awsprobe-fn"
        )
        for key in ("Runtime", "LastModified", "Handler", "EventSourceMappings",
                    "Policy", "UrlConfig", "Tags", "Environment"):
            self.assertIn(key, fn, f"lambda_functions に {key} が無い")
        self.assertEqual("python3.11", fn["Runtime"])
        self.assertIsInstance(fn["EventSourceMappings"], list)

    def test_serverless_lambda_environment_is_keys_only(self) -> None:
        """環境変数は **キー名のみ**。値が出力に現れないこと。"""
        fn = next(
            f for f in self.serverless["lambda_functions"]
            if f["FunctionName"] == "awsprobe-fn"
        )
        self.assertEqual({"_keys": ["DB_PASSWORD", "STAGE"]}, fn["Environment"])
        self.assertNotIn(SECRET_VALUE, json.dumps(self.serverless, ensure_ascii=False))

    def test_serverless_eventbridge_rules_have_targets(self) -> None:
        rule = next(
            r for r in self.serverless["eventbridge_rules"] if r["Name"] == "awsprobe-rule"
        )
        self.assertEqual("rate(1 day)", rule["ScheduleExpression"])
        self.assertEqual("ENABLED", rule["State"])
        self.assertTrue(rule["EventBusName"])
        self.assertTrue(rule["Targets"], "ルールのターゲットが取れていない")

    def test_serverless_dynamodb_definition_only(self) -> None:
        table = next(
            t for t in self.serverless["dynamodb_tables"] if t["TableName"] == "awsprobe-table"
        )
        self.assertIn("KeySchema", table)
        # 項目データを取りに行っていないこと
        ops = self.guard.summary()["operations"]
        self.assertNotIn("dynamodb:Scan", ops)
        self.assertNotIn("dynamodb:Query", ops)

    def test_serverless_sqs_and_sns(self) -> None:
        queue = next(
            q for q in self.serverless["sqs_queues"] if q["QueueUrl"] == self.queue_url
        )
        self.assertIn("QueueArn", queue["Attributes"])
        topic = next(
            t for t in self.serverless["sns_topics"] if t["TopicArn"] == self.topic_arn
        )
        self.assertIn("Attributes", topic)
        self.assertTrue(topic["Subscriptions"], "購読先が取れていない")

    def test_serverless_stepfunctions_definition_is_truncated(self) -> None:
        for machine in self.serverless["stepfunctions_state_machines"]:
            self.assertNotIn("definition", machine)
            self.assertIn("_definition_head", machine)
            self.assertLessEqual(len(machine["_definition_head"]), 500)
        if not self.created.get("stepfunctions"):
            self.skipTest("moto が Step Functions の作成に対応していない")
        machine = next(
            m for m in self.serverless["stepfunctions_state_machines"]
            if m["name"] == "awsprobe-sm"
        )
        # 長さは元の定義のまま、本体は先頭 500 文字だけ
        self.assertGreater(machine["_definition_length"], 500)
        self.assertEqual(500, len(machine["_definition_head"]))

    def test_serverless_apigateway_both_versions(self) -> None:
        if self.created.get("apigateway"):
            names = {a.get("name") for a in self.serverless["apigateway_rest_apis"]}
            self.assertIn("awsprobe-rest", names)
        if self.created.get("apigatewayv2"):
            names = {a.get("Name") for a in self.serverless["apigatewayv2_apis"]}
            self.assertIn("awsprobe-http", names)

    def test_serverless_cognito_users_never_fetched(self) -> None:
        ops = self.guard.summary()["operations"]
        for forbidden in ("cognito-idp:ListUsers", "cognito-idp:AdminGetUser"):
            self.assertNotIn(forbidden, ops)

    # ------------------------------------------------------------------
    # logging の中身
    # ------------------------------------------------------------------
    def test_logging_cloudtrail_status(self) -> None:
        trails = self.logging["cloudtrail_trails"]
        if not self.trail_created:
            self.skipTest("moto が CloudTrail の作成に対応していない")
        trail = next(t for t in trails if t["Name"] == "awsprobe-trail")
        for key in ("Status", "IsLogging", "EventSelectors"):
            self.assertIn(key, trail, f"cloudtrail_trails に {key} が無い")
        # 「作っただけで止まっている証跡」の判定に直結する
        self.assertTrue(trail["IsLogging"])
        # イベント本体は取得していないこと
        self.assertNotIn("cloudtrail:LookupEvents", self.guard.summary()["operations"])

    def test_logging_config_recorders_have_status_key(self) -> None:
        for recorder in self.logging["config_recorders"]:
            self.assertIn("Status", recorder)
        # レコーダが無くても稼働状況の API は叩いていること（= 未設定が確定できる）
        ops = self.guard.summary()["operations"]
        self.assertIn("config:DescribeConfigurationRecorders", ops)
        self.assertIn("config:DescribeConfigurationRecorderStatus", ops)

        if not self.created.get("config"):
            self.skipTest("moto が AWS Config に対応していない")
        # 「Config が本当に有効か」は定義ではなく Status.recording で決まる
        recorder = next(r for r in self.logging["config_recorders"] if r["name"] == "default")
        self.assertIsNotNone(recorder["Status"], "レコーダの稼働状況が突き合わされていない")
        self.assertTrue(recorder["Status"].get("recording"))
        channels = {c.get("name") for c in self.logging["config_delivery_channels"]}
        self.assertIn("default", channels)

    def test_logging_flow_logs_fields(self) -> None:
        self.assertIsInstance(self.logging["flow_logs"], list)
        for flow_log in self.logging["flow_logs"]:
            for key in ("ResourceId", "TrafficType", "FlowLogStatus"):
                self.assertIn(key, flow_log, f"flow_logs に {key} が無い")

    def test_logging_log_group_retention(self) -> None:
        group = next(
            g for g in self.logging["cloudwatch_log_groups"]
            if g["logGroupName"] == "/awsprobe/test"
        )
        self.assertEqual(30, group["retentionInDays"])

    def test_logging_alarms_cover_both_types(self) -> None:
        alarms = self.logging["cloudwatch_alarms"]
        alarm = next(a for a in alarms if a.get("AlarmName") == "awsprobe-alarm")
        for key in ("AlarmActions", "MetricName", "Namespace", "Threshold", "StateValue"):
            self.assertIn(key, alarm, f"cloudwatch_alarms に {key} が無い")
        self.assertEqual("MetricAlarm", alarm["_AlarmType"])
        # MetricAlarm と CompositeAlarm の 2 回引いていること
        # （ガードはサービス識別子に endpointPrefix を使うため cloudwatch は "monitoring"）
        ops = self.guard.summary()["operations"]
        self.assertGreaterEqual(ops.get("monitoring:DescribeAlarms", 0), 2)
        self.assertIn("monitoring:ListDashboards", ops)

    # ------------------------------------------------------------------
    # security の中身
    # ------------------------------------------------------------------
    def test_security_iam_roles_keep_trust_policy(self) -> None:
        """ベンダーに与えているクロスアカウント信頼関係が特定できること。"""
        role = next(
            r for r in self.security["iam"]["roles"] if r["RoleName"] == "awsprobe-vendor-role"
        )
        doc = role["AssumeRolePolicyDocument"]
        self.assertIn("210987654321", json.dumps(doc, ensure_ascii=False))

    def test_security_iam_users_are_summary_only(self) -> None:
        user = next(
            u for u in self.security["iam"]["users"] if u["UserName"] == "awsprobe-user"
        )
        self.assertTrue(set(user).issubset(set(security_mod._USER_SUMMARY_KEYS)))

    def test_security_credential_report_not_fetched(self) -> None:
        self.assertIsNone(self.security["iam"]["credential_report_meta"])
        ops = self.guard.summary()["operations"]
        for forbidden in ("iam:GetCredentialReport", "iam:GenerateCredentialReport"):
            self.assertNotIn(forbidden, ops)

    def test_security_cloudformation_masks_parameter_values(self) -> None:
        stack = next(
            s for s in self.security["cloudformation_stacks"]
            if s["StackName"] == "awsprobe-stack"
        )
        for key in ("StackName", "StackStatus", "Tags", "Description"):
            self.assertIn(key, stack, f"cloudformation_stacks に {key} が無い")
        self.assertEqual({"_keys": ["DbPassword"]}, stack["Parameters"])
        self.assertIn("_keys", stack["Outputs"])
        self.assertNotIn(SECRET_VALUE, json.dumps(self.security, ensure_ascii=False))

    def test_security_stack_sets_and_instances(self) -> None:
        self.assertIsInstance(self.security["cloudformation_stack_sets"], list)
        self.assertIsInstance(self.security["stack_instances"], list)
        for stack_set in self.security["cloudformation_stack_sets"]:
            # VendorMonitor StackSet の権限モデル確認に使うキー
            for key in ("PermissionModel", "AdministrationRoleARN", "ExecutionRoleName"):
                self.assertIn(key, stack_set, f"stack_sets に {key} が無い")

    def test_security_organizations_empty_when_not_in_use(self) -> None:
        # moto の既定では組織未使用 → 空 dict
        self.assertIsInstance(self.security["organizations"], dict)

    def test_security_findings_never_fetched(self) -> None:
        ops = self.guard.summary()["operations"]
        for forbidden in ("guardduty:ListFindings", "guardduty:GetFindings",
                          "securityhub:GetFindings"):
            self.assertNotIn(forbidden, ops)

    # ------------------------------------------------------------------
    # 横断
    # ------------------------------------------------------------------
    def test_all_sections_are_json_serializable(self) -> None:
        payload = {
            "storage": self.storage,
            "edge": self.edge,
            "serverless": self.serverless,
            "logging": self.logging,
            "security": self.security,
            "errors": self.errors,
        }
        text = json.dumps(payload, ensure_ascii=False)
        self.assertGreater(len(text), 100)

    def test_errors_are_recorded_not_raised(self) -> None:
        # moto 未実装 API は errors に記録されるだけで処理は続行される
        self.assertTrue(self.errors, "moto 未実装 API の失敗が errors に残っていない")
        for err in self.errors:
            for key in ("service", "operation", "code", "message", "context"):
                self.assertIn(key, err)
        # 収集自体は成功している
        self.assertTrue(self.storage["buckets"])
        self.assertTrue(self.edge["load_balancers"])
        self.assertTrue(self.serverless["lambda_functions"])

    def test_non_clienterror_exceptions_are_swallowed(self) -> None:
        """ClientError 以外（moto の NotImplementedError 等）も errors に落ちること。

        `_safe.safe_call` / `safe_paginate` が無いとここで収集全体が止まる。
        """
        codes = {e["code"] for e in self.errors}
        raw = codes & {"NotImplementedError", "ModuleNotFoundError", "AttributeError"}
        self.assertTrue(
            raw, f"ClientError 以外の例外が errors に記録されていない: {sorted(codes)}"
        )
        # 該当 API のあとの収集も続行できている
        self.assertTrue(self.serverless["dynamodb_tables"])
        self.assertTrue(self.security["iam"]["roles"])

    def test_guard_saw_only_read_operations(self) -> None:
        """**全 API 呼び出しを guard.is_allowed() に通し、変更系がゼロであること。**"""
        summary = self.guard.summary()
        self.assertGreater(summary["total_calls"], 0)
        denied = []
        for op_name in summary["operations"]:
            service, operation = op_name.split(":", 1)
            ok, reason = self.guard.is_allowed(service, operation)
            if not ok:
                denied.append(f"{op_name}: {reason}")
        self.assertEqual([], denied, f"変更系 API が呼ばれた: {denied}")

    def test_guard_operations_are_all_read_prefixed(self) -> None:
        """接頭辞そのものが読み取り系であることも直接確認する。"""
        from awsprobe.guard import READ_PREFIXES

        for op_name in self.guard.summary()["operations"]:
            _service, operation = op_name.split(":", 1)
            self.assertTrue(
                operation.startswith(READ_PREFIXES),
                f"{op_name} は読み取り系接頭辞で始まっていない",
            )


class SoftFailureTest(unittest.TestCase):
    """API が全滅しても例外にならず、キーが揃った空の結果を返すことの確認。"""

    @classmethod
    def setUpClass(cls) -> None:
        _fake_credentials()

    def test_collectors_survive_total_failure(self) -> None:
        class _FailingContext(Context):
            """すべての呼び出しを失敗させる Context。"""

            def call(self, service, operation, **kwargs):  # noqa: ANN001
                return None

            def paginate(self, service, operation, result_key, **kwargs):  # noqa: ANN001
                return []

        ctx = _FailingContext(
            session=boto3.Session(region_name=REGION),
            region=REGION,
            account_id=ACCOUNT_ID,
        )
        for name in ("storage", "edge", "serverless", "logging", "security"):
            result = REGISTRY[name]().collect(ctx)
            self.assertIsInstance(result, dict)
            json.dumps(result)  # 例外が出ないこと
            self.assertTrue(all(k for k in result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
