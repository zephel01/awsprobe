"""network / compute / database コレクタの検証（moto によるモック AWS）。

確認すること:
1. 3 コレクタが REGISTRY に登録されていること
2. INVENTORY_SCHEMA.md のキーがすべて埋まること（欠けキーが無いこと）
3. 「未確認事項の解消」に直結する項目が実際に値を持つこと
   （サブネットの DefaultForAz、ルートテーブルの Routes/Associations、
     ENI の Description、SG の IpPermissions、インスタンスの _reservation_id など）
4. moto が未実装の API（SSM 等）は errors に記録されるだけで落ちないこと
5. 戻り値が json.dumps 可能であること（datetime が ISO 文字列になっていること）
6. 読み取り専用ガードを付けたセッションでも例外が出ないこと
   （= 変更系 API を 1 つも呼んでいないこと）

実行:
    python3 -m pytest tests/test_collectors_1.py -v
"""
from __future__ import annotations

import json
import os
import sys
import unittest

import boto3
from moto import mock_aws

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from awsprobe.collectors.base import REGISTRY  # noqa: E402
from awsprobe.collectors import compute as compute_mod  # noqa: E402,F401
from awsprobe.collectors import database as database_mod  # noqa: E402,F401
from awsprobe.collectors import network as network_mod  # noqa: E402,F401
from awsprobe.guard import ReadOnlyGuard  # noqa: E402
from awsprobe.session import Context  # noqa: E402

REGION = "ap-northeast-1"


def _fake_credentials() -> None:
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
    os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)


class CollectorMotoTest(unittest.TestCase):
    """moto 上に最小構成の環境を作り、3 コレクタを回す。"""

    @classmethod
    def setUpClass(cls) -> None:
        _fake_credentials()
        cls._mock = mock_aws()
        cls._mock.start()

        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        rds = session.client("rds", region_name=REGION)

        # --- ネットワーク（セットアップのみ変更系 API を使う。ガードは付けない）---
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        cls.vpc_id = vpc["VpcId"]
        azs = ec2.describe_availability_zones()["AvailabilityZones"]
        subnet = ec2.create_subnet(
            VpcId=cls.vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone=azs[0]["ZoneName"],
        )["Subnet"]
        cls.subnet_id = subnet["SubnetId"]

        igw = ec2.create_internet_gateway()["InternetGateway"]
        ec2.attach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=cls.vpc_id)
        rt = ec2.create_route_table(VpcId=cls.vpc_id)["RouteTable"]
        ec2.create_route(
            RouteTableId=rt["RouteTableId"],
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw["InternetGatewayId"],
        )
        ec2.associate_route_table(RouteTableId=rt["RouteTableId"], SubnetId=cls.subnet_id)

        sg = ec2.create_security_group(
            GroupName="awsprobe-test-sg", Description="awsprobe test", VpcId=cls.vpc_id
        )
        cls.sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=cls.sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "https"}],
                }
            ],
        )

        eni = ec2.create_network_interface(
            SubnetId=cls.subnet_id, Description="awsprobe test ENI", Groups=[cls.sg_id]
        )["NetworkInterface"]
        cls.eni_id = eni["NetworkInterfaceId"]

        # --- EC2 インスタンス ---
        images = ec2.describe_images()["Images"]
        cls.image_id = images[0]["ImageId"]
        run = ec2.run_instances(
            ImageId=cls.image_id,
            MinCount=1,
            MaxCount=1,
            InstanceType="t3.micro",
            SubnetId=cls.subnet_id,
            SecurityGroupIds=[cls.sg_id],
            TagSpecifications=[
                {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "awsprobe-test"}]}
            ],
        )
        cls.instance_id = run["Instances"][0]["InstanceId"]
        cls.reservation_id = run["ReservationId"]

        # --- RDS インスタンス ---
        rds.create_db_subnet_group(
            DBSubnetGroupName="awsprobe-subnets",
            DBSubnetGroupDescription="awsprobe test",
            SubnetIds=[
                cls.subnet_id,
                ec2.create_subnet(
                    VpcId=cls.vpc_id,
                    CidrBlock="10.0.2.0/24",
                    AvailabilityZone=azs[1]["ZoneName"],
                )["Subnet"]["SubnetId"],
            ],
        )
        rds.create_db_parameter_group(
            DBParameterGroupName="awsprobe-pg",
            DBParameterGroupFamily="mysql8.0",
            Description="awsprobe test",
        )
        rds.create_db_instance(
            DBInstanceIdentifier="awsprobe-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            EngineVersion="8.0.35",
            MasterUsername="admin",
            MasterUserPassword="Password123!",  # moto 内のダミー。実 AWS には送られない
            AllocatedStorage=20,
            DBSubnetGroupName="awsprobe-subnets",
            DBParameterGroupName="awsprobe-pg",
            VpcSecurityGroupIds=[cls.sg_id],
            BackupRetentionPeriod=7,
            StorageEncrypted=True,
            MultiAZ=False,
            # moto は明示指定しないと PubliclyAccessible を返さないため明示する
            # （実 AWS は常に返す）
            PubliclyAccessible=False,
        )

        # --- コレクタ実行用の Context（読み取り専用ガード付き）---
        probe_session = boto3.Session(region_name=REGION)
        cls.guard = ReadOnlyGuard()
        cls.guard.attach(probe_session)
        cls.ctx = Context(
            session=probe_session,
            region=REGION,
            account_id="123456789012",
            guard=cls.guard,
        )

        cls.network = REGISTRY["network"]().collect(cls.ctx)
        cls.compute = REGISTRY["compute"]().collect(cls.ctx)
        cls.database = REGISTRY["database"]().collect(cls.ctx)
        cls.errors = cls.ctx.error_dicts()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._mock.stop()

    # -- 登録 ------------------------------------------------------------
    def test_registry(self) -> None:
        for name in ("network", "compute", "database"):
            self.assertIn(name, REGISTRY)
            self.assertTrue(REGISTRY[name].iam_actions, f"{name} に iam_actions が無い")

    # -- スキーマのキー --------------------------------------------------
    def test_network_schema_keys(self) -> None:
        expected = {
            "vpcs", "subnets", "route_tables", "network_acls", "internet_gateways",
            "nat_gateways", "egress_only_internet_gateways", "network_interfaces",
            "security_groups", "vpc_peering_connections", "vpc_endpoints",
            "transit_gateway_vpc_attachments", "elastic_ips", "prefix_lists",
            "availability_zones",
        }
        self.assertEqual(expected, set(self.network))

    def test_compute_schema_keys(self) -> None:
        expected = {
            "instances", "instance_statuses", "images", "volumes", "snapshots",
            "auto_scaling_groups", "launch_templates", "key_pairs",
            "ssm_managed_instances", "ssm_inventory", "ssm_patch_states",
            # セキュリティ実施状況（posture.py）の判定に使う追加項目
            "ebs_encryption_by_default", "ebs_default_kms_key_id",
            "instance_credit_specifications", "instance_connect_endpoints",
        }
        self.assertEqual(expected, set(self.compute))

    def test_database_schema_keys(self) -> None:
        expected = {
            "db_instances", "db_clusters", "db_parameter_groups", "db_parameters",
            "db_subnet_groups", "db_snapshots", "db_engine_versions",
            "event_subscriptions",
        }
        self.assertEqual(expected, set(self.database))
        self.assertIsInstance(self.database["db_parameters"], dict)

    # -- network の中身 ---------------------------------------------------
    def test_network_vpc_and_subnet_fields(self) -> None:
        vpc_ids = {v["VpcId"] for v in self.network["vpcs"]}
        self.assertIn(self.vpc_id, vpc_ids)
        for vpc in self.network["vpcs"]:
            self.assertIn("IsDefault", vpc)
            self.assertIn("CidrBlockAssociationSet", vpc)

        subnet = next(s for s in self.network["subnets"] if s["SubnetId"] == self.subnet_id)
        # デフォルト VPC 由来サブネットの判別と CIDR 重複の確定に使うキー
        for key in (
            "AvailabilityZone", "AvailabilityZoneId", "CidrBlock",
            "AvailableIpAddressCount", "DefaultForAz", "MapPublicIpOnLaunch",
        ):
            self.assertIn(key, subnet, f"subnets に {key} が無い")

    def test_network_route_tables_have_routes_and_associations(self) -> None:
        tables = [t for t in self.network["route_tables"] if t["VpcId"] == self.vpc_id]
        self.assertTrue(tables)
        for table in tables:
            self.assertIn("Routes", table)
            self.assertIn("Associations", table)
        # メインルートテーブルが Main フラグで識別できること
        mains = [
            t for t in tables
            if any(a.get("Main") for a in t.get("Associations") or [])
        ]
        self.assertTrue(mains, "Main フラグ付きの Associations が見つからない")
        # 0.0.0.0/0 の経路が取れること
        default_routes = [
            r for t in tables for r in t.get("Routes") or []
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
        ]
        self.assertTrue(default_routes)

    def test_network_acls_have_entries_and_associations(self) -> None:
        acls = [a for a in self.network["network_acls"] if a["VpcId"] == self.vpc_id]
        self.assertTrue(acls)
        for acl in acls:
            self.assertIn("Entries", acl)
            self.assertIn("Associations", acl)

    def test_network_security_group_rules_are_raw(self) -> None:
        sg = next(g for g in self.network["security_groups"] if g["GroupId"] == self.sg_id)
        self.assertIn("IpPermissions", sg)
        self.assertIn("IpPermissionsEgress", sg)
        ingress = sg["IpPermissions"][0]
        self.assertIn("IpRanges", ingress)
        self.assertIn("UserIdGroupPairs", ingress)
        self.assertEqual("0.0.0.0/0", ingress["IpRanges"][0]["CidrIp"])

    def test_network_interfaces_keep_identifying_fields(self) -> None:
        eni = next(
            e for e in self.network["network_interfaces"]
            if e["NetworkInterfaceId"] == self.eni_id
        )
        # 用途不明 ENI の正体特定に使う（Global Accelerator 等は Description で判別）
        self.assertEqual("awsprobe test ENI", eni.get("Description"))
        self.assertIn("InterfaceType", eni)
        self.assertIn("Groups", eni)

    def test_network_nat_gateways_exclude_deleted(self) -> None:
        for ngw in self.network["nat_gateways"]:
            self.assertNotEqual("deleted", (ngw.get("State") or "").lower())

    def test_network_availability_zone_mapping(self) -> None:
        azs = self.network["availability_zones"]
        self.assertTrue(azs)
        for az in azs:
            self.assertIn("ZoneName", az)
            self.assertIn("ZoneId", az)

    # -- compute の中身 ---------------------------------------------------
    def test_compute_instances_flattened_with_reservation_id(self) -> None:
        instances = self.compute["instances"]
        self.assertTrue(instances)
        self.assertTrue(all(isinstance(i, dict) and "InstanceId" in i for i in instances))
        inst = next(i for i in instances if i["InstanceId"] == self.instance_id)
        self.assertEqual(self.reservation_id, inst["_reservation_id"])
        for key in (
            "ImageId", "InstanceType", "Placement", "SubnetId", "VpcId",
            "SecurityGroups", "BlockDeviceMappings", "Monitoring", "State",
            "LaunchTime", "Tags",
        ):
            self.assertIn(key, inst, f"instances に {key} が無い")
        # LaunchTime は ISO 文字列に正規化されている
        self.assertIsInstance(inst["LaunchTime"], str)

    def test_compute_instance_statuses_include_all(self) -> None:
        # IncludeAllInstances=True なので、稼働中インスタンスの状態が返る
        ids = {s.get("InstanceId") for s in self.compute["instance_statuses"]}
        self.assertIn(self.instance_id, ids)

    def test_compute_images_cover_instance_image(self) -> None:
        image_ids = {i["ImageId"] for i in self.compute["images"]}
        self.assertIn(self.image_id, image_ids)
        image = next(i for i in self.compute["images"] if i["ImageId"] == self.image_id)
        self.assertIn("CreationDate", image)
        self.assertIn("Name", image)

    def test_compute_volumes_and_keypairs_present(self) -> None:
        self.assertIsInstance(self.compute["volumes"], list)
        self.assertTrue(self.compute["volumes"], "インスタンスのルート EBS が取れていない")
        self.assertIsInstance(self.compute["key_pairs"], list)

    def test_compute_ssm_never_raises(self) -> None:
        # moto の SSM は DescribeInstanceInformation を実装していない。
        # 取れなくても例外にならず、list のまま返ること（errors 側に残る）。
        for key in ("ssm_managed_instances", "ssm_inventory", "ssm_patch_states"):
            self.assertIsInstance(self.compute[key], list)
        # SSM が引けたことになっている（= 呼び出しは実際に行われた）
        ops = self.guard.summary()["operations"]
        self.assertIn("ssm:DescribeInstanceInformation", ops)
        # 空なら必ず理由が errors に残っていること（黙って空にしない）
        if not self.compute["ssm_managed_instances"]:
            ssm_errors = [
                e for e in self.errors
                if e["service"] == "ssm" and e["operation"] == "describe_instance_information"
            ]
            self.assertTrue(ssm_errors, "SSM が空なのに errors に理由が無い")

    # -- database の中身 --------------------------------------------------
    def test_database_instance_fields(self) -> None:
        dbs = self.database["db_instances"]
        self.assertTrue(dbs)
        db = next(d for d in dbs if d["DBInstanceIdentifier"] == "awsprobe-db")
        for key in (
            "Engine", "EngineVersion", "MultiAZ", "BackupRetentionPeriod",
            "PreferredBackupWindow", "AutoMinorVersionUpgrade", "StorageEncrypted",
            "VpcSecurityGroups", "DBSubnetGroup", "DBParameterGroups",
            "DBInstanceClass", "AvailabilityZone", "PubliclyAccessible",
            "DeletionProtection", "KmsKeyId", "EnabledCloudwatchLogsExports",
        ):
            self.assertIn(key, db, f"db_instances に {key} が無い")
        self.assertEqual("mysql", db["Engine"])
        self.assertEqual(7, db["BackupRetentionPeriod"])
        # NOTE: SecondaryAvailabilityZone は moto が MultiAZ=True でも返さないため
        # ここでは検証できない。コレクタはレスポンスを加工しないので、
        # 実 AWS では自動的に含まれる。

    def test_database_parameters_only_for_used_groups(self) -> None:
        params = self.database["db_parameters"]
        self.assertIn("awsprobe-pg", params, "使用中パラメータグループが引かれていない")
        self.assertIsInstance(params["awsprobe-pg"], list)
        # 使っていないグループ（default.* 等）は引かない
        used = {
            g["DBParameterGroupName"]
            for d in self.database["db_instances"]
            for g in d.get("DBParameterGroups") or []
        }
        self.assertTrue(set(params).issubset(used))

    def test_database_engine_versions_are_narrowed(self) -> None:
        pairs = {
            (d["Engine"], d["EngineVersion"]) for d in self.database["db_instances"]
        }
        self.assertTrue(pairs)
        # 使用中の (Engine, EngineVersion) の数だけ呼ばれていること。
        # 絞らずに引くと 1 回で全バージョンが返り、出力が巨大になる。
        ops = self.guard.summary()["operations"]
        self.assertEqual(len(pairs), ops.get("rds:DescribeDBEngineVersions"))
        # moto は本 API 未実装のため中身は空になる（errors に記録される）。
        # 実 AWS で返る場合は使用中の組み合わせに限られること。
        for ver in self.database["db_engine_versions"]:
            self.assertIn((ver["Engine"], ver["EngineVersion"]), pairs)

    def test_database_snapshots_cover_both_types(self) -> None:
        self.assertIsInstance(self.database["db_snapshots"], list)
        types = {s.get("SnapshotType") for s in self.database["db_snapshots"]}
        self.assertTrue(types.issubset({"manual", "automated", None}))
        # manual と automated の 2 回引いていること
        ops = self.guard.summary()["operations"]
        self.assertEqual(2, ops.get("rds:DescribeDBSnapshots"))

    # -- 横断 --------------------------------------------------------------
    def test_all_sections_are_json_serializable(self) -> None:
        payload = {
            "network": self.network,
            "compute": self.compute,
            "database": self.database,
            "errors": self.errors,
        }
        text = json.dumps(payload, ensure_ascii=False)
        self.assertGreater(len(text), 100)

    def test_errors_are_recorded_not_raised(self) -> None:
        # 未実装／権限不足の API は errors に記録されるだけで処理は続行される
        self.assertTrue(self.errors, "moto 未実装 API の失敗が errors に残っていない")
        for err in self.errors:
            for key in ("service", "operation", "code", "message", "context"):
                self.assertIn(key, err)
        # moto が実装していない API（SSM 等）が errors 側にあること
        failed = {(e["service"], e["operation"]) for e in self.errors}
        self.assertIn(("ssm", "describe_instance_information"), failed)
        # network / compute の主要データは errors があっても埋まっている
        self.assertTrue(self.network["vpcs"])
        self.assertTrue(self.compute["instances"])

    def test_guard_saw_only_read_operations(self) -> None:
        summary = self.guard.summary()
        self.assertGreater(summary["total_calls"], 0)
        for op_name in summary["operations"]:
            _service, operation = op_name.split(":", 1)
            ok, reason = self.guard.is_allowed(_service, operation)
            self.assertTrue(ok, f"{op_name} が読み取り専用ガードに拒否された: {reason}")


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
            account_id="123456789012",
        )
        for name in ("network", "compute", "database"):
            result = REGISTRY[name]().collect(ctx)
            self.assertIsInstance(result, dict)
            json.dumps(result)  # 例外が出ないこと
            # 値が空でもキーは必ず存在する（判定ロジックが no_data を返せるように）
            self.assertTrue(all(k for k in result))


if __name__ == "__main__":
    unittest.main(verbosity=2)
