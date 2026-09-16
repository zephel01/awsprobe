"""inventory.json から構成図生成スクリプト用のデータファイルを作る。

既存の構成図生成スクリプト
`dist_next/構成図生成スクリプト` はサブネット名・CIDR・AZ・
EC2名・RDS名・ALB名・NAT・NACL・ENI数などを **手でハードコード** している。
このモジュールは、それらすべてを inventory dict の実データから
機械的に組み立て直せる形（TSV + JSON）で出力する。

厳守事項:
- **AWS API を呼ばない。boto3 を import しない。** 入力は inventory dict のみ。
- inventory のキーが欠けていても KeyError で落ちない（`.get()` を徹底する）。
- 依存は標準ライブラリのみ（openpyxl も使わない）。
"""
from __future__ import annotations

import json
import os
from typing import Any, Sequence

# ---------------------------------------------------------------------------
# inventory アクセスの共通ヘルパー（excel.py と同じ流儀だが独立実装）
# ---------------------------------------------------------------------------


def _sect(inv: dict, name: str) -> dict:
    val = inv.get(name)
    return val if isinstance(val, dict) else {}


def _lst(inv: dict, section: str, key: str) -> list:
    val = _sect(inv, section).get(key)
    return val if isinstance(val, list) else []


def _map(inv: dict, section: str, key: str) -> dict:
    val = _sect(inv, section).get(key)
    return val if isinstance(val, dict) else {}


def _dicts(inv: dict, section: str, key: str) -> list[dict]:
    return [x for x in _lst(inv, section, key) if isinstance(x, dict)]


def _tag(resource: dict, key: str = "Name", default: str = "") -> str:
    for t in (resource or {}).get("Tags") or []:
        if isinstance(t, dict) and t.get("Key") == key:
            return t.get("Value") or default
    return default


def _index_by(items: list[dict], key: str) -> dict[str, dict]:
    return {i.get(key): i for i in items if isinstance(i, dict) and i.get(key)}


#: 環境接頭辞（Example の命名規則 ex-prod- / ex-stg- / ex-demo- / ex-check- 等）
_ENV_ORDER = ("stg3", "stg2", "check", "demo", "prod", "stg")


def _guess_env(*names: Any) -> str:
    """リソース名・IDから環境名を推定する（questions.py の `_guess_env` と同じ規則）。

    複数の候補文字列（Name タグ・リソースID等）を順に試し、最初に当たったものを返す。
    どれにも一致しなければ「その他」。**推定であることは呼び出し側が列名で明示する**。
    """
    for name in names:
        lowered = str(name or "").lower()
        for env in _ENV_ORDER:
            if env in lowered:
                return env
        if "production" in lowered:
            return "prod"
        if "staging" in lowered:
            return "stg"
    return "その他"


def _route_table_for_subnet(subnet_id: str, vpc_id: Any, route_tables: list[dict]) -> dict | None:
    for rt in route_tables:
        for assoc in rt.get("Associations") or []:
            if isinstance(assoc, dict) and assoc.get("SubnetId") == subnet_id:
                return rt
    for rt in route_tables:
        if rt.get("VpcId") != vpc_id:
            continue
        for assoc in rt.get("Associations") or []:
            if isinstance(assoc, dict) and assoc.get("Main"):
                return rt
    return None


def _is_public_route_table(rt: dict | None) -> bool:
    if not rt:
        return False
    for route in rt.get("Routes") or []:
        if isinstance(route, dict) and str(route.get("GatewayId") or "").startswith("igw-"):
            return True
    return False


def _port_label(perm: dict) -> str:
    proto = perm.get("IpProtocol")
    if str(proto) == "-1":
        return "全ポート"
    fp, tp = perm.get("FromPort"), perm.get("ToPort")
    if fp is None and tp is None:
        return "全ポート"
    if fp == tp:
        return str(fp)
    return f"{fp}-{tp}"


# ---------------------------------------------------------------------------
# TSV 出力の共通処理
# ---------------------------------------------------------------------------


def _tsv_cell(value: Any) -> str:
    """TSV の1セルに書ける文字列に整形する（タブ・改行を潰す）。"""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set)):
        value = "; ".join(str(v) for v in value if v is not None and v != "")
    text = str(value)
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def _write_tsv(path: str, headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
    """headers と同じ列数を必ず維持しながら TSV を書く。"""
    ncols = len(headers)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\t".join(headers) + "\n")
        for row in rows:
            cells = [_tsv_cell(v) for v in row]
            if len(cells) < ncols:
                cells += [""] * (ncols - len(cells))
            elif len(cells) > ncols:
                cells = cells[:ncols]
            f.write("\t".join(cells) + "\n")


# ---------------------------------------------------------------------------
# サブネット
# ---------------------------------------------------------------------------

_SUBNET_HEADERS = (
    "サブネット名", "CIDR", "実AZ", "種別(public/private)", "環境(推定)",
    "ルートテーブル", "配置リソース", "ENI数",
)


def _build_subnets(inv: dict) -> list[dict]:
    subnets = _dicts(inv, "network", "subnets")
    route_tables = _dicts(inv, "network", "route_tables")
    instances = _dicts(inv, "compute", "instances")
    db_instances = _dicts(inv, "database", "db_instances")
    mount_targets = _dicts(inv, "storage", "efs_mount_targets")
    load_balancers = _dicts(inv, "edge", "load_balancers")
    enis = _dicts(inv, "network", "network_interfaces")

    eni_count_by_subnet: dict[str, int] = {}
    for e in enis:
        sid = e.get("SubnetId")
        if sid:
            eni_count_by_subnet[sid] = eni_count_by_subnet.get(sid, 0) + 1

    out: list[dict] = []
    for s in subnets:
        subnet_id = s.get("SubnetId")
        name = _tag(s) or subnet_id or ""
        rt = _route_table_for_subnet(subnet_id, s.get("VpcId"), route_tables)
        rt_label = (_tag(rt) or rt.get("RouteTableId")) if rt else ""
        kind = "public" if _is_public_route_table(rt) else "private"

        placed: list[str] = []
        for i in instances:
            if i.get("SubnetId") == subnet_id:
                placed.append(f"EC2:{_tag(i) or i.get('InstanceId')}")
        for db in db_instances:
            for sub in (db.get("DBSubnetGroup") or {}).get("Subnets") or []:
                if isinstance(sub, dict) and sub.get("SubnetIdentifier") == subnet_id:
                    placed.append(f"RDS:{db.get('DBInstanceIdentifier')}")
        for mt in mount_targets:
            if mt.get("SubnetId") == subnet_id:
                placed.append(f"EFS-MT:{mt.get('FileSystemId')}")
        for lb in load_balancers:
            for az in lb.get("AvailabilityZones") or []:
                if isinstance(az, dict) and az.get("SubnetId") == subnet_id:
                    placed.append(f"LB:{lb.get('LoadBalancerName')}")

        out.append(
            {
                "subnet_id": subnet_id,
                "name": name,
                "cidr": s.get("CidrBlock"),
                "az": s.get("AvailabilityZone"),
                "az_id": s.get("AvailabilityZoneId"),
                "kind": kind,
                "env_guess": _guess_env(name, subnet_id),
                "route_table": rt_label,
                "route_table_id": rt.get("RouteTableId") if rt else None,
                "placed_resources": placed,
                "eni_count": eni_count_by_subnet.get(subnet_id, 0),
                "vpc_id": s.get("VpcId"),
                "default_for_az": s.get("DefaultForAz"),
                "available_ip_count": s.get("AvailableIpAddressCount"),
            }
        )
    return out


def _subnets_rows(subnets: list[dict]) -> list[list[Any]]:
    return [
        [
            s["name"], s["cidr"], s["az"], s["kind"], s["env_guess"],
            s["route_table"], s["placed_resources"], s["eni_count"],
        ]
        for s in subnets
    ]


# ---------------------------------------------------------------------------
# EC2 インスタンス
# ---------------------------------------------------------------------------

_INSTANCE_HEADERS = ("インスタンス名", "ID", "タイプ", "AZ", "サブネット", "SG", "環境(推定)")


def _build_instances(inv: dict) -> list[dict]:
    instances = _dicts(inv, "compute", "instances")
    subnets_idx = _index_by(_dicts(inv, "network", "subnets"), "SubnetId")

    out: list[dict] = []
    for i in instances:
        name = _tag(i) or i.get("InstanceId") or ""
        placement = i.get("Placement") or {}
        subnet_id = i.get("SubnetId")
        subnet = subnets_idx.get(subnet_id)
        subnet_name = _tag(subnet) or subnet_id if subnet else subnet_id
        sgs = [
            g.get("GroupName") or g.get("GroupId")
            for g in i.get("SecurityGroups") or []
            if isinstance(g, dict)
        ]
        out.append(
            {
                "name": name,
                "instance_id": i.get("InstanceId"),
                "instance_type": i.get("InstanceType"),
                "az": placement.get("AvailabilityZone"),
                "subnet_id": subnet_id,
                "subnet_name": subnet_name,
                "sgs": sgs,
                "env_guess": _guess_env(name, i.get("InstanceId")),
            }
        )
    return out


def _instances_rows(instances: list[dict]) -> list[list[Any]]:
    return [
        [i["name"], i["instance_id"], i["instance_type"], i["az"], i["subnet_name"], i["sgs"], i["env_guess"]]
        for i in instances
    ]


# ---------------------------------------------------------------------------
# RDS
# ---------------------------------------------------------------------------

_DATABASE_HEADERS = ("識別子", "エンジン", "バージョン", "クラス", "MultiAZ", "AZ", "サブネットグループ", "環境(推定)")


def _build_databases(inv: dict) -> list[dict]:
    db_instances = _dicts(inv, "database", "db_instances")
    out: list[dict] = []
    for db in db_instances:
        identifier = db.get("DBInstanceIdentifier") or ""
        out.append(
            {
                "identifier": identifier,
                "engine": db.get("Engine"),
                "version": db.get("EngineVersion"),
                "class": db.get("DBInstanceClass"),
                "multi_az": db.get("MultiAZ"),
                "az": db.get("AvailabilityZone"),
                "subnet_group": (db.get("DBSubnetGroup") or {}).get("DBSubnetGroupName"),
                "env_guess": _guess_env(identifier),
            }
        )
    return out


def _databases_rows(dbs: list[dict]) -> list[list[Any]]:
    return [
        [d["identifier"], d["engine"], d["version"], d["class"], d["multi_az"], d["az"],
         d["subnet_group"], d["env_guess"]]
        for d in dbs
    ]


# ---------------------------------------------------------------------------
# ロードバランサ
# ---------------------------------------------------------------------------

_LB_HEADERS = ("名前", "種別", "スキーム", "AZ", "サブネット", "ターゲットグループ", "環境(推定)")


def _build_load_balancers(inv: dict) -> list[dict]:
    lbs = _dicts(inv, "edge", "load_balancers")
    target_groups = _dicts(inv, "edge", "target_groups")
    tg_by_lb: dict[str, list[str]] = {}
    for tg in target_groups:
        for arn in tg.get("LoadBalancerArns") or []:
            tg_by_lb.setdefault(arn, []).append(tg.get("TargetGroupName") or "")

    out: list[dict] = []
    for lb in lbs:
        name = lb.get("LoadBalancerName") or ""
        azs = [az.get("ZoneName") for az in lb.get("AvailabilityZones") or [] if isinstance(az, dict)]
        subnets = [az.get("SubnetId") for az in lb.get("AvailabilityZones") or [] if isinstance(az, dict)]
        out.append(
            {
                "name": name,
                "type": lb.get("Type"),
                "scheme": lb.get("Scheme"),
                "az": azs,
                "subnets": subnets,
                "target_groups": tg_by_lb.get(lb.get("LoadBalancerArn"), []),
                "env_guess": _guess_env(name),
                "arn": lb.get("LoadBalancerArn"),
                "vpc_id": lb.get("VpcId"),
            }
        )
    return out


def _load_balancers_rows(lbs: list[dict]) -> list[list[Any]]:
    return [
        [l["name"], l["type"], l["scheme"], l["az"], l["subnets"], l["target_groups"], l["env_guess"]]
        for l in lbs
    ]


# ---------------------------------------------------------------------------
# 接続関係（エッジ）
# ---------------------------------------------------------------------------

_EDGE_HEADERS = ("from", "to", "種別", "ポート", "備考")

#: 主要 DB エンジン → 既定ポート（EC2→RDS のエッジ推定に使う）
_DB_DEFAULT_PORTS = {
    "mysql": 3306, "mariadb": 3306, "postgres": 5432, "aurora-postgresql": 5432,
    "aurora-mysql": 3306, "oracle-se2": 1521, "oracle-ee": 1521, "sqlserver-ex": 1433,
    "sqlserver-web": 1433, "sqlserver-se": 1433, "sqlserver-ee": 1433,
}


def _build_edges(inv: dict) -> list[dict]:
    edges: list[dict] = []

    sgs = _dicts(inv, "network", "security_groups")
    sg_idx = _index_by(sgs, "GroupId")
    sg_label_map = {
        gid: (sg.get("GroupName") or gid) for gid, sg in sg_idx.items()
    }

    # -- (a) SG ルール（SG参照によるインバウンド許可） -----------------------
    for sg in sgs:
        target_label = sg_label_map.get(sg.get("GroupId"), sg.get("GroupId"))
        for perm in sg.get("IpPermissions") or []:
            if not isinstance(perm, dict):
                continue
            port = _port_label(perm)
            for pair in perm.get("UserIdGroupPairs") or []:
                if not isinstance(pair, dict):
                    continue
                source_label = sg_label_map.get(pair.get("GroupId"), pair.get("GroupId"))
                edges.append(
                    {
                        "from": source_label, "to": target_label, "kind": "SG許可",
                        "port": port, "note": pair.get("Description") or "",
                    }
                )

    # -- (b) ルートテーブル（0.0.0.0/0 の向き先） -----------------------------
    for rt in _dicts(inv, "network", "route_tables"):
        rt_label = _tag(rt) or rt.get("RouteTableId")
        for route in rt.get("Routes") or []:
            if not isinstance(route, dict):
                continue
            dest = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
            if dest not in ("0.0.0.0/0", "::/0"):
                continue
            gateway_id = str(route.get("GatewayId") or "")
            if gateway_id.startswith("igw-"):
                edges.append(
                    {"from": rt_label, "to": route.get("GatewayId"), "kind": "ルーティング",
                     "port": "", "note": f"{dest} → IGW"}
                )
            elif route.get("NatGatewayId"):
                edges.append(
                    {"from": rt_label, "to": route.get("NatGatewayId"), "kind": "ルーティング",
                     "port": "", "note": f"{dest} → NAT"}
                )

    # -- (c) ALB → ターゲットグループ → ターゲット ----------------------------
    target_groups = _dicts(inv, "edge", "target_groups")
    lbs = _dicts(inv, "edge", "load_balancers")
    lb_by_arn = _index_by(lbs, "LoadBalancerArn")
    instances = _dicts(inv, "compute", "instances")
    instance_by_id = _index_by(instances, "InstanceId")
    for tg in target_groups:
        tg_name = tg.get("TargetGroupName")
        for lb_arn in tg.get("LoadBalancerArns") or []:
            lb = lb_by_arn.get(lb_arn)
            lb_name = lb.get("LoadBalancerName") if lb else lb_arn
            edges.append(
                {"from": lb_name, "to": tg_name, "kind": "ロードバランシング",
                 "port": str(tg.get("Port") or ""), "note": tg.get("Protocol") or ""}
            )
        for target in tg.get("Targets") or []:
            if not isinstance(target, dict):
                continue
            desc = target.get("Target") or {}
            target_id = desc.get("Id")
            inst = instance_by_id.get(target_id)
            target_label = (_tag(inst) or target_id) if inst else target_id
            if target_label:
                edges.append(
                    {"from": tg_name, "to": target_label, "kind": "ターゲット",
                     "port": str(desc.get("Port") or ""), "note": (target.get("TargetHealth") or {}).get("State") or ""}
                )

    # -- (d) EC2 → RDS（SG ルールから推定） -----------------------------------
    db_instances = _dicts(inv, "database", "db_instances")
    instance_sg_ids: dict[str, set[str]] = {}
    for i in instances:
        name = _tag(i) or i.get("InstanceId")
        instance_sg_ids[name] = {
            g.get("GroupId") for g in i.get("SecurityGroups") or [] if isinstance(g, dict) and g.get("GroupId")
        }
    for db in db_instances:
        identifier = db.get("DBInstanceIdentifier")
        db_sg_ids = {
            g.get("VpcSecurityGroupId") for g in db.get("VpcSecurityGroups") or []
            if isinstance(g, dict) and g.get("VpcSecurityGroupId")
        }
        if not db_sg_ids:
            continue
        port = _DB_DEFAULT_PORTS.get(str(db.get("Engine") or "").lower())
        # 対象 SG に、EC2 の SG からの参照許可があるかを確認する
        allowed_source_sgs: set[str] = set()
        for sg_id in db_sg_ids:
            sg = sg_idx.get(sg_id)
            if not sg:
                continue
            for perm in sg.get("IpPermissions") or []:
                if not isinstance(perm, dict):
                    continue
                if port is not None and not _perm_covers_port(perm, port):
                    continue
                for pair in perm.get("UserIdGroupPairs") or []:
                    if isinstance(pair, dict) and pair.get("GroupId"):
                        allowed_source_sgs.add(pair["GroupId"])
        if not allowed_source_sgs:
            continue
        for inst_name, sg_ids in instance_sg_ids.items():
            if sg_ids & allowed_source_sgs:
                edges.append(
                    {
                        "from": inst_name, "to": identifier, "kind": "DB接続(推定)",
                        "port": str(port) if port else "", "note": "SGルールから推定",
                    }
                )

    return edges


def _perm_covers_port(perm: dict, port: int) -> bool:
    proto = str(perm.get("IpProtocol", "")).lower()
    if proto == "-1":
        return True
    if proto not in ("tcp", "6"):
        return False
    fp, tp = perm.get("FromPort"), perm.get("ToPort")
    if fp is None or tp is None:
        return True
    try:
        return int(fp) <= port <= int(tp)
    except (TypeError, ValueError):
        return False


def _edges_rows(edges: list[dict]) -> list[list[Any]]:
    return [[e["from"], e["to"], e["kind"], e["port"], e["note"]] for e in edges]


# ---------------------------------------------------------------------------
# リージョンサービス
# ---------------------------------------------------------------------------

_REGIONAL_HEADERS = ("サービス種別", "名前", "詳細", "環境(推定)")


def _build_regional(inv: dict) -> list[dict]:
    out: list[dict] = []

    for b in _dicts(inv, "storage", "buckets"):
        name = b.get("Name") or ""
        out.append(
            {
                "kind": "S3", "name": name,
                "detail": f"region={b.get('Region')}",
                "env_guess": _guess_env(name),
            }
        )

    for d in _dicts(inv, "edge", "cloudfront_distributions"):
        out.append(
            {
                "kind": "CloudFront", "name": d.get("Id") or "",
                "detail": d.get("DomainName") or "",
                "env_guess": "共通",
            }
        )

    for fn in _dicts(inv, "serverless", "lambda_functions"):
        name = fn.get("FunctionName") or ""
        out.append(
            {
                "kind": "Lambda", "name": name,
                "detail": fn.get("Runtime") or "",
                "env_guess": _guess_env(name),
            }
        )

    for t in _dicts(inv, "serverless", "sns_topics"):
        arn = t.get("TopicArn") or ""
        name = arn.rsplit(":", 1)[-1] if arn else ""
        out.append({"kind": "SNS", "name": name, "detail": arn, "env_guess": _guess_env(name)})

    for q in _dicts(inv, "serverless", "sqs_queues"):
        url = q.get("QueueUrl") or ""
        name = url.rstrip("/").rsplit("/", 1)[-1] if url else ""
        out.append({"kind": "SQS", "name": name, "detail": url, "env_guess": _guess_env(name)})

    for t in _dicts(inv, "serverless", "dynamodb_tables"):
        name = t.get("TableName") or ""
        out.append(
            {"kind": "DynamoDB", "name": name, "detail": t.get("TableStatus") or "", "env_guess": _guess_env(name)}
        )

    for p in _dicts(inv, "serverless", "cognito_user_pools"):
        out.append(
            {"kind": "Cognito", "name": p.get("Name") or p.get("Id") or "",
             "detail": p.get("MfaConfiguration") or "", "env_guess": _guess_env(p.get("Name"))}
        )

    for b in _dicts(inv, "serverless", "eventbridge_buses"):
        out.append({"kind": "EventBridge", "name": b.get("Name") or "", "detail": "", "env_guess": "共通"})

    for a in _dicts(inv, "edge", "global_accelerators"):
        out.append(
            {"kind": "GlobalAccelerator", "name": a.get("Name") or "", "detail": a.get("DnsName") or "",
             "env_guess": "共通"}
        )

    for m in _dicts(inv, "serverless", "stepfunctions_state_machines"):
        out.append(
            {"kind": "StepFunctions", "name": m.get("name") or "", "detail": m.get("status") or "",
             "env_guess": _guess_env(m.get("name"))}
        )

    # SES はコレクタが収集していない（инventory に該当セクションが無い）ため出力しない。
    # 構成図側で SES の存在を示す場合は、別途手動で追記する必要がある。

    return out


def _regional_rows(items: list[dict]) -> list[list[Any]]:
    return [[i["kind"], i["name"], i["detail"], i["env_guess"]] for i in items]


# ---------------------------------------------------------------------------
# エントリポイント
# ---------------------------------------------------------------------------


def build_diagram_data(inventory: dict, out_dir: str) -> list[str]:
    """inventory dict から構成図生成用のデータファイル一式を `out_dir` に書き出す。

    Returns:
        書き出したファイルパスの一覧（TSV 6本 + diagram_data.json）。
    """
    inv = inventory if isinstance(inventory, dict) else {}
    os.makedirs(out_dir, exist_ok=True)

    subnets = _build_subnets(inv)
    instances = _build_instances(inv)
    databases = _build_databases(inv)
    load_balancers = _build_load_balancers(inv)
    edges = _build_edges(inv)
    regional = _build_regional(inv)

    written: list[str] = []

    path = os.path.join(out_dir, "diagram_subnets.tsv")
    _write_tsv(path, _SUBNET_HEADERS, _subnets_rows(subnets))
    written.append(path)

    path = os.path.join(out_dir, "diagram_instances.tsv")
    _write_tsv(path, _INSTANCE_HEADERS, _instances_rows(instances))
    written.append(path)

    path = os.path.join(out_dir, "diagram_databases.tsv")
    _write_tsv(path, _DATABASE_HEADERS, _databases_rows(databases))
    written.append(path)

    path = os.path.join(out_dir, "diagram_loadbalancers.tsv")
    _write_tsv(path, _LB_HEADERS, _load_balancers_rows(load_balancers))
    written.append(path)

    path = os.path.join(out_dir, "diagram_edges.tsv")
    _write_tsv(path, _EDGE_HEADERS, _edges_rows(edges))
    written.append(path)

    path = os.path.join(out_dir, "diagram_regional.tsv")
    _write_tsv(path, _REGIONAL_HEADERS, _regional_rows(regional))
    written.append(path)

    data = {
        "generated_from": "awsprobe.diagram.build_diagram_data",
        "note": (
            "dist_next/構成図生成スクリプト がハードコードしている"
            "サブネット名・CIDR・AZ・EC2名・RDS名・ALB名・NAT・NACL・ENI数等を"
            "inventory の実データから機械的に再構成したもの。"
        ),
        "meta": _sect(inv, "meta"),
        "subnets": subnets,
        "instances": instances,
        "databases": databases,
        "load_balancers": load_balancers,
        "edges": edges,
        "regional_services": regional,
    }
    path = os.path.join(out_dir, "diagram_data.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    written.append(path)

    return written
