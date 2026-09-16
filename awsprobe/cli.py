"""awsprobe のコマンドラインインターフェース。

サブコマンド:
    doctor        認証・権限・到達性の事前診断
    collect       全コレクタを実行して inventory.json を出力
    answer        未確認事項 Q1〜Q42 を判定して Markdown を出力
    posture       セキュリティ設定の実施状況を評価して Markdown を出力
    host-probe    SSM 経由で EC2 内部を調査（既定は無効。--enable-ssm が必要）
    excel         棚卸し Excel を出力
    diagram-data  構成図生成用のデータを出力
    iam-policy    必要な最小権限ポリシーを出力
    all           collect → answer → posture → excel → diagram-data

読み取り専用であることは guard.ReadOnlyGuard が機構として担保している。
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import os
import sys
import traceback

from . import __version__
from .guard import ReadOnlyViolation, mask_secret_values, redact as redact_obj
from .session import (
    DEFAULT_MAX_BUCKETS, DEFAULT_REGION, CollectError, Context,
    CredentialsUnavailable, build_context,
)

LOG = logging.getLogger("awsprobe")

DEFAULT_OUT = "out"
INVENTORY_NAME = "inventory.json"
ANSWER_NAME = "未確認事項_突合レポート.md"
POSTURE_NAME = "セキュリティ設定_実施状況.md"
EXCEL_NAME = "AWS実査_棚卸し.xlsx"


# --------------------------------------------------------------------------
# 共通ユーティリティ
# --------------------------------------------------------------------------

def _now() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _ensure_out(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _write_text(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def _load_inventory(args) -> dict:
    """--inventory / --from-fixture / 既定パス の順で inventory を読む。"""
    path = getattr(args, "inventory", None) or getattr(args, "from_fixture", None)
    if not path:
        path = os.path.join(args.out, INVENTORY_NAME)
    if not os.path.exists(path):
        raise SystemExit(
            f"inventory が見つかりません: {path}\n"
            f"先に `awsprobe collect` を実行するか、--inventory でパスを指定してください。"
        )
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _is_dry_run_inventory(inv: dict) -> bool:
    """`collect --dry-run` が作った inventory かどうか。"""
    meta = inv.get("meta") if isinstance(inv.get("meta"), dict) else {}
    return bool(meta.get("dry_run"))


def _reject_dry_run(inv: dict, command: str) -> int:
    """dry-run 由来の inventory なら理由を示して 2 を返す（C-2）。

    dry-run では全 API がガードに握られるため、`errors` が空のまま
    「何も無かった」形の inventory が出来上がる。これを判定に通すと
    「CloudTrail の証跡が1本も無い」等の**確定的な誤判定**になる。
    """
    if not _is_dry_run_inventory(inv):
        return 0
    print(
        f"\n【中断】--dry-run で作られた inventory では判定できません（{command}）。\n"
        "  この inventory は AWS へ1度も接続せずに作られた空の器です。\n"
        "  そのまま判定すると『設定されていない』と『確認していない』が\n"
        "  区別できず、事実と異なる是正指摘が出ます。\n"
        "  `--dry-run` を外して `awsprobe collect` を実行し直してください。",
        file=sys.stderr,
    )
    return 2


def _redact_for_output(inv: dict, args) -> tuple[dict, bool]:
    """出力生成の直前にマスクを掛ける（I-5）。

    `--no-redact` で収集した inventory や `--import-dir` で取り込んだ
    inventory は生値のままなので、**既定では必ずここでマスクする**。
    `--no-redact-output` を付けたときだけ生値のまま出す。

    Returns:
        (出力に使う inventory, マスク済みかどうか)
    """
    meta = inv.get("meta") if isinstance(inv.get("meta"), dict) else {}
    already = bool(meta.get("redacted", True))
    if getattr(args, "no_redact_output", False):
        if not already:
            print("  ※ --no-redact-output のため、出力に生値（アカウントID・"
                  "グローバルIP）が含まれます。取扱い注意。", file=sys.stderr)
        return inv, already
    if already:
        return inv, True
    account_ids = {str(meta.get("account_id") or "")}
    masked = redact_obj(mask_secret_values(inv), account_ids)
    masked.setdefault("meta", {})["redacted"] = True
    LOG.info("inventory が生値だったため、出力生成の直前にマスクを適用しました。")
    return masked, True


def _load_for_output(args, command: str) -> tuple[dict | None, bool, int]:
    """answer / posture / excel / diagram-data 共通の入力準備。

    Returns:
        (inventory, マスク済みか, 終了コード)。終了コードが 0 以外なら
        inventory は None で、呼び出し側はそのまま return すること。
    """
    inv = _load_inventory(args)
    rc = _reject_dry_run(inv, command)
    if rc:
        return None, True, rc
    inv, redacted = _redact_for_output(inv, args)
    return inv, redacted, 0


def _context(args, *, allow_ssm_command: bool = False) -> Context:
    return build_context(
        profile=args.profile,
        region=args.region,
        assume_role_arn=args.assume_role_arn,
        external_id=args.external_id,
        account_alias=args.account_alias,
        allow_ssm_command=allow_ssm_command,
        dry_run=getattr(args, "dry_run", False),
        max_buckets=getattr(args, "max_buckets", DEFAULT_MAX_BUCKETS),
    )


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

#: 事前診断で叩くサービスと、その代表的な読み取り API
DOCTOR_PROBES: tuple[tuple[str, str, str, dict], ...] = (
    ("ec2", "describe_vpcs", "VPC・サブネット・SG", {"MaxResults": 5}),
    ("ec2", "describe_instances", "EC2 インスタンス", {"MaxResults": 5}),
    ("rds", "describe_db_instances", "RDS", {"MaxRecords": 20}),
    ("s3", "list_buckets", "S3", {}),
    ("elasticfilesystem", "describe_file_systems", "EFS", {"MaxItems": 5}),
    ("elbv2", "describe_load_balancers", "ロードバランサ", {"PageSize": 5}),
    ("acm", "list_certificates", "ACM 証明書", {"MaxItems": 5}),
    ("wafv2", "list_web_acls", "WAFv2（REGIONAL）", {"Scope": "REGIONAL", "Limit": 5}),
    ("lambda", "list_functions", "Lambda", {"MaxItems": 5}),
    ("events", "list_rules", "EventBridge", {"Limit": 5}),
    ("cloudtrail", "describe_trails", "CloudTrail", {}),
    ("config", "describe_configuration_recorders", "AWS Config", {}),
    ("logs", "describe_log_groups", "CloudWatch Logs", {"limit": 5}),
    ("cloudwatch", "describe_alarms", "CloudWatch アラーム", {"MaxRecords": 5}),
    ("guardduty", "list_detectors", "GuardDuty", {"MaxResults": 5}),
    ("securityhub", "describe_hub", "Security Hub", {}),
    ("inspector2", "batch_get_account_status", "Inspector", {}),
    ("iam", "get_account_summary", "IAM", {}),
    ("kms", "list_keys", "KMS", {"Limit": 5}),
    ("secretsmanager", "list_secrets", "Secrets Manager", {"MaxResults": 5}),
    ("organizations", "describe_organization", "Organizations", {}),
    ("cloudformation", "list_stack_sets", "CloudFormation StackSet", {"MaxResults": 5}),
    ("ssm", "describe_instance_information", "SSM（EC2 内部調査の可否）", {"MaxResults": 5}),
    ("backup", "list_backup_plans", "AWS Backup", {"MaxResults": 5}),
    ("route53", "list_hosted_zones", "Route 53", {"MaxItems": "5"}),
    ("cloudfront", "list_distributions", "CloudFront", {"MaxItems": "5"}),
    ("globalaccelerator", "list_accelerators", "Global Accelerator", {"MaxResults": 5}),
)

#: グローバルサービスのリージョン固定
DOCTOR_REGION_OVERRIDE = {
    "cloudfront": "us-east-1",
    "globalaccelerator": "us-west-2",
    "route53": "us-east-1",
}


def cmd_doctor(args) -> int:
    ctx = _context(args)
    print("=" * 72)
    print("awsprobe doctor — 認証・権限・到達性の事前診断")
    print("=" * 72)
    print(f"リージョン      : {ctx.region}")
    print(f"プロファイル    : {args.profile or '(既定)'}")
    print(f"AssumeRole      : {args.assume_role_arn or '(なし)'}")
    if not ctx.caller_arn:
        print()
        print("【NG】呼び出し元を特定できませんでした。認証情報が無効か期限切れです。")
        print("      SSO なら `aws sso login --profile <プロファイル名>` を実行してください。")
        return 2
    print(f"呼び出し元      : {ctx.caller_arn}")
    print(f"アカウント      : {ctx.account_id}")
    print()

    ok, ng, unknown = [], [], []
    for service, operation, label, kwargs in DOCTOR_PROBES:
        region = DOCTOR_REGION_OVERRIDE.get(service)
        before = len(ctx.errors)
        try:
            ctx.call(service, operation, region=region, context="doctor", **kwargs)
        except ReadOnlyViolation as exc:
            ng.append((label, f"{service}:{operation}", f"ガード違反: {exc}"))
            continue
        except Exception as exc:  # noqa: BLE001  botocore が知らないサービス等
            unknown.append((label, f"{service}:{operation}", type(exc).__name__))
            continue
        if len(ctx.errors) > before:
            err = ctx.errors[-1]
            if err.code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                            "AuthorizationError", "AuthFailure", "Forbidden"}:
                ng.append((label, f"{service}:{operation}", f"権限不足 ({err.code})"))
            else:
                unknown.append((label, f"{service}:{operation}", err.code))
        else:
            ok.append((label, f"{service}:{operation}"))

    print(f"■ 呼べた            : {len(ok)} 件")
    for label, api in ok:
        print(f"    OK   {label:<28} {api}")
    if ng:
        print()
        print(f"■ 権限不足          : {len(ng)} 件  ← この範囲は調査できません")
        for label, api, reason in ng:
            print(f"    NG   {label:<28} {api}  {reason}")
    if unknown:
        print()
        print(f"■ 未導入・該当なし  : {len(unknown)} 件  （サービス未使用なら正常）")
        for label, api, reason in unknown:
            print(f"    --   {label:<28} {api}  {reason}")

    print()
    if ng:
        print("【判定】一部の範囲が調査できません。")
        print("        `docs/iam-policy-readonly.json` のポリシー、または AWS 管理ポリシー")
        print("        `ReadOnlyAccess` を実行者に付与してから再実行してください。")
    else:
        print("【判定】必要な読み取り権限は揃っています。`awsprobe collect` に進めます。")

    guard = ctx.guard.summary() if ctx.guard else {}
    print()
    print(f"発行した API 呼び出し: {guard.get('total_calls', 0)} 回 "
          f"（すべて読み取り系。変更系はガードが拒否します）")
    return 1 if ng else 0


# --------------------------------------------------------------------------
# collect
# --------------------------------------------------------------------------

def cmd_collect(args) -> int:
    from .collectors import DEFAULT_ORDER, REGISTRY

    ctx = _context(args)
    if not ctx.caller_arn and not args.dry_run:
        print("認証情報が無効です。`awsprobe doctor` で確認してください。", file=sys.stderr)
        return 2

    names = [n.strip() for n in args.collectors.split(",")] if args.collectors else list(DEFAULT_ORDER)
    unknown = [n for n in names if n not in REGISTRY]
    if unknown:
        print(f"未知のコレクタ: {', '.join(unknown)}\n"
              f"使えるのは: {', '.join(sorted(REGISTRY))}", file=sys.stderr)
        return 2

    inventory: dict = {"meta": {}, "errors": []}
    ran: list[str] = []
    for name in names:
        LOG.info("収集中: %s", name)
        collector = REGISTRY[name]()
        try:
            inventory[name] = collector.collect(ctx)
            ran.append(name)
        except ReadOnlyViolation:
            raise
        except Exception as exc:  # noqa: BLE001
            LOG.error("コレクタ %s が失敗しました: %s", name, exc)
            if args.verbose:
                traceback.print_exc()
            inventory[name] = {}
            ctx.errors.append(CollectError(name, "collect", "CollectorError", str(exc), ""))

    inventory["errors"] = ctx.error_dicts()
    inventory["meta"] = {
        "awsprobe_version": __version__,
        "collected_at": _now(),
        "account_id": ctx.account_id,
        "account_alias": args.account_alias or ctx.account_alias,
        "region": ctx.region,
        "caller_arn": ctx.caller_arn,
        "redacted": not args.no_redact,
        # --dry-run の成果物を「収集できた inventory」と取り違えないための印。
        # answer / posture / excel / diagram-data はこれを見て判定を拒否する。
        "dry_run": bool(args.dry_run),
        # dry-run では実際には何も収集していないので collectors_run は空にする。
        "collectors_run": [] if args.dry_run else ran,
        "max_buckets": getattr(args, "max_buckets", DEFAULT_MAX_BUCKETS),
        "guard": ctx.guard.summary() if ctx.guard else {},
    }

    if not args.no_redact:
        inventory = redact_obj(inventory, {ctx.account_id} if ctx.account_id else set())

    out = _ensure_out(args.out)
    path = os.path.join(out, INVENTORY_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, ensure_ascii=False, indent=2)

    counts = {k: _count(v) for k, v in inventory.items() if k not in {"meta", "errors"}}
    fatal = [e for e in inventory["errors"] if e.get("fatal")]
    print(f"inventory を書き出しました: {path}")
    # dry-run では meta.collectors_run が空になるので、表示もそれに合わせる
    # （画面と inventory で食い違うと「収集できた」と読まれてしまう）。
    print("  収集したコレクタ: "
          + (", ".join(inventory["meta"]["collectors_run"]) or "（なし）"))
    for name, n in counts.items():
        print(f"    {name:<12} {n:>5} 件")
    print(f"  API 呼び出し   : {inventory['meta'].get('guard', {}).get('total_calls', 0)} 回")
    print(f"  収集エラー     : {len(inventory['errors'])} 件"
          + (f"（うち収集欠損 {len(fatal)} 件）" if fatal else "")
          + ("（--verbose で詳細）" if inventory["errors"] else ""))
    if args.verbose:
        for err in inventory["errors"][:50]:
            mark = "!" if err.get("fatal") else " "
            print(f"   {mark}{err['service']}:{err['operation']} "
                  f"{err['code']} {err['message'][:80]}")
    print(f"  マスキング     : {'有効' if not args.no_redact else '無効（生値）'}")
    if args.no_redact:
        print("  ※ アカウントID・ENI ID・グローバルIPが生のまま入っています。取扱い注意。")

    if fatal:
        _print_fatal_warning(fatal)
    if args.dry_run:
        _print_dry_run_notice()
    return 0


def _print_fatal_warning(fatal: list[dict]) -> None:
    """スロットリング・期限切れ等で収集が欠けたことを強く警告する（I-6）。"""
    print(file=sys.stderr)
    print("!" * 72, file=sys.stderr)
    print("!! 収集が不完全です。この結果で判定してはいけません。", file=sys.stderr)
    print("!!", file=sys.stderr)
    print("!! スロットリング・資格情報の期限切れ・AWS 側の一時障害により、"
          "一部の一覧が", file=sys.stderr)
    print("!! 取得できていません。取得できなかったものは『存在しない』と"
          "区別が付きません。", file=sys.stderr)
    for err in fatal[:10]:
        print(f"!!   {err.get('service')}:{err.get('operation')} "
              f"{err.get('code')} {str(err.get('message'))[:60]}", file=sys.stderr)
    if len(fatal) > 10:
        print(f"!!   ほか {len(fatal) - 10} 件", file=sys.stderr)
    print("!!", file=sys.stderr)
    print("!! 時間帯を変えて `awsprobe collect` を再実行してください。", file=sys.stderr)
    print("!" * 72, file=sys.stderr)


def _print_dry_run_notice() -> None:
    """dry-run の成果物が判定に使えないことを明示する（C-2）。"""
    print()
    print("=" * 72)
    print("これは送信していない確認用の出力です。判定には使えません。")
    print("=" * 72)
    print("  --dry-run では AWS へ1バイトも送信していません。")
    print("  上の件数はすべて 0 件であり、『そのリソースが無い』という意味では"
          "ありません。")
    print("  この inventory.json を answer / posture / excel / diagram-data に"
          "渡しても、")
    print("  meta.dry_run の印を見て拒否されます（終了コード 2）。")


def _count(section) -> int:
    if isinstance(section, dict):
        return sum(len(v) if isinstance(v, (list, dict)) else 1 for v in section.values())
    if isinstance(section, list):
        return len(section)
    return 0


# --------------------------------------------------------------------------
# answer / posture / excel / diagram-data
# --------------------------------------------------------------------------

def cmd_answer(args) -> int:
    from .questions import resolve_all, status_counts
    from .report import render_markdown

    inv, redacted, rc = _load_for_output(args, "answer")
    if rc:
        return rc
    answers = resolve_all(inv)
    text = render_markdown(answers, inv, redacted=redacted)
    path = _write_text(os.path.join(_ensure_out(args.out), ANSWER_NAME), text)
    counts = status_counts(answers)
    print(f"未確認事項の判定レポートを書き出しました: {path}")
    print(f"  設問 {len(answers)} 件 / 確定 {counts.get('answered', 0)} ・"
          f" 部分 {counts.get('partial', 0)} ・"
          f" 要ヒアリング {counts.get('needs_manual', 0)} ・"
          f" データ無し {counts.get('no_data', 0)}")
    return 0


def cmd_posture(args) -> int:
    from .posture import evaluate, score
    from .posture_report import render_posture_markdown

    inv, redacted, rc = _load_for_output(args, "posture")
    if rc:
        return rc
    results = evaluate(inv)
    text = render_posture_markdown(results, inv, redacted=redacted)
    path = _write_text(os.path.join(_ensure_out(args.out), POSTURE_NAME), text)
    summary = score(results)
    by_status = summary.get("by_status", {})
    print(f"セキュリティ設定の実施状況レポートを書き出しました: {path}")
    print(f"  チェック {len(results)} 件 / "
          + " ・".join(f"{k} {v}" for k, v in by_status.items()))
    return 0


def cmd_excel(args) -> int:
    from .excel import build_workbook

    inv, _redacted, rc = _load_for_output(args, "excel")
    if rc:
        return rc
    answers = posture_results = None
    if not args.no_analysis:
        try:
            from .questions import resolve_all
            answers = resolve_all(inv)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("未確認事項の判定をスキップします: %s", exc)
        try:
            from .posture import evaluate
            posture_results = evaluate(inv)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("セキュリティ評価をスキップします: %s", exc)

    path = os.path.join(_ensure_out(args.out), EXCEL_NAME)
    build_workbook(inv, path, posture_results=posture_results, answers=answers)
    print(f"棚卸し Excel を書き出しました: {path}")
    return 0


def cmd_diagram_data(args) -> int:
    from .diagram import build_diagram_data

    inv, _redacted, rc = _load_for_output(args, "diagram-data")
    if rc:
        return rc
    out = _ensure_out(os.path.join(args.out, "diagram"))
    paths = build_diagram_data(inv, out)
    print(f"構成図用データを書き出しました: {out}")
    for p in paths:
        print(f"    {os.path.basename(p)}")
    return 0


def cmd_iam_policy(args) -> int:
    from .gen_iam_policy import main as gen_main

    return gen_main(["-o", args.out] if args.out else [])


# --------------------------------------------------------------------------
# host-probe
# --------------------------------------------------------------------------

#: probe_hosts が返す reason コードの日本語表示
REASON_LABELS = {
    "ssm_command_disabled": "--enable-ssm が指定されていないため、SSM コマンドの発行を行わなかった",
    "not_confirmed": "--yes が指定されていないため、確認待ちで停止した",
    "dry_run": "--dry-run のため送信しなかった",
    "no_reachable_instances": "SSM で到達できるインスタンスが1台も無かった",
    "ssm_unavailable": "SSM の API を呼べなかった（権限不足またはサービス未使用）",
}

def _redact_host_section(inv: dict) -> dict:
    """inventory に書き戻す直前に `host` セクションをマスクする（I-5）。

    `host` には EC2 内部から採った内容（IP・ホスト名・設定値）が入る。
    SSM 経路でも `--import-dir` 経路でも、マスク済み inventory に生値の
    セクションを混ぜないよう、ここで必ず通す。
    """
    if not isinstance(inv, dict) or "host" not in inv:
        return inv
    meta = inv.get("meta") if isinstance(inv.get("meta"), dict) else {}
    if not meta.get("redacted", True):
        # inventory 全体が生値運用（--no-redact）なら host だけ隠しても
        # 意味がないので、そちらの方針に合わせる。
        return inv
    account_ids = {str(meta.get("account_id") or "")}
    out = dict(inv)
    out["host"] = redact_obj(mask_secret_values(inv["host"]), account_ids)
    return out


def cmd_host_probe(args) -> int:
    from . import host as host_mod

    # 手動採取結果の取り込みモード
    if args.import_dir:
        result = host_mod.import_manual_results([args.import_dir])
        inv = _load_inventory(args)
        merged = host_mod.merge_into_inventory(inv, result)
        merged = _redact_host_section(merged)
        path = os.path.join(_ensure_out(args.out), INVENTORY_NAME)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, ensure_ascii=False, indent=2)
        n = len(result.get("instances") or {})
        print(f"手動採取結果 {n} 台分を inventory に取り込みました: {path}")
        print("  `awsprobe answer` を再実行すると Q9 / Q14 / Q31 / Q36 の判定が更新されます。")
        return 0

    inv = None
    inv_path = os.path.join(args.out, INVENTORY_NAME)
    if os.path.exists(inv_path):
        with open(inv_path, encoding="utf-8") as fh:
            inv = json.load(fh)

    ctx = _context(args, allow_ssm_command=args.enable_ssm)

    instance_ids = [i.strip() for i in args.instance_ids.split(",")] if args.instance_ids else None

    if args.enable_ssm and not args.yes:
        # 送信するスクリプトの全文を見せて止める
        print(host_mod.render_plan(instance_ids or ["（SSM 到達可能な全インスタンス）"]))
        print()
        print("上記を実行するには `--yes` を付けて再実行してください。")
        print("（--yes が無い限り ssm:SendCommand は発行されません）")
        return 0

    result = host_mod.probe_hosts(
        ctx,
        instance_ids,
        timeout=args.timeout,
        dry_run=args.dry_run,
        confirm=args.yes,
        inventory=inv,
    )

    if result.get("method") == "manual":
        host_mod.render_manual_doc(
            (inv or {}).get("compute", {}).get("instances") if inv else None,
            out_path=args.manual_doc,
            inventory=inv,
            allow_ssm_command=args.enable_ssm,
            reason=result.get("reason"),
        )
        print("SSM 経由での調査は行いませんでした。")
        print(f"  理由: {REASON_LABELS.get(result.get('reason'), result.get('reason'))}")
        print(f"  手動実行の手順書を書き出しました: {args.manual_doc}")
        print("  採取したテキストは `awsprobe host-probe --import-dir <ディレクトリ>` で取り込めます。")
        return 0

    if inv is not None:
        merged = host_mod.merge_into_inventory(inv, result)
        merged = _redact_host_section(merged)
        with open(inv_path, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, ensure_ascii=False, indent=2)
        print(f"inventory に host セクションを追記しました: {inv_path}")
    n = len(result.get("instances") or {})
    print(f"EC2 内部調査が完了しました（{n} 台）。")
    print("  `awsprobe answer` を再実行すると Q9 / Q14 / Q31 / Q36 の判定が更新されます。")
    return 0


# --------------------------------------------------------------------------
# all
# --------------------------------------------------------------------------

def cmd_all(args) -> int:
    rc = cmd_collect(args)
    if rc != 0:
        return rc
    if getattr(args, "dry_run", False):
        # dry-run の inventory は判定に使えない（C-2）。後続は回さない。
        print()
        print("--dry-run のため、answer / posture / excel / diagram-data は"
              "実行しませんでした。")
        return 0
    print()
    args.inventory = os.path.join(args.out, INVENTORY_NAME)
    for fn in (cmd_answer, cmd_posture, cmd_excel, cmd_diagram_data):
        try:
            fn(args)
        except Exception as exc:  # noqa: BLE001
            LOG.error("%s が失敗しました: %s", fn.__name__, exc)
            if args.verbose:
                traceback.print_exc()
        print()
    print("完了しました。出力先:", os.path.abspath(args.out))
    return 0


# --------------------------------------------------------------------------
# パーサ
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="awsprobe",
        description="AWS 環境を読み取り専用で実査し、未確認事項とセキュリティ設定の実施状況を出力する。",
        epilog="変更系 API はガードが機構として拒否するため、この CLI が AWS に変更を加えることはありません。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"awsprobe {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", help="AWS プロファイル名（SSO プロファイル可）")
    common.add_argument("--region", default=DEFAULT_REGION, help=f"リージョン（既定 {DEFAULT_REGION}）")
    common.add_argument("--assume-role-arn", help="引き受けるロールの ARN（他アカウント調査用）")
    common.add_argument("--external-id", help="AssumeRole の ExternalId")
    common.add_argument("--account-alias", default="", help="出力に付ける環境名（例: example）")
    common.add_argument("--out", default=DEFAULT_OUT, help=f"出力先ディレクトリ（既定 {DEFAULT_OUT}）")
    common.add_argument("-v", "--verbose", action="store_true", help="詳細ログを出す")

    offline = argparse.ArgumentParser(add_help=False)
    offline.add_argument("--inventory", help="読み込む inventory.json のパス")
    offline.add_argument("--from-fixture", help="--inventory の別名（実 AWS 無しの動作確認用）")
    offline.add_argument(
        "--no-redact-output", action="store_true",
        help="生値の inventory を読んでも出力をマスクしない（取扱い注意）。"
             "既定では inventory が生値でも出力は必ずマスクする",
    )

    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("doctor", parents=[common], help="認証・権限・到達性を事前診断する")
    sp.set_defaults(func=cmd_doctor, dry_run=False)

    sp = sub.add_parser("collect", parents=[common], help="AWS から読み取って inventory.json を作る")
    sp.add_argument("--collectors", help="実行するコレクタをカンマ区切りで指定（既定は全部）")
    sp.add_argument("--no-redact", action="store_true",
                    help="アカウントID・ENI ID・グローバルIPをマスクしない（取扱い注意）")
    sp.add_argument("--dry-run", action="store_true", help="呼ぶ API を確認するだけで送信しない")
    sp.add_argument("--max-buckets", type=int, default=DEFAULT_MAX_BUCKETS,
                    help=f"詳細を取る S3 バケット数の上限（既定 {DEFAULT_MAX_BUCKETS}）。"
                         "バケット1本につき 11 コール発行されるため、"
                         "スロットリング回避に使う。0 で無制限")
    sp.set_defaults(func=cmd_collect, no_redact_output=False)

    sp = sub.add_parser("answer", parents=[common, offline],
                        help="未確認事項 Q1〜Q42 を判定して Markdown を出す")
    sp.set_defaults(func=cmd_answer, dry_run=False)

    sp = sub.add_parser("posture", parents=[common, offline],
                        help="セキュリティ設定の実施状況を評価して Markdown を出す")
    sp.set_defaults(func=cmd_posture, dry_run=False)

    sp = sub.add_parser("excel", parents=[common, offline], help="棚卸し Excel を出す")
    sp.add_argument("--no-analysis", action="store_true",
                    help="判定シートとセキュリティ評価シートを省く")
    sp.set_defaults(func=cmd_excel, dry_run=False)

    sp = sub.add_parser("diagram-data", parents=[common, offline],
                        help="構成図生成用の TSV / JSON を出す")
    sp.set_defaults(func=cmd_diagram_data, dry_run=False)

    sp = sub.add_parser("iam-policy", parents=[], help="必要な最小権限ポリシーを出力する")
    sp.add_argument("--out", help="出力先 JSON のパス")
    sp.set_defaults(func=cmd_iam_policy, verbose=False, dry_run=False)

    sp = sub.add_parser("host-probe", parents=[common],
                        help="SSM 経由で EC2 内部を調べる（既定は無効）")
    sp.add_argument("--enable-ssm", action="store_true",
                    help="ssm:SendCommand を解禁する。これが無いと手順書の生成だけを行う")
    sp.add_argument("--yes", action="store_true",
                    help="実行するスクリプトを確認したうえで送信する")
    sp.add_argument("--instance-ids", help="対象インスタンスIDをカンマ区切りで指定")
    sp.add_argument("--timeout", type=int, default=120, help="コマンドのタイムアウト秒（既定 120）")
    sp.add_argument("--manual-doc", default="docs/manual-ssh-commands.md",
                    help="手動実行手順書の出力先")
    sp.add_argument("--import-dir", help="手動採取したテキストのディレクトリを取り込む")
    sp.add_argument("--dry-run", action="store_true", help="送信せずに計画だけ表示する")
    sp.set_defaults(func=cmd_host_probe)

    sp = sub.add_parser("all", parents=[common],
                        help="collect → answer → posture → excel → diagram-data を通しで実行")
    sp.add_argument("--collectors", help="実行するコレクタをカンマ区切りで指定")
    sp.add_argument("--no-redact", action="store_true", help="マスクしない（取扱い注意）")
    sp.add_argument("--no-analysis", action="store_true", help="Excel の分析シートを省く")
    sp.add_argument("--no-redact-output", action="store_true",
                    help="出力をマスクしない（取扱い注意）")
    sp.add_argument("--dry-run", action="store_true", help="送信しない")
    sp.add_argument("--max-buckets", type=int, default=DEFAULT_MAX_BUCKETS,
                    help=f"詳細を取る S3 バケット数の上限（既定 {DEFAULT_MAX_BUCKETS}）")
    sp.set_defaults(func=cmd_all)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    try:
        return args.func(args)
    except CredentialsUnavailable as exc:
        print(f"\n【中断】{exc}", file=sys.stderr)
        print("  SSO プロファイルなら `aws sso login --profile <名前>` を実行してください。", file=sys.stderr)
        print("  アクセスキーなら AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY を設定してください。", file=sys.stderr)
        return 2
    except ReadOnlyViolation as exc:
        print(f"\n【中断】{exc}", file=sys.stderr)
        print("これは awsprobe のバグです。変更系 API を呼ぼうとしたため停止しました。", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\n中断しました。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
