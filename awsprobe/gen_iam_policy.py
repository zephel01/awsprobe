#!/usr/bin/env python3
"""全コレクタの `iam_actions` から最小権限の読み取り専用 IAM ポリシーを生成する。

`awsprobe/collectors/*.py` の `Collector.iam_actions`（`REGISTRY` 経由）を
機械的に集約するだけで、**アクション一覧をこのスクリプトにハードコードしない**。
コレクタに `iam_actions` を追加・削除すれば、次にこのスクリプトを実行した
ときの出力に自動で反映される。

出力するポリシーは2つの Statement からなる:

1. `AwsprobeReadOnlyCollect`（Effect: Allow）
   … 全コレクタの読み取り系アクションをサービスごとにグループ化した一覧。
2. `SsmRunCommandForHostProbeDisabledByDefault`（**Effect: Deny**）
   … `awsprobe host-probe --enable-ssm` が使う `ssm:SendCommand` 系。
     EC2 内でコマンドを実行する操作であり、通常の読み取り収集とは
     性質が異なるため、既定では Deny にして無効化した状態で出力する。
     `--enable-ssm` を実際に使う運用のときだけ、このステートメントの
     `Effect` を手動で `Allow` に書き換えて有効化すること
     （`docs/iam-policy-readonly.md` に運用手順を記載）。

厳守事項:
- ここでは AWS API を呼ばない（`REGISTRY` の静的なメタデータしか読まない）。
- コレクタモジュールを import する都合上、`awsprobe.session`
  （`boto3` を import している）が間接的に読み込まれるが、これは
  契約上許容されている（他の `awsprobe/*.py` は `boto3` を直接 import しない）。

使い方::

    python -m awsprobe.gen_iam_policy
    python -m awsprobe.gen_iam_policy -o docs/iam-policy-readonly.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # `python awsprobe/gen_iam_policy.py` で直接実行された場合の救済
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from awsprobe.collectors import (  # type: ignore[no-redef]
        compute, database, edge, logging_, network, security, serverless, storage,
    )
    from awsprobe.collectors.base import REGISTRY  # type: ignore[no-redef]
    from awsprobe.guard import SSM_COMMAND_OPERATIONS  # type: ignore[no-redef]
else:
    # import するだけで各コレクタが REGISTRY に自身を登録する（import の副作用）。
    from .collectors import (  # noqa: F401
        compute, database, edge, logging_, network, security, serverless, storage,
    )
    from .collectors.base import REGISTRY
    from .guard import SSM_COMMAND_OPERATIONS

_POLICY_VERSION = "2012-10-17"
_MAIN_SID = "AwsprobeReadOnlyCollect"
_SSM_SID = "SsmRunCommandForHostProbeDisabledByDefault"


def _sort_key(action: str) -> tuple[str, str]:
    """`service:Action` を (サービス名, アクション名) に分解する。グループ化・ソート用。"""
    if ":" in action:
        service, name = action.split(":", 1)
    else:
        service, name = "", action
    return (service, name)


def collect_actions() -> list[str]:
    """`REGISTRY` に登録済みの全コレクタから `iam_actions` を集めて重複を除く。

    サービスごとにグループ化されるよう、`service:Action` の文字列としてソートする。
    """
    actions: set[str] = set()
    for collector_cls in REGISTRY.values():
        for action in getattr(collector_cls, "iam_actions", None) or ():
            if action:
                actions.add(str(action))
    return sorted(actions, key=_sort_key)


def actions_by_service() -> dict[str, list[str]]:
    """サービス名 → アクション一覧（ソート済み）。報告・検証に使う。"""
    grouped: dict[str, list[str]] = {}
    for action in collect_actions():
        service, _name = _sort_key(action)
        grouped.setdefault(service, []).append(action)
    return grouped


def _ssm_run_command_actions() -> list[str]:
    return sorted(f"{service}:{operation}" for service, operation in SSM_COMMAND_OPERATIONS)


def build_policy() -> dict:
    """最小権限ポリシー（dict）を組み立てる。"""
    actions = collect_actions()
    if not actions:
        raise RuntimeError(
            "REGISTRY からアクションを1件も収集できなかった"
            "（コレクタモジュールの import 漏れの可能性がある）"
        )

    return {
        "Version": _POLICY_VERSION,
        "Statement": [
            {
                "Sid": _MAIN_SID,
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
            },
            {
                "Sid": _SSM_SID,
                "Effect": "Deny",
                "Action": _ssm_run_command_actions(),
                "Resource": "*",
            },
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="awsprobe 用の最小権限 IAM ポリシーを生成する")
    parser.add_argument(
        "-o", "--out", default="docs/iam-policy-readonly.json",
        help="出力先パス（既定: docs/iam-policy-readonly.json）",
    )
    args = parser.parse_args(argv)

    policy = build_policy()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    main_count = len(policy["Statement"][0]["Action"])
    ssm_count = len(policy["Statement"][1]["Action"])
    service_count = len(actions_by_service())
    print(
        f"wrote: {out_path} "
        f"({main_count} 読み取りアクション / {service_count} サービス / "
        f"{ssm_count} 件の SSM RunCommand アクション[既定 Deny])"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
