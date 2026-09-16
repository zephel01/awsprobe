"""セキュリティ実施状況（CheckResult 一覧）から Markdown レポートを生成する。

書式は `report.py`（未確認事項レポート）に揃える:
- 見出しは `##` / `###`
- 表は `|` 区切り
- **結論を先に書く**

`posture.py` と同じく AWS API は呼ばない（inventory dict と CheckResult だけを見る）。
機微情報（アクセスキーID・シークレット・パラメータ値）は inventory の時点で
除外されているため、ここでは追加のマスキングを行わない。
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from .posture import (
    CRITICAL,
    DOMAINS,
    DONE,
    HIGH,
    LOW,
    MEDIUM,
    NOT_APPLICABLE,
    NOT_DONE,
    PARTIAL,
    SEVERITIES,
    UNKNOWN,
    CheckResult,
    score,
    status_counts,
    top_priority,
)
from .questions import DENIED_CODES, errors_of

#: status の意味（サマリ表に添える）
STATUS_MEANING: dict[str, str] = {
    DONE: "対象リソースすべてが条件を満たしている",
    PARTIAL: "一部のリソースのみ条件を満たしている",
    NOT_DONE: "対象リソースが存在するが、どれも条件を満たしていない",
    NOT_APPLICABLE: "対象リソースがそもそも存在しない（評価対象外）",
    UNKNOWN: "データが取得できておらず判定できない（権限不足・未収集）",
}

#: 深刻度の日本語表記
SEVERITY_LABEL: dict[str, str] = {
    CRITICAL: "critical（致命的）",
    HIGH: "high（高）",
    MEDIUM: "medium（中）",
    LOW: "low（低）",
}

#: 表示順（サマリ表・詳細セクション共通）
STATUS_ORDER = (DONE, PARTIAL, NOT_DONE, NOT_APPLICABLE, UNKNOWN)


def _cell(value: Any) -> str:
    """表のセル文字列に整形する（改行とパイプを潰す）。"""
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "はい" if value else "いいえ"
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip() or "—"


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    """Markdown 表の行リストを作る。"""
    if not rows:
        return []
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return lines


def _meta_table(inventory: dict, redacted: bool) -> list[str]:
    """収集メタ情報の表（report.py と同じ体裁）。"""
    meta = inventory.get("meta") if isinstance(inventory.get("meta"), dict) else {}
    account = meta.get("account_id") or "（未取得）"
    if redacted:
        account = "＜マスク済み＞"
    return _table(
        ["項目", "値"],
        [
            ["アカウント", account],
            ["アカウント別名", meta.get("account_alias") or "—"],
            ["リージョン", meta.get("region") or "—"],
            ["収集日時", meta.get("collected_at") or "—"],
            ["awsprobe バージョン", meta.get("awsprobe_version") or "—"],
            ["実行したコレクタ", ", ".join(meta.get("collectors_run") or []) or "—"],
            ["マスキング", "有効" if redacted else "**無効（生値を含む）**"],
        ],
    )


def _bullets(items: list[str], limit: int = 20, indent: str = "") -> list[str]:
    """箇条書きにする（件数が多い場合は打ち切って残件数を示す）。"""
    lines = [f"{indent}- {item}" for item in items[:limit]]
    if len(items) > limit:
        lines.append(f"{indent}- …ほか {len(items) - limit} 件")
    return lines


def _result_block(result: CheckResult, level: str = "###") -> list[str]:
    """チェック1件分の Markdown ブロック。

    結論 → 満たしたリソース / 満たさなかったリソース → 是正方針 → 根拠パス の順。
    """
    check = result.check
    lines: list[str] = [
        f"{level} {check.cid} {check.title}",
        "",
        f"**判定: {result.status}**"
        f"（深刻度: {SEVERITY_LABEL.get(check.severity, check.severity)}）",
        "",
        result.summary,
        "",
        f"*なぜ重要か*: {check.why}",
        "",
    ]

    if result.failed:
        lines.append(f"**満たさなかったリソース（{len(result.failed)} 件）**")
        lines.append("")
        lines.extend(_bullets(result.failed))
        lines.append("")
    if result.passed:
        lines.append(f"**条件を満たしたリソース（{len(result.passed)} 件）**")
        lines.append("")
        lines.extend(_bullets(result.passed, limit=10))
        lines.append("")
    if result.notes:
        lines.append("**注記（意図的な設定の可能性・判定の限界）**")
        lines.append("")
        lines.extend(_bullets(result.notes))
        lines.append("")
    if result.remediation:
        lines.append(f"> **是正方針**: {result.remediation}")
        lines.append("")
    if result.evidence:
        shown = result.evidence[:12]
        joined = " / ".join(f"`{e}`" for e in shown)
        if len(result.evidence) > 12:
            joined += f" ほか{len(result.evidence) - 12}件"
        lines.append(f"<small>根拠: {joined} ／ 基準: {check.reference}</small>")
        lines.append("")
    else:
        lines.append(f"<small>基準: {check.reference}</small>")
        lines.append("")
    return lines


def render_posture_markdown(
    results: list[CheckResult],
    inventory: dict,
    *,
    title: str = "AWS セキュリティ設定 実施状況レポート",
    redacted: bool = True,
) -> str:
    """CheckResult 一覧と inventory から Markdown レポート全文を生成する。

    Args:
        results: `posture.evaluate()` の戻り値。
        inventory: 判定に使った inventory dict（meta / errors を参照する）。
        title: レポートのタイトル（H1）。
        redacted: アカウントID等をマスク済みとして扱うか。
    """
    results = list(results or [])
    inv = inventory if isinstance(inventory, dict) else {}
    summary = score(results)
    counts = summary["by_status"]
    lines: list[str] = []

    # -- 見出し ---------------------------------------------------------
    lines.append(f"# {title}")
    lines.append("")
    lines.append(
        f"*生成日時: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M')} ／ "
        "`awsprobe` による読み取り専用調査の結果。AWS への変更操作は一切行っていない。*"
    )
    lines.append("")
    lines.append(
        "*評価基準: CIS AWS Foundations Benchmark v3.0 および "
        "AWS Foundational Security Best Practices（FSBP）。*"
    )
    lines.append("")

    # -- 1. サマリ -------------------------------------------------------
    lines.append("## 1. サマリ")
    lines.append("")
    lines.append(
        f"**チェック {summary['total']} 項目のうち、評価できた {summary['scored']} 項目での"
        f"実施率は {summary['rate']}%**"
        f"（一部実施を 0.5 件として計算。完全実施のみで数えると {summary['strict_rate']}%）。"
        f" **critical で未対応が {summary['open_critical']} 件、high で {summary['open_high']} 件ある。**"
    )
    lines.append("")
    lines.extend(
        _table(
            ["判定", "件数", "意味"],
            [[s, counts.get(s, 0), STATUS_MEANING[s]] for s in STATUS_ORDER],
        )
    )
    lines.append("")

    # ドメイン別スコア表
    lines.append("**ドメイン別スコア**")
    lines.append("")
    domain_rows: list[list[Any]] = []
    for domain in DOMAINS:
        bucket = summary["by_domain"].get(domain)
        if not bucket:
            continue
        domain_rows.append(
            [
                domain,
                bucket["total"],
                bucket.get(DONE, 0),
                bucket.get(PARTIAL, 0),
                bucket.get(NOT_DONE, 0),
                bucket.get(NOT_APPLICABLE, 0),
                bucket.get(UNKNOWN, 0),
                f"{bucket['rate']}%",
            ]
        )
    lines.extend(
        _table(
            ["ドメイン", "項目数", "実施済", "一部実施", "未実施", "該当なし", "判定不能", "実施率"],
            domain_rows,
        )
    )
    lines.append("")

    # 深刻度別
    lines.append("**深刻度別の内訳**")
    lines.append("")
    severity_rows: list[list[Any]] = []
    for severity in SEVERITIES:
        bucket = summary["by_severity"].get(severity)
        if not bucket:
            continue
        severity_rows.append(
            [
                SEVERITY_LABEL.get(severity, severity),
                bucket["total"],
                bucket.get(DONE, 0),
                bucket.get(PARTIAL, 0) + bucket.get(NOT_DONE, 0),
                bucket.get(UNKNOWN, 0),
                f"{bucket['rate']}%",
            ]
        )
    lines.extend(
        _table(
            ["深刻度", "項目数", "実施済", "**未対応（一部＋未実施）**", "判定不能", "実施率"],
            severity_rows,
        )
    )
    lines.append("")

    lines.append("**収集メタ情報**")
    lines.append("")
    lines.extend(_meta_table(inv, redacted))
    lines.append("")

    # -- 2. critical / high の未対応 --------------------------------------
    lines.append("## 2. critical / high の未対応項目（対応すべき順）")
    lines.append("")
    urgent = [
        r for r in results
        if r.severity in (CRITICAL, HIGH) and r.is_open
    ]
    urgent.sort(key=lambda r: (r.priority, r.cid), reverse=True)
    if urgent:
        lines.append(
            f"深刻度 critical / high で未実施・一部実施の項目は **{len(urgent)} 件**。"
            "この表の順に着手すること。"
        )
        lines.append("")
        lines.extend(
            _table(
                ["#", "深刻度", "判定", "チェック", "未対応リソース数", "結論"],
                [
                    [
                        r.cid,
                        r.severity,
                        r.status,
                        r.check.title,
                        len(r.failed),
                        r.summary,
                    ]
                    for r in urgent
                ],
            )
        )
        lines.append("")
    else:
        lines.append("critical / high で未対応の項目はありません。")
        lines.append("")

    # -- 3. ドメイン別の詳細 ----------------------------------------------
    section = 3
    for domain in DOMAINS:
        subset = [r for r in results if r.domain == domain]
        if not subset:
            continue
        bucket = summary["by_domain"].get(domain, {})
        lines.append(f"## {section}. {domain}")
        lines.append("")
        lines.append(
            f"実施率 **{bucket.get('rate', 0)}%**"
            f"（実施済 {bucket.get(DONE, 0)} / 一部実施 {bucket.get(PARTIAL, 0)} / "
            f"未実施 {bucket.get(NOT_DONE, 0)} / 該当なし {bucket.get(NOT_APPLICABLE, 0)} / "
            f"判定不能 {bucket.get(UNKNOWN, 0)}）"
        )
        lines.append("")
        lines.extend(
            _table(
                ["#", "チェック", "深刻度", "判定", "根拠基準"],
                [
                    [r.cid, r.check.title, r.severity, r.status, r.check.reference]
                    for r in subset
                ],
            )
        )
        lines.append("")
        for result in subset:
            lines.extend(_result_block(result))
        section += 1

    # -- 4. 今すぐ直すべき上位10件 -----------------------------------------
    lines.append(f"## {section}. この環境で今すぐ直すべき上位10件")
    lines.append("")
    top = top_priority(results, limit=10)
    if top:
        lines.append(
            "**深刻度 × 影響リソース数**で並べたもの。"
            "上から順に着手すれば、同じ工数で減らせるリスクが最も大きくなる。"
        )
        lines.append("")
        lines.extend(
            _table(
                ["順位", "#", "チェック", "深刻度", "判定", "影響リソース数", "是正方針"],
                [
                    [
                        rank,
                        r.cid,
                        r.check.title,
                        r.severity,
                        r.status,
                        len(r.failed),
                        r.remediation or "—",
                    ]
                    for rank, r in enumerate(top, start=1)
                ],
            )
        )
        lines.append("")
    else:
        lines.append("未実施・一部実施の項目はありません。")
        lines.append("")
    section += 1

    # -- 5. 意図的な設定として除外すべきものの注記 --------------------------
    lines.append(f"## {section}. 意図的な設定として除外すべきものの注記")
    lines.append("")
    noted = [r for r in results if r.notes]
    if noted:
        lines.append(
            "**以下は機械的には「違反」に見えるが、設計上の意図である可能性がある項目。**"
            "そのまま是正対象にせず、意図を確認してから判断すること"
            "（静的サイト用の公開バケット、ログ保管用バケット、検証環境の Single-AZ など）。"
        )
        lines.append("")
        for result in noted:
            lines.append(f"**{result.cid} {result.check.title}**")
            lines.append("")
            lines.extend(_bullets(result.notes))
            lines.append("")
    else:
        lines.append("注記事項はありません。")
        lines.append("")
    section += 1

    # -- 6. 判定不能の一覧 -------------------------------------------------
    lines.append(f"## {section}. 判定不能の項目と理由")
    lines.append("")
    undetermined = [r for r in results if r.status == UNKNOWN]
    if undetermined:
        lines.append(
            f"データが取得できず判定できなかった項目が **{len(undetermined)} 件**。"
            "権限追加またはコレクタの拡張で解消できるものと、"
            "AWS API では原理的に取れないものが混在している。"
        )
        lines.append("")
        lines.extend(
            _table(
                ["#", "チェック", "深刻度", "判定不能の理由", "解消方法"],
                [
                    [r.cid, r.check.title, r.severity, r.summary, r.remediation or "—"]
                    for r in undetermined
                ],
            )
        )
        lines.append("")
    else:
        lines.append("判定不能の項目はありません。")
        lines.append("")
    section += 1

    # -- 7. 収集エラー一覧 -------------------------------------------------
    lines.append(f"## {section}. 収集エラー一覧")
    lines.append("")
    errors = errors_of(inv)
    denied = [e for e in errors if e.get("code") in DENIED_CODES]
    others = [e for e in errors if e.get("code") not in DENIED_CODES]
    lines.append(
        f"収集時のエラーは計 {len(errors)} 件"
        f"（**権限不足 {len(denied)} 件** / その他 {len(others)} 件）。"
        + (
            "権限不足は判定精度に直結するため、IAM ポリシーを追加して再収集すること。"
            if denied
            else "権限不足によるエラーは無い。"
        )
    )
    lines.append("")
    if denied:
        lines.append(f"### {section}-1. 権限不足（判定に影響する）")
        lines.append("")
        lines.extend(
            _table(
                ["サービス", "オペレーション", "コード", "コンテキスト"],
                [
                    [e.get("service"), e.get("operation"), e.get("code"), e.get("context") or "—"]
                    for e in denied
                ],
            )
        )
        lines.append("")
    if others:
        lines.append(f"### {section}-2. その他（未設定・未導入・サービス未使用など）")
        lines.append("")
        lines.extend(
            _table(
                ["サービス", "オペレーション", "コード", "コンテキスト", "メッセージ"],
                [
                    [
                        e.get("service"),
                        e.get("operation"),
                        e.get("code"),
                        e.get("context") or "—",
                        str(e.get("message") or "")[:80],
                    ]
                    for e in others
                ],
            )
        )
        lines.append("")
    if not errors:
        lines.append("収集エラーはありません。")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*本レポートは `awsprobe` が inventory.json のみから機械的に生成したものである。"
        "AWS API を用いた読み取り操作のみで、変更操作は行っていない。"
        "`判定不能` の項目と「意図的な設定」の注記は、自動判定では結論を出せない領域であり、"
        "運用担当者・委託先への確認が必要である。*"
    )
    lines.append("")

    return "\n".join(lines)


def render_posture_summary(results: list[CheckResult]) -> str:
    """1行サマリ（CLI の標準出力向け）。"""
    counts = status_counts(results)
    summary = score(results)
    return (
        f"実施済 {counts[DONE]} / 一部 {counts[PARTIAL]} / 未実施 {counts[NOT_DONE]} / "
        f"該当なし {counts[NOT_APPLICABLE]} / 判定不能 {counts[UNKNOWN]}"
        f"（実施率 {summary['rate']}%・critical 未対応 {summary['open_critical']} 件）"
    )
