"""判定結果（Answer 一覧）から Markdown レポートを生成する。

書式は次のとおり:
- 見出しは `##` / `###`
- 表は `|` 区切り
- **結論を先に書く**

`questions.py` と同じく AWS API は呼ばない（inventory dict と Answer だけを見る）。
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from .questions import (
    ANSWERED,
    CATEGORIES,
    CAT_TOP,
    DENIED_CODES,
    NEEDS_MANUAL,
    NO_DATA,
    PARTIAL,
    Answer,
    errors_of,
    status_counts,
)

#: 最優先9件（確認事項の「最優先」の並び順をそのまま使う）
TOP_PRIORITY_ORDER = ("Q1", "Q8", "Q9", "Q23", "Q27", "Q36", "Q33", "Q37", "Q38")

#: status の日本語表記と意味
STATUS_LABEL: dict[str, str] = {
    ANSWERED: "確定（answered）",
    PARTIAL: "部分的に確定（partial）",
    NEEDS_MANUAL: "要ヒアリング／実査（needs_manual）",
    NO_DATA: "データ無し（no_data）",
}

STATUS_MEANING: dict[str, str] = {
    ANSWERED: "inventory のデータだけで設問に確定的に答えられた",
    PARTIAL: "部分的に答えられたが、確定には EC2 内部調査やヒアリングが要る",
    NEEDS_MANUAL: "AWS API では原理的に取れない（契約内容・人の運用など）",
    NO_DATA: "該当セクションが空、または権限不足で取得できなかった",
}

#: 設計資料をどう更新するかの方針
UPDATE_POLICY: dict[str, str] = {
    ANSWERED: "**確認事項から削除し、設計資料の該当節に確定値として反映する**",
    PARTIAL: "確認事項に残すが、設問を「未確認の残り部分」だけに絞り込む",
    NEEDS_MANUAL: "確認事項に残し、質問票（委託先ベンダー宛）に移す",
    NO_DATA: "確認事項に残す。まず収集権限を追加して再実行する",
}


def _cell(value: Any) -> str:
    """表のセル文字列に整形する。"""
    if value is None:
        return "—"
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


def _meta_line(inventory: dict, redacted: bool) -> list[str]:
    """収集メタ情報の行を作る。"""
    meta = inventory.get("meta") if isinstance(inventory.get("meta"), dict) else {}
    account = meta.get("account_id") or "（未取得）"
    if redacted:
        account = "＜マスク済み＞"
    rows = [
        ["アカウント", account],
        ["アカウント別名", meta.get("account_alias") or "—"],
        ["リージョン", meta.get("region") or "—"],
        ["収集日時", meta.get("collected_at") or "—"],
        ["awsprobe バージョン", meta.get("awsprobe_version") or "—"],
        ["実行したコレクタ", ", ".join(meta.get("collectors_run") or []) or "—"],
        ["マスキング", "有効" if redacted else "**無効（生値を含む）**"],
    ]
    return _table(["項目", "値"], rows)


def _normalize(details: list[str]) -> list[str]:
    """details の行間を Markdown として正しい形に整える。

    - 表の直前が非空行なら空行を1本入れる（見出し行と表がくっつくと崩れる）
    - 表の直後が非空行なら空行を1本入れる
    - 空行が2本以上続いたら1本にまとめる
    """
    out: list[str] = []
    previous_was_table = False
    for line in details:
        stripped = line.strip()
        if not stripped and not out:
            continue  # 先頭の空行は落とす（結論との間が二重に空くのを防ぐ）
        is_table = stripped.startswith("|")
        if is_table and out and out[-1].strip() and not previous_was_table:
            out.append("")
        if previous_was_table and stripped and not is_table:
            out.append("")
        if not stripped and out and not out[-1].strip():
            previous_was_table = False
            continue
        out.append(line)
        previous_was_table = is_table
    return out


def _answer_block(answer: Answer, level: str = "###") -> list[str]:
    """設問1件分の Markdown ブロック（結論 → 根拠 → evidence）。"""
    lines: list[str] = [
        f"{level} {answer.qid} {answer.title}",
        "",
        f"**判定: {STATUS_LABEL.get(answer.status, answer.status)}**",
        "",
        answer.summary,
        "",
    ]
    if answer.details:
        lines.extend(_normalize(answer.details))
        if lines[-1].strip():
            lines.append("")
    if answer.manual_steps:
        lines.append(f"> **確認手順**: {answer.manual_steps}")
        lines.append("")
    if answer.evidence:
        shown = answer.evidence[:12]
        joined = " / ".join(f"`{e}`" for e in shown)
        if len(answer.evidence) > 12:
            joined += f" ほか{len(answer.evidence) - 12}件"
        lines.append(f"<small>根拠: {joined}</small>")
        lines.append("")
    return lines


def render_markdown(
    answers: list[Answer],
    inventory: dict,
    *,
    title: str = "AWS 未確認事項 自動判定レポート",
    redacted: bool = True,
) -> str:
    """Answer 一覧と inventory から Markdown レポート全文を生成する。

    Args:
        answers: `questions.resolve_all()` の戻り値。
        inventory: 判定に使った inventory dict（meta / errors を参照する）。
        title: レポートのタイトル（H1）。
        redacted: アカウントID等をマスク済みとして扱うか。
    """
    answers = list(answers or [])
    inv = inventory if isinstance(inventory, dict) else {}
    lines: list[str] = []

    counts = status_counts(answers)
    resolved = counts.get(ANSWERED, 0)
    remaining = len(answers) - resolved

    # -- 見出し ---------------------------------------------------------
    lines.append(f"# {title}")
    lines.append("")
    lines.append(
        f"*生成日時: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M')} ／ "
        f"`awsprobe` による読み取り専用調査の結果。AWS への変更操作は一切行っていない。*"
    )
    lines.append("")

    # -- 1. 冒頭サマリ ---------------------------------------------------
    lines.append("## 1. サマリ")
    lines.append("")
    lines.append(
        f"**設問 {len(answers)} 件のうち、{resolved} 件を自動で確定させた"
        f"（残り {remaining} 件）。**"
    )
    lines.append("")
    lines.extend(
        _table(
            ["判定", "件数", "意味"],
            [
                [STATUS_LABEL[s], counts.get(s, 0), STATUS_MEANING[s]]
                for s in (ANSWERED, PARTIAL, NEEDS_MANUAL, NO_DATA)
            ],
        )
    )
    lines.append("")
    lines.extend(
        _table(
            ["区分", "件数"],
            [
                ["**自動で解消した件数（answered）**", resolved],
                ["残った件数（partial / needs_manual / no_data）", remaining],
                ["　うち部分的に解消（partial）", counts.get(PARTIAL, 0)],
                ["　うち要ヒアリング（needs_manual）", counts.get(NEEDS_MANUAL, 0)],
                ["　うちデータ未取得（no_data）", counts.get(NO_DATA, 0)],
            ],
        )
    )
    lines.append("")

    # カテゴリ別の内訳
    category_rows: list[list[Any]] = []
    for category in CATEGORIES:
        subset = [a for a in answers if a.category == category]
        if not subset:
            continue
        sub_counts = status_counts(subset)
        category_rows.append(
            [
                category,
                len(subset),
                sub_counts.get(ANSWERED, 0),
                sub_counts.get(PARTIAL, 0),
                sub_counts.get(NEEDS_MANUAL, 0),
                sub_counts.get(NO_DATA, 0),
            ]
        )
    if category_rows:
        lines.append("**カテゴリ別の内訳**")
        lines.append("")
        lines.extend(
            _table(
                ["カテゴリ", "設問数", "確定", "部分", "要ヒアリング", "データ無し"],
                category_rows,
            )
        )
        lines.append("")

    lines.append("**収集メタ情報**")
    lines.append("")
    lines.extend(_meta_line(inv, redacted))
    lines.append("")

    # -- 2. 最優先9件 ----------------------------------------------------
    by_id = {a.qid: a for a in answers}
    top = [by_id[q] for q in TOP_PRIORITY_ORDER if q in by_id]
    top += [a for a in answers if a.category == CAT_TOP and a.qid not in TOP_PRIORITY_ORDER]

    lines.append("## 2. 最優先（切離し日程・安全性に直結）")
    lines.append("")
    if top:
        lines.append(
            "確認事項一覧 の「最優先」9件。**結論 → 根拠 → 根拠となった JSON パス**の順に記載する。"
        )
        lines.append("")
        lines.extend(
            _table(
                ["#", "設問", "判定", "結論（要約）"],
                [
                    [a.qid, a.title, STATUS_LABEL.get(a.status, a.status), a.summary]
                    for a in top
                ],
            )
        )
        lines.append("")
        for answer in top:
            lines.extend(_answer_block(answer))
    else:
        lines.append("最優先カテゴリの設問がありません。")
        lines.append("")

    # -- 3. カテゴリ別 ---------------------------------------------------
    section = 3
    for category in CATEGORIES:
        if category == CAT_TOP:
            continue
        subset = sorted(
            [a for a in answers if a.category == category], key=lambda x: x.number
        )
        if not subset:
            continue
        lines.append(f"## {section}. {category}")
        lines.append("")
        lines.extend(
            _table(
                ["#", "設問", "判定"],
                [[a.qid, a.title, STATUS_LABEL.get(a.status, a.status)] for a in subset],
            )
        )
        lines.append("")
        for answer in subset:
            lines.extend(_answer_block(answer))
        section += 1

    # -- 4. needs_manual のまとめ（質問票） -------------------------------
    lines.append(f"## {section}. 要ヒアリング事項のチェックリスト（質問票）")
    lines.append("")
    manual = [
        a
        for a in answers
        if a.status in (NEEDS_MANUAL, PARTIAL) and a.manual_steps
    ]
    lines.append(
        "**このまま委託先ベンダーへの質問票として使える形で整理した。** "
        f"AWS API では確定できず、人に聞くか実査が必要な項目は {len(manual)} 件。"
    )
    lines.append("")
    strictly_manual = [a for a in manual if a.status == NEEDS_MANUAL]
    if strictly_manual:
        lines.append(
            f"### {section}-1. AWS API では原理的に取得できない項目（{len(strictly_manual)}件）"
        )
        lines.append("")
        for answer in strictly_manual:
            lines.append(f"- [ ] **{answer.qid}** {answer.title}")
            lines.append(f"  - {answer.manual_steps}")
        lines.append("")
    partial_manual = [a for a in manual if a.status == PARTIAL]
    if partial_manual:
        lines.append(
            f"### {section}-2. 自動判定で一部が埋まり、残りの確認が必要な項目（{len(partial_manual)}件）"
        )
        lines.append("")
        for answer in partial_manual:
            lines.append(f"- [ ] **{answer.qid}** {answer.title}")
            lines.append(f"  - 自動判定でわかったこと: {answer.summary}")
            lines.append(f"  - 残りの確認: {answer.manual_steps}")
        lines.append("")
    if not manual:
        lines.append("要ヒアリング事項はありません。")
        lines.append("")
    section += 1

    # -- 5. 収集エラー一覧 -----------------------------------------------
    lines.append(f"## {section}. 収集エラー一覧")
    lines.append("")
    errors = errors_of(inv)
    denied = [e for e in errors if e.get("code") in DENIED_CODES]
    others = [e for e in errors if e.get("code") not in DENIED_CODES]
    lines.append(
        f"収集時のエラーは計 {len(errors)} 件"
        f"（**権限不足 {len(denied)} 件** / その他 {len(others)} 件）。"
        + (
            "権限不足は判定の精度に直結するため、IAM ポリシーを追加して再収集すること。"
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
    section += 1

    # -- 6. 確認事項一覧 の更新対応表 ---------------------------------------------
    lines.append(f"## {section}. 設計資料の更新対応表")
    lines.append("")
    lines.append(
        "**この結果をもとに設計資料をどう更新するか。**"
    )
    lines.append("")
    lines.extend(
        _table(
            ["#", "設問", "判定", "更新方針", "反映先"],
            [
                [
                    a.qid,
                    a.title[:40] + ("…" if len(a.title) > 40 else ""),
                    STATUS_LABEL.get(a.status, a.status),
                    UPDATE_POLICY.get(a.status, "—"),
                    "確認事項一覧の「確認済み」表" if a.status == ANSWERED else "確認事項一覧の各カテゴリ表",
                ]
                for a in sorted(answers, key=lambda x: x.number)
            ],
        )
    )
    lines.append("")
    lines.append(
        f"**合計: 確定 {counts.get(ANSWERED, 0)} 件を 確認事項一覧から削除できる。"
        f"残り {remaining} 件のうち、{counts.get(NEEDS_MANUAL, 0)} 件は質問票へ、"
        f"{counts.get(PARTIAL, 0)} 件は設問を絞り込んで 確認事項一覧に残す、"
        f"{counts.get(NO_DATA, 0)} 件は収集権限を追加して再実行する。**"
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "*本レポートは `awsprobe` が inventory.json のみから機械的に生成したものである。"
        "AWS API を用いた読み取り操作のみで、変更操作は行っていない。"
        "経営判断・契約・人の運用に関する項目は自動判定の対象外であり、"
        "上記の質問票で別途確認すること。*"
    )
    lines.append("")

    return "\n".join(lines)
