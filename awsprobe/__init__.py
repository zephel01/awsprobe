"""awsprobe — AWS 環境の読み取り専用実査ツール。

設計資料や引き継ぎ資料からは確定できない AWS の現況を
**一切変更を加えずに**調べ、次の4つを出力する。

1. `out/inventory.json`            … 生インベントリ
2. `out/未確認事項_突合レポート.md`  … 確認事項 Q1〜Q42 の自動判定
3. `out/セキュリティ設定_実施状況.md` … CIS / FSBP を下敷きにした72項目の実施状況
4. `out/AWS実査_棚卸し.xlsx`        … シート別の棚卸し表

読み取り専用は `guard.ReadOnlyGuard` が機構として担保している。
`Describe* / List* / Get* / Head* / Lookup*` 以外の API は例外で拒否される。
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
