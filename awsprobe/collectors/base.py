"""コレクタの基底と登録。

各コレクタは `Collector` を継承し、`name` と `collect(ctx) -> dict` を実装する。
戻り値の dict がそのまま inventory[<name>] になる。

規約:
- boto3 を直接触らない。必ず ctx.client / ctx.call / ctx.paginate を使う。
- 権限不足や未導入サービスで落ちない。ctx が None / [] を返すのでそのまま扱う。
- レスポンスは極力そのまま入れる（後段の判定ロジックが生データを見られるように）。
  ただし datetime は ISO 文字列に正規化する（json.dumps を通すため）。
- 追加の詳細取得（例: S3 バケットのポリシー）は、一覧要素に "_detail" ではなく
  素直な追加キー（例: "Policy", "PublicAccessBlock"）を足す形で埋め込む。
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from ..session import Context


class Collector:
    """コレクタ基底クラス。"""

    name: str = ""
    #: このコレクタが必要とする IAM アクション（README とポリシー生成に使う）
    iam_actions: tuple[str, ...] = ()

    def collect(self, ctx: Context) -> dict:  # pragma: no cover - 抽象
        raise NotImplementedError


def jsonable(value: Any) -> Any:
    """datetime / set / bytes を JSON 化可能な形に正規化する。"""
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, set):
        return sorted(jsonable(v) for v in value)
    if isinstance(value, (_dt.datetime, _dt.date)):
        return value.isoformat()
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return repr(value)
    return value


def tag_name(resource: dict, default: str = "") -> str:
    """Tags 配列から Name タグを取り出す。"""
    for tag in resource.get("Tags") or []:
        if tag.get("Key") == "Name":
            return tag.get("Value") or default
    return default


#: cli.py から参照される登録簿。各モジュールが import 時に自身を追加する。
REGISTRY: dict[str, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    if not cls.name:
        raise ValueError("Collector.name が未設定です")
    REGISTRY[cls.name] = cls
    return cls
