"""`ctx.call` / `ctx.paginate` に薄い保険をかけるヘルパー。

`Context` は ClientError と BotoCoreError を握って None / [] を返すが、
それ以外の例外は素通しする。実運用ではこの経路で収集全体が止まりうる:

- botocore が古く、新しいオペレーションを知らない → `AttributeError`
- モック／代替エンドポイント環境で未実装 → `NotImplementedError`
- レスポンス形状が想定外でパーサが落ちる

awsprobe は「1つの API が引けないこと」自体が調査結果（未確認事項の解消）なので、
どの経路で失敗しても収集は止めず、errors に記録して次へ進む。
読み取り専用ガード違反 (`ReadOnlyViolation`) だけは握り潰さず必ず送出する。

呼び出しは必ず `ctx` 経由のまま（boto3 を直接触らない）。
"""
from __future__ import annotations

from ..guard import ReadOnlyViolation
from ..session import CollectError, Context


def safe_paginate(ctx: Context, service: str, operation: str, result_key: str,
                  *, region: str | None = None, context: str = "", **kwargs) -> list:
    """`ctx.paginate` と同じ使い方。想定外の例外時も空リストを返す。"""
    try:
        return ctx.paginate(
            service, operation, result_key, region=region, context=context, **kwargs
        )
    except ReadOnlyViolation:
        raise
    except Exception as exc:  # noqa: BLE001 - 収集の継続を最優先する
        _record(ctx, service, operation, exc, context)
        return []


def safe_call(ctx: Context, service: str, operation: str,
              *, region: str | None = None, context: str = "", **kwargs) -> dict | None:
    """`ctx.call` と同じ使い方。想定外の例外時も None を返す。"""
    try:
        return ctx.call(service, operation, region=region, context=context, **kwargs)
    except ReadOnlyViolation:
        raise
    except Exception as exc:  # noqa: BLE001 - 収集の継続を最優先する
        _record(ctx, service, operation, exc, context)
        return None


def _record(ctx: Context, service: str, operation: str, exc: Exception, context: str) -> None:
    """例外クラス名を code として errors に積む（AccessDenied 等と区別できる形）。"""
    ctx.errors.append(
        CollectError(service, operation, type(exc).__name__, str(exc), context)
    )
