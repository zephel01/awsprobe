"""未確認事項 Q1〜Q42 の自動判定。

設計資料からは確定できない確認事項 Q1〜Q42 を、
`awsprobe collect` が出力した inventory dict だけを見て判定する。

厳守事項:
- **AWS API を呼ばない。boto3 を import しない。** 入力は inventory dict のみ。
- 標準ライブラリのみを使う（ipaddress / datetime / re / dataclasses）。
- inventory のキーが欠けていても KeyError で落ちない（`.get()` を徹底する）。

status の使い分け:
- ``answered``     … inventory のデータだけで確定的に答えられた
- ``partial``      … 部分的に答えられたが、確定には EC2 内部調査やヒアリングが要る
- ``needs_manual`` … AWS API では原理的に取れない（契約内容・人の運用・鍵の保有者など）
- ``no_data``      … 該当セクションが空、または errors に AccessDenied 等があって取れなかった
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

# guard は標準ライブラリ（re / threading）しか import しないため、
# 「boto3 を import しない」という questions.py の厳守事項を壊さない。
from .guard import ACCOUNT_TOKEN_RE, SELF_ACCOUNT_TOKEN

# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------

#: status の取りうる値
ANSWERED = "answered"
PARTIAL = "partial"
NEEDS_MANUAL = "needs_manual"
NO_DATA = "no_data"

STATUSES = (ANSWERED, PARTIAL, NEEDS_MANUAL, NO_DATA)

#: カテゴリ（確認事項の小見出しに対応）
CAT_TOP = "最優先"
CAT_NET = "ネットワーク・セキュリティ"
CAT_COMPUTE = "コンピュート・データ"
CAT_APP = "アプリ・デプロイ・委託"
CAT_OTHER = "その他リソース・統制"

CATEGORIES = (CAT_TOP, CAT_NET, CAT_COMPUTE, CAT_APP, CAT_OTHER)

#: 権限不足を示すエラーコード（session.SOFT_ERROR_CODES のうち「見えなかった」もの）。
#: 「未設定だから取れなかった」系（NoSuchBucketPolicy 等）とは区別する。
DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AccessDeniedFault",
        "UnauthorizedOperation",
        "AuthorizationError",
        "AuthFailure",
        "Forbidden",
        "InvalidClientTokenId",
        "SubscriptionRequiredException",
        "OptInRequired",
        "UnrecognizedClientException",
    }
)

#: 判定基準日（EOL 判定に使う）
_TODAY = _dt.date.today()

#: Lambda / ステートマシンを「動いていない」とみなす未実行日数
_LAMBDA_IDLE_DAYS = 90
_SFN_IDLE_DAYS = 90


# ---------------------------------------------------------------------------
# Answer
# ---------------------------------------------------------------------------


@dataclass
class Answer:
    """設問1件に対する判定結果。"""

    #: 設問 ID（"Q1" 形式）
    qid: str
    #: 確認事項の設問文（原文をそのまま）
    title: str
    #: カテゴリ（CATEGORIES のいずれか）
    category: str
    #: answered / partial / needs_manual / no_data
    status: str
    #: 結論を1〜2文で（日本語）
    summary: str
    #: 箇条書きの根拠・内訳（Markdown 表の行を含んでよい）
    details: list[str] = field(default_factory=list)
    #: 根拠となった inventory の JSON パス
    evidence: list[str] = field(default_factory=list)
    #: needs_manual のとき、誰に何を聞く／どこを見るか
    manual_steps: str | None = None

    def to_dict(self) -> dict:
        """JSON 化しやすい dict に変換する。"""
        return asdict(self)

    @property
    def number(self) -> int:
        """"Q12" → 12。並べ替え用。"""
        m = re.search(r"\d+", self.qid or "")
        return int(m.group()) if m else 0


# ---------------------------------------------------------------------------
# レゾルバ登録
# ---------------------------------------------------------------------------

#: qid -> (設問文, カテゴリ)
QUESTION_META: dict[str, tuple[str, str]] = {}

#: qid -> inventory dict を受けて Answer を返す関数
RESOLVERS: dict[str, Callable[[dict], Answer]] = {}


#: inventory が持ちうるリソースセクション名（meta / errors / host を除く）
SECTION_NAMES = (
    "network",
    "compute",
    "database",
    "storage",
    "edge",
    "serverless",
    "logging",
    "security",
)


def _has_section(inventory: dict, name: str) -> bool:
    """セクションが dict として存在するか（空 dict でも「収集した」とみなす）。"""
    return isinstance((inventory or {}).get(name), dict)


def question(qid: str, title: str, category: str, requires: tuple[str, ...] = ()):
    """レゾルバを RESOLVERS に登録するデコレータ。

    `requires` に挙げたセクションが inventory に1つも無い場合は、
    判定関数を呼ばずに `no_data` を返す（コレクタ未実行・権限不足の切り分け）。
    判定関数が想定外の例外で落ちても、レポート全体を止めないよう
    `no_data` の Answer に変換する（KeyError 等の最終防衛線）。
    """

    def decorator(fn: Callable[[dict], Answer]) -> Callable[[dict], Answer]:
        QUESTION_META[qid] = (title, category)

        def wrapper(inventory: dict | None) -> Answer:
            inv = inventory if isinstance(inventory, dict) else {}

            # inventory にリソースセクションが1つも無い＝そもそも収集できていない
            if not any(_has_section(inv, s) for s in SECTION_NAMES):
                return Answer(
                    qid, title, category, NO_DATA,
                    "inventory にリソースセクションが1つも存在しないため判定できない"
                    "（`awsprobe collect` が未実行、または全コレクタが失敗している）。"
                    + (f" 収集エラー: {format_errors(errors_of(inv))}。" if errors_of(inv) else ""),
                )

            if requires and not any(_has_section(inv, s) for s in requires):
                missing = "／".join(requires)
                summary, details = no_data(
                    f"判定に必要なセクション（{missing}）", inv
                )
                return Answer(
                    qid, title, category, NO_DATA, summary, details,
                    [f"{s}" for s in requires],
                )

            try:
                answer = fn(inv)
            except Exception as exc:  # noqa: BLE001 - 判定は絶対に止めない
                answer = Answer(
                    qid=qid,
                    title=title,
                    category=category,
                    status=NO_DATA,
                    summary=(
                        f"判定中に想定外のエラーが発生したため判定できなかった"
                        f"（{type(exc).__name__}: {exc}）。"
                    ),
                )
            # レゾルバ側の書き間違いを防ぐため、識別情報は必ず上書きする。
            answer.qid, answer.title, answer.category = qid, title, category
            if answer.status not in STATUSES:
                answer.status = NO_DATA
            return answer

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        RESOLVERS[qid] = wrapper
        return wrapper

    return decorator


def resolve_all(inventory: dict) -> list[Answer]:
    """Q1〜Q42 をすべて判定し、設問番号順の Answer 一覧を返す。

    inventory が空 dict `{}` でも例外を出さず、全件が `no_data` 相当になる。
    """
    inv = inventory if isinstance(inventory, dict) else {}
    answers = [RESOLVERS[qid](inv) for qid in RESOLVERS]
    answers.sort(key=lambda a: a.number)
    return answers


def status_counts(answers: list[Answer]) -> dict[str, int]:
    """status ごとの件数を返す（0 件の status もキーを持つ）。"""
    counts = {s: 0 for s in STATUSES}
    for a in answers:
        counts[a.status] = counts.get(a.status, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# inventory アクセスの共通ヘルパー（すべて .get() ベースで落ちない）
# ---------------------------------------------------------------------------


def _sect(inv: dict, name: str) -> dict:
    """inventory のセクションを dict として取り出す（無ければ空 dict）。"""
    value = (inv or {}).get(name)
    return value if isinstance(value, dict) else {}


def _lst(inv: dict, section: str, key: str) -> list[Any]:
    """inventory[section][key] を list として取り出す（無ければ空 list）。"""
    value = _sect(inv, section).get(key)
    return [v for v in value] if isinstance(value, list) else []


def _dicts(inv: dict, section: str, key: str) -> list[dict]:
    """`_lst` のうち dict 要素だけを返す。"""
    return [v for v in _lst(inv, section, key) if isinstance(v, dict)]


def _map(inv: dict, section: str, key: str) -> dict:
    """inventory[section][key] を dict として取り出す（無ければ空 dict）。"""
    value = _sect(inv, section).get(key)
    return value if isinstance(value, dict) else {}


def _tag(resource: dict, key: str = "Name", default: str = "") -> str:
    """Tags 配列から指定キーの値を取り出す。"""
    for item in (resource or {}).get("Tags") or []:
        if isinstance(item, dict) and item.get("Key") == key:
            return item.get("Value") or default
    return default


# ---------------------------------------------------------------------------
# アカウントIDの表記（生値とマスク済みトークンの両対応）
# ---------------------------------------------------------------------------
#
# `guard.redact()` はアカウントIDを **消さずに擬似化する**:
#   自アカウント   → ``＜自アカウント＞``
#   それ以外       → ``＜アカウント:f428＞``（同じ ID は常に同じトークン）
#
# `awsprobe all` の既定動線ではマスク済み inventory が判定に渡るため、
# 12桁だけを見る実装のままだと Q27（外部アカウントを信頼する IAM ロール）が
# **1本も見つからず 0 本に化ける**。以下のパターンは 3 表記すべてを拾う。
# `meta.account_id` 自体もマスクで ``＜自アカウント＞`` になっている点に注意。
# （同じ対応が posture.py の `_ACCOUNT_FIELD` / `_is_self_account` にも入っている）

#: ARN のアカウント位置・Principal に現れうるアカウント表記
_ACCOUNT_FIELD = r"(?:\d{12}|＜自アカウント＞|＜アカウント:[0-9a-f]{4}＞)"
#: `arn:aws:iam::<アカウント>:...` からアカウント部分を取り出す
_IAM_ARN_ACCOUNT_RE = re.compile(r"arn:aws[\w-]*:iam::(" + _ACCOUNT_FIELD + r"):")
#: iam / sts どちらの ARN でも拾う
_IAM_STS_ARN_ACCOUNT_RE = re.compile(
    r"arn:aws[\w-]*:(?:iam|sts)::(" + _ACCOUNT_FIELD + r"):"
)
#: ARN ではなく単体のアカウント表記（Principal に直接書かれた形）
_BARE_ACCOUNT_RE = re.compile(_ACCOUNT_FIELD)
#: JSON 文字列のまま入っている場合の `"AWS": "<アカウント>"`
_JSON_AWS_PRINCIPAL_RE = re.compile(r'"AWS"\s*:\s*"(' + _ACCOUNT_FIELD + r')"')


def is_self_account(ref: Any, account_id: str) -> bool:
    """アカウント参照 ``ref`` が自アカウントを指すか。

    - ``＜自アカウント＞``      … 自アカウント（マスク済み inventory）
    - ``＜アカウント:xxxx＞``   … **外部アカウント**。マスク時に自分は必ず
      ``＜自アカウント＞`` になるので、このトークンは自分ではありえない。
    - 生の12桁                  … 従来どおり ``meta.account_id`` と比較する
    """
    text = str(ref or "")
    if not text:
        return False
    if text == SELF_ACCOUNT_TOKEN:
        return True
    if ACCOUNT_TOKEN_RE.fullmatch(text):
        return False
    return bool(account_id) and text == account_id


def errors_of(inv: dict) -> list[dict]:
    """inventory["errors"] を dict のリストとして取り出す。"""
    value = (inv or {}).get("errors")
    if not isinstance(value, list):
        return []
    return [e for e in value if isinstance(e, dict)]


def errors_for(
    inv: dict,
    services: tuple[str, ...] = (),
    operations: tuple[str, ...] = (),
) -> list[dict]:
    """サービス名／オペレーション名で errors を絞り込む。"""
    out: list[dict] = []
    for err in errors_of(inv):
        if services and err.get("service") not in services:
            continue
        if operations and err.get("operation") not in operations:
            continue
        out.append(err)
    return out


def is_denied(err: dict) -> bool:
    """そのエラーが「権限不足で見えなかった」ものかどうか。"""
    return (err or {}).get("code") in DENIED_CODES


def denied_for(inv: dict, services: tuple[str, ...] = ()) -> list[dict]:
    """指定サービスの権限不足エラーのみを返す。"""
    return [e for e in errors_for(inv, services=services) if is_denied(e)]


def format_errors(errs: list[dict], limit: int = 4) -> str:
    """errors を1行の文字列にまとめる（summary に埋め込む用）。"""
    parts = [
        f"{e.get('service')}:{e.get('operation')} {e.get('code')}"
        + (f"（{e.get('context')}）" if e.get("context") else "")
        for e in errs[:limit]
    ]
    if len(errs) > limit:
        parts.append(f"ほか{len(errs) - limit}件")
    return " / ".join(parts)


def no_data(
    what: str,
    inv: dict,
    services: tuple[str, ...] = (),
    extra: str = "",
) -> tuple[str, list[str]]:
    """`no_data` 用の summary と details を組み立てる。

    権限不足エラーがあればその内容を summary に含める（契約どおり）。
    戻り値は (summary, details)。
    """
    denied = denied_for(inv, services)
    if denied:
        summary = (
            f"{what}が取得できていない（権限不足）。"
            f"該当エラー: {format_errors(denied)}。"
        )
        details = ["| サービス | オペレーション | コード | コンテキスト |", "|---|---|---|---|"] + [
            f"| {e.get('service')} | {e.get('operation')} | {e.get('code')} | {e.get('context') or '—'} |"
            for e in denied[:10]
        ]
        return summary + extra, details
    other = errors_for(inv, services=services)
    if other:
        return (
            f"{what}が空だった。収集時のエラー: {format_errors(other)}。" + extra,
            [],
        )
    return (f"{what}が inventory に存在しない（収集対象外か、リソースが0件）。" + extra, [])


# ---------------------------------------------------------------------------
# Markdown 補助
# ---------------------------------------------------------------------------


def _cell(value: Any) -> str:
    """表のセル文字列に整形する（改行とパイプを潰す）。"""
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "はい" if value else "いいえ"
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip() or "—"


def table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    """Markdown 表の行リストを作る（details にそのまま入れる）。"""
    if not rows:
        return []
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return lines


# ---------------------------------------------------------------------------
# ドメイン補助（SG / サブネット / 日時）
# ---------------------------------------------------------------------------


def sg_index(inv: dict) -> dict[str, dict]:
    """GroupId -> SecurityGroup の索引。"""
    return {
        sg.get("GroupId"): sg
        for sg in _dicts(inv, "network", "security_groups")
        if sg.get("GroupId")
    }


def sg_label(sg: dict) -> str:
    """SG を「名前 (sg-xxxx)」形式で表す。"""
    if not sg:
        return "（不明なSG）"
    return f"{sg.get('GroupName') or _tag(sg) or '(名前なし)'} ({sg.get('GroupId')})"


def subnet_index(inv: dict) -> dict[str, dict]:
    """SubnetId -> Subnet の索引。"""
    return {
        s.get("SubnetId"): s
        for s in _dicts(inv, "network", "subnets")
        if s.get("SubnetId")
    }


def subnet_label(subnet: dict) -> str:
    """サブネットを「Name (subnet-xxxx)」形式で表す。"""
    if not subnet:
        return "（不明なサブネット）"
    return f"{_tag(subnet) or '(名前なし)'} ({subnet.get('SubnetId')})"


def port_label(perm: dict) -> str:
    """IpPermission をプロトコル／ポート表記にする。"""
    proto = perm.get("IpProtocol")
    if str(proto) == "-1":
        return "全プロトコル/全ポート"
    from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
    if from_port is None and to_port is None:
        return f"{proto}/全ポート"
    if from_port == to_port:
        return f"{proto}/{from_port}"
    return f"{proto}/{from_port}-{to_port}"


def perm_sources(perm: dict) -> list[str]:
    """IpPermission の送信元をすべて文字列化する（CIDR / SG参照 / プレフィックスリスト）。"""
    out: list[str] = []
    for rng in perm.get("IpRanges") or []:
        if not isinstance(rng, dict):
            continue
        desc = rng.get("Description")
        out.append(f"{rng.get('CidrIp')}" + (f"（{desc}）" if desc else ""))
    for rng in perm.get("Ipv6Ranges") or []:
        if not isinstance(rng, dict):
            continue
        desc = rng.get("Description")
        out.append(f"{rng.get('CidrIpv6')}" + (f"（{desc}）" if desc else ""))
    for pair in perm.get("UserIdGroupPairs") or []:
        if not isinstance(pair, dict):
            continue
        desc = pair.get("Description")
        out.append(f"SG参照 {pair.get('GroupId')}" + (f"（{desc}）" if desc else ""))
    for pfx in perm.get("PrefixListIds") or []:
        if not isinstance(pfx, dict):
            continue
        out.append(f"プレフィックスリスト {pfx.get('PrefixListId')}")
    return out or ["（送信元の記載なし）"]


def perm_covers_port(perm: dict, port: int) -> bool:
    """その IpPermission が指定 TCP ポートを許可しているか。"""
    proto = str(perm.get("IpProtocol", "")).lower()
    if proto == "-1":
        return True
    if proto not in ("tcp", "6"):
        return False
    from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
    if from_port is None or to_port is None:
        return True
    try:
        return int(from_port) <= port <= int(to_port)
    except (TypeError, ValueError):
        return False


def is_open_to_world(source: str) -> bool:
    """送信元文字列が 0.0.0.0/0 または ::/0 を含むか。"""
    return source.startswith("0.0.0.0/0") or source.startswith("::/0")


def parse_dt(value: Any) -> _dt.datetime | None:
    """ISO 文字列（末尾 Z や +09:00 を含む）を datetime に直す。失敗したら None。"""
    if isinstance(value, (int, float)):
        try:
            return _dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # "2024-01-02T03:04:05.000+0000" のようなコロン無しオフセットに対応する
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    try:
        return _dt.datetime.fromisoformat(text)
    except ValueError:
        try:
            return _dt.datetime.fromisoformat(text[:19])
        except ValueError:
            return None


def days_since(value: Any) -> int | None:
    """ISO 日時から今日までの経過日数。"""
    parsed = parse_dt(value)
    if parsed is None:
        return None
    return (_TODAY - parsed.date()).days


def net_of(cidr: Any):
    """CIDR 文字列を ip_network にする。失敗したら None。"""
    if not isinstance(cidr, str) or not cidr:
        return None
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def host_section(inv: dict) -> dict:
    """host-probe の結果（awsprobe host-probe が追記する）。"""
    return _sect(inv, "host")


def host_instances(inv: dict) -> dict:
    """host セクションの instances（{instance-id: {...}}）。"""
    value = host_section(inv).get("instances")
    return value if isinstance(value, dict) else {}


# ===========================================================================
# 最優先（切離し日程・安全性に直結）
# ===========================================================================


@question(
    "Q1",
    "WAF は導入されているか。無い場合、本番公開サービスとして許容できるか",
    CAT_TOP,
    requires=("edge",),
)
def q1_waf(inv: dict) -> Answer:
    """WAFv2 Web ACL の有無と、ALB / CloudFront への関連付けを判定する。

    CLOUDFRONT スコープでは ListResourcesForWebACL が使えず
    `AssociatedResourceArns` が常に空になる（edge.py の実装コメント参照）ため、
    CloudFront 側の関連付けは `cloudfront_distributions[].WebACLId` で判定する。
    """
    acls = _dicts(inv, "edge", "wafv2_web_acls")
    load_balancers = _dicts(inv, "edge", "load_balancers")
    distributions = _dicts(inv, "edge", "cloudfront_distributions")
    denied = denied_for(inv, ("wafv2",))

    if not acls and denied:
        summary, details = no_data("WAFv2 Web ACL の一覧", inv, ("wafv2",))
        return Answer("", "", "", NO_DATA, summary, details, ["edge.wafv2_web_acls", "errors"])

    evidence = ["edge.wafv2_web_acls"]
    details: list[str] = []

    # 関連付け済み ARN の集合（REGIONAL スコープのみ取得できる）
    associated: set[str] = set()
    acl_rows: list[list[Any]] = []
    for i, acl in enumerate(acls):
        arns = [a for a in (acl.get("AssociatedResourceArns") or []) if isinstance(a, str)]
        associated.update(arns)
        acl_rows.append(
            [
                acl.get("Name"),
                acl.get("Scope"),
                acl.get("Id"),
                len(arns) if acl.get("Scope") == "REGIONAL" else "取得不可(API制約)",
                ", ".join(arns[:3]) or "—",
            ]
        )
        evidence.append(f"edge.wafv2_web_acls[{i}].AssociatedResourceArns")

    if acl_rows:
        details.append("**Web ACL 一覧**")
        details.extend(
            table(["名前", "スコープ", "ID", "関連リソース数", "関連 ARN（先頭3件）"], acl_rows)
        )

    # ALB 側の判定
    alb_rows: list[list[Any]] = []
    unprotected: list[str] = []
    for i, lb in enumerate(load_balancers):
        arn = lb.get("LoadBalancerArn") or ""
        name = lb.get("LoadBalancerName") or arn
        protected = arn in associated
        alb_rows.append([name, lb.get("Type"), lb.get("Scheme"), "あり" if protected else "**なし**"])
        if not protected:
            unprotected.append(str(name))
        evidence.append(f"edge.load_balancers[{i}].LoadBalancerArn")
    if alb_rows:
        details.append("")
        details.append("**ALB / NLB への WAF 関連付け**")
        details.extend(table(["ロードバランサ", "種別", "公開範囲", "WAF"], alb_rows))

    # CloudFront 側の判定
    cf_rows: list[list[Any]] = []
    cf_unprotected: list[str] = []
    for i, dist in enumerate(distributions):
        web_acl_id = dist.get("WebACLId") or ""
        aliases = (dist.get("Aliases") or {}).get("Items") or []
        cf_rows.append(
            [
                dist.get("Id"),
                dist.get("DomainName"),
                ", ".join(str(a) for a in aliases) or "—",
                web_acl_id or "**なし**",
            ]
        )
        if not web_acl_id:
            cf_unprotected.append(str(dist.get("Id")))
        evidence.append(f"edge.cloudfront_distributions[{i}].WebACLId")
    if cf_rows:
        details.append("")
        details.append("**CloudFront への WAF 関連付け**")
        details.extend(table(["ID", "ドメイン", "別名", "WebACLId"], cf_rows))

    if not acls:
        summary = (
            "**WAF は導入されていない。** REGIONAL・CLOUDFRONT のどちらのスコープにも "
            "WAFv2 Web ACL が 1 件も存在しない。"
            f"ALB/NLB {len(load_balancers)} 本・CloudFront {len(distributions)} 本が"
            "すべて WAF 無しで公開されている。"
        )
        details.append("")
        details.append(
            "- 「本番公開サービスとして許容できるか」は**経営判断**であり、"
            "本ツールでは判定しない。上表を判断材料として使うこと。"
        )
        return Answer("", "", "", ANSWERED, summary, details, evidence)

    if unprotected or cf_unprotected:
        summary = (
            f"WAFv2 Web ACL は {len(acls)} 件存在するが、"
            f"ALB/NLB {len(unprotected)} 本・CloudFront {len(cf_unprotected)} 本が"
            "未関連付けのまま公開されている。"
        )
        return Answer("", "", "", PARTIAL, summary, details, evidence, manual_steps=(
            "未関連付けの公開リソースについて、WAF を付けない理由（費用・誤検知懸念など）を"
            "運用側に確認し、経営判断として残すこと。"
        ))

    summary = (
        f"WAFv2 Web ACL が {len(acls)} 件あり、"
        f"ALB/NLB {len(load_balancers)} 本・CloudFront {len(distributions)} 本すべてに"
        "関連付けられている。"
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q8",
    "ポート22を許可している送信元IPの一覧。監視ベンダー側のIPは含まれているか",
    CAT_TOP,
    requires=("network",),
)
def q8_ssh_sources(inv: dict) -> Answer:
    """全 SG の IpPermissions から TCP/22 を許可しているルールを抽出する。"""
    groups = _dicts(inv, "network", "security_groups")
    if not groups:
        summary, details = no_data("セキュリティグループ", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["network.security_groups"])

    rows: list[list[Any]] = []
    evidence: list[str] = []
    world_open: list[str] = []
    for i, sg in enumerate(groups):
        for j, perm in enumerate(sg.get("IpPermissions") or []):
            if not isinstance(perm, dict) or not perm_covers_port(perm, 22):
                continue
            for source in perm_sources(perm):
                flagged = is_open_to_world(source)
                rows.append(
                    [
                        sg_label(sg),
                        sg.get("VpcId"),
                        port_label(perm),
                        f"**{source}（全世界に開放）**" if flagged else source,
                    ]
                )
                if flagged:
                    world_open.append(sg_label(sg))
            evidence.append(f"network.security_groups[{i}].IpPermissions[{j}]")

    if not rows:
        return Answer(
            "",
            "",
            "",
            ANSWERED,
            f"**ポート22を許可しているセキュリティグループは存在しない**（SG {len(groups)} 本を全走査）。"
            "SSH は SG レベルでは開いていない。",
            ["- 全 SG の IpPermissions を TCP/22 を含むルールで絞り込んだ結果が 0 件。"],
            ["network.security_groups"],
        )

    details = ["**ポート22を許可しているルール**"]
    details.extend(table(["セキュリティグループ", "VPC", "プロトコル/ポート", "送信元"], rows))
    if world_open:
        details.append("")
        details.append(
            "- **0.0.0.0/0 または ::/0 からの SSH を許可している SG がある: "
            + "、".join(sorted(set(world_open)))
            + "**。踏み台なしの直接 SSH 構成と合わせて最優先の是正対象。"
        )

    summary = (
        f"ポート22を許可しているルールが {len(rows)} 件ある"
        f"（SG {len(set(r[0] for r in rows))} 本）。"
        + ("**うち全世界開放あり。**" if world_open else "全世界開放（0.0.0.0/0）は無い。")
        + " ただし各送信元IPが 監視ベンダーのものかは AWS 側からは判別できない。"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "監視ベンダーに「保守作業で使用する送信元グローバルIP」の開示を求め、"
            "上表の CIDR と突き合わせること。突き合わない CIDR は"
            "発注元／開発ベンダー／退職者のいずれに属するかを個別に確認する。"
        ),
    )


@question(
    "Q9",
    "各EC2の authorized_keys の公開鍵は何個で、誰が秘密鍵を持つか",
    CAT_TOP,
    requires=("compute",),
)
def q9_authorized_keys(inv: dict) -> Answer:
    """起動時に指定されたキーペアまでは API で答えられる。

    `~/.ssh/authorized_keys` に後から追記された鍵は AWS API では原理的に見えない。
    `host` セクション（host-probe の結果）があればそれを反映して昇格させる。
    """
    instances = _dicts(inv, "compute", "instances")
    key_pairs = _dicts(inv, "compute", "key_pairs")
    hosts = host_instances(inv)

    if not instances and not key_pairs:
        summary, details = no_data("EC2 インスタンスとキーペア", inv, ("ec2",))
        return Answer(
            "",
            "",
            "",
            NO_DATA,
            summary,
            details,
            ["compute.instances", "compute.key_pairs"],
            manual_steps="各EC2に実際にログインし `wc -l ~/.ssh/authorized_keys` を実行する。",
        )

    evidence = ["compute.instances[].KeyName", "compute.key_pairs"]
    rows: list[list[Any]] = []
    for i, ins in enumerate(instances):
        probe = hosts.get(ins.get("InstanceId")) or {}
        results = probe.get("results") if isinstance(probe.get("results"), dict) else {}
        keys_result = ""
        for name, res in (results or {}).items():
            if "authorized_keys" in str(name) and isinstance(res, dict):
                keys_result = str(res.get("stdout") or "").strip()
                break
        rows.append(
            [
                _tag(ins) or ins.get("InstanceId"),
                ins.get("InstanceId"),
                ins.get("KeyName") or "**起動時キーペア指定なし**",
                keys_result or "未取得",
            ]
        )
        evidence.append(f"compute.instances[{i}].KeyName")

    details = ["**起動時に指定されたキーペア**"]
    details.extend(table(["インスタンス", "ID", "KeyName", "authorized_keys 実測"], rows))

    if key_pairs:
        details.append("")
        details.append("**アカウントに登録されているキーペア**")
        details.extend(
            table(
                ["キーペア名", "KeyPairId", "指紋", "作成日"],
                [
                    [
                        kp.get("KeyName"),
                        kp.get("KeyPairId"),
                        kp.get("KeyFingerprint"),
                        kp.get("CreateTime"),
                    ]
                    for kp in key_pairs
                ],
            )
        )

    manual = (
        "各EC2にログイン（または `awsprobe host-probe --enable-ssm`）して "
        "`ls -l /home/*/.ssh/authorized_keys` と各ファイルの行数・コメント欄を採取する。"
        "採取した公開鍵の指紋について、発注元／開発ベンダー／監視ベンダーのそれぞれに"
        "「この鍵の秘密鍵を保有しているか」を書面で確認すること（退職者の鍵の検出が目的）。"
    )

    if hosts:
        summary = (
            "host-probe の結果があるため、各EC2の authorized_keys の実測値まで確認できている。"
            "ただし**秘密鍵を誰が保有しているか**は鍵の指紋とヒアリングの突合が必要。"
        )
        return Answer("", "", "", PARTIAL, summary, details, evidence + ["host.instances"], manual)

    named = sum(1 for ins in instances if ins.get("KeyName"))
    summary = (
        f"**起動時に指定された鍵は判明する**（EC2 {len(instances)} 台中 {named} 台に KeyName あり）が、"
        "**後から `authorized_keys` に追記された鍵は AWS API では原理的に見えない。**"
        "鍵の個数と秘密鍵の保有者は EC2 内部調査とヒアリングが必要。"
    )
    return Answer("", "", "", PARTIAL, summary, details, evidence, manual)


@question(
    "Q23",
    "Global Accelerator はどのリソースを向いており、本番経路上か",
    CAT_TOP,
    requires=("edge", "network"),
)
def q23_global_accelerator(inv: dict) -> Answer:
    """アクセラレータ → リスナー → エンドポイントグループから向き先を確定する。"""
    accelerators = _dicts(inv, "edge", "global_accelerators")
    lb_by_arn = {
        lb.get("LoadBalancerArn"): lb
        for lb in _dicts(inv, "edge", "load_balancers")
        if lb.get("LoadBalancerArn")
    }
    ga_enis = [
        eni
        for eni in _dicts(inv, "network", "network_interfaces")
        if "global accelerator" in str(eni.get("Description") or "").lower()
    ]
    denied = denied_for(inv, ("globalaccelerator",))

    evidence = ["edge.global_accelerators", "network.network_interfaces[].Description"]
    details: list[str] = []

    if ga_enis:
        subnets = subnet_index(inv)
        details.append("**Global Accelerator 由来と判定した ENI**")
        details.extend(
            table(
                ["ENI", "サブネット", "プライベートIP", "Description"],
                [
                    [
                        eni.get("NetworkInterfaceId"),
                        subnet_label(subnets.get(eni.get("SubnetId"), {}))
                        if eni.get("SubnetId")
                        else "—",
                        eni.get("PrivateIpAddress"),
                        eni.get("Description"),
                    ]
                    for eni in ga_enis
                ],
            )
        )

    if not accelerators:
        if denied:
            summary, extra = no_data("Global Accelerator の一覧", inv, ("globalaccelerator",))
            return Answer("", "", "", NO_DATA, summary, extra + details, evidence)
        if ga_enis:
            return Answer(
                "",
                "",
                "",
                PARTIAL,
                f"**このアカウントに Global Accelerator は存在しない**が、"
                f"Description に 'Global Accelerator' を含む ENI が {len(ga_enis)} 本残っている。"
                "**別アカウントのアクセラレータがこの VPC の ALB を向いている可能性がある。**",
                details,
                evidence,
                manual_steps=(
                    "上表の ENI の `RequesterId` に記載されたアカウントIDの持ち主を特定し、"
                    "そのアカウントの Global Accelerator の向き先を開示させること。"
                ),
            )
        return Answer(
            "",
            "",
            "",
            ANSWERED,
            "**Global Accelerator は存在しない。** アクセラレータ0件、"
            "'Global Accelerator' を含む ENI も0本。本番経路上に GA は無い。",
            details,
            evidence,
        )

    rows: list[list[Any]] = []
    on_prod = False
    for i, acc in enumerate(accelerators):
        evidence.append(f"edge.global_accelerators[{i}].Listeners")
        ip_sets = acc.get("IpSets") or []
        static_ips = [
            ip
            for s in ip_sets
            if isinstance(s, dict)
            for ip in (s.get("IpAddresses") or [])
        ]
        for listener in acc.get("Listeners") or []:
            if not isinstance(listener, dict):
                continue
            ports = ", ".join(
                f"{p.get('FromPort')}-{p.get('ToPort')}"
                for p in listener.get("PortRanges") or []
                if isinstance(p, dict)
            )
            for group in listener.get("EndpointGroups") or []:
                if not isinstance(group, dict):
                    continue
                for endpoint in group.get("EndpointDescriptions") or []:
                    if not isinstance(endpoint, dict):
                        continue
                    endpoint_id = endpoint.get("EndpointId") or ""
                    target = lb_by_arn.get(endpoint_id)
                    if target is not None:
                        label = (
                            f"ALB `{target.get('LoadBalancerName')}`"
                            f"（{target.get('Scheme')}）"
                        )
                        if "prod" in str(target.get("LoadBalancerName") or "").lower():
                            on_prod = True
                    elif str(endpoint_id).startswith("eipalloc-"):
                        label = f"Elastic IP `{endpoint_id}`"
                    else:
                        label = f"`{endpoint_id}`"
                    rows.append(
                        [
                            acc.get("Name"),
                            acc.get("Enabled"),
                            ", ".join(str(ip) for ip in static_ips) or "—",
                            ports or "—",
                            group.get("EndpointGroupRegion"),
                            label,
                            endpoint.get("HealthState"),
                        ]
                    )

    header = ["アクセラレータ", "有効", "静的IP", "ポート", "エンドポイントリージョン", "向き先", "健全性"]
    # 向き先の表を先頭に置き、ENI の表はその後ろに回す
    details = ["**Global Accelerator の向き先**"] + table(header, rows) + [""] + details

    summary = (
        f"Global Accelerator が {len(accelerators)} 本あり、"
        f"エンドポイント {len(rows)} 件の向き先を特定した。"
        + ("**本番 ALB を向いており、本番経路上である。**" if on_prod else
           "本番 ALB を向いているものは検出されなかった。")
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q27",
    "`StackSetVendorMonitorStackSet-*` はどのアカウントからデプロイされ、どのIAMロール・権限を付与しているか",
    CAT_TOP,
    requires=("security",),
)
def q27_vendormonitor_stackset(inv: dict) -> Answer:
    """VendorMonitor StackSet の権限モデルと、外部アカウントを信頼している IAM ロールを列挙する。"""
    stack_sets = _dicts(inv, "security", "cloudformation_stack_sets")
    instances = _dicts(inv, "security", "stack_instances")
    # security.iam はサブ dict なので、roles はそこから取り出す
    iam = _map(inv, "security", "iam")
    roles = [r for r in (iam.get("roles") or []) if isinstance(r, dict)]
    account_id = str(_sect(inv, "meta").get("account_id") or "")

    denied = denied_for(inv, ("cloudformation", "iam"))
    if not stack_sets and not roles and denied:
        summary, details = no_data("StackSet と IAM ロール", inv, ("cloudformation", "iam"))
        return Answer(
            "",
            "",
            "",
            NO_DATA,
            summary,
            details,
            ["security.cloudformation_stack_sets", "security.iam.roles"],
        )

    evidence = ["security.cloudformation_stack_sets", "security.stack_instances", "security.iam.roles"]
    details: list[str] = []

    vendormonitor = [
        (i, s)
        for i, s in enumerate(stack_sets)
        if "vendormonitor" in str(s.get("StackSetName") or "").lower()
    ]
    if vendormonitor:
        details.append("**VendorMonitor StackSet の実体**")
        details.extend(
            table(
                ["StackSet名", "権限モデル", "管理ロール ARN", "実行ロール名", "Capabilities", "説明"],
                [
                    [
                        s.get("StackSetName"),
                        s.get("PermissionModel"),
                        s.get("AdministrationRoleARN"),
                        s.get("ExecutionRoleName"),
                        ", ".join(str(c) for c in (s.get("Capabilities") or [])) or "—",
                        s.get("Description"),
                    ]
                    for _, s in vendormonitor
                ],
            )
        )
        for i, _ in vendormonitor:
            evidence.append(f"security.cloudformation_stack_sets[{i}].AdministrationRoleARN")

        names = {str(s.get("StackSetName")) for _, s in vendormonitor}
        targets = [inst for inst in instances if str(inst.get("StackSetName")) in names]
        if targets:
            details.append("")
            details.append("**展開先（スタックインスタンス）**")
            details.extend(
                table(
                    ["StackSet名", "アカウント", "リージョン", "状態", "スタックID"],
                    [
                        [
                            inst.get("StackSetName"),
                            inst.get("Account"),
                            inst.get("Region"),
                            inst.get("Status"),
                            inst.get("StackId"),
                        ]
                        for inst in targets
                    ],
                )
            )
    else:
        details.append(
            f"- 名前に 'VendorMonitor' を含む StackSet は見つからなかった（StackSet 全{len(stack_sets)}本）。"
        )
        if stack_sets:
            details.extend(
                table(
                    ["StackSet名", "権限モデル", "説明"],
                    [[s.get("StackSetName"), s.get("PermissionModel"), s.get("Description")] for s in stack_sets],
                )
            )

    # 外部アカウントを信頼している IAM ロール（ベンダーに与えている権限の特定）
    external_rows: list[list[Any]] = []
    for i, role in enumerate(roles):
        accounts, services = _trusted_principals(role.get("AssumeRolePolicyDocument"))
        # マスク済み inventory では account_id も信頼先も擬似トークンになるため、
        # 単純な文字列比較ではなく is_self_account() で自他を判定する。
        external = sorted(a for a in accounts if a and not is_self_account(a, account_id))
        if not external:
            continue
        attached = _attached_policy_names(iam, role.get("RoleName"))
        external_rows.append(
            [
                role.get("RoleName"),
                ", ".join(external),
                ", ".join(sorted(services)) or "—",
                ", ".join(attached) or "（管理ポリシー無し／インラインのみ）",
            ]
        )
        evidence.append(f"security.iam.roles[{i}].AssumeRolePolicyDocument")

    if external_rows:
        details.append("")
        details.append("**外部アカウントを信頼している IAM ロール（ベンダーに与えている権限）**")
        details.extend(
            table(["ロール名", "信頼している外部アカウント", "信頼サービス", "付与管理ポリシー"], external_rows)
        )
    else:
        details.append("")
        details.append("- 外部アカウント（自アカウント以外）を信頼する IAM ロールは検出されなかった。")

    manual = (
        "監視ベンダーに対し、(1) StackSet を配信している管理アカウントID、(2) 上表の実行ロールに"
        "付与しているポリシーの本文（インラインポリシーを含む）、(3) 取得しているデータの種類と保存先、"
        "の3点を書面で開示させること。ポリシー本文は awsprobe では取得していない"
        "（iam:GetPolicyVersion / GetRolePolicy は収集対象外）。"
    )

    if vendormonitor or external_rows:
        summary = (
            f"VendorMonitor 系 StackSet {len(vendormonitor)} 本と、"
            f"外部アカウントを信頼する IAM ロール {len(external_rows)} 本を特定した。"
            "**デプロイ元アカウントと引き受けロールは判明したが、"
            "実際に付与されている権限（ポリシー本文）は未取得。**"
        )
        return Answer("", "", "", PARTIAL, summary, details, evidence, manual)

    summary = (
        "VendorMonitor 名義の StackSet も、外部アカウントを信頼する IAM ロールも検出されなかった。"
        "StackSet 経由での権限付与は現時点では確認できない。"
    )
    return Answer("", "", "", PARTIAL, summary, details, evidence, manual)


def _trusted_principals(document: Any) -> tuple[set[str], set[str]]:
    """AssumeRolePolicyDocument から信頼アカウントIDと信頼サービスを抽出する。

    botocore は本ドキュメントを dict にデコードして返すが、
    文字列のまま入っている場合にも備えて正規表現で拾う。

    アカウントは**生の12桁でもマスク済みトークンでも同じように扱う**。
    戻り値の集合には表記そのもの（12桁 / ``＜自アカウント＞`` /
    ``＜アカウント:xxxx＞``）が入るので、自分か外部かの判定は
    :func:`is_self_account` で行うこと。
    """
    accounts: set[str] = set()
    services: set[str] = set()
    if document is None:
        return accounts, services
    if isinstance(document, str):
        accounts.update(_IAM_ARN_ACCOUNT_RE.findall(document))
        accounts.update(_JSON_AWS_PRINCIPAL_RE.findall(document))
        services.update(re.findall(r'"Service"\s*:\s*"([\w.\-]+)"', document))
        return accounts, services
    if not isinstance(document, dict):
        return accounts, services

    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements or []:
        if not isinstance(statement, dict):
            continue
        principal = statement.get("Principal")
        if not isinstance(principal, dict):
            continue
        aws = principal.get("AWS")
        for value in [aws] if isinstance(aws, str) else (aws or []):
            if not isinstance(value, str):
                continue
            found = _IAM_STS_ARN_ACCOUNT_RE.search(value)
            if found:
                accounts.add(found.group(1))
            elif _BARE_ACCOUNT_RE.fullmatch(value):
                accounts.add(value)
        svc = principal.get("Service")
        for value in [svc] if isinstance(svc, str) else (svc or []):
            if isinstance(value, str):
                services.add(value)
    return accounts, services


def _attached_policy_names(iam: dict, role_name: Any) -> list[str]:
    """policies_attached_summary から、そのロールに付いている管理ポリシー名を取り出す。"""
    if not role_name:
        return []
    for entry in iam.get("policies_attached_summary") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("PrincipalType") != "role" or entry.get("Name") != role_name:
            continue
        return [
            str(p.get("PolicyName"))
            for p in entry.get("AttachedPolicies") or []
            if isinstance(p, dict) and p.get("PolicyName")
        ]
    return []


@question(
    "Q33",
    "demo / stg のサブネットが属する実際のAZ（名前は1c、手描き図は1d）",
    CAT_TOP,
    requires=("network",),
)
def q33_actual_az(inv: dict) -> Answer:
    """サブネット名に含まれる AZ 接尾辞と、実際の AvailabilityZone の一致を判定する。"""
    subnets = _dicts(inv, "network", "subnets")
    if not subnets:
        summary, details = no_data("サブネット", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["network.subnets"])

    rows: list[list[Any]] = []
    mismatches: list[str] = []
    matched: list[str] = []          # 名前と実AZを実際に照合できたもの
    unnamed: list[str] = []          # 名前に AZ 表記が無く照合できなかったもの
    actual_suffixes: set[str] = set()  # 実在する AZ の末尾文字（a/c/d...）
    evidence: list[str] = []
    for i, subnet in enumerate(subnets):
        name = _tag(subnet)
        az = str(subnet.get("AvailabilityZone") or "")
        label = name or str(subnet.get("SubnetId") or "(不明)")
        # 大文字の命名（"PROD-1A-APP" 等）も拾うため IGNORECASE にする。
        # 小文字限定のままだと正真正銘の不一致を見逃していた（I-4）。
        named = re.search(r"-1([a-d])(?:\b|$|-)", name, re.IGNORECASE)
        named_suffix = named.group(1).lower() if named else ""
        actual_suffix = az[-1].lower() if az else ""
        if actual_suffix:
            actual_suffixes.add(actual_suffix)
        if not named_suffix:
            verdict = "名前に AZ 表記なし（照合不可）"
            unnamed.append(label)
        elif not actual_suffix:
            verdict = "実際の AZ が取得できていない（照合不可）"
            unnamed.append(label)
        elif named_suffix != actual_suffix:
            verdict = f"**不一致（名前=1{named_suffix} / 実際={az}）**"
            mismatches.append(label)
        else:
            verdict = "一致"
            matched.append(label)
        rows.append(
            [
                name or "(名前なし)",
                subnet.get("SubnetId"),
                az or "—",
                subnet.get("AvailabilityZoneId"),
                verdict,
            ]
        )
        evidence.append(f"network.subnets[{i}].AvailabilityZone")

    details = ["**サブネット名の AZ 表記と実際の AZ**"]
    details.extend(table(["サブネット名", "SubnetId", "実際の AZ", "AZ ID", "判定"], rows))

    demo_stg = [
        r for r in rows if re.search(r"(demo|stg)", str(r[0]), re.IGNORECASE)
    ]
    if demo_stg:
        azs = sorted({str(r[2]) for r in demo_stg})
        details.append("")
        details.append(
            f"- demo / stg 系サブネット {len(demo_stg)} 本が実際に属する AZ: **{', '.join(azs)}**"
        )

    comparable = len(matched) + len(mismatches)
    details.append("")
    details.append(
        f"- 照合できたサブネット: **{comparable} 本**"
        f"（一致 {len(matched)} 本 / 不一致 {len(mismatches)} 本）。"
        f"名前に AZ 表記が無い等で照合できなかったもの: {len(unnamed)} 本。"
    )

    # 「1d のサブネットは存在しない」と書けるのは、実際に 1d が1本も無いときだけ。
    # 以前は無条件に「手描き図の 1d は現況と異なる」と出力していた（I-4）。
    has_1d = "d" in actual_suffixes
    if has_1d:
        details.append(
            "- 実際に末尾 `1d` の AZ に属するサブネットは**存在する**ため、"
            "手描き図の 1d という記載が誤りとは言えない。"
        )
    else:
        details.append(
            "- 末尾 `1d` の AZ に属するサブネットは**1本も無い**（手描き図の 1d は現況と異なる）。"
        )

    if mismatches:
        summary = (
            f"**サブネット名の AZ 表記と実際の AZ が食い違っているサブネットが {len(mismatches)} 本ある**"
            f"（{', '.join(mismatches[:5])}）。名前を信用してはならない。"
            f"（照合できたのは全{len(subnets)}本中 {comparable} 本）"
        )
        return Answer("", "", "", ANSWERED, summary, details, evidence)

    if comparable == 0:
        # 1本も照合できていないのに「すべて一致」と言い切るのは誤り。
        # 「名前が AZ を表していない」こと自体が調査結果なので partial で返す。
        summary = (
            f"サブネット {len(subnets)} 本のうち、名前に AZ 表記を持つものが 1 本も無く、"
            "**名前と実際の AvailabilityZone を照合できなかった**。"
            "命名から AZ を推定することはできないため、実 AZ は表の値で確認すること。"
        )
        return Answer("", "", "", PARTIAL, summary, details, evidence)

    summary = (
        f"名前に AZ 表記を持つサブネット {comparable} 本すべてで、"
        "名前の AZ 表記と実際の AvailabilityZone が一致している"
        f"（残り {len(unnamed)} 本は名前に AZ 表記が無く照合できない）。"
        + (
            ""
            if has_1d
            else "末尾 1d の AZ に属するサブネットは無く、手描き図の 1d という記載は現況と異なる。"
        )
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q36",
    "`vendor-agent` が何を、どの閾値で取得しているか",
    CAT_TOP,
    requires=("compute",),
)
def q36_vendor_agent(inv: dict) -> Answer:
    """ベンダー製監視エージェントの取得項目・閾値は 監視ベンダーの非開示情報のため API では取れない。

    SSM 到達性（= host-probe で常駐プロセスと設定ファイルまでは自動確認できるか）だけは
    inventory から示せる。
    """
    managed = _dicts(inv, "compute", "ssm_managed_instances")
    instances = _dicts(inv, "compute", "instances")
    hosts = host_instances(inv)

    evidence = ["compute.ssm_managed_instances", "compute.instances"]
    details: list[str] = []

    if managed:
        details.append("**SSM で到達できるインスタンス**")
        details.extend(
            table(
                ["インスタンスID", "プラットフォーム", "エージェント版", "PingStatus", "最終Ping"],
                [
                    [
                        m.get("InstanceId"),
                        f"{m.get('PlatformName')} {m.get('PlatformVersion')}".strip(),
                        m.get("AgentVersion"),
                        m.get("PingStatus"),
                        m.get("LastPingDateTime"),
                    ]
                    for m in managed
                ],
            )
        )
        reach = f"EC2 {len(instances)} 台中 {len(managed)} 台が SSM で到達可能。"
        guide = (
            "- **`awsprobe host-probe --enable-ssm` を実行すれば、"
            "vendor-agent の常駐プロセスと設定ファイルの有無までは自動確認できる**"
            "（プロセス一覧・`/etc` 配下の設定ファイル・常駐サービスの登録状況）。"
        )
    else:
        reach = f"SSM で到達できるインスタンスは0台（EC2 {len(instances)} 台）。"
        guide = (
            "- SSM 到達性が無いため `awsprobe host-probe --enable-ssm` は使えない。"
            "SSH による手動調査（`docs/manual-ssh-commands.md`）が必要。"
        )
    details.append("")
    details.append(guide)

    manual = (
        "監視ベンダーに対し、vendor-agent が取得しているメトリクスの一覧・取得間隔・"
        "アラート閾値・通知経路・保存期間を書面で開示させること（INFRA-718 の続き）。"
        "**取得項目と閾値は AWS API では原理的に取得できない。** "
        "並行して `awsprobe host-probe --enable-ssm` で常駐プロセス名と設定ファイルの所在を押さえ、"
        "開示内容と突き合わせること。"
    )

    if hosts:
        found: list[list[Any]] = []
        for instance_id, probe in hosts.items():
            results = probe.get("results") if isinstance(probe, dict) else None
            if not isinstance(results, dict):
                continue
            for name, res in results.items():
                if not isinstance(res, dict):
                    continue
                stdout = str(res.get("stdout") or "")
                if "vendor-agent" in stdout.lower() or "vendor-agent" in str(name).lower():
                    found.append([instance_id, name, res.get("status"), stdout[:120]])
        if found:
            details.append("")
            details.append("**host-probe で検出した vendor-agent 関連の痕跡**")
            details.extend(table(["インスタンス", "プローブ", "結果", "出力（先頭120文字）"], found))
        return Answer(
            "",
            "",
            "",
            PARTIAL,
            f"host-probe の結果から vendor-agent の常駐状況までは確認できた（{reach}）。"
            "**ただし取得項目と閾値は 監視ベンダーの非開示情報であり、開示要求が必要。**",
            details,
            evidence + ["host.instances"],
            manual,
        )

    return Answer(
        "",
        "",
        "",
        NEEDS_MANUAL,
        f"**vendor-agent の取得項目と閾値は AWS API では原理的に取得できない**（監視ベンダー製エージェントの内部設定）。"
        f"{reach} SSM 経由なら常駐の有無までは自動確認できる。",
        details,
        evidence,
        manual,
    )


@question(
    "Q37",
    "各サブネットの実際のCIDR（/20 と /24 が重複しており両立しない）",
    CAT_TOP,
    requires=("network",),
)
def q37_actual_cidr(inv: dict) -> Answer:
    """全サブネットの CIDR を列挙し、アドレス範囲の重複を計算する。"""
    subnets = _dicts(inv, "network", "subnets")
    vpcs = _dicts(inv, "network", "vpcs")
    if not subnets:
        summary, details = no_data("サブネット", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["network.subnets"])

    evidence: list[str] = []
    normal: list[list[Any]] = []
    default_rows: list[list[Any]] = []
    #: VpcId -> [(ラベル, ip_network), ...]。**重複判定は VPC 内でしか行わない**
    #: （別VPCに同じ CIDR があるのは正常な独立構成であり、重複ではない）。
    by_vpc: dict[str, list[tuple[str, Any]]] = {}
    ipv6_count = 0

    for i, subnet in enumerate(subnets):
        name = _tag(subnet) or "(名前なし)"
        cidr = subnet.get("CidrBlock")
        vpc_id = str(subnet.get("VpcId") or "(VpcId 不明)")
        label = f"{name} ({subnet.get('SubnetId')})"
        network = net_of(cidr)
        if network is not None:
            by_vpc.setdefault(vpc_id, []).append((label, network))

        # IPv6 も一覧と重複判定の対象にする。IPv4 しか見ていないと
        # 「重複は存在しない」という断定が IPv6 について無根拠になる（I-4）。
        ipv6_blocks: list[str] = []
        for assoc in subnet.get("Ipv6CidrBlockAssociationSet") or []:
            if not isinstance(assoc, dict):
                continue
            block = assoc.get("Ipv6CidrBlock")
            if not block:
                continue
            ipv6_blocks.append(str(block))
            v6 = net_of(block)
            if v6 is not None:
                by_vpc.setdefault(vpc_id, []).append((f"{label} [IPv6]", v6))
        if ipv6_blocks:
            ipv6_count += 1
            evidence.append(f"network.subnets[{i}].Ipv6CidrBlockAssociationSet")

        row = [
            name,
            subnet.get("SubnetId"),
            vpc_id,
            cidr,
            ", ".join(ipv6_blocks) or "—",
            subnet.get("AvailabilityZone"),
            subnet.get("AvailableIpAddressCount"),
            subnet.get("MapPublicIpOnLaunch"),
        ]
        if subnet.get("DefaultForAz"):
            default_rows.append(row)
        else:
            normal.append(row)
        evidence.append(f"network.subnets[{i}].CidrBlock")

    headers = [
        "サブネット名", "SubnetId", "VpcId", "IPv4 CIDR", "IPv6 CIDR",
        "AZ", "空きIP数", "自動パブリックIP",
    ]
    details = [f"**サブネット CIDR 一覧（全{len(subnets)}本）**"]
    details.extend(table(headers, normal))
    if default_rows:
        details.append("")
        details.append(f"**デフォルトVPC由来のサブネット（DefaultForAz=True、{len(default_rows)}本）**")
        details.extend(table(headers, default_rows))
    details.append("")
    details.append(
        f"- IPv6 CIDR を持つサブネット: **{ipv6_count} 本**"
        + ("（IPv6 も下の重複判定の対象にしている）。" if ipv6_count else "（IPv6 は未使用）。")
    )

    # -- 重複計算（**VPC ごとに閉じて行う**）---------------------------------
    overlaps: list[list[Any]] = []
    per_vpc_overlaps: dict[str, int] = {}
    for vpc_id in sorted(by_vpc):
        parsed = by_vpc[vpc_id]
        found = 0
        for i in range(len(parsed)):
            for j in range(i + 1, len(parsed)):
                (label_a, net_a), (label_b, net_b) = parsed[i], parsed[j]
                if net_a.version != net_b.version:
                    continue
                if net_a.overlaps(net_b):
                    relation = (
                        "完全一致"
                        if net_a == net_b
                        else ("前者が後者を包含" if net_a.supernet_of(net_b) else
                              "後者が前者を包含" if net_b.supernet_of(net_a) else "部分重複")
                    )
                    overlaps.append(
                        [vpc_id, label_a, str(net_a), label_b, str(net_b), relation]
                    )
                    found += 1
        per_vpc_overlaps[vpc_id] = found

    if overlaps:
        details.append("")
        details.append(
            "**アドレス範囲の重複（ipaddress モジュールで計算／同一 VPC 内のみ）**"
        )
        details.extend(
            table(
                ["VpcId", "サブネットA", "CIDR A", "サブネットB", "CIDR B", "関係"],
                overlaps,
            )
        )
    else:
        details.append("")
        details.append(
            "- **CIDR の重複は検出されなかった**"
            "（同一 VPC 内の全ペアを IPv4・IPv6 ともに ipaddress で突合済み）。"
        )

    if len(by_vpc) > 1:
        details.append("")
        details.append("**VPC ごとの重複件数**")
        details.extend(
            table(
                ["VpcId", "判定対象 CIDR 数", "重複ペア数"],
                [
                    [vpc_id, len(by_vpc[vpc_id]), per_vpc_overlaps.get(vpc_id, 0)]
                    for vpc_id in sorted(by_vpc)
                ],
            )
        )
        details.append("")
        details.append(
            "- **別々の VPC に同じ CIDR があっても重複とは扱っていない。**"
            "VPC はアドレス空間が独立しており、ピアリング／Transit Gateway で"
            "接続しない限り衝突しないため。"
        )

    if vpcs:
        vpc_rows: list[list[Any]] = []
        for i, vpc in enumerate(vpcs):
            for assoc in vpc.get("CidrBlockAssociationSet") or []:
                if not isinstance(assoc, dict):
                    continue
                state = assoc.get("CidrBlockState") or {}
                vpc_rows.append(
                    [
                        vpc.get("VpcId"),
                        vpc.get("IsDefault"),
                        "IPv4",
                        assoc.get("CidrBlock"),
                        state.get("State") if isinstance(state, dict) else "—",
                    ]
                )
            for assoc in vpc.get("Ipv6CidrBlockAssociationSet") or []:
                if not isinstance(assoc, dict):
                    continue
                state = assoc.get("Ipv6CidrBlockState") or {}
                vpc_rows.append(
                    [
                        vpc.get("VpcId"),
                        vpc.get("IsDefault"),
                        "IPv6",
                        assoc.get("Ipv6CidrBlock"),
                        state.get("State") if isinstance(state, dict) else "—",
                    ]
                )
            evidence.append(f"network.vpcs[{i}].CidrBlockAssociationSet")
        if vpc_rows:
            details.append("")
            details.append("**VPC の CIDR 関連付け**")
            details.extend(
                table(["VpcId", "デフォルトVPC", "IP版", "CIDR", "状態"], vpc_rows)
            )

    scope = (
        f"{len(by_vpc)} つの VPC それぞれの内部で"
        if len(by_vpc) > 1
        else "同一 VPC 内で"
    )
    summary = (
        f"サブネット {len(subnets)} 本の実際の CIDR をすべて列挙した"
        f"（うちデフォルトVPC由来 {len(default_rows)} 本、IPv6 を持つもの {ipv6_count} 本）。"
        + (
            f"**アドレス範囲の重複が {len(overlaps)} ペアある。**"
            if overlaps
            else f"{scope}突合した範囲では**重複は存在しない**"
            "（IPv4・IPv6 の全ペアを突合済み。別 VPC 間の同一 CIDR は重複として数えない）。"
        )
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q38",
    "NAT Gateway の実際の台数（自動生成図1台 vs 手描き図4台）",
    CAT_TOP,
    requires=("network",),
)
def q38_nat_gateways(inv: dict) -> Answer:
    """NAT の台数・配置 AZ と、どのサブネットがどの NAT を使っているかを逆引きする。"""
    nats = _dicts(inv, "network", "nat_gateways")
    subnets = subnet_index(inv)
    route_tables = _dicts(inv, "network", "route_tables")

    if not nats and not route_tables:
        summary, details = no_data("NAT Gateway とルートテーブル", inv, ("ec2",))
        return Answer(
            "", "", "", NO_DATA, summary, details, ["network.nat_gateways", "network.route_tables"]
        )

    evidence: list[str] = []
    nat_az: dict[str, str] = {}
    #: State ごとの行。**台数は available のものだけで数える。**
    #: `describe_nat_gateways` は削除後およそ1時間 `deleted` を返し続けるため、
    #: State を無視すると「自動生成図1台 vs 手描き図4台」の確定を誤る（I-4）。
    available_rows: list[list[Any]] = []
    transitional_rows: list[list[Any]] = []   # pending / deleting（遷移中）
    gone_rows: list[list[Any]] = []           # deleted / failed（実在しない）
    available_ids: set[str] = set()
    nat_state: dict[str, str] = {}

    for i, nat in enumerate(nats):
        subnet = subnets.get(nat.get("SubnetId"), {})
        az = str(subnet.get("AvailabilityZone") or "")
        nat_id = str(nat.get("NatGatewayId") or "")
        state = str(nat.get("State") or "").lower()
        nat_az[nat_id] = az
        nat_state[nat_id] = state or "不明"
        public_ips = [
            addr.get("PublicIp")
            for addr in nat.get("NatGatewayAddresses") or []
            if isinstance(addr, dict) and addr.get("PublicIp")
        ]
        row = [
            _tag(nat) or nat_id,
            nat_id,
            subnet_label(subnet),
            az or "不明",
            nat.get("State"),
            ", ".join(str(ip) for ip in public_ips) or "—",
        ]
        if state == "available":
            available_rows.append(row)
            available_ids.add(nat_id)
        elif state in ("pending", "deleting"):
            transitional_rows.append(row)
        else:
            # deleted / failed / 状態不明。実稼働していないので台数に入れない。
            gone_rows.append(row)
        evidence.append(f"network.nat_gateways[{i}].State")
        evidence.append(f"network.nat_gateways[{i}].SubnetId")

    nat_count = len(available_rows)
    headers = ["名前", "NatGatewayId", "配置サブネット", "AZ", "状態", "EIP"]
    details = [f"**稼働中の NAT Gateway（State=available、{nat_count}台）**"]
    if available_rows:
        details.extend(table(headers, available_rows))
    else:
        details.append("- State=available の NAT Gateway は 1 台も無い。")
    if transitional_rows:
        details.append("")
        details.append(
            f"**遷移中の NAT Gateway（pending / deleting、{len(transitional_rows)}台）**"
        )
        details.extend(table(headers, transitional_rows))
        details.append("")
        details.append(
            "- 遷移中のものがあるため、**台数は数分後に変わりうる**（確定値ではない）。"
        )
    if gone_rows:
        details.append("")
        details.append(
            f"**既に存在しない NAT Gateway（deleted / failed、{len(gone_rows)}台）**"
        )
        details.extend(table(headers, gone_rows))
        details.append("")
        details.append(
            "- `describe_nat_gateways` は削除後およそ1時間 `deleted` のレコードを返し続ける。"
            "**上記は台数に数えていない。**"
        )

    # ルートテーブル逆引き
    usage_rows: list[list[Any]] = []
    cross_az: list[str] = []
    stale_routes: list[str] = []   # 消えた／遷移中の NAT を指しているルート
    for i, rtb in enumerate(route_tables):
        nat_targets = [
            str(route.get("NatGatewayId"))
            for route in rtb.get("Routes") or []
            if isinstance(route, dict) and route.get("NatGatewayId")
        ]
        if not nat_targets:
            continue
        evidence.append(f"network.route_tables[{i}].Routes")
        associated = [
            assoc.get("SubnetId")
            for assoc in rtb.get("Associations") or []
            if isinstance(assoc, dict) and assoc.get("SubnetId")
        ]
        if not associated:
            usage_rows.append(
                [_tag(rtb) or rtb.get("RouteTableId"), "（サブネット関連付けなし）", "—", ", ".join(nat_targets), "—"]
            )
            continue
        for subnet_id in associated:
            subnet = subnets.get(subnet_id, {})
            subnet_az = str(subnet.get("AvailabilityZone") or "")
            for nat_id in nat_targets:
                target_az = nat_az.get(nat_id, "")
                if nat_id in nat_state and nat_id not in available_ids:
                    # 既に消えた／遷移中の NAT を指すルート。クロスAZの件数には数えない。
                    verdict = (
                        f"**向き先 NAT が available ではない"
                        f"（State={nat_state.get(nat_id)}）**"
                    )
                    stale_routes.append(f"{subnet_label(subnet)} → {nat_id}")
                elif subnet_az and target_az and subnet_az != target_az:
                    verdict = f"**クロスAZ（{subnet_az} → {target_az}）**"
                    cross_az.append(f"{subnet_label(subnet)} → {nat_id}")
                elif subnet_az and target_az:
                    verdict = "同一AZ"
                else:
                    verdict = "判定不可"
                usage_rows.append(
                    [
                        _tag(rtb) or rtb.get("RouteTableId"),
                        subnet_label(subnet),
                        subnet_az or "—",
                        nat_id,
                        verdict,
                    ]
                )

    if usage_rows:
        details.append("")
        details.append("**どのサブネットがどの NAT を使っているか（ルートテーブルからの逆引き）**")
        details.extend(
            table(["ルートテーブル", "サブネット", "サブネットAZ", "向き先 NAT", "AZ判定"], usage_rows)
        )
    else:
        details.append("")
        details.append("- NAT Gateway を参照しているルートは1本も見つからなかった。")

    if stale_routes:
        details.append("")
        details.append(
            f"- 既に available でない NAT を指しているルートが {len(stale_routes)} 本ある"
            "（ブラックホール経路の可能性。クロスAZの件数には数えていない）。"
        )

    az_summary = (
        ", ".join(sorted({nat_az.get(n, "") for n in available_ids if nat_az.get(n)}))
        or "不明"
    )
    summary = (
        f"**稼働中（State=available）の NAT Gateway は {nat_count} 台**"
        f"（配置 AZ: {az_summary}）。"
        + (
            f"**うち {len(cross_az)} 経路がクロスAZ通信になっており、AZ間転送料金が発生している。**"
            if cross_az
            else "クロスAZの NAT 利用は検出されなかった。"
        )
    )
    if gone_rows:
        summary += (
            f"（inventory には deleted / failed の NAT が {len(gone_rows)} 件残っているが、"
            "実在しないため台数に含めていない。）"
        )

    if transitional_rows:
        # 遷移中のものがある間は台数が確定しないので answered とは言わない。
        summary += (
            f"**ただし pending / deleting の NAT が {len(transitional_rows)} 台あり、"
            "台数は確定していない。**数分後に再取得して確認すること。"
        )
        return Answer("", "", "", PARTIAL, summary, details, evidence)

    return Answer("", "", "", ANSWERED, summary, details, evidence)


# ===========================================================================
# ネットワーク・セキュリティ
# ===========================================================================


@question(
    "Q5",
    "各RDS用SGは、どの送信元（SG参照かCIDRか）からどのポートを許可しているか",
    CAT_NET,
    requires=("database", "network"),
)
def q5_rds_security_groups(inv: dict) -> Answer:
    """RDS に付いている SG を解決し、許可ルールを送信元種別つきで展開する。"""
    db_instances = _dicts(inv, "database", "db_instances")
    groups = sg_index(inv)
    vpc_cidrs: list[Any] = []
    for vpc in _dicts(inv, "network", "vpcs"):
        for assoc in vpc.get("CidrBlockAssociationSet") or []:
            if isinstance(assoc, dict):
                network = net_of(assoc.get("CidrBlock"))
                if network is not None:
                    vpc_cidrs.append(network)
        network = net_of(vpc.get("CidrBlock"))
        if network is not None and network not in vpc_cidrs:
            vpc_cidrs.append(network)

    if not db_instances:
        summary, details = no_data("RDS インスタンス", inv, ("rds",))
        return Answer("", "", "", NO_DATA, summary, details, ["database.db_instances"])

    rows: list[list[Any]] = []
    evidence: list[str] = []
    broad: list[str] = []
    world: list[str] = []
    for i, db in enumerate(db_instances):
        evidence.append(f"database.db_instances[{i}].VpcSecurityGroups")
        identifier = db.get("DBInstanceIdentifier")
        attached = [
            g for g in db.get("VpcSecurityGroups") or [] if isinstance(g, dict)
        ]
        if not attached:
            rows.append([identifier, "（SG 未取得）", "—", "—", "—"])
            continue
        for ref in attached:
            sg = groups.get(ref.get("VpcSecurityGroupId"))
            if sg is None:
                rows.append(
                    [identifier, f"{ref.get('VpcSecurityGroupId')}（SG 定義が未取得）", "—", "—", "—"]
                )
                continue
            permissions = [p for p in sg.get("IpPermissions") or [] if isinstance(p, dict)]
            if not permissions:
                rows.append([identifier, sg_label(sg), "（インバウンド許可なし）", "—", "—"])
                continue
            for perm in permissions:
                for source in perm_sources(perm):
                    kind = "SG参照" if source.startswith("SG参照") else (
                        "プレフィックスリスト" if source.startswith("プレフィックスリスト") else "CIDR"
                    )
                    note = ""
                    if kind == "CIDR":
                        network = net_of(source.split("（")[0])
                        if is_open_to_world(source):
                            note = "**全世界に開放**"
                            world.append(f"{identifier}/{sg.get('GroupId')}")
                        elif network is not None and any(
                            network.version == v.version and network.supernet_of(v)
                            for v in vpc_cidrs
                        ):
                            note = "**VPC CIDR 全体を許可**"
                            broad.append(f"{identifier}/{sg.get('GroupId')}")
                    rows.append([identifier, sg_label(sg), port_label(perm), f"{kind}: {source}", note or "—"])

    details = ["**RDS に付いているセキュリティグループのインバウンド許可**"]
    details.extend(table(["DB識別子", "セキュリティグループ", "プロトコル/ポート", "送信元", "所見"], rows))

    notes: list[str] = []
    if world:
        notes.append(f"- **0.0.0.0/0 からの許可がある: {', '.join(sorted(set(world)))}**")
    if broad:
        notes.append(f"- **VPC CIDR 全体を許可している: {', '.join(sorted(set(broad)))}**")
    if not world and not broad:
        notes.append("- VPC CIDR 全体を許可しているルール・全世界開放のルールは検出されなかった。")
    details.append("")
    details.extend(notes)

    sg_ref = sum(1 for r in rows if str(r[3]).startswith("SG参照"))
    cidr_ref = sum(1 for r in rows if str(r[3]).startswith("CIDR"))
    summary = (
        f"RDS {len(db_instances)} 台に付いた SG の許可ルール {len(rows)} 件を展開した"
        f"（SG参照 {sg_ref} 件 / CIDR指定 {cidr_ref} 件）。"
        + (
            "**VPC CIDR 全体または全世界を許可している過剰開放がある。**"
            if (world or broad)
            else "過剰開放（VPC CIDR 全体・全世界）は検出されなかった。"
        )
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q10",
    "`acl-43d54d25` のルール内容。デフォルト全許可か、明示的 deny があるか",
    CAT_NET,
    requires=("network",),
)
def q10_network_acl(inv: dict) -> Answer:
    """NACL の Entries を展開し、デフォルト（全許可）のままかを判定する。"""
    acls = _dicts(inv, "network", "network_acls")
    if not acls:
        summary, details = no_data("ネットワークACL", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["network.network_acls"])

    subnets = subnet_index(inv)
    evidence: list[str] = []
    details: list[str] = []
    non_default: list[str] = []

    for i, acl in enumerate(acls):
        evidence.append(f"network.network_acls[{i}].Entries")
        acl_id = acl.get("NetworkAclId")
        entries = [e for e in acl.get("Entries") or [] if isinstance(e, dict)]
        associations = [
            a for a in acl.get("Associations") or [] if isinstance(a, dict)
        ]
        # 既定 NACL は「100: allow 0.0.0.0/0」と「32767: deny 0.0.0.0/0」を
        # 受信・送信それぞれ1本ずつ持つだけの計4本。
        is_default_shape = len(entries) == 4 and all(
            str(e.get("CidrBlock")) in ("0.0.0.0/0", "::/0") for e in entries
        ) and all(
            (e.get("RuleNumber") in (100, 32767)) for e in entries
        )
        explicit_deny = [
            e for e in entries
            if e.get("RuleAction") == "deny" and e.get("RuleNumber") != 32767
        ]
        if not is_default_shape or explicit_deny:
            non_default.append(str(acl_id))

        details.append(
            f"**{_tag(acl) or acl_id}（{acl_id}）** — "
            f"既定ACL={'はい' if acl.get('IsDefault') else 'いいえ'} / "
            f"関連付けサブネット {len(associations)} 本 / ルール {len(entries)} 本 / "
            f"明示 deny {len(explicit_deny)} 本"
        )
        details.extend(
            table(
                ["ルール番号", "方向", "アクション", "プロトコル", "ポート", "CIDR"],
                [
                    [
                        e.get("RuleNumber"),
                        "送信(Egress)" if e.get("Egress") else "受信(Ingress)",
                        e.get("RuleAction"),
                        e.get("Protocol"),
                        (
                            f"{(e.get('PortRange') or {}).get('From')}-"
                            f"{(e.get('PortRange') or {}).get('To')}"
                            if isinstance(e.get("PortRange"), dict)
                            else "全ポート"
                        ),
                        e.get("CidrBlock") or e.get("Ipv6CidrBlock"),
                    ]
                    for e in sorted(entries, key=lambda x: (bool(x.get("Egress")), x.get("RuleNumber") or 0))
                ],
            )
        )
        if associations:
            names = [
                subnet_label(subnets.get(a.get("SubnetId"), {"SubnetId": a.get("SubnetId")}))
                for a in associations
            ]
            details.append(f"- 関連付けサブネット: {', '.join(names)}")
        details.append("")

    total_assoc = sum(
        len([a for a in acl.get("Associations") or [] if isinstance(a, dict)]) for acl in acls
    )
    if non_default:
        summary = (
            f"NACL は {len(acls)} 本（関連付け計 {total_assoc} 件）。"
            f"**うち {len(non_default)} 本はデフォルト全許可ではなく、明示的なルールが入っている。**"
        )
    else:
        summary = (
            f"NACL は {len(acls)} 本（関連付け計 {total_assoc} 件）で、"
            "**いずれもデフォルトの全許可（100:allow / 32767:deny の4本）のまま**。"
            "サブネット単位での遮断は現状できない。"
        )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


def _eni_rows(inv: dict, enis: list[dict]) -> list[list[Any]]:
    """ENI を用途推定つきの表の行にする。"""
    subnets = subnet_index(inv)
    rows: list[list[Any]] = []
    for eni in enis:
        attachment = eni.get("Attachment") if isinstance(eni.get("Attachment"), dict) else {}
        attached_to = (
            attachment.get("InstanceId")
            or attachment.get("InstanceOwnerId")
            or ("未アタッチ" if eni.get("Status") == "available" else "—")
        )
        rows.append(
            [
                eni.get("NetworkInterfaceId"),
                subnet_label(subnets.get(eni.get("SubnetId"), {"SubnetId": eni.get("SubnetId")})),
                eni.get("InterfaceType"),
                eni.get("Status"),
                eni.get("RequesterId") or "—",
                attached_to,
                eni.get("Description") or "（説明なし）",
            ]
        )
    return rows


_ENI_HEADERS = ["ENI", "サブネット", "種別", "状態", "RequesterId", "アタッチ先", "Description"]


@question(
    "Q11",
    "`ex-spare-public/private-subnet-1d` は何のために作られたか。ENI 5本は何に紐づくか",
    CAT_NET,
    requires=("network",),
)
def q11_spare_subnet_enis(inv: dict) -> Answer:
    """名前に spare を含むサブネットの ENI を用途推定つきで列挙する。"""
    subnets = _dicts(inv, "network", "subnets")
    if not subnets:
        summary, details = no_data("サブネット", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["network.subnets"])

    spare_ids = {
        s.get("SubnetId")
        for s in subnets
        if "spare" in _tag(s).lower() and s.get("SubnetId")
    }
    enis = [
        eni
        for eni in _dicts(inv, "network", "network_interfaces")
        if eni.get("SubnetId") in spare_ids
    ]

    evidence = ["network.subnets", "network.network_interfaces"]
    details: list[str] = []

    if not spare_ids:
        return Answer(
            "",
            "",
            "",
            ANSWERED,
            "名前に 'spare' を含むサブネットは存在しない。設計資料 §5-2 の "
            "`ex-spare-*` は現況では確認できなかった（改名または削除済み）。",
            [f"- 走査したサブネット {len(subnets)} 本の Name タグに 'spare' を含むものは無し。"],
            evidence,
        )

    details.append(f"**spare 系サブネット（{len(spare_ids)}本）**")
    details.extend(
        table(
            ["サブネット名", "SubnetId", "CIDR", "AZ", "ENI数"],
            [
                [
                    _tag(s),
                    s.get("SubnetId"),
                    s.get("CidrBlock"),
                    s.get("AvailabilityZone"),
                    sum(1 for e in enis if e.get("SubnetId") == s.get("SubnetId")),
                ]
                for s in subnets
                if s.get("SubnetId") in spare_ids
            ],
        )
    )
    if enis:
        details.append("")
        details.append(f"**spare 系サブネットに存在する ENI（{len(enis)}本）**")
        details.extend(table(_ENI_HEADERS, _eni_rows(inv, enis)))
        requesters = sorted({str(e.get("RequesterId")) for e in enis if e.get("RequesterId")})
        if requesters:
            details.append("")
            details.append(
                f"- AWS サービスが作成した ENI（RequesterId あり）: {', '.join(requesters)}"
            )
    else:
        details.append("")
        details.append("- **spare 系サブネットに ENI は1本も存在しない**（削除候補）。")

    summary = (
        f"spare 系サブネット {len(spare_ids)} 本に ENI が {len(enis)} 本ぶら下がっており、"
        "各 ENI の Description / InterfaceType / RequesterId から所属サービスは特定できた。"
        "**ただし『何のために作られたか』という設計意図は当時の担当者に聞くしかない。**"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "開発ベンダー／監視ベンダーに、spare 系サブネットを作成した経緯（将来の拡張用か、"
            "検証の残骸か）を確認すること。ENI が0本なら削除可否の判断だけで済む。"
        ),
    )


@question(
    "Q12",
    "デフォルトVPC由来サブネットと `rtb-318fcf57` に、現在ENI・関連付けは残っているか",
    CAT_NET,
    requires=("network",),
)
def q12_default_subnet_leftovers(inv: dict) -> Answer:
    """DefaultForAz=True のサブネットの ENI と、ルートテーブル関連付けを確認する。"""
    subnets = _dicts(inv, "network", "subnets")
    if not subnets:
        summary, details = no_data("サブネット", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["network.subnets"])

    default_subnets = [s for s in subnets if s.get("DefaultForAz")]
    default_ids = {s.get("SubnetId") for s in default_subnets}
    enis = [
        eni
        for eni in _dicts(inv, "network", "network_interfaces")
        if eni.get("SubnetId") in default_ids
    ]

    evidence = [
        "network.subnets[].DefaultForAz",
        "network.network_interfaces[].SubnetId",
        "network.route_tables[].Associations",
    ]
    details: list[str] = []

    details.append(f"**デフォルトVPC由来のサブネット（DefaultForAz=True、{len(default_subnets)}本）**")
    details.extend(
        table(
            ["サブネット名", "SubnetId", "CIDR", "AZ", "ENI数"],
            [
                [
                    _tag(s) or "(名前なし)",
                    s.get("SubnetId"),
                    s.get("CidrBlock"),
                    s.get("AvailabilityZone"),
                    sum(1 for e in enis if e.get("SubnetId") == s.get("SubnetId")),
                ]
                for s in default_subnets
            ],
        )
        or ["- デフォルトVPC由来のサブネットは存在しない。"]
    )

    if enis:
        details.append("")
        details.append(f"**残存 ENI（{len(enis)}本）**")
        details.extend(table(_ENI_HEADERS, _eni_rows(inv, enis)))

    # ルートテーブルの関連付け
    rt_rows: list[list[Any]] = []
    subnets_by_id = subnet_index(inv)
    for rtb in _dicts(inv, "network", "route_tables"):
        associations = [a for a in rtb.get("Associations") or [] if isinstance(a, dict)]
        explicit = [a for a in associations if a.get("SubnetId")]
        main = any(a.get("Main") for a in associations)
        routes = [r for r in rtb.get("Routes") or [] if isinstance(r, dict)]
        rt_rows.append(
            [
                _tag(rtb) or rtb.get("RouteTableId"),
                rtb.get("RouteTableId"),
                "はい" if main else "いいえ",
                len(explicit),
                ", ".join(subnet_label(subnets_by_id.get(a.get("SubnetId"), {})) for a in explicit) or "—",
                len(routes),
            ]
        )
    if rt_rows:
        details.append("")
        details.append("**ルートテーブルのサブネット関連付け**")
        details.extend(
            table(["名前", "RouteTableId", "メイン", "明示関連付け数", "関連付けサブネット", "ルート数"], rt_rows)
        )

    if not default_subnets:
        summary = (
            "**DefaultForAz=True のサブネットは存在しない。** "
            "デフォルトVPC由来のサブネットは削除済み、または元から存在しない。"
        )
        return Answer("", "", "", ANSWERED, summary, details, evidence)

    if enis:
        summary = (
            f"デフォルトVPC由来のサブネット {len(default_subnets)} 本に、"
            f"**ENI が {len(enis)} 本残っている。そのまま削除すると通信断になる。**"
        )
    else:
        summary = (
            f"デフォルトVPC由来のサブネット {len(default_subnets)} 本に **ENI は残っていない**。"
            "ルートテーブルの関連付けだけを確認すれば削除できる。"
        )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q13",
    "各ルートテーブルの実際のルート。非本番も常時NAT経由か。クロスAZ通信料は発生しているか",
    CAT_NET,
    requires=("network",),
)
def q13_route_tables(inv: dict) -> Answer:
    """全ルートテーブルのルートを表形式で出し、NAT 経由の有無を判定する。"""
    route_tables = _dicts(inv, "network", "route_tables")
    if not route_tables:
        summary, details = no_data("ルートテーブル", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["network.route_tables"])

    subnets = subnet_index(inv)
    nat_az = {}
    for nat in _dicts(inv, "network", "nat_gateways"):
        subnet = subnets.get(nat.get("SubnetId"), {})
        nat_az[str(nat.get("NatGatewayId"))] = str(subnet.get("AvailabilityZone") or "")

    rows: list[list[Any]] = []
    evidence: list[str] = []
    nat_users: list[str] = []
    cross_az = 0
    for i, rtb in enumerate(route_tables):
        evidence.append(f"network.route_tables[{i}].Routes")
        name = _tag(rtb) or rtb.get("RouteTableId")
        associated = [
            subnet_label(subnets.get(a.get("SubnetId"), {}))
            for a in rtb.get("Associations") or []
            if isinstance(a, dict) and a.get("SubnetId")
        ]
        associated_azs = {
            str(subnets.get(a.get("SubnetId"), {}).get("AvailabilityZone") or "")
            for a in rtb.get("Associations") or []
            if isinstance(a, dict) and a.get("SubnetId")
        }
        for route in rtb.get("Routes") or []:
            if not isinstance(route, dict):
                continue
            target = (
                route.get("GatewayId")
                or route.get("NatGatewayId")
                or route.get("TransitGatewayId")
                or route.get("VpcPeeringConnectionId")
                or route.get("NetworkInterfaceId")
                or route.get("EgressOnlyInternetGatewayId")
                or "—"
            )
            note = ""
            if route.get("NatGatewayId"):
                nat_users.append(str(name))
                target_az = nat_az.get(str(route.get("NatGatewayId")), "")
                others = {az for az in associated_azs if az and target_az and az != target_az}
                if others:
                    note = f"**クロスAZ（{', '.join(sorted(others))} → {target_az}）**"
                    cross_az += 1
            rows.append(
                [
                    name,
                    ", ".join(associated) or "（関連付けなし）",
                    route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock") or route.get("DestinationPrefixListId"),
                    target,
                    route.get("State"),
                    note or "—",
                ]
            )

    details = [f"**ルートテーブルの実ルート（{len(route_tables)}本）**"]
    details.extend(
        table(["ルートテーブル", "関連付けサブネット", "宛先", "ターゲット", "状態", "所見"], rows)
    )
    details.append("")
    if nat_users:
        details.append(
            f"- NAT 経由で 0.0.0.0/0 を抜けているルートテーブル: {', '.join(sorted(set(nat_users)))}"
        )
    else:
        details.append("- NAT Gateway を向いているルートは存在しない。")
    details.append(
        "- **実際の課金額（AZ間転送料金・NAT データ処理料金）は Cost Explorer / CUR でしか確認できない。"
        "awsprobe は料金 API を呼ばない。**"
    )

    summary = (
        f"ルートテーブル {len(route_tables)} 本・ルート {len(rows)} 件を全件展開した。"
        + (
            f"**クロスAZの NAT 経路がルートテーブル {cross_az} 本で発生しており、"
            "AZ間転送料金がかかる構成になっている**（サブネット単位の内訳は Q38 を参照）。"
            if cross_az
            else "クロスAZの NAT 経路は検出されなかった。"
        )
        + " 実際の課金額は Cost Explorer での確認が必要。"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "Cost Explorer で `DataTransfer-Regional-Bytes`（AZ間転送）と "
            "`NatGateway-Bytes`（NAT データ処理）の月額を環境別タグで確認すること。"
        ),
    )


# ===========================================================================
# コンピュート・データ
# ===========================================================================


@question(
    "Q14",
    "各EC2のOS種別・バージョン、Webサーバ・言語ランタイムのバージョンとサポート期限",
    CAT_COMPUTE,
    requires=("compute",),
)
def q14_os_and_middleware(inv: dict) -> Answer:
    """OS / AMI レベルまでは inventory で答える。ミドルウェアは SSM インベントリ次第。"""
    instances = _dicts(inv, "compute", "instances")
    images = {
        img.get("ImageId"): img for img in _dicts(inv, "compute", "images") if img.get("ImageId")
    }
    inventory_entries = _dicts(inv, "compute", "ssm_inventory")
    managed = {
        m.get("InstanceId"): m
        for m in _dicts(inv, "compute", "ssm_managed_instances")
        if m.get("InstanceId")
    }

    if not instances:
        summary, details = no_data("EC2 インスタンス", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["compute.instances"])

    evidence: list[str] = []
    rows: list[list[Any]] = []
    deprecated_amis: list[str] = []
    for i, ins in enumerate(instances):
        evidence.append(f"compute.instances[{i}].PlatformDetails")
        image = images.get(ins.get("ImageId")) or {}
        deprecation = image.get("DeprecationTime")
        deprecated = False
        if deprecation:
            parsed = parse_dt(deprecation)
            deprecated = parsed is not None and parsed.date() <= _TODAY
            if deprecated:
                deprecated_amis.append(str(ins.get("InstanceId")))
        ssm = managed.get(ins.get("InstanceId")) or {}
        rows.append(
            [
                _tag(ins) or ins.get("InstanceId"),
                ins.get("PlatformDetails") or ins.get("Platform") or "—",
                f"{ssm.get('PlatformName') or ''} {ssm.get('PlatformVersion') or ''}".strip() or "—",
                ins.get("ImageId"),
                image.get("Name") or "（AMI 情報未取得）",
                image.get("CreationDate") or "—",
                (f"**{deprecation}（期限切れ）**" if deprecated else (deprecation or "—")),
            ]
        )

    details = ["**EC2 の OS / AMI**"]
    details.extend(
        table(
            ["インスタンス", "PlatformDetails", "SSM 認識 OS", "ImageId", "AMI名", "AMI作成日", "AMI廃止予定"],
            rows,
        )
    )

    app_rows: list[list[Any]] = []
    for entry in inventory_entries:
        instance_id = entry.get("InstanceId")
        for item in entry.get("Entries") or []:
            if not isinstance(item, dict):
                continue
            app_rows.append(
                [instance_id, item.get("Name"), item.get("Version"), item.get("PackageId") or "—"]
            )
    if app_rows:
        details.append("")
        details.append(f"**SSM インベントリで確認できた導入ソフトウェア（{len(app_rows)}件）**")
        details.extend(table(["インスタンス", "ソフトウェア", "バージョン", "パッケージ"], app_rows[:80]))
        if len(app_rows) > 80:
            details.append(f"- ほか {len(app_rows) - 80} 件（`compute.ssm_inventory` を直接参照）")

    manual = (
        "Web サーバ（nginx / Apache）と言語ランタイム（PHP / Node.js / Go）の"
        "実バージョンとサポート期限は、`awsprobe host-probe --enable-ssm` または"
        "各EC2での `nginx -v` / `php -v` / `node -v` の実行で確定させること。"
        "コンテナで動いている場合はホスト側の値ではなくイメージ側の値を見る必要がある。"
    )

    if app_rows:
        summary = (
            f"EC2 {len(instances)} 台の OS / AMI と、SSM インベントリによる導入ソフトウェア"
            f"{len(app_rows)} 件まで確認できた。"
            + (f"**AMI の廃止期限が切れているインスタンスが {len(deprecated_amis)} 台ある。**" if deprecated_amis else "")
        )
        return Answer("", "", "", PARTIAL, summary, details, evidence + ["compute.ssm_inventory"], manual)

    summary = (
        f"**OS 種別と AMI レベルまでは確定した**（EC2 {len(instances)} 台）。"
        "**Web サーバ・言語ランタイムのバージョンとサポート期限は EC2 内部を見ないと分からない**"
        "（SSM インベントリが空）。"
        + (f" AMI の廃止期限切れが {len(deprecated_amis)} 台ある。" if deprecated_amis else "")
    )
    return Answer("", "", "", PARTIAL, summary, details, evidence, manual)


@question(
    "Q34",
    "各EC2のインスタンスタイプ。CPUクレジットの消費状況",
    CAT_COMPUTE,
    requires=("compute",),
)
def q34_instance_types(inv: dict) -> Answer:
    """インスタンスタイプを一覧化し、T系（バースト）を注記する。"""
    instances = _dicts(inv, "compute", "instances")
    if not instances:
        summary, details = no_data("EC2 インスタンス", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["compute.instances"])

    evidence: list[str] = []
    rows: list[list[Any]] = []
    burstable: list[str] = []
    unlimited_unknown = 0
    for i, ins in enumerate(instances):
        evidence.append(f"compute.instances[{i}].InstanceType")
        instance_type = str(ins.get("InstanceType") or "")
        is_burst = bool(re.match(r"^t[234]", instance_type))
        if is_burst:
            burstable.append(_tag(ins) or str(ins.get("InstanceId")))
            unlimited_unknown += 1
        cpu_options = ins.get("CpuOptions") if isinstance(ins.get("CpuOptions"), dict) else {}
        rows.append(
            [
                _tag(ins) or ins.get("InstanceId"),
                ins.get("InstanceId"),
                instance_type,
                "**バースト（T系）**" if is_burst else "固定性能",
                (ins.get("Placement") or {}).get("AvailabilityZone") if isinstance(ins.get("Placement"), dict) else "—",
                (ins.get("State") or {}).get("Name") if isinstance(ins.get("State"), dict) else "—",
                cpu_options.get("CoreCount"),
                (ins.get("Monitoring") or {}).get("State") if isinstance(ins.get("Monitoring"), dict) else "—",
            ]
        )

    details = ["**EC2 インスタンスタイプ**"]
    details.extend(
        table(
            ["インスタンス", "ID", "タイプ", "性能特性", "AZ", "状態", "コア数", "詳細モニタリング"],
            rows,
        )
    )
    by_type: dict[str, int] = {}
    for ins in instances:
        by_type[str(ins.get("InstanceType"))] = by_type.get(str(ins.get("InstanceType")), 0) + 1
    details.append("")
    details.append("**タイプ別台数**")
    details.extend(table(["タイプ", "台数"], [[k, v] for k, v in sorted(by_type.items())]))

    if burstable:
        details.append("")
        details.append(
            f"- **T系（バースト）インスタンスが {len(burstable)} 台ある**: {', '.join(burstable)}。"
            "CPUクレジットが枯渇するとベースライン性能まで落ちる。本番で使う以上、"
            "`CPUCreditBalance` の監視は必須。"
        )
        details.append(
            "- `standard` / `unlimited` のクレジット指定は `ec2:DescribeInstanceCreditSpecifications` "
            "でしか取得できず、awsprobe では収集していない。"
        )

    summary = (
        f"EC2 {len(instances)} 台のインスタンスタイプをすべて特定した"
        f"（{', '.join(f'{k}×{v}' for k, v in sorted(by_type.items()))}）。"
        + (f"**うち {len(burstable)} 台がバースト（T系）。**" if burstable else "")
        + " **CPUクレジットの消費状況は CloudWatch メトリクスでしか分からない（awsprobe は取得しない）。**"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "CloudWatch で `CPUCreditBalance` / `CPUSurplusCreditBalance` の過去3か月を確認し、"
            "枯渇の有無を判定すること。併せて `DescribeInstanceCreditSpecifications` で "
            "unlimited 設定（超過課金の有無）を確認する。"
        ),
    )


@question(
    "Q15",
    "本番EC2 2台はアクティブ/アクティブか。セッション情報はどこで保持しているか",
    CAT_COMPUTE,
    requires=("edge", "compute"),
)
def q15_session_handling(inv: dict) -> Answer:
    """ターゲットグループのスティッキネス設定までは答えられる。保持先はアプリ実装。"""
    target_groups = _dicts(inv, "edge", "target_groups")
    if not target_groups:
        summary, details = no_data("ターゲットグループ", inv, ("elbv2",))
        return Answer(
            "",
            "",
            "",
            NO_DATA,
            summary,
            details,
            ["edge.target_groups"],
            manual_steps="アプリのセッション保持先（ファイル / Redis / DB / Cookie）を開発側に確認する。",
        )

    evidence: list[str] = []
    rows: list[list[Any]] = []
    sticky_on: list[str] = []
    for i, group in enumerate(target_groups):
        evidence.append(f"edge.target_groups[{i}].Attributes")
        attrs = {
            a.get("Key"): a.get("Value")
            for a in group.get("Attributes") or []
            if isinstance(a, dict)
        }
        enabled = str(attrs.get("stickiness.enabled", "")).lower() == "true"
        if enabled:
            sticky_on.append(str(group.get("TargetGroupName")))
        targets = [t for t in group.get("Targets") or [] if isinstance(t, dict)]
        healthy = sum(
            1
            for t in targets
            if str((t.get("TargetHealth") or {}).get("State")) == "healthy"
        )
        rows.append(
            [
                group.get("TargetGroupName"),
                len(targets),
                healthy,
                "**有効**" if enabled else "無効",
                attrs.get("stickiness.type") or "—",
                attrs.get("stickiness.lb_cookie.duration_seconds") or "—",
                attrs.get("deregistration_delay.timeout_seconds") or "—",
            ]
        )

    details = ["**ターゲットグループのセッションスティッキネス**"]
    details.extend(
        table(
            ["ターゲットグループ", "ターゲット数", "healthy", "スティッキネス", "方式", "Cookie有効期間(秒)", "登録解除待ち(秒)"],
            rows,
        )
    )
    multi = [r for r in rows if isinstance(r[1], int) and r[1] >= 2]
    details.append("")
    if multi:
        details.append(
            f"- ターゲットを2つ以上持つターゲットグループが {len(multi)} 本ある"
            "（= ロードバランサから見ればアクティブ/アクティブ配信）。"
        )
    if sticky_on:
        details.append(
            f"- **スティッキネスが有効なターゲットグループ: {', '.join(sticky_on)}**。"
            "アプリ側がセッションをローカルに持っている可能性が高い。"
        )
    else:
        details.append(
            "- スティッキネスはどのターゲットグループでも無効。"
            "**セッションを共有ストア（DB / Redis / EFS）に置いているか、ステートレスかのいずれか。**"
        )

    summary = (
        f"**ALB から見た配信形態（アクティブ/アクティブか）とスティッキネス設定は確定した**"
        f"（ターゲットグループ {len(target_groups)} 本、スティッキネス有効 {len(sticky_on)} 本）。"
        "**ただしセッション情報の実際の保持先はアプリの実装であり、AWS API からは分からない。**"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "開発（開発ベンダー）に、Laravel の `SESSION_DRIVER` の設定値と保存先"
            "（file なら EFS 共有か各EC2ローカルか）を確認すること。"
            "EC2 ローカルファイル＋スティッキネス無効なら、切離し時のローリング再起動で"
            "ログアウトが発生する。"
        ),
    )


@question(
    "Q4",
    "RDSのエンジンバージョン。自動マイナーバージョンアップグレードは有効か",
    CAT_COMPUTE,
    requires=("database",),
)
def q4_rds_engine_version(inv: dict) -> Answer:
    """エンジンバージョンと自動マイナーアップグレード、EOL 状況を判定する。"""
    db_instances = _dicts(inv, "database", "db_instances")
    if not db_instances:
        summary, details = no_data("RDS インスタンス", inv, ("rds",))
        return Answer("", "", "", NO_DATA, summary, details, ["database.db_instances"])

    engine_versions = {
        (v.get("Engine"), v.get("EngineVersion")): v
        for v in _dicts(inv, "database", "db_engine_versions")
    }

    evidence: list[str] = []
    rows: list[list[Any]] = []
    auto_off: list[str] = []
    eol: list[str] = []
    for i, db in enumerate(db_instances):
        evidence.append(f"database.db_instances[{i}].EngineVersion")
        key = (db.get("Engine"), db.get("EngineVersion"))
        version_info = engine_versions.get(key) or {}
        status = str(version_info.get("Status") or "")
        lifecycle = version_info.get("SupportedEngineLifecycleSupport")
        identifier = str(db.get("DBInstanceIdentifier"))
        auto = bool(db.get("AutoMinorVersionUpgrade"))
        if not auto:
            auto_off.append(identifier)
        if status and status != "available":
            eol.append(identifier)
        rows.append(
            [
                identifier,
                db.get("Engine"),
                db.get("EngineVersion"),
                f"**{status}**" if status and status != "available" else (status or "（未取得）"),
                "有効" if auto else "**無効**",
                db.get("MultiAZ"),
                db.get("DBInstanceClass"),
                ", ".join(str(x) for x in (lifecycle or [])) if isinstance(lifecycle, list) else (lifecycle or "—"),
            ]
        )

    details = ["**RDS のエンジンバージョンと自動マイナーアップグレード**"]
    details.extend(
        table(
            ["DB識別子", "エンジン", "バージョン", "バージョン状態", "自動マイナーUG", "Multi-AZ", "クラス", "ライフサイクル"],
            rows,
        )
    )
    upgrade_rows: list[list[Any]] = []
    for (engine, version), info in engine_versions.items():
        targets = [
            t.get("EngineVersion")
            for t in info.get("ValidUpgradeTarget") or []
            if isinstance(t, dict) and t.get("IsMajorVersionUpgrade") is False
        ]
        upgrade_rows.append(
            [engine, version, info.get("Status"), ", ".join(str(t) for t in targets[:6]) or "—"]
        )
    if upgrade_rows:
        details.append("")
        details.append("**アップグレード可能なマイナーバージョン**")
        details.extend(table(["エンジン", "現行", "状態", "移行先（マイナー、先頭6件）"], upgrade_rows))

    if auto_off:
        details.append("")
        details.append(
            f"- **自動マイナーバージョンアップグレードが無効の DB: {', '.join(auto_off)}**。"
            "セキュリティパッチが自動適用されない。"
        )
    if eol:
        details.append(
            f"- **バージョン状態が available でない（非推奨／EOL）DB: {', '.join(eol)}**。"
            "RDS 延長サポート課金の対象になっている可能性がある。"
        )

    summary = (
        f"RDS {len(db_instances)} 台のエンジンバージョンをすべて確定した。"
        f"自動マイナーアップグレードは {len(db_instances) - len(auto_off)}/{len(db_instances)} 台で有効"
        + (f"、**{len(eol)} 台が非推奨バージョン**。" if eol else "、非推奨バージョンは無い。")
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q16",
    "本番RDSの自動バックアップ保持期間。非本番5台はバックアップされているか",
    CAT_COMPUTE,
    requires=("database",),
)
def q16_backup_retention(inv: dict) -> Answer:
    """BackupRetentionPeriod を全 DB で一覧し、0（バックアップ無効）を強調する。"""
    db_instances = _dicts(inv, "database", "db_instances")
    if not db_instances:
        summary, details = no_data("RDS インスタンス", inv, ("rds",))
        return Answer("", "", "", NO_DATA, summary, details, ["database.db_instances"])

    snapshots = _dicts(inv, "database", "db_snapshots")
    snapshot_count: dict[str, int] = {}
    latest_manual: dict[str, str] = {}
    for snap in snapshots:
        identifier = str(snap.get("DBInstanceIdentifier"))
        snapshot_count[identifier] = snapshot_count.get(identifier, 0) + 1
        if snap.get("SnapshotType") == "manual":
            created = str(snap.get("SnapshotCreateTime") or "")
            if created > latest_manual.get(identifier, ""):
                latest_manual[identifier] = created

    evidence: list[str] = []
    rows: list[list[Any]] = []
    disabled: list[str] = []
    for i, db in enumerate(db_instances):
        evidence.append(f"database.db_instances[{i}].BackupRetentionPeriod")
        identifier = str(db.get("DBInstanceIdentifier"))
        retention = db.get("BackupRetentionPeriod")
        if not retention:
            disabled.append(identifier)
        rows.append(
            [
                identifier,
                f"**{retention} 日（バックアップ無効）**" if not retention else f"{retention} 日",
                db.get("PreferredBackupWindow") or "—",
                db.get("MultiAZ"),
                db.get("DeletionProtection"),
                db.get("StorageEncrypted"),
                snapshot_count.get(identifier, 0),
                latest_manual.get(identifier, "—"),
            ]
        )

    details = ["**RDS の自動バックアップ保持期間**"]
    details.extend(
        table(
            ["DB識別子", "保持期間", "バックアップ時間帯", "Multi-AZ", "削除保護", "暗号化", "スナップショット数", "最新手動SS"],
            rows,
        )
    )
    details.append("")
    if disabled:
        details.append(
            f"- **自動バックアップが無効（保持0日）の DB: {', '.join(disabled)}**。"
            "ポイントインタイムリカバリができない。"
        )
    else:
        details.append("- 全 DB で自動バックアップが有効（保持期間1日以上）。")

    summary = (
        f"RDS {len(db_instances)} 台すべての自動バックアップ保持期間を確定した。"
        + (
            f"**うち {len(disabled)} 台はバックアップ無効（保持0日）。**"
            if disabled
            else "バックアップ無効の DB は無い。"
        )
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q7",
    "EFS は本番と check で物理的に別ファイルシステムか、同一FS内の別アクセスポイントか",
    CAT_COMPUTE,
    requires=("storage",),
)
def q7_efs_separation(inv: dict) -> Answer:
    """ファイルシステム件数と、マウントターゲット／アクセスポイントの FS 分布で確定判定する。"""
    file_systems = _dicts(inv, "storage", "efs_file_systems")
    mount_targets = _dicts(inv, "storage", "efs_mount_targets")
    access_points = _dicts(inv, "storage", "efs_access_points")

    if not file_systems:
        summary, details = no_data("EFS ファイルシステム", inv, ("efs",))
        return Answer("", "", "", NO_DATA, summary, details, ["storage.efs_file_systems"])

    evidence = ["storage.efs_file_systems", "storage.efs_mount_targets", "storage.efs_access_points"]

    def _fs_label(fs: dict) -> str:
        return f"{fs.get('Name') or _tag(fs) or '(名前なし)'} ({fs.get('FileSystemId')})"

    rows: list[list[Any]] = []
    for fs in file_systems:
        fs_id = fs.get("FileSystemId")
        mts = [m for m in mount_targets if m.get("FileSystemId") == fs_id]
        aps = [a for a in access_points if a.get("FileSystemId") == fs_id]
        rows.append(
            [
                _fs_label(fs),
                fs.get("LifeCycleState"),
                len(mts),
                ", ".join(sorted({str(m.get("AvailabilityZoneName")) for m in mts})) or "—",
                len(aps),
                ", ".join(
                    str((a.get("RootDirectory") or {}).get("Path"))
                    for a in aps
                    if isinstance(a.get("RootDirectory"), dict)
                ) or "—",
            ]
        )

    details = [f"**EFS ファイルシステム（{len(file_systems)}本）**"]
    details.extend(
        table(["ファイルシステム", "状態", "MT数", "MTのAZ", "AP数", "アクセスポイントのパス"], rows)
    )

    def _is_check(text: str) -> bool:
        return "check" in text.lower()

    prod_fs = {
        str(fs.get("FileSystemId"))
        for fs in file_systems
        if not _is_check(str(fs.get("Name") or _tag(fs)))
    }
    check_fs = {
        str(fs.get("FileSystemId"))
        for fs in file_systems
        if _is_check(str(fs.get("Name") or _tag(fs)))
    }
    # アクセスポイント側の命名でも判定する
    ap_prod = {
        str(a.get("FileSystemId"))
        for a in access_points
        if not _is_check(str((a.get("RootDirectory") or {}).get("Path") or "") + str(_tag(a)))
    }
    ap_check = {
        str(a.get("FileSystemId"))
        for a in access_points
        if _is_check(str((a.get("RootDirectory") or {}).get("Path") or "") + str(_tag(a)))
    }
    shared = (ap_prod & ap_check) or (prod_fs & check_fs)

    details.append("")
    details.append(
        f"- 本番系と判定したファイルシステム: {', '.join(sorted(prod_fs)) or '—'}"
    )
    details.append(f"- check 系と判定したファイルシステム: {', '.join(sorted(check_fs)) or '—'}")
    if shared:
        details.append(
            f"- **本番と check が同一ファイルシステムを共有している: {', '.join(sorted(shared))}**"
        )

    if shared:
        summary = (
            f"**本番と check が同一 EFS ファイルシステムを共有している**（{', '.join(sorted(shared))}）。"
            "バーストクレジットとスループットを奪い合う構成であり、是正対象。"
        )
    elif check_fs and prod_fs:
        summary = (
            f"**本番と check は物理的に別ファイルシステムである。**"
            f"EFS は計 {len(file_systems)} 本（本番系 {len(prod_fs)} 本 / check 系 {len(check_fs)} 本）で、"
            "共有しているファイルシステムは無い。"
        )
    else:
        summary = (
            f"EFS は {len(file_systems)} 本存在し、マウントターゲット／アクセスポイントの分布まで確定した。"
            "命名から本番／check の区別が付かないため、用途の対応付けは名称ルールの確認が必要。"
        )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q17",
    "EFS のスループットモードと AWS Backup 設定",
    CAT_COMPUTE,
    requires=("storage",),
)
def q17_efs_throughput(inv: dict) -> Answer:
    """ThroughputMode / PerformanceMode と自動バックアップポリシーを判定する。"""
    file_systems = _dicts(inv, "storage", "efs_file_systems")
    if not file_systems:
        summary, details = no_data("EFS ファイルシステム", inv, ("efs",))
        return Answer("", "", "", NO_DATA, summary, details, ["storage.efs_file_systems"])

    backup_policies = _map(inv, "storage", "efs_backup_policies")
    evidence = ["storage.efs_file_systems", "storage.efs_backup_policies"]

    rows: list[list[Any]] = []
    bursting: list[str] = []
    backup_off: list[str] = []
    for fs in file_systems:
        fs_id = str(fs.get("FileSystemId"))
        policy = backup_policies.get(fs_id)
        status = (policy or {}).get("Status") if isinstance(policy, dict) else None
        mode = str(fs.get("ThroughputMode") or "")
        if mode == "bursting":
            bursting.append(fs_id)
        if status != "ENABLED":
            backup_off.append(fs_id)
        size = fs.get("SizeInBytes") if isinstance(fs.get("SizeInBytes"), dict) else {}
        rows.append(
            [
                f"{fs.get('Name') or '(名前なし)'} ({fs_id})",
                f"**{mode}**" if mode == "bursting" else mode,
                fs.get("PerformanceMode"),
                fs.get("ProvisionedThroughputInMibps") or "—",
                fs.get("Encrypted"),
                size.get("Value"),
                f"**{status or '未設定/未取得'}**" if status != "ENABLED" else status,
            ]
        )

    details = ["**EFS のスループット・性能モードと自動バックアップ**"]
    details.extend(
        table(
            ["ファイルシステム", "スループットモード", "性能モード", "プロビジョンド(MiB/s)", "暗号化", "サイズ(byte)", "自動バックアップ"],
            rows,
        )
    )
    details.append("")
    if bursting:
        details.append(
            f"- **バーストモードのファイルシステムが {len(bursting)} 本ある**: {', '.join(bursting)}。"
            "バーストクレジット枯渇時にベースライン（サイズ比例）まで落ちる。"
        )
    if backup_off:
        details.append(
            f"- **EFS 自動バックアップが有効でないファイルシステム: {', '.join(backup_off)}**。"
        )
    else:
        details.append("- 全ファイルシステムで EFS 自動バックアップが有効。")

    plans = _dicts(inv, "storage", "backup_plans")
    if plans:
        details.append("")
        details.append("**AWS Backup プラン**")
        details.extend(
            table(
                ["プラン名", "プランID", "ルール数", "最終実行"],
                [
                    [
                        p.get("BackupPlanName"),
                        p.get("BackupPlanId"),
                        len(((p.get("BackupPlan") or {}).get("Rules") or []))
                        if isinstance(p.get("BackupPlan"), dict)
                        else 0,
                        p.get("LastExecutionDate") or "—",
                    ]
                    for p in plans
                ],
            )
        )
        evidence.append("storage.backup_plans")

    summary = (
        f"EFS {len(file_systems)} 本のスループットモード・性能モードと自動バックアップ設定をすべて確定した"
        f"（バーストモード {len(bursting)} 本 / 自動バックアップ無効 {len(backup_off)} 本）。"
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q18",
    "AMI の定期取得有無、取得元・世代数・保持ルール",
    CAT_COMPUTE,
    requires=("compute",),
)
def q18_ami_lifecycle(inv: dict) -> Answer:
    """自アカウント所有 AMI の作成日分布と命名から、定期取得の有無を推定する。"""
    images = _dicts(inv, "compute", "images")
    account_id = str(_sect(inv, "meta").get("account_id") or "")
    # OwnerId も account_id もマスクで ＜自アカウント＞ になるため、
    # 生値・トークンの両方を扱える is_self_account() で突き合わせる。
    owned = [
        img for img in images
        if not account_id or is_self_account(img.get("OwnerId"), account_id)
    ]
    snapshots = _dicts(inv, "compute", "snapshots")
    dlm_policies = _dicts(inv, "compute", "dlm_lifecycle_policies")

    evidence = ["compute.images", "compute.snapshots", "compute.dlm_lifecycle_policies"]
    details: list[str] = []

    if not owned:
        return Answer(
            "",
            "",
            "",
            PARTIAL,
            "**自アカウント所有の AMI は1本も存在しない。** "
            "AMI による世代バックアップは行われていないと考えられる"
            f"（参照中の AMI {len(images)} 本はすべて他者所有）。",
            [
                f"- 収集した AMI {len(images)} 本のうち、自アカウント（{account_id or '不明'}）所有は0本。",
                f"- Data Lifecycle Manager のポリシー: {len(dlm_policies)} 件"
                + ("（**取得の仕組み自体が無い**）" if not dlm_policies else "（下記参照）"),
            ]
            + _dlm_lines(dlm_policies),
            evidence,
            manual_steps=(
                "AMI ではなく EBS スナップショット／AWS Backup で世代管理している可能性があるため、"
                "`storage.backup_plans` と運用手順書を確認すること。"
            )
            if not dlm_policies
            else None,
        )

    rows: list[list[Any]] = []
    dates: list[_dt.date] = []
    for img in sorted(owned, key=lambda x: str(x.get("CreationDate") or "")):
        parsed = parse_dt(img.get("CreationDate"))
        if parsed:
            dates.append(parsed.date())
        rows.append(
            [
                img.get("Name") or img.get("ImageId"),
                img.get("ImageId"),
                img.get("CreationDate"),
                img.get("State"),
                img.get("DeprecationTime") or "—",
                len(img.get("BlockDeviceMappings") or []),
            ]
        )
    details.append(f"**自アカウント所有 AMI（{len(owned)}本）**")
    details.extend(table(["AMI名", "ImageId", "作成日", "状態", "廃止予定", "ボリューム数"], rows))

    # 命名から世代管理のパターンを推定する
    dated_names = [
        str(img.get("Name"))
        for img in owned
        if re.search(r"\d{4}[-_]?\d{2}[-_]?\d{2}", str(img.get("Name") or ""))
    ]
    interval_note = "—"
    if len(dates) >= 2:
        dates.sort()
        gaps = [(dates[i + 1] - dates[i]).days for i in range(len(dates) - 1)]
        gaps = [g for g in gaps if g > 0]
        if gaps:
            interval_note = (
                f"最短{min(gaps)}日 / 最長{max(gaps)}日 / 平均{sum(gaps) // len(gaps)}日"
            )
    details.append("")
    details.append(f"- 作成日の間隔: {interval_note}")
    details.append(
        f"- 名前に日付を含む AMI: {len(dated_names)}/{len(owned)} 本"
        + ("（**日次／定期取得のスクリプトが存在する可能性が高い**）" if dated_names else "")
    )
    if dates:
        newest = max(dates)
        details.append(
            f"- 最新 AMI の作成日: {newest.isoformat()}（{(_TODAY - newest).days} 日前）"
        )
    details.append(f"- 自アカウント所有の EBS スナップショット: {len(snapshots)} 本")

    details.append("")
    details.extend(_dlm_lines(dlm_policies))

    if dlm_policies:
        summary = (
            f"自アカウント所有 AMI {len(owned)} 本の作成日分布と命名に加え、"
            f"**Data Lifecycle Manager のポリシー {len(dlm_policies)} 件で取得元と保持ルールまで確定した**"
            f"（作成間隔: {interval_note}）。"
        )
        manual = None
    else:
        summary = (
            f"自アカウント所有 AMI {len(owned)} 本の作成日分布と命名までは確認できた"
            f"（作成間隔: {interval_note}）。"
            "**Data Lifecycle Manager のポリシーは 1 件も無いので、定期取得しているなら "
            "EventBridge / cron / 外部ツールのいずれかであり、そこは inventory からは辿れない。**"
        )
        manual = (
            "DLM を使っていないのに AMI が定期的に増えているなら、EventBridge / cron / "
            "外部ツールのどれが作っているかを確認すること。実施主体と保持世代数・"
            "復旧手順の文書の所在も併せて確認する。"
        )
    return Answer(
        "",
        "",
        "",
        ANSWERED if dlm_policies else PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=manual,
    )


def _dlm_lines(policies: list[dict]) -> list[str]:
    """DLM ポリシーを「取得元・対象・スケジュール・保持世代」の表にする。"""
    if not policies:
        return ["- Data Lifecycle Manager のポリシーは存在しない。"]
    rows: list[list[Any]] = []
    for policy in policies:
        details_body = policy.get("PolicyDetails")
        details_body = details_body if isinstance(details_body, dict) else {}
        schedules = [s for s in (details_body.get("Schedules") or []) if isinstance(s, dict)]
        if not schedules:
            schedules = [{}]
        for schedule in schedules:
            create = schedule.get("CreateRule") if isinstance(schedule.get("CreateRule"), dict) else {}
            retain = schedule.get("RetainRule") if isinstance(schedule.get("RetainRule"), dict) else {}
            cron = create.get("CronExpression")
            interval = create.get("Interval")
            when = (
                str(cron)
                if cron
                else (f"{interval}{create.get('IntervalUnit') or ''}ごと" if interval else "—")
            )
            keep = retain.get("Count")
            keep_text = (
                f"{keep} 世代"
                if keep
                else (f"{retain.get('Interval')}{retain.get('IntervalUnit') or ''}保持" if retain.get("Interval") else "—")
            )
            rows.append(
                [
                    policy.get("PolicyId"),
                    policy.get("State") or "—",
                    details_body.get("ResourceTypes") and ", ".join(
                        str(r) for r in details_body.get("ResourceTypes") or []
                    ) or (details_body.get("PolicyType") or "—"),
                    schedule.get("Name") or "—",
                    when,
                    keep_text,
                ]
            )
    out = [f"**Data Lifecycle Manager のポリシー（{len(policies)}件）**"]
    out.extend(
        table(["ポリシーID", "状態", "対象", "スケジュール名", "取得間隔", "保持"], rows)
    )
    out.append("")
    out.append(
        "- DLM のポリシーがあれば、AMI / スナップショットの定期取得は"
        "**仕組みとして存在する**と言い切れる（手動運用との区別がつく）。"
    )
    return out


@question(
    "Q31",
    "本番2台構成でバッチの二重実行をどう防いでいるか",
    CAT_COMPUTE,
    requires=("compute", "serverless"),
)
def q31_batch_double_run(inv: dict) -> Answer:
    """二重実行の防止方法はアプリ／cron の実装であり、AWS API では取得できない。"""
    instances = _dicts(inv, "compute", "instances")
    rules = _dicts(inv, "serverless", "eventbridge_rules")
    state_machines = _dicts(inv, "serverless", "stepfunctions_state_machines")
    queues = _dicts(inv, "serverless", "sqs_queues")

    details: list[str] = []
    evidence = ["compute.instances", "serverless.eventbridge_rules", "serverless.sqs_queues"]

    scheduled = [r for r in rules if r.get("ScheduleExpression")]
    if scheduled:
        details.append("**AWS 側でスケジュール実行されているもの（二重実行の対象外）**")
        details.extend(
            table(
                ["ルール名", "スケジュール", "状態", "ターゲット数"],
                [
                    [r.get("Name"), r.get("ScheduleExpression"), r.get("State"), len(r.get("Targets") or [])]
                    for r in scheduled
                ],
            )
        )
    else:
        details.append("- EventBridge によるスケジュール実行は存在しない。")

    if state_machines:
        details.append("")
        details.append(f"- Step Functions のステートマシン: {len(state_machines)} 本")
    if queues:
        fifo = [q for q in queues if str(q.get("QueueUrl") or "").endswith(".fifo")]
        details.append(
            f"- SQS キュー: {len(queues)} 本（うち FIFO {len(fifo)} 本）。"
            + ("FIFO キューは重複排除に使える。" if fifo else "")
        )

    details.append("")
    details.append(
        f"- 本番相当の EC2 は {len([i for i in instances if 'prod' in _tag(i).lower()])} 台"
        f"（全 {len(instances)} 台）。**EC2 上の cron / supervisor は AWS API からは見えない。**"
    )

    return Answer(
        "",
        "",
        "",
        NEEDS_MANUAL,
        "**バッチの二重実行防止方法は AWS API では原理的に判定できない**"
        "（EC2 上の cron 設定・アプリのロック実装であるため）。"
        "AWS 側のスケジューラ（EventBridge / Step Functions / SQS FIFO）の有無だけは上記のとおり。",
        details,
        evidence,
        manual_steps=(
            "開発ベンダーに、(1) バッチをどちらのEC2で実行しているか（片系固定か両系か）、"
            "(2) 排他制御の実装（DB のアドバイザリロック / `flock` / Laravel の `withoutOverlapping`）、"
            "(3) 片系障害時にバッチが止まらない仕組みがあるか、を確認すること。"
            "並行して `awsprobe host-probe --enable-ssm` で `crontab -l` の差分を2台分採取すると裏が取れる。"
        ),
    )


# ===========================================================================
# アプリ・デプロイ・委託
# ===========================================================================


@question(
    "Q2",
    "対象アカウントの認証基盤は何か（設計資料では確認済み: Auth0。awsprobe による裏取り）",
    CAT_APP,
    requires=("serverless",),
)
def q2_auth_platform(inv: dict) -> Answer:
    """設計資料で「Auth0」と結論済みの設問を、AWS 側の不在確認で裏取りする。"""
    pools = _dicts(inv, "serverless", "cognito_user_pools")
    evidence = ["serverless.cognito_user_pools"]
    details: list[str] = []

    if pools:
        details.append("**Cognito ユーザープール**")
        details.extend(
            table(
                ["名前", "ID", "作成日", "最終更新", "推定ユーザー数", "MFA"],
                [
                    [
                        p.get("Name"),
                        p.get("Id"),
                        p.get("CreationDate"),
                        p.get("LastModifiedDate"),
                        p.get("EstimatedNumberOfUsers"),
                        p.get("MfaConfiguration"),
                    ]
                    for p in pools
                ],
            )
        )
    app_pools = [p for p in pools if "load-test" not in str(p.get("Name") or "").lower()]
    details.append("")
    details.append(
        "- AWS 側にアプリ認証に使えるマネージド認証基盤（Cognito）は"
        + (
            f"{len(app_pools)} 本ある（負荷試験用を除く）。"
            if app_pools
            else "**負荷試験用を除けば存在しない**。"
        )
    )
    details.append(
        "- **Auth0 は AWS 外のサービスであり、inventory には現れない。** "
        "設計資料の「Auth0（ID基盤）」という結論と矛盾しないことだけが確認できる。"
    )

    if app_pools:
        summary = (
            f"**負荷試験用以外の Cognito ユーザープールが {len(app_pools)} 本存在する。** "
            "設計資料の「認証は Auth0」という結論と食い違う可能性があるため、用途の確認が必要。"
        )
        return Answer(
            "", "", "", PARTIAL, summary, details, evidence,
            manual_steps="上記ユーザープールの用途（アプリ認証か、別システムか）を開発側に確認すること。",
        )

    summary = (
        "**設計資料の結論（認証基盤は Auth0）と矛盾しない。** "
        f"AWS 側の Cognito ユーザープールは {len(pools)} 本で、いずれも負荷試験用（`*load-test*`）。"
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q6",
    "「vendor-agent 監視の維持・再導入」の主対象はどこか（設計資料では確認済み: 対象の EC2）",
    CAT_APP,
    requires=("compute",),
)
def q6_vendor_agent_target(inv: dict) -> Answer:
    """vendor-agent の導入対象となる EC2 の台数と環境内訳を確定する。"""
    instances = _dicts(inv, "compute", "instances")
    managed = _dicts(inv, "compute", "ssm_managed_instances")
    if not instances:
        summary, details = no_data("EC2 インスタンス", inv, ("ec2",))
        return Answer("", "", "", NO_DATA, summary, details, ["compute.instances"])

    by_env: dict[str, list[str]] = {}
    for ins in instances:
        name = _tag(ins) or str(ins.get("InstanceId"))
        env = _guess_env(name)
        by_env.setdefault(env, []).append(name)

    details = ["**EC2 の環境別内訳（vendor-agent 再導入の対象範囲）**"]
    details.extend(
        table(
            ["環境", "台数", "インスタンス"],
            [[env, len(names), ", ".join(sorted(names))] for env, names in sorted(by_env.items())],
        )
    )
    details.append("")
    details.append(
        f"- SSM で到達できるインスタンス: {len(managed)}/{len(instances)} 台"
        "（再導入作業を SSM Run Command で流せるかの目安）。"
    )
    details.append(
        "- コンテナ・マネージドサービス（RDS / ALB / EFS / Lambda）にはエージェントを入れられないため、"
        "vendor-agent の対象は EC2 に限られる。"
    )

    summary = (
        f"**設計資料の結論（対象は EC2）と一致する。** EC2 は {len(instances)} 台で、"
        f"環境内訳は {', '.join(f'{k}:{len(v)}台' for k, v in sorted(by_env.items()))}。"
    )
    return Answer(
        "", "", "", ANSWERED, summary, details,
        ["compute.instances", "compute.ssm_managed_instances"],
    )


def _guess_env(name: str) -> str:
    """リソース名から環境名を推定する（prod / check / demo / stg / stg2 / stg3 / その他）。"""
    lowered = str(name).lower()
    for env in ("stg3", "stg2", "check", "demo", "prod", "stg"):
        if env in lowered:
            return env
    if "production" in lowered:
        return "prod"
    if "staging" in lowered:
        return "stg"
    return "その他"


@question(
    "Q3",
    "GitHub からのデプロイ経路。`CodeStarNotifications-test-codebuild-*` は現役か。使用しているIAM認証情報は何か",
    CAT_APP,
    requires=("security", "serverless"),
)
def q3_deploy_path(inv: dict) -> Answer:
    """CFn スタック・Lambda・CodeBuild 相当リソース・IAM ユーザーから分かる範囲を出す。"""
    stacks = _dicts(inv, "security", "cloudformation_stacks")
    functions = _dicts(inv, "serverless", "lambda_functions")
    topics = _dicts(inv, "serverless", "sns_topics")
    rules = _dicts(inv, "serverless", "eventbridge_rules")
    iam = _map(inv, "security", "iam")
    users = [u for u in (iam.get("users") or []) if isinstance(u, dict)]

    evidence = [
        "security.cloudformation_stacks",
        "serverless.lambda_functions",
        "serverless.sns_topics",
        "security.iam.users",
    ]
    details: list[str] = []

    def _matches(text: Any) -> bool:
        lowered = str(text or "").lower()
        return any(k in lowered for k in ("codebuild", "codestar", "codepipeline", "codedeploy", "deploy"))

    hits: list[list[Any]] = []
    for stack in stacks:
        if _matches(stack.get("StackName")):
            hits.append(["CloudFormation スタック", stack.get("StackName"), stack.get("StackStatus"), stack.get("LastUpdatedTime") or stack.get("CreationTime")])
    for topic in topics:
        arn = str(topic.get("TopicArn") or "")
        if _matches(arn):
            hits.append(["SNS トピック", arn.rsplit(":", 1)[-1], f"購読 {len(topic.get('Subscriptions') or [])} 件", "—"])
    for rule in rules:
        if _matches(rule.get("Name")):
            hits.append(["EventBridge ルール", rule.get("Name"), rule.get("State"), rule.get("ScheduleExpression") or "イベント駆動"])
    for fn in functions:
        if _matches(fn.get("FunctionName")):
            hits.append(["Lambda 関数", fn.get("FunctionName"), fn.get("Runtime"), fn.get("LastModified")])

    if hits:
        details.append("**デプロイ関連と思われるリソース**")
        details.extend(table(["種別", "名前", "状態/ランタイム", "最終更新"], hits))
    else:
        details.append("- 名前に codebuild / codestar / codepipeline / codedeploy / deploy を含むリソースは無い。")

    details.append("")
    details.append(
        "- **CodeBuild / CodePipeline / CodeDeploy / ECR は awsprobe の収集対象外**であり、"
        "本判定では「存在しない」ことを確定できない（コレクタ側への追加要望）。"
    )

    if users:
        details.append("")
        details.append("**IAM ユーザー（デプロイ用アクセスキーの候補）**")
        details.extend(
            table(
                ["ユーザー名", "作成日", "パスワード最終利用", "付与ポリシー"],
                [
                    [
                        u.get("UserName"),
                        u.get("CreateDate"),
                        u.get("PasswordLastUsed") or "—",
                        ", ".join(_attached_policy_names_for_user(iam, u.get("UserName"))) or "—",
                    ]
                    for u in users
                ],
            )
        )
        details.append(
            "- **アクセスキーの発行状況・最終使用日時は `iam:ListAccessKeys` / "
            "`GetAccessKeyLastUsed` でしか取れず、awsprobe では収集していない。**"
        )

    summary = (
        f"デプロイ関連と推測されるリソースを {len(hits)} 件、IAM ユーザーを {len(users)} 件まで洗い出した。"
        "**ただしデプロイ経路そのもの（EC2 上の `git pull` か、外部 CI か）と"
        "使用している認証情報の実体は AWS API からは確定できない。**"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "開発ベンダーに (1) デプロイのトリガと手順、(2) `composer install` の実行場所、"
            "(3) GitHub トークン／デプロイキーの保管場所と保有者、(4) 上表の IAM ユーザーのうち"
            "デプロイに使っているもの、を確認すること。"
            "AWS 側は `iam:ListAccessKeys` と CloudTrail の `AssumeRole` / `GetObject` 履歴で裏が取れる。"
        ),
    )


def _attached_policy_names_for_user(iam: dict, user_name: Any) -> list[str]:
    """policies_attached_summary から、そのユーザーの管理ポリシー名を取り出す。"""
    if not user_name:
        return []
    for entry in iam.get("policies_attached_summary") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("PrincipalType") != "user" or entry.get("Name") != user_name:
            continue
        return [
            str(p.get("PolicyName"))
            for p in entry.get("AttachedPolicies") or []
            if isinstance(p, dict) and p.get("PolicyName")
        ]
    return []


@question(
    "Q19",
    "デプロイの実施者は誰か。切り戻し手順は文書化されているか",
    CAT_APP,
    requires=("security",),
)
def q19_deploy_owner(inv: dict) -> Answer:
    """実施者と手順書の有無は人と文書の話であり、AWS API では取得できない。"""
    return Answer(
        "",
        "",
        "",
        NEEDS_MANUAL,
        "**デプロイの実施者と切り戻し手順書の有無は AWS API では原理的に取得できない**"
        "（組織と文書の話であるため）。CloudTrail のイベント履歴から"
        "「誰が最近 AWS を操作したか」の傾向だけは後追いできる。",
        [
            "- awsprobe は CloudTrail の**イベント本体（LookupEvents）を取得しない**"
            "（ガードで拒否しているため）。実施者の特定にはコンソールでの証跡検索が必要。",
            "- 手順書の所在（Backlog / Confluence / ローカル）は資料管理の問題であり、"
            "inventory からは判定できない。",
        ],
        ["security.iam.users", "logging.cloudtrail_trails"],
        manual_steps=(
            "発注元／開発ベンダー／監視ベンダーの3者に対し、"
            "(1) 本番デプロイを実行できる人の氏名と所属、(2) デプロイ手順書の所在と最終更新日、"
            "(3) 切り戻し手順の有無と、直近で実際に切り戻した事例、を確認すること。"
            "裏取りとして CloudTrail を過去90日分検索し、本番リソースへの操作主体を一覧化する。"
        ),
    )


@question(
    "Q20",
    "`check` 環境の位置づけ。監視対象外なのに本番サブネットに同居している理由",
    CAT_APP,
    requires=("compute", "network"),
)
def q20_check_env(inv: dict) -> Answer:
    """同居の事実は inventory で示せるが、「理由」は人に聞くしかない。"""
    instances = _dicts(inv, "compute", "instances")
    subnets = subnet_index(inv)

    rows: list[list[Any]] = []
    colocated: list[str] = []
    for ins in instances:
        name = _tag(ins) or str(ins.get("InstanceId"))
        if "check" not in name.lower():
            continue
        subnet = subnets.get(ins.get("SubnetId"), {})
        subnet_name = _tag(subnet)
        is_prod_subnet = "prod" in subnet_name.lower()
        if is_prod_subnet:
            colocated.append(name)
        rows.append(
            [
                name,
                ins.get("InstanceId"),
                subnet_label(subnet),
                "**本番サブネットに同居**" if is_prod_subnet else "専用サブネット",
                ins.get("InstanceType"),
            ]
        )

    details: list[str] = []
    if rows:
        details.append("**check 環境のリソース配置**")
        details.extend(table(["インスタンス", "ID", "サブネット", "判定", "タイプ"], rows))
    else:
        details.append("- 名前に 'check' を含む EC2 は存在しない。")
    if colocated:
        details.append("")
        details.append(
            f"- **check の EC2 {len(colocated)} 台が本番サブネットに同居している**: "
            f"{', '.join(colocated)}。NACL が共用のため、サブネット単位で check だけを遮断できない。"
        )

    return Answer(
        "",
        "",
        "",
        NEEDS_MANUAL,
        "**check 環境の位置づけ（何のための環境か、誰が使うか）は AWS API では取得できない。** "
        + (
            f"本番サブネットへの同居という事実は確認できた（{len(colocated)}台）。"
            if colocated
            else "本番サブネットへの同居は検出されなかった。"
        ),
        details,
        ["compute.instances[].SubnetId", "network.subnets"],
        manual_steps=(
            "発注元社内／開発ベンダーに、(1) check 環境の用途（本番データを使う受入確認か、"
            "外形監視の受け皿か）、(2) 本番データのコピーが入っているか、"
            "(3) 監視対象外のまま本番サブネットに置く判断を誰がいつしたか、を確認すること。"
            "本番データが入っているなら、監視対象外であること自体が是正対象になる。"
        ),
    )


@question(
    "Q21",
    "stg / stg2 / stg3 はそれぞれ誰が何の目的で使っているか。統廃合できないか。CP・ID基盤と接続されているか",
    CAT_APP,
    requires=("network", "compute", "database"),
)
def q21_staging_environments(inv: dict) -> Answer:
    """Name タグから環境ごとのリソース棚卸しを出し、統廃合の判断材料として提示する。"""
    subnets = _dicts(inv, "network", "subnets")
    instances = _dicts(inv, "compute", "instances")
    db_instances = _dicts(inv, "database", "db_instances")
    load_balancers = _dicts(inv, "edge", "load_balancers")

    inventory_by_env: dict[str, dict[str, list[str]]] = {}

    def _add(env: str, kind: str, name: str) -> None:
        inventory_by_env.setdefault(env, {}).setdefault(kind, []).append(name)

    for subnet in subnets:
        name = _tag(subnet) or str(subnet.get("SubnetId"))
        _add(_guess_env(name), "サブネット", name)
    for ins in instances:
        name = _tag(ins) or str(ins.get("InstanceId"))
        _add(_guess_env(name), "EC2", name)
    for db in db_instances:
        name = str(db.get("DBInstanceIdentifier"))
        _add(_guess_env(name), "RDS", name)
    for lb in load_balancers:
        name = str(lb.get("LoadBalancerName"))
        _add(_guess_env(name), "ALB/NLB", name)

    kinds = ["サブネット", "EC2", "RDS", "ALB/NLB"]
    rows: list[list[Any]] = []
    for env in sorted(inventory_by_env):
        entry = inventory_by_env[env]
        rows.append([env] + [f"{len(entry.get(k, []))}" for k in kinds])

    details = ["**環境ごとのリソース棚卸し（統廃合の判断材料）**"]
    details.extend(table(["環境"] + kinds, rows))

    for env in ("stg", "stg2", "stg3"):
        entry = inventory_by_env.get(env)
        if not entry:
            continue
        details.append("")
        details.append(f"**{env} の内訳**")
        details.extend(
            table(
                ["種別", "リソース"],
                [[k, ", ".join(sorted(v))] for k, v in sorted(entry.items())],
            )
        )

    # CP / ID基盤との接続は VPC 間接続の有無で分かる範囲を出す
    peerings = _dicts(inv, "network", "vpc_peering_connections")
    endpoints = _dicts(inv, "network", "vpc_endpoints")
    details.append("")
    details.append(
        f"- VPC ピアリング {len(peerings)} 本 / VPC エンドポイント {len(endpoints)} 本。"
        "**stg 系が CP・ID基盤とどう接続しているかは、アプリの接続先設定（環境変数）を見ないと分からない。**"
    )

    summary = (
        f"環境ごとのリソース棚卸しを作成した（環境 {len(inventory_by_env)} 種類）。"
        "**stg / stg2 / stg3 のリソース構成は確定したが、"
        "利用者・利用目的・統廃合可否は AWS API では判定できない。**"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        ["network.subnets", "compute.instances", "database.db_instances", "edge.load_balancers"],
        manual_steps=(
            "上表をそのまま提示して、発注元社内／開発ベンダーに "
            "(1) stg / stg2 / stg3 のそれぞれの利用者と用途、(2) 直近3か月の利用実績、"
            "(3) 統合した場合に困る人がいるか、(4) それぞれが CP・ID基盤のどの環境に接続しているか、"
            "を確認すること。未使用の環境があれば、そのまま削減候補になる。"
        ),
    )


@question(
    "Q22",
    "開発ベンダーとの契約上、本番環境に対してどこまでの作業権限を与えているか",
    CAT_APP,
    requires=("security",),
)
def q22_vendor_contract(inv: dict) -> Answer:
    """契約上の権限範囲は AWS API では取得できない。IAM 実態だけは併記する。"""
    iam = _map(inv, "security", "iam")
    users = [u for u in (iam.get("users") or []) if isinstance(u, dict)]
    roles = [r for r in (iam.get("roles") or []) if isinstance(r, dict)]

    details: list[str] = []
    admin_rows: list[list[Any]] = []
    for entry in iam.get("policies_attached_summary") or []:
        if not isinstance(entry, dict):
            continue
        names = [
            str(p.get("PolicyName"))
            for p in entry.get("AttachedPolicies") or []
            if isinstance(p, dict)
        ]
        strong = [n for n in names if n in ("AdministratorAccess", "PowerUserAccess") or n.endswith("FullAccess")]
        if strong:
            admin_rows.append([entry.get("PrincipalType"), entry.get("Name"), ", ".join(strong)])

    if admin_rows:
        details.append("**強い権限（Administrator / PowerUser / *FullAccess）を持つプリンシパル**")
        details.extend(table(["種別", "名前", "付与ポリシー"], admin_rows))
    else:
        details.append("- Administrator / PowerUser / *FullAccess を直接付与されたプリンシパルは検出されなかった。")
    details.append("")
    details.append(
        f"- IAM ユーザー {len(users)} / ロール {len(roles)}。"
        "**どの ID を 開発ベンダーが使っているかは命名からは断定できない。**"
    )
    details.append(
        "- **インラインポリシー（`iam:ListRolePolicies` / `GetRolePolicy`）と"
        "ポリシー本文は awsprobe では収集していない**ため、実効権限の厳密な評価はできない。"
    )

    return Answer(
        "",
        "",
        "",
        NEEDS_MANUAL,
        "**契約上の作業権限の範囲は AWS API では原理的に取得できない**（契約書・覚書の内容であるため）。"
        f"IAM 上の実態としては、強い権限を持つプリンシパルが {len(admin_rows)} 件ある。",
        details,
        ["security.iam.users", "security.iam.roles", "security.iam.policies_attached_summary"],
        manual_steps=(
            "法務・調達に 開発ベンダーとの業務委託契約書（および SLA・作業範囲合意書）を提示させ、"
            "(1) 本番環境への直接操作が認められている作業、(2) 事前承認が必要な作業、"
            "(3) 禁止されている作業、を条文単位で整理すること。"
            "そのうえで上表の IAM 実効権限と突き合わせ、契約より広い権限が付いていないかを確認する。"
        ),
    )


@question(
    "Q32",
    "`code` ディレクトリは Nuxt 単体か、Laravel が同居しているか",
    CAT_APP,
    requires=("compute", "storage"),
)
def q32_code_directory(inv: dict) -> Answer:
    """ディレクトリの中身は EC2 / EFS の内部であり、AWS API では見えない。"""
    access_points = _dicts(inv, "storage", "efs_access_points")
    hosts = host_instances(inv)

    details: list[str] = []
    paths = [
        str((a.get("RootDirectory") or {}).get("Path"))
        for a in access_points
        if isinstance(a.get("RootDirectory"), dict) and (a.get("RootDirectory") or {}).get("Path")
    ]
    if paths:
        details.append("**EFS アクセスポイントのルートパス（`code` の所在の手掛かり）**")
        details.extend(
            table(
                ["アクセスポイント", "FileSystemId", "ルートパス"],
                [
                    [
                        a.get("Name") or _tag(a) or a.get("AccessPointId"),
                        a.get("FileSystemId"),
                        (a.get("RootDirectory") or {}).get("Path"),
                    ]
                    for a in access_points
                    if isinstance(a.get("RootDirectory"), dict)
                ],
            )
        )
        laravel_hint = [p for p in paths if "storage/framework" in p or "storage/app" in p]
        if laravel_hint:
            details.append("")
            details.append(
                f"- **`storage/framework` / `storage/app` を含むパスが {len(laravel_hint)} 件ある**"
                "（Laravel のディレクトリ構造と一致する）: "
                + ", ".join(laravel_hint)
            )
    else:
        details.append("- EFS アクセスポイントが無く、パスからの推定はできない。")

    if hosts:
        details.append("")
        details.append(
            f"- host-probe の結果が {len(hosts)} 台分ある。`ls` / `cat composer.json` 系のプローブ出力を"
            "確認すれば、`code` 配下の構成は確定できる。"
        )

    return Answer(
        "",
        "",
        "",
        NEEDS_MANUAL,
        "**`code` ディレクトリの中身は EC2 / EFS の内部であり、AWS API では取得できない。** "
        + (
            "ただし EFS アクセスポイントのパスが Laravel のディレクトリ構造と一致しており、"
            "Laravel が同居している可能性が高い。"
            if any("storage/framework" in p or "storage/app" in p for p in paths)
            else "EFS のパスからも判断材料は得られなかった。"
        ),
        details,
        ["storage.efs_access_points[].RootDirectory.Path"],
        manual_steps=(
            "`awsprobe host-probe --enable-ssm` で各EC2の `ls -la <アプリルート>/code` と "
            "`composer.json` / `package.json` / `artisan` の有無を採取すること。"
            "または 開発ベンダーにリポジトリのディレクトリ構成図を提出させる。"
        ),
    )


# ===========================================================================
# その他リソース・統制
# ===========================================================================

#: Lambda ランタイムのサポート終了日（AWS 公表値。判定は _TODAY との比較）
LAMBDA_RUNTIME_EOL: dict[str, str] = {
    "python2.7": "2021-07-15",
    "python3.6": "2022-07-18",
    "python3.7": "2023-11-27",
    "python3.8": "2024-10-14",
    "python3.9": "2025-12-15",
    "nodejs": "2016-10-31",
    "nodejs4.3": "2018-04-30",
    "nodejs6.10": "2019-08-12",
    "nodejs8.10": "2020-03-06",
    "nodejs10.x": "2022-07-30",
    "nodejs12.x": "2023-03-31",
    "nodejs14.x": "2024-12-04",
    "nodejs16.x": "2025-06-12",
    "nodejs18.x": "2026-09-01",
    "ruby2.5": "2021-07-30",
    "ruby2.7": "2024-01-09",
    "java8": "2024-01-08",
    "go1.x": "2024-01-08",
    "dotnetcore2.1": "2022-01-05",
    "dotnetcore3.1": "2023-04-03",
    "dotnet5.0": "2022-05-10",
    "dotnet7": "2024-05-14",
    "provided": "2023-12-31",
}


def runtime_eol(runtime: Any) -> tuple[bool, str]:
    """ランタイムが EOL かどうかと、その期日を返す。"""
    eol = LAMBDA_RUNTIME_EOL.get(str(runtime or ""))
    if not eol:
        return False, "—"
    try:
        expired = _dt.date.fromisoformat(eol) <= _TODAY
    except ValueError:
        return False, eol
    return expired, eol


@question(
    "Q24",
    "Lambda 10関数それぞれの名前・用途・ランタイム・トリガ",
    CAT_OTHER,
    requires=("serverless",),
)
def q24_lambda_functions(inv: dict) -> Answer:
    """Lambda の一覧とトリガを表にし、ランタイム EOL を判定する。"""
    functions = _dicts(inv, "serverless", "lambda_functions")
    if not functions:
        summary, details = no_data("Lambda 関数", inv, ("lambda",))
        return Answer("", "", "", NO_DATA, summary, details, ["serverless.lambda_functions"])

    rules = _dicts(inv, "serverless", "eventbridge_rules")
    # EventBridge ターゲットから Lambda への逆引き
    triggers_by_arn: dict[str, list[str]] = {}
    for rule in rules:
        for target in rule.get("Targets") or []:
            if not isinstance(target, dict):
                continue
            arn = str(target.get("Arn") or "")
            if ":function:" in arn:
                triggers_by_arn.setdefault(arn, []).append(
                    f"EventBridge `{rule.get('Name')}`"
                    + (f"（{rule.get('ScheduleExpression')}）" if rule.get("ScheduleExpression") else "")
                )

    evidence: list[str] = []
    rows: list[list[Any]] = []
    eol_functions: list[str] = []
    public_urls: list[str] = []
    idle: list[str] = []
    silent: list[str] = []
    for i, fn in enumerate(functions):
        evidence.append(f"serverless.lambda_functions[{i}].Runtime")
        evidence.append(f"serverless.lambda_functions[{i}]._LastLogEvent")
        arn = str(fn.get("FunctionArn") or "")
        name = str(fn.get("FunctionName") or "")
        expired, eol_date = runtime_eol(fn.get("Runtime"))
        if expired:
            eol_functions.append(name)

        triggers = list(triggers_by_arn.get(arn, []))
        for mapping in fn.get("EventSourceMappings") or []:
            if not isinstance(mapping, dict):
                continue
            source = str(mapping.get("EventSourceArn") or "")
            triggers.append(f"イベントソース `{source.rsplit(':', 1)[-1] or source}`（{mapping.get('State')}）")
        policy = fn.get("Policy")
        if isinstance(policy, dict):
            for statement in policy.get("Statement") or []:
                if not isinstance(statement, dict):
                    continue
                principal = statement.get("Principal")
                service = principal.get("Service") if isinstance(principal, dict) else None
                if service:
                    triggers.append(f"リソースポリシー許可 `{service}`")
        url_config = fn.get("UrlConfig") if isinstance(fn.get("UrlConfig"), dict) else None
        if url_config:
            auth = url_config.get("AuthType")
            triggers.append(f"関数URL（AuthType={auth}）")
            if auth == "NONE":
                public_urls.append(name)

        env = fn.get("Environment") if isinstance(fn.get("Environment"), dict) else {}
        last_log = fn.get("_LastLogEvent") if isinstance(fn.get("_LastLogEvent"), dict) else None
        last_run_days = days_since((last_log or {}).get("lastEventTime"))
        if last_log is None:
            last_run = "ログ無し"
            silent.append(name)
        elif last_run_days is None:
            last_run = "—"
        else:
            last_run = f"{last_run_days}日前"
            if last_run_days > _LAMBDA_IDLE_DAYS:
                idle.append(f"{name}（{last_run_days}日前）")
        rows.append(
            [
                name,
                f"**{fn.get('Runtime')}（EOL {eol_date}）**" if expired else fn.get("Runtime"),
                fn.get("Handler"),
                fn.get("LastModified"),
                last_run,
                f"{fn.get('MemorySize')}MB / {fn.get('Timeout')}s",
                ", ".join(triggers) or "**トリガ未検出**",
                ", ".join(str(k) for k in (env.get("_keys") or [])[:6]) or "—",
            ]
        )

    details = [f"**Lambda 関数一覧（{len(functions)}本）**"]
    details.extend(
        table(
            ["関数名", "ランタイム", "ハンドラ", "最終更新", "最終実行", "メモリ/タイムアウト", "トリガ", "環境変数キー（先頭6件）"],
            rows,
        )
    )
    details.append("")
    if eol_functions:
        details.append(
            f"- **サポート終了済みランタイムを使っている関数が {len(eol_functions)} 本ある**: "
            f"{', '.join(eol_functions)}。セキュリティパッチが提供されず、"
            "コード更新もブロックされる（AWS はランタイム廃止後に更新を拒否する）。"
        )
    else:
        details.append("- サポート終了済みランタイムを使っている関数は無い。")
    if public_urls:
        details.append(
            f"- **認証なしの関数URL（AuthType=NONE）が開いている関数: {', '.join(public_urls)}**。"
        )
    untriggered = [str(r[0]) for r in rows if "トリガ未検出" in str(r[6])]
    if untriggered:
        details.append(
            f"- トリガが検出できなかった関数: {', '.join(untriggered)}"
            "（手動実行・他アカウントからの呼び出し・未使用のいずれか）。"
            "**最終実行の列と併せて読むこと。**"
        )
    if silent:
        details.append(
            f"- **ロググループが存在しない関数: {', '.join(silent)}**。"
            "一度も実行されていないか、ログを消したか、`logs:DescribeLogStreams` の"
            "権限が無いかのいずれか（権限不足なら errors に記録が残る）。"
        )
    if idle:
        details.append(
            f"- **{_LAMBDA_IDLE_DAYS}日以上動いていない関数: {', '.join(idle)}**。削除候補。"
        )
    details.append(
        "- 最終実行は `/aws/lambda/<関数名>` の最新ログストリームの書き込み時刻から取った"
        "（**ログ本文は読んでいない**。ストリームのメタデータのみ）。"
    )

    summary = (
        f"Lambda {len(functions)} 本の名前・ランタイム・ハンドラ・トリガをすべて特定した。"
        + (
            f"**うち {len(eol_functions)} 本が EOL ランタイム。**"
            if eol_functions
            else "EOL ランタイムは無い。"
        )
        + " 用途（何のための関数か）は命名と環境変数キーからの推定にとどまる。"
        + (
            f" **最終実行まで確定済み（{len(idle)}本が{_LAMBDA_IDLE_DAYS}日以上未実行）。**"
            if idle
            else " 最終実行まで確定済み。"
        )
    )
    # トリガが検出できなくても、最終実行が取れていれば「動いているか」は確定する。
    # 全ての関数で最終実行の判定材料が揃っていれば answered に上げる。
    unresolved = [n for n in untriggered if n in silent]
    return Answer(
        "",
        "",
        "",
        ANSWERED if not unresolved else PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "トリガもロググループも見つからない関数（"
            + "、".join(unresolved)
            + "）について、`logs:DescribeLogStreams` の権限があるかを errors で確認し、"
            "権限があってログが無いなら未使用として削除候補に回すこと。"
        )
        if unresolved
        else None,
    )


@question(
    "Q25",
    "EventBridge ルール5本それぞれのスケジュール／イベントパターンとターゲット。`RdsAutoStopNotify` は何を停止・通知しているか",
    CAT_OTHER,
    requires=("serverless",),
)
def q25_eventbridge_rules(inv: dict) -> Answer:
    """EventBridge ルールの定義とターゲットを表にする。"""
    rules = _dicts(inv, "serverless", "eventbridge_rules")
    if not rules:
        summary, details = no_data("EventBridge ルール", inv, ("events",))
        return Answer("", "", "", NO_DATA, summary, details, ["serverless.eventbridge_rules"])

    evidence: list[str] = []
    rows: list[list[Any]] = []
    disabled: list[str] = []
    for i, rule in enumerate(rules):
        evidence.append(f"serverless.eventbridge_rules[{i}].Targets")
        name = str(rule.get("Name") or "")
        if str(rule.get("State")) != "ENABLED":
            disabled.append(name)
        pattern = rule.get("EventPattern")
        targets = [
            f"{str(t.get('Arn') or '').rsplit(':', 1)[-1] or t.get('Arn')}"
            for t in rule.get("Targets") or []
            if isinstance(t, dict)
        ]
        rows.append(
            [
                name,
                rule.get("EventBusName") or "default",
                rule.get("ScheduleExpression") or "—",
                (str(pattern)[:80] + "…") if pattern and len(str(pattern)) > 80 else (pattern or "—"),
                rule.get("State"),
                ", ".join(targets) or "**ターゲット無し**",
                rule.get("Description") or "—",
            ]
        )

    details = [f"**EventBridge ルール一覧（{len(rules)}本）**"]
    details.extend(
        table(
            ["ルール名", "イベントバス", "スケジュール", "イベントパターン", "状態", "ターゲット", "説明"],
            rows,
        )
    )

    rds_rules = [r for r in rules if "rdsautostop" in str(r.get("Name") or "").lower().replace("-", "").replace("_", "")]
    details.append("")
    if rds_rules:
        details.append("**`RdsAutoStopNotify` 関連ルールの詳細**")
        for rule in rds_rules:
            details.append(
                f"- `{rule.get('Name')}`: スケジュール `{rule.get('ScheduleExpression') or '—'}` / "
                f"状態 {rule.get('State')} / ターゲット "
                + ", ".join(
                    f"`{t.get('Arn')}`" for t in rule.get("Targets") or [] if isinstance(t, dict)
                )
            )
            for target in rule.get("Targets") or []:
                if isinstance(target, dict) and target.get("Input"):
                    details.append(f"  - 入力: `{str(target.get('Input'))[:200]}`")
    else:
        details.append(
            "- 名前に `RdsAutoStopNotify` を含む EventBridge ルールは存在しない"
            "（SNS トピック側にある可能性については Q41 を参照）。"
        )
    if disabled:
        details.append("")
        details.append(f"- **無効（DISABLED）のルール: {', '.join(disabled)}**")

    summary = (
        f"EventBridge ルール {len(rules)} 本のスケジュール／イベントパターン／ターゲットをすべて特定した"
        f"（無効 {len(disabled)} 本）。"
        + (
            f"`RdsAutoStopNotify` 関連のルールは {len(rds_rules)} 本で、停止対象と通知先を特定できた。"
            if rds_rules
            else "`RdsAutoStopNotify` は EventBridge ルールではない（Q41 参照）。"
        )
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q41",
    "`RdsAutoStopNotify` / `config-topic` / `CodeStarNotifications-test-codebuild-*` のサービス種別（SNSトピックか、EventBridge ルールか）",
    CAT_OTHER,
    requires=("serverless", "security"),
)
def q41_service_types(inv: dict) -> Answer:
    """名前一致で EventBridge / SNS / CloudFormation を横断し、サービス種別を確定する。"""
    rules = _dicts(inv, "serverless", "eventbridge_rules")
    topics = _dicts(inv, "serverless", "sns_topics")
    stacks = _dicts(inv, "security", "cloudformation_stacks")
    functions = _dicts(inv, "serverless", "lambda_functions")
    queues = _dicts(inv, "serverless", "sqs_queues")

    targets = ("rdsautostopnotify", "configtopic", "codestarnotifications")

    def _norm(text: Any) -> str:
        return re.sub(r"[-_\s]", "", str(text or "")).lower()

    rows: list[list[Any]] = []
    found: dict[str, list[str]] = {t: [] for t in targets}

    def _check(kind: str, name: Any, extra: Any = "") -> None:
        normalized = _norm(name)
        for key in targets:
            if key in normalized:
                found[key].append(kind)
                rows.append([str(name), f"**{kind}**", extra])

    for rule in rules:
        _check(
            "EventBridge ルール",
            rule.get("Name"),
            f"スケジュール={rule.get('ScheduleExpression') or '—'} / 状態={rule.get('State')}",
        )
    for topic in topics:
        arn = str(topic.get("TopicArn") or "")
        _check(
            "SNS トピック",
            arn.rsplit(":", 1)[-1],
            f"購読 {len(topic.get('Subscriptions') or [])} 件",
        )
    for fn in functions:
        _check("Lambda 関数", fn.get("FunctionName"), f"ランタイム={fn.get('Runtime')}")
    for queue in queues:
        _check("SQS キュー", str(queue.get("QueueUrl") or "").rsplit("/", 1)[-1])
    for stack in stacks:
        _check("CloudFormation スタック", stack.get("StackName"), stack.get("StackStatus"))

    details: list[str] = []
    if rows:
        details.append("**名前一致で特定したリソースの実サービス種別**")
        details.extend(table(["リソース名", "サービス種別", "補足"], rows))
    label = {
        "rdsautostopnotify": "RdsAutoStopNotify",
        "configtopic": "config-topic",
        "codestarnotifications": "CodeStarNotifications-test-codebuild-*",
    }
    details.append("")
    details.append("**設問で挙げられた3リソースの判定**")
    details.extend(
        table(
            ["リソース", "判定"],
            [
                [
                    label[key],
                    "／".join(sorted(set(kinds))) if kinds else "**このアカウントに存在しない**",
                ]
                for key, kinds in found.items()
            ],
        )
    )

    resolved = sum(1 for kinds in found.values() if kinds)
    summary = (
        f"EventBridge / SNS / Lambda / SQS / CloudFormation を横断して名前一致で走査し、"
        f"設問の3リソースのうち {resolved} 件のサービス種別を確定した。"
        + (
            "残りはこのアカウントに存在しない（削除済みか、別アカウントのリソース）。"
            if resolved < len(found)
            else ""
        )
    )
    return Answer(
        "",
        "",
        "",
        ANSWERED,
        summary,
        details,
        ["serverless.eventbridge_rules", "serverless.sns_topics", "security.cloudformation_stacks"],
    )


@question(
    "Q26",
    "DLT（Step Functions / DynamoDB×2 / Cognito）は最後にいつ使われたか。今後の負荷試験計画はあるか。無いなら削除できるか",
    CAT_OTHER,
    requires=("serverless",),
)
def q26_dlt(inv: dict) -> Answer:
    """DLT 一式の最終更新日時から使用状況を推定する。計画の有無は人に聞く。"""
    machines = _dicts(inv, "serverless", "stepfunctions_state_machines")
    tables = _dicts(inv, "serverless", "dynamodb_tables")
    pools = _dicts(inv, "serverless", "cognito_user_pools")

    def _is_dlt(name: Any) -> bool:
        lowered = str(name or "").lower()
        return "dlt" in lowered or "load-test" in lowered or "loadtest" in lowered

    rows: list[list[Any]] = []
    ages: list[int] = []

    last_runs: list[str] = []
    never_run: list[str] = []
    for machine in machines:
        if not _is_dlt(machine.get("name")):
            continue
        age = days_since(machine.get("creationDate"))
        if age is not None:
            ages.append(age)
        execution = (
            machine.get("_LastExecution")
            if isinstance(machine.get("_LastExecution"), dict)
            else None
        )
        run_age = days_since((execution or {}).get("startDate"))
        if execution is None:
            note = "**実行履歴なし**"
            never_run.append(str(machine.get("name")))
        else:
            note = (
                f"最終実行 {run_age} 日前（{execution.get('status')}）"
                if run_age is not None
                else f"最終実行 {execution.get('startDate')}（{execution.get('status')}）"
            )
            last_runs.append(note)
        rows.append(
            [
                "Step Functions",
                machine.get("name"),
                machine.get("creationDate"),
                f"{age} 日前" if age is not None else "—",
                note,
            ]
        )
    for tbl in tables:
        if not _is_dlt(tbl.get("TableName")):
            continue
        age = days_since(tbl.get("CreationDateTime"))
        if age is not None:
            ages.append(age)
        rows.append(
            [
                "DynamoDB",
                tbl.get("TableName"),
                tbl.get("CreationDateTime"),
                f"{age} 日前" if age is not None else "—",
                f"{tbl.get('ItemCount')} 項目 / {tbl.get('TableSizeBytes')} byte",
            ]
        )
    for pool in pools:
        if not _is_dlt(pool.get("Name")):
            continue
        age = days_since(pool.get("LastModifiedDate"))
        if age is not None:
            ages.append(age)
        rows.append(
            [
                "Cognito",
                pool.get("Name"),
                pool.get("LastModifiedDate"),
                f"{age} 日前" if age is not None else "—",
                f"推定ユーザー {pool.get('EstimatedNumberOfUsers')}",
            ]
        )

    evidence = [
        "serverless.stepfunctions_state_machines",
        "serverless.dynamodb_tables",
        "serverless.cognito_user_pools",
    ]

    if not rows:
        return Answer(
            "",
            "",
            "",
            ANSWERED,
            "**DLT（Distributed Load Testing）関連のリソースは存在しない。** "
            "Step Functions / DynamoDB / Cognito のいずれにも DLT 由来の名前を持つものが無く、"
            "削除済みと判断できる。",
            [
                f"- 走査対象: Step Functions {len(machines)} 本 / DynamoDB {len(tables)} 本 / "
                f"Cognito {len(pools)} 本。うち DLT 該当 0 件。"
            ],
            evidence,
        )

    details = [f"**DLT 関連リソース（{len(rows)}件）**"]
    details.extend(table(["サービス", "リソース名", "作成/最終更新", "経過", "補足"], rows))
    details.append("")
    if ages:
        details.append(
            f"- 最も新しい更新でも **{min(ages)} 日前**（最古 {max(ages)} 日前）。"
            + (
                "1年以上動いていない残骸と判断してよい。"
                if min(ages) > 365
                else "直近で触られている可能性があるため、利用者への確認が必要。"
            )
        )
    details.append(
        "- **DynamoDB の `ItemCount` は AWS が約6時間ごとに更新する概算値**であり、"
        "0 でもデータが無いとは限らない点に注意。"
    )
    if never_run:
        details.append(
            f"- **実行履歴が 1 件も無いステートマシン: {', '.join(never_run)}**。"
            "作られたまま一度も動いていない（または履歴の保持期間を過ぎている）。"
        )
    if last_runs:
        details.append("- 最終実行は `states:ListExecutions` の直近 1 件から取った"
                       "（**実行の入出力は取得していない**）。")

    summary = (
        f"DLT 一式 {len(rows)} 件を特定し、作成／最終更新の経過日数と"
        "**Step Functions の最終実行日まで**確認できた"
        + (f"（最新の更新でも {min(ages)} 日前）" if ages else "")
        + "。"
        + (
            "**実行履歴は 1 件も無い。**"
            if never_run and not last_runs
            else ""
        )
        + "残るのは今後の負荷試験計画の有無だけで、これは人に聞くしかない。"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "最終実行日はこのレポートで確定済み。残るは発注元社内・開発ベンダーへの"
            "「今後1年の負荷試験計画の有無」の確認だけで、計画が無ければ DLT 一式"
            "（Step Functions / DynamoDB×2 / Cognito / 関連 IAM ロール）はまとめて削除できる。"
        ),
    )


def _is_log_bucket(name: Any) -> bool:
    """バケット名がログ用途（log / cloudtrail / config）を示すか。"""
    lowered = str(name or "").lower()
    return any(k in lowered for k in ("log", "cloudtrail", "config"))


@question(
    "Q28",
    "各ログバケット（CloudTrail / Config / フローログ / ALB）のライフサイクルルール（保持期間）",
    CAT_OTHER,
    requires=("storage",),
)
def q28_log_bucket_lifecycle(inv: dict) -> Answer:
    """ログ用バケットの Lifecycle を判定する。"""
    buckets = _dicts(inv, "storage", "buckets")
    if not buckets:
        summary, details = no_data("S3 バケット", inv, ("s3",))
        return Answer("", "", "", NO_DATA, summary, details, ["storage.buckets"])

    log_buckets = [b for b in buckets if _is_log_bucket(b.get("Name"))]
    evidence: list[str] = []
    rows: list[list[Any]] = []
    no_lifecycle: list[str] = []
    for i, bucket in enumerate(buckets):
        if not _is_log_bucket(bucket.get("Name")):
            continue
        evidence.append(f"storage.buckets[{i}].Lifecycle")
        name = str(bucket.get("Name"))
        rules = bucket.get("Lifecycle")
        if not rules:
            no_lifecycle.append(name)
            rows.append([name, bucket.get("Region"), "**ルール無し（無期限保持）**", "—", "—", "—"])
            continue
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, dict):
                continue
            transitions = ", ".join(
                f"{t.get('Days')}日→{t.get('StorageClass')}"
                for t in rule.get("Transitions") or []
                if isinstance(t, dict)
            )
            expiration = rule.get("Expiration") if isinstance(rule.get("Expiration"), dict) else {}
            noncurrent = rule.get("NoncurrentVersionExpiration") if isinstance(rule.get("NoncurrentVersionExpiration"), dict) else {}
            rows.append(
                [
                    name,
                    bucket.get("Region"),
                    rule.get("ID") or "(名前なし)",
                    rule.get("Status"),
                    f"{expiration.get('Days')}日" if expiration.get("Days") else (expiration.get("Date") or "—"),
                    f"{transitions or '—'}"
                    + (
                        f" / 旧バージョン {noncurrent.get('NoncurrentDays')}日"
                        if noncurrent.get("NoncurrentDays")
                        else ""
                    ),
                ]
            )

    if not log_buckets:
        return Answer(
            "",
            "",
            "",
            ANSWERED,
            f"**ログ用途と判定できるバケットは存在しない**（全 {len(buckets)} バケットの名前に "
            "log / cloudtrail / config を含むものが無い）。",
            [],
            ["storage.buckets"],
        )

    details = [f"**ログ用バケットのライフサイクルルール（{len(log_buckets)}本）**"]
    details.extend(
        table(["バケット", "リージョン", "ルールID", "状態", "有効期限", "ストレージクラス移行"], rows)
    )
    details.append("")
    if no_lifecycle:
        details.append(
            f"- **ライフサイクルルールが設定されていないログバケット: {', '.join(no_lifecycle)}**。"
            "オブジェクトが無期限に蓄積し、ストレージ料金が増え続ける。"
        )
    else:
        details.append("- すべてのログバケットにライフサイクルルールが設定されている。")

    summary = (
        f"ログ用バケット {len(log_buckets)} 本のライフサイクル設定をすべて確定した。"
        + (
            f"**うち {len(no_lifecycle)} 本はルール無し（無期限保持）。**"
            if no_lifecycle
            else "全バケットに保持期間が設定されている。"
        )
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q42",
    "AWS Config レコーダー・VPC フローログ・ALBアクセスログは実際に有効か。ALBは本番以外の5本もログを取っているか",
    CAT_OTHER,
    requires=("logging", "edge"),
)
def q42_logging_actually_enabled(inv: dict) -> Answer:
    """Config の recording / フローログの FlowLogStatus / ALB 属性を実値で判定する。"""
    recorders = _dicts(inv, "logging", "config_recorders")
    flow_logs = _dicts(inv, "logging", "flow_logs")
    load_balancers = _dicts(inv, "edge", "load_balancers")
    trails = _dicts(inv, "logging", "cloudtrail_trails")

    evidence: list[str] = []
    details: list[str] = []
    problems: list[str] = []

    # --- AWS Config -------------------------------------------------
    recorder_rows: list[list[Any]] = []
    for i, recorder in enumerate(recorders):
        evidence.append(f"logging.config_recorders[{i}].Status.recording")
        status = recorder.get("Status") if isinstance(recorder.get("Status"), dict) else {}
        recording = bool(status.get("recording"))
        if not recording:
            problems.append(f"Config レコーダー `{recorder.get('name')}`")
        group = recorder.get("recordingGroup") if isinstance(recorder.get("recordingGroup"), dict) else {}
        recorder_rows.append(
            [
                recorder.get("name"),
                "**有効**" if recording else "**停止中**",
                status.get("lastStatus") or "—",
                status.get("lastStatusChangeTime") or "—",
                group.get("allSupported"),
                status.get("lastErrorMessage") or "—",
            ]
        )
    details.append("**AWS Config レコーダー**")
    details.extend(
        table(["レコーダー名", "記録", "最終ステータス", "最終変化", "全リソース記録", "最終エラー"], recorder_rows)
        or ["", "- **Config レコーダーが1件も存在しない。AWS Config は無効。**"]
    )
    if not recorders:
        problems.append("AWS Config（レコーダー未作成）")

    channels = _dicts(inv, "logging", "config_delivery_channels")
    if channels:
        details.append("")
        details.append("**Config 配信チャネル**")
        details.extend(
            table(
                ["名前", "配信先バケット", "プレフィックス", "SNS"],
                [
                    [c.get("name"), c.get("s3BucketName"), c.get("s3KeyPrefix") or "—", c.get("snsTopicARN") or "—"]
                    for c in channels
                ],
            )
        )

    # --- VPC フローログ ---------------------------------------------
    details.append("")
    flow_rows: list[list[Any]] = []
    for i, flow in enumerate(flow_logs):
        evidence.append(f"logging.flow_logs[{i}].FlowLogStatus")
        active = str(flow.get("FlowLogStatus")) == "ACTIVE"
        if not active:
            problems.append(f"フローログ `{flow.get('FlowLogId')}`")
        flow_rows.append(
            [
                flow.get("FlowLogId"),
                flow.get("ResourceId"),
                "**ACTIVE**" if active else f"**{flow.get('FlowLogStatus')}**",
                flow.get("TrafficType"),
                flow.get("LogDestinationType"),
                flow.get("LogDestination") or flow.get("LogGroupName") or "—",
                flow.get("DeliverLogsErrorMessage") or "—",
            ]
        )
    details.append("**VPC フローログ**")
    details.extend(
        table(["FlowLogId", "対象リソース", "状態", "種別", "出力先種別", "出力先", "配信エラー"], flow_rows)
        or ["", "- **VPC フローログが1件も存在しない。フローログは無効。**"]
    )
    if not flow_logs:
        problems.append("VPC フローログ（未作成）")

    # --- ALB アクセスログ -------------------------------------------
    details.append("")
    lb_rows: list[list[Any]] = []
    logging_off: list[str] = []
    for i, lb in enumerate(load_balancers):
        evidence.append(f"edge.load_balancers[{i}].Attributes")
        attrs = {
            a.get("Key"): a.get("Value")
            for a in lb.get("Attributes") or []
            if isinstance(a, dict)
        }
        enabled = str(attrs.get("access_logs.s3.enabled", "")).lower() == "true"
        name = str(lb.get("LoadBalancerName"))
        if not enabled:
            logging_off.append(name)
        lb_rows.append(
            [
                name,
                lb.get("Type"),
                lb.get("Scheme"),
                "**有効**" if enabled else "**無効**",
                attrs.get("access_logs.s3.bucket") or "—",
                attrs.get("access_logs.s3.prefix") or "—",
                attrs.get("deletion_protection.enabled") or "—",
            ]
        )
    details.append(f"**ALB / NLB アクセスログ（{len(load_balancers)}本すべて）**")
    details.extend(
        table(["ロードバランサ", "種別", "公開範囲", "アクセスログ", "出力先バケット", "プレフィックス", "削除保護"], lb_rows)
        or ["", "- ロードバランサが存在しない。"]
    )

    # --- CloudTrail（参考） -----------------------------------------
    if trails:
        details.append("")
        details.append("**CloudTrail（参考）**")
        details.extend(
            table(
                ["証跡名", "記録中", "全リージョン", "出力先バケット", "最終配信"],
                [
                    [
                        t.get("Name"),
                        "**はい**" if t.get("IsLogging") else "**いいえ**",
                        t.get("IsMultiRegionTrail"),
                        t.get("S3BucketName"),
                        (t.get("Status") or {}).get("LatestDeliveryTime") if isinstance(t.get("Status"), dict) else "—",
                    ]
                    for t in trails
                ],
            )
        )
        evidence.append("logging.cloudtrail_trails[].IsLogging")
        for trail in trails:
            if not trail.get("IsLogging"):
                problems.append(f"CloudTrail `{trail.get('Name')}`（記録停止中）")

    details.append("")
    if logging_off:
        problems.append(f"アクセスログ無効な LB {len(logging_off)} 本")
        details.append(
            f"- **アクセスログが無効なロードバランサが {len(logging_off)}/{len(load_balancers)} 本ある**: "
            f"{', '.join(logging_off)}。インシデント時に通信元を追跡できない。"
        )
    else:
        details.append(f"- ロードバランサ {len(load_balancers)} 本すべてでアクセスログが有効。")

    active_recorders = sum(
        1
        for r in recorders
        if isinstance(r.get("Status"), dict) and r["Status"].get("recording")
    )
    active_flows = sum(1 for f in flow_logs if str(f.get("FlowLogStatus")) == "ACTIVE")
    summary = (
        f"**Config レコーダー {active_recorders}/{len(recorders)} 件が記録中、"
        f"VPC フローログ {active_flows}/{len(flow_logs)} 件が ACTIVE、"
        f"アクセスログ有効な LB は {len(load_balancers) - len(logging_off)}/{len(load_balancers)} 本。**"
        + (
            f" **是正が必要な項目: {', '.join(problems[:5])}。**"
            if problems
            else " Config・フローログ・ALBアクセスログの3系統すべてが正常に稼働している。"
        )
    )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q29",
    "Next のアカウントは Organizations 配下にあり、既存8環境と同じOU／SCPの統制下にあるか",
    CAT_OTHER,
    requires=("security",),
)
def q29_organizations(inv: dict) -> Answer:
    """Organizations の所属と、アカウントに直接付いている SCP を判定する。"""
    organizations = _map(inv, "security", "organizations")
    denied = denied_for(inv, ("organizations",))
    evidence = ["security.organizations"]

    if not organizations:
        if denied:
            summary, details = no_data("Organizations 情報", inv, ("organizations",))
            return Answer("", "", "", NO_DATA, summary, details, evidence)
        org_errors = errors_for(inv, services=("organizations",))
        not_in_use = any(
            str(e.get("code")) == "AWSOrganizationsNotInUseException" for e in org_errors
        )
        summary = (
            "**このアカウントは AWS Organizations に所属していない**"
            "（`AWSOrganizationsNotInUseException`）。SCP による統制は一切効いていない。"
            if not_in_use
            else "Organizations 情報が空だった。組織未参加か、収集できなかった。"
        )
        return Answer(
            "",
            "",
            "",
            ANSWERED if not_in_use else NO_DATA,
            summary,
            [
                "- 既存8環境と同じ OU／SCP の統制下には無いため、"
                "切離しの前後で統制レベルを揃える設計が別途必要。"
            ]
            if not_in_use
            else [],
            evidence,
        )

    org = organizations.get("Organization") if isinstance(organizations.get("Organization"), dict) else {}
    parents = [p for p in organizations.get("Parents") or [] if isinstance(p, dict)]
    scps = [p for p in organizations.get("ServiceControlPolicies") or [] if isinstance(p, dict)]

    details = ["**組織情報**"]
    details.extend(
        table(
            ["組織ID", "管理アカウント", "機能セット", "ARN"],
            [
                [
                    org.get("Id"),
                    org.get("MasterAccountId") or org.get("ManagementAccountId"),
                    org.get("FeatureSet"),
                    org.get("Arn"),
                ]
            ],
        )
    )
    details.append("")
    details.append("**自アカウントの親（OU）**")
    details.extend(
        table(["親ID", "種別"], [[p.get("Id"), p.get("Type")] for p in parents])
        or ["- 親 OU が取得できていない（Root 直下、または権限不足）。"]
    )
    details.append("")
    details.append("**アカウントに直接アタッチされている SCP**")
    details.extend(
        table(
            ["ポリシー名", "ID", "AWS管理", "説明"],
            [[p.get("Name"), p.get("Id"), p.get("AwsManaged"), p.get("Description")] for p in scps],
        )
        or ["- 直接アタッチされている SCP は無い（OU 継承分は別途確認が必要）。"]
    )
    details.append("")
    details.append(
        "- **OU から継承している SCP は `list_policies_for_target` では取得できない**"
        "（awsprobe は自アカウント直下の SCP のみ収集）。完全な実効権限の評価には"
        "親 OU と Root の SCP も辿る必要がある。"
    )

    only_default = all(str(p.get("Name")) == "FullAWSAccess" for p in scps) if scps else True
    summary = (
        f"**このアカウントは Organizations（{org.get('Id')}）配下にある。** "
        f"親 {len(parents)} 件・直接アタッチされた SCP {len(scps)} 件を特定した。"
        + (
            "**直接アタッチされた SCP は FullAWSAccess のみで、追加の制限は効いていない。**"
            if only_default
            else ""
        )
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "既存8環境のアカウントがどの OU に属し、どの SCP を継承しているかを"
            "管理アカウント側で確認し、対象アカウントと突き合わせること"
            "（OU 継承分の SCP は本ツールでは取得できない）。"
        ),
    )


@question(
    "Q40",
    "`example.com` のホストゾーンはどのアカウントにあるか。ALB 6本・CloudFront 2本のACM証明書はどこで管理されているか",
    CAT_OTHER,
    requires=("edge",),
)
def q40_domain_and_acm(inv: dict) -> Answer:
    """自アカウントにゾーンが無いことの確認と、ACM 証明書の一覧を出す。"""
    zones = _dicts(inv, "edge", "route53_hosted_zones")
    certificates = _dicts(inv, "edge", "acm_certificates")
    evidence = ["edge.route53_hosted_zones", "edge.acm_certificates"]

    target = "example.com"
    matched = [z for z in zones if target in str(z.get("Name") or "")]

    details = [f"**このアカウントの Route 53 ホストゾーン（{len(zones)}件）**"]
    details.extend(
        table(
            ["ゾーン名", "ID", "プライベート", "レコード数"],
            [
                [
                    z.get("Name"),
                    str(z.get("Id") or "").rsplit("/", 1)[-1],
                    (z.get("Config") or {}).get("PrivateZone") if isinstance(z.get("Config"), dict) else "—",
                    z.get("ResourceRecordSetCount"),
                ]
                for z in zones
            ],
        )
        or ["- ホストゾーンは1件も存在しない。"]
    )
    details.append("")
    details.append(
        f"- **`{target}` のホストゾーンはこのアカウントに"
        + ("存在する。**" if matched else "**存在しない**。他アカウント（DNS管理アカウント）にある。**")
    )

    cert_rows: list[list[Any]] = []
    expiring: list[str] = []
    unused: list[str] = []
    for i, cert in enumerate(certificates):
        evidence.append(f"edge.acm_certificates[{i}].InUseBy")
        in_use = [u for u in (cert.get("InUseBy") or []) if isinstance(u, str)]
        not_after = cert.get("NotAfter")
        days = None
        parsed = parse_dt(not_after)
        if parsed:
            days = (parsed.date() - _TODAY).days
            if days is not None and days < 60:
                expiring.append(str(cert.get("DomainName")))
        if not in_use:
            unused.append(str(cert.get("DomainName")))
        cert_rows.append(
            [
                cert.get("DomainName"),
                cert.get("_Region"),
                cert.get("Status"),
                cert.get("Type"),
                not_after or "—",
                f"{days} 日" if days is not None else "—",
                len(in_use),
                ", ".join(u.rsplit("/", 1)[-1] for u in in_use[:3]) or "**未使用**",
            ]
        )

    details.append("")
    details.append(f"**ACM 証明書（{len(certificates)}件。調査リージョンと us-east-1 の両方）**")
    details.extend(
        table(
            ["ドメイン", "リージョン", "状態", "種別", "有効期限", "残日数", "使用数", "使用先"],
            cert_rows,
        )
        or ["- ACM 証明書は1件も存在しない。"]
    )
    details.append("")
    if expiring:
        details.append(f"- **60日以内に期限切れになる証明書: {', '.join(sorted(set(expiring)))}**")
    if unused:
        details.append(f"- 使用されていない証明書: {', '.join(sorted(set(unused)))}")
    details.append(
        "- **ALB/CloudFront が使っている証明書が他アカウント発行のものである場合、"
        "この一覧には現れない。** リスナーの `Certificates[].CertificateArn` と突き合わせること。"
    )

    listeners = _dicts(inv, "edge", "listeners")
    listener_certs: list[list[Any]] = []
    known = {str(c.get("CertificateArn")) for c in certificates if c.get("CertificateArn")}
    for listener in listeners:
        for cert in listener.get("Certificates") or []:
            if not isinstance(cert, dict):
                continue
            arn = str(cert.get("CertificateArn") or "")
            listener_certs.append(
                [
                    str(listener.get("LoadBalancerArn") or "").rsplit("/", 2)[-2]
                    if "/" in str(listener.get("LoadBalancerArn") or "")
                    else listener.get("LoadBalancerArn"),
                    listener.get("Port"),
                    arn.rsplit("/", 1)[-1],
                    "このアカウント" if arn in known else "**別アカウント／未取得**",
                ]
            )
    if listener_certs:
        details.append("")
        details.append("**リスナーが使っている証明書**")
        details.extend(table(["ロードバランサ", "ポート", "証明書ID", "所在"], listener_certs))
        evidence.append("edge.listeners[].Certificates")

    summary = (
        f"**`{target}` のホストゾーンはこのアカウントに"
        + ("ある。**" if matched else "無い（他アカウント管理）。**")
        + f" ACM 証明書 {len(certificates)} 件の使用先・有効期限は確定した。"
        "**ただし『どのアカウントにゾーンがあるか』は、そのアカウントを調査しないと特定できない。**"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            f"`dig NS {target}` で権威ネームサーバを確認し、その NS が属する Route 53 ゾーンを"
            "他アカウント（DNS管理アカウント）で検索すること。"
            "併せて、切離し時にゾーンを移管するのか委任だけ変えるのかを決める。"
        ),
    )


@question(
    "Q30",
    "Route 53 ホストゾーン `portal.example.net.` が 対象アカウントにある理由。CloudFront 2本はそれぞれ何を配信しているか",
    CAT_OTHER,
    requires=("edge",),
)
def q30_secondary_zone(inv: dict) -> Answer:
    """CP のゾーンの存在と、CloudFront の配信対象（オリジン）を特定する。"""
    zones = _dicts(inv, "edge", "route53_hosted_zones")
    record_sets = _map(inv, "edge", "route53_record_sets")
    distributions = _dicts(inv, "edge", "cloudfront_distributions")
    evidence = ["edge.route53_hosted_zones", "edge.route53_record_sets", "edge.cloudfront_distributions"]

    cp_zones = [z for z in zones if "portal.example.net" in str(z.get("Name") or "").lower()]
    details: list[str] = []

    if cp_zones:
        details.append("**`portal.example.net` のホストゾーン**")
        details.extend(
            table(
                ["ゾーン名", "ID", "プライベート", "レコード数", "コメント"],
                [
                    [
                        z.get("Name"),
                        str(z.get("Id") or "").rsplit("/", 1)[-1],
                        (z.get("Config") or {}).get("PrivateZone") if isinstance(z.get("Config"), dict) else "—",
                        z.get("ResourceRecordSetCount"),
                        (z.get("Config") or {}).get("Comment") if isinstance(z.get("Config"), dict) else "—",
                    ]
                    for z in cp_zones
                ],
            )
        )
        for zone in cp_zones:
            zone_id = str(zone.get("Id") or "").rsplit("/", 1)[-1]
            records = [r for r in (record_sets.get(zone_id) or []) if isinstance(r, dict)]
            important = [
                r for r in records if r.get("Type") in ("A", "AAAA", "CNAME", "NS", "MX")
            ]
            if important:
                details.append("")
                details.append(f"**`{zone.get('Name')}` の主要レコード（{len(important)}件）**")
                details.extend(
                    table(
                        ["名前", "種別", "向き先"],
                        [
                            [
                                r.get("Name"),
                                r.get("Type"),
                                (r.get("AliasTarget") or {}).get("DNSName")
                                if isinstance(r.get("AliasTarget"), dict)
                                else ", ".join(
                                    str(v.get("Value"))
                                    for v in r.get("ResourceRecords") or []
                                    if isinstance(v, dict)
                                ),
                            ]
                            for r in important[:30]
                        ],
                    )
                )
    else:
        details.append(
            "- **`portal.example.net` のホストゾーンはこのアカウントに存在しない。** "
            "設計資料 §5-10 の記載は現況と異なる（移管済みか、元から別アカウント）。"
        )

    cf_rows: list[list[Any]] = []
    for i, dist in enumerate(distributions):
        evidence.append(f"edge.cloudfront_distributions[{i}].Origins")
        origins = dist.get("Origins") if isinstance(dist.get("Origins"), dict) else {}
        origin_names = [
            f"{o.get('DomainName')}{o.get('OriginPath') or ''}"
            for o in (origins.get("Items") or [])
            if isinstance(o, dict)
        ]
        aliases = (dist.get("Aliases") or {}).get("Items") or [] if isinstance(dist.get("Aliases"), dict) else []
        logging_config = dist.get("Logging") if isinstance(dist.get("Logging"), dict) else {}
        cf_rows.append(
            [
                dist.get("Id"),
                dist.get("DomainName"),
                ", ".join(str(a) for a in aliases) or "**別名なし**",
                ", ".join(origin_names) or "—",
                dist.get("Enabled"),
                dist.get("Status"),
                "有効" if logging_config.get("Enabled") else "無効",
                dist.get("WebACLId") or "—",
            ]
        )
    details.append("")
    details.append(f"**CloudFront ディストリビューション（{len(distributions)}本）の配信対象**")
    details.extend(
        table(
            ["ID", "CloudFrontドメイン", "別名(CNAME)", "オリジン", "有効", "状態", "アクセスログ", "WebACL"],
            cf_rows,
        )
        or ["- CloudFront ディストリビューションは存在しない。"]
    )

    summary = (
        (
            f"**`portal.example.net` のホストゾーンはこのアカウントに存在する**"
            f"（{len(cp_zones)} 件）。"
            if cp_zones
            else "**`portal.example.net` のホストゾーンはこのアカウントに存在しない。**"
        )
        + f" CloudFront {len(distributions)} 本のオリジン（配信対象）はすべて特定できた。"
        + "**ただし『なぜ 対象アカウントにあるのか』という経緯は人に聞くしかない。**"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "CP 側の運用担当（および当時の構築ベンダー）に、`portal.example.net` のゾーンを"
            "対象アカウントに置いた経緯と、現在このゾーンを誰が更新しているかを確認すること。"
            "対象アカウントの扱いを変える前に、CP の名前解決への影響評価が必須。"
        ),
    )


@question(
    "Q35",
    "Next と CP の通信経路（インターネット経由か、ピアリング／PrivateLink か）",
    CAT_OTHER,
    requires=("network",),
)
def q35_next_cp_path(inv: dict) -> Answer:
    """VPC 間接続（ピアリング / エンドポイント / TGW）の有無で通信経路を判定する。"""
    peerings = _dicts(inv, "network", "vpc_peering_connections")
    endpoints = _dicts(inv, "network", "vpc_endpoints")
    attachments = _dicts(inv, "network", "transit_gateway_vpc_attachments")
    evidence = [
        "network.vpc_peering_connections",
        "network.vpc_endpoints",
        "network.transit_gateway_vpc_attachments",
    ]

    details: list[str] = []
    if peerings:
        details.append("**VPC ピアリング接続**")
        details.extend(
            table(
                ["接続ID", "状態", "リクエスタVPC", "アクセプタVPC", "アクセプタアカウント"],
                [
                    [
                        p.get("VpcPeeringConnectionId"),
                        (p.get("Status") or {}).get("Code") if isinstance(p.get("Status"), dict) else "—",
                        (p.get("RequesterVpcInfo") or {}).get("VpcId") if isinstance(p.get("RequesterVpcInfo"), dict) else "—",
                        (p.get("AccepterVpcInfo") or {}).get("VpcId") if isinstance(p.get("AccepterVpcInfo"), dict) else "—",
                        (p.get("AccepterVpcInfo") or {}).get("OwnerId") if isinstance(p.get("AccepterVpcInfo"), dict) else "—",
                    ]
                    for p in peerings
                ],
            )
        )
    else:
        details.append("- **VPC ピアリング接続は存在しない（0本）。**")

    if endpoints:
        interface_eps = [e for e in endpoints if str(e.get("VpcEndpointType")) == "Interface"]
        details.append("")
        details.append(f"**VPC エンドポイント（{len(endpoints)}本。うち Interface 型 {len(interface_eps)}本）**")
        details.extend(
            table(
                ["エンドポイントID", "種別", "サービス名", "状態"],
                [
                    [e.get("VpcEndpointId"), e.get("VpcEndpointType"), e.get("ServiceName"), e.get("State")]
                    for e in endpoints
                ],
            )
        )
        third_party = [
            e for e in interface_eps
            if not str(e.get("ServiceName") or "").startswith("com.amazonaws.")
        ]
        if third_party:
            details.append("")
            details.append(
                "- **AWS 標準サービス以外の Interface エンドポイント（= PrivateLink）がある**: "
                + ", ".join(str(e.get("ServiceName")) for e in third_party)
            )
    else:
        details.append("")
        details.append("- **VPC エンドポイントは存在しない（0本）。**")

    if attachments:
        details.append("")
        details.append("**Transit Gateway アタッチメント**")
        details.extend(
            table(
                ["アタッチメントID", "TGW", "VPC", "状態"],
                [
                    [a.get("TransitGatewayAttachmentId"), a.get("TransitGatewayId"), a.get("VpcId"), a.get("State")]
                    for a in attachments
                ],
            )
        )
    else:
        details.append("")
        details.append("- **Transit Gateway アタッチメントは存在しない（0本）。**")

    private_paths = len(peerings) + len(attachments) + len(
        [
            e
            for e in endpoints
            if str(e.get("VpcEndpointType")) == "Interface"
            and not str(e.get("ServiceName") or "").startswith("com.amazonaws.")
        ]
    )

    if private_paths == 0:
        summary = (
            "**Next と CP の通信はインターネット経由である。** "
            "VPC ピアリング0本・Transit Gateway アタッチメント0本・"
            "サードパーティ PrivateLink 0本で、VPC 間のプライベート経路は存在しない。"
            "設計資料の推定 P12 は裏付けられた。"
        )
        details.append("")
        details.append(
            "- CP→Next の連携 API は、NAT Gateway → インターネット → ALB という経路を通る。"
            "切離し時は、CP 側の接続先 IP／FQDN と、ALB 側の SG 許可元 IP の両方の変更が必要。"
        )
    else:
        summary = (
            f"**VPC 間のプライベート経路が {private_paths} 本存在する。** "
            "Next と CP の通信がインターネット経由だけではない可能性が高い。"
        )
    return Answer("", "", "", ANSWERED, summary, details, evidence)


@question(
    "Q39",
    "Go API が使っている S3 の用途分割（チャット添付・プロフィール画像・記事メディアがどのバケットのどのプレフィックスか）",
    CAT_OTHER,
    requires=("storage",),
)
def q39_s3_usage(inv: dict) -> Answer:
    """バケット一覧と、Website 設定・パブリック許可から静的配信用途を判別する。"""
    buckets = _dicts(inv, "storage", "buckets")
    if not buckets:
        summary, details = no_data("S3 バケット", inv, ("s3",))
        return Answer("", "", "", NO_DATA, summary, details, ["storage.buckets"])

    evidence: list[str] = []
    rows: list[list[Any]] = []
    public: list[str] = []
    websites: list[str] = []
    for i, bucket in enumerate(buckets):
        evidence.append(f"storage.buckets[{i}].Website")
        name = str(bucket.get("Name"))
        website = bucket.get("Website")
        policy_status = bucket.get("PolicyStatus") if isinstance(bucket.get("PolicyStatus"), dict) else {}
        pab = bucket.get("PublicAccessBlock") if isinstance(bucket.get("PublicAccessBlock"), dict) else {}
        is_public = bool(policy_status.get("IsPublic")) or _policy_allows_public(bucket.get("Policy"))
        if is_public:
            public.append(name)
        if website:
            websites.append(name)
        if _is_log_bucket(name):
            usage = "ログ保管"
        elif website or is_public:
            usage = "**静的配信（公開）**"
        elif "chat" in name.lower():
            usage = "チャットデータ"
        else:
            usage = "アプリ用（推定）"
        rows.append(
            [
                name,
                bucket.get("Region"),
                usage,
                "あり" if website else "—",
                "**公開**" if is_public else "非公開",
                "全ブロック" if all(
                    pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
                ) else ("一部のみ" if pab else "**未設定**"),
                "有効" if bucket.get("Versioning") else "—",
                "あり" if bucket.get("Encryption") else "**なし**",
                "あり" if bucket.get("Lifecycle") else "—",
            ]
        )

    details = [f"**S3 バケット一覧（{len(buckets)}本）**"]
    details.extend(
        table(
            ["バケット", "リージョン", "推定用途", "静的ウェブサイト", "公開状態", "パブリックアクセスブロック", "バージョニング", "暗号化", "ライフサイクル"],
            rows,
        )
    )
    details.append("")
    if websites:
        details.append(
            f"- **静的ウェブサイトホスティングが有効なバケット: {', '.join(websites)}**。"
            "パブリックアクセスブロックを一律で掛けるとサイトが落ちる。"
        )
    if public:
        details.append(
            f"- **バケットポリシーで公開されているバケット: {', '.join(public)}**。"
            "意図的な公開かどうかを用途確定の前提として確認すること。"
        )
    details.append(
        "- **プレフィックス単位の用途（チャット添付 / プロフィール画像 / 記事メディア）は、"
        "オブジェクト一覧を取得しないと分からない。awsprobe は `s3:ListObjects` を発行しない"
        "（機微データに触れないため）。**"
    )

    summary = (
        f"S3 バケット {len(buckets)} 本の用途区分（ログ保管／静的配信／アプリ用）と"
        f"公開状態を判別した（静的配信 {len(websites)} 本、公開 {len(public)} 本）。"
        "**ただし『どのバケットのどのプレフィックスに何を置いているか』は"
        "アプリのコードを読むしかない。**"
    )
    return Answer(
        "",
        "",
        "",
        PARTIAL,
        summary,
        details,
        evidence,
        manual_steps=(
            "Go API の `common/awss3` と Laravel の `config/filesystems.php` を読み、"
            "バケット名とプレフィックスの定数を抽出すること。"
            "併せて各バケットで `aws s3 ls --summarize` を実行し、"
            "実際に使われているプレフィックスとコードの定義を突き合わせる。"
        ),
    )


def _policy_allows_public(policy: Any) -> bool:
    """バケットポリシーが Principal:"*" の Allow を含むか（簡易判定）。"""
    if not isinstance(policy, dict):
        return False
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements or []:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False
