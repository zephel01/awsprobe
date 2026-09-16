# awsprobe 用 最小権限 IAM ポリシー

`docs/iam-policy-readonly.json` は `awsprobe/gen_iam_policy.py` が
`awsprobe/collectors/*.py` の各コレクタの `Collector.iam_actions` を
`REGISTRY` 経由で機械的に集約して生成したものである。**アクション一覧は
どこにもハードコードされておらず**、コレクタに `iam_actions` を追加・削除
した後に

```
python -m awsprobe.gen_iam_policy
```

を再実行すれば、その時点のコレクタ実装に合わせて自動的に更新される。

## ポリシーの構成

`docs/iam-policy-readonly.json` は2つの Statement からなる。

1. **`AwsprobeReadOnlyCollect`（`Effect: Allow`）**
   `awsprobe collect` が発行する読み取り系 API（`Describe*` / `List*` /
   `Get*` 等）のみを、37 サービス・153 アクションに絞ってサービスごとに
   グループ化して列挙している。`Resource` はすべて `"*"`
   （読み取り専用 API の大半はリソース単位の絞り込みに対応していないため）。

2. **`SsmRunCommandForHostProbeDisabledByDefault`（**既定で `Effect: Deny`**）**
   `awsprobe host-probe --enable-ssm` が使う `ssm:SendCommand` /
   `ssm:GetCommandInvocation` / `ssm:ListCommandInvocations` /
   `ssm:ListCommands` の4アクションだけを含む。これらは EC2 インスタンスの
   中でコマンドを実行する操作であり、他の読み取り専用アクションとは
   性質がまったく異なる（`awsprobe/guard.py` の `ReadOnlyGuard` でも
   `allow_ssm_command=True` を明示しない限り拒否される）。
   **`--enable-ssm` を実際に使う運用のときだけ**、このステートメントの
   `Effect` を手動で `"Allow"` に書き換えて有効化すること。使い終えたら
   `"Deny"` に戻す（または該当ステートメントを削除する）運用を推奨する。

## AWS 管理ポリシー `ReadOnlyAccess` との違い

AWS 管理ポリシー `arn:aws:iam::aws:policy/ReadOnlyAccess` で代替することも
できるが、`ReadOnlyAccess` は **awsprobe が使わないサービスも含めた
AWS のほぼ全サービスの読み取り系 API**（数百サービス分）を許可する、
実務上「読み取りなら何でも見える」に近い非常に広いポリシーである。
一方 `docs/iam-policy-readonly.json` は **awsprobe の8コレクタ
（network / compute / database / storage / edge / serverless / logging /
security）が実際に呼び出す 37 サービス・153 アクションだけ**に絞った、
`ReadOnlyAccess` の厳密な部分集合に近いポリシーであり、監査対象の調査に
不要な権限（例えば awsprobe が触らない Redshift・SageMaker・EMR 等）を
一切含まない分だけ攻撃対象・誤用リスクが小さい。**最小権限の原則を優先
するなら本ポリシーを、運用の簡便さ（コレクタ追加のたびにポリシーを
再生成する手間を省く）を優先するなら `ReadOnlyAccess` を選ぶ**、という
トレードオフになる。なお `ReadOnlyAccess` を使う場合でも、SSM
RunCommand 系は `ReadOnlyAccess` に含まれないため、host-probe を使うには
別途 `AmazonSSMFullAccess` 相当（本来はより絞ったカスタムポリシー）を
追加する必要がある点は本ポリシーと変わらない。

## 再生成方法

```bash
python -m awsprobe.gen_iam_policy -o docs/iam-policy-readonly.json
```

コレクタの `iam_actions` を変更したら、このコマンドで
`docs/iam-policy-readonly.json` を必ず再生成すること。
