# awsprobe — AWS 環境 読み取り専用 実査ツール

既存の AWS 環境の**現況**を、AWS に一切変更を加えずに調べる CLI。

設計資料や引き継ぎ資料だけでは確定できない項目を、実データで埋めることを目的にしている。
出力は **確認事項 Q1〜Q42 の自動判定**と、**セキュリティ設定の実施状況 72 項目**の 2 本立て。

想定している使いどころ:

- 運用を引き継いだ／これから引き継ぐ AWS アカウントの棚卸し
- 構成図・設計資料と実環境の突き合わせ（記載と実物の食い違いの検出）
- 外部委託先に預けていた範囲の可視化（IAM 権限・外部信頼ロール・StackSet・常駐エージェント）
- セキュリティ設定のベースライン診断（CIS AWS Foundations v3.0 / AWS FSBP）

---

## 1. 何ができるか

| 出力 | 内容 |
|---|---|
| `out/inventory.json` | インベントリ。8コレクタ・153 の読み取り API の結果（**既定でマスク済み**） |
| `out/未確認事項_突合レポート.md` | **Q1〜Q42 を自動判定**。確定 / 部分的に確定 / 要ヒアリング / データ無し を根拠付きで |
| `out/セキュリティ設定_実施状況.md` | **72 項目の実施状況**（CIS AWS Foundations v3.0 / AWS FSBP 準拠）。ドメイン別スコアと是正方針 |
| `out/AWS実査_棚卸し.xlsx` | 16 シートの棚卸し表。0.0.0.0/0 開放や未実施項目は色で強調 |
| `out/diagram/*.tsv` `diagram_data.json` | 構成図を**実データで再生成**するための入力 |
| `docs/manual-ssh-commands.md` | SSM が使えない場合の、コピペで流せる手動調査手順書（自動生成） |

### 自動化カバレッジ（同梱サンプル `tests/fixtures/inventory_example.json` での実測）

| 区分 | 件数 | 例 |
|---|---:|---|
| **確定（answered）** | 19 | Q1(WAF の有無)・Q37(実CIDR と重複)・Q38(NAT 台数とクロスAZ)・Q33(サブネット名と実AZの食い違い)・Q7(EFS の物理分離)・Q23(Global Accelerator の向き先)・Q42(Config/FlowLogs/ALBログの実有効化) |
| **部分的に確定（partial）** | 17 | Q8(22番の許可元。IP の持ち主だけ不明)・Q9(起動時の鍵は判明。追記された鍵は EC2 内部が必要)・Q27(外部配信 StackSet の権限モデル) |
| **要ヒアリング（needs_manual）** | 6 | Q19/Q20/Q22(契約と運用)・Q31/Q32/Q36(EC2 内部・ベンダー製エージェントの内部設定) |

内訳は対象環境によって変わる。`host-probe` で EC2 内部まで調べると
**Q9 / Q14 / Q31 / Q36** が partial 以上に昇格する。

---

## 2. 安全性 — なぜ「変更しない」と言い切れるか

**読み取り専用は運用ルールではなく、コードの機構で担保している。**

1. **API ガード**（`awsprobe/guard.py`）
   boto3 の `before-call` フックで、実際に発行されるオペレーション名を毎回検査する。
   許可する接頭辞は次の **6 つだけ**で、これ以外は**例外を投げて即停止**する。

   `Describe` / `List` / `Get` / `Head` / `Lookup` / `BatchGet`

   つまり「うっかり変更 API を呼ぶコードを書いてしまった」場合でも、AWS には届かない。
   `Select` / `Query` / `Scan` / `Retrieve` / `Preview`（データ本体を読む）、
   `Estimate`（1リクエスト課金）、`Simulate`、`Check` / `Test` / `Validate`
   （`apigateway:TestInvokeMethod` はバックエンドを実際に叩く、
   `license-manager:CheckoutLicense` はライセンスを消費する）は、
   読み取り系に見えるが**意図的に許可していない**。

2. **読み取り系に見えて危険なものは個別に拒否**（`DENY_OPERATIONS`）
   `secretsmanager:GetSecretValue` / `BatchGetSecretValue`・`ssm:GetParameter*`（SecureString）・
   `ec2:GetPasswordData`・`ec2:DescribeInstanceAttribute`（UserData に認証情報が入る）・
   `dynamodb:GetItem/BatchGetItem/Scan/Query`・`s3:GetObject/SelectObjectContent`・
   `logs:GetLogEvents/FilterLogEvents`・`cloudtrail:LookupEvents`・
   `iam:GetCredentialReport`・`ce:GetCostAndUsage`（課金）、および
   一時認証情報を発行する `sts:GetSessionToken` / `GetFederationToken` /
   `ecr:GetAuthorizationToken` / `redshift:GetClusterCredentials` などは
   明示的な拒否リストに入れてある。

3. **SSM RunCommand は三重のロック**
   `ssm:SendCommand` は変更系 API なので既定で拒否される。実行には
   **`--enable-ssm`（ガード解除）＋ `--yes`（内容確認）** の両方が必要で、
   実行するコマンドは**モジュール定数の固定ホワイトリスト**（16 プローブ）から動的に組み立てられない。
   テストで、プローブのコマンド文字列に `rm` `mv` `chmod` `curl` `systemctl start` 等が
   含まれていないことを毎回検査している。

4. **機微情報を取りに行かない**
   Secrets Manager の値・SSM パラメータの値・DynamoDB の項目・Cognito のユーザー・
   IAM の credential report・CloudTrail のイベント本体は**収集対象外**。
   Lambda の環境変数と CloudFormation のパラメータは**キー名のみ**に置き換える。
   `authorized_keys` は**鍵本体を出さず**、行数・コメント欄・フィンガープリントのみを採る。

5. **出力のマスキング（既定 ON。`inventory.json` も含む）**
   アカウントIDは**消さずに擬似化する**。同じアカウントは必ず同じトークンになり、
   自アカウントだけは別表記になる。

   | 元の値 | マスク後 |
   |---|---|
   | 自アカウントの 12 桁 ID | `＜自アカウント＞` |
   | それ以外の 12 桁 ID | `＜アカウント:f428＞`（ID ごとに固定） |
   | ENI ID | `＜ENI-ID＞` |
   | グローバル IPv4 / IPv6 | `203.0.x.x` / `2001:db8:x:x` |

   擬似化なので `arn:aws:iam::＜アカウント:f428＞:role/Vendor` と
   `arn:aws:iam::＜自アカウント＞:root` が区別でき、
   **「外部アカウントを信頼しているか」（IAM-07 / GOV-05 / Q27）の判定はマスク後も成立する**。
   VPC 内部の私設アドレス（10 / 172.16-31 / 192.168 / 100.64-127）と
   ユニークローカル / リンクローカル IPv6（`fd00::` / `fe80::`）は
   ネットワーク判断に必要なので残す。`vol-123456789012` のような
   リソースIDの 12 桁は誤ってマスクしない。

   **収集時（`collect`）と出力生成時（`answer` / `posture` / `excel` / `diagram-data`）の
   両方でマスクする。** `--no-redact` で収集した inventory や `--import-dir` で
   取り込んだ inventory を読んだ場合も、出力を作る直前に必ずマスクを掛ける。
   生値のまま出すには出力側にも `--no-redact-output` を明示する必要がある。
   `host` セクションも同じ扱いで、inventory に書き戻す前にマスクを通す。

6. **機微な設定値そのもののマスク**
   CloudFront の `Origins[].CustomHeaders[].HeaderValue`（ALB を CloudFront 限定に
   するための共有シークレット）と SNS の `Subscriptions[].Endpoint`（運用担当者の
   メールアドレス・電話番号）は、**コレクタが保存する時点で**値を落とす。
   キー名・`Protocol`・件数は構成の判断に必要なので残す。

7. **`--dry-run` の成果物では判定させない**
   `collect --dry-run` は `meta.dry_run: true` を書き、`collectors_run` を空にする。
   `answer` / `posture` / `excel` / `diagram-data` はこの印を見て
   **終了コード 2 で判定を拒否する**。
   AWS に一度も接続していない空の inventory から
   「CloudTrail の証跡が1本も存在しない」といった確定的な誤判定が出るのを防ぐため。
   `--dry-run` は AssumeRole も行わない（外向きのコネクション試行は 0 回）。

8. **取れなかったものを「無い」と言わない**
   スロットリング（`Throttling*` / `SlowDown` / `RequestLimitExceeded` ほか）、
   資格情報の期限切れ（`ExpiredToken*` / `RequestExpired`）、
   AWS 側の一時障害（`InternalError` / `ServiceUnavailable` ほか）は
   `HARD_ERROR_CODES` として `errors[].fatal: true` で記録する。
   該当サービスに `fatal` なエラーがあるチェックは、
   **`該当なし`（＝問題なし）ではなく `判定不能` になる**。
   `collect` の実行結果にも「収集が不完全です。この結果で判定してはいけません」と警告を出す。
   リトライは 10 回まで行い、S3 のバケット詳細取得は `--max-buckets`（既定 200）で
   上限を掛けられる（上限で打ち切った場合もその旨が `fatal` として残る）。

---

## 3. 使い方

### 3-1. 準備

```bash
pip install -r requirements.txt          # boto3, openpyxl
# または
pip install -e .                         # awsprobe コマンドが入る
```

権限は **AWS 管理ポリシー `ReadOnlyAccess`** を実行者に付ければ足りる。
より狭くしたい場合は `docs/iam-policy-readonly.json`（153 アクション / 37 サービス）を使う。
違いは `docs/iam-policy-readonly.md` を参照。

### 3-2. まず doctor

```bash
aws sso login --profile example          # SSO の場合
python -m awsprobe doctor --profile example
```

27 サービスの代表 API を1つずつ叩き、**呼べた / 権限不足 / 未導入**に仕分けて表示する。
権限不足が出た範囲はそのまま調査の穴になるので、先に解消しておく。

### 3-3. 収集して全部出す

```bash
python -m awsprobe all --profile example --account-alias example --out out
```

`collect → answer → posture → excel → diagram-data` を通しで実行する。
個別に回すこともできる。

```bash
python -m awsprobe collect --profile example --out out
python -m awsprobe answer  --out out
python -m awsprobe posture --out out
python -m awsprobe excel   --out out
python -m awsprobe diagram-data --out out
```

### 3-4. EC2 の中を調べる（任意）

既定では**何も送信せず**、手動実行の手順書だけを生成する。

```bash
python -m awsprobe host-probe --out out
#  → docs/manual-ssh-commands.md（SSH でコピペして流せる読み取り専用スクリプト）
```

SSM 経由で自動採取する場合:

```bash
python -m awsprobe host-probe --enable-ssm --out out        # 送信するスクリプト全文を表示して停止
python -m awsprobe host-probe --enable-ssm --yes --out out  # 内容に納得したうえで実行
```

手動採取したテキストは取り込める。

```bash
python -m awsprobe host-probe --import-dir ./採取結果 --out out
python -m awsprobe answer --out out       # Q9 / Q14 / Q31 / Q36 の判定が更新される
```

### 3-5. 他のアカウントを調べる

コレクタはセッションを受け取るだけの作りなので、**ロール ARN を差し替えるだけ**で使える。

```bash
python -m awsprobe all \
  --assume-role-arn arn:aws:iam::＜アカウントID＞:role/ReadOnlyForSurvey \
  --external-id ＜ExternalId＞ \
  --account-alias prod-account \
  --out out/prod-account
```

### 3-6. 実 AWS なしで動作を確かめる

```bash
python -m awsprobe answer  --inventory tests/fixtures/inventory_example.json --out /tmp/demo
python -m awsprobe posture --inventory tests/fixtures/inventory_example.json --out /tmp/demo
python -m awsprobe collect --dry-run          # 呼ぶ API を確認するだけで送信しない
```

`--dry-run` は AWS へ1バイトも送信しない（AssumeRole も行わない）。
そのぶん**出来上がる `inventory.json` は空の器**であり、判定には使えない。
`answer` / `posture` / `excel` / `diagram-data` に渡すと終了コード 2 で拒否される。

---

## 4. セキュリティ設定の評価項目（72 件）

| ドメイン | 件数 | 主な内容 |
|---|---:|---|
| 暗号化 | 8 | RDS / EBS（既定暗号化含む）/ EFS / S3 / CloudTrail / SNS・SQS / スナップショット |
| 公開範囲 | 7 | S3 のアカウント・バケット両レベルの PAB、ポリシー公開、RDS・EC2 の公開、スナップショット・AMI の共有 |
| ネットワーク | 11 | 0.0.0.0/0 開放（**管理・DBポートは critical、80/443 は別枠**）、既定SG、NACL、フローログ、**IMDSv2 必須化**、TLS ポリシー世代、HTTP→HTTPS、削除保護、WAF 関連付け |
| IAM・認証 | 9 | ルート MFA / ルートアクセスキー / パスワードポリシー / ユーザー MFA / アクセスキー経過日数 / ワイルドカード権限 / **外部アカウント信頼ロール** / インスタンスプロファイル / 未使用プリンシパル |
| ログ・証跡 | 9 | CloudTrail（全リージョン・ログ検証）/ Config / フローログ / **ALB アクセスログ（全本）** / CW Logs 保持期間 / S3 アクセスログ / ログバケットのライフサイクル |
| 脅威検知 | 5 | GuardDuty（保護機能別）/ Security Hub / Inspector / Access Analyzer / 検知アラーム |
| バックアップ・可用性 | 8 | RDS 保持期間・Multi-AZ・削除保護 / EFS バックアップ / AWS Backup / EBS スナップショット / 冗長構成 / **NAT の冗長性** |
| 鍵・シークレット | 5 | KMS 自動ローテーション / Secrets Manager ローテーション / SecureString / キーペア棚卸し / ACM 有効期限 |
| パッチ・構成管理 | 5 | **SSM 管理下比率** / パッチコンプライアンス / AMI 鮮度 / RDS エンジン EOL / **Lambda ランタイム EOL** |
| 統制 | 5 | Organizations と SCP / IAM Identity Center / タグ一貫性 / リージョン絞り込み / StackSet 権限モデル |

深刻度の内訳: critical 10 / high 24 / medium 30 / low 8。

判定は **実施済 / 一部実施 / 未実施 / 該当なし / 判定不能** の5段階。
「一部実施」は満たしたリソースと満たさないリソースの両方を列挙するので、どこを直せばよいかが分かる。
ログ保管用バケット・静的サイト用の公開バケット・検証環境の Single-AZ など、
**意図的な設定として除外すべきものは `failed` に入れず、レポートの注記に回している。**

---

## 5. 構成

```
awsprobe/
├── guard.py            読み取り専用ガードとマスキング  ← 安全性の要
├── session.py          プロファイル / AssumeRole / Context
├── cli.py              サブコマンド
├── collectors/         8コレクタ（network, compute, database, storage,
│                       edge, serverless, logging, security）
├── questions.py        未確認事項 Q1〜Q42 の判定
├── report.py           判定レポート（Markdown）
├── posture.py          セキュリティ設定 72 項目の評価
├── posture_report.py   評価レポート（Markdown）
├── excel.py            棚卸し Excel
├── diagram.py          構成図用データ
├── host.py             SSM 経由の EC2 内部調査 ＋ 手順書生成
└── gen_iam_policy.py   最小権限ポリシーの生成

docs/
├── INVENTORY_SCHEMA.md       inventory.json のキー契約
├── iam-policy-readonly.json  最小権限ポリシー（自動生成）
├── iam-policy-readonly.md    ReadOnlyAccess との違い
└── manual-ssh-commands.md    手動調査手順書（host-probe が生成）

tests/                  329 テスト / 1,532 サブテスト
└── fixtures/inventory_example.json   実 AWS 無しで全機能を動かせるダミーデータ
```

---

## 6. 動作確認の状況

```
$ python3 -m pytest tests/ -q
329 passed, 1532 subtests passed in 27.40s
```

検証済みの内容:

- **全 API 呼び出しをガードに通して変更系がゼロであることを、コレクタごとに検査**している
- プローブのコマンド文字列に破壊的コマンドが含まれていないことを正規表現で検査（偽陰性テストも込み）
- `--enable-ssm` 無し・`--yes` 無し・`--dry-run` のいずれでも `ssm:SendCommand` が発行されないことを、ガードの呼び出し実績で確認
- CIDR 重複検出と NAT クロスAZ判定を**両方向**（検出する / しない）で検証
- セキュリティ評価の代表 5 項目を、違反フィクスチャと準拠フィクスチャの**両方**で反転することを検証
- 成果物に完全なアクセスキーID・秘密鍵・SSH 公開鍵本体が混ざらないことを全ファイル走査で確認
- 認証情報が無い / プロファイルが空文字 / inventory が無い、いずれでもスタックトレースを出さず助言を返すことを確認
- **マスク前の inventory とマスク後の inventory で、72 件すべての判定結果が一致する**ことを検証
  （アカウントIDを擬似化しているので、外部アカウント信頼の判定 IAM-07 / GOV-05 / Q27 がマスクで消えない）
- `meta.dry_run: true` の inventory を `answer` / `posture` / `excel` / `diagram-data` が
  終了コード 2 で拒否すること、`--dry-run` の外向きコネクション試行が 0 回であることを実測
- `errors` に `ThrottlingException` があると、該当サービスのチェックが
  `該当なし` ではなく `判定不能` になることを検証
- 生値（`meta.redacted: false`）の inventory から作った Markdown / Excel / TSV に、
  アカウントIDの生値とグローバルIPが1つも含まれないことを全ファイル走査で確認
- SSM の 24,000 字打ち切りで `authorized_keys` が消えないこと（3バッチ分割＋番兵での検出）
- ホスト側スクリプトのウォッチドッグが dash / bash × プロセスグループリーダーの有無の4通りで効くこと

### 実環境でしか確認できていない部分

moto（モック AWS）が未実装のため、以下は**実アカウントでの `doctor` 実行が初回の検証**になる。

- `ssm:DescribeInstanceInformation`（SSM 到達性。**host-probe の可否を決める最重要項目**）
- `globalaccelerator:ListAccelerators`（Q23 の向き先特定）
- `wafv2:ListResourcesForWebACL`（Q1 の関連付け）
- `securityhub:GetEnabledStandards` / `inspector2:BatchGetAccountStatus`
- Organizations / StackSet 系（Q27 外部配信 StackSet の権限モデル）

---

## 7. 注意

- **出力には対象環境の機微な情報が含まれる。`out/` は `.gitignore` に入れること（同梱の `.gitignore` に設定済み）。**
  マスキングの実態は次のとおり（§2-5 を参照）。

  | 対象 | 既定 | 解除方法 |
  |---|---|---|
  | `inventory.json` | **マスクされる** | `collect --no-redact` |
  | Markdown / Excel / TSV | **マスクされる**（生値の inventory から作った場合も） | `--no-redact-output` |
  | `host` セクション | **マスクされる**（SSM 経路・`--import-dir` 経路の両方） | `collect --no-redact` で収集した inventory に追記する場合のみ生値 |

  ただしマスクされるのはアカウントID・ENI ID・グローバル IP と、
  §2-6 に挙げた機微な設定値だけである。**リソース名・タグ・ホスト名・
  内部パス・ユーザー名・IAM ロール名・私設 IP アドレスは残る。**
  これらは調査の目的そのものなので落とせない。取り扱いは社外秘に準じること。
- 社外に共有する場合は、`--no-redact` / `--no-redact-output` を**付けずに**生成した
  Markdown / Excel を使うこと。
- **`--dry-run` の出力は「送信していない確認用」であって調査結果ではない。**
  そのまま判定に回すことはできない（終了コード 2 で拒否される）。
- **`collect` が「収集が不完全です」と警告した実行結果で判定してはいけない。**
  スロットリング等で取れなかった範囲は `判定不能` になるが、
  取れた範囲の件数自体も信用できない。時間帯を変えて取り直すこと。
- `host-probe` の `disk_usage` プローブは `du -x /` を実行する（60秒でタイムアウト）。本番2台で同時に流す場合は業務時間外を推奨。
- 生成された `docs/manual-ssh-commands.md` は**編集せずにそのまま流す**こと。編集した場合、awsprobe の安全検査は効かない。
