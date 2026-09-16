# EC2 内部調査 手動実行手順（SSM が使えない場合）

*生成日時: 2026-09-16 13:08 ／ `awsprobe host-probe` が自動生成。**この手順は読み取りのみで、サーバーに一切変更を加えない。***

## 1. SSM が使えなかった理由

**判定: ssm_command_disabled**

`ssm:SendCommand` は awsprobe の読み取り専用ガードで既定拒否されている。実行するには `--enable-ssm --yes` を明示的に付ける必要がある。　なお環境側にも別の課題がある: IAM ロールと通信経路はあるのに SSM に登録されていない（または PingStatus が Online でない）。SSM Agent が未導入・停止・旧版である可能性が高い。

| 原因の候補 | 該当 | 解消方法 |
|---|---|---|
| --enable-ssm 未指定 | — | `awsprobe host-probe --enable-ssm --yes` を付けて再実行する |
| 権限不足 | — | 調査用 IAM に `ssm:SendCommand` / `ssm:GetCommandInvocation` を付与する |
| IAM ロール未付与 | — | EC2 に `AmazonSSMManagedInstanceCore` を含むインスタンスプロファイルを付ける |
| VPC エンドポイント未設定 | — | ssm / ssmmessages / ec2messages の VPC エンドポイントを作る（または NAT 経路を通す） |
| SSM エージェント未導入または停止 | — | SSM Agent の導入・起動状況を確認する（本手順書で `systemd_units` を採取すれば分かる） |

**インスタンス別の判定**

| インスタンスID | IAM ロール | SSM 登録状態 | サブネットの既定経路 | 判定 |
|---|---|---|---|---|
| i-0chk01 | あり | Online | あり | 到達可能 |
| i-0chk02 | あり | Online | あり | 到達可能 |
| i-0demo01 | あり | Online | あり | 到達可能 |
| i-0prod01 | あり | Online | あり | 到達可能 |
| i-0prod02 | あり | Online | あり | 到達可能 |
| i-0stg01 | あり | Online | あり | 到達可能 |
| i-0stg02 | あり | （SSM に未登録） | あり | SSM エージェント未導入または停止 |
| i-0stg03 | あり | （SSM に未登録） | あり | SSM エージェント未導入または停止 |

## 2. 対象インスタンス

| インスタンスID | Name タグ | プライベートIP | サブネット | 状態 | SSM 到達性 |
|---|---|---|---|---|---|
| i-0prod01 | ex-prod-ec2-01 | — | subnet-0a21 | running | **到達不可** |
| i-0prod02 | ex-prod-ec2-02 | — | subnet-0a22 | running | **到達不可** |
| i-0chk01 | ex-check-ec2-01 | — | subnet-0a21 | running | **到達不可** |
| i-0chk02 | ex-check-ec2-02 | — | subnet-0a22 | running | **到達不可** |
| i-0demo01 | ex-demo-ec2 | — | subnet-0b21 | running | **到達不可** |
| i-0stg01 | ex-stg-ec2 | — | subnet-0c21 | running | **到達不可** |
| i-0stg02 | ex-stg2-ec2 | — | subnet-0c21 | running | **到達不可** |
| i-0stg03 | ex-stg3-ec2 | — | subnet-0c21 | running | **到達不可** |

## 3. 実行するスクリプト（このままコピペ可）

踏み台（bastion）等から対象サーバーへ SSH できる端末で、以下をそのまま実行する。ヒアドキュメントでローカルにスクリプトを作り、SSH の標準入力へ流す形にしてある（**リモート側にはファイルを一切作らない**）。

```bash
# 1) ローカルに調査スクリプトを作る（リモートには置かない）
cat > awsprobe-host-probe.sh <<'AWSPROBE_EOF'
# awsprobe host-probe: 読み取り専用の内部調査スクリプト（自動生成・編集不可）
# 書き込み・インストール・サービス操作は一切行わない。
set +e
export LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# --- 自己終了のウォッチドッグ（最長 240 秒） ---
# $$ はこのスクリプト自身の PID。サブシェル内で $$ を書くと
# 「親シェルの PID」という紛らわしい仕様に頼ることになるため、
# 先に変数へ退避してから参照する。
AWSPROBE_MAIN_PID=$$
AWSPROBE_MAIN_PGID=$(ps -o pgid= -p "$AWSPROBE_MAIN_PID" 2>/dev/null | tr -d ' ')
(
  sleep 240
  # bash は前面ジョブの実行中に受けた SIGTERM を、その子プロセスが
  # 終わるまで処理しない。シェルだけに送っても長い du 等は止まらないので、
  # **自分がプロセスグループのリーダーのときだけ** グループごと止める。
  # リーダーでなければ他人のグループを巻き込む恐れがあるため、
  # シェル本体と自分の直下の子プロセスだけに送る。
  if [ -n "$AWSPROBE_MAIN_PGID" ] && [ "$AWSPROBE_MAIN_PGID" = "$AWSPROBE_MAIN_PID" ]; then
    kill -TERM "-$AWSPROBE_MAIN_PGID"
  else
    kill -TERM "$AWSPROBE_MAIN_PID"
    for awsprobe_child in $(ps -o pid= --ppid "$AWSPROBE_MAIN_PID" 2>/dev/null); do
      kill -TERM "$awsprobe_child"
    done
  fi
) >/dev/null 2>&1 &
AWSPROBE_WATCHDOG=$!

printf '%s\n' '===== PROBE:os_release ====='
{ cat /etc/os-release 2>/dev/null; uname -a 2>/dev/null ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:os_eol_hint ====='
{ cat /etc/system-release 2>/dev/null; hostnamectl 2>/dev/null | head -20; cat /etc/debian_version 2>/dev/null ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:packages ====='
{ if command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -Ei '^(nginx|php|httpd|mysql|mariadb|golang|go|nodejs|node|postfix)' | sort; elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | grep -Ei '^(nginx|php|apache2|httpd|mysql|mariadb|golang|go|nodejs|node|postfix)' | sort; else echo '(rpm / dpkg のどちらも見つかりません)'; fi ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:runtime_versions ====='
{ for c in nginx php httpd mysql node npm python3; do if command -v "$c" >/dev/null 2>&1; then printf '%s: ' "$c"; { "$c" --version 2>&1 || "$c" -v 2>&1; } | head -2; else printf '%s: (未導入)\n' "$c"; fi; done; if command -v go >/dev/null 2>&1; then go version 2>&1; else echo 'go: (未導入)'; fi ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:listening_ports ====='
{ ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo '(ss / netstat のどちらも見つかりません)' ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:processes ====='
{ ps auxww 2>/dev/null | grep -Ei 'vendor|agent|nginx|php-fpm|node|cron' | grep -vw grep | head -60 ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:vendor_agent_files ====='
{ find /opt /usr/local /etc /lib/systemd/system /etc/systemd/system -maxdepth 4 -iname '*vendor-agent*' 2>/dev/null | head -100; echo '--- systemd unit files'; systemctl list-unit-files --no-pager --no-legend 2>/dev/null | grep -Ei 'vendor|agent' | head -20 ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:systemd_units ====='
{ systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -80 || echo '(systemd ではない、または権限がありません)' ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:cron_jobs ====='
{ echo '--- /etc/crontab'; cat /etc/crontab 2>/dev/null; echo '--- /etc/cron.d'; ls -la /etc/cron.d/ 2>/dev/null; for f in /etc/cron.d/*; do if [ -f "$f" ]; then echo "--- $f"; cat "$f" 2>/dev/null; fi; done; echo '--- cron.hourly / daily / weekly'; ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly 2>/dev/null; echo '--- user crontabs'; printf '（/etc/passwd のローカルユーザー %s 名中、先頭50名のみ走査）\n' "$(awk -F: 'END {print NR}' /etc/passwd 2>/dev/null)"; for u in $(awk -F: '{print $1}' /etc/passwd 2>/dev/null | head -50); do out=$(crontab -l -u "$u" </dev/null 2>/dev/null); if [ -n "$out" ]; then echo "--- user cron: $u"; echo "$out"; fi; done; echo '--- systemd timers'; systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -20 ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:authorized_keys ====='
{ for h in $(getent passwd 2>/dev/null | awk -F: '{print $6}' | sort -u | head -50) /root; do f="$h/.ssh/authorized_keys"; if [ -f "$f" ]; then echo "--- $f"; stat -c '    perm=%a owner=%U group=%G mtime=%y' "$f" 2>/dev/null; printf '    lines=%s\n' "$(grep -c '[^[:space:]]' "$f" 2>/dev/null)"; echo '    comments:'; awk '{ t=0; for (i=1;i<=NF;i++) if ($i ~ /^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-[A-Za-z0-9-]+|sk-[A-Za-z0-9.@-]+)$/) { t=i; break } if (t==0) { print "      - (鍵行として解析できない行)"; next } c=""; for (i=t+2;i<=NF;i++) c=c" "$i; if (c=="") c=" (コメント欄なし)"; print "      - [" $t "]" c }' "$f" 2>/dev/null; echo '    fingerprints:'; ssh-keygen -lf "$f" 2>/dev/null | awk '{ print "      - " $1 " " $2 " " $NF }'; fi; done ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:sshd_config ====='
{ { sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null; } | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|allowgroups|port|kbdinteractiveauthentication|challengeresponseauthentication|permitemptypasswords)' || grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups|Port|PermitEmptyPasswords)' /etc/ssh/sshd_config 2>/dev/null ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:users ====='
{ getent passwd | awk -F: '$7 ~ /sh$/ { printf "%s uid=%s gid=%s home=%s shell=%s\n", $1,$3,$4,$6,$7 }'; echo '--- 特権グループ'; getent group wheel sudo adm 2>/dev/null; echo '--- sudoers.d のファイル名のみ'; ls -la /etc/sudoers.d/ 2>/dev/null ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:mounts ====='
{ df -hT 2>/dev/null; echo '--- nfs / efs マウント'; mount 2>/dev/null | grep -Ei 'nfs|efs'; echo '--- fstab の nfs/efs 行'; grep -Ei 'efs|nfs' /etc/fstab 2>/dev/null ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:disk_usage ====='
{ df -h 2>/dev/null; echo '--- 使用量の大きいディレクトリ（上位20）'; if command -v timeout >/dev/null 2>&1; then timeout 30 du -xh --max-depth=1 /var /opt /srv /home /usr/local /tmp 2>/dev/null | sort -rh | head -20; else echo '(timeout コマンドが無いため、ディスク使用量の詳細は採取しませんでした／df の結果のみ)'; fi ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:app_layout ====='
{ for d in /var/www /var/www/html /usr/share/nginx/html /opt/app /opt/code /srv /var/app; do if [ -d "$d" ]; then echo "--- $d"; ls -la "$d" 2>/dev/null | head -40; fi; done; echo '--- 目印ファイル（存在と mtime のみ / 中身は読まない）'; find /var/www /opt /srv /home -maxdepth 4 \( -name node_modules -o -name vendor -o -name .git -o -name .cache \) -prune -o \( -name composer.json -o -name package.json -o -name artisan -o -name go.mod -o -name .env \) -printf '%TY-%Tm-%Td %TH:%TM %10s %p\n' 2>/dev/null | head -40 ; } 2>&1 | head -c 1500; printf '\n'
printf '%s\n' '===== PROBE:time_sync ====='
{ timedatectl 2>/dev/null; echo '--- chrony'; chronyc sources 2>/dev/null | head -10; echo '--- ntpstat'; ntpstat 2>/dev/null ; } 2>&1 | head -c 1500; printf '\n'

# --- ウォッチドッグを止めてから番兵を出す ---
kill "$AWSPROBE_WATCHDOG" >/dev/null 2>&1
printf '%s\n' '===== PROBE:__end__ ====='
AWSPROBE_EOF

# 2) 対象サーバーごとに実行して結果を保存する
#    <instance-id> は「2. 対象インスタンス」の表の値に置き換える
# ex-prod-ec2-01
ssh ec2-user@＜i-0prod01 のプライベートIP＞ 'sudo bash -s' < awsprobe-host-probe.sh | tee host_manual_i-0prod01.txt
# ex-prod-ec2-02
ssh ec2-user@＜i-0prod02 のプライベートIP＞ 'sudo bash -s' < awsprobe-host-probe.sh | tee host_manual_i-0prod02.txt
# ex-check-ec2-01
ssh ec2-user@＜i-0chk01 のプライベートIP＞ 'sudo bash -s' < awsprobe-host-probe.sh | tee host_manual_i-0chk01.txt
# ex-check-ec2-02
ssh ec2-user@＜i-0chk02 のプライベートIP＞ 'sudo bash -s' < awsprobe-host-probe.sh | tee host_manual_i-0chk02.txt
# ex-demo-ec2
ssh ec2-user@＜i-0demo01 のプライベートIP＞ 'sudo bash -s' < awsprobe-host-probe.sh | tee host_manual_i-0demo01.txt
# ex-stg-ec2
ssh ec2-user@＜i-0stg01 のプライベートIP＞ 'sudo bash -s' < awsprobe-host-probe.sh | tee host_manual_i-0stg01.txt
# ex-stg2-ec2
ssh ec2-user@＜i-0stg02 のプライベートIP＞ 'sudo bash -s' < awsprobe-host-probe.sh | tee host_manual_i-0stg02.txt
# ex-stg3-ec2
ssh ec2-user@＜i-0stg03 のプライベートIP＞ 'sudo bash -s' < awsprobe-host-probe.sh | tee host_manual_i-0stg03.txt
```

> `sudo` は `crontab -l -u <user>` と `sshd -T` と他ユーザーの `authorized_keys` の参照に必要。sudo が使えない場合はそのまま `bash -s` で実行してよい（採取できる範囲が狭まるだけで、手順は変わらない）。

## 4. 各コマンドが解消する設問

| プローブ名 | 解消する設問 | 内容 | 何のために取るか |
|---|---|---|---|
| os_release | Q14 | OS 種別とバージョン | OS ディストリビューションとカーネル版数を確定し、EOL 判定の土台にするため。 |
| os_eol_hint | Q14 | OS サポート期限の手掛かり | Amazon Linux 2 / 2023 など、os-release だけでは分からない世代を特定するため。 |
| packages | Q14 | ミドルウェアのパッケージ版数 | nginx / php / httpd / mysql / go / node / postfix の実バージョンを押さえ、EOL を判定するため。 |
| runtime_versions | Q14 | ランタイムの実行バージョン | パッケージ管理に載っていないランタイムも含め、実際に動いている版数を確認するため。 |
| listening_ports | Q14, Q36 | 待ち受けポートとプロセス | どのプロセスがどのポートを持っているかを把握し、構成図と実機の差分を見るため。 |
| processes | Q36 | 常駐プロセス（監視エージェント・Web・cron） | ベンダー製監視エージェントが実際に常駐しているかを確認するため（Q36 の中核）。 |
| vendor_agent_files | Q36 | vendor-agent 関連ファイルの所在（パスのみ） | vendor-agent の導入先ディレクトリと systemd ユニットの所在を特定するため（設定内容は開示要求の対象）。 |
| systemd_units | Q14, Q36 | 稼働中の systemd サービス | 常駐サービスの一覧から、AWS 標準以外の第三者エージェントの有無を見るため。 |
| cron_jobs | Q31 | cron の定義（システム・ユーザー） | 本番2台でバッチが二重実行されないための仕掛け（片系のみ定義／排他制御）を確認するため。 |
| authorized_keys | Q9 | authorized_keys の実測（鍵本体は出さない） | 切離し時にベンダーの鍵が残らないよう、鍵の本数・ラベル・指紋を控えて保有者と突合するため。 |
| sshd_config | Q9 | sshd の実効設定 | パスワード認証や root 直ログインが開いていないかを確認し、鍵の棚卸しと併せて評価するため。 |
| users | Q9 | ログイン可能なユーザーと特権グループ | 鍵の持ち主候補となるローカルユーザーと特権付与の実態を把握するため。 |
| mounts | Q7 | ファイルシステムと EFS/NFS マウント | EFS が実際にどのパスへどのオプションでマウントされているかを確定するため。 |
| disk_usage | Q7, Q14 | ディスク使用量と大きいディレクトリ | 容量逼迫の有無と、移行時にコピーが必要なデータの所在・規模を見積もるため。 |
| app_layout | Q32 | アプリのデプロイ先の構造（中身は読まない） | `code` が Laravel かどうか（artisan / composer.json の有無）と、.env の所在を中身を見ずに判定するため。 |
| time_sync | Q31 | 時刻同期の状態 | cron の実行時刻とログの時刻が信頼できるか（NTP 同期の有無）を確認するため。 |

## 5. 結果を awsprobe に取り込む

出力は `===== PROBE:<name> =====` 区切りになっている。**ファイル名を `host_manual_<instance-id>.txt` にしておくこと**（インスタンス ID をファイル名から復元するため）。

最終行に番兵 `===== PROBE:__end__ =====` が出ていれば、出力は途中で切れていない。**この行が無いファイルは途中で切れている**ので、取り込む前に採取をやり直すこと。

```bash
# 採取したファイルを1つのディレクトリに集める
ls manual-results/
#   host_manual_i-0123456789abcdef0.txt
#   host_manual_i-0fedcba9876543210.txt

# inventory.json の host セクションへマージする
awsprobe host-probe --import-dir manual-results/
```

マージ後に `awsprobe report` を再実行すると、Q9 / Q14 / Q31 / Q36 などの判定に実測値が反映される。

## 6. 実行時の注意

- **本番サーバーで実行すること。** ステージングでは authorized_keys も cron も本番と異なるため、切離しの判断材料にならない。
- **読み取りのみで副作用は無い。** ファイルの作成・変更・削除、パッケージ導入、サービスの起動・停止・再起動は一切行わない。`systemctl` は一覧表示のみ、`sshd -T` は設定表示のみ（デーモンは起動しない）、`crontab` は必ず `-l` を付け標準入力を `/dev/null` に固定してある（誤って crontab を上書きしないため）。
- **`authorized_keys` は鍵本体を出さない形にしてある。** 出力されるのは行数・コメント欄（末尾のラベル）・指紋（`ssh-keygen -lf`）・mtime・パーミッションのみ。取り込み時にも正規表現で鍵本体らしき文字列をマスクする二重防御が入っている。
- **読まないもの**: 秘密鍵、`.env` の中身、`/var/log` の中身、アプリのソースコード、データベースの中身。`.env` と `composer.json` は**存在と更新日時だけ**を確認する。
- **スクリプト自身に実行時間の上限（240 秒）が入っている。**冒頭でウォッチドッグを起動し、上限を過ぎたら自分自身へ SIGTERM を送って停止する（自分がプロセスグループのリーダーのときはグループごと停止する）。手元で Ctrl-C しても、サーバー側でコマンドが走り続けることはない。
- `disk_usage` の `du` は **`timeout` コマンドがある環境でのみ**、`/var /opt /srv /home /usr/local /tmp` に限定して最長 30 秒で実行する。`timeout` が無い環境では `du` を**実行せず**、その旨だけを出力する（上限の無い `du -x /` が本番サーバーで走り続けるのを防ぐため）。
- `cron_jobs` と `authorized_keys` のユーザー走査は **50 件で打ち切る**。LDAP / AD / SSSD 参加ホストでは `getent passwd` が数千件返り、そのぶんプロセスを起動してしまうため（`cron_jobs` はローカル定義の `/etc/passwd` のみを対象にする）。
- 各プローブの出力は **1500 バイトで打ち切る**（`head -c`）。SSM 経由では stdout 全体が 24000 文字で切られるため、その対策がそのまま入っている。手動実行では全バッチを 1 本のスクリプトで流してよい（ファイルに保存するので上限は無い）。
- 採取結果には社内のユーザー名・ホスト名・鍵のラベルが含まれる。**取扱いは社外秘**とし、共有先を限定すること。

