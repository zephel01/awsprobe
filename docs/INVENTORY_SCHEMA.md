# inventory.json スキーマ契約

`awsprobe collect` が出力する `out/inventory.json` の形。
**コレクタ実装者と判定ロジック実装者は、このキー名に必ず従うこと。**
値は原則として AWS API のレスポンス要素をそのまま入れる（datetime は ISO 文字列）。

```jsonc
{
  "meta": {
    "awsprobe_version": "1.0.0",
    "collected_at": "2026-09-16T12:34:56+09:00",
    "account_id": "＜アカウントID＞",      // redact 有効時はマスク済み
    "account_alias": "example",
    "region": "ap-northeast-1",
    "caller_arn": "...",
    "redacted": true,
    "collectors_run": ["network", "compute", ...],
    "guard": { "total_calls": 0, "distinct_operations": 0, "operations": {} }
  },
  "errors": [
    { "service": "wafv2", "operation": "list_web_acls", "code": "AccessDeniedException",
      "message": "...", "context": "scope=REGIONAL" }
  ],

  "network": {
    "vpcs": [],                      // ec2:DescribeVpcs
    "subnets": [],                   // ec2:DescribeSubnets（AvailabilityZone / CidrBlock / MapPublicIpOnLaunch を含む素のまま）
    "route_tables": [],              // ec2:DescribeRouteTables（Routes / Associations 込み）
    "network_acls": [],              // ec2:DescribeNetworkAcls（Entries / Associations 込み）
    "internet_gateways": [],         // ec2:DescribeInternetGateways
    "nat_gateways": [],              // ec2:DescribeNatGateways（State != deleted のみ）
    "egress_only_internet_gateways": [],
    "network_interfaces": [],        // ec2:DescribeNetworkInterfaces（Attachment / Groups / Description 込み）
    "security_groups": [],           // ec2:DescribeSecurityGroups（IpPermissions / IpPermissionsEgress 込み）
    "vpc_peering_connections": [],
    "vpc_endpoints": [],
    "transit_gateway_vpc_attachments": [],
    "elastic_ips": [],               // ec2:DescribeAddresses
    "prefix_lists": [],              // ec2:DescribeManagedPrefixLists（SG 参照解決用・任意）
    "availability_zones": []         // ec2:DescribeAvailabilityZones（ZoneName と ZoneId の対応）
  },

  "compute": {
    "instances": [],                 // ec2:DescribeInstances を平坦化した Instance の配列。
                                     //   各要素に "_reservation_id" を足す。
                                     //   Platform / PlatformDetails / ImageId / InstanceType /
                                     //   Placement.AvailabilityZone / SubnetId / SecurityGroups /
                                     //   IamInstanceProfile / KeyName / BlockDeviceMappings /
                                     //   MetadataOptions / Monitoring を含む素のまま
    "instance_statuses": [],         // ec2:DescribeInstanceStatus（IncludeAllInstances=True。Events を見る）
    "images": [],                    // 上記 instances の ImageId と自アカウント所有 AMI
    "volumes": [],                   // ec2:DescribeVolumes
    "snapshots": [],                 // ec2:DescribeSnapshots（OwnerIds=['self']）
    "auto_scaling_groups": [],       // autoscaling:DescribeAutoScalingGroups
    "launch_templates": [],
    "key_pairs": [],                 // ec2:DescribeKeyPairs
    "ssm_managed_instances": [],     // ssm:DescribeInstanceInformation（SSM 到達性の判定に使う）
    "ssm_inventory": [],             // ssm:ListInventoryEntries が引ければ AWS:Application 等（任意）
    "ssm_patch_states": [],          // ssm:DescribeInstancePatchStates（任意）
    "dlm_lifecycle_policies": [],    // dlm:GetLifecyclePolicies + GetLifecyclePolicy
                                     //   AMI/スナップショットの定期取得が「仕組みとして」
                                     //   有るかの確認。PolicyDetails.Schedules に
                                     //   CreateRule(スケジュール)と RetainRule(保持世代)
    "ebs_encryption_by_default": {}, // ec2:GetEbsEncryptionByDefault → {"EbsEncryptionByDefault": bool}
    "ebs_default_kms_key_id": {},    // ec2:GetEbsDefaultKmsKeyId → {"KmsKeyId": "..."}
    "instance_credit_specifications": [], // ec2:DescribeInstanceCreditSpecifications
                                     //   （T 系のみ。CpuCredits が unlimited / standard）
    "instance_connect_endpoints": [] // ec2:DescribeInstanceConnectEndpoints（あれば）
  },

  "database": {
    "db_instances": [],              // rds:DescribeDBInstances（Engine / EngineVersion / MultiAZ /
                                     //   BackupRetentionPeriod / AutoMinorVersionUpgrade /
                                     //   StorageEncrypted / VpcSecurityGroups / DBSubnetGroup 込み）
    "db_clusters": [],               // rds:DescribeDBClusters（Aurora 用。Next では空のはず）
    "db_parameter_groups": [],       // rds:DescribeDBParameterGroups
    "db_parameters": {},             // { "<ParameterGroupName>": [ ...非デフォルト値のみ... ] }
    "db_subnet_groups": [],
    "db_snapshots": [],              // rds:DescribeDBSnapshots（SnapshotType='manual' と 'automated'）
    "db_engine_versions": [],        // rds:DescribeDBEngineVersions（EOL 判定用。使用中エンジンのみ）
    "event_subscriptions": []
  },

  "storage": {
    "buckets": [],                   // s3:ListBuckets の各要素に以下を追加した配列
                                     //   "Region", "Policy"(dict|null), "PublicAccessBlock",
                                     //   "PolicyStatus", "Encryption", "Versioning",
                                     //   "Lifecycle"(Rules|null), "Website"(dict|null),
                                     //   "Logging", "Acl", "Tagging", "ReplicationStatus"
    "efs_file_systems": [],          // efs:DescribeFileSystems（ThroughputMode / PerformanceMode /
                                     //   Encrypted / SizeInBytes / Name 込み）
    "efs_mount_targets": [],         // 各 FS の MountTargets を平坦化。"FileSystemId" を含む
    "efs_access_points": [],         // efs:DescribeAccessPoints（RootDirectory.Path が重要）
    "efs_policies": {},              // { "<FileSystemId>": <policy dict|null> }
    "efs_backup_policies": {},       // { "<FileSystemId>": {"Status": "ENABLED"|"DISABLED"} }
    "fsx_file_systems": [],
    "backup_plans": [],              // backup:ListBackupPlans + GetBackupPlan
    "backup_selections": [],
    "backup_vaults": [],
    "backup_protected_resources": []
  },

  "edge": {
    "load_balancers": [],            // elbv2:DescribeLoadBalancers に "Attributes"(list) を追加
    "target_groups": [],             // elbv2:DescribeTargetGroups に "Targets"(TargetHealthDescriptions),
                                     //   "Attributes" を追加
    "listeners": [],                 // 各 LB のリスナーを平坦化（Certificates / DefaultActions 込み）
    "listener_rules": [],
    "classic_load_balancers": [],    // elb:DescribeLoadBalancers（あれば）
    "acm_certificates": [],          // acm:ListCertificates + DescribeCertificate
                                     //   （DomainName / InUseBy / Status / NotAfter が重要）
    "cloudfront_distributions": [],  // cloudfront:ListDistributions + GetDistributionConfig
                                     //   （Aliases / Origins / DefaultCacheBehavior / WebACLId 込み）
    "global_accelerators": [],       // globalaccelerator:ListAccelerators（us-west-2 固定）に
                                     //   "Listeners" と各リスナーの "EndpointGroups" を追加
    "route53_hosted_zones": [],      // route53:ListHostedZones に "VPCs"(private の場合) を追加
    "route53_record_sets": {},       // { "<HostedZoneId>": [ ...ResourceRecordSets... ] }
    "wafv2_web_acls": [],            // REGIONAL と CLOUDFRONT 両方。各要素に "Scope" と
                                     //   "AssociatedResourceArns" を追加
    "shield_subscription": null
  },

  "serverless": {
    "lambda_functions": [],          // lambda:ListFunctions に "EventSourceMappings",
                                     //   "Policy"(resource policy|null), "UrlConfig" を追加
                                     //   "_LastLogEvent": {logGroupName, logStreamName,
                                     //     lastEventTimestamp(ms), lastEventTime(ISO)} | null
                                     //     logs:DescribeLogStreams の結果。**本文は読まない**。
                                     //     null はロググループ不在（＝未実行）か権限不足
    "eventbridge_rules": [],         // events:ListRules に "Targets" を追加（全 EventBus を走査）
    "eventbridge_buses": [],
    "stepfunctions_state_machines": [],
                                     // states:DescribeStateMachine（definition は長さと
                                     //   先頭500文字のみ）。"_LastExecution":
                                     //   {name, status, startDate, stopDate} | null
                                     //   states:ListExecutions の直近1件。**入出力は取らない**
    "dynamodb_tables": [],           // dynamodb:DescribeTable（項目の中身は取得しない）
    "sqs_queues": [],                // sqs:ListQueues + GetQueueAttributes（URL と属性のみ）
    "sns_topics": [],                // sns:ListTopics + GetTopicAttributes + ListSubscriptionsByTopic
    "cognito_user_pools": [],        // cognito-idp:ListUserPools + DescribeUserPool（ユーザーは取得しない）
    "apigateway_rest_apis": [],
    "apigatewayv2_apis": []
  },

  "logging": {
    "cloudtrail_trails": [],         // cloudtrail:DescribeTrails に "Status"(GetTrailStatus),
                                     //   "EventSelectors", "IsLogging" を追加。
                                     //   describe_trails 由来の "LogFileValidationEnabled" /
                                     //   "KmsKeyId" / "IsMultiRegionTrail" /
                                     //   "IsOrganizationTrail" はキーを必ず残す（欠けたら null）
    "config_recorders": [],          // config:DescribeConfigurationRecorders に "Status" を追加
    "config_delivery_channels": [],
    "config_rules": [],
    "flow_logs": [],                 // ec2:DescribeFlowLogs
    "cloudwatch_log_groups": [],     // logs:DescribeLogGroups
                                     //   **実際のキーは logs API のまま camelCase**:
                                     //   logGroupName / retentionInDays / kmsKeyId
                                     //   （retentionInDays が無い＝無期限保持）
    "log_group_kms": {},             // { "<logGroupName>": "<kmsKeyId>"|null }
                                     //   上記から組み立てるだけ（追加 API 呼び出しなし）
    "cloudwatch_alarms": [],         // cloudwatch:DescribeAlarms（MetricAlarm と CompositeAlarm。
                                     //   種別が分かるよう "_AlarmType" を追加）
    "cloudwatch_dashboards": []
  },

  "security": {
    "guardduty_detectors": [],       // guardduty:ListDetectors + GetDetector + ListMembers
    "securityhub": {},               // securityhub:DescribeHub + GetEnabledStandards（見出しのみ）
    "inspector2": {},                // inspector2:BatchGetAccountStatus
    "access_analyzer": [],
    "securityhub_standards_controls": [], // securityhub:DescribeStandardsControls
                                     //   （有効な標準ごと。Findings は取得しない）
    "iam": {
      "users": [], "roles": [], "policies_attached_summary": [],
      "account_summary": {}, "password_policy": null,
      "credential_report_meta": null, // 実体は取得しない（機微）
      "account_aliases": [],
      "role_inline_policies": {},    // { "<RoleName>": { "<PolicyName>": <ドキュメント> } }
                                     //   外部信頼ロール・VendorMonitor/StackSet/Service 系を優先、最大50ロール
      "role_attached_policy_documents": {}, // { "<PolicyArn>": {PolicyName, Document, ...} }
                                     //   **カスタマー管理ポリシーのみ**、最大50件
      "access_keys": [],             // { UserName, AccessKeyId(**"****XXXX" にマスク済み**),
                                     //   Status, CreateDate, LastUsedDate, ServiceName, Region }
      "mfa_devices": {},             // { "UserDevices": {"<UserName>": [...]}, "VirtualDevices": [...] }
      "server_certificates": []      // iam:ListServerCertificates
    },
    "organizations": {},             // organizations:DescribeOrganization + ListParents + ListPoliciesForTarget
    "organizations_policies": [],    // SCP の**本文**（organizations:DescribePolicy）。
                                     //   親 OU / ルートを辿って継承分も含める。
                                     //   各要素に "Content" と "AttachedTo" を持つ
    "kms_keys": [],                  // kms:ListKeys + DescribeKey + GetKeyRotationStatus
                                     //   （**KeyManager == "CUSTOMER" のみ**。
                                     //     "RotationEnabled" は取得不可なら null）
    "secrets": [],                   // secretsmanager:ListSecrets のメタ情報のみ。
                                     //   **GetSecretValue は絶対に呼ばない**
    "ssm_parameters_meta": [],       // ssm:DescribeParameters（Name / Type のみ。**値は取らない**）
    "account_public_access_block": null, // s3control:GetPublicAccessBlock の
                                     //   PublicAccessBlockConfiguration（未設定なら null）
    "identity_center": {},           // sso-admin:ListInstances（あれば）
    "cloudformation_stacks": [],     // cloudformation:DescribeStacks（StackName / StackStatus / Tags）
    "cloudformation_stack_sets": [], // cloudformation:ListStackSets + DescribeStackSet
                                     //   （VendorMonitor StackSet の実体確認に使う）
    "stack_instances": []            // 上記 StackSet の ListStackInstances
  },


  "host": {                          // awsprobe host-probe が追記する（既定は存在しない）
    "method": "ssm",                 // "ssm" | "manual"
    "collected_at": "...",
    "truncated": false,              // SSM の stdout 24,000 字打ち切りが起きたか
    "batches": 3,                    // プローブを何回に分けて送ったか（打ち切り回避のため分割する）
    "command_ids": ["..."],          // SendCommand の CommandId（監査用）
    "reason": null,                  // 実行しなかった場合の理由コード
                                     //   ssm_command_disabled / not_confirmed / dry_run /
                                     //   no_reachable_instances / ssm_unavailable
    "manual_doc": "docs/manual-ssh-commands.md",
    "instances": {
      "<instance-id>": {
        "ssm_reachable": true,
        "truncated_probes": [],      // 打ち切りで取れなかったプローブ名
        "results": {
          "<probe-name>": {
            "status": "Success",     // Success / NoOutput / Truncated / PartiallyTruncated / Failed
            "stdout": "...",         // 鍵本体・秘密情報はマスク済み
            "stderr": ""
          }
        }
      }
    }
  }

    "method": "ssm" | "manual",
    "collected_at": "...",
    "instances": {
      "<instance-id>": {
        "ssm_reachable": true,
        "results": { "<probe-name>": {"status":"Success","stdout":"...","stderr":""} }
      }
    },
    "manual_doc": "docs/manual-ssh-commands.md"
  }
}
```

## 判定ロジック側の約束

- `questions.py` / `posture.py` は `inventory` dict だけを見て判定する。AWS API は呼ばない。
- 該当セクションが存在しない／空の場合は `status="no_data"` を返し、
  `errors` に対応する `AccessDenied` があればそれを `summary` に含める。
- `evidence` は JSON のパス文字列で示す。例: `network.security_groups[2].IpPermissions[0]`
- `posture.py`（CIS AWS Foundations v3.0 / AWS FSBP に基づく実施状況評価）は
  `実施済` / `一部実施` / `未実施` / `該当なし` / `判定不能` の5値を返す。
  データが取れていない場合は `判定不能` とし、`errors` に該当する AccessDenied が
  あれば summary に明記する。

## 機微情報の扱い（inventory に出してはならないもの）

- IAM アクセスキー ID の全体（`access_keys[].AccessKeyId` は `****XXXX` にマスク済み）
- シークレットの値（`secretsmanager:GetSecretValue` はガードの拒否リスト）
- SSM パラメータの値（`ssm:GetParameter*` はガードの拒否リスト）
- CloudFormation の `Parameters` / `Outputs` の値（`_keys` にキー名だけ残す）
