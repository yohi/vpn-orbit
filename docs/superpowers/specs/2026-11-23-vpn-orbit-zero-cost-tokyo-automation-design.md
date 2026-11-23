# VPN-ORBIT — Zero-Cost Automated Tokyo VPN Design R0.1

**状態：Design R0.1 Human Owner ADOPTED（2026-11-23）／feature/vpn-orbit-gha-isolation-feasibility-design-20261123に追加済み（master未反映）／実装・GitHub Actions DispatchはHOLD**

## 1. 目的

追加費用0円で、VPN Gateの東京出口候補を自動発見・実通信検証・補充し、Cloudflare Workers FreeからiPhone/iPadのsing-box MTに配信する。

最優先要件は東京出口と通信の安定性。

検証済み候補が全滅した場合はエラーとしてVPNを停止する。停止後の通常Wi-Fi／モバイル通信は許可する。

## 2. 採用アーキテクチャ

| コンポーネント | 責務 |
|---|---|
| GitHub Actions Scheduler | 定期実行・排他・実行上限 |
| Discovery / Validator | 公開CSV取得・厳格なCA/TLS/Identity評価 |
| Isolated OpenVPN Runner | 隔離実通信・出口IPv4・東京判定・安定性評価 |
| Verified Tokyo Pool | 検証証拠・有効期限・候補状態 |
| Trusted Publisher | 検証済み候補のみKVへ反映 |
| Workers Free | 認証・鮮度検証・プロファイル配信 |
| sing-box MT | VPN接続・切替・Remote Profile更新 |

既存のPhase 1～3とStage 1の実装を再利用する。

## 3. 検証・採用契約

- 公開CSVは信頼できない入力として処理する。
- CA/TLS検証、クライアントIdentity、暗号方式を緩和しない。
- 初期の信頼グループは既存のHuman Owner検証証拠に基づいて確定する。
- 新規Remoteは個別Owner承認なしで自動検証・採用できる。
- 未承認の新規CA・信頼グループは自動昇格させない。
- 実通信後の出口IPv4と東京GeoIPを確認する。
- 接続成功だけでなく、継続通信・応答時間・切断状況を評価する。
- 検証結果には時刻・対象Identity・期限を付与する。
- 有効な東京候補が2件未満の場合、新しい配信Snapshotを発行しない。
- 未確認状態、検証失敗、Cleanup異常はFail-Closedとする。

数値的な安定性基準や有効期限は、実測と無料実行枠の条件を踏まえて実装計画で固定する。

## 4. GitHub-hosted Runnerの安全境界

初回は実VPN接続なしで、TUN・Namespace・nftables・権限・経路復元の成立性を確認する。

成立した場合に限り、別途承認された実通信試験へ進む。

本番Runnerでは候補を逐次検証し、実行数・時間・帯域に上限を設ける。

OpenVPNプロセスにCloudflare認証情報、GitHub書込み権限、Publisher用資格情報を渡さない。

検証Jobと配信Jobの権限を分離する。検証証拠にはProfile原文・秘密鍵を含めず、配信前に候補のProfile Identityを再照合する。

Cleanup不完全、隔離不成立、権限逸脱を検出した場合は、そのバッチ全体を停止する。

### 初回Kernel Capability Smokeの限定安全契約（実通信なし）

- **実行Identity（F-001）**：Owner承認記録に、Workflow定義の完全Commit SHA／WorkflowファイルIdentity、Dispatch Ref、checkout対象の実行コードCommit SHA、Smoke PythonファイルのGit blob SHAを固定する。実行コードCommitとWorkflow定義Commitは区別する。実行コードはPython標準ライブラリだけを使用する単独の承認済みSmokeファイルとし、特権起動を`/usr/bin/python3 -I -S <検証済みSmokeファイル絶対パス>`に限定する。`-I`はPythonの隔離モード、`-S`は`site`初期化無効化を意味し、`-m`／任意の`PYTHONPATH`／リポジトリ内の未承認モジュールimportを禁止する。Namespace内の固定UDP送信も`/usr/bin/python3 -I -S -c <承認済み固定コード定数>`だけを許可する。Identity照合に含まれない特権コードを実行しない。
- **Dispatch／特権起動前ゲート**：Ownerは実行前にDispatch Refの指すWorkflow定義Commitが承認済みと一致することをreadbackする。JobはRefの許可リスト一致、`github.sha`とcheckout済みWorkflow側HEADの一致、および別途SHA固定した実行コードCommitのHEADとSmoke blob SHAの一致を、sudo起動前にすべて検査する。GitHub workflow定義の自己Commit SHAは同一YAMLに埋め込めないため、**OwnerのDispatch直前確認は機械検証の代替ではなく必須の独立ゲート**とする。照合できない／不一致なら起動せず`BLOCKED`。`actions/checkout@<full SHA>`はAction自体のIdentityであり、checkoutされたコードのIdentityを証明しない。Workflow入力や外部書込みを増やさない。**mutableな`dispatch_ref`にはOwnerのreadbackとDispatchの間にRefが更新される競合窓が残る**ため、直前readbackは原子的に実行WorkflowのIdentityを保証する仕組みではない。この残余リスクをOwnerが明示的に受容しない限りDispatchは`HOLD`とする。保護Refなどの代替手段は別途Owner承認なしに採用しない。
- **実行境界（F-002）**：`CommandRunner.run(argv: tuple[str, ...], *, timeout_s: float) -> CommandResult`を唯一のOSコマンド経路とし、`shell=False`、絶対パス、最小環境allowlist、引数ごとの固定許可構文、各コマンドタイムアウトを強制する。`CommandResult`は`argv`／`returncode`／`stdout`／`stderr`／`timed_out`／`spawn_failed`を持つ。非0終了・タイムアウト・出力過大・不許可argvは成功に変換しない。具体的な許可構文・上限は同一採択Specに対応する実装Planに固定する。
- **リソースの所有とCleanup（F-002）**：衝突しない実行nonceから生成した**送信／受信2つの一時Namespace**および専用veth、Namespace内TUNとnftテーブルだけを対象とする。事前の不存在、作成コマンド成功、期待する実体のreadbackが揃ったものだけを所有済みとする。既存・所有不明・作成成否不明の実体は削除せず、`CLEANUP_FAILED`または`BLOCKED`として停止。部分失敗時も所有確認済みの対象を逆順Cleanupし、最後に独立readbackで不存在とHost route／`ip_forward`不変を確認する。`CLEANUP_FAILED`はCapability成功より優先する。
- **DROPの実効性（F-003）**：送信Namespace内の`nft inet vof_<nonce> out`（`type filter hook output priority 0; policy accept`）に、受信側専用veth IPv4への**UDP/9 `counter drop`**を明示する。試験は外部宛ではなく、送信Namespaceから受信Namespaceの専用veth宛へ**UDP datagram 1件だけ**送る。前後の同一ルールcounterについて`after.packets - before.packets == 1`、ルールの`counter drop`読戻し、専用veth宛routeを確認する。いずれか未確認・未増加・不一致なら`BLOCKED`とし、Host既存Firewall／外部ネットワークは変更しない。

この限定SmokeはLinux Kernel能力のみを判断するもので、OpenVPN・東京出口・継続運用のPASSを意味しない。実行には別途OwnerのWorkflow定義・対象Commit・Dispatch承認が必要。

## 5. Verified PoolとWorker配信

Poolは候補ごとにIngress、検証済み出口IPv4、東京判定、TLS Identity、最終成功時刻、失効期限、安定性指標を管理する。

新しいPool Snapshotは認証済みPublisherだけが更新する。

Workerは現在の固定`APPROVED_REMOTES`依存方式から、検証済みSnapshotを厳格に検証する方式へ限定変更する。

Worker側で未知のVPN Gate候補を無条件採用しない。

古いSnapshotは有効期限で拒否し、直接接続用のフォールバック設定を発行しない。

Cloudflare KVの結果整合性とGitHub Actionsのスケジュール遅延を考慮する。候補更新が遅れても、未検証候補を配信して補わない。

## 6. iOSの動作契約

稼働中の接続障害時は、プロファイル内の別の検証済み候補へ切り替える。

候補集合が変わった場合はRemote Profileを更新する。

全候補失敗時はVPN停止とエラー通知を目指し、停止後の通常回線利用を許可する。

ただし、Remote Profile更新・実行中設定の再読込み・VPNの自動停止をsing-box MTが提供するかは未検証であり、実機E2Eの必須確認事項とする。

WorkerのHTTP 503だけでiOS側のVPN停止が実現したとは判断しない。

## 7. 実装・実証順序

| 順序 | 成果 |
|---|---|
| 1 | GitHub-hosted Runnerで隔離機能の成立性を確認 |
| 2 | 既存Stage 1を基礎とする制限付き自動検証Runner |
| 3 | Verified Tokyo Poolと失効・補充制御 |
| 4 | 信頼済みPublisherとWorker配信の統合 |
| 5 | iPhone実機E2E、続いてiPad実機E2E |
| 6 | スケジュール欠落・候補枯渇・異常停止の運用受入 |

Runnerの隔離検証に失敗した場合は実通信せず停止し、無料の代替方式をOwnerが判断する。

## 8. 完了条件

東京出口として検証された互換候補が自動補充され、Workerから有効なプロファイルが配信される。

iPhone/iPadで接続・候補切替・更新・全候補失敗時の動作を実機確認する。

検証不能時やサービス障害時に、未検証の東京以外の出口へ切り替わらない。

追加費用を発生させない。

## 9. 対象外・禁止事項

自宅Hostでの本番実行、有料サービス、無制限のVPN接続試行、TLS検証の緩和、未検証候補の配信は対象外。

この設計の採択だけでは実通信、GitHub Actions起動、Cloudflare書込み、資格情報変更を許可しない。

追加レビューを自動連鎖させない。必要な限定修正後はHuman Owner Checkpointで停止する。