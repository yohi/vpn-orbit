# vpn-orbit — Dynamic Tokyo VPN Pool Design R0.1

> Status: Human Owner approved the design direction in chat on 2026-11-14 (JST). Local export only; not committed or deployed.

## 1. 目的

VPN Gateから東京と判定されるVPN出口を自動発見・検証・補充し、iPhone/iPadのsing-box MTで継続利用する。

固定IPへの依存をなくし、自動補充は数時間以内を目標とする。

## 2. 採用方式

**方式A：GitHub Actions定期検証 + Cloudflare Workers/KV配信**

| 方式 | 特徴 | 判断 |
|---|---|---|
| A：GitHub Actions定期実行 | 最小構成・既存資産活用 | 採用 |
| B：WorkersからActions起動 | 起動管理が複雑になる | 不採用 |
| C：常時稼働VPS | 継続監視は容易だが費用・運用負担あり | 不採用 |

## 3. システム構成

### GitHub Actions（2時間ごと）

通常のUbuntu VM Runnerを起動して以下を実施する。

1. VPN Gate公式APIから日本国内候補を取得。
2. GeoIP APIで入口IPが東京都の候補を優先抽出。
3. 安全に解析できるOpenVPN設定だけを採用候補にする。
4. 独立したネットワーク隔離環境でVPN接続を試行。
5. VPN経由の出口IPv4を取得。
6. GeoIP APIで出口IPの東京都判定を確認。
7. TLS・認証条件と接続結果を検査。
8. 適格候補をまとめてCloudflare KVへ公開。

入口IPのGeoIPは事前フィルターであり、出口IPの東京判定を必須条件とする。

### Cloudflare Workers + KV

- GitHub Actionsが生成した検証済みプロファイルを保持。
- 既存の`/profile.json`と`/health`を維持。
- 認証・TLS安全条件・有効期限を検証して配信。
- 既存の固定2台用Cron更新処理は、動的方式へ切り替える段階で停止。
- 検証と配信を分離する。

### iPhone / iPad

- sing-box MTでRemote Profileを利用。
- 同じOpenVPN Endpointに安全に統合できる複数候補を設定。
- 接続失敗時の再接続はsing-boxが担当。
- 新しいRemote Profileが実行中のVPNに反映されるかは実機検証する。

## 4. 安全条件

- 東京と確認できない出口IPは採用しない。
- TLS検証を無効化しない。
- 未承認のTLS信頼設定を自動的に信用しない。
- 既存の検証済みTLS Identityと互換な新規接続先は、自動採用の対象にできる。
- 異なるCA・認証設定を持つ候補は、無理に単一Endpointへ統合しない。
- VPN検証ジョブにはCloudflare書込用Secretを渡さない。
- KVへの書込ジョブはVPNトンネルを利用しない。
- プロファイル、クライアント鍵、APIトークンを公開ログに記録しない。
- 不正な検証結果や候補不足があっても、未検証候補で補充しない。
- 既存のiOSキャッシュを強制失効できない制約を明記する。

## 5. 運用パラメータ案

| 項目 | 初期値案 |
|---|---|
| 新規候補検証 | 2時間ごと |
| 公開候補数 | 2〜5台 |
| 検証結果の有効期間 | 最大6時間 |
| 候補不足 | 新規更新停止、期限切れはHTTP 503 |
| GeoIP判定 | 出口IPv4の東京都判定必須 |
| クラウド環境 | GitHub-hosted `ubuntu-24.04` |
| 公開先 | 既存Cloudflare KV |
| 失敗時 | 東京以外へのフォールバック禁止 |

6時間の有効期間は、GitHub Actionsの起動遅延・欠落を考慮した提案値であり、現行2時間からの変更には別途承認が必要。

## 6. 段階的な完成条件

### Stage 1：クラウド上での成立性確認

GitHub-hosted Runnerから、既存の固定2台以外のVPN Gateサーバーに接続し、出口IPv4の東京判定に成功する。本番Cloudflare環境には書き込まない。

### Stage 2：動的候補管理

新しい接続先を自動検証し、既存の安全条件を満たす候補を自動補充できる。

### Stage 3：Cloudflare統合

動的プールをKVに反映し、Workerから認証付きプロファイルを取得できる。

### Stage 4：iOS実機確認

プロファイル更新、別サーバーへの再接続、東京出口の維持、通信漏れの有無を確認する。

各Stageの実施にはHuman Ownerの承認が必要。後続Stageやレビューを自動開始しない。

## 7. 残余リスク

- GitHub Actionsの定期実行は保証時刻に起動するとは限らない。
- GeoIP APIの東京判定は実際の位置やアプリ固有の判断を保証しない。
- 新しいVPN Gate候補のTLS Identityが既存の信頼対象と異なる場合、自動補充が制限される。
- Cloudflare KVは即時整合性を保証しない。
- Remote Profileの更新が、実行中のVPNへ即座に適用されるとは限らない。
- iOSレベルでの完全なKill Switchは未実証。

## 8. 停止条件

Stage 1でクラウド上のVPN接続が成立しない場合、GitHub Actions方式の実現可能性を再評価する。

安全に検証できないVPN候補を本番へ流さない。新規候補の検証失敗は既存Workerの運用を変更する理由にしない。

設計承認だけで実装・GitHubへのCommit・Cloudflareの設定変更を開始しない。
