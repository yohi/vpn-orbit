# VPN-ORBIT — Zero-Cost Automated Tokyo VPN Design R0.1

**状態：Human Owner ADOPTED（2026-11-23、会話内で承認）／Repositoryには未反映**

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