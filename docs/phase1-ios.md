# Phase 1 — iPhone / iPad 実機接続テスト

## 完了条件

sing-box MTへ生成したJSONをインポートし、VPN GateサーバーへのVPN接続が実際に確立する。IP確認サイトで**VPN接続前後の出口IPv4が変化**し、Wi-Fiと携帯網のいずれかで通信できることを確認する。東京判定は追加観測であり、Phase 1の必須条件にはしない。

## 手順

1. iPhone/iPadにsing-box MTをインストールする（公式App Storeの提供元を確認）。WARPや他のVPNは検証中OFFにする。
2. PCから `python3 -m vpn_orbit.phase1 --from-vpngate --list` で候補を確認。取れない場合はVPN Gate公式から`.ovpn`を取得してローカル変換する。
3. `--index 1` などで1台のみJSONを生成。秘密情報を含む可能性があるため、公開リポジトリ・公開URLへアップロードしない。
4. AirDropまたはAppleの「ファイル」経由で端末へ渡し、sing-box MTの**ローカル**プロファイルとして読み込む。VPN権限を許可する。
5. VPN開始前のIPv4を https://ipinfo.io/ などで確認し、sing-box MTで接続してから同じサイトでIPv4と都市表示を確認する。必要なアプリ側でも確認する。
6. sing-box MTで接続失敗した場合はエラー表示・アプリバージョン・選択した接続先プロトコル・非機密ログを記録する。証明書検証を無効化して通すことはしない。
7. VPNをOFFに戻し、通常通信へ戻ることを確認する。

## 記録する証拠

- sing-box MTのアプリバージョン（1.14系か）
- 生成コマンド（認証情報は記録しない）・プロファイルの選択結果（国/UDP-TCP/ポート）
- 設定読み込み：PASS / FAIL / NOT_TESTED
- TLS確立：PASS / FAIL / NOT_TESTED
- VPN外向きIPv4変更：PASS / FAIL / NOT_TESTED
- 利用先アプリでの東京判定：PASS / FAIL / NOT_TESTED

## 停止条件

基本接続が不可ならPhase 1の範囲で原因を整理して停止。**Phase 2の自動切替やPhase 3のWorkers構築を自動開始しない。** Human Ownerが結果を確認して次段階を判断する。
