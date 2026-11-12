# Phase 1 — iPhone / iPad 実機接続テスト

## 完了条件

sing-box MTへ生成したJSONをインポートし、VPN GateサーバーへのVPN接続が実際に確立する。IP確認サイトで**VPN接続前後の出口IPv4が変化**し、Wi-Fiと携帯網のいずれかで通信できることを確認する。東京判定は追加観測であり、Phase 1の必須条件にはしない。

## 手順

1. iPhone/iPadにsing-box MTをインストールする（公式App Storeの提供元を確認）。WARPや他のVPNは検証中OFFにする。
2. PCから `python3 -m vpn_orbit.phase1 --from-vpngate --list` で候補を確認。取れない場合はVPN Gate公式から`.ovpn`を取得してローカル変換する。
3. `--index 1` などで1台のみJSONを生成。秘密情報を含む可能性があるため、公開リポジトリ・公開URLへアップロードしない。
4. AirDropまたはAppleの「ファイル」経由で端末へ渡し、sing-box MTの**ローカル**プロファイルとして読み込む。VPN権限を許可する。
5. VPN開始前に、IPv4出口とIPv6出口を確認して記録する。IPv4は https://ipinfo.io/ など、IPv6は https://test-ipv6.com/ などを利用する。DNS漏えい確認サービスでも、表示されたDNSリゾルバー名・国や地域を記録する。
6. sing-box MTで接続する。生成設定はIPv6をTUN経由でOpenVPN endpointへ送り、endpoint側でローカル拒否する構成なので、接続中はIPv4通信がVPN経由になり、IPv6通信は利用できないことを確認する。同じIPv4/IPv6確認とDNS漏えい確認を再実施し、接続前の値と比較する。IPv6の外部到達性が残る場合、DNSリゾルバーに接続元ISP等が表示される場合、または判定できない場合は合格にしない。
7. sing-box MTで接続失敗した場合はエラー表示・アプリバージョン・選択した接続先プロトコル・非機密ログを記録する。証明書検証を無効化して通すことはしない。
8. VPNをOFFに戻し、通常通信へ戻ることを確認する。切断後のIPv6出口も観測・記録する。この設定はVPN切断中のKill Switchを保証しないため、切断後のIPv6通信が通常経路へ戻る可能性を前提に扱う。

## 記録する証拠

- sing-box MTのアプリバージョン（1.14系か）
- 生成コマンド（認証情報は記録しない）・プロファイルの選択結果（国/UDP-TCP/ポート）
- 設定読み込み：PASS / FAIL / NOT_TESTED
- TLS確立：PASS / FAIL / NOT_TESTED
- VPN外向きIPv4変更：PASS / FAIL / NOT_TESTED
- 接続前IPv6出口（アドレス/ISP/国・地域、または利用不可）：
- 接続中IPv6確認（遮断を期待、利用した確認サービスと結果）：PASS / FAIL / NOT_TESTED
- VPN切断後IPv6状態（アドレス/ISP/国・地域、または利用不可）：
- 接続前DNS漏えい確認（表示されたリゾルバー/ISP/国・地域）：
- 接続中DNS漏えい確認（表示されたリゾルバー/ISP/国・地域）：PASS / FAIL / NOT_TESTED
- DNS漏えい確認サービス名・確認時刻：
- 利用先アプリでの東京判定：PASS / FAIL / NOT_TESTED

## 停止条件

基本接続が不可ならPhase 1の範囲で原因を整理して停止。**Phase 2の自動切替やPhase 3のWorkers構築を自動開始しない。** Human Ownerが結果を確認して次段階を判断する。
