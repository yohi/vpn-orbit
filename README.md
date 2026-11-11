# vpn-orbit

VPN GateのOpenVPN接続設定から、iOS/iPadOS向け **sing-box MT 1.14+** の単一接続先プロファイルを生成する **Phase 1 PoC** です。

**現状：変換・候補抽出のローカルテスト段階。iPhone/iPadの実VPN接続成功、東京GeoIP判定、フェイルオーバーは未確認です。** Workersデプロイ、クラウドへの書込み、VPNの自動切替はこのPhaseには含みません。

## 目的・範囲

- VPN Gate公式CSV API（日本 `JP`）を取得し、候補を抽出・順位付けする
- 信頼できない`.ovpn`ファイルを実行せずにパースし、安全に対応できる設定だけをsing-box JSONに変換する
- iPhone/iPadで単一VPN Gateサーバーへの接続を試せる設定を作る
- 失敗時は**拒否**し、TLS検証の無効化・直接接続による代替動作を自動導入しない

## 環境

Python 3.11以降、標準ライブラリのみ。生成ファイルを利用するiOS/iPadOSアプリは [sing-box MT](https://apps.apple.com/jp/app/sing-box-mt/id6785326793)（1.14以降）。

## 使い方

```bash
# cloneしたリポジトリのルートから実行。最新JP候補を表示（APIへのHTTPSアクセスあり）
python3 -m vpn_orbit.phase1 --from-vpngate --list

# 最新CSVの最上位候補を選んでJSON生成（APIへのHTTPSアクセスあり）
python3 -m vpn_orbit.phase1 --from-vpngate --index 1 --output /tmp/vpn-orbit-test.json

# ダウンロード済み.ovpnのオフライン変換（APIアクセス不要）
python3 -m vpn_orbit.phase1 --ovpn /path/to/downloaded.ovpn --output /tmp/vpn-orbit-local.json

# テスト
python3 -m unittest discover -s tests -v
```

`--output`は既存ファイルの上書きを拒否し、権限0600で保存します。出力JSONには公開VPNの接続先やCA証明書のほか、認証情報が必要な設定なら`vpn/vpn`（環境変数`VPN_ORBIT_USERNAME` / `VPN_ORBIT_PASSWORD`で変更可能）も含まれます。**生成したJSONや実サーバーの`.ovpn`、認証情報をGitHubへコミットしないでください。**

## 制約

- `.ovpn`のインラインCA必須、リモートIPはグローバルIPv4のみ。外部ファイル、未知のディレクティブ、スクリプト実行、複雑なTLS/暗号設定は拒否します。VPN Gate公開サーバーをすべて変換できるわけではありません。
- TLSのCAとサーバー用途を検証する設定を生成します。元ファイルに`verify-x509-name`がある場合は引き継ぎます。ない場合は特定のサーバー名との照合は行わないため、公開CA信頼の限界が残ります。
- `JP`で選別しても**東京のIPと判定される保証はありません**。実際の接続後、利用したいアプリと複数のGeoIP確認サービスで判断してください。
- JSONの構文・自動テスト通過は、sing-box MTでのロード成功やVPN接続成功を意味しません。**現環境ではsing-box 1.14バイナリおよび実機による検証は未実施**です。
- TUN切断時の直接接続復帰、DNS/IPv6漏れを防ぐ「完全なKill Switch」は実証していません。機密通信や位置保証の必要な利用には使わないでください。
- ローカルVPNはiOSの他のVPN（WARP等）と競合する可能性があります。検証時は併用しないでください。

続きの操作は [docs/phase1-ios.md](docs/phase1-ios.md) を参照。

## 参照

- https://www.vpngate.net/api/iphone/
- https://sing-box.sagernet.org/configuration/endpoint/openvpn-client/
- https://sing-box.sagernet.org/configuration/inbound/tun/
- https://sing-box.sagernet.org/configuration/route/
