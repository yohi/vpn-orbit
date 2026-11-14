# vpn-orbit

VPN GateのOpenVPN接続設定から、iOS/iPadOS向け **sing-box MT 1.14+** のプロファイルを生成するPoCです。Phase 1（単一接続先）に、Phase 2（互換な複数OpenVPN接続先での再接続）を積み上げています。

**現状：2026-11-13にiPhoneのsing-box MTで、単一VPN Gate接続と外向きIPv4の変化を実機確認しました（TCP 218.226.0.144:1822、位置判定は三重県）。** ただし実機成功時のJSONは手動でTUN経路を修正したものです。この修正を生成器へ取り込んだ後の再接続確認、東京GeoIP判定、iPad、障害時の無操作フェイルオーバーは未検証です。Workersデプロイ、クラウドへの書込みは含みません。

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
- JSONの構文・自動テスト通過は実機のVPN接続成功を意味しません。2026-11-13に**手動調整した単一サーバーJSONでiPhone実機接続を確認**しましたが、修正後の生成器から作ったJSONそのものとPhase 2/3の実機動作は未検証です。
- TUN切断時の直接接続復帰、DNS/IPv6漏れを防ぐ「完全なKill Switch」は実証していません。機密通信や位置保証の必要な利用には使わないでください。
- ローカルVPNはiOSの他のVPN（WARP等）と競合する可能性があります。検証時は併用しないでください。

### Phase 2：複数接続先（新規）

```bash
# 2件以上のローカル .ovpn から、TLS設定が互換な接続先だけを選択
python3 -m vpn_orbit.phase2 \
  --ovpn /path/a.ovpn /path/b.ovpn \
  --output /tmp/vpn-orbit-phase2.json

# APIから最大5台の互換なJP接続先を検索
python3 -m vpn_orbit.phase2 --from-vpngate \
  --max-servers 5 --output /tmp/vpn-orbit-phase2.json
```

sing-boxは1つのOpenVPN Client Endpointに`servers`配列を設定でき、接続失敗時の次候補再試行が公式仕様として存在します。ただし**異なるCA等を自動的に安全に切り替える機能ではありません**。原則としてCA・TLS・認証設定が同一の候補のみをまとめます。条件に合わない場合は出力しません。異なるCAを統合する明示的な実験用オプション`--allow-ca-union`も用意しましたが、個別IPへのCAピン留めはできず、信頼対象が広がるため通常利用は非推奨です。

詳細な条件と実機試験は [docs/phase2-ios.md](docs/phase2-ios.md) を参照。単体テストは `python3 -m unittest discover -s tests -v`。Phase 2は**コンバーター実装**であり、iOS実機での自動切替成功ではありません。

Phase 1の実機テストは [docs/phase1-ios.md](docs/phase1-ios.md) を参照。生成するTUNは `auto_route: true` の標準経路を使い、廃止済み `inet6_route_address` と明示的 `route_address` を出力しません。OpenVPN接続先IPのみ `route_exclude_address` でTUNから除外します（その宛先への通信は直接経路になる）。複数接続先では全登録IPを除外します。これ自体はKill SwitchやIPv6/DNS漏れ防止を保証しません。

## 参照

- https://www.vpngate.net/api/iphone/
- https://sing-box.sagernet.org/configuration/endpoint/openvpn-client/
- https://sing-box.sagernet.org/configuration/inbound/tun/
- https://sing-box.sagernet.org/configuration/route/

## Inline OpenVPN client identity (2026-11-13)

VPN Gate/SoftEtherの.ovpnに含まれる`<cert>`/`<key>`をPhase 1とPhase 3で安全に解析し、sing-boxの`tls.client_certificate`/`tls.client_key`へ引き継ぎます。片方だけのペア、不正・暗号化PEMは拒否します。**PEM構造検査は証明書と鍵の暗号学的な一致や実機接続成功を証明しません。** Phase 2では異なるクライアントIDを同一Endpointへ結合しません。

Workerの`/profile.json`と`/health`は`PROFILE_ACCESS_TOKEN`（64文字の16進数）による認証が必要です。`Authorization: Bearer <token>`、またはsing-box MTのRemote Profile向けに`/profile.json?token=<token>`を使用します。認証がない・不正な場合はHTTP 401、WorkerにSecretが未設定の場合はHTTP 503を返します。トークンを含むURLは秘密情報として扱ってください。`ALLOW_PUBLIC_CLIENT_KEYS="true"`は公開済み共通テスト用クライアント鍵のKV保存と**認証付き配信**を許可する設定であり、認証を無効化しません。**公開済み共通鍵だとHuman Ownerが確認・承認した場合だけ**有効にし、個人固有・非公開の鍵には使用しないでください。詳細: [Phase 3](docs/phase3-workers.md)。

## Phase 3 — Cloudflare Workers / remote profile distribution

Phase 3 builds on Phase 2, adding a Cloudflare Worker that periodically fetches VPN Gate's JP catalog and serves a sing-box MT profile at `GET /profile.json`. It selects only operator-approved Tokyo-tested ingress IPs sharing identical CA and TLS settings, requires at least two distinct remotes, and never emits a direct fallback. An expired profile returns HTTP 503; **this does not revoke a profile already cached on iOS**.

Run Phase 3 unit tests with `cd worker && npm test` (Node.js 20+, no dependencies). See [Phase 3 guide](docs/phase3-workers.md). The deployment config is an intentionally nonfunctional template. **No Cloudflare resources were created or deployed; live VPN connectivity, iOS remote update, automatic failover, Tokyo classification, and kill-switch behavior remain unverified.**
