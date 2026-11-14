# vpn-orbit — Dynamic Tokyo VPN Pool Design R0.1.1（限定訂正案）

> Status: 元のDesign R0.1の設計方針はHuman Owner承認済み。本R0.1.1はfeatureブランチにCommit・Push済み。ただし、**Human OwnerによるR0.1.1の正式採択は未承認**であり、Stage 1の実装・実行も未承認。Reviewed HEAD（過去の文書レビュー基準点）: `e7da31fd035bed95671cd41d42b419a450f2a976`。

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

### GitHub Actions（定常運用は2時間ごとを想定、Stage 1は手動のみ）

通常のUbuntu VM Runnerを起動して以下を実施する。

1. VPN Gate公式APIから日本国内候補を取得。
2. GeoIP APIで入口IPが東京都の候補を優先抽出。
3. 安全に解析できるOpenVPN設定だけを採用候補にする。
4. 独立したネットワーク隔離環境でVPN接続を試行。
5. VPN経由の出口IPv4を取得。
6. GeoIP APIで出口IPの東京都判定を確認。
7. TLS・認証条件と接続結果を検査。
8. 適格候補をまとめてCloudflare KVへ公開。

入口IPのGeoIPは**優先順位付け**にのみ使用し、非東京/不明入口を捨てない。出口IPの東京判定を必須条件とする。**Stage 1は手動実証だけで、Cloudflare KVへの書込みはしない。** 上の手順8は後続Stageでのみ適用する。

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

## Stage 1 共通規範（F-001〜F-004、R0.1.1 限定訂正）

この節とStage 1 Planの「Stage 1 共通規範」は同一の契約を示す。矛盾する旧表現より本節を優先する。Stage 2〜4の将来設計を追加承認したものではない。

### F-001 候補選別・順序（契約）

- `vpn_orbit.phase1.fetch_catalog()` → `parse_catalog(catalog, country="JP")` を使用する。既存関数は**有効候補を最大1,000件収集してからソート**するため、1,000件より後のCSV行は探索範囲外である。
- 個々の`Candidate`は`profile`を持つがport/protocolフィールドを持たない。**必ず**`convert_ovpn(candidate.profile, expected_ip=candidate.ip)`から`server`, `server_port`, `network`を得て、`RemoteKey = (IPv4, port:int, protocol:Literal["tcp","udp"])`を形成する。二重のパースでも安全条件を緩和しない。
- 固定入口IPv4 `119.105.93.237`と`126.234.242.57`はport/protocolを問わず除外する。その他は`RemoteKey`単位で重複排除する。同一IPでもportまたはprotocolが異なれば保持する。同一キーが重複した場合はソート済みカタログ上で最初の候補を採用する。
- 重複除去後、カタログ順位のままTCP・UDP別に上位20件ずつを暫定選抜する。不足した側の枠は残り全候補から**元のカタログ順位**で埋め、全体の**探索窓`scan_window=40`件**を確定する。TCP・UDPの一方だけで40件に達してよい。IP単位で窓を切らず、異なるport/protocolを早期に失わない。
- 入口GeoIPは探索窓内の**IPごとに1回**照会・キャッシュし、`TOKYO=0`, `NON_TOKYO=1`, `UNKNOWN=2`の優先ランクを付ける。入口が非東京・不明でも捨てない。入口GeoIPの失敗も`UNKNOWN`として保持する。GeoIPは`https://api.ipapi.is/`のAPIキー付き応答を用い、判定項目は`ip`, `location.country_code`, `location.state`とする。
- **GeoIP HTTP契約（F-006）**：入口・出口の双方で`POST https://api.ipapi.is/`のみ使用し、`Content-Type: application/json`、JSON本文は`{"q":"<IPv4>","key":"<API_KEY>"}`とする。APIキーをURL・Query String・ログ・例外・Artifactに含めない。HTTPSの証明書とホスト名を通常検証し、redirectを追跡しない（3xxは`UNKNOWN`）。HTTP timeoutは**5秒**、レスポンスは本文読み込み中を含め最大**64KiB（65,536 bytes）**に制限する。HTTP 200以外、200でもトップレベル`error`または`error_code`フィールドが存在する応答、不正JSON、非object応答、タイムアウト、サイズ超過、HTTP/TLS例外はいずれも`GeoDecision.UNKNOWN`。異常応答の本文・秘密を含み得る例外メッセージは出力しない。`TOKYO`は既存の`ip`一致・`location.country_code="JP"`・`location.state="Tokyo"`等の受理条件をすべて満たす場合に限る。
- **同一IP分散をGeoIP順位より優先する**。探索窓の各IPの候補をカタログ順位で並べ、各候補に同一IP内の出現順`round=0,1,...`を与える。全候補を`(round, ingress_geo_rank, catalog_rank, ip, port, protocol)`の昇順で並べる。したがって第1巡の非東京入口は、第2巡の東京入口より先になる。同一巡内は東京入口を優先する。この規則により入口GeoIPの優先とIP分散が矛盾しない。
- 上記の並びの先頭から**実接続上限`limit=10`件**を選ぶ。`limit`はCSV行数やGeoIP照会件数ではなく、OpenVPN接続試行数であり、`1 <= limit <= 10`のみ許容する。`scan_window=40`はこの前段の接続候補数とする。採用の最終条件は**隔離VPNを通過した出口IPv4**がGeoIPで東京都と判定されることであり、入口判定は採用条件ではない。
- 成功例：入口`UNKNOWN`でも出口が`Tokyo`なら`PASS`可能。入口`Tokyo`でも出口が`Osaka`なら`NOT_VERIFIED`。固定2台、未検証TLS、不正/私有IPv4、接続不能候補はWitnessにならない。

### F-002 OpenVPN設定再構成・認証（契約）

- `convert_ovpn()`は**sing-box形式のEndpoint辞書**（`type="openvpn-client"`）を返す。これはOpenVPN CLI設定ではない。元の`.ovpn`を`openvpn --config`に渡さず、解析済みEndpointから検証器専用のallowlist設定だけを生成する。元のOpenVPNコメント・IGNORABLE指定・未知directive・script/plugin/external path・`pull`/route指令を**再利用しない**。
- 構造チェック：`server`/`server_port`/`network`が`RemoteKey`と完全一致し、`tls.certificate`は非空配列で各要素をPEM CAとして検証する。`auth`は既存`AUTHS`、`data_ciphers`とfallbackは既存`CIPHERS`の許容値のみ。未知Endpointキー、未知TLSフィールド、未対応の組み合わせは拒否する。CAの暗黙結合、TLS検証無効化、暗号の暗黙ダウングレードは禁止。
- 明示マッピング：`server,server_port`→`remote <IPv4> <port>`、`network=tcp|udp`→`proto tcp-client|udp`、`tls.certificate[]`→検証器の`ca`ファイル、`remote_certificate_tls="server"`→`remote-cert-tls server`、`remote_certificate_eku`→`remote-cert-eku`、`server_name`と`server_name_type`→`verify-x509-name`、`client_certificate[]/client_key[]`→`cert`/`key`、`auth`→`auth`、`data_ciphers`→`data-ciphers`、`data_ciphers_fallback`→`data-ciphers-fallback`。不明な対応は**推測せず拒否**。
- `tls.control_wrap.type=tls_auth`→`tls-auth`（OpenVPN静的キー）、`tls_crypt`→`tls-crypt`。`tls_auth`の`direction`: **`client`→`1`、`server`→`0`、キー不在→方向指定なし**。その他の値は拒否する。`tls_crypt`は方向を持っていてはならない。静的キーを外部パスから読み込まない。
- クライアント証明書と秘密鍵は、双方存在するか双方存在しないかのどちらか。存在する場合、**先頭のleaf証明書**の公開鍵をOpenSSL `x509 -pubkey -noout`で抽出し、`pkey -pubin -outform DER`へ変換したSPKIと、秘密鍵の`pkey -pubout -outform DER`から得たSPKIを**バイト一致**で照合する。非一致、OpenSSL不在・エラー、曖昧なPEM構造は拒否。比較で秘密鍵の原文・公開鍵をログ出力しない。
- `auth-user-pass`が明示されていた場合だけ`username/password`を使用する。Stage 1のエントリポイントは起動環境に`VPN_ORBIT_USERNAME`または`VPN_ORBIT_PASSWORD`が存在したら**拒否**し、既存`convert_ovpn()`のデフォルト値`vpn/vpn`のみを採用する（ユーザー固有の資格情報には対応しない）。これは既存コードの環境変数参照を変更せずに環境汚染を防ぐStage 1の方針である。
- 生成されたOpenVPN設定は`0700`の一時ディレクトリに、CA/証明書/秘密鍵/認証ファイルは`0600`、新規作成・シンボリックリンク拒否で保持する。OpenVPN subprocessは**明示的allowlistの環境だけ**を受け取り、`IPAPI_IS_API_KEY`を含む親環境を継承しない。CLI引数は配列（shell禁止）とし、秘密情報や生成設定の全文をログ・Artifactに含めない。

### F-003 Namespace・経路・IP-Echo（契約）

- プローブごとに新しいLinux Network Namespace、vethペア、専用nftablesルールと`0700`一時ディレクトリを作る。Host側vethに`10.253.240.1/30`、Namespace側に`10.253.240.2/30`を設定する。使用前にHost/Namespaceとのアドレス競合を検査し、競合・`CAP_NET_ADMIN`不足・TUN不在・nft設定不可なら**`BLOCKED`**。Hostのdefault routeは変更しない。
- Namespaceには**default routeを一切設定しない**。トンネル外に許す経路は`<remote IPv4>/32 via 10.253.240.1 dev <veth>`だけ。Hostは既存の外向きinterfaceを`ip -4 route get <remote>`で特定して固定し、専用nftables `forward/input`の優先ルールで、Namespace送信元から**選択remoteのIP/port/protocol宛の転送とそのconntrack返信だけ**を許す。それ以外のNamespace→Host、Namespace→WAN、WAN→NamespaceをDROP。Hostの`ip_forward`値は保存して必要時だけ有効化し、必ず復元する。専用NAT masqueradeはこの許可されたremote向け通信だけに適用する。他のFirewallルールに依存して隔離を代用しない。
- Namespaceの`input/output`もdefault DROPとし、loopback、veth上の選択remote transportと確立済み返信、後述のtun0上の固定HTTPS IP-Echo通信と返信だけを許す。Namespace内の直接DNS（UDP/TCP 53）、IPv6、その他の直接通信は禁止。VPN接続先は数値IPv4なのでNamespace内DNS解決は不要。Host側のDNS通信はVPN検証通信と分離する。
- OpenVPNを**Namespace内部だけ**で起動し、生成設定に`client`, `dev tun0`, `route-nopull`を強制する。`route-nopull`によってサーバーpushのroute/redirect-gateway/DNSを採用しない一方、**サーバーが指定するTUNのIPv4インターフェースアドレス設定だけはOpenVPNが実施**する。検証器はtun0の確立と妥当なIPv4アドレスを確認し、**IP-Echoサーバーの固定IPv4/32経路だけ**を`dev tun0`へ明示追加する。default routeやその他のpush経路が入れば`FAIL`。`route-nopull`が効かない場合は代替へ緩和しない。
- IP-Echoは`https://api.ipify.org/`のみ。Host Namespaceで`api.ipify.org`をAレコード解決し、globally routableな応答IPv4を1つ選んでそのプローブ中固定する。Hostの直接IP-Echo結果は証拠として使用しない。Namespace内では`curl -4 --interface tun0 --resolve api.ipify.org:443:<固定IPv4> --noproxy '*' --proto '=https'`相当で実行し、**TLSチェーンとホスト名/SNIを通常検証**する（`-k`禁止、redirect禁止、proxy禁止、短いconnect/total timeout）。応答は`<=64`バイトの厳密なglobally routable IPv4のみ受理する。IP-Echo用の直接veth経路は作らない。
- **PASS証拠のAND条件**：NamespaceとFirewallが設定済み、トンネル未確立状態ではEchoへの直接接続が拒否される、OpenVPN TLS接続確立、tun0 IPv4あり、`ip -4 route get <echo IPv4>`が`dev tun0`、Echo接続がtun0に束縛されTLS検証成功、取得した出口IPv4がHost側からの鍵付きipapi.is照会で`location.country_code="JP"`かつ`location.state="Tokyo"`、照会対象IPが応答`ip`と一致、全Cleanup成功。いずれか欠けた場合は`PASS`しない。
- 終了処理は`try/finally`で**60秒/候補**を上限とし、プロセスグループにSIGTERM→猶予3秒→SIGKILL、OpenVPN終了確認、/32 Echo経路・Namespace内nft・Host専用nft/NAT・veth・Namespace・全秘密ファイルの削除、Host `ip_forward`の復元を行う。各操作はべき等・失敗を記録し、Cleanup未完了は**`FAIL`**として最終結果を上書きする。Host既存ルールを破壊しない。
- **判定の区別**：環境能力不足/隔離設定不可→`BLOCKED`、候補接続不能/TLS拒否/出口不明/非東京/GeoIPエラー→`NOT_VERIFIED`、観測された直接経路への漏れ、許可外外向き通信、予期せぬ経路適用、秘密ログ漏れ、Cleanup失敗→`FAIL`。唯一の`PASS`は上記AND証拠を満たす候補である。より弱い隔離方式へのFallbackは禁止。

### F-004 初回Workflow実行の承認境界（契約）

- Stage 1で作る`.github/workflows/probe-tokyo-vpn.yml`は`workflow_dispatch`**のみ**。`push`, `pull_request`, `schedule`は追加しない。`ubuntu-24.04` VMを使い、`permissions: contents: read`、Cloudflare Secret・本番KV権限を持たず、生成したOpenVPNプロファイルをArtifactに保存しない。
- GitHub Actionsの`workflow_dispatch`はWorkflowファイルが**default branch (`master`)に存在**して初めて実行可能。featureブランチへの作成/Pushだけでは初回dispatchできない。**feature側の実装/Commit承認、master反映承認、初回dispatch承認は独立**しており、どれも本書の文書承認によって付与されない。dispatch未承認ならPlan Task 4は`HOLD`。
- Stage 1は手動起動1回の限定実証まで。2時間ごとのActions定期検証は将来のStage 2以降の採用方式であり、**Stage 1ではCronも自動実行も追加しない**。既存Worker/KV/固定2台は変更しない。

**共通テスト・完了条件**：候補40件/TCP・UDP配分/実接続10件/決定的順序、入口非東京/不明でも出口東京を許す判定、TLS設定変換・証明書鍵一致と拒否系、Host/Namespace通信の許可/拒否とCleanup、manual-only Workflow/default-branch HOLDをオフラインテストの必須対象とする。オフラインテストPASSはクラウド実証PASSを意味しない。Stage 1の成功は**固定2台以外の少なくとも1台**について前記AND証拠を得た場合だけで、本番への自動採用権限は含まない。

**参照一次資料**：OpenVPN 2.6 manual（`route-nopull`）、ipapi.is API Docs（key付き応答の`location.state`）、GitHub Docs（`workflow_dispatch`はdefault branch必須）。

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

上表はStage 2以降の**将来運用値**である。Stage 1は`scan_window=40`、`limit=10`、`timeout_s=60`、manual-only。6時間の有効期間は将来提案値に限り、現行Workerの2時間TTLを含め、Stage 1で一切変更しない。

## 6. 段階的な完成条件

### Stage 1：クラウド上での成立性確認

GitHub-hosted Runner上の隔離OpenVPN検証がStage 1のAND証拠を満たし、既存固定2台以外のVPN Gate候補の出口IPv4がipapi.is keyed APIで東京都と判定されれば`PASS`。`NOT_VERIFIED`/`BLOCKED`/`FAIL`は共通規範で区別する。本番Cloudflare環境には書き込まない。初回dispatch前には**master反映とdispatchの各別承認**が必須。

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
