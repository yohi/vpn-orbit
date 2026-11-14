# vpn-orbit Stage 1 Cloud Verifier Implementation Plan R0.1.1（限定訂正案）

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task **only after explicit Human Owner execution authorization**. Steps use `- [ ]` syntax. No task, commit, push, workflow run or deployment is authorized by the existence of this plan.

**Goal:** GitHub-hosted Ubuntu VM上で既存固定2台以外のVPN Gate候補に隔離接続し、**トンネル経由の出口IPv4**がGeoIP APIで東京都と判定されることを実証する。

**Architecture:** Read-onlyな候補収集・GeoIP選別と、ネットワーク分離されたOpenVPN接続検証を独立モジュールに分ける。まずmock/offlineテストを作り、最後に手動起動のGitHub Actionsで限定的な実機試験を行う。Cloudflare/KV/既存Worker/iOS設定には一切書き込まない。

**Tech Stack:** Python 3.11+ standard library; Ubuntu `ubuntu-24.04` VM; OpenVPN CLI; Linux network namespace and scoped firewall; GitHub Actions; ipapi.is GeoIP API (keyed tier); existing `vpn_orbit.phase1` parsing/conversion.

**Spec:** `docs/superpowers/specs/2026-11-14-vpn-orbit-dynamic-tokyo-pool-design.md` (R0.1 approved direction; R0.1.1 amendment **proposed, not approved**). Reviewed HEAD `e7da31fd035bed95671cd41d42b419a450f2a976`. This **proposed R0.1.1** plan covers **Stage 1 only**; no GitHub write or Stage 2–4 authorization.

## Stage 1 共通規範（F-001〜F-004、R0.1.1 限定訂正）

この節とStage 1 Planの「Stage 1 共通規範」は同一の契約を示す。矛盾する旧表現より本節を優先する。Stage 2〜4の将来設計を追加承認したものではない。

### F-001 候補選別・順序（契約）

- `vpn_orbit.phase1.fetch_catalog()` → `parse_catalog(catalog, country="JP")` を使用する。既存関数は**有効候補を最大1,000件収集してからソート**するため、1,000件より後のCSV行は探索範囲外である。
- 個々の`Candidate`は`profile`を持つがport/protocolフィールドを持たない。**必ず**`convert_ovpn(candidate.profile, expected_ip=candidate.ip)`から`server`, `server_port`, `network`を得て、`RemoteKey = (IPv4, port:int, protocol:Literal["tcp","udp"])`を形成する。二重のパースでも安全条件を緩和しない。
- 固定入口IPv4 `119.105.93.237`と`126.234.242.57`はport/protocolを問わず除外する。その他は`RemoteKey`単位で重複排除する。同一IPでもportまたはprotocolが異なれば保持する。同一キーが重複した場合はソート済みカタログ上で最初の候補を採用する。
- 重複除去後、カタログ順位のままTCP・UDP別に上位20件ずつを暫定選抜する。不足した側の枠は残り全候補から**元のカタログ順位**で埋め、全体の**探索窓`scan_window=40`件**を確定する。TCP・UDPの一方だけで40件に達してよい。IP単位で窓を切らず、異なるport/protocolを早期に失わない。
- 入口GeoIPは探索窓内の**IPごとに1回**照会・キャッシュし、`TOKYO=0`, `NON_TOKYO=1`, `UNKNOWN=2`の優先ランクを付ける。入口が非東京・不明でも捨てない。入口GeoIPの失敗も`UNKNOWN`として保持する。GeoIPは`https://api.ipapi.is/`のAPIキー付き応答を用い、判定項目は`ip`, `location.country_code`, `location.state`とする。
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

## Global Constraints

- Project `yohi/vpn-orbit` / branch baseline `master` (observed 2026-11-14); preserve existing fixed 2 Tokyo remotes, authenticated Worker endpoints, Cloudflare KV and Cron.
- Existing fixed remotes `119.105.93.237:1279/tcp`, `126.234.242.57:1281/tcp` are **excluded** from the Stage 1 success witness.
- No production Cloudflare API token or KV write access in probe jobs; `permissions: contents: read`; no `wrangler deploy`.
- No automatic adoption of newly found servers until endpoint identity and geo acceptance meet the approved policy; Stage 1 never publishes.
- Every OpenVPN profile is **untrusted**; do not execute downloaded `.ovpn` instructions, scripts or external include paths. Validate by existing strict parser and synthesize only allowlisted directives for OpenVPN CLI.
- OpenVPN is confined to a dedicated netns/veth/nft/NAT with no namespace default route: remote IPv4/32 via veth only; `route-nopull`, tun0 interface IP from OpenVPN, Echo IPv4/32 via tun0 from verifier; host default route untouched. Uncertain live evidence→`NOT_VERIFIED`; capability/policy setup unavailable→`BLOCKED`; **observed unsafe bypass or cleanup failure→`FAIL`**. No fallback.
- GeoIP admission: exit IPv4 is global/public, API response corresponds to the exact queried IP, `location.country_code == 'JP'` and `location.state == 'Tokyo'`. Missing/conflicting/ambiguous fields are rejected. The state field is **not** named `region` in the keyed ipapi.is schema.
- Respect API quotas, use keyed ipapi.is only, per-request timeout 5秒/response最大64KiB、探索窓40件/TCP・UDP各20枠/実接続10件、各probe 60秒。 Never log/write raw client keys, profiles, bearer tokens or GeoIP API credentials. Never persist untrusted executable content as an artifact.
- End a bounded probe after a short timeout even if servers are unresponsive; one bad candidate must not hang the entire workflow.
- Tests can PASS while a live external server is unavailable: classify `PASS` (verified Tokyo exit), `NOT_VERIFIED` (insufficient live evidence), `BLOCKED` (runner capability or policy constraint), `FAIL` (an observed safety assertion failure). Never conflate them.
- No automatic push, merge, deploy, independent review or later Stage start. Owner checkpoint at the end.

## File map

| Path | Purpose |
|---|---|
| `vpn_orbit/cloud_probe.py` | 40件探索窓→入口GeoIP順位→同一IP分散→10件実接続のdeterministic selection、redacted CLI orchestration |
| `vpn_orbit/geoip.py` | Typed response parsing and Tokyo decision; outbound API adapter |
| `vpn_orbit/openvpn_probe.py` | sing-box Endpoint→OpenVPN CLIのallowlist再合成、OpenSSL client pair検証、Network Namespace+veth+nft/NAT、tun0 IP-EchoとCleanup |
| `tests/test_geoip.py` | Exact keyed/anonymous schema tests, invalid and ambiguous geo responses |
| `tests/test_cloud_probe.py` | Candidate limiting, fixed-IP exclusion, aggregate status/redaction tests |
| `tests/test_openvpn_probe.py` | Stubbed process/namespace tests, fail-closed route/firewall/cleanup scenarios |
| `.github/workflows/probe-tokyo-vpn.yml` | Manual-only cloud verification, separate from existing Worker deployment workflow |
| `docs/superpowers/plans/2026-11-14-vpn-orbit-stage1-cloud-verifier.md` | This plan; write to repo only after separately authorized |

Existing `vpn_orbit/phase1.py` / `vpn_orbit/phase2.py` should be reused, not rewritten. No change is planned to `worker/src/*` or `.github/workflows/deploy-vpn-orbit.yml` in Stage 1.

## Review Focus (five highest-risk input classes)

1. A VPN Gate profile containing `up`, `down`, `script-security`, `plugin`, `management`, or external file directives must be **rejected before OpenVPN is executed**. Test in Task 2.
2. A connected tunnel with the IP-echo request accidentally using the host's direct route must **not** produce `PASS`. Test in Task 2.
3. A GeoIP JSON with missing/conflicting country/state or mismatched queried IPv4 must be **rejected**, not treated as Tokyo. Test in Task 1.
4. A crashed/aborted OpenVPN probe must clean the namespace, routes, firewall rules and private temp files; never retain a tunnel on the runner. Test in Task 2.
5. An untrusted or malicious workflow result must never enable a Cloudflare write path; no secret/token in stdout or artifacts. Test in Task 3.

---

### Task 1: GeoIP 東京判定と候補スクリーニング（F-001）

**Files:** Create `vpn_orbit/geoip.py`, `vpn_orbit/cloud_probe.py`; test `tests/test_geoip.py`, `tests/test_cloud_probe.py`.

**Interfaces:**
- `class GeoDecision(Enum): TOKYO, NON_TOKYO, UNKNOWN`。
- `@dataclass(frozen=True) class RemoteKey: ip: str; port: int; protocol: Literal["tcp", "udp"]`。`ip`はglobally routable IPv4、portは`1..65535`。
- `@dataclass(frozen=True) class ScreenedCandidate: candidate: Candidate; remote: RemoteKey; ingress_geo: GeoDecision; catalog_rank: int`。
- `def decide_tokyo(ip: str, response: dict) -> GeoDecision`：返却`ip`一致、`location.country_code="JP"`、`location.state="Tokyo"`のみ`TOKYO`。bogon/reservedや応答不一致は`UNKNOWN`（最終採用拒否）。東京以外の有効応答は`NON_TOKYO`。
- `def lookup_geoip(ip: str, *, api_key: str, timeout_s: float = 5.0) -> GeoDecision`：鍵付きipapi.is HTTPS。最大応答64KiB、redirect禁止、429/timeout/JSON不正→`UNKNOWN`。秘密をURL、例外、ログへ表示しない。
- `def screen_candidates(catalog: str, *, existing_pins: frozenset[str], geo_lookup: Callable[[str], GeoDecision], scan_window: int = 40, limit: int = 10) -> list[ScreenedCandidate]`：共通F-001規範の順序を厳守。`scan_window`はStage 1では40固定、`limit`は1..10。port/protocolは既存`convert_ovpn`のEndpointから抽出し、`Candidate`に存在すると仮定しない。

- [ ] **Step 1: RED tests**：入口東京/非東京/不明を保持し出口GeoIPとは独立に順位付け、固定2台全port除外、同一IP/別port/別protocol保持、完全同一RemoteKey除去、TCP/UDP各20件→不足補充で40件、同一IP roundがGeoIPランクに優先、同round内のTokyo優先、実接続10件、CSV順位タイブレーク、別port/protocolが窓に残る。鍵付きipapi.is応答、IP不一致/予約IP/bogon/HTTP429/timeout/大きすぎるJSONはTOKYOにしない。`8.8.8.8`の例は**mock形状試験のみ**で実IPの東京性を主張しない。
- [ ] **Step 2: Verify RED**：`python3 -m unittest tests.test_geoip tests.test_cloud_probe -v` →未実装の失敗。
- [ ] **Step 3: Implement interfaces**：既存`fetch_catalog/parse_catalog/convert_ovpn`を再利用。IPごとのGeoIP 1回キャッシュ、決定的`RemoteKey`順位、`UNKNOWN`継続、候補生データのログ抑止。
- [ ] **Step 4: Verify GREEN and regression**：同じ2テストと`python3 -m unittest discover -s tests -v` →PASS。
- [ ] **Step 5: Commit boundary**：Ownerの別実装承認後だけLocal Commit。Push/実機実行はさらに別承認。

### Task 2: 隔離OpenVPNトンネル検証器（F-002・F-003）

**Files:** Create `vpn_orbit/openvpn_probe.py`, `tests/test_openvpn_probe.py`; modify `vpn_orbit/cloud_probe.py`, `tests/test_cloud_probe.py`.

**Interfaces:**
- `class ProbeStatus(Enum): PASS, NOT_VERIFIED, BLOCKED, FAIL`。
- `@dataclass(frozen=True) class ProbeResult: ingress_ip: str; port: int; protocol: str; exit_ip: str | None; status: ProbeStatus; reason_code: str`（秘密文字列を含まない）。
- `def synthesize_openvpn_config(parsed_endpoint: dict, *, remote_ip: str, port: int, protocol: str, private_dir: Path) -> bytes`：**既に`0700`で作成した空の専用ディレクトリ**へ`0600`ファイルを安全に作り、生成CLI設定バイト列を返す。ファイルパスは`private_dir`配下だけ。`convert_ovpn()`が返したEndpoint辞書のallowlistのみ使用。control-wrap directionとOpenSSL SPKI照合を実施。
- `def probe_one(candidate: ScreenedCandidate, *, geo_lookup: Callable[[str], GeoDecision], timeout_s: int = 60, runner=None) -> ProbeResult`：`candidate.candidate.profile`を`convert_ovpn(..., expected_ip=...)`で再解析、合成、NamespaceでOpenVPN→tun0固定HTTPS Echo→Hostで出口GeoIP。`runner`は特権操作/コマンド/時間/後片付けをfakeできるadapter。`geo_lookup`は**出口IPv4**を照会し、入口GeoIP結果はPASS判定に使わない。
- `probe_one`の契約：開始前に`VPN_ORBIT_USERNAME/PASSWORD`が環境に存在する場合は拒否（default `vpn/vpn`のみ）、subprocessはAPIキーや親環境変数を一切継承しない。CAP_NET_ADMIN・TUN・nft・veth/Host forwardの安全設定ができなければ`BLOCKED`。

- [ ] **Step 1: RED config tests**：`ca`, `cert/key`, `auth-user-pass`, `data-ciphers`, fallback, `auth`, `remote-cert-tls`/EKU, verify-x509-name、`tls_auth`方向client=1/server=0/absent=無指定、`tls_crypt`で方向指定拒否、未知方向・未知フィールド・raw `.ovpn`のdirect実行・秘密環境変数継承・鍵証明書不一致を拒否。OpenSSLによるSPKI DERバイト比較が行われ、エラー時秘密を表示しない。
- [ ] **Step 2: RED isolation tests**：専用Namespace・veth/Host forwarding/NATの候補限定規則、外向きremote以外DROP、直接DNS/IPv6 DROP、VPN未確立時Echo不可、`route-nopull`でpushされたroute/DNS/redirect-gateway不採用、TUNアドレスはOpenVPN側、Echo/32は検証器側、`ip route get`がtun0、curlの`--interface tun0`/`--resolve`/TLS検証、EchoのIP形式・長さ・Host直接経路rejectを確認。host default route不変。許可外送信観測→`FAIL`。CAP_NET_ADMIN/TUN不可→`BLOCKED`。
- [ ] **Step 3: RED lifecycle tests**：候補60秒上限、SIGTERM→3秒→SIGKILL、成功・タイムアウト・例外・キャンセルの全経路で子プロセス/経路/nft/NAT/veth/Namespace/0600ファイルを削除し`ip_forward`復元。cleanup失敗→最終`FAIL`。TLS/GeoIP/候補障害→`NOT_VERIFIED`、全AND証拠成功→`PASS`。no secrets in stdout/stderr/artifacts。
- [ ] **Step 4: Verify RED**：`python3 -m unittest tests.test_openvpn_probe tests.test_cloud_probe -v` →未実装失敗。
- [ ] **Step 5: Implement minimal safe path**：`synthesize_openvpn_config`は構造化allowlistから生成し、`--config <untrusted-ovpn>`は禁止。`runner`経由のNamespace→veth→Host専用forward/NATを設定。**Namespace default routeなし、remote/32 via vethのみ、`route-nopull`、OpenVPN tun0アドレス、Echo/32 via tun0**。独立したnft allowlist/denyとcleanup、shell interpolationなし。`https://api.ipify.org/`のIPv4をHostで事前解決し、NamespaceではHTTPS TLSホスト名検証+interface bind、Hostで出口IPのGeoIP照会。安全条件を満たせなければFail-Closed。
- [ ] **Step 6: Verify GREEN / regression**：`python3 -m unittest tests.test_openvpn_probe tests.test_cloud_probe -v`および`python3 -m unittest discover -s tests -v` →PASS。実機成立性は未証明。
- [ ] **Step 7: Commit boundary**：Ownerの別実装承認後だけLocal Commit。Push/dispatchしない。

### Task 3: GitHub Actions manual-only live feasibility check

**Files:**
- Create: `.github/workflows/probe-tokyo-vpn.yml`
- Modify: `vpn_orbit/cloud_probe.py` (CLI entrypoint + redacted summary)
- Test: `tests/test_cloud_probe.py` (workflow output and status contract)

**Interfaces:**
- CLI: `python3 -m vpn_orbit.cloud_probe --scan-window 40 --limit 10 --timeout-seconds 60`; accepts `IPAPI_IS_API_KEY` from Actions Secret; emits only a summary `{status, tested_count, tokyo_confirmed_count, witness_ingress, witness_exit, reason_codes}`; no raw `.ovpn` or credentials.
- Workflow: `workflow_dispatch` only; `runs-on: ubuntu-24.04`; `permissions: contents: read`; timeout <= 20 minutes; `concurrency` with no overlapping probe runs; install only explicit OpenVPN/netns/firewall dependencies; no Cloudflare secrets or deployment steps. The workflow must not run on push/PR/schedule at this Stage.

- [ ] **Step 1: Failing tests**: workflowは`workflow_dispatch`**のみ**、`ubuntu-24.04`、`permissions: contents: read`、Cloudflare Secret/Worker deploy/本番KV write/アップロードArtifactなし、CLIは`--scan-window 40 --limit 10 --timeout-seconds 60`とredacted allowlist JSONだけ、`IPAPI_IS_API_KEY`は特権OpenVPN subprocessに継承させない。`push`, `pull_request`, `schedule`は不在。
- [ ] **Step 2: Run** `python3 -m unittest discover -s tests -v` to see failing workflow contract test.
- [ ] **Step 3: Implement** bounded candidate count, `IPAPI_IS_API_KEY` secret handling, manual workflow and redacted summary. Avoid explicit `run: curl` that could leak API credentials in the job log.
- [ ] **Step 4: Re-run** all unit tests; expected PASS. Check workflow syntax separately if validation tooling is available.
- [ ] **Step 5: Local commit** only after separate implementation authorization。feature Pushも別承認。**Workflowをmasterへ反映する承認と初回dispatchする承認も各別**。default branchにWorkflowがない状態ではdispatch不可。

### Task 4: One-time live verification and Owner checkpoint (NOT AUTOMATIC)

**Prerequisites:** Tasks 1–3 verified; feature branch上の実装/Commit/Pushを個別に承認; `.github/workflows/probe-tokyo-vpn.yml`を**default branch `master`へ反映済み**（独立Owner承認）; **初回`workflow_dispatch`に別途Owner承認済み**; API keyはOwnerがGitHub Secretへ登録しチャットに貼らない。未承認ならTask 4=`HOLD`。

- [ ] **Step 1:** **別途dispatch承認がある場合のみ**、default branchから1回手動起動。探索窓40件、実接続最大10件、各60秒、workflow合計20分以内。自動Cron/production KV writeなし。
- [ ] **Step 2:** Redacted logsでF-003のAND証拠を判定：Namespace・nft/NAT許可/拒否、pre-tunnel Echo拒否、TLS接続、tun0 IPv4、Echo/32 route dev tun0、interface-bound HTTPS/TLS、globally routable出口IPv4、出口GeoIP東京、完全Cleanup。Witnessは固定2台以外。Host direct route Echoは無効証拠。
- [ ] **Step 3:** Report one of `PASS`, `NOT_VERIFIED`, `BLOCKED`, `FAIL` with evidence; do not turn “no server found” into an observed tooling failure.
- [ ] **Step 4:** **Stop.** Ask the Owner whether to authorize Stage 2. No new review, implementation, write, or deployment may auto-start.

## Success / Stop / Remaining Risk

- **PASS:** GitHub-hosted standard Ubuntu runner establishes a safely isolated, verified OpenVPN tunnel to a new VPN Gate remote, proves an observed exit IPv4, and ipapi.is keyed API returns Tokyo for that exit; no Cloudflare state altered.
- **NOT_VERIFIED:** no reachable/compatible non-baseline Tokyo witness within bounded candidates, or service was unavailable. No claim that the architecture is impossible.
- **BLOCKED:** runner lacks required TUN/netns/network capability, or safe confinement cannot be established. No weaker fallback.
- **FAIL:** observed unsafe route escape, logging of private material, acceptance of non-Tokyo/unverified exit, or other violated safety property.
- **Residual risks after PASS:** Tokyo GeoIP can drift; endpoints can expire; differing TLS identities may prevent multi-endpoint merge; iOS automatic Remote Profile reloading and kill-switch behavior remain unverified; Actions schedules may be delayed/dropped.

## Deferred Stage 2–4 (not in this plan)

- **Stage 2:** dynamic approved-identity policy, bounded candidate pool and signed/validated handoff to publisher. Requires Stage 1 evidence and new Owner scope approval.
- **Stage 3:** Worker/KV publish, replace fixed `APPROVED_REMOTES` and fixed approval assumptions without relaxing integrity policy, prevent stale or malicious profile publication, reconcile 2-hour current TTL with proposed 2-hour schedule/6-hour cache horizon. Separate authorization required for Cloudflare writes.
- **Stage 4:** sing-box MT Remote Profile activation, automatic reconnect, Tokyo validation and leak test in iOS; no automatic claim of complete kill switch.

## Owner Decision

Review and approve only the **Stage 1 plan scope**. No implementation, commit, push, Actions dispatch, Cloudflare mutation, next stage or independent reviewer is authorized by this document alone. Prefer an inline/native implementation session and one checkpoint over repetitive review rounds.
