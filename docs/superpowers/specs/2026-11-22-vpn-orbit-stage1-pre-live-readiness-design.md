# VPN-ORBIT — Stage 1 Pre-Live Readiness Design R0.1.5

**Status:** LIMITED_DOCUMENT_REMEDIATION / OWNER_ADOPTION_OF_R0.1.5_PENDING  
**Prior adoption:** Human Owner approved Design R0.1; RG-VOR-010-001〜005 remain RESOLVED; R0.1.5 addresses the four inline documentation findings; OwnerApproval, fixed CLI lock scope, DROP and Cleanup FAIL precedence remain unchanged  
**Repository:** `yohi/vpn-orbit`  
**Reviewed HEAD:** `d23536a396f2d8098e7e6bd4d5f06a3e9657d238`  
**Baseline:** `master@7f1ae8cab84a94cea8369e8075b4982b652f1557`  
**Related:** [Issue #9](https://github.com/yohi/vpn-orbit/issues/9) / [PR #10](https://github.com/yohi/vpn-orbit/pull/10) / PR #8 (merged)  
**Selected Approach:** A — master限定補強（変更なし）

## 1. Goal

Stage 1の固定候補実通信を、安全かつ再現可能に実施するための機能を完成させ、Human Ownerの新規承認を待つ状態にする。

本設計の完成は東京出口IPv4の実証成功を意味しない。目標状態は `READY_FOR_LIVE_APPROVAL` であり、新たな実通信許可ではない。

### Deliverables

1. 最新masterを基準にした必要最小限の安全検証補強
2. 固定候補IDによる1候補実行機能
3. 実行結果・中断状態・Cleanup証拠の記録
4. オフラインテストと回帰テストの結果
5. KVM実機検証用の最小Runbook

## 2. Approaches

**A. master限定補強 — 採択済み。** 現行のProbeRunner、Supervisor、Isolation、Cleanupを維持し、不足している境界だけ実装する。KVMパッチは参考資料として使用し、機械的移植は行わない。

**B. KVMパッチ3本を移植 — 不採択。** masterの変更と衝突する可能性があり、不要な差分の混入を避ける。

## 3. Architecture

既存の `vpn_orbit.cloud_probe` による通常候補探索は維持する。固定候補検証には `vpn_orbit.stage1_fixed_probe` CLIを追加し、既存 `probe_one()` を1件だけ呼ぶ。Supervisor／Namespace／Cleanupの基本構造は変更しない。

```text
Stage 1 Fixed CLI
  +-- --list: Catalog取得・候補ID表示（OpenVPNを起動しない）
  +-- --probe-id: 固定ID照合
        +-- Safety/Owner gate: Issue #9 legacy HOLD + 新規の明示Owner承認
        +-- AttemptJournal.inspect() / reserve()（固定候補CLI経由の全candidate IDで排他）
        +-- mark_running()（OpenVPN呼出前に永続化）
        +-- probe_one() [既存実装]
             +-- Supervisor / Namespace / OpenVPN / TUN
             +-- nftables DROP証拠 / TUN HTTPS / GeoIP
             +-- Cleanup（既存のFAIL優先）
        +-- complete() → ロック解放 → 固定スキーマJSON / CLI終了
```

## 4. Fixed Candidate Contract

- `python3 -m vpn_orbit.stage1_fixed_probe --list`
- `python3 -m vpn_orbit.stage1_fixed_probe --probe-id <ID>`

両モードは排他的。固定候補IDはBase64デコード直後の**元OpenVPNプロファイルのバイト列**を使う。既存のBOMなしUTF-8プロファイルのIDは従来と同一だが、先頭UTF-8 BOM (`EF BB BF`) の追加・削除は別IDとなる。

```python
sha256(
    f"{ip}:{port}/{protocol}\n".encode("ascii")
    + profile_raw_bytes  # Base64 decode後の無変更バイト列
).hexdigest()
```

**取得・互換性:** 既存 `vpn_orbit.phase1.parse_catalog()` は `raw = base64.b64decode(encoded, validate=True)` 後に `raw.decode("utf-8-sig")` するため、現在の `Candidate.profile: str` だけではBOMを復元できない。将来の別途承認済み実装では `Candidate` に省略可能な末尾フィールド `profile_raw_bytes: bytes | None = None` を追加し、`parse_catalog()` で元 `raw` を保持する。`Candidate.profile` と既存 `convert_ovpn()`、`screen_candidates()` の解析・選別・並び順は変更しない。`ScreenedCandidate.candidate` が元バイト列をそのまま固定CLIへ渡す。既存サイズ上限とUTF-8妥当性検査も維持する。

`candidate_id(candidate: ScreenedCandidate) -> str` は `profile_raw_bytes` が存在し、`raw.decode("utf-8-sig") == candidate.candidate.profile` を確認できた場合のみ元バイト列をハッシュする。バイト列欠落・不整合なら `BLOCKED / NOT_STARTED / candidate_identity_unavailable`、OpenVPN呼出0回。`profile.encode("utf-8")` への黙示フォールバックは禁止。元の生バイト列をJournal・JSON・生ログに保存しない。

**旧ID:** BOMなしの既存IDは維持する。BOMありプロファイルで旧方式の正規化後IDは**別名として受け入れない**。新 `--list` は元バイト列検証済み候補のIDだけを表示し、旧ID不一致は `NOT_VERIFIED / NOT_STARTED / candidate_not_found`。Issue #9の旧IDは履歴として保持し、LEGACY_RESULT_UNKNOWNやOwnerApprovalは自動解除・流用しない。Ownerの新規単発承認は現行candidate IDとHEADに完全一致させる。

`--probe-id` はCatalogを再取得し、元バイト列のある候補を既存のStage 1選別条件に従って指定IDと完全照合する。元プロファイルが1byteでも変われば別IDであり、旧IDで起動しない。ID不一致・候補消失・プロファイル変更なら `NOT_VERIFIED`、OpenVPN起動禁止。重複ID・識別不整合なら `BLOCKED`。別候補への切替／フォールバックは禁止。

固定候補モードではTCP事前疎通確認を行わない。既存 `screen_candidates()` に `existing_pins=frozenset(), scan_window=40, limit=10, reachable=None` を明示的に渡し、内部の固定IP除外条件を維持する。Catalog／GeoIP照会と隔離下のVPN実通信を区別する。

## 5. DROP Evidence Contract — RG-VOR-010-004

既存`route_get_via_tun0()` はecho IPv4の `/32` routeを `tun0` に設定した後に、`host_direct_route_rejected()` を呼ぶ。したがって `curl --interface if!<veth_ns>` の拒否・タイムアウトだけでは、veth送信パケットが専用DROPルールに到達した証拠にならない。実カーネルでの成立は未実証であり、Mock PASSを実測証拠としない。

**計測パケットと経路の限定契約（既存Runner内、後続のOwner承認付き実通信時のみ）:**

1. 対象echo IPv4を既存のグローバルIPv4検証値に固定し、事前に `tun0` の当該 `/32` routeが存在することを確認・記録する。別の宛先、デフォルトルート、VPNサーバーへのルートには触れない。
2. **経路変更より先に** Namespaceの既存 `inet <resources.table> output` へ、`oifname <veth_ns> ip daddr <echo_ip> tcp dport 443 counter drop` の専用ルールを追加する。同一テーブル内のルール識別子・パケットカウンターを取得し、条件が厳密に一致することを確認できなければパケット送出禁止。既存のデフォルトDROP、VPNサーバー宛許可、TUN HTTPS許可、ホスト側の限定forward/NATを変更しない。
3. ルール確認後に限り、Namespaceの**当該echo IPv4の `/32` routeのみ**を一時的に `via 10.253.240.1 dev <veth_ns>` へ切り替える。通常の `ip -4 route get <echo_ip>` の結果と限定 `/32` routeを確認し、veth・想定gatewayへの経路が成立しなければ送出禁止。`ip route get ... oif` 単独の成功は経路成立の根拠にしない。
4. この状態でのみ、既存のタイムアウト付きcurl（HTTPS、`--noproxy '*'`、`--resolve api.ipify.org:443:<echo_ip>`、`--interface if!<veth_ns>`、TCP/443、単発）を**遮断計測パケット**として送出する。curl終了コード7/28に加え、**同一の専用DROPルールのパケットカウンターが送出前後で厳密に増加**したことを確認する。curlの拒否だけ、あるいは `ip route get` だけではPASSとしない。
5. **成功・失敗・例外・タイムアウトのすべてで `finally` に復旧を試みる。** まず一時veth向け `/32` を元の `tun0` 向け `/32` routeへ復元し、通常のroute getとroute一覧で `dev tun0`、元の経路属性、veth向け一時 `/32` の不在を確認する。**復元を確認してから**専用DROPルールを識別子で撤去し、その不在を確認する。ルールは復元前に撤去しない。復旧できなければ、制限的なDROPを保持して後続の既存Supervisor/Namespace Cleanupに委ね、成功扱いせず停止する。ホストデフォルトルート不変と既存CleanupのFAIL優先も維持する。
6. 上記の送出・カウンター・経路復元・専用ルール撤去の**全条件が確認できた場合のみ**、Runnerは `(True, "direct_drop_counter_verified")` を返し、`_verify_routes()` は固定成功マーカーを採用する。復元未確認のままTUN HTTPSへ進まない。

**FAIL正規化:** Runnerは、ルール作成・取得/解析・同一性確認・カウンター不増加・curl拒否不成立・一時経路切替/確認・tun0経路復元/確認・専用ルール撤去/確認の失敗を `(False, <固定コード>)` にする。`_verify_routes()` はFalse、予期しないTrue/detail、またはDROP検証呼出しからの `Exception`（`TimeoutError`等）を最終 `ProbeStatus.FAIL` に正規化し、既存 `probe_one()` の一般例外 `NOT_VERIFIED` 経路へ逃がさない。`BaseException` は握り潰さない。既存Cleanup失敗は `FAIL / cleanup_failed:*` を最優先とする。

固定失敗コード: `drop_curl_not_refused`、`drop_counter_unavailable`、`drop_counter_invalid`、`drop_counter_not_advanced`、`drop_route_unavailable`、`drop_route_restore_failed`、`drop_rule_cleanup_failed`、`drop_evidence_unavailable`。どの失敗でも最終FAILとし、`direct_drop_counter_verified` を付与しない。生のコマンド出力、nftables JSON、OpenVPNログ、秘密情報をreason/evidenceへ流さない。TLS/DNS/IPv6・許可宛先の既存制限を緩和しない。

## 6. Attempt Journal Contract — RG-VOR-010-001/002

### 6.1 Legacy HOLD：Journal導入前のRESULT_UNKNOWN

[Issue #9](https://github.com/yohi/vpn-orbit/issues/9) には、旧固定候補 `106.161.34.210:1998/tcp`、候補ID `00aaf9a56bb43fbeea8b02e19cf98e620fc69f079bc4ab93b3e3d62cdb8fb5d8` の**以前の起動試行があった可能性があり、結果未回収**と記録されている。新Journal導入前の試行はJournalから自動発見できない。

この既知未回収試行を `LEGACY_RESULT_UNKNOWN` とし、**空Journal／履歴なし／新規インストールでも `--probe-id` 実行を `BLOCKED / legacy_unknown_owner_decision_required` にする。** `--list` はOpenVPNを起動しないため利用可能。旧候補以外への切替でもIssue #9のHOLDを暗黙には解除しない。

新しい実行を認める条件は、Human Ownerが**Issue #9の未知状態を認識した上で、新たな1試行について別途明示承認した**ことを示す、制限アクセスの `OwnerApproval` レコードだけとする。これは過去の試行をPASS/FAILへ書き換える操作ではなく、新しい単発試行の権限付与である。自動承認・`--force`・`--retry`・候補変更による回避は禁止。記録には `approval_id`, `issue_ref="yohi/vpn-orbit#9"`, `legacy_disposition="ACKNOWLEDGED_RESULT_UNKNOWN"`, `candidate_id`, `approved_head`, `scope="ONE_NEW_ATTEMPT"`, `approved_at` を必須とする。レコードはroot所有0600の既定パスに置き、RunbookにOwnerによる確認・作成・提示の手順を記載する。AIはOwnerの承認を推測・代理生成しない。承認IDは使い捨てとし、Journalで原子的に使用済みを記録する。**実行可能性は空Journalではなく、既存HOLDの認識＋当該試行への明示承認＋Journalの原子的検査によってのみ確定する。**

### 6.2 固定候補CLI経由の全candidate IDの排他、公開契約と状態遷移

状態ディレクトリはゲスト内の `/var/lib/vpn-orbit/stage1-attempts`（root所有0700、ファイル0600）とし、Gitリポジトリ外に置く。`fcntl.flock` は**新設の `vpn_orbit.stage1_fixed_probe --probe-id` を経由する全candidate IDで共通の1個のロック**を使用する。固定候補CLIから異なるcandidate IDを同時指定しても2件目はCLI応答 `status=BLOCKED / recovery_state=NOT_STARTED / reason_codes=["preflight_blocked"]` とし、Design §7.3のロック取得不可の行に一致させる。予約前の拒否なので `attempt_id=null`、`exit_code=null`、`probe_one()` 未呼出とする。これは**固定候補CLI内だけの技術的排他保証**であり、既存の `vpn_orbit.cloud_probe` はAttemptJournalを通らず `probe_candidates()` を実行するため、このロックによる排他対象外である。**既存CLIを含むStage 1全体の排他保証は主張しない。** 今回のOwner承認は既存CLIでの追加実通信を許可しない。所有者不正・symlink・書込み不可・ロック取得不可なら固定候補CLIは起動前にBLOCKED。

公開契約は、`inspect() -> JournalSnapshot`（状態の読み取り、`legacy_hold` と未確定試行の有無）、`reserve(*, candidate_id, ingress, head, approval: OwnerApproval) -> AttemptHandle`、`mark_running(handle) -> None`、`complete(handle, *, result: JournalResult) -> None`、`AttemptHandle.__enter__/__exit__`（ロック保持・解放）とする。`inspect()` は参考情報であり、**`reserve()` がロック下で既存HOLD・既存未確定試行・承認IDの未使用・承認スコープ・候補/HEADを再検査**し、予約を永続化する。Task 4はこの公開契約以外に状態ファイルの内部構造へ依存しない。

```text
（未予約） -- reserve() / 承認IDを一回消費 --> RESERVED
RESERVED -- mark_running() を永続化 --> RUNNING
RUNNING  -- complete() を永続化 --> COMPLETED
RESERVED/RUNNING -- crash・停止・保存失敗 --> RESULT_UNKNOWN（回収時に判定）
COMPLETED -- 次の試行 --> 自動遷移しない。新規OwnerApprovalが必要
```

`AttemptHandle` は `reserve()` 取得時から `complete()` 終了または異常終了までロックを保持し、`finally`／context managerで解放する。プロセス死亡ならOSがロックを解放するが、**予約レコードは消えず `RESULT_UNKNOWN` を保持**する。未確定レコードを自動修復・削除しない。未確定状態は、同じ候補だけでなく**固定候補CLI経由の全candidate IDへの新規実行をブロック**する。既存CLIはこの自動HOLDを技術的には参照しないため、Runbookではその実行禁止・事前不存在確認・Owner承認境界を明示する。事前確認は既存CLIとの競合が絶対に起こらない証明ではない。Ownerが別途停止と扱いを判断するまで再試行禁止。

記録の永続化は原子的更新と必要な `fsync` を伴う。`mark_running()` 失敗なら `probe_one()` を呼ばない。`complete()` 失敗時は回収状態 `RESULT_UNKNOWN` とし、たとえProbeResultがPASSでもCLIは正常終了しない。Cleanup優先は既存 `probe_one()` の責務として維持する。

記録項目: attempt_id、candidate_id、ingress IP/port/protocol、Git HEAD、approval_id、開始/終了時刻、phase、ProbeStatus、固定reason_code、CLI終了コード、Cleanup status、TUN/DROP/HTTPS/GeoIP段階証拠。APIキー、OpenVPNプロファイル本文・生ログ、認証情報、秘密鍵、トークンを保存しない。

## 7. Result Contract — RG-VOR-010-003/006

既存 `ProbeStatus` は `PASS / NOT_VERIFIED / BLOCKED / FAIL` のまま。`RESULT_UNKNOWN` はJournal回収状態であり、ProbeStatusではない。

### 7.1 終了コードと保存形式

`JournalResult.exit_code: int | None` とJSON `exit_code: int | null` は、**当該固定候補CLIが返す予定の終了コード**を表す。OpenVPN子プロセスのexit codeではなく、OSが実際にCLIプロセス終了を観測した証拠でもない。`COMPLETED` に永続化した上でCLIが戻る際に0（`ProbeResult.status == PASS` かつCleanup confirmed）または1（それ以外）を返す。`RESERVED`、`RUNNING`、`RESULT_UNKNOWN`、保存失敗による未確定では `exit_code=null`。未取得コードを0に補完しない。実際のシェル終了コード回収は実機Runbookの別確認であり、このフィールドの意味を変更しない。

`JournalResult` は `status: ProbeStatus | None`, `recovery_state: Literal["FINALIZED", "RESULT_UNKNOWN"]`, `reason_codes: tuple[str, ...]`, `exit_code: int | None`, `phase: str`, `cleanup_status: str`, `tun_evidence/drop_evidence/tunnel_https_evidence/tokyo_geoip_evidence: EvidenceState` を持つ不変・検証済みの最小型。`EvidenceState` は `VERIFIED`, `FAILED`, `NOT_OBSERVED` のいずれか。

### 7.2 ProbeResult → Journal/JSON投影規則

既存 `ProbeResult` (`status`, `reason_code`, `evidence`, `phase`, `exit_ip`, `cleanup_status`) から以下に従い投影する。生ログ・例外本文を使わず固定マーカーのみを解釈し、`tunnel_https_verified` はHTTPS成功確認直後の固定マーカーとして追加する。

**Cleanup前の失敗帰属:** 将来の実装では `probe_one()` の `finally` 内で `cleanup()` を呼ぶ**直前**に、失敗・未検証の確定済み `state.phase` と `reason` を固定allowlistで照合し、`pre_cleanup_failure:<fixed_phase>:<fixed_reason>` を `state.evidence` に保存する。許可済みphase/reasonの組合せ以外は `stage_failure_unclassified` として扱い、失敗した段階や証拠を推測しない。Cleanup前PASSなら失敗マーカーは付けない。既存の `ProbeResult` スキーマを変更せず、成功マーカーと共存させる。

Cleanupが失敗しても最終 `ProbeResult.status=FAIL`、`reason_code=cleanup_failed:*`、`phase=cleanup`、`cleanup_status=failed` の優先順位を維持する。一方、**Journal/CLIへ投影する段階別証拠とJournal `phase` は、保存済み失敗マーカーの固定phase/reasonを優先**し、Cleanupで上書きされた `reason_code`・`final_phase` から逆算しない。失敗マーカーがない場合のみ許可済み `ProbeResult.phase` を採用する。Cleanup単独失敗では架空のステージ失敗を生成しない。

| Field | VERIFIEDの根拠 | FAILEDの根拠 | その他・未観測 |
|---|---|---|---|
| `tun_evidence` | `tls_tun_established:` マーカー（既存 `wait_for_tun()` 成功後、IPv4形式確認済み） | `pre_cleanup_failure:tun_wait:tun_not_established` / `pre_cleanup_failure:tun_wait:tun_ip_invalid` | `NOT_OBSERVED` |
| `drop_evidence` | 固定マーカー `direct_drop_counter_verified`（curl拒否・専用DROPカウンター増加・経路復元確認済み） | 許可済み `pre_cleanup_failure:route_verification:drop_*` または同phaseの固定 `host_direct_echo_route:*` | `NOT_OBSERVED` |
| `tunnel_https_evidence` | 固定マーカー `tunnel_https_verified`（TLS検証付きHTTPS応答200とグローバルIPv4本文が妥当） | `pre_cleanup_failure:tunnel_echo:exit_ip_fetch_failed` / `pre_cleanup_failure:tunnel_echo:exit_ip_body_not_global_ipv4` | `NOT_OBSERVED` |
| `tokyo_geoip_evidence` | Cleanup前に `exit_ip_tokyo_verified` を確認し、既存PASS条件を満たす | `pre_cleanup_failure:exit_geoip:exit_ip_non_tokyo` | `NOT_OBSERVED`（GeoIP照会不能等） |

`cleanup_status` は既存の値のみを採用し、`failed` は必ず最終FAIL。段階別証拠はCleanup前の許可済みマーカーに帰属させ、未到達の後続証拠はFAILEDにせずNOT_OBSERVEDとする。許可されないphase/reasonや `stage_failure_unclassified` から失敗を推測しない。`ProbeResult`に存在しないOpenVPNプロセスexit codeは取得元に使わず、`reason_codes` は最終Cleanup失敗優先・固定allowlistのみで生成する。

JournalとCLIのJSONは `attempt_id` で照合できる（予約前のCLI拒否では `attempt_id=null`）。**予約済み**の結果が回収不能な場合に限り、その未確定レコードを `RESULT_UNKNOWN` として扱う。JSONへの投影失敗、Journal確定失敗はPASS出力禁止。

### 7.3 固定候補CLI応答とJournal回収状態 — RG-VOR-010-006

この対応表は `--probe-id` の**今回のCLI応答JSON**にのみ適用する。`--list` は候補一覧専用であり、試行済みを表すJSONではない。CLI応答型 `CliProbeOutcome` は `status: Literal["PASS", "NOT_VERIFIED", "BLOCKED", "FAIL"] | None`、`recovery_state: Literal["NOT_STARTED", "FINALIZED", "RESULT_UNKNOWN"]`、`reason_codes: list[str]` を持つ。`NOT_STARTED` は**CLI応答専用**で、既存の `JournalResult.recovery_state: Literal["FINALIZED", "RESULT_UNKNOWN"]` および `ProbeStatus` は変更しない。

| 今回の `--probe-id` の状況 | CLI `status` | CLI `recovery_state` | CLI `reason_codes`（固定コード） |
|---|---|---|---|
| Issue #9の既存HOLD、OwnerApproval欠落・不一致・使用済み、空Journalでも承認なし | `BLOCKED` | `NOT_STARTED` | `legacy_unknown_owner_decision_required`（旧試行のHOLD時）、それ以外は `preflight_blocked` |
| CLI引数不正、権限不正、既存の未確定予約、ロック取得不可、Journal予約前の他の安全拒否 | `BLOCKED` | `NOT_STARTED` | `preflight_blocked` |
| 固定候補IDが現行候補一覧に存在しない（変更・消失を含む） | `NOT_VERIFIED` | `NOT_STARTED` | `candidate_not_found` |
| 予約後、`mark_running()`が永続化できず、`probe_one()`を**一度も呼んでいないことが確実** | `BLOCKED` | `NOT_STARTED` | `probe_start_blocked` |
| `probe_one()`呼出後、結果を回収できない（起動有無が不確実な中断を含む） | `null` | `RESULT_UNKNOWN` | `attempt_result_unavailable` |
| `probe_one()`後、Journalの `complete()` に失敗して最終結果を永続化できない | `null` | `RESULT_UNKNOWN` | `journal_finalization_failed` |
| Probe結果を回収し、Journalの `COMPLETED` 永続化にも成功 | `ProbeResult.status.value` | `FINALIZED` | 検証済み `ProbeResult.reason_code` をallowlistから投影 |

- **試行の帰属:** `LEGACY_RESULT_UNKNOWN` はIssue #9で記録された過去の可能性のある試行のみを指す。現在の新規試行の `recovery_state` には使用しない。旧HOLDを検出して今回のCLIが停止した場合、今回の状態は常に `NOT_STARTED`。過去の試行を新Journalに成功・失敗・今回実行済みとして遡及登録しない。
- **開始判定:** `NOT_STARTED` は、今回 `probe_one()` が未呼出であると確実に断定できる場合に限る。`mark_running()` 永続化後のクラッシュ等、呼出の有無を確証できない場合は保守的に `RESULT_UNKNOWN` として新規実行を止める。予約済みレコードが未確定なら、CLIが `NOT_STARTED` を返した場合もJournalの全候補HOLDを解除しない。
- **未開始・未回収の値:** 予約前の拒否は `attempt_id=null`、予約後に未開始と確認できる場合は当該 `AttemptHandle.attempt_id`。いずれも `exit_code=null`、`phase="not_started"`、証拠4項目は `NOT_OBSERVED`、Probe未実行につき `cleanup_status="not_required"`（ProbeのCleanupが実行されたという主張ではない）。`RESULT_UNKNOWN` でも `exit_code=null` とし、観測済みの安全な固定コード以外を推測で追加しない。
- **終了値:** `FINALIZED` の場合だけ、既存§7.1の条件に従い `exit_code=0|1`（当該CLIの**予定**終了コード）を付ける。事前拒否時にOSが返す非0のシェル終了コードとは別の意味であり、その値をJSON `exit_code` に転用しない。
- **安全性:** 上表の `reason_codes` は固定allowlistのみ使用し、生ログ・例外本文・OpenVPNプロファイルを出力しない。Journal確定失敗や帰属不明時に `PASS`、`FINALIZED` または新しい試行の成功・失敗を作り出さない。既存のCleanup FAIL優先、Issue #9の既定HOLD、**固定候補CLI経由の全candidate IDに対する排他**を維持する。既存 `cloud_probe` との技術的相互排他は保証しない。

## 8. Scope Boundaries

### 変更を許容する範囲（**別途**実装承認後のみ）

- `vpn_orbit/live_runner.py`
- `vpn_orbit/openvpn_probe.py`
- `vpn_orbit/phase1.py`（元Profileバイト保持のみ）
- `vpn_orbit/isolation.py`
- `vpn_orbit/runner_types.py`（必要な契約変更のみ）
- 固定候補CLI・Journal用の小さな新規モジュール
- 対応するオフラインテスト
- 実機検証用Runbook

変更ファイルは最小化する。変更しない範囲：VPN Gate CSV Phase 1の既存解析・選別挙動（元バイト列保持のみ例外）、既存通常候補探索CLI、Supervisorの資格情報隔離、Cleanup優先順位、iOS/sing-box連携、GitHub Actionsの自動実通信設定。OpenVPN認証原因の追加診断は本スコープ外。

## 9. Offline Acceptance

実装はSuperpowers TDDで行う。固定ID一致/不一致/候補変更、最大1候補、認証情報欠落、固定候補CLI経由の全candidate IDに対する排他（競合時 `BLOCKED / NOT_STARTED / preflight_blocked`）、Issue #9 legacy HOLD、空Journalからの実行禁止、OwnerApproval1回消費、未確定予約、異常終了、書込み不能、DROP例外の最終FAIL、ProbeResultの固定コード投影、Cleanup失敗優先、秘密情報非露出、既存回帰を必須テストとする。

MockテストPASSは実LinuxカーネルのDROP証拠や東京出口IPv4の実証を意味しない。

## 10. Pre-Live Completion Gate

承認範囲での実装完了、オフラインTDD／回帰PASS、失敗系PASS、固定候補・Journal・Cleanup契約のオフライン整合、Preflight／**Issue #9 legacy HOLD・Owner判断**／実行／証拠回収／Cleanupを記載したRunbook、対象Commit・残余リスク報告が揃ったら `READY_FOR_LIVE_APPROVAL` とする。Human Owner Checkpointで停止。これは実通信・運用開始の承認ではない。

## 11. Stop Conditions — RG-VOR-010-001

以下で実行禁止：HEAD/環境不一致、不明なNamespace/OpenVPN残存、候補同一性不明、秘密情報取扱不明、Journalの作成・排他・確定不良、**空Journalを根拠とした起動許可**、**Issue #9のLEGACY_RESULT_UNKNOWNへの新規Owner判断欠如**、承認IDの再利用・承認候補/HEAD不一致、他候補の活動中／結果不明試行、DROP証拠不備、Cleanup異常。

Runbookは実機検証前にIssue #9の既知結果不明試行を確認し、**新たな単発実行についてHuman Ownerの明示承認を確認・記録**する。未承認の旧試行を自動再実行しない。追加のレビュー・実行・訂正ループは自動開始しない。

## 12. Authority

- Design R0.1: **APPROVED**（方式Aを維持）
- Design R0.1.5: **PENDING_OWNER_ADOPTION**（inline指摘4件の文書限定訂正版）
- Implementation Plan R0.1.5: **PENDING_OWNER_ADOPTION**
- Implementation Authorization: **HOLD**
- Source Code Modification / Test Execution: **HOLD**
- GitHub Commit / Push / PR Update / Merge: **HOLD**
- Live Execution (KVM / GitHub Actions): **HOLD**

今回のOwner承認は文書2件のCommit/Pushのみ。実装、テスト、実通信、Merge、後続Taskは未承認のまま。
