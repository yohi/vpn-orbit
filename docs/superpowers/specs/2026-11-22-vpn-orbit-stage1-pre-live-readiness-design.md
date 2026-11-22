# VPN-ORBIT — Stage 1 Pre-Live Readiness Design R0.1.1

**Status:** LIMITED_DOCUMENT_REMEDIATION / OWNER_ADOPTION_OF_R0.1.1_PENDING  
**Prior adoption:** Human Owner approved Design R0.1; this revision only addresses RG-VOR-010-001〜005  
**Repository:** `yohi/vpn-orbit`  
**Reviewed HEAD:** `fb81579e32f0c7ba0da90853123c449bf0fb442e`  
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
        +-- AttemptJournal.inspect() / reserve()（Stage 1全体の排他）
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

両モードは排他的。候補IDは既存補助スクリプトとの互換性を維持する。

```python
sha256(
    f"{ip}:{port}/{protocol}\n".encode("ascii")
    + profile.encode("utf-8")
).hexdigest()
```

`--probe-id` はCatalogを再取得し、既存のStage 1選別条件に従い指定IDを完全照合する。ID不一致・候補消失・プロファイル変更なら `NOT_VERIFIED`、OpenVPN起動禁止。重複ID・識別不整合なら `BLOCKED`。別候補への切替／フォールバックは禁止。

固定候補モードではTCP事前疎通確認を行わない。既存 `screen_candidates()` に `existing_pins=frozenset(), scan_window=40, limit=10, reachable=None` を明示的に渡し、内部の固定IP除外条件を維持する。Catalog／GeoIP照会と隔離下のVPN実通信を区別する。

## 5. DROP Evidence Contract — RG-VOR-010-004

既存の `host_direct_route_rejected()` を限定補強する。遮断成功は、**vethへ固定したHTTPS通信のcurl終了コード7/28** と、**同じ専用nftables `counter drop` ルールのパケットカウンターが試行前後で増加**したことの両方で確認する。

専用ルールはNamespace内 `output` に置き、指定echo IPv4・TCP/443・対象vethのみに限定する。同じルールを識別子で前後照合する。`ip route get ... oif` は情報として記録するだけでPASS判定に使わない。成功時のみRunnerは `(True, "direct_drop_counter_verified")` を返す。これ以外のTrue/detail組合せは `_verify_routes()` がFAILへ正規化し、`ProbeResult.evidence` に `direct_drop_counter_verified` を付与しない。

**責務境界:** Runnerは、nftables取得失敗・解析失敗・識別子不一致・カウンター不増加・curl拒否不成立を `(False, <固定コード>)` に正規化する。`_verify_routes()` はRunnerからのFalse、**またはDROP検証呼出しからの `Exception`**（`TimeoutError`、デコード不良、想定外のRuntimeError等）を `ProbeStatus.FAIL` / `drop_evidence_unavailable` に変換する。`BaseException` は握り潰さない。既存 `probe_one()` の一般例外 `NOT_VERIFIED` 経路へDROP検証の例外を逃がさない。

使用する固定失敗コードは `drop_curl_not_refused`、`drop_counter_unavailable`、`drop_counter_invalid`、`drop_counter_not_advanced`、`drop_evidence_unavailable`。**どのケースも最終 `ProbeResult.status == FAIL`**。Cleanup失敗が発生した場合は従来どおり `FAIL / cleanup_failed:*` を優先する。秘密情報、生のコマンド出力、nftables JSON、OpenVPNログを理由コードに含めない。

VPNサーバーへの許可、TUN経由HTTPS、DNS/IPv6遮断、TLS検証は緩和しない。`direct_drop_counter_verified` が無い場合、東京出口IPv4のPASSを確定しない。

## 6. Attempt Journal Contract — RG-VOR-010-001/002

### 6.1 Legacy HOLD：Journal導入前のRESULT_UNKNOWN

[Issue #9](https://github.com/yohi/vpn-orbit/issues/9) には、旧固定候補 `106.161.34.210:1998/tcp`、候補ID `00aaf9a56bb43fbeea8b02e19cf98e620fc69f079bc4ab93b3e3d62cdb8fb5d8` の**以前の起動試行があった可能性があり、結果未回収**と記録されている。新Journal導入前の試行はJournalから自動発見できない。

この既知未回収試行を `LEGACY_RESULT_UNKNOWN` とし、**空Journal／履歴なし／新規インストールでも `--probe-id` 実行を `BLOCKED / legacy_unknown_owner_decision_required` にする。** `--list` はOpenVPNを起動しないため利用可能。旧候補以外への切替でもIssue #9のHOLDを暗黙には解除しない。

新しい実行を認める条件は、Human Ownerが**Issue #9の未知状態を認識した上で、新たな1試行について別途明示承認した**ことを示す、制限アクセスの `OwnerApproval` レコードだけとする。これは過去の試行をPASS/FAILへ書き換える操作ではなく、新しい単発試行の権限付与である。自動承認・`--force`・`--retry`・候補変更による回避は禁止。記録には `approval_id`, `issue_ref="yohi/vpn-orbit#9"`, `legacy_disposition="ACKNOWLEDGED_RESULT_UNKNOWN"`, `candidate_id`, `approved_head`, `scope="ONE_NEW_ATTEMPT"`, `approved_at` を必須とする。レコードはroot所有0600の既定パスに置き、RunbookにOwnerによる確認・作成・提示の手順を記載する。AIはOwnerの承認を推測・代理生成しない。承認IDは使い捨てとし、Journalで原子的に使用済みを記録する。**実行可能性は空Journalではなく、既存HOLDの認識＋当該試行への明示承認＋Journalの原子的検査によってのみ確定する。**

### 6.2 全Stage 1の排他、公開契約と状態遷移

状態ディレクトリはゲスト内の `/var/lib/vpn-orbit/stage1-attempts`（root所有0700、ファイル0600）とし、Gitリポジトリ外に置く。`fcntl.flock` は**候補IDに関係なくStage 1全体で1個のグローバルロック**を使用する。異なる候補IDを同時指定しても2件目は `BLOCKED / stage1_already_active`。所有者不正・symlink・書込み不可・ロック取得不可なら起動前にBLOCKED。

公開契約は、`inspect() -> JournalSnapshot`（状態の読み取り、`legacy_hold` と未確定試行の有無）、`reserve(*, candidate_id, ingress, head, approval: OwnerApproval) -> AttemptHandle`、`mark_running(handle) -> None`、`complete(handle, *, result: JournalResult) -> None`、`AttemptHandle.__enter__/__exit__`（ロック保持・解放）とする。`inspect()` は参考情報であり、**`reserve()` がロック下で既存HOLD・既存未確定試行・承認IDの未使用・承認スコープ・候補/HEADを再検査**し、予約を永続化する。Task 4はこの公開契約以外に状態ファイルの内部構造へ依存しない。

```text
（未予約） -- reserve() / 承認IDを一回消費 --> RESERVED
RESERVED -- mark_running() を永続化 --> RUNNING
RUNNING  -- complete() を永続化 --> COMPLETED
RESERVED/RUNNING -- crash・停止・保存失敗 --> RESULT_UNKNOWN（回収時に判定）
COMPLETED -- 次の試行 --> 自動遷移しない。新規OwnerApprovalが必要
```

`AttemptHandle` は `reserve()` 取得時から `complete()` 終了または異常終了までロックを保持し、`finally`／context managerで解放する。プロセス死亡ならOSがロックを解放するが、**予約レコードは消えず `RESULT_UNKNOWN` を保持**する。未確定レコードを自動修復・削除しない。未確定状態は、同じ候補だけでなく**全候補への新規実行をブロック**する。Ownerが別途停止と扱いを判断するまで再試行禁止。

記録の永続化は原子的更新と必要な `fsync` を伴う。`mark_running()` 失敗なら `probe_one()` を呼ばない。`complete()` 失敗時は回収状態 `RESULT_UNKNOWN` とし、たとえProbeResultがPASSでもCLIは正常終了しない。Cleanup優先は既存 `probe_one()` の責務として維持する。

記録項目: attempt_id、candidate_id、ingress IP/port/protocol、Git HEAD、approval_id、開始/終了時刻、phase、ProbeStatus、固定reason_code、CLI終了コード、Cleanup status、TUN/DROP/HTTPS/GeoIP段階証拠。APIキー、OpenVPNプロファイル本文・生ログ、認証情報、秘密鍵、トークンを保存しない。

## 7. Result Contract — RG-VOR-010-003

既存 `ProbeStatus` は `PASS / NOT_VERIFIED / BLOCKED / FAIL` のまま。`RESULT_UNKNOWN` はJournal回収状態であり、ProbeStatusではない。

### 7.1 終了コードと保存形式

`JournalResult.exit_code: int | None` とJSON `exit_code: int | null` は、**当該固定候補CLIが返す予定の終了コード**を表す。OpenVPN子プロセスのexit codeではなく、OSが実際にCLIプロセス終了を観測した証拠でもない。`COMPLETED` に永続化した上でCLIが戻る際に0（`ProbeResult.status == PASS` かつCleanup confirmed）または1（それ以外）を返す。`RESERVED`、`RUNNING`、`RESULT_UNKNOWN`、保存失敗による未確定では `exit_code=null`。未取得コードを0に補完しない。実際のシェル終了コード回収は実機Runbookの別確認であり、このフィールドの意味を変更しない。

`JournalResult` は `status: ProbeStatus | None`, `recovery_state: Literal["FINALIZED", "RESULT_UNKNOWN"]`, `reason_codes: tuple[str, ...]`, `exit_code: int | None`, `phase: str`, `cleanup_status: str`, `tun_evidence/drop_evidence/tunnel_https_evidence/tokyo_geoip_evidence: EvidenceState` を持つ不変・検証済みの最小型。`EvidenceState` は `VERIFIED`, `FAILED`, `NOT_OBSERVED` のいずれか。

### 7.2 ProbeResult → Journal/JSON投影規則

既存 `ProbeResult` (`status`, `reason_code`, `evidence`, `phase`, `exit_ip`, `cleanup_status`) から以下に従い投影する。`evidence` は既知の固定マーカー**のみ**を解釈し、生ログ・生のエラー文言・未検証の値をそのままJSONへ転送しない。改修時に `tunnel_https_verified` をHTTPS成功確認直後の固定マーカーとして追加する。

| Field | VERIFIEDの根拠 | FAILEDの根拠 | その他・未観測 |
|---|---|---|---|
| `tun_evidence` | `tls_tun_established:` マーカー（既存 `wait_for_tun()` 成功後、IPv4形式確認済み） | `reason_code` が `tun_not_established` / `tun_ip_invalid` | `NOT_OBSERVED` |
| `drop_evidence` | 新規固定マーカー `direct_drop_counter_verified`（curl拒否＋専用DROPカウンター増加の双方検証済み） | DROP専用失敗コード `drop_*` または `host_direct_echo_route:*` | `NOT_OBSERVED` |
| `tunnel_https_evidence` | 新規固定マーカー `tunnel_https_verified`（TLS検証付きHTTPS応答200とグローバルIPv4本文が妥当） | `exit_ip_fetch_failed` / `exit_ip_body_not_global_ipv4` | `NOT_OBSERVED` |
| `tokyo_geoip_evidence` | `status=PASS` かつ `reason_code=exit_ip_tokyo_verified` | `reason_code=exit_ip_non_tokyo` | `NOT_OBSERVED`（GeoIP照会不能等） |

`cleanup_status` は既存の値のみを採用し、`failed` は必ず最終FAIL。段階的な検証の途中で失敗したからといって、未到達の後続証拠をFAILEDにしない。`ProbeResult`に存在しないOpenVPNプロセスexit codeは取得元として使用しない。`reason_codes` は固定コードallowlistからのみ生成する。

JournalとCLIのJSONは `attempt_id` で照合できる。CLI出力不能時も予約レコードを `RESULT_UNKNOWN` として読み取れる。JSONへの投影失敗、Journal確定失敗はPASS出力禁止。

## 8. Scope Boundaries

### 変更を許容する範囲（**別途**実装承認後のみ）

- `vpn_orbit/live_runner.py`
- `vpn_orbit/openvpn_probe.py`
- `vpn_orbit/isolation.py`
- `vpn_orbit/runner_types.py`（必要な契約変更のみ）
- 固定候補CLI・Journal用の小さな新規モジュール
- 対応するオフラインテスト
- 実機検証用Runbook

変更ファイルは最小化する。変更しない範囲：VPN Gate CSV Phase 1、既存通常候補探索CLI、Supervisorの資格情報隔離、Cleanup優先順位、iOS/sing-box連携、GitHub Actionsの自動実通信設定。OpenVPN認証原因の追加診断は本スコープ外。

## 9. Offline Acceptance

実装はSuperpowers TDDで行う。固定ID一致/不一致/候補変更、最大1候補、認証情報欠落、Stage 1グローバルロック、Issue #9 legacy HOLD、空Journalからの実行禁止、OwnerApproval1回消費、未確定予約、異常終了、書込み不能、DROP例外の最終FAIL、ProbeResultの固定コード投影、Cleanup失敗優先、秘密情報非露出、既存回帰を必須テストとする。

MockテストPASSは実LinuxカーネルのDROP証拠や東京出口IPv4の実証を意味しない。

## 10. Pre-Live Completion Gate

承認範囲での実装完了、オフラインTDD／回帰PASS、失敗系PASS、固定候補・Journal・Cleanup契約のオフライン整合、Preflight／**Issue #9 legacy HOLD・Owner判断**／実行／証拠回収／Cleanupを記載したRunbook、対象Commit・残余リスク報告が揃ったら `READY_FOR_LIVE_APPROVAL` とする。Human Owner Checkpointで停止。これは実通信・運用開始の承認ではない。

## 11. Stop Conditions — RG-VOR-010-001

以下で実行禁止：HEAD/環境不一致、不明なNamespace/OpenVPN残存、候補同一性不明、秘密情報取扱不明、Journalの作成・排他・確定不良、**空Journalを根拠とした起動許可**、**Issue #9のLEGACY_RESULT_UNKNOWNへの新規Owner判断欠如**、承認IDの再利用・承認候補/HEAD不一致、他候補の活動中／結果不明試行、DROP証拠不備、Cleanup異常。

Runbookは実機検証前にIssue #9の既知結果不明試行を確認し、**新たな単発実行についてHuman Ownerの明示承認を確認・記録**する。未承認の旧試行を自動再実行しない。追加のレビュー・実行・訂正ループは自動開始しない。

## 12. Authority

- Design R0.1: **APPROVED**（方式Aを維持）
- Design R0.1.1: **PENDING_OWNER_ADOPTION**（今回限定訂正版）
- Implementation Plan R0.1.1: **PENDING_OWNER_ADOPTION**
- Implementation Authorization: **HOLD**
- Source Code Modification / Test Execution: **HOLD**
- GitHub Commit / Push / PR Update / Merge: **HOLD**
- Live Execution (KVM / GitHub Actions): **HOLD**

この限定訂正はチャット内・ローカル成果物作成に留め、GitHubへの反映や後続Taskを自動開始しない。
