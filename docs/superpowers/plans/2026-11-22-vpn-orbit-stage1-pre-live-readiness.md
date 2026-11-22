# VPN-ORBIT Stage 1 Pre-Live Readiness Implementation Plan R0.1.1

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` or `superpowers:subagent-driven-development` only when implementation is separately authorized. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** LIMITED_DOCUMENT_REMEDIATION / PENDING_OWNER_ADOPTION / IMPLEMENTATION_HOLD  
**Goal:** 最新masterに固定候補実行、安全な直接通信遮断証拠、実行結果回収を統合し、実機検証直前の状態を完成させる。  
**Architecture:** 既存Cloud Probe、OpenVPN Probe、Supervisor、Isolation、Cleanupを再利用する。固定候補CLIとAttempt Journalを追加し、実通信前に候補同一性、Issue #9旧試行HOLD、新しいOwner承認、Stage 1全体の排他を確定する。  
**Tech Stack:** Python 3.11+、標準ライブラリ、unittest、Linux Network Namespace、nftables、OpenVPN。  
**Spec:** [Design R0.1.1（限定訂正版・Owner採択待ち）](../specs/2026-11-22-vpn-orbit-stage1-pre-live-readiness-design.md)  
**Baseline:** `master@7f1ae8cab84a94cea8369e8075b4982b652f1557`  
**Reviewed HEAD:** `fb81579e32f0c7ba0da90853123c449bf0fb442e`  
**Related:** [Issue #9](https://github.com/yohi/vpn-orbit/issues/9) / PR #10 / PR #8 merged

## Global Constraints

- 方式A（master限定補強）を維持。通常候補探索CLIとPhase 1〜3の挙動を維持する。
- 固定候補は指定IDの1候補・1試行のみ。再試行、フォールバック、候補すり替え禁止。
- 今回の文書訂正ではKVM/GitHub Actions実通信、コード変更、テスト実行をしない。
- Supervisor、Namespace、Cleanupの基本構造、TLS/DNS/IPv6拒否・秘密情報境界を緩和しない。
- **Issue #9の既知LEGACY_RESULT_UNKNOWNを空Journalで解除しない。** 新規試行にはHuman Ownerの単発明示承認を必須とする。
- Stage 1全候補を通じて同時実行は1件。未確定試行があれば別候補も含め新規起動を拒否する。
- DROP証拠欠落／取得失敗／不増加は最終 `ProbeResult.status=FAIL`、Cleanup失敗のFAIL優先を保持する。
- `RESULT_UNKNOWN` はJournal回収状態であり既存 `ProbeStatus` に追加しない。
- `exit_code: int | None` はCLIが返す予定のコード（OpenVPN子プロセス終了コードではない）。未回収時はnull。
- Python新規外部依存なし。APIキー、OpenVPNプロファイル本文、生ログ、秘密鍵を保存・公開しない。
- 実装、Commit、Push、PR更新、Merge、実機検証は別途Human Owner承認を待つ。

## Review Focus（必ずテストで固定）

1. 同じIP:portでプロファイルが変わる → 旧IDでは起動しない（Task 1）。
2. curl timeoutでもDROP counter不増加 → `probe_one()`の**最終FAIL**（Task 2）。
3. 新Journalが空でもIssue #9旧試行の結果不明 → Owner未承認なら起動不可（Task 3/4）。
4. 別candidate IDでの同時試行 → Stage 1グローバルロックで拒否（Task 3/4）。
5. DROP JSON破損またはJournal確定失敗 → 最終FAIL／RESULT_UNKNOWN、PASS禁止（Task 2〜4）。

## File Structure

**Create:** `vpn_orbit/fixed_candidates.py`（Task 1）、`vpn_orbit/attempt_journal.py`（Task 3）、`vpn_orbit/stage1_fixed_probe.py`（Task 4）、`tests/test_stage1_fixed_candidates.py`、`tests/test_stage1_attempt_journal.py`、`tests/test_stage1_fixed_probe.py`、`docs/stage1-pre-live.md`（Task 5）。

**Modify only after separate implementation approval:** `vpn_orbit/live_runner.py:147-158`（DROP）、`vpn_orbit/openvpn_probe.py:107-121,155-185`（例外FAILとHTTPS marker）、`tests/_probe_live_cases.py`、`tests/test_openvpn_probe.py`（必要時）。`vpn_orbit/isolation.py`、`vpn_orbit/runner_types.py` は既存境界維持に必要な時だけ変更する。Supervisor再設計はしない。

---

### Task 1: 固定候補IDと選択契約 — RG-VOR-010-005

**Files:** Create `vpn_orbit/fixed_candidates.py`、`tests/test_stage1_fixed_candidates.py`。Reuse `vpn_orbit/cloud_probe.py`。

**Interfaces / Produces:**

```python
def candidate_id(candidate: ScreenedCandidate) -> str: ...
def fixed_shortlist(
    catalog: str, geo_lookup: Callable[[str], GeoDecision],
) -> tuple[ScreenedCandidate, ...]: ...
def resolve_fixed_candidate(
    candidates: Sequence[ScreenedCandidate], requested_id: str,
) -> ScreenedCandidate | None: ...
```

ID計算はDesign §4のSHA-256式。`fixed_shortlist()`の呼出しを以下で固定する。

```python
screen_candidates(
    catalog, existing_pins=frozenset(), geo_lookup=geo_lookup,
    scan_window=40, limit=10, reachable=None,
)
```

`resolve_fixed_candidate()` は完全一致を返す。未検出はNone、不正ID・重複IDは固定例外で拒否。直接TCP事前疎通なし、OpenVPN起動なし。

- [ ] Step 1: `test_candidate_id_uses_exact_profile_bytes`、`test_profile_change_changes_id`、`test_fixed_shortlist_passes_empty_existing_pins_and_preserves_exclusions` を追加。
- [ ] Step 2: `python3 -m unittest tests.test_stage1_fixed_candidates -v` を実行しRED（未実装FAIL）を確認。
- [ ] Step 3: 上記3関数を最小実装。
- [ ] Step 4: `test_missing_id_never_selects_another_candidate`、`test_invalid_id_is_rejected`、`test_duplicate_id_is_blocked`、`test_empty_catalog_never_probes` をRED→GREENにする。
- [ ] Step 5: 同モジュールを再実行しGREEN（全PASS）確認。

**Acceptance:** 既存APIの必須 `existing_pins` 引数と選別条件が一致。Profile変化・候補消失時に代替候補へ切替しない。

### Task 2: DROP証拠と最終FAIL正規化 — RG-VOR-010-004

**Files:** Modify `vpn_orbit/live_runner.py` の `host_direct_route_rejected()`、`vpn_orbit/openvpn_probe.py` の `_verify_routes()`。Tests: `tests/_probe_live_cases.py`（`tests/test_openvpn_probe.py`経由）。

**Interface / Produces:**

```python
def host_direct_route_rejected(
    self, echo_ip: str, resources: IsolationResources, deadline: float,
) -> tuple[bool, str]: ...
```

Runnerは成功時に正確に `(True, "direct_drop_counter_verified")` を返す。失敗時はFalseと固定コードのみ。`_verify_routes()`はFalse、予期しないTrue/detail、**DROP呼出しからの `Exception`** を `(ProbeStatus.FAIL, fixed_reason)` に正規化し、既存 `probe_one()` 一般例外の `NOT_VERIFIED` 経路へ伝播させない（`BaseException` は捕捉しない）。Cleanup失敗のFAIL優先は維持。

固定失敗コード: `drop_curl_not_refused`、`drop_counter_unavailable`、`drop_counter_invalid`、`drop_counter_not_advanced`、`drop_evidence_unavailable`。秘密情報、生JSON、生コマンド出力を含めない。

- [ ] Step 1: `test_curl_refused_and_counter_advanced_is_verified`、`test_curl_timeout_without_counter_increment_is_fail` を追加。専用ルールのveth・IPv4・TCP/443・識別子とカウンター差分をassert。
- [ ] Step 2: `test_counter_read_failure_is_fail`、`test_malformed_nft_json_is_fail`、`test_unexpected_counter_identity_is_fail`、`test_direct_curl_success_is_fail` を追加。
- [ ] Step 3: `test_drop_counter_error_yields_probe_fail_not_not_verified`、`test_drop_json_error_yields_probe_fail`、`test_drop_rule_mismatch_yields_probe_fail`、`test_drop_counter_no_increment_yields_probe_fail` を追加し、各 `probe_one()` の最終 `result.status == ProbeStatus.FAIL` をassert。Cleanup失敗のFAIL優先もassert。
- [ ] Step 4: `python3 -m unittest tests.test_openvpn_probe -v` でREDを確認。
- [ ] Step 5: Runnerに専用 `counter drop`（Namespace output、echo IP/TCP443/veth限定）の作成、前後カウンター読込、同一識別子の検証を実装。`ip route get ... oif` は補助情報に留める。
- [ ] Step 6: `_verify_routes()`で例外・不正detailのFAIL変換を実装。成功時のみ固定 `direct_drop_counter_verified` を `ProbeResult.evidence` に追加。
- [ ] Step 7: 上記モジュールでGREEN確認。TUN HTTPS許可・デフォルト経路不変・Cleanup優先も回帰。

**Acceptance:** nftables取得失敗、JSON破損、識別不一致、カウンター不増加は最終FAIL。Mock PASSは実カーネルのDROP実証ではない。

### Task 3: Journal、Issue #9 Legacy HOLD、全体排他 — RG-VOR-010-001/002/003

**Files:** Create `vpn_orbit/attempt_journal.py`、`tests/test_stage1_attempt_journal.py`。

**Interfaces / Produces for Task 4:**

```python
EvidenceState = Literal["VERIFIED", "FAILED", "NOT_OBSERVED"]

@dataclass(frozen=True)
class OwnerApproval:
    approval_id: str
    issue_ref: Literal["yohi/vpn-orbit#9"]
    legacy_disposition: Literal["ACKNOWLEDGED_RESULT_UNKNOWN"]
    candidate_id: str
    approved_head: str
    scope: Literal["ONE_NEW_ATTEMPT"]
    approved_at: str

@dataclass(frozen=True)
class JournalSnapshot:
    legacy_hold: bool
    has_active: bool
    has_unresolved: bool

@dataclass(frozen=True)
class JournalResult:
    status: ProbeStatus | None
    recovery_state: Literal["FINALIZED", "RESULT_UNKNOWN"]
    reason_codes: tuple[str, ...]
    exit_code: int | None  # intended fixed CLI return code; not OpenVPN exit
    phase: str
    cleanup_status: str
    tun_evidence: EvidenceState
    drop_evidence: EvidenceState
    tunnel_https_evidence: EvidenceState
    tokyo_geoip_evidence: EvidenceState

class AttemptHandle:
    attempt_id: str
    def __enter__(self) -> AttemptHandle: ...
    def __exit__(self, exc_type, exc, tb) -> None: ...

class AttemptJournal:
    def __init__(self, root: Path) -> None: ...
    def inspect(self) -> JournalSnapshot: ...
    def read_approval(self) -> OwnerApproval | None: ...
    def reserve(
        self, *, candidate_id: str, ingress: str, head: str,
        approval: OwnerApproval,
    ) -> AttemptHandle: ...
    def mark_running(self, handle: AttemptHandle) -> None: ...
    def complete(self, handle: AttemptHandle, *, result: JournalResult) -> None: ...
```

**Contract:** `/var/lib/vpn-orbit/stage1-attempts` root所有0700、各ファイル0600、symlink禁止。テストは隔離tempdirとMockでroot権限不要。`read_approval()` はOwnerの制限アクセスファイルを**読み取るだけ**。Issue #9の旧結果不明は既定HOLDであり、空Journalでも新しい単発承認がなければBLOCKED。承認内容はDesign §6.1に完全一致。AIは承認を作成・推測しない。

1個のStage 1グローバル `flock(LOCK_NB)` を予約から完了まで保持。`reserve()` はOwner承認の候補ID、HEAD、Issue #9認識、承認ID未消費、他試行の `ACTIVE` / `RESULT_UNKNOWN` 不存在を**ロック下で再確認**し、承認IDを一度消費して予約をfsync。`inspect()`は参考表示であり唯一の実行許可判定にはならない。

状態: `UNRESERVED → RESERVED → RUNNING → COMPLETED`。`RESERVED/RUNNING` で異常終了または記録失敗なら次回の `inspect()` は `has_unresolved=True`（`RESULT_UNKNOWN`）で全候補HOLD。プロセス終了でロックが解放されても未確定ファイルは削除しない。`mark_running()`失敗で `probe_one()` 起動禁止。`complete()`失敗ならCLIはPASS禁止。`AttemptHandle.__exit__` は正常・異常どちらもロック解放。

- [ ] Step 1: `test_empty_journal_still_blocks_issue9_legacy_unknown_without_owner_approval`、`test_read_approval_rejects_wrong_issue_or_scope`、`test_approval_is_one_time_and_candidate_head_scoped` を書く。
- [ ] Step 2: `python3 -m unittest tests.test_stage1_attempt_journal -v` でRED確認。
- [ ] Step 3: 既定legacy HOLD、OwnerApproval読込と権限検査、`inspect()`を実装。
- [ ] Step 4: `test_global_lock_blocks_different_candidate_ids`、`test_reserve_rechecks_under_lock`、`test_duplicate_approval_id_is_blocked`、`test_wrong_head_is_blocked`、`test_reserve_writes_restricted_durable_record` を追加しRED確認。
- [ ] Step 5: 予約・承認ID消費・原子的保存・グローバルロックを実装。
- [ ] Step 6: `test_reserved_or_running_after_crash_is_result_unknown`、`test_unresolved_blocks_all_candidates`、`test_mark_running_failure_prevents_probe`、`test_symlink_or_wrong_owner_is_blocked`、`test_unwritable_store_is_blocked` を追加しRED確認。
- [ ] Step 7: 状態遷移、未確定HOLD、`AttemptHandle` ロック解放を最小実装。
- [ ] Step 8: `test_complete_failure_leaves_unknown_and_never_reports_pass`、`test_null_exit_code_for_unknown`、`test_secret_values_are_not_serialized` をRED→GREENにする。
- [ ] Step 9: 同テストモジュールを再実行し全PASS確認。

**Acceptance:** Task 4は公開 `inspect/read_approval/reserve/mark_running/complete/AttemptHandle` のみで動作。空Journal、過去未回収、別候補並列、未確定、記録失敗からOpenVPNへ到達しない。

### Task 4: 固定候補CLI・結果投影・回収 — RG-VOR-010-001/002/003

**Files:** Create `vpn_orbit/stage1_fixed_probe.py`、`tests/test_stage1_fixed_probe.py`。Modify minimally `vpn_orbit/openvpn_probe.py` for HTTPS成功マーカー。Reuse Task 1〜3、既存 `probe_one()`。

**Interfaces / Consumes:**

```python
# Task 1
candidate_id(candidate: ScreenedCandidate) -> str
fixed_shortlist(catalog: str, geo_lookup: Callable[[str], GeoDecision]) -> tuple[ScreenedCandidate, ...]
resolve_fixed_candidate(candidates: Sequence[ScreenedCandidate], requested_id: str) -> ScreenedCandidate | None

# Task 3
AttemptJournal.inspect() -> JournalSnapshot
AttemptJournal.read_approval() -> OwnerApproval | None
AttemptJournal.reserve(*, candidate_id: str, ingress: str, head: str, approval: OwnerApproval) -> AttemptHandle
AttemptJournal.mark_running(handle: AttemptHandle) -> None
AttemptJournal.complete(handle: AttemptHandle, *, result: JournalResult) -> None
# AttemptHandle is a context manager. Private Journal state files must not be read by Task 4.

def main(argv: list[str] | None = None) -> int: ...
```

**CLI contract:** `python3 -m vpn_orbit.stage1_fixed_probe --list` / `--probe-id <64-character-id>`。`--list` はCatalog／GeoIP照会のみでOpenVPN起動なし。`--probe-id` は候補完全一致後、`inspect()`とOwnerApprovalの読込みを行い、`reserve()`で再チェックして承認を一度だけ消費。`mark_running()`が永続化に成功した後だけ `probe_one()` を**1回だけ**呼ぶ。フォールバック・自動再試行なし。空JournalでもIssue #9が未判断ならBLOCKED。APIキーはGeoIP用であり、Journal/OpenVPN環境へ渡さない。

**JSON / JournalResult の完全投影契約:**

| Field / Type | Source | 未取得・未到達の値 |
|---|---|---|
| `attempt_id: str | null` | `AttemptHandle.attempt_id` | 予約前ならnull |
| `candidate_id: str | null` | Task 1固定候補照合 | 未確定ならnull。指定値を照合済みと偽装しない |
| `status: str | null` | `ProbeResult.status.value` | Probe未実行・結果未回収ならnull。CLI拒否状態は固定reason_codeで示す |
| `recovery_state: str` | `FINALIZED` / `RESULT_UNKNOWN` | 未確定なら `RESULT_UNKNOWN` |
| `reason_codes: list[str]` | 既存固定 `ProbeResult.reason_code` とCLI固定拒否コードのallowlist | 不明文字列は固定の非秘匿エラーコードへ正規化 |
| `exit_code: int | null` | **固定候補CLIが返す予定のコード**。PASS + cleanup confirmed + Journal確定なら0、その他の確定結果は1 | 予約／実行中／結果未回収ならnull。OpenVPN終了コードではない |
| `phase: str` | `ProbeResult.phase` の許可済み固定phase | `not_started` |
| `cleanup_status: str` | `ProbeResult.cleanup_status` の既存許可値 | `not_required`等、推測しない |
| `tun_evidence: EvidenceState` | `tls_tun_established:` の既存成功マーカー → VERIFIED；`tun_not_established`/`tun_ip_invalid` → FAILED | NOT_OBSERVED |
| `drop_evidence: EvidenceState` | **新規** `direct_drop_counter_verified` のみ → VERIFIED；`drop_*`/`host_direct_echo_route:*` → FAILED | NOT_OBSERVED |
| `tunnel_https_evidence: EvidenceState` | **新規** `tunnel_https_verified` → VERIFIED；`exit_ip_fetch_failed`/`exit_ip_body_not_global_ipv4` → FAILED | NOT_OBSERVED |
| `tokyo_geoip_evidence: EvidenceState` | `PASS + exit_ip_tokyo_verified` → VERIFIED；`exit_ip_non_tokyo` → FAILED | NOT_OBSERVED |

`EvidenceState` は `VERIFIED / FAILED / NOT_OBSERVED` の3値のみ。`tunnel_https_verified` は、既存 `curl_via_tun()` のHTTP 200・TLS検証とグローバルIPv4本文の検証が完了した時点でのみ追加。DROP成功はTask 2の正規マーカーのみを信頼する。後続の未到達をFAILEDにしない。`ProbeResult.evidence` 内の不明な情報や生ログをJSONへ透過させない。

- [ ] Step 1: `test_list_never_invokes_probe`、`test_exact_id_invokes_probe_once`、`test_missing_candidate_never_reserves_or_probes` を追加。
- [ ] Step 2: `python3 -m unittest tests.test_stage1_fixed_probe -v` でREDを確認。
- [ ] Step 3: `main(argv)`、候補ID照合、Journal公開API、`probe_one()`単発呼出、結果投影、JSON出力を実装。
- [ ] Step 4: `test_issue9_unknown_blocks_empty_journal_without_owner_decision`、`test_issue9_unknown_blocks_different_candidate_without_owner_decision`、`test_owner_approval_must_reference_issue9_and_new_single_attempt`、`test_used_approval_cannot_relaunch`、`test_existing_unknown_attempt_blocks_probe` を追加してRED→GREEN。
- [ ] Step 5: `test_parallel_different_candidate_is_blocked`、`test_mark_running_failure_never_calls_probe`、`test_journal_complete_failure_never_reports_pass`、`test_cleanup_failure_overrides_pass` をRED→GREEN。
- [ ] Step 6: `test_exit_code_is_nullable_and_cli_not_openvpn`、`test_tun_drop_https_tokyo_evidence_projection`、`test_drop_unverified_is_not_verified`、`test_unreached_is_not_observed`、`test_result_unknown_has_null_exit_code`、`test_json_redacts_secrets_and_raw_profile`、`test_untrusted_errors_emit_fixed_codes_only` をRED→GREEN。
- [ ] Step 7: `python3 -m unittest tests.test_stage1_fixed_probe -v` でGREEN確認。
- [ ] Step 8: `python3 -m unittest tests.test_stage1_fixed_candidates tests.test_stage1_attempt_journal tests.test_stage1_fixed_probe tests.test_openvpn_probe -v` でTask 1〜4をまとめて回帰確認。

**Acceptance:** Issue #9既存未回収試行、空Journal、候補変更、Owner承認再利用、別候補並列のいずれでも無断OpenVPN起動なし。全JSON/Journalフィールドの取得元・型・未取得値が確定。失敗や保存不能でPASSを報告しない。

### Task 5: オフライン受入と実機検証Runbook — RG-VOR-010-001

**Files:** Create `docs/stage1-pre-live.md`。Task 1〜4のテストに必要な既存テストのみ限定変更。

- [ ] Step 1: 基準master/feature HEAD・変更対象・Pythonバージョンを確認。drift時は停止しOwnerへ報告。
- [ ] Step 2: `python3 -m unittest discover -s tests -v` を実行。Expected: 実行対象PASS、skipの理由は記録。
- [ ] Step 3: `python3 -m compileall -q vpn_orbit tests` を実行。Expected: 終了コード0。
- [ ] Step 4: `git diff --check` を実行。Expected: PASS。
- [ ] Step 5: Catalog/GeoIP/OpenVPN/nftables/RunnerをMockし、ネットワーク実通信を禁止した状態でCLIの正常系・失敗系テストを実行。
- [ ] Step 6: `docs/stage1-pre-live.md` にホストと `vpn-orbit-probe` の識別、Preflight、固定候補SHA、**Issue #9のLEGACY_RESULT_UNKNOWN確認**、**Ownerによる新たな1試行の承認判断と制限アクセスOwnerApprovalの確認**、空Journalでは許可されないこと、結果回収、実シェル終了コードとJSON予定終了コードの違い、Cleanupの実リソース不存在、RESULT_UNKNOWN時停止、再試行禁止を記載。
- [ ] Step 7: `test_issue9_unknown_blocks_empty_journal_without_owner_decision` と `test_issue9_unknown_blocks_different_candidate_without_owner_decision` が存在しPASSすることと、Runbookが同一HOLD条件を明記することを確認。
- [ ] Step 8: 実装差分・テスト結果・未実証事項・残余リスクを最終報告しHuman Owner Checkpointで停止。

**Acceptance:** オフラインTDD・既存回帰PASS、旧試行と新Journal両方のFail-Closed確認、Runbook完成、KVM/GitHub Actions実通信未実施。未実行テストをPASSと呼ばない。

## Integration and Commit Policy

実装は別途Human Owner承認後のみ、既存worktreeを保護して開始。masterが基準からdriftしていれば無断rebaseせず報告。新コードCommit・Push・PR作成は別承認までHOLD。Commit数やレビュー回数の増加を目的としない。初回検証・必要な限定訂正の後はHuman Owner Checkpointへ戻す。

## Completion Gate

1. 承認範囲での実装完成。
2. オフラインTDD・回帰テストPASS。
3. Issue #9 legacy HOLD、Stage 1グローバル排他、DROP例外最終FAIL、Journal障害、JSON投影をテスト確認。
4. 実行結果・中断状態を回収する仕組み完成。
5. KVM Pre-Live Runbook完成。
6. 実カーネル・実通信・東京出口IPv4の未実証を明記。
7. KVM／GitHub Actions実通信 `NOT_RUN`。
8. Human Owner Checkpointで停止。

これらを満たす時だけ `READY_FOR_LIVE_APPROVAL`。実通信のPASS・運用開始承認を意味しない。

## Stop Conditions and Authority

- HEAD・環境不一致、Namespace/OpenVPN等の不明残存、候補ID不一致、APIキー取扱不明、**Issue #9旧試行に対する新規Owner判断欠落**、空Journalを根拠とする実行、承認ID再利用、別候補並列、未確定試行、Journal書込み失敗、DROP証拠欠落、Cleanup異常はFail-Closed。
- Design R0.1: APPROVED（方式A維持）
- Design R0.1.1 / Plan R0.1.1: PENDING_OWNER_ADOPTION
- Implementation / Source Changes / Test Execution: HOLD
- GitHub Commit / Push / PR Update / Merge: HOLD
- KVM / GitHub Actions Live: HOLD
- No automatic follow-on Task, independent review or remediation cycle

今回の限定訂正は2文書の修正版提示のみ。Ownerの明示承認なしに次工程を開始しない。
