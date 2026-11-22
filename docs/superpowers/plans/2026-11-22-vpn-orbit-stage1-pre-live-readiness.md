# VPN-ORBIT Stage 1 Pre-Live Readiness Implementation Plan R0.1.4

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` or `superpowers:subagent-driven-development` only when implementation is separately authorized. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** LIMITED_DOCUMENT_REMEDIATION / PENDING_OWNER_ADOPTION / IMPLEMENTATION_HOLD  
**Goal:** 最新masterに固定候補実行、安全な直接通信遮断証拠、実行結果回収を統合し、実機検証直前の状態を完成させる。  
**Architecture:** 既存Cloud Probe、OpenVPN Probe、Supervisor、Isolation、Cleanupを再利用する。固定候補CLIとAttempt Journalを追加し、実通信前に候補同一性、Issue #9旧試行HOLD、新しいOwner承認、**固定候補CLI経由の全candidate IDの排他**を確定する。既存 `cloud_probe` は排他対象外。  
**Tech Stack:** Python 3.11+、標準ライブラリ、unittest、Linux Network Namespace、nftables、OpenVPN。  
**Spec:** [Design R0.1.4（RG-VOR-010-002限定訂正版・Owner採択待ち）](../specs/2026-11-22-vpn-orbit-stage1-pre-live-readiness-design.md)  
**Baseline:** `master@7f1ae8cab84a94cea8369e8075b4982b652f1557`  
**Reviewed HEAD:** `e2562201e13f75b64ba124186a41a9c12bbc41c3`  
**Related:** [Issue #9](https://github.com/yohi/vpn-orbit/issues/9) / PR #10 / PR #8 merged

## Global Constraints

- 方式A（master限定補強）を維持。通常候補探索CLIとPhase 1〜3の挙動を維持する。
- 固定候補は指定IDの1候補・1試行のみ。再試行、フォールバック、候補すり替え禁止。
- 今回の文書訂正ではKVM/GitHub Actions実通信、コード変更、テスト実行をしない。
- Supervisor、Namespace、Cleanupの基本構造、TLS/DNS/IPv6拒否・秘密情報境界を緩和しない。
- **Issue #9の既知LEGACY_RESULT_UNKNOWNを空Journalで解除しない。** 新規試行にはHuman Ownerの単発明示承認を必須とする。
- **固定候補CLI経由の全candidate IDに対して**同時実行は1件。Journal未確定試行があれば固定候補CLIからの別候補起動も拒否する。既存 `vpn_orbit.cloud_probe` はJournalを通らず排他保証対象外であり、この承認で既存CLIの追加実通信を許可しない。
- DROP証拠欠落／取得失敗／不増加は最終 `ProbeResult.status=FAIL`、Cleanup失敗のFAIL優先を保持する。
- `RESULT_UNKNOWN` はJournal回収状態であり既存 `ProbeStatus` に追加しない。
- `exit_code: int | None` はCLIが返す予定のコード（OpenVPN子プロセス終了コードではない）。未回収時はnull。
- Python新規外部依存なし。APIキー、OpenVPNプロファイル本文、生ログ、秘密鍵を保存・公開しない。
- 実装、Commit、Push、PR更新、Merge、実機検証は別途Human Owner承認を待つ。

## Review Focus（必ずテストで固定）

1. 同じIP:portでプロファイルが変わる → 旧IDでは起動しない（Task 1）。
2. curl timeoutでもDROP counter不増加 → `probe_one()`の**最終FAIL**（Task 2）。
3. 新Journalが空でもIssue #9旧試行の結果不明 → Owner未承認なら起動不可（Task 3/4）。
4. 固定候補CLIを通した別candidate IDの同時試行 → **固定CLI共通ロック**で拒否。既存cloud_probeには共有されない（Task 3/4）。
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

**Files:** Modify `vpn_orbit/live_runner.py` の `host_direct_route_rejected()`、`vpn_orbit/openvpn_probe.py` の `_verify_routes()`。Tests: `tests/_probe_live_cases.py`（`tests/test_openvpn_probe.py`経由）。既存の `route_get_via_tun0()` がecho IPv4 `/32` を `tun0` に設定することを前提とし、その後続処理のみ限定補強する。

**Interface / Produces:**

```python
def host_direct_route_rejected(
    self, echo_ip: str, resources: IsolationResources, deadline: float,
) -> tuple[bool, str]: ...
```

Runnerの成功値は正確に `(True, "direct_drop_counter_verified")`。それ以外はFalse＋固定コード。`_verify_routes()` はFalse、不正なTrue/detail、DROP検証呼出しの `Exception` を `(ProbeStatus.FAIL, fixed_reason)` に正規化する（`BaseException` は捕捉しない）。既存Cleanup失敗のFAIL優先を維持する。

**安全な計測手順（Design §5と同一）:**

1. 既存 `route_get_via_tun0()` が確立したecho IPv4 `/32 dev tun0` routeを検査・保存する。対象IPは既存で検証済みのglobal IPv4のみ。
2. Namespace既存の `inet <resources.table> output` に、echo IPv4/TCP443/`oifname <veth_ns>` に限定した `counter drop` を**先に**置く。ルール識別子、完全一致する条件、送出前パケットカウンターを確認。失敗ならパケット送出禁止。
3. echo IPv4の `/32` routeのみを一時的に `via 10.253.240.1 dev <veth_ns>` に切替。通常の `ip -4 route get <echo_ip>` とroute一覧でvethとgatewayへの到達経路を検証。デフォルト経路・他宛先・VPN peerの許可経路は変更しない。`ip route get ... oif` 単独の成功は根拠にしない。
4. 元のcurlを、HTTPS/`--noproxy '*'`/`--resolve api.ipify.org:443:<echo_ip>`/`--interface if!<veth_ns>`/TCP443/既存短時間timeoutに固定して**1回だけ**送出。curl終了コード7/28と、同じ `counter drop` ルールのpacketカウンターの厳密な増加が必要。カウンターが増えなければ遮断証拠なし。
5. `finally` で、成功・失敗・例外・期限切れを問わず **echo IPv4 `/32` を保存した `tun0` routeへ戻し**、通常route getとroute一覧により復元・veth向け一時route不在を確認。その**後**で所有する専用DROPルールを識別子で撤去・不在確認。復元不能時はルールを先に撤去せず、FAILとして既存Supervisor/Namespace Cleanupへ移る。復元確認できなければTUN HTTPSへ進めない。
6. 送出・カウンター増加・経路復元・ルール撤去の全条件が確認できた場合だけ成功マーカーを生成する。

固定失敗コード: `drop_curl_not_refused`、`drop_counter_unavailable`、`drop_counter_invalid`、`drop_counter_not_advanced`、`drop_route_unavailable`、`drop_route_restore_failed`、`drop_rule_cleanup_failed`、`drop_evidence_unavailable`。生JSONやsecretを公開しない。

- [ ] Step 1: `test_curl_refused_and_counter_advanced_is_verified`、`test_curl_timeout_without_counter_increment_is_fail` を追加。専用ルールの条件・識別子・カウンター差分をassert。
- [ ] Step 2: `test_counter_read_failure_is_fail`、`test_malformed_nft_json_is_fail`、`test_unexpected_counter_identity_is_fail`、`test_direct_curl_success_is_fail` を追加。
- [ ] Step 3: `test_drop_rule_installed_before_temporary_route`、`test_no_packet_if_drop_rule_missing`、`test_temporary_echo_32_route_points_to_veth`、`test_only_one_bounded_echo_packet_is_attempted` を追加。コマンド順序、対象echo/32以外の経路不変、curlの固定引数を検証。
- [ ] Step 4: `test_tun0_echo_route_restored_before_drop_rule_removed`、`test_route_restore_failure_yields_probe_fail`、`test_drop_rule_cleanup_failure_yields_probe_fail`、`test_counter_increment_without_route_restoration_is_not_pass` を追加。成功時・失敗時・例外時の復旧順序と未到達TUN HTTPSをassert。
- [ ] Step 5: `test_drop_counter_error_yields_probe_fail_not_not_verified`、`test_drop_json_error_yields_probe_fail`、`test_drop_rule_mismatch_yields_probe_fail`、`test_drop_counter_no_increment_yields_probe_fail` を追加し、各 `probe_one()` 最終 `result.status == ProbeStatus.FAIL` をassert。復元・撤去失敗でも最終FAIL、Cleanup失敗は `cleanup_failed:*` 優先とする。
- [ ] Step 6: `python3 -m unittest tests.test_openvpn_probe -v` でREDを確認。
- [ ] Step 7: Runnerに上記専用ルール、限定route切替、送出、前後カウンター、`finally` 復元・撤去を実装。`_verify_routes()` で固定FAIL正規化し、全条件成立時のみ `direct_drop_counter_verified` を `ProbeResult.evidence` に追加。
- [ ] Step 8: 同テストでGREEN確認。TUN HTTPS許可、ホストデフォルトルート不変、Namespace Cleanup、Cleanup失敗優先を回帰。

**Acceptance:** ルール未設置時は送出なし。計測中のveth `/32` は限定的・一時的。ルート復元とルール撤去が確認できない限りPASSなし。実カーネルでの到達・DROPカウンター増加・TUN HTTPS成功は `NOT_VERIFIED` のまま（このTaskではテストも実通信も未実行）。

### Task 3: Journal、Issue #9 Legacy HOLD、固定候補CLI内排他 — RG-VOR-010-001/002/003

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

固定候補CLIで共有する1個の `flock(LOCK_NB)` を、candidate IDに関係なく予約から完了まで保持。**固定CLI内のロック競合は `status=BLOCKED / recovery_state=NOT_STARTED / reason_codes=["preflight_blocked"]`（予約前、`attempt_id=null`、`exit_code=null`、Probe未呼出）とする。**既存 `vpn_orbit.cloud_probe` はJournalを通らず、この技術的ロックを共有しない（Stage 1全体の排他保証ではない）。`reserve()` はOwner承認の候補ID、HEAD、Issue #9認識、承認ID未消費、他試行の `ACTIVE` / `RESULT_UNKNOWN` 不存在を**ロック下で再確認**し、承認IDを一度消費して予約をfsync。`inspect()`は参考表示であり唯一の実行許可判定にはならない。

状態: `UNRESERVED → RESERVED → RUNNING → COMPLETED`。`RESERVED/RUNNING` で異常終了または記録失敗なら次回の `inspect()` は `has_unresolved=True`（`RESULT_UNKNOWN`）で全候補HOLD。プロセス終了でロックが解放されても未確定ファイルは削除しない。`mark_running()`失敗で `probe_one()` 起動禁止。`complete()`失敗ならCLIはPASS禁止。`AttemptHandle.__exit__` は正常・異常どちらもロック解放。

- [ ] Step 1: `test_empty_journal_still_blocks_issue9_legacy_unknown_without_owner_approval`、`test_read_approval_rejects_wrong_issue_or_scope`、`test_approval_is_one_time_and_candidate_head_scoped` を書く。
- [ ] Step 2: `python3 -m unittest tests.test_stage1_attempt_journal -v` でRED確認。
- [ ] Step 3: 既定legacy HOLD、OwnerApproval読込と権限検査、`inspect()`を実装。
- [ ] Step 4: `test_global_lock_blocks_different_candidate_ids`（異なるcandidate IDの競合時に `reserve()` を拒否し、追加予約を作成しないことをassert。CLI公開コードはTask 4で検証）、`test_reserve_rechecks_under_lock`、`test_duplicate_approval_id_is_blocked`、`test_wrong_head_is_blocked`、`test_reserve_writes_restricted_durable_record` を追加しRED確認。
- [ ] Step 5: 予約・承認ID消費・原子的保存・固定候補CLI共通ロックを実装。
- [ ] Step 6: `test_reserved_or_running_after_crash_is_result_unknown`、`test_unresolved_blocks_all_candidates`、`test_mark_running_failure_prevents_probe`、`test_symlink_or_wrong_owner_is_blocked`、`test_unwritable_store_is_blocked` を追加しRED確認。
- [ ] Step 7: 状態遷移、未確定HOLD、`AttemptHandle` ロック解放を最小実装。
- [ ] Step 8: `test_complete_failure_leaves_unknown_and_never_reports_pass`、`test_null_exit_code_for_unknown`、`test_secret_values_are_not_serialized` をRED→GREENにする。
- [ ] Step 9: 同テストモジュールを再実行し全PASS確認。

**Acceptance:** Task 4は公開 `inspect/read_approval/reserve/mark_running/complete/AttemptHandle` のみで動作。空Journal、過去未回収、**固定候補CLI経由の別candidate ID並列**、未確定、記録失敗から無断OpenVPNへ到達しない。ロック競合のCLI公開reason codeは `preflight_blocked` のみ。既存CLIへの適用は保証しない。

### Task 4: 固定候補CLI・結果投影・回収 — RG-VOR-010-001/002/003/006

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

**CLI contract:** `python3 -m vpn_orbit.stage1_fixed_probe --list` / `--probe-id <64-character-id>`。`--list` はCatalog／GeoIP照会のみでOpenVPN起動なし。`--probe-id` は候補完全一致後、`inspect()`とOwnerApprovalの読込みを行い、`reserve()`で再チェックして承認を一度だけ消費。`mark_running()`が永続化に成功した後だけ `probe_one()` を**1回だけ**呼ぶ。固定CLIの**全candidate ID**は同じJournalロックと未確定HOLDを共有する。既存 `vpn_orbit.cloud_probe` はこの契約・ロックを利用しないため、**既存CLIを含む並列実行防止は保証しない**し、今回の承認で既存CLIの追加実通信を許可しない。フォールバック・自動再試行なし。空JournalでもIssue #9が未判断ならBLOCKED。APIキーはGeoIP用であり、Journal/OpenVPN環境へ渡さない。

**JSON / JournalResult の完全投影契約:**

| Field / Type | Source | 未取得・未到達の値 |
|---|---|---|
| `attempt_id: str | null` | `AttemptHandle.attempt_id` | 予約前ならnull。予約済みでProbe未呼出が確実な場合は実際のattempt_idを残す |
| `candidate_id: str | null` | Task 1固定候補照合 | 未確定ならnull。指定値を照合済みと偽装しない |
| `status: str | null` | `NOT_STARTED`時はCLIの固定拒否状態 `BLOCKED` / `NOT_VERIFIED`；`FINALIZED`時は `ProbeResult.status.value` | `RESULT_UNKNOWN`時だけnull。未開始を実行済みとみなさない |
| `recovery_state: str` | CLI専用 `NOT_STARTED` またはJournal由来 `FINALIZED` / `RESULT_UNKNOWN` | Probe未呼出が確実なら `NOT_STARTED`；開始有無不明・回収不能なら `RESULT_UNKNOWN` |
| `reason_codes: list[str]` | `NOT_STARTED`時はCLIの固定拒否コード、`FINALIZED`時は `ProbeResult.reason_code` allowlist、`RESULT_UNKNOWN`時は固定回収不能コード | 不明文字列は固定の非秘匿コードへ正規化。旧 `LEGACY_RESULT_UNKNOWN` を今回の状態として記録しない |
| `exit_code: int | null` | **固定候補CLIが返す予定のコード**。`FINALIZED` かつPASS + cleanup confirmedなら0、その他の確定結果は1 | `NOT_STARTED`/`RESULT_UNKNOWN` は常にnull。CLI拒否時の実シェル終了コードでもOpenVPN終了コードでもない |
| `phase: str` | `FINALIZED`時は `ProbeResult.phase` の許可済み固定phase | `NOT_STARTED`時は `not_started`。`RESULT_UNKNOWN`時は最後に確証できた固定phaseのみ |
| `cleanup_status: str` | `FINALIZED`時は `ProbeResult.cleanup_status` の既存許可値 | 今回のProbe未呼出が確実な `NOT_STARTED`時は `not_required`。`RESULT_UNKNOWN`時は確認値のみ、確認不能なら `not_required` を成功証拠として使用しない |
| `tun_evidence: EvidenceState` | `tls_tun_established:` の既存成功マーカー → VERIFIED；`tun_not_established`/`tun_ip_invalid` → FAILED | NOT_OBSERVED |
| `drop_evidence: EvidenceState` | **新規** `direct_drop_counter_verified` のみ → VERIFIED；`drop_*`/`host_direct_echo_route:*` → FAILED | NOT_OBSERVED |
| `tunnel_https_evidence: EvidenceState` | **新規** `tunnel_https_verified` → VERIFIED；`exit_ip_fetch_failed`/`exit_ip_body_not_global_ipv4` → FAILED | NOT_OBSERVED |
| `tokyo_geoip_evidence: EvidenceState` | `PASS + exit_ip_tokyo_verified` → VERIFIED；`exit_ip_non_tokyo` → FAILED | NOT_OBSERVED |

`EvidenceState` は `VERIFIED / FAILED / NOT_OBSERVED` の3値のみ。`tunnel_https_verified` は、既存 `curl_via_tun()` のHTTP 200・TLS検証とグローバルIPv4本文の検証が完了した時点でのみ追加。DROP成功はTask 2の正規マーカーのみを信頼する。後続の未到達をFAILEDにしない。`ProbeResult.evidence` 内の不明な情報や生ログをJSONへ透過させない。

**CLI応答の状態対応表（Design §7.3と同一）:**

`CliProbeOutcome`: `status: Literal["PASS", "NOT_VERIFIED", "BLOCKED", "FAIL"] | None`、`recovery_state: Literal["NOT_STARTED", "FINALIZED", "RESULT_UNKNOWN"]`、`reason_codes: list[str]`。`NOT_STARTED` はCLI専用で、Task 3が生成する `JournalResult.recovery_state`（`FINALIZED` / `RESULT_UNKNOWN`）は変更しない。以下は `--probe-id` 応答に適用し、`--list` は試行JSONとして扱わない。

| 今回の `--probe-id` の状況 | CLI `status` | CLI `recovery_state` | CLI `reason_codes`（固定コード） |
|---|---|---|---|
| Issue #9の既存HOLD、OwnerApproval欠落・不一致・使用済み、空Journalでも承認なし | `BLOCKED` | `NOT_STARTED` | `legacy_unknown_owner_decision_required`（旧試行のHOLD時）、それ以外は `preflight_blocked` |
| CLI引数不正、権限不正、既存の未確定予約、ロック取得不可、Journal予約前の他の安全拒否 | `BLOCKED` | `NOT_STARTED` | `preflight_blocked` |
| 固定候補IDが現行候補一覧に存在しない（変更・消失を含む） | `NOT_VERIFIED` | `NOT_STARTED` | `candidate_not_found` |
| 予約後、`mark_running()`が永続化できず、`probe_one()`を**一度も呼んでいないことが確実** | `BLOCKED` | `NOT_STARTED` | `probe_start_blocked` |
| `probe_one()`呼出後、結果を回収できない（起動有無が不確実な中断を含む） | `null` | `RESULT_UNKNOWN` | `attempt_result_unavailable` |
| `probe_one()`後、Journalの `complete()` に失敗して最終結果を永続化できない | `null` | `RESULT_UNKNOWN` | `journal_finalization_failed` |
| Probe結果を回収し、Journalの `COMPLETED` 永続化にも成功 | `ProbeResult.status.value` | `FINALIZED` | 検証済み `ProbeResult.reason_code` をallowlistから投影 |

`NOT_STARTED` は今回の `probe_one()` 未呼出が確実な場合に限る。`mark_running()`永続化後にクラッシュし、呼出有無が不明なら `RESULT_UNKNOWN`。`NOT_STARTED`でも予約済み未確定レコードがあればJournalの全候補HOLDを維持する。Issue #9の旧試行は独立した `LEGACY_RESULT_UNKNOWN` として残し、今回の `recovery_state` には転記しない。`NOT_STARTED`時の `exit_code=null`、`phase="not_started"`、4証拠 `NOT_OBSERVED`、Probe未呼出で `cleanup_status="not_required"`。`RESULT_UNKNOWN`では `exit_code=null` とし、確認済みの情報以外を推測しない。`FINALIZED`だけ予定CLI終了コード `0|1` を記録する。成功や失敗の偽装、秘密情報・例外本文・生ログの透過出力は禁止。

- [ ] Step 1: `test_list_never_invokes_probe`、`test_exact_id_invokes_probe_once`、`test_missing_candidate_never_reserves_or_probes` を追加。
- [ ] Step 2: `python3 -m unittest tests.test_stage1_fixed_probe -v` でREDを確認。
- [ ] Step 3: `main(argv)`、候補ID照合、Journal公開API、`probe_one()`単発呼出、結果投影、JSON出力を実装。
- [ ] Step 4: `test_issue9_unknown_blocks_empty_journal_without_owner_decision`、`test_issue9_unknown_blocks_different_candidate_without_owner_decision`、`test_owner_approval_must_reference_issue9_and_new_single_attempt`、`test_used_approval_cannot_relaunch`、`test_existing_unknown_attempt_blocks_probe`、`test_pre_reservation_rejection_is_not_started`、`test_legacy_unknown_does_not_become_new_attempt_unknown` を追加してRED→GREEN。
- [ ] Step 5: `test_parallel_different_candidate_is_blocked`（`status=BLOCKED, recovery_state=NOT_STARTED, reason_codes=["preflight_blocked"], attempt_id=null, exit_code=null`、Probe呼出0回をassert）、`test_mark_running_failure_never_calls_probe`、`test_no_probe_invocation_after_reservation_reports_not_started`、`test_journal_complete_failure_never_reports_pass`、`test_cleanup_failure_overrides_pass` をRED→GREEN。
- [ ] Step 6: `test_exit_code_is_nullable_and_cli_not_openvpn`、`test_tun_drop_https_tokyo_evidence_projection`、`test_drop_unverified_is_not_verified`、`test_unreached_is_not_observed`、`test_result_unknown_has_null_exit_code`、`test_started_attempt_without_result_is_unknown`、`test_journal_finalization_failure_never_reports_success`、`test_json_redacts_secrets_and_raw_profile`、`test_untrusted_errors_emit_fixed_codes_only` をRED→GREEN。
- [ ] Step 7: `python3 -m unittest tests.test_stage1_fixed_probe -v` でGREEN確認。
- [ ] Step 8: `python3 -m unittest tests.test_stage1_fixed_candidates tests.test_stage1_attempt_journal tests.test_stage1_fixed_probe tests.test_openvpn_probe -v` でTask 1〜4をまとめて回帰確認。

**Acceptance:** Issue #9既存未回収試行、空Journal、候補変更、Owner承認再利用、固定候補CLI経由の別candidate ID並列のいずれでも無断OpenVPN起動なし。全JSON/Journalフィールドの取得元・型・未取得値が確定。失敗や保存不能でPASSを報告しない。

### Task 5: オフライン受入と実機検証Runbook — RG-VOR-010-001

**Files:** Create `docs/stage1-pre-live.md`。Task 1〜4のテストに必要な既存テストのみ限定変更。

- [ ] Step 1: 基準master/feature HEAD・変更対象・Pythonバージョンを確認。drift時は停止しOwnerへ報告。
- [ ] Step 2: `python3 -m unittest discover -s tests -v` を実行。Expected: 実行対象PASS、skipの理由は記録。
- [ ] Step 3: `python3 -m compileall -q vpn_orbit tests` を実行。Expected: 終了コード0。
- [ ] Step 4: `git diff --check` を実行。Expected: PASS。
- [ ] Step 5: Catalog/GeoIP/OpenVPN/nftables/RunnerをMockし、ネットワーク実通信を禁止した状態でCLIの正常系・失敗系テストを実行。
- [ ] Step 6: `docs/stage1-pre-live.md` にホストと `vpn-orbit-probe` の識別、Preflight、固定候補SHA、**Issue #9のLEGACY_RESULT_UNKNOWN確認**、**Ownerによる新たな1試行の承認判断と制限アクセスOwnerApprovalの確認**、空Journalでは許可されないこと、**固定候補CLIに限る全candidate ID排他と既存cloud_probe非対象**、既存CLI/OpenVPN等が動作していないことの事前確認・並行実行禁止（技術的相互排他は未保証）、実行許可は固定CLIの単発承認のみで既存CLIには及ばないこと、DROP計測の一時 `/32` route→tun0復元・専用ルール撤去の確認と失敗時停止、結果回収、実シェル終了コードとJSON予定終了コードの違い、Cleanupの実リソース不存在、RESULT_UNKNOWN時停止、再試行禁止を記載。
- [ ] Step 7: `test_issue9_unknown_blocks_empty_journal_without_owner_decision` と `test_issue9_unknown_blocks_different_candidate_without_owner_decision` が存在しPASSすることと、Runbookが同一HOLD条件を明記することを確認。
- [ ] Step 8: 実装差分・テスト結果・未実証事項・残余リスクを最終報告しHuman Owner Checkpointで停止。

**Acceptance:** オフラインTDD・既存回帰PASS、旧試行と新Journal両方のFail-Closed確認、固定候補CLIの排他範囲と既存CLIとの技術的非排他をRunbookで明確化し、DROP計測後のtun0経路復元・一時ルール撤去と失敗時FAILを記録する。KVM/GitHub Actions実通信未実施。未実行テストをPASSと呼ばない。

## Integration and Commit Policy

実装は別途Human Owner承認後のみ、既存worktreeを保護して開始。masterが基準からdriftしていれば無断rebaseせず報告。新コードCommit・Push・PR作成は別承認までHOLD。Commit数やレビュー回数の増加を目的としない。初回検証・必要な限定訂正の後はHuman Owner Checkpointへ戻す。

## Completion Gate

1. 承認範囲での実装完成。
2. オフラインTDD・回帰テストPASS。
3. Issue #9 legacy HOLD、**固定候補CLI経由の全candidate ID排他**、DROP計測の一時route復元・ルール撤去失敗時の最終FAIL、Journal障害、JSON投影をオフラインテスト確認（既存CLIとの排他・実カーネル挙動は未実証）。
4. 実行結果・中断状態を回収する仕組み完成。
5. KVM Pre-Live Runbook完成。
6. 実カーネル・実通信・東京出口IPv4の未実証を明記。
7. KVM／GitHub Actions実通信 `NOT_RUN`。
8. Human Owner Checkpointで停止。

これらを満たす時だけ `READY_FOR_LIVE_APPROVAL`。実通信のPASS・運用開始承認を意味しない。

## Stop Conditions and Authority

- HEAD・環境不一致、Namespace/OpenVPN等の不明残存、候補ID不一致、APIキー取扱不明、**Issue #9旧試行に対する新規Owner判断欠落**、空Journalを根拠とする実行、承認ID再利用、固定候補CLI経由の別candidate ID並列、未確定試行、Journal書込み失敗、DROP証拠欠落、Cleanup異常はFail-Closed。
- Design R0.1: APPROVED（方式A維持）
- Design R0.1.4 / Plan R0.1.4: PENDING_OWNER_ADOPTION
- Implementation / Source Changes / Test Execution: HOLD
- GitHub Commit / Push / PR Update / Merge: HOLD
- KVM / GitHub Actions Live: HOLD
- No automatic follow-on Task, independent review or remediation cycle

今回の限定訂正は2文書の修正版提示のみ。Ownerの明示承認なしに次工程を開始しない。
