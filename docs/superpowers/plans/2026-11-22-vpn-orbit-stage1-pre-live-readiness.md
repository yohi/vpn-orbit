# VPN-ORBIT Stage 1 Pre-Live Readiness Implementation Plan R0.1

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` or `superpowers:subagent-driven-development` when implementation is separately authorized. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PENDING_OWNER_ADOPTION / IMPLEMENTATION_HOLD  
**Goal:** 最新masterに固定候補実行、安全な直接通信遮断証拠、実行結果回収を統合し、実機検証直前の状態を完成させる。

**Architecture:** 既存のCloud Probe、OpenVPN Probe、Supervisor、Isolation、Cleanupを再利用する。新しい固定候補CLIとAttempt Journalを追加し、実通信を開始する前に候補同一性と試行予約を確定する。

**Tech Stack:** Python 3.11+、標準ライブラリ、unittest、Linux Network Namespace、nftables、OpenVPN。

**Spec:** [採択済みDesign R0.1](../specs/2026-11-22-vpn-orbit-stage1-pre-live-readiness-design.md)

**Baseline:** `master@7f1ae8cab84a94cea8369e8075b4982b652f1557`  
**Related:** Issue #9 / PR #8 merged

## Global Constraints

- ベースは最新masterとし、開始時に基準HEADとの一致を確認する。
- 既存の通常候補探索CLIとPhase 1〜3の動作を維持する。
- 固定候補モードは1件のみ実行し、再試行・フォールバックを行わない。
- TUN、TLS、DNS、IPv6、Namespace、nftablesの安全条件を緩和しない。
- 実通信はKVM・GitHub Actionsの双方で禁止する（この計画の実装・検証中）。
- APIキー、OpenVPNプロファイル本文、生ログ、秘密鍵を成果物に含めない。
- Cleanup失敗はFAILを優先する。
- RESULT_UNKNOWNはPASS、FAIL、NOT_VERIFIEDとは区別する。
- Pythonの新規外部依存を追加しない。
- 実装開始、GitHubへのコードCommit・Push・PRには別途Human Ownerの明示承認を必要とする。
- 本計画の文書Commit・PRは、実装・実通信の承認を意味しない。

## Review Focus

設計で明示された境界に加えて、次の実利用上の失敗条件を各TaskのTDDで固定する。

1. **プロファイル変更:** 同じIP・portでもプロファイルが変わったら古いIDを拒否する（Task 1）。
2. **偽の遮断証拠:** curlがタイムアウトしてもDROPカウンターが増えなければFAILとする（Task 2）。
3. **未確定予約:** プロセス再起動後に未完了のJournalが残ればRESULT_UNKNOWNを維持し実行禁止（Task 3）。
4. **状態ディレクトリ攻撃:** symlink・権限不正・書込み不可ならOpenVPN起動前にBLOCKED（Task 3/4）。
5. **終了報告不整合:** Probe成功でもCleanupまたはJournal確定に失敗した場合、成功として出力しない（Task 4）。

## File Structure

### New files

- `vpn_orbit/fixed_candidates.py`: 候補ID生成・一覧・固定照合
- `vpn_orbit/attempt_journal.py`: 予約・排他・結果永続化
- `vpn_orbit/stage1_fixed_probe.py`: 固定候補CLI・実行統合
- `tests/test_stage1_fixed_candidates.py`: 候補識別
- `tests/test_stage1_attempt_journal.py`: 状態管理の失敗系
- `tests/test_stage1_fixed_probe.py`: CLI統合・試行回収
- `docs/stage1-pre-live.md`: 実機検証直前のRunbook

### Existing files

- `vpn_orbit/live_runner.py`: `host_direct_route_rejected`へのDROP証拠統合
- `vpn_orbit/openvpn_probe.py`: `_verify_routes`による安全判定の接続（必要最小限）
- `tests/_probe_live_cases.py`: Runnerの固定コマンド・判定テスト
- `tests/test_openvpn_probe.py`: 既存unittest集約の調整（必要時のみ）
- `vpn_orbit/isolation.py` / `vpn_orbit/runner_types.py`: 必要な契約変更時のみ。Supervisor再設計は禁止

---

### Task 1: 固定候補IDと選択契約

**Files:**
- Create: `vpn_orbit/fixed_candidates.py`
- Create: `tests/test_stage1_fixed_candidates.py`
- Reuse: `vpn_orbit/cloud_probe.py`

**Interfaces:**

```python
def candidate_id(candidate: ScreenedCandidate) -> str: ...
def fixed_shortlist(
    catalog: str,
    geo_lookup: Callable[[str], GeoDecision],
) -> tuple[ScreenedCandidate, ...]: ...
def resolve_fixed_candidate(
    candidates: Sequence[ScreenedCandidate],
    requested_id: str,
) -> ScreenedCandidate | None: ...
```

`candidate_id`はDesign記載の `SHA256(f"{ip}:{port}/{protocol}\n" + profile)` をUTF-8プロフィールで計算する。`fixed_shortlist` は `screen_candidates(..., scan_window=40, limit=10, reachable=None)` を使用し、候補確認のための直接TCP事前疎通をしない。`resolve_fixed_candidate`は不正ID・重複IDで例外を返し、候補不在はNone。

- [ ] Step 1: `test_candidate_id_uses_exact_profile_bytes`、`test_profile_change_changes_id`、`test_fixed_shortlist_uses_existing_ranking_without_tcp_preflight` を追加する。
- [ ] Step 2: `python3 -m unittest tests.test_stage1_fixed_candidates -v` を実行しREDを確認する。
- [ ] Step 3: 上記3関数を最小実装する（IDは64文字の小文字16進数）。
- [ ] Step 4: `test_missing_id_never_selects_another_candidate`、`test_invalid_id_is_rejected`、`test_duplicate_id_is_blocked`、`test_empty_catalog_never_probes` を追加しRED→GREENを確認する。
- [ ] Step 5: 対象テストモジュールを再実行し全PASSを確認する。

**Acceptance:** 指定候補のみ照合でき、候補消失・プロファイル変更で別候補を選ばない。OpenVPN起動なし。

### Task 2: DROPカウンター証拠の統合

**Files:**
- Modify: `vpn_orbit/live_runner.py` — `host_direct_route_rejected()`
- Modify if needed: `vpn_orbit/openvpn_probe.py` — `_verify_routes()`
- Test: `tests/_probe_live_cases.py`

**Interface (既存Runner契約を維持):**

```python
def host_direct_route_rejected(
    self,
    echo_ip: str,
    resources: IsolationResources,
    deadline: float,
) -> tuple[bool, str]: ...
```

**Implementation contract:** Namespace内のnftables outputに、指定echo IPv4・TCP/443・veth出力インターフェースだけを対象とする識別可能な `counter drop` ルールを設置。同じルールを実行前後で検証し、パケット数の厳密な増加とcurl終了コード7/28の両方を必要とする。既存のVPNサーバー許可・TUN HTTPS許可・DNS/IPv6拒否・デフォルトDROPを維持する。 `ip route get ... oif` は補助情報に限定。

- [ ] Step 1: `test_curl_refused_and_counter_advanced_is_verified` を追加する。
- [ ] Step 2: `test_curl_timeout_without_counter_increment_is_fail` と `test_successful_direct_curl_is_fail` を追加する。
- [ ] Step 3: `test_counter_read_failure_is_fail`、`test_malformed_nft_json_is_fail`、`test_unexpected_counter_identity_is_fail` を追加する。
- [ ] Step 4: `python3 -m unittest tests.test_openvpn_probe -v` のREDを確認する。
- [ ] Step 5: 既存のRunnerメソッドに専用ルールと前後カウンター判定を限定実装する。
- [ ] Step 6: 同テストを実行しGREENを確認する。
- [ ] Step 7: 既存のTUN HTTPS許可・ホストデフォルト経路不変・Cleanup失敗優先も回帰テストする。

**Acceptance:** curl拒否だけではPASSにならず、カウンター欠落・不一致・不増加・取得失敗はFAIL。実カーネルでの検証は未実施と明記する。

### Task 3: Attempt Journal

**Files:**
- Create: `vpn_orbit/attempt_journal.py`
- Create: `tests/test_stage1_attempt_journal.py`

**Interfaces:**

```python
class AttemptJournal:
    def __init__(self, root: Path) -> None: ...
    def reserve(
        self,
        *,
        candidate_id: str,
        ingress: str,
        head: str,
    ) -> AttemptHandle: ...
    def complete(
        self,
        handle: AttemptHandle,
        *,
        result: dict[str, object],
        exit_code: int,
    ) -> None: ...
```

`AttemptHandle` は `attempt_id` と保持中の排他ロックを管理する型。成功・異常終了時に安全な解放を実装し、未完了レコードを勝手に消さない。

**Storage contract:** `/var/lib/vpn-orbit/stage1-attempts`、root所有・ディレクトリ0700・ファイル0600。`fcntl.flock`、原子的なファイル作成・更新・必要な `fsync`、不正所有者・権限・symlink拒否。識別子は予測困難な一意値。未確定予約は `RESULT_UNKNOWN` として次回の実行を拒否する。Journalに鍵・プロファイル・生ログを保存しない。

- [ ] Step 1: `test_reserve_creates_restricted_durable_record` と `test_duplicate_active_reservation_is_blocked` を追加する。
- [ ] Step 2: `python3 -m unittest tests.test_stage1_attempt_journal -v` のREDを確認する。
- [ ] Step 3: ディレクトリ検証、排他、予約レコードの原子的保存を最小実装する。
- [ ] Step 4: `test_unfinished_record_is_result_unknown_after_restart`、`test_symlink_path_is_blocked`、`test_unwritable_store_is_blocked` を追加しRED→GREENを確認する。
- [ ] Step 5: `complete()` による終了状態・終了コード・Cleanup結果の永続化を実装する。
- [ ] Step 6: `test_failed_commit_never_reports_completed`、`test_secret_values_are_not_serialized` をRED→GREENにする。
- [ ] Step 7: Journalテストを再実行し全PASSを確認する。

**Acceptance:** 未完了試行の自動再試行なし。結果未回収をRESULT_UNKNOWNとして読める。書込み異常は起動前にBLOCKED。

### Task 4: 固定候補CLIと結果回収の統合

**Files:**
- Create: `vpn_orbit/stage1_fixed_probe.py`
- Create: `tests/test_stage1_fixed_probe.py`
- Reuse: `vpn_orbit/openvpn_probe.py`、`vpn_orbit/cloud_probe.py`

**Interface:**

```python
def main(argv: list[str] | None = None) -> int: ...
```

**CLI contract:**

```bash
python3 -m vpn_orbit.stage1_fixed_probe --list
python3 -m vpn_orbit.stage1_fixed_probe --probe-id <64-character-id>
```

`--list` はCatalog取得・GeoIP照会と候補一覧出力だけを行い、Probeを呼ばない。`--probe-id` は完全一致した1候補だけを選定し、Journal予約を永続化してから `probe_one()` を**1回だけ**実行する。自動再試行・フォールバックなし。APIキーはGeoIP照会専用で、OpenVPN環境やJournalに渡さない。

**JSON contract:**

- `attempt_id`, `candidate_id`, `status`, `recovery_state`, `reason_codes`
- `exit_code`, `phase`, `cleanup_status`
- `tun_evidence`, `drop_evidence`, `tunnel_https_evidence`, `tokyo_geoip_evidence`

各段階の証拠は既存のProbeResultの検証済みフィールドと限定された証拠コードから投影する。未確認値を推測で補完せず、出力を固定スキーマに限定する。

- [ ] Step 1: `test_list_never_invokes_probe`、`test_exact_id_invokes_probe_once` を追加する。
- [ ] Step 2: `python3 -m unittest tests.test_stage1_fixed_probe -v` のREDを確認する。
- [ ] Step 3: 引数解析、固定候補照合、Journal予約、Probe呼び出しを最小実装する。
- [ ] Step 4: `test_missing_candidate_never_reserves_or_probes`、`test_missing_geoip_key_blocks_before_probe`、`test_existing_unknown_attempt_blocks_probe` をRED→GREENにする。
- [ ] Step 5: `test_successful_probe_persists_result`、`test_cleanup_failure_overrides_pass`、`test_journal_failure_never_reports_pass` をRED→GREENにする。
- [ ] Step 6: `test_json_redacts_secrets_and_raw_profile`、`test_untrusted_errors_emit_fixed_codes_only` をRED→GREENにする。
- [ ] Step 7: Task 1〜4の全テストを実行しPASSを確認する。

**Acceptance:** 指定した候補に限り1回実行。結果不明・Journal異常・Cleanup異常・安全証拠不足では正常完了扱いにしない。既存 `vpn_orbit.cloud_probe` CLIは変更しない。

### Task 5: オフライン受入・実機検証Runbook

**Files:**
- Create: `docs/stage1-pre-live.md`
- Modify existing tests only as required by Tasks 1–4

- [ ] Step 1: 実行対象HEAD・変更対象・Pythonバージョンを確認する。
- [ ] Step 2: `python3 -m unittest discover -s tests -v` を実行する（全実行対象PASS、skipは理由を記録）。
- [ ] Step 3: `python3 -m compileall -q vpn_orbit tests` を実行し終了コード0を確認する。
- [ ] Step 4: `git diff --check` を実行しPASSを確認する。
- [ ] Step 5: ネットワークアクセスとOpenVPN起動をMockで拒否したCLI正常系・異常系を実行する。
- [ ] Step 6: `docs/stage1-pre-live.md` にゲスト識別、Preflight、固定候補選定、対話型APIキー入力、Journal確認、Cleanup確認、実行中断時停止条件、Human Owner承認ゲートを記載する。
- [ ] Step 7: 無関係な機能変更と秘密情報混入がないことを確認する。
- [ ] Step 8: テスト結果・未実証事項・残余リスクを最終報告して停止する。

**Acceptance:** オフラインTDD・回帰PASS、固定候補1件のみ、DROP/Jounal/失敗系がFail-Closed、Runbook完成。実機検証は行わない。

## Integration and Commit Policy

実装開始は別途Human Ownerが許可する場合のみ、`superpowers:using-git-worktrees` を使い、既存worktreeを保護する。

master HEADが計画基準から変化していたら差分を報告し、無断rebase・cherry-pick・実装を行わない。

実装Commit／Push／PRは別途承認されるまで禁止。実装時の論理的Commit単位はTask 1〜4の独立成果物とTask 5の受入成果物。Commit数の増加は目的としない。

Taskごとの新しい独立レビューを機械的に連鎖させず、初回の限定検証・必要な限定訂正の後にHuman Ownerの判断を置く。

## Completion Gate

次のすべてを満たした場合のみ `READY_FOR_LIVE_APPROVAL` とする。

1. 実装が固定スコープで存在し、検証可能。
2. オフラインTDD・回帰テストPASS。
3. 安全境界の失敗系テストPASS。
4. 実行結果・中断状態を回収できる仕組みが存在。
5. 実機検証Runbookが完成。
6. 未実証事項と残余リスクが明示されている。
7. **KVM・GitHub Actionsでの実通信は未実行**。
8. Human Owner Checkpointで停止。

オフラインMockのPASSを実LinuxカーネルのDROP証拠や東京出口IPv4の実証と混同しない。

## Stop Conditions and Authority

- Preflight不一致、環境相違、候補ID不一致、Namespace/OpenVPN等の残存、APIキー不明、Journal書込み失敗、DROP証拠不備、Cleanup異常、試行結果未回収ならFail-Closed。
- Design Adoption: APPROVED
- Plan Adoption: PENDING
- Implementation Authorization: HOLD
- Source Code Writes: HOLD
- KVM Live: HOLD
- GitHub Actions Live: HOLD
- Documentation-only feature branch / commits / PR: authorized separately

計画文書をGitHubに置いたことによって実装を自動開始しない。
