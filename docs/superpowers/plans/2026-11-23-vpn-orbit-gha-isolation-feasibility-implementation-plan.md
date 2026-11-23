# VPN-ORBIT GitHub-hosted Runner Isolation Feasibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GitHub-hosted `ubuntu-latest`標準Runnerで、VPN接続なしにLinuxのNamespace／veth／TUN／nftablesの隔離機能とCleanup成立性を一度だけ実証できる、手動起動専用のゲートを作る。

**Architecture:** `vpn_orbit/gha_isolation_feasibility.py`に外部接続を行わない、自己完結するKernel Smoke Testを実装し、`.github/workflows/gha-isolation-feasibility.yml`から特権コマンドとして実行する。Hostのdefault routeおよび`ip_forward`を変えず、検証用Namespace・veth・nftablesのみ一時作成し、必ずCleanupと独立したreadbackを行う。成果は限定的なKernel Capability Verdictであり、OpenVPN実通信や東京出口の証拠にはならない。

**Tech Stack:** Python 3.11+標準ライブラリ、Linux iproute2/nftables、GitHub Actions `ubuntu-latest` standard hosted runner、unittest。新規Python依存なし。

**Spec:** `docs/superpowers/specs/2026-11-23-vpn-orbit-zero-cost-tokyo-automation-design.md`（Human Owner ADOPTED R0.1。対象featureブランチに追加済み、master未反映。Spec採択は実装・Commit/Push・Dispatch承認ではない）

## Global Constraints

- リポジトリ：`yohi/vpn-orbit`。設計時基準HEAD：`master@f54e5db35cfad3094521c5d5f191fc5b9e7324a4`。実装時に基準ドリフトを確認し、コードに合わせて最小限更新する。
- 追加費用0円：Publicリポジトリのstandard GitHub-hosted Linux Runnerを使用。larger runner、有料プラン、自宅Host、self-hosted runner、Cloudflare Containersは禁止。
- 初回の検証は**実OpenVPN接続なし**、VPN Gate CSV取得なし、GeoIP照会なし、Cloudflare API/KV書込みなし。
- `workflow_dispatch`のみ。Cron、push、pull_request、pull_request_target、workflow_runで起動しない。**Workflowはdefault branch上に存在するまで通常はdispatch不可**。新規Workflowをdefault branchへ取り込む操作と実際のDispatchは別々の明示Owner承認を要する。
- **実行Identity F-001**：Owner承認は`(workflow_definition_commit_sha, workflow_blob_sha, dispatch_ref, code_commit_sha, smoke_blob_sha)`の5要素を**各フルSHA／完全Ref**で特定する。どれか未固定・不一致・未承認ならDispatch不可。`workflow_definition_commit_sha`は実行Workflowを含むCommit、`code_commit_sha`は特権Smokeの凍結済み実装を含むCommitであり、両者は別物として扱う。SmokeはPython標準ライブラリだけをimportする単独ファイル（`/usr/bin/python3 -I -S <検証済みSmokeファイル絶対パス>`で直接実行）とし、未承認のリポジトリ内モジュールを特権実行しない。
- **Dispatch Refの承認**：Workflowは`refs/heads/feature/vpn-orbit-gha-isolation-feasibility-design-20261123`を唯一の許可Refとする（将来Ref変更はOwner再承認）。default branch上でWorkflowを有効化する承認と、対象feature Refの**Workflow定義Commit**を選択して1回Dispatchする承認は別。OwnerはDispatch直前に`dispatch_ref`の現在HEAD、対象WorkflowファイルBlobが承認タプルと一致することをGitHub readbackで確認する。**同一Workflowファイルに自己Commit SHAを埋め込むことはできない**ため、実行中YAMLが自分自身のOwner承認済みCommitであることをYAMLだけで保証したと主張しない。OwnerによるRef/HEAD固定確認が実証不可能な場合はDispatchを承認せずSTOPする。**mutableな`dispatch_ref`では、OwnerのreadbackとDispatchの間のRef更新を完全に排除する原子的保証はない**。`github.sha`／checkout HEADの一致検査はJobが参照したCommitを照合するものであり、OwnerがreadbackしたWorkflow定義Commitと実際に実行されたWorkflow定義の一致まで保証しない。この残余リスクをOwnerが別途明示的に受容しない限りDispatchは`HOLD`。保護Refや別方式への切替は自動採用せず、Ownerの別承認を要する。
- **特権起動前ゲート**：Workflow Jobはcheckout Actionの固定フルSHAと`persist-credentials: false`を用い、先に`github.ref == approved dispatch_ref`を検査。Workflow側checkout HEADが`github.sha`と一致することを確認し、別途承認済み`code_commit_sha`を**SHA指定でcheckout**、`git rev-parse HEAD == code_commit_sha`および`git hash-object vpn_orbit/gha_isolation_feasibility.py == smoke_blob_sha`を確認する。テスト／特権実行は検証済みコードからのみ行う。期待SHAはWorkflow定義に固定し、未承認Ref・未固定SHA・readback失敗・比較不一致ではsudoへ進まず非0終了。`actions/checkout@<SHA>`固定は**Action本体**だけを固定し、Repositoryのcheckout対象Commit/Blobを保証しない。Workflow inputs/`vars`/SecretsによるIdentity上書きを許さない。
- `permissions: contents: read`、`actions/checkout`は固定SHAを検証して使用し`persist-credentials: false`。workflowにSecretsを注入せず、特権Pythonプロセスへ`GITHUB_TOKEN`・認証情報・環境変数全体を渡さない。
- Shellの`set -x`を使用せず、出力は固定コード、Python／Kernel version、合否、許可済み一時リソース名とcleanup結果のみ。`env`、secret、Profile原文、Client Key、例外stacktraceは出力しない。
- **限定OS実行 F-002**：絶対パス`/usr/sbin/ip`、`/usr/sbin/nft`、`/usr/bin/python3`だけ（名前空間内の固定UDP送信コードのみ）を許可し、実行前に`os.geteuid()==0`を確認。`CommandRunner.run()`のみ、`shell=False`、固定`env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LANG":"C","LC_ALL":"C"}`、`cwd="/"`、stdin閉鎖、stdout/stderr各4096 bytes上限、コマンドごと`0 < timeout_s <= 5.0`、Smoke全体90秒上限、timeout時は実行プロセス群kill/wait。非0、起動失敗、超過出力、timeoutは`BLOCKED`とし、Cleanupは別の有界deadlineで試す。raw stderrや例外・環境情報はstdoutへ出さない。
- **一時リソース F-002**：`scope`は`^[a-z0-9]{1,8}$`、nonceは`secrets.token_hex(4)`の8文字小文字hex。Namespaceは`vof-<scope>-<nonce>-tx`/`-rx`、専用veth名は`vt<nonce>`/`vr<nonce>`、TUN名`voftun0`、nftは**送信Namespace内**の`inet vof_<nonce> out`だけ。Namespaceを2つ作りveth両端を各Namespaceに配置するため、Hostにveth・IP・経路・Firewallを追加しない。両Namespaceにdefault routeを置かない。テスト専用IPv4は`198.18.0.1/30`（送信側）と`198.18.0.2/30`（受信側）のみ。
- **所有・競合 F-002**：Namespace名・Link名・nft名の**作成前不存在**をreadbackし、衝突時は未所有実体に触れず`BLOCKED`。`planned_ns`は生成nonceと事前不存在確認で**作成を許された名前集合**であり、所有権の証拠ではない。`ip netns add`は`planned_ns`に属する名前に限る。作成コマンドのexit 0と直後の名前・所属・専用実体readbackが成功した時だけ、その名前を`owned_ns`へ遷移させる。`ip netns del`は`owned_ns`だけに許可する。作成失敗時に不存在が確証された場合は`BLOCKED`、成否不明・readback不成立・他者所有が疑われる場合は削除せず、残留または不存在未確認なら`CLEANUP_FAILED`とする。他者・未所有Resourceの削除は禁止。Namespace以外の`owned`も作成成功と実体readbackの両方で確定させる。作成済み所有対象は逆順でCleanupし、失敗後も残りの所有対象に対してCleanupを試行する。**Host初期snapshotとCleanup後の独立readbackは同一の`/usr/sbin/ip -j -4 route show table all`を使い、全IPv4 routing tableを比較する**。両方の結果はexit 0かつ有効なJSONであることを要求し、比較不能・取得不能・不正JSONはPASSとしない。初期snapshot失敗は`BLOCKED`、Cleanup後のreadback不成立・route差分・`ip_forward`差分・許可済み一時Resourceの残留は`CLEANUP_FAILED`を優先する。
- **許可argv F-002**：`/usr/sbin/ip`の`-j -4 route show table all`／`netns list`／`netns add <planned_ns>`／`netns del <owned_ns>`／`-n <owned_ns> link add|set|show|del`（作成したveth・TUNだけ）／`-n <owned_ns> addr add|show`（専用アドレスだけ）／`-n <owned_ns> route get 198.18.0.2`／`-n <owned_ns> tuntap add|del dev voftun0 mode tun`、`ip netns exec <owned_tx_ns> /usr/sbin/nft ...`（下記固定テーブル・チェーン・ルールのadd/list/deleteだけ）、`ip netns exec <owned_tx_ns> /usr/bin/python3 -I -S -c <固定UDP送信コード定数>`のみ。`-c`引数は単一の承認済み固定コード定数との完全一致だけを許容し、未承認のimport・引数変更を禁止する。引数はトークン単位で許可構文と照合する。`sh`/`bash`、`curl`、`openvpn`、apt、外部IP宛接続、任意コマンド、Host route/`ip_forward`変更、Host nft変更は許可しない。
- **DROP F-003**：送信Namespaceの`nft add table inet vof_<nonce>`、`add chain inet vof_<nonce> out { type filter hook output priority 0; policy accept; }`、`add rule inet vof_<nonce> out oifname vt<nonce> ip daddr 198.18.0.2 udp dport 9 counter drop`（順序・要素固定）を許可。`nft -j list chain inet vof_<nonce> out`から対象ルールの構文、counter packets/bytes、hook等をreadbackし、試験前`before.packets == 0`、送信Namespaceから受信専用vethへ単発UDP（ポート9、payloadは固定3 bytes）、試験後`after.packets - before.packets == 1`かつ`after.bytes > before.bytes`を要求する。送信前にRouteが専用vethに限定されdefault route不在であることを確認。Counter不変・解析不能・ルール不一致・送信失敗は`BLOCKED`。送信成功だけでDROP成功と扱わない。
- **Namespace IPv4経路readbackの許可argv追補（RG-003 / F-002）**：上記「許可argv F-002」の固定許可集合に、読取専用`/usr/sbin/ip -n <owned_ns> -j -4 route show table all`を追加する。`<owned_ns>`は生成成功・所属readback済みの送信`owned_tx_ns`または受信`owned_rx_ns`の実名との完全一致のみ許可し、**両方で各1回以上**送信前に実行する。送信側の宛先経路判定に用いる既存`/usr/sbin/ip -n <owned_ns> route get 198.18.0.2`は`owned_tx_ns`に限る。これ以外の`route show`（`table all`省略、`-j`/`-4`省略、他Namespace・引数・操作の差し替えを含む）はOS起動0件で拒否する。Host経路変更・Namespace経路変更を新たに許可しない。追加の依存関係・権限・ネットワーク通信は不要。
- **送信前のNamespace経路安全ゲート（RG-003）**：上記両Namespaceの全IPv4 route readbackのexit 0・JSON配列／各経路objectの構文と比較可能性を検証する。`default`または`0.0.0.0/0`の経路が送信側・受信側の**いずれのtableにも存在しないこと**、main tableの転送可能経路が各Namespaceの`198.18.0.0/30`・専用veth（tx=`vt<nonce>`／rx=`vr<nonce>`）に限定され、local tableも当該IPv4とloopback由来のkernel生成local/broadcast経路に限定されることを要求する。想定外table・gateway/via・追加経路・不正または不確定な経路属性は拒否する。さらに`owned_tx_ns`の`route get 198.18.0.2`が`dev vt<nonce>`・`src 198.18.0.1`でありgateway/via・別devを含まないことを確認する。**全条件PASSの前には固定UDPを1件も送らない**。readback起動失敗・非0・timeout・JSON不正・欠損・比較不能・default route・想定外経路・`route get`不一致は`BLOCKED`（`checks["nft_drop"]="BLOCKED"`、既存`reason_codes`の`DROP_UNVERIFIED`を使用）とし、Owned Cleanupを継続する。Cleanup／Host最終readbackに問題があれば既存優先順位の`CLEANUP_FAILED`が上書きする。固定7 Checksキー・CLI JSON型・5秒/command・90秒/Smokeの契約は変えない。
- 非Network操作の能力確認でも、操作は実行前に許可された一時リソース名だけ。既存プロセス／Firewall／routeには触れない。
- **Verdict優先順位**：Cleanup／独立readback／Host保全の異常=`CLEANUP_FAILED`が常に最優先。次にIdentity不一致・権限不足・command失敗・DROP証拠不足=`BLOCKED`。全条件確認済みの場合だけ`KERNEL_CAPABILITY_PASS`。Job未実行=`NOT_RUN`、強制終了で最終結果未確定=`UNKNOWN`（いずれもPASSではない）。
- Issue #9 `LEGACY_RESULT_UNKNOWN`を維持。Stage 1固定候補CLI、Journal、OwnerApproval、既存Runnerの実行経路を変更しない。
- 設計採択はコード変更、GitHub commit/push/PR、Workflow起動、外部サービス書込みの許可ではない。各実行許可は別Checkpointで取得する。
- Review Loop Prevention：限定テストと必要な局所訂正を行ったらOwner判断へ。機械的な独立レビュー連鎖を作らない。

## Review Focus

1. **実行Identity不一致**：未承認Ref、Source Commit、Smoke blob不一致はsudo起動0件で`BLOCKED`（Task 2の`test_workflow_rejects_unapproved_ref_or_source_identity`）。
2. **Namespace衝突・生成成否不明**：事前不存在の`planned_ns`に限り生成し、作成exit 0＋readback後の`owned_ns`だけ削除。他者・未所有Resourceを削除せず、不確実残留は`CLEANUP_FAILED`（Task 1の`test_planned_ns_add_allowed_before_ownership`、`test_netns_del_requires_confirmed_owned_ns`、`test_preexisting_name_collision_never_deleted`、`test_ambiguous_creation_not_deleted`）。
3. **DROP実効性なし**：ruleの`counter drop`・before/after・宛先route・単発UDPを確認できなければ`BLOCKED`（Task 1の`test_nft_drop_counter_not_incremented`）。
4. **CleanupまたはHost保全失敗**：初期と最終の`ip -j -4 route show table all`を使った全IPv4 routing table比較を必須とし、最終readbackの取得・JSON・比較失敗も`CLEANUP_FAILED`を優先。後続Owned対象もCleanupする（Task 1の`test_host_ipv4_route_snapshot_all_tables`、`test_cleanup_route_readback_failure_is_cleanup_failed`、`test_cleanup_failure_overrides_capability_pass`）。
5. **Workflow権限・起動拡大**：Secretsを特権環境に渡さず、起動は`workflow_dispatch`のみ（Task 2の`test_workflow_does_not_pass_secrets`、`test_workflow_only_manual_dispatch`）。

---

## File Structure

- **Create** `vpn_orbit/gha_isolation_feasibility.py` — 今回だけのKernel Capability Smoke、固定スキーマの結果、Cleanup、CLI。
- **Create** `tests/test_gha_isolation_feasibility.py` — 実カーネルやネットワークを操作しないモック単体テスト。
- **Create** `.github/workflows/gha-isolation-feasibility.yml` — `workflow_dispatch`限定の手動Workflow。既存WorkerデプロイWorkflowとは分離。
- **Create** `tests/test_gha_isolation_workflow.py` — Workflowの起動経路・権限・Secrets非使用などの静的契約テスト。YAMLパーサーの新規依存は増やさず、対象Workflowの固定テンプレートとキーを精密に検査する。
- **Reference existing adopted spec** `docs/superpowers/specs/2026-11-23-vpn-orbit-zero-cost-tokyo-automation-design.md` — 対象featureブランチへ追加済み。master未反映・実装未承認。
- **This plan's target** `docs/superpowers/plans/2026-11-23-vpn-orbit-gha-isolation-feasibility-implementation-plan.md`。
- **Do not modify** `vpn_orbit/stage1_fixed_probe.py`、`vpn_orbit/attempt_journal.py`、既存`worker/`、既存Workflow。

## Task 1: Offline-tested Linux Isolation Capability Smoke

**Files:**
- Create: `vpn_orbit/gha_isolation_feasibility.py`
- Test: `tests/test_gha_isolation_feasibility.py`

**Interfaces:**
- `CommandResult`（frozen dataclass）：`argv: tuple[str, ...]`、`returncode: int | None`、`stdout: str`、`stderr: str`、`timed_out: bool`、`spawn_failed: bool`。タイムアウト／起動失敗なら`returncode=None`、`stdout`/`stderr`は上限内の診断用内部値（外部に生出力禁止）。上限超過は成功ではない。戻り値の非0・`None`を正常値に変換しない。
- `CommandRunner.run(argv: tuple[str, ...], *, timeout_s: float) -> CommandResult`：唯一のOS command境界。許可された絶対パスと固定argv文法だけを許容し、`shell=False`、固定allowlist env、5秒上限、stdout/stderr各4096 bytes上限、timeout時の子プロセス群回収を強制。拒否されたargvは**OS起動0件で`CommandRejected`例外**、`run_smoke`が固定Reason Codeの`BLOCKED`に変換する。FakeRunnerも同一`CommandResult`型を返す。
- `SmokeVerdict`（frozen dataclass）：`verdict: Literal["KERNEL_CAPABILITY_PASS", "BLOCKED", "CLEANUP_FAILED", "UNKNOWN"]`、`reason_codes: tuple[str, ...]`、`checks: dict[str, Literal["PASS", "BLOCKED", "NOT_RUN", "UNKNOWN"]]`。`checks`のキーは`namespace`,`veth`,`tun`,`nft_drop`,`host_route`,`ip_forward`,`cleanup`に固定。理由コードは`IDENTITY_MISMATCH`,`PREREQUISITE_MISSING`,`RESOURCE_COLLISION`,`OWNERSHIP_AMBIGUOUS`,`COMMAND_FAILED`,`COMMAND_TIMEOUT`,`OUTPUT_LIMIT`,`DROP_UNVERIFIED`,`CLEANUP_INCOMPLETE`,`HOST_STATE_CHANGED`から選択し、生例外を露出しない。
- `run_smoke(runner: CommandRunner, *, scope: str) -> SmokeVerdict`：`scope`は`^[a-z0-9]{1,8}$`。承認済み前提で2つの閉じた一時Namespace、専用veth、TUN、専用nftを検証し、作成成功確認済みの所有対象だけCleanup、最後に独立readback。Cleanup失敗を最優先。
- `main() -> int`：CLI引数なしで**固定`scope="gha"`**を渡し、`{ "verdict": str, "reason_codes": [str], "checks": {<固定7キー>: str} }`のJSON1件だけ出力。追加引数は実行前`BLOCKED`。PASS時のみ0、それ以外は非0。Workflow/Identity gateの`NOT_RUN`はSmoke内部のVerdictではなく実行前状態。

- [ ] **Step 1: Write failing tests** in `tests/test_gha_isolation_feasibility.py`。テスト名と期待値：
  - `test_safe_scope_rejects_shell_metacharacters`：不正scopeで実行コマンド0件、`BLOCKED`。
  - `test_command_result_fields_and_rejects_unapproved_argv`：`CommandResult`の6フィールドと固定argv構文。Host IPv4 routeは`/usr/sbin/ip -j -4 route show table all`だけ許可し、`table all`省略・不許可パス・shell・引数変更は実行0件で`BLOCKED`。
  - `test_command_timeout_nonzero_and_output_limit_block`：timeout/非0/4096 bytes超過は`BLOCKED`、Owned Cleanup継続。
  - `test_namespace_create_failure`：事前不存在確認済みNamespaceの生成拒否・生成後不存在確定で`BLOCKED`、作成済みOwnedだけCleanup、Host route変更0回。
  - `test_planned_ns_add_allowed_before_ownership`：不存在確認済み名前が`planned_ns`にある段階では`ip netns add`を許可するが、`owned_ns`へは追加しない。
  - `test_netns_del_requires_confirmed_owned_ns`：`ip netns del`は作成exit 0・所属readback後の`owned_ns`のみ許可し、`planned_ns`と既存・所有不明NamespaceへのdeleteはOS実行0件。
  - `test_preexisting_name_collision_never_deleted`：衝突した既存Namespace/Link/Tableを`planned_ns`へ登録せず、削除コマンド0件、`BLOCKED`。
  - `test_ambiguous_creation_not_deleted`：Namespaceの作成タイムアウト・非0で所有未確定なら`owned_ns`へ移さずdelete 0件。不存在確認ができないか残留すれば`CLEANUP_FAILED`。
  - `test_tun_missing_or_creation_denied`：`/dev/net/tun`欠落またはTUN作成拒否で`BLOCKED`、Owned Cleanup実施。
  - `test_nft_rule_definition_and_counter_delta_one`：`inet vof_<nonce> out`のhook/output/priority/policy/`counter drop`が一致し、送信側UDP/9 1件でcounter差分が正確に1、bytes増加、専用veth routeを確認して初めてDROP=`PASS`。
  - `test_nft_drop_counter_not_incremented`：counter差分0、読み取れないcounter、drop文言不足、宛先route不一致、送信失敗のいずれも`BLOCKED`。
  - `test_host_ipv4_route_snapshot_all_tables`：初期Snapshot・Cleanup後独立readbackの双方で`/usr/sbin/ip -j -4 route show table all`を呼び、main以外のtableを含めJSONを検証して同じ全経路集合を比較する。
  - `test_host_ipv4_route_initial_failure_blocks`：初期route取得不能・非0・JSON不正・比較前処理不能は`BLOCKED`で、Kernel操作を開始しない。
  - `test_cleanup_route_readback_failure_is_cleanup_failed`：Cleanup後のroute取得不能・JSON不正・比較不能・main以外のtable差分はいずれも`CLEANUP_FAILED`。
  - `test_cleanup_failure_overrides_capability_pass`：一部Cleanup失敗後も他のOwnedを処理、全table route/`ip_forward`差分または残留があれば`CLEANUP_FAILED`。
  - `test_no_vpn_or_external_network_command`：OpenVPN、curl、GET、外部宛通信、Host route/`ip_forward`やHost Firewall変更のargvが一件もない。
  - `test_success_requires_cleanup_and_route_unchanged`：前後の`ip -j -4 route show table all`のJSON正常取得と全table前後一致、`ip_forward`不変、全Owned Namespace/Link/Table不在の独立readbackを満たす場合だけ`KERNEL_CAPABILITY_PASS`。
  - `test_main_redacts_errors_and_uses_fixed_schema`：例外や環境値をログに露出せず、固定JSON3キーのみ出力。
  - `test_namespace_route_readback_allowlist_tx_rx_only`：固定`/usr/sbin/ip -n <owned_ns> -j -4 route show table all`を`owned_tx_ns`/`owned_rx_ns`にのみ許可。`planned_ns`・既存・所有不明Namespace、`table all`/`-j`/`-4`省略、argv差し替えはOS起動0件で拒否。既存のtx `route get 198.18.0.2`だけを宛先選択確認に使用する。
  - `test_namespace_routes_require_no_default_and_only_dedicated_veth`：送受双方のJSON全IPv4 tableにdefault route（`default`/`0.0.0.0/0`）なし、mainは`198.18.0.0/30`の専用veth接続経路のみ、localは当該アドレスとloopbackのkernel生成経路のみを許容。想定外table・経路・gateway/via・dev・属性欠損では`BLOCKED`、UDP送信0件。
  - `test_tx_route_get_requires_dedicated_veth_and_source`：`198.18.0.2`宛の送信側`route get`で`dev vt<nonce>`、`src 198.18.0.1`、gateway/via不在を必須とし、別dev・src・gateway・不正readbackでは`BLOCKED`、UDP送信0件。
  - `test_namespace_route_readback_failure_blocks_before_udp`：送受いずれかのroute readbackの非0・timeout・JSON不正・配列／object欠損・比較不能を`DROP_UNVERIFIED`/`nft_drop=BLOCKED`とし、固定UDP実行0件、Owned Cleanup継続。Cleanup異常時は`CLEANUP_FAILED`優先。正常な両Namespace readbackと専用veth宛route getが揃わなければ`KERNEL_CAPABILITY_PASS`を出さない。
- [ ] **Step 2: Run tests expecting RED**: `python3 -m unittest tests.test_gha_isolation_feasibility -v`。期待：未実装の公開インターフェースに関するFAIL/ERROR。
- [ ] **Step 3: Implement minimal smoke**：以下の順序を守る。
  1. root、固定絶対パスの`ip`/`nft`/Python、`/dev/net/tun`、Kernel versionを確認。Host IPv4 route**全体**を`/usr/sbin/ip -j -4 route show table all`で初期snapshotし、`ip_forward`もread-only取得。exit 0・有効なJSON・前後比較可能な構造を検証し、初期取得不能・JSON不正なら`BLOCKED`としてKernel変更前に停止。
  2. nonceを生成し2つのNamespace名・専用veth/表名の不存在をreadback。衝突した名前は登録・変更せず`BLOCKED`。不存在確認済みの`tx`/`rx`だけを`planned_ns`に登録し、`ip netns add <planned_ns>`を個別実行。各addのexit 0と直後readbackで所属・存在を確かめた名前だけ`owned_ns`へ遷移。失敗・成否不明の名前は未所有として削除せず、残留／不存在不明なら`CLEANUP_FAILED`。所有確定済みNamespaceだけでvethを作り片側をrxへ移動。vethも作成exit 0とpeer対応readbackでOwned確定。
  3. 専用`198.18.0.1/30`（tx）と`198.18.0.2/30`（rx）を各vethに割り当てup。Namespaceにdefault routeなし。HostへInterface/IP/route/firewallを追加せず、Hostのrouting/ip_forwardを変更しない。
  4. tx Namespace内の`voftun0` TUNを作り、readback。OpenVPNは起動しない。
  4a. **RG-003送信前readback**：両Namespaceの所有確定後・専用veth IPv4割当後、UDP送信より前に固定argv`/usr/sbin/ip -n <owned_tx_ns> -j -4 route show table all`と`/usr/sbin/ip -n <owned_rx_ns> -j -4 route show table all`を実行する。`table all`の全IPv4経路を厳密に解析し、双方のdefault routeが全tableで不存在、mainの非local経路が各専用vethに接続された`198.18.0.0/30`のみ、localが各Namespaceの割当IPv4/loopbackに付随するkernel生成経路のみであることを確認する。続けてtxの固定`route get 198.18.0.2`が`dev vt<nonce>`・`src 198.18.0.1`・gatewayなしであることを確認する。読取失敗・非0・timeout・不正JSON・未解析フィールド・追加table/経路・不正経路はいずれも`DROP_UNVERIFIED`/`nft_drop=BLOCKED`として**固定UDP送信前に停止**、finallyのOwned Cleanupへ進む。既存の`CLEANUP_FAILED`優先は不変。
  5. tx Namespaceの`inet vof_<nonce> out` chainを`filter/output/priority 0/policy accept`で作成、宛先rx `198.18.0.2`/UDP9への`counter drop`のみを登録。ルールの構造とbefore.packets=0をJSON readbackし、rx宛routeがtx vethであることを確認。tx Namespace内から固定3 bytesのUDP1回だけ送信した後、同じruleのafter.packets−before.packets=1かつbytes増加を確認。測定不能・不一致は`BLOCKED`。
  6. 正常・部分失敗ともfinallyで**Owned確認済み**のnft/TUN/veth/Namespaceを逆順Cleanup。`netns del`は`owned_ns`のみ、他者・`planned_ns`のままの名前・所有不明実体は削除しない。失敗しても後続Owned Cleanup継続。最後にHost初期snapshotと**同じ`/usr/sbin/ip -j -4 route show table all`**で独立readbackし、全tableのJSON正常性・比較可能性・前後一致、`ip_forward`不変、許可済みリソース不在を確認。route取得・JSON・比較の失敗、残留・不変性未確認・cleanup失敗なら`CLEANUP_FAILED`が優先。
  7. `CommandRunner`は各コマンド5秒以内、単発Smoke90秒以内、外部通信なし。異常終了の生例外・stderrを出力せず固定Reason CodeとChecksだけ出す。`KERNEL_CAPABILITY_PASS`は独立readbackを含む全条件PASS時のみ。
- [ ] **Step 4: Run GREEN**：`python3 -m unittest tests.test_gha_isolation_feasibility -v`、`python3 -m compileall -q vpn_orbit tests`、`git diff --check`。すべて成功でTask 1の実装準備完了。これは**実RunnerのPASSではない**。
- [ ] **Step 5: Commit only after separate Owner authorization**。コード変更は専用feature branchで管理し、既存`master`を直接変更しない。承認されるまでCommit/Pushしない。

## Task 2: Manually Gated GitHub-hosted Runner Workflow

**Files:**
- Create: `.github/workflows/gha-isolation-feasibility.yml`
- Test: `tests/test_gha_isolation_workflow.py`

**Interfaces:**
- Consumes: Task 1の`SmokeVerdict`と、独立してIdentityを検証した`vpn_orbit/gha_isolation_feasibility.py`（`/usr/bin/python3 -I -S <承認済みcheckoutのSmokeファイル絶対パス>`で直接起動。`-S`により`site`初期化を無効化し、`-m`や任意`PYTHONPATH`経由の未確認importは不可。Smokeが未承認のリポジトリ内モジュールをimportしないことを単体テストとソース確認の対象にする）。
- Produces: `workflow_dispatch`専用Job（`runs-on: ubuntu-latest`）、Ref/HEAD/Smoke blob照合を**sudoより先に**実施。`KERNEL_CAPABILITY_PASS`以外はJob FAILURE。Owner承認のないRefは即時停止。

- [ ] **Step 1: Write failing workflow contract tests**：
  - `test_workflow_only_manual_dispatch`：`on`に`workflow_dispatch`のみ。Cron、push、pull_request、pull_request_target、workflow_runなし。
  - `test_workflow_readonly_token_and_no_persisted_checkout_credentials`：`permissions: contents: read`およびcheckoutの`persist-credentials: false`。
  - `test_workflow_does_not_pass_secrets`：`secrets`、`vars`、Cloudflare/GitHub token環境注入、artifact upload、publisher stepなし。
  - `test_workflow_uses_standard_runner_and_bounded_single_job`：`ubuntu-latest`標準Runner、`timeout-minutes: 10`、`concurrency`設定、`cancel-in-progress: false`。
  - `test_workflow_root_process_has_minimal_environment`：`sudo env -i`で`PATH`、`LANG`、`LC_ALL`だけを許可し、検証済み絶対パスの単独Smoke Pythonを`/usr/bin/python3 -I -S`で直接実行。`-I -S`の**両フラグ**と順序を検査し、`PYTHONPATH`、`-m`、未承認のリポジトリ内モジュールimportなし。
  - `test_workflow_rejects_unapproved_ref_or_source_identity`：未承認`github.ref`、`github.sha`/Workflow checkout HEAD不一致、source checkout HEADとOwner承認フルSHA不一致、Smoke Git blob SHA不一致時はsudo実行0件・Job FAILED。
  - `test_workflow_identity_checks_precede_privileged_code`：固定Identity readbackがoffline testより前、必ずsudoより前。`actions/checkout@SHA`はActionのみをpinし、対象Code SHA/Blobを別途確認。
  - `test_workflow_does_not_add_inputs_or_write_external_state`：追加`workflow_dispatch.inputs`なし、workflow_runなし、Cloudflare/API token/Artifactへ書込みなし。
  - `test_workflow_restricts_namespace_python_to_isolated_stdlib`：Namespace内の固定UDPコードは`/usr/bin/python3 -I -S -c <固定コード定数>`のみ。任意Pythonコード・フラグ省略・未承認リポジトリimportを拒否。
- [ ] **Step 2: Run expecting RED**：`python3 -m unittest tests.test_gha_isolation_workflow -v`。期待：Workflow未実装のFAIL。
- [ ] **Step 3: Implement Workflow**：
  - `workflow_dispatch`のみ、inputsなし。`ubuntu-latest`標準Jobで`actions/checkout`の**Action自体**を検証済みフルSHA固定、`persist-credentials: false`。Workflowは予めOwner承認された`dispatch_ref`からのみ起動し、`github.ref`の一致とWorkflow側checkout HEAD=`github.sha`を確認。
  - SourceはWorkflow定義Commitとは区別し、Owner承認済み`code_commit_sha`（フル40桁）を明示してcheckout。`git rev-parse HEAD`とSmokeの`git hash-object`が承認済みSHA/Blobに一致しなければ**一切のテスト・sudo実行をしない**。`code_commit_sha`/blob期待値はOwner承認後にWorkflowへ固定し、Workflow定義のCommit自体は**Dispatch直前のOwner readback**で別途承認する（自己SHAのYAML内埋込みをしない）。固定Identityの承認済み値が揃わない段階ではDispatch HOLD。
  - Identity全PASS後、オフラインunit testsを実行。続いて`sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C /usr/bin/python3 -I -S <検証済み絶対パス>/vpn_orbit/gha_isolation_feasibility.py`。OS commandはTask 1の限定allowlistだけ。Python/Kernel command不足なら`BLOCKED`で停止し、暗黙の`apt install`なし。
  - `GITHUB_TOKEN`はcheckout用最小権限に限定し、特権プロセスへ継承しない。Secretsは使用しない。
  - JSONの固定結果をconsoleに出し、非PASS時にJob FAILURE。Artifact、キャッシュ、公開Profile、KV書込みは作成しない。
  - Default branchにWorkflowが存在するまで`workflow_dispatch`が利用できない制約を文書に明記し、承認なしにマージ・dispatchしない。
- [ ] **Step 4: Run GREEN**：
  - `python3 -m unittest tests.test_gha_isolation_feasibility tests.test_gha_isolation_workflow -v`
  - `python3 -m unittest discover -s tests -v`
  - `python3 -m compileall -q vpn_orbit tests`
  - `git diff --check`
  - いずれもPASS。GitHub上での実Jobは`NOT_RUN`のまま。
- [ ] **Step 5: Commit/Push/PR only after separate Owner authorization**。本計画採択のみでWorkflow公開・起動は許可されない。

## Owner Checkpoint: One bounded GitHub-hosted Kernel Test

**Preparation complete when:** Task 1/2のOffline Tests PASS、特権Smoke直起動とNamespace内固定UDP送信の双方が`-I -S`を使用し、未承認リポジトリモジュールimportがないことを静的／単体テストで確認し、`(workflow_definition_commit_sha, workflow_blob_sha, dispatch_ref, code_commit_sha, smoke_blob_sha)`が全て確定し、OwnerがWorkflow定義の実行Ref/HEADとCode IdentityをGitHub readbackで照合可能な状態。Spec R0.1は既にfeatureブランチに存在、master未反映。Workflowファイルの自己Commit SHAを同一ファイルへ固定する循環は許容しない。Owner readbackによるWorkflow定義Identityの確認ができない場合は特権実行せずSTOP。さらにmutable Refのreadback→Dispatch間の競合は残るため、Ownerがその残余リスクを明示受容しなければ`HOLD`を維持する。

**Owner must separately authorize:** Source／Workflow各Commit、Feature PR/merge、および承認した`dispatch_ref`・Workflow定義SHAでの`workflow_dispatch`1回。承認Refが移動していた場合は実行せず停止し、新Refの採用やSHA更新を自動で承認しない。Ownerはmutable Refの競合リスクについて「受容して1回Dispatch」または「受容せずHOLD」を独立判断する。受容が明示されなければDispatchは`HOLD`。保護Ref等の代替設計への自動移行は禁止する。安全要件を満たさず`workflow_dispatch`を可能にできない場合は**STOP**、未承認triggerを追加しない。

**Live execution here means Kernel smoke only**（Namespace／veth／TUN／nftables作成、ローカル試験パケット、Cleanup）。VPN Gate/OpenVPN/GeoIP/Cloudflare通信や実接続は禁止。

| Evidence | 判定 |
|---|---|
| 作成／権限／TUN／Namespace／nftables／DROP実効性／Cleanup／Host route不変すべて確認 | `KERNEL_CAPABILITY_PASS`（限定） |
| 必須Binary・権限・Kernel機能不足、またはDROP実効性を検証できない | `BLOCKED` |
| Cleanup不完全、Host route/`ip_forward`改変 | `CLEANUP_FAILED`、即停止 |
| Workflow未実行、Job中断等で判定不能 | `NOT_RUN`または`UNKNOWN` |

**Next-task decision (NOT AUTHORIZED):** この限定PASSのみではVPNトンネル実通信の安全性を証明できない。Runnerの隔離が成立した場合に限り、別の限定Owner判断でStage 1実OpenVPN Runner移植・実通信試験へ進む。BLOCKEDなら無料代替技術を比較し、無限の再試行・レビュー連鎖を行わない。

## Self-Review / Stop

- 仕様R0.1の順序1（GitHub-hosted隔離成立性）だけをこの計画の対象とした。残る自動検証Runner／Pool／Publisher／iOS実機E2Eは**本計画には含まれず、未承認**。
- ファイル責務はSmoke本体、unit tests、manual Workflow、workflow testsに限定した。
- テストはIdentity・namespace衝突/所有・DROP実効性・Cleanup・Workflow権限/triggerの5つの主な失敗条件をカバーする。
- 外部からの通知や秘密情報、Profile発行、Cloudflare変更に依存しない。
- 完了時は`KERNEL_CAPABILITY_PASS`か明確な停止理由を報告してこのTaskを終了。独立レビュー・追加Taskは自動起動しない。