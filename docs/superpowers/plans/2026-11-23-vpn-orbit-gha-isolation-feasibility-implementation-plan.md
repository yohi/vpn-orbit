# VPN-ORBIT GitHub-hosted Runner Isolation Feasibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GitHub-hosted `ubuntu-latest`標準Runnerで、VPN接続なしにLinuxのNamespace／veth／TUN／nftablesの隔離機能とCleanup成立性を一度だけ実証できる、手動起動専用のゲートを作る。

**Architecture:** `vpn_orbit/gha_isolation_feasibility.py`に外部接続を行わない、自己完結するKernel Smoke Testを実装し、`.github/workflows/gha-isolation-feasibility.yml`から特権コマンドとして実行する。Hostのdefault routeおよび`ip_forward`を変えず、検証用Namespace・veth・nftablesのみ一時作成し、必ずCleanupと独立したreadbackを行う。成果は限定的なKernel Capability Verdictであり、OpenVPN実通信や東京出口の証拠にはならない。

**Tech Stack:** Python 3.11+標準ライブラリ、Linux iproute2/nftables、GitHub Actions `ubuntu-latest` standard hosted runner、unittest。新規Python依存なし。

**Spec:** `docs/superpowers/specs/2026-11-23-vpn-orbit-zero-cost-tokyo-automation-design.md`（Human Owner採択R0.1。現在はチャット内採択、リポジトリには未反映。実装に先立ち、この採択済み文面と同一のSpecを同じPRに含める）

## Global Constraints

- リポジトリ：`yohi/vpn-orbit`。設計時基準HEAD：`master@f54e5db35cfad3094521c5d5f191fc5b9e7324a4`。実装時に基準ドリフトを確認し、コードに合わせて最小限更新する。
- 追加費用0円：Publicリポジトリのstandard GitHub-hosted Linux Runnerを使用。larger runner、有料プラン、自宅Host、self-hosted runner、Cloudflare Containersは禁止。
- 初回の検証は**実OpenVPN接続なし**、VPN Gate CSV取得なし、GeoIP照会なし、Cloudflare API/KV書込みなし。
- `workflow_dispatch`のみ。Cron、push、pull_request、pull_request_target、workflow_runで起動しない。**Workflowはdefault branch上に存在するまで通常はdispatch不可**。新規Workflowをdefault branchへ取り込む操作と実際のDispatchは別々の明示Owner承認を要する。
- `permissions: contents: read`、`actions/checkout`は固定SHAを検証して使用し`persist-credentials: false`。workflowにSecretsを注入せず、特権Pythonプロセスへ`GITHUB_TOKEN`・認証情報・環境変数全体を渡さない。
- Shellの`set -x`を使用せず、出力は固定コード、Python／Kernel version、合否、許可済み一時リソース名とcleanup結果のみ。`env`、secret、Profile原文、Client Key、例外stacktraceは出力しない。
- 非Network操作の能力確認でも、操作は実行前に許可された一時リソース名だけ。既存プロセス／Firewall／routeには触れない。
- cleanupが失敗したら`CLEANUP_FAILED`を優先し、成功を主張しない。検証が未実行なら`NOT_RUN`、能力不足なら`BLOCKED`。不測の強制終了では結果を`UNKNOWN`として扱う。
- Issue #9 `LEGACY_RESULT_UNKNOWN`を維持。Stage 1固定候補CLI、Journal、OwnerApproval、既存Runnerの実行経路を変更しない。
- 設計採択はコード変更、GitHub commit/push/PR、Workflow起動、外部サービス書込みの許可ではない。各実行許可は別Checkpointで取得する。
- Review Loop Prevention：限定テストと必要な局所訂正を行ったらOwner判断へ。機械的な独立レビュー連鎖を作らない。

## Review Focus

1. **Namespace作成失敗**：Hostのroute／ip_forward変更なし、作成済み対象があれば削除、`BLOCKED`で終了する（Task 1の`test_namespace_create_failure`）。
2. **nftables拒否／DROPの実効性欠如**：安全成功にしない。ローカルveth宛の試験パケットがDROP counterを増加させなければ`BLOCKED`（Task 1の`test_nft_drop_counter_not_incremented`）。
3. **Cleanup失敗**：失敗時にも後続対象の除去を試み、残留を再照合して`CLEANUP_FAILED`優先（Task 1の`test_cleanup_failure_overrides_capability_pass`）。
4. **RunnerへのSecrets混入**：Workflowの特権起動環境がallowlistだけであることを検査（Task 2の`test_workflow_does_not_pass_secrets`）。
5. **予期しない自動起動**：Workflowのtriggerは`workflow_dispatch`だけ（Task 2の`test_workflow_only_manual_dispatch`）。

---

## File Structure

- **Create** `vpn_orbit/gha_isolation_feasibility.py` — 今回だけのKernel Capability Smoke、固定スキーマの結果、Cleanup、CLI。
- **Create** `tests/test_gha_isolation_feasibility.py` — 実カーネルやネットワークを操作しないモック単体テスト。
- **Create** `.github/workflows/gha-isolation-feasibility.yml` — `workflow_dispatch`限定の手動Workflow。既存WorkerデプロイWorkflowとは分離。
- **Create** `tests/test_gha_isolation_workflow.py` — Workflowの起動経路・権限・Secrets非使用などの静的契約テスト。YAMLパーサーの新規依存は増やさず、対象Workflowの固定テンプレートとキーを精密に検査する。
- **Copy adopted spec** `docs/superpowers/specs/2026-11-23-vpn-orbit-zero-cost-tokyo-automation-design.md` — 採択済みR0.1。現行ソースへの書込みは未承認。
- **This plan's target** `docs/superpowers/plans/2026-11-23-vpn-orbit-gha-isolation-feasibility-implementation-plan.md`。
- **Do not modify** `vpn_orbit/stage1_fixed_probe.py`、`vpn_orbit/attempt_journal.py`、既存`worker/`、既存Workflow。

## Task 1: Offline-tested Linux Isolation Capability Smoke

**Files:**
- Create: `vpn_orbit/gha_isolation_feasibility.py`
- Test: `tests/test_gha_isolation_feasibility.py`

**Interfaces:**
- `SmokeVerdict`: 状態 `KERNEL_CAPABILITY_PASS | BLOCKED | CLEANUP_FAILED | UNKNOWN`、固定理由コード配列、Namespace/TUN/nft/route/cleanupの個別判定を持つ値型。
- `CommandRunner.run(argv: tuple[str, ...], *, timeout_s: float) -> CommandResult`：許可されたコマンドだけを実行する注入可能な実行境界。テストはFakeRunnerを利用。
- `run_smoke(runner: CommandRunner, *, scope: str) -> SmokeVerdict`：限定Namespace、veth、TUN、nftablesで能力検証し、必ずreadbackして返す。`scope`はASCII英数字の短い固定安全名のみ許可。
- `main() -> int`：結果を固定キーのJSON1件だけ出力。PASS時のみ0、それ以外は非0。

- [ ] **Step 1: Write failing tests** in `tests/test_gha_isolation_feasibility.py`。テスト名と期待値：
  - `test_safe_scope_rejects_shell_metacharacters`：不正scopeで実行コマンド0件、`BLOCKED`。
  - `test_namespace_create_failure`：Namespace生成拒否で`BLOCKED`、既存Host route変更0回。
  - `test_tun_missing_or_creation_denied`：`/dev/net/tun`欠落またはTUN作成拒否で`BLOCKED`、Cleanup実施。
  - `test_nft_drop_counter_not_incremented`：DROPカウンタ非増加で`BLOCKED`。
  - `test_cleanup_failure_overrides_capability_pass`：能力確認PASSでも残留readbackなら`CLEANUP_FAILED`。
  - `test_no_vpn_or_external_network_command`：OpenVPN、curl、GET、外部宛通信を要求せず、Host default route/`ip_forward`への書込みをしない。
  - `test_success_requires_cleanup_and_route_unchanged`：すべて通過し、Host default routeの前後一致、Namespace・veth消失なら`KERNEL_CAPABILITY_PASS`。
  - `test_main_redacts_errors_and_uses_fixed_schema`：例外や環境値をログに露出せず、意図したJSONキーだけ出力。
- [ ] **Step 2: Run tests expecting RED**: `python3 -m unittest tests.test_gha_isolation_feasibility -v`。期待：未実装の公開インターフェースに関するFAIL/ERROR。
- [ ] **Step 3: Implement minimal smoke**：以下の順序を守る。
  1. root/`sudo`、`ip`、`nft`、`/dev/net/tun`、Kernel version、Host IPv4 default routeと`ip_forward`の読み取り専用Snapshot。
  2. 実行IDに紐づく衝突不能な一時Namespace・vethを作成。既存リソースに名前衝突したら触らず停止。
  3. vethはHostとNamespaceをローカルの小さな専用Subnetで接続するが、Host WAN forwarding/routeは追加せず、Namespaceにdefault routeを追加しない。
  4. Namespace内にTUN interfaceを作成してreadbackする。OpenVPN起動なし。
  5. Namespace内にnftables OUTPUT DROPを作り、**専用veth peerだけ**に対するローカル試験パケットでカウンタ増加を確認。外部ネットワークへ通信しない。
  6. finallyで作成したNamespace・veth・nft・TUNを可能な範囲で撤去。Host route/`ip_forward`の前後一致とリソース不在を独立readback。Cleanup異常は合否に優先。
  7. 一時的なLinux操作が失敗しても候補試験や他のJobへ進まない。例外文字列をstdout/stderrへ投影しない。
- [ ] **Step 4: Run GREEN**：`python3 -m unittest tests.test_gha_isolation_feasibility -v`、`python3 -m compileall -q vpn_orbit tests`、`git diff --check`。すべて成功でTask 1の実装準備完了。これは**実RunnerのPASSではない**。
- [ ] **Step 5: Commit only after separate Owner authorization**。コード変更は専用feature branchで管理し、既存`master`を直接変更しない。承認されるまでCommit/Pushしない。

## Task 2: Manually Gated GitHub-hosted Runner Workflow

**Files:**
- Create: `.github/workflows/gha-isolation-feasibility.yml`
- Test: `tests/test_gha_isolation_workflow.py`

**Interfaces:**
- Consumes: Task 1の`python3 -m vpn_orbit.gha_isolation_feasibility`と`SmokeVerdict`。
- Produces: `workflow_dispatch`でのみ1回起動できるJob（`runs-on: ubuntu-latest`）、赤字の非PASS時はJob FAILURE、全条件PASSでも出力するのはKernel Capabilityの限定PASSだけ。

- [ ] **Step 1: Write failing workflow contract tests**：
  - `test_workflow_only_manual_dispatch`：`on`に`workflow_dispatch`のみ。Cron、push、pull_request、pull_request_target、workflow_runなし。
  - `test_workflow_readonly_token_and_no_persisted_checkout_credentials`：`permissions: contents: read`およびcheckoutの`persist-credentials: false`。
  - `test_workflow_does_not_pass_secrets`：`secrets`、`vars`、Cloudflare/GitHub token環境注入、artifact upload、publisher stepなし。
  - `test_workflow_uses_standard_runner_and_bounded_single_job`：`ubuntu-latest`標準Runner、`timeout-minutes: 10`、`concurrency`設定、`cancel-in-progress: false`。
  - `test_workflow_root_process_has_minimal_environment`：`sudo env -i`等で実行プロセスへの環境変数をallowlistに限定し、固定パスからModule実行。
- [ ] **Step 2: Run expecting RED**：`python3 -m unittest tests.test_gha_isolation_workflow -v`。期待：Workflow未実装のFAIL。
- [ ] **Step 3: Implement Workflow**：
  - `workflow_dispatch`のみ。追加の入力なし。`ubuntu-latest`上で通常checkout（verified full SHA pin、`persist-credentials: false`）。
  - 最初にPythonのオフラインunit test、次に`sudo env -i PATH=... LANG=C PYTHONPATH=... /usr/bin/python3 -m vpn_orbit.gha_isolation_feasibility`。Runnerに必要コマンド・Pythonが不足する場合はBLOCKEDで停止し、暗黙の`apt install`を行わない。
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

**Preparation complete when:** Task 1/2のOffline Tests PASS、固定HEADとWorkflow差分・secret absence確認、同じ採択済みSpecがリポジトリに存在し、Ownerがコード差分と実行範囲を読める状態。

**Owner must separately authorize:** Feature PR/mergeおよび`workflow_dispatch`1回。安全要件を満たさず`workflow_dispatch`を可能にできない場合は**STOP**、未承認triggerを追加しない。

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
- テストはNamespace・nft・Cleanup・資格情報・triggerの5つの主な失敗条件をカバーする。
- 外部からの通知や秘密情報、Profile発行、Cloudflare変更に依存しない。
- 完了時は`KERNEL_CAPABILITY_PASS`か明確な停止理由を報告してこのTaskを終了。独立レビュー・追加Taskは自動起動しない。