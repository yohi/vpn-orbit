# Stage 1 Pre-Live Verification Runbook

**Purpose:** Prepare a controlled, single-attempt KVM verification of one fixed VPN Gate candidate. This runbook is a preflight and evidence-collection procedure, not authorization to perform live network activity. KVM and GitHub Actions live tests remain `NOT_RUN` unless separately approved and actually executed.

**Current authority:** Design R0.1 is approved for approach A. Design R0.1.5 and Plan R0.1.5 remain pending Human Owner adoption. Implementation, source changes, tests, live execution, and any additional attempts require their respective explicit authorization. `READY_FOR_LIVE_APPROVAL` is not live-execution or operational approval.

## 1. Scope and critical limitations

- This runbook covers only the new fixed-candidate CLI: `python3 -m vpn_orbit.stage1_fixed_probe --list` and, only after every gate below is met, `python3 -m vpn_orbit.stage1_fixed_probe --probe-id <64-character-candidate-id>`.
- Its `flock` and unresolved-attempt hold are shared across **all candidate IDs invoked through the fixed-candidate CLI**. This is not a repository-wide or Stage 1-wide lock. Existing `vpn_orbit.cloud_probe` does not use the AttemptJournal and is **not covered** by this lock.
- The preflight checks below do not technically synchronize or prove the absence of `cloud_probe` or other external launchers. Therefore do not run any other probe, CLI, OpenVPN, or VPN activity in parallel. If an existing process or namespace cannot be positively accounted for, stop; do not treat the fixed CLI lock as protection from it.
- A possible prior attempt documented by Issue #9 remains `LEGACY_RESULT_UNKNOWN`. Never repeat or reinterpret that attempt. Only a Human Owner can make a new, explicit decision about one new attempt; the decision does not resolve the old unknown result.
- The authorization, if any, is for **one invocation of the fixed-candidate CLI with the exact approved candidate ID and HEAD**. It does not authorize the existing CLI, another candidate, retries, fallback, or a second attempt.
- Offline Mock tests do **not** prove real Linux kernel/nftables behavior, real VPN communication, or a Tokyo egress IPv4 address. All three remain **unverified** until separately approved evidence is collected. Do not claim live PASS from offline test results.

## 2. Preflight checklist — stop on any mismatch

Record the operator, UTC start time, KVM host identity, guest identity, and the guest's `vpn-orbit-probe` identity (hostname/VM name and the intended account/service). Do not expose API keys, credentials, profile content, private keys, or raw OpenVPN logs in notes or artifacts.

On the guest, from the repository root, record and verify:

```bash
hostname -f
python3 --version
GIT_MASTER=1 git status --short --branch
GIT_MASTER=1 git rev-parse HEAD
GIT_MASTER=1 git diff --name-only
```

Compare the branch, HEAD, changed-file list, and Python version with the explicitly approved fixed candidate and the reviewed baseline. The baseline recorded in the plan is `master@7f1ae8cab84a94cea8369e8075b4982b652f1557`; the reviewed design HEAD is `d23536a396f2d8098e7e6bd4d5f06a3e9657d238`. Use the exact subsequently approved feature commit for execution; do not assume these references equal the execution HEAD. Any drift, dirty/unexpected changes, unavailable identity, or version/environment mismatch is a stop condition. Do not rebase or silently update the candidate; report to the Human Owner.

Confirm no existing fixed or ordinary CLI, `vpn_orbit.cloud_probe`, OpenVPN process, probe process, VPN connection, Network Namespace, or prior attempt is active or left behind. Use read-only process/namespace inspection appropriate to the guest (for example `pgrep -a -f 'vpn_orbit|openvpn'` and `ip netns list`); investigate every match. Also confirm no other operator or automation can start a probe during this window. Do not terminate or clean up an unknown resource by guesswork. If presence, ownership, or state is ambiguous, stop and request Human Owner direction. These checks reduce risk but **do not provide a technical lock against existing `cloud_probe` or other launchers**.

Verify the fixed-candidate CLI and its test/runtime prerequisites are the reviewed versions. Verify API-key handling and restricted state storage are understood; API keys must not be passed to OpenVPN or persisted in the Journal. The expected Journal directory is `/var/lib/vpn-orbit/stage1-attempts` (root-owned directory mode 0700; files mode 0600). Never use an empty/missing Journal as permission to proceed.

### Offline gate evidence

The offline suite must include and pass these exact fail-closed tests:

- `test_issue9_unknown_blocks_empty_journal_without_owner_decision`
- `test_issue9_unknown_blocks_different_candidate_without_owner_decision`
- `test_parallel_different_candidate_is_blocked` (or the equivalent regression test asserting fixed-CLI lock contention blocks a different candidate before probe invocation)
- DROP route restoration and dedicated-rule cleanup tests, including `test_tun0_echo_route_restored_before_drop_rule_removed`, `test_route_restore_failure_yields_probe_fail`, and `test_drop_rule_cleanup_failure_yields_probe_fail` (or equivalent tests proving the same guarantees).

These tests establish offline behavior only. They do not establish real kernel enforcement or interference exclusion from `cloud_probe`.

## 3. Fixed candidate identity and SHA verification

The candidate ID is SHA-256 over the ASCII ingress tuple and the **unaltered original profile bytes immediately after Base64 decoding**:

```python
sha256(
    f"{ip}:{port}/{protocol}\n".encode("ascii") + profile_raw_bytes
).hexdigest()
```

Before any approval or attempt, use the fixed CLI's `--list` mode to retrieve the current candidate list and its candidate IDs. This mode may contact the catalog/GeoIP services but must not start OpenVPN. Compare the full 64-character candidate ID, ingress IP/port/protocol, and fixed candidate identity against the independently recorded intended candidate. The profile bytes are not to be copied into a report. A one-byte profile change, including a UTF-8 BOM change, means a different candidate ID. Do not substitute, re-resolve by list position, accept an old normalized ID, or fall back to another candidate. If the requested ID is absent, duplicated, malformed, or cannot be verified against the exact current candidate, stop without probing.

Record the exact approved HEAD and candidate ID in the restricted OwnerApproval. Reconfirm them immediately before the single authorized CLI invocation. Any mismatch invalidates the authorization and is a stop condition.

## 4. Issue #9 legacy HOLD and OwnerApproval gate

Before the first possible probe invocation, inspect [Issue #9](https://github.com/yohi/vpn-orbit/issues/9) and confirm the documented prior attempt is still `LEGACY_RESULT_UNKNOWN` (old candidate `106.161.34.210:1998/tcp`, legacy candidate ID `00aaf9a56bb43fbeea8b02e19cf98e620fc69f079bc4ab93b3e3d62cdb8fb5d8`). The old outcome must not be inferred, backfilled, retried, or converted to PASS/FAIL. If the issue history or current disposition is unclear, stop and ask the Human Owner.

A missing OwnerApproval, a used approval ID, or a candidate/HEAD mismatch means **no attempt**. A Human Owner must explicitly acknowledge the old result remains unknown and decide whether to authorize **one new attempt** for the exact current candidate ID and HEAD. The fixed CLI's tests `test_issue9_unknown_blocks_empty_journal_without_owner_decision` and `test_issue9_unknown_blocks_different_candidate_without_owner_decision` enforce that both an empty Journal and a different candidate remain blocked without that decision.

If and only if the Human Owner makes that explicit decision, have the Owner provide the restricted-access `OwnerApproval` record at the configured approved path. Confirm its presence, root ownership, file mode 0600, and exact fields without copying sensitive contents into logs:

- `approval_id` (unused, single-use)
- `issue_ref="yohi/vpn-orbit#9"`
- `legacy_disposition="ACKNOWLEDGED_RESULT_UNKNOWN"`
- `candidate_id` (exact current fixed candidate)
- `approved_head` (exact approved execution HEAD)
- `scope="ONE_NEW_ATTEMPT"`
- `approved_at`

The operator or agent must not create, infer, or proxy the Owner's decision. The empty Journal is **not authorization** and does not release the legacy HOLD. Approval consumption is atomic and single-use; do not reuse an ID. If OwnerApproval verification, access controls, Journal ownership/permissions, lock acquisition, reservation, or persistence fails, stop before OpenVPN is invoked.

## 5. One-attempt execution gate

Immediately before execution, the operator and Human Owner (or their explicitly designated operator) must reconfirm all of the following: correct host/guest and `vpn-orbit-probe`; approved HEAD and exact candidate ID; Issue #9 remains acknowledged as unknown; a valid, unused, exact-scope OwnerApproval exists; no active or unresolved prior attempt; no CLI/OpenVPN/VPN/namespace residue; no parallel operator or automation; and the guest remains in the reviewed state. Any uncertainty is a stop condition.

The fixed-candidate CLI's common lock covers its candidate IDs only. Do not launch `cloud_probe` or any other CLI/probe/OpenVPN process during this procedure; do not run multiple invocations in parallel. The manual no-parallel rule is mandatory precisely because the existing CLI is not covered by the fixed-CLI lock. Do not treat preflight process checks as proof of technical mutual exclusion.

Only after a Human Owner's explicit single-attempt authorization and all gates pass may the operator run the exact approved `--probe-id` command, once. Do not use `--force`, `--retry`, an alternate candidate, a second invocation, or fallback. This permit applies only to that one fixed-candidate CLI invocation and **does not authorize or extend to the existing `vpn_orbit.cloud_probe` CLI**. On an unexpected response, interruption, lost connection, or ambiguous invocation state, do not relaunch; collect state and stop.

## 6. DROP measurement, restoration, and cleanup gate

The DROP measurement is valid only under the approved Runner procedure and only if every evidence and cleanup condition is confirmed:

1. Confirm and record the existing echo target's `/32` route via `tun0`; do not change the default route, VPN server route, or any other destination.
2. Install the dedicated nftables output `counter drop` rule restricted to the namespace's `oifname <veth_ns>`, the fixed echo IPv4 destination, and TCP/443. Record its exact identity and pre-send counter. If creation, parsing, identity, or counter inspection fails, send no packet.
3. Only after verifying that rule, temporarily change only the target echo IPv4 `/32` route to `via 10.253.240.1 dev <veth_ns>`. Confirm the normal route lookup and route listing establish the intended path. An `ip route get ... oif` result alone is not evidence.
4. Send only the existing bounded single HTTPS measurement request with `--noproxy '*'`, the fixed `--resolve api.ipify.org:443:<echo_ip>`, `--interface if!<veth_ns>`, and TCP/443. A curl refusal/timeout alone is not proof. Verify the same dedicated DROP counter increased strictly between before and after observations.
5. On success, failure, exception, or timeout, restore the target `/32` to its saved `tun0` route **first**. Confirm normal route lookup and route listing show `dev tun0`, expected original route attributes, and no temporary veth `/32`. Only after that restoration is confirmed, remove the dedicated rule by its recorded identity and verify it is absent.

Every step must succeed for the DROP evidence to count. Missing evidence, a non-incrementing counter, route-restore failure, rule-removal failure, or ambiguous cleanup is final FAIL: stop immediately, do not continue to tunnel HTTPS/GeoIP checks, do not claim PASS, and do not start a second attempt. If restoration cannot be confirmed, do not remove the protective DROP rule before restoration; preserve the restrictive state for the existing controlled namespace cleanup path and escalate to the Human Owner. Cleanup failure retains FAIL precedence.

After the attempt, independently inspect the actual resources, not merely the CLI's cleanup summary: confirm no probe-created namespace, OpenVPN process, tunnel interface, temporary `/32` route, dedicated DROP rule, or other attempt-owned resource remains. Verify the host default route is unchanged. If a resource remains or absence cannot be confirmed, stop and escalate; do not perform speculative cleanup or retry.

## 7. Result collection and stop conditions

Collect the fixed CLI's complete JSON response and corresponding Journal record by `attempt_id`, plus the **actual shell exit status** observed by the operator. Preserve only approved, non-secret evidence. Do not capture raw OpenVPN output, profile content, API keys, private keys, credentials, or exception text. Record verification of route restoration/rule absence, other resource absence, host default route, and timestamps. Keep the result and restricted OwnerApproval in their approved access-controlled locations.

Distinguish these values:

- JSON/Journal `exit_code` is the fixed-candidate CLI's **planned/intended** exit code after a finalized result: 0 only for PASS with confirmed cleanup, otherwise 1. It is not the OpenVPN child's exit code and is not proof of what the operating system actually returned.
- The actual shell exit status is observed separately when the CLI process exits. A preflight rejection can have a nonzero shell status while JSON `exit_code` is null. For `NOT_STARTED`, `RESULT_UNKNOWN`, or failed finalization, the JSON planned `exit_code` remains null; never fill it from the shell result or assume zero.

Stop and report to the Human Owner for `RESULT_UNKNOWN`, null status after an attempted invocation, Journal finalization failure, interruption with uncertain probe start, any discrepancy between JSON/Journal and shell status, any FAIL/BLOCKED/NOT_VERIFIED outcome, missing evidence, cleanup anomaly, or unexpected output. A `RESULT_UNKNOWN` is a global unresolved hold for all fixed-candidate CLI candidate IDs. Do not retry, repair the Journal by hand, delete the unknown record, select another candidate, or use the existing CLI to bypass the hold. The legacy Issue #9 unknown remains separate from the current attempt's recovery state.

## 8. Offline acceptance and final report

Run only the repository's offline checks specified for this task:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q vpn_orbit tests
git diff --check
```

Catalog, GeoIP, OpenVPN, nftables, and Runner dependencies must be mocked for offline CLI tests; prohibit network communication and real process execution. Record exact command outcomes and skip reasons. Do not run live network tests, real OpenVPN, or KVM/GitHub Actions live tests as part of offline acceptance. The absence of an executed live test must be reported as `NOT_RUN`, never PASS.

The final acceptance record must include the reviewed/execution HEAD, changed files, offline test and compile/diff-check outcomes, skip reasons, result and cleanup evidence (if separately authorized live execution occurred), and remaining risks. State explicitly that the real kernel DROP behavior, real VPN communication, and Tokyo egress IPv4 are **not proven by offline acceptance**. Stop at the Human Owner checkpoint; do not automatically continue to another attempt or remediation cycle.
