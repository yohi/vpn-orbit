# vpn-orbit Stage 1 Cloud Verifier Implementation Plan R0.1

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task **only after explicit Human Owner execution authorization**. Steps use `- [ ]` syntax. No task, commit, push, workflow run or deployment is authorized by the existence of this plan.

**Goal:** GitHub-hosted Ubuntu VM上で既存固定2台以外のVPN Gate候補に隔離接続し、**トンネル経由の出口IPv4**がGeoIP APIで東京都と判定されることを実証する。

**Architecture:** Read-onlyな候補収集・GeoIP選別と、ネットワーク分離されたOpenVPN接続検証を独立モジュールに分ける。まずmock/offlineテストを作り、最後に手動起動のGitHub Actionsで限定的な実機試験を行う。Cloudflare/KV/既存Worker/iOS設定には一切書き込まない。

**Tech Stack:** Python 3.11+ standard library; Ubuntu `ubuntu-24.04` VM; OpenVPN CLI; Linux network namespace and scoped firewall; GitHub Actions; ipapi.is GeoIP API (keyed tier); existing `vpn_orbit.phase1` parsing/conversion.

**Spec:** `docs/superpowers/specs/2026-11-14-vpn-orbit-dynamic-tokyo-pool-design.md` (chat-approved R0.1). This plan deliberately covers **Stage 1 only**. The design's Stage 2–4 implementation plans are gated on this stage's evidence and explicit Owner authorization.

## Global Constraints

- Project `yohi/vpn-orbit` / branch baseline `master` (observed 2026-11-14); preserve existing fixed 2 Tokyo remotes, authenticated Worker endpoints, Cloudflare KV and Cron.
- Existing fixed remotes `119.105.93.237:1279/tcp`, `126.234.242.57:1281/tcp` are **excluded** from the Stage 1 success witness.
- No production Cloudflare API token or KV write access in probe jobs; `permissions: contents: read`; no `wrangler deploy`.
- No automatic adoption of newly found servers until endpoint identity and geo acceptance meet the approved policy; Stage 1 never publishes.
- Every OpenVPN profile is **untrusted**; do not execute downloaded `.ovpn` instructions, scripts or external include paths. Validate by existing strict parser and synthesize only allowlisted directives for OpenVPN CLI.
- Run OpenVPN only in an isolated network namespace; do not alter the runner's host default route. Allow only the candidate VPN server transport outside the tunnel; assert that egress-IP lookup travels through the tunnel, not the runner's direct path. On uncertainty, mark `NOT_VERIFIED` and refuse acceptance.
- GeoIP admission: exit IPv4 is global/public, API response corresponds to the exact queried IP, `location.country_code == 'JP'` and `location.state == 'Tokyo'`. Missing/conflicting/ambiguous fields are rejected. The state field is **not** named `region` in the keyed ipapi.is schema.
- Respect API quotas, apply per-request timeout, bounded input size and candidate limits. Never log/write raw client keys, profiles, bearer tokens or GeoIP API credentials. Never persist untrusted executable content as an artifact.
- End a bounded probe after a short timeout even if servers are unresponsive; one bad candidate must not hang the entire workflow.
- Tests can PASS while a live external server is unavailable: classify `PASS` (verified Tokyo exit), `NOT_VERIFIED` (insufficient live evidence), `BLOCKED` (runner capability or policy constraint), `FAIL` (an observed safety assertion failure). Never conflate them.
- No automatic push, merge, deploy, independent review or later Stage start. Owner checkpoint at the end.

## File map

| Path | Purpose |
|---|---|
| `vpn_orbit/cloud_probe.py` | Bounded candidate discovery, GeoIP filtering, redacted result schema and CLI orchestration |
| `vpn_orbit/geoip.py` | Typed response parsing and Tokyo decision; outbound API adapter |
| `vpn_orbit/openvpn_probe.py` | Sanitized OpenVPN config builder, isolated namespace setup/teardown and tunnel-verification adapter |
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

### Task 1: GeoIP 東京判定と候補スクリーニング（オフラインテスト可能）

**Files:**
- Create: `vpn_orbit/geoip.py`
- Create: `vpn_orbit/cloud_probe.py`
- Test: `tests/test_geoip.py`, `tests/test_cloud_probe.py`

**Interfaces:**
- `class GeoDecision(Enum): TOKYO, NON_TOKYO, UNKNOWN`
- `def decide_tokyo(ip: str, response: dict) -> GeoDecision`: fail-closed exact matching, keyed API `location.country_code`, `location.state`, response `ip`.
- `def lookup_geoip(ip: str, *, api_key: str, timeout_s: float = 5.0) -> GeoDecision`: HTTPS request to `https://api.ipapi.is/`, bounded JSON, no credential logging; API errors -> UNKNOWN.
- `def screen_candidates(catalog: str, *, existing_pins: frozenset[str], geo_lookup, limit: int = 20) -> list[Candidate]`: use existing `parse_catalog(..., country='JP')`; exclude two baseline IPs; stable de-dup and limit; fail-closed on invalid/missing geo fields. `Candidate` is the existing `vpn_orbit.phase1.Candidate`.

- [ ] **Step 1: Failing tests**: keyed mock response `{ip:'8.8.8.8',location:{country_code:'JP',state:'Tokyo'}}` yields TOKYO for the synthetic mocked response (not an assertion about the real IP). Reserved IPv4 `203.0.113.1` must be rejected even if mock geo data says Tokyo. `Osaka`, missing state, wrong IP, `is_bogon=true` when present, malformed JSON and HTTP quota/timeout yield NON_TOKYO or UNKNOWN, never TOKYO. API key must not be echoed. CSV with baseline remotes excluded and duplicates reduced deterministically.
- [ ] **Step 2: Run** `python3 -m unittest tests.test_geoip tests.test_cloud_probe -v`; expected initial failure due to missing modules.
- [ ] **Step 3: Implement** both interfaces and only the minimal input/bound/error logic needed to satisfy tests; validate globally routable IPv4 for actual admission, not test fixtures.
- [ ] **Step 4: Re-run** the tests; expected PASS. Run existing `python3 -m unittest discover -s tests -v`; expected no regression.
- [ ] **Step 5: Local commit** only within the separately approved implementation session; no push/PR without approval.

### Task 2: 隔離OpenVPNトンネル検証器（mock + live contract）

**Files:**
- Create: `vpn_orbit/openvpn_probe.py`
- Test: `tests/test_openvpn_probe.py`
- Modify: `vpn_orbit/cloud_probe.py` (invoke probe and aggregate results)
- Test: `tests/test_cloud_probe.py` (integration mocked result)

**Interfaces:**
- `class ProbeStatus(Enum): PASS, NOT_VERIFIED, BLOCKED, FAIL`
- `@dataclass(frozen=True) class ProbeResult: ingress_ip: str; port: int; protocol: str; exit_ip: str | None; status: ProbeStatus; reason_code: str`
- `def synthesize_openvpn_config(parsed_endpoint: dict, *, remote_ip: str, port: int, protocol: str) -> bytes`: emit only known-safe explicit OpenVPN directives after `vpn_orbit.phase1.convert_ovpn(...)`; reject unsupported directives; write 0600 private material in ephemeral workspace.
- `def probe_one(candidate: Candidate, *, geo_lookup, timeout_s: int = 60, runner=None) -> ProbeResult`: timeout-bounded isolated namespace; OpenVPN runs *inside* namespace; prove tunnel interface active, route to echo service through VPN, and actual observed public IPv4; call geo_lookup on observed IPv4 outside the tunnel using the trusted host namespace. No direct-route fallback.

- [ ] **Step 1: Failing tests**: unsafe directives rejected; no namespace/TUN -> BLOCKED; TLS handshake failure/timeouts -> NOT_VERIFIED; exit echo request routed outside tunnel -> FAIL; successful tunnel + Tokyo egress -> PASS; Kyoto or unknown -> NOT_VERIFIED; process crash, timeout and cancellation clean namespace/firewall/files; no key/profile/log leak.
- [ ] **Step 2: Run** `python3 -m unittest tests.test_openvpn_probe -v`; expect missing implementation failures.
- [ ] **Step 3: Implement** sanitized config derivation, namespace/veth/firewall lifecycle with scoped candidate-only direct egress, `tun` routing assertion, subprocess supervision and cleanup. Isolate command execution behind a fakeable runner; no shell interpolation of CSV-derived fields. Do not use `sudo openvpn --config <downloaded-ovpn>`.
- [ ] **Step 4: Re-run** unit tests and regression tests; PASS needed before a real Runner probe. If safe namespace confinement is unavailable, report BLOCKED and stop; do not silently use host routing.
- [ ] **Step 5: Local commit** only after the separate implementation authorization; do not push/run remotely automatically.

### Task 3: GitHub Actions manual-only live feasibility check

**Files:**
- Create: `.github/workflows/probe-tokyo-vpn.yml`
- Modify: `vpn_orbit/cloud_probe.py` (CLI entrypoint + redacted summary)
- Test: `tests/test_cloud_probe.py` (workflow output and status contract)

**Interfaces:**
- CLI: `python3 -m vpn_orbit.cloud_probe --limit 10 --timeout-seconds 60`; accepts `IPAPI_IS_API_KEY` from Actions Secret; emits only a summary `{status, tested_count, tokyo_confirmed_count, witness_ingress, witness_exit, reason_codes}`; no raw `.ovpn` or credentials.
- Workflow: `workflow_dispatch` only; `runs-on: ubuntu-24.04`; `permissions: contents: read`; timeout <= 20 minutes; `concurrency` with no overlapping probe runs; install only explicit OpenVPN/netns/firewall dependencies; no Cloudflare secrets or deployment steps. The workflow must not run on push/PR/schedule at this Stage.

- [ ] **Step 1: Failing tests**: parse workflow and assert manual-only trigger, read-only permissions, no Worker deploy/Cloudflare Secret, no uploaded profile/credential artifacts; CLI JSON output contains only allowlisted fields. (YAML parsing can be tested via test-time dependency or lightweight strict file scan without adding a runtime dependency.)
- [ ] **Step 2: Run** `python3 -m unittest discover -s tests -v` to see failing workflow contract test.
- [ ] **Step 3: Implement** bounded candidate count, `IPAPI_IS_API_KEY` secret handling, manual workflow and redacted summary. Avoid explicit `run: curl` that could leak API credentials in the job log.
- [ ] **Step 4: Re-run** all unit tests; expected PASS. Check workflow syntax separately if validation tooling is available.
- [ ] **Step 5: Local commit** only after authorization; **do not push or dispatch** until Human Owner explicitly approves those distinct actions.

### Task 4: One-time live verification and Owner checkpoint (NOT AUTOMATIC)

**Prerequisites:** Tasks 1–3 verified, workflow version on approved branch/default branch, and **separate explicit authorization** to dispatch the workflow. API key configured by the Owner, never sent in chat.

- [ ] **Step 1:** Run a single manual workflow; cap live attempts at 10 candidates, 60 seconds each, 20 minutes total. No Cron, no production KV writes.
- [ ] **Step 2:** Inspect only redacted logs. Verify namespace isolation, authentic VPN tunnel + changed egress IPv4, exact GeoIP Tokyo result, and at least one witness **other than the two fixed servers**.
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
