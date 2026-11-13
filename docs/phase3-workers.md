# Phase 3 — Cloudflare Workers candidate refresh and remote profile distribution

## Goal / completion boundary

Implement a **Cloudflare Worker source module**, deterministic tests, and a deployment *template* to serve a single sing-box 1.14+ profile from a reviewed list of geographically verified VPN Gate servers. Stack this commit on Phase 2; **do not deploy, create cloud resources, modify accounts, or begin Phase 4**.

**Implementation is not proof of runtime operation.** Phase 1 iPhone single-server OpenVPN connection and changed egress IPv4 were observed on 2026-11-13 using a manually adjusted local JSON (Tokyo was not reached). Regenerated JSON, Phase 2 automatic reconnect/failover, Cloudflare Worker runtime, VPN Gate API accessibility from Cloudflare, and background profile refresh on sing-box MT remain **NOT_TESTED** at integration level.

## Architecture

1. Operator tests a candidate *ingress* IP on an iPhone/iPad, checks its observed *egress* IP and whether the **target app** says Tokyo, and approves the ingress IP explicitly.
2. Worker Cron (every 30 minutes, UTC) requests `https://www.vpngate.net/api/iphone/` with TLS, a short deadline, and a bounded response size.
3. Parse CSV, keep `CountryShort=JP` entries matching an exact `APPROVED_REMOTES` IP/port/transport pin; parse inline `.ovpn` profiles using a conservative directive whitelist. Reject unknown directives, external credential paths, malformed certs, private/reserved addresses, remote-IP mismatches, and insecure TLS options.
4. Group candidates by **identical** TLS roots/control keys/ciphers/identity rules and credentials. Select the largest compatible group, preserving latency ordering; require **at least two distinct servers**. CA union is **not** supported.
5. Generate one OpenVPN Client Endpoint with `servers` and the existing Phase 2 TUN/route/DNS structure. Write a validated snapshot into a single Workers KV key.
6. Authenticated `GET /profile.json` serves the current profile; authenticated `GET /health` reports only its age and number of remotes. A missing snapshot, one older than 2 hours, or one containing a remote no longer present in the current `APPROVED_REMOTES` receives HTTP 503; the Worker never emits a `direct` fallback route.

**Important:** A VPN Gate CSV entry is NOT a live OpenVPN connection probe. A healthy API request alone does not establish that the chosen volunteers are reachable or that they will exit in Tokyo. KV is eventually consistent, and cannot support instantaneous failover. sing-box MT is responsible for VPN transport and switching; the Worker only updates the *candidate profile*.

## Local tests (no Cloudflare account required)

```bash
cd worker
npm test
```

Uses only Node.js built-in test runner (`node >= 20`), with no dependencies installed. Test certificates in `worker/test/fixtures/` are throwaway public-only fixtures, not credentials. Fixtures use well-known example public IP addresses as **fake test rows only** and must never be registered as real VPN Gate servers.

## Deployment preparation — NOT authorized or performed in this task

When and only when Human Owner later approves Cloudflare setup:

1. Create one Workers KV namespace. KV is eventually consistent; recently updated profiles can be seen late in other regions (often up to 60 seconds or more).
2. Copy `worker/wrangler.example.jsonc` to `worker/wrangler.jsonc` (the real config is gitignored). Set its KV namespace ID.
3. **Independently test at least two different VPN Gate ingress IPs** on iOS and record exit IP + target app Tokyo judgment. Add each approved *ingress IP, port, and transport* to `APPROVED_REMOTES` in `IP:port/tcp` or `IP:port/udp` form. Do NOT use fixture IPs, IPs inferred solely from a CSV `JP` label, or personal secrets.
4. Configure access control: **both `/profile.json` and `/health` require `PROFILE_ACCESS_TOKEN`** (a 64-hex-character Cloudflare Secret). Supply `Authorization: Bearer <token>`, or use `/profile.json?token=<token>` for an iOS Remote Profile client that cannot add a custom header. Missing/invalid authentication returns HTTP 401; a missing/invalid Worker Secret returns HTTP 503. Treat the token-bearing URL as a secret. VPN Gate profiles can contain publicly distributed inline client certificates **and private keys**. The converter preserves this pair; the Worker refuses to persist or serve `tls.client_key` unless `ALLOW_PUBLIC_CLIENT_KEYS` is explicitly set to `"true"` after Human Owner approval. This permits KV storage and **authenticated** delivery; it does not remove token authentication. Do not enable it for personal, uniquely issued, or confidential credentials, and do not assume every API-provided key is public test material. Never paste the profile JSON, client key, or token-bearing URL into GitHub issues, logs, or support requests.
5. After approval, use the GitHub Actions deployment workflow described below, confirm Cron execution, then test `/health` and `/profile.json` **with a valid `PROFILE_ACCESS_TOKEN`**. Even with valid authentication, `/profile.json` initially returns HTTP 503 **until the first successful Cron refresh**; this is intentional. Do not make a forced refresh HTTP endpoint.
6. Import `https://<YOUR-WORKER>.workers.dev/profile.json?token=<token>` as a **Remote Profile** in sing-box MT, keeping the full URL confidential. Record whether iOS actually refreshes and activates it while the VPN is running; **do not assume** a downloaded profile forces the app to reload its live VPN configuration.

The config template intentionally contains nonfunctional placeholders and does **not** deploy as-is.

## Stop conditions / risk decisions

- `<2` compatible, distinct approved servers: **no new KV write**. The previous snapshot can be served until its two-hour expiry only while every remote in it remains in the current `APPROVED_REMOTES`; removing any remote from that list makes both `/profile.json` and `/health` return HTTP 503 immediately. This does **not** disconnect a device that already cached a profile — actual fail-closed network behavior requires an independent iOS leak test.
- Unexpected API redirect, timeout, HTTP error, malformed CSV, unknown/malicious OpenVPN directive: **no new KV write**. Do not silently drop TLS checks or promote all JP servers to Tokyo-approved.
- iOS Phase 2 failover is still NOT_TESTED: this Phase 3 is a *config distribution layer*, not an independent runtime failover solution.
- Server's IP may be a data-center IP or its egress differs from its ingress. Tokyo classification can change at any time; Workers cannot certify the target app's current GeoIP interpretation. `APPROVED_REMOTES` contains operator-verified ingress IP/port/transport pins, not self-healing Tokyo discovery.
- iOS VPN interruption can leak traffic via direct carrier/Wi-Fi paths and IPv6 or DNS; the emitted config's direct-fallback absence and Endpoint `block_ipv6` do not constitute a verified OS-level kill switch.
- Workers KV cache propagation, Cron cold start, API limits, app background refresh, and Cloudflare runtime behavior are **not tested** by local Node tests.
- Secrets, cloud resources, any live deployment, Phase 4 and separate reviews are outside this task. Stop after GitHub commit/readback.

## References

- VPN Gate catalog: https://www.vpngate.net/api/iphone/
- sing-box 1.14 OpenVPN Endpoint: https://sing-box.sagernet.org/configuration/endpoint/openvpn-client/
- Cloudflare Cron: https://developers.cloudflare.com/workers/configuration/cron-triggers/
- Workers KV consistency: https://developers.cloudflare.com/kv/concepts/how-kv-works/

## 2026-11-13 — Phase 3 current deployment gate (supersedes earlier untested status)

The user tested both `119.105.93.237:1279/tcp` and
`126.234.242.57:1281/tcp` on iPhone: both have Tokyo egress. The Phase 2
combined profile and first-remote-failed automatic retry succeeded; Wi-Fi->4G
restored the tunnel and Tokyo IPv4 without taps. DNS test found only Cloudflare
resolvers, no public IPv6 was observed while connected. Mid-session server
outage failover and leak-free network transition remain **NOT VERIFIED**.

This Worker now requires `APPROVED_REMOTES` with exact IP, port, transport.
A port change is rejected: renewed iPhone verification is mandatory.
This is *refresh of approved identities*, not auto-promotion of new Tokyo IPs.
`GET /profile.json` and `GET /health` require a 64-hex
`PROFILE_ACCESS_TOKEN` Cloudflare Secret, sent as a Bearer header or
`?token=` (iOS Remote Profile URL, treat as sensitive).

| Type | Name | Required value |
|---|---|---|
| Workers KV | `PROFILE_KV` | New namespace ID |
| Variable | `APPROVED_REMOTES` | `119.105.93.237:1279/tcp,126.234.242.57:1281/tcp` |
| Variable | `MAX_SERVERS` | `2` |
| Variable | `ALLOW_PUBLIC_CLIENT_KEYS` | `false` until public/test-only client key is verified |
| Secret | `PROFILE_ACCESS_TOKEN` | Locally generated via `openssl rand -hex 32`, never shared |

Operator-run commands (NOT run by the code-writing assistant):

```bash
cd ~/program/private/vpn-orbit/worker
npm test
cp wrangler.example.jsonc wrangler.jsonc
npx wrangler@latest login
npx wrangler@latest kv namespace create PROFILE_KV
# Set returned KV id in ignored wrangler.jsonc.
openssl rand -hex 32
npx wrangler@latest secret put PROFILE_ACCESS_TOKEN
# After inspecting VPN Gate client-key classification and explicit approval:
npx wrangler@latest deploy
```

`wrangler secret put` may deploy a Worker version immediately. This is why
cloud commands and the explicit client-key distribution decision are separate.
If VPN Gate rows contain an inline client private key, the existing
`ALLOW_PUBLIC_CLIENT_KEYS=false` gate refuses to persist or serve the profile.
Do not override this for private/personal identity material. A protected URL
can still leak if shared, logged or included in screenshots.

Authenticated test after a successful Cron (initially HTTP 503 until refreshed):

```bash
read -rsp 'Token: ' VPN_ORBIT_TOKEN; echo
curl --fail-with-body -H "Authorization: Bearer ${VPN_ORBIT_TOKEN}" \
  'https://<YOUR-WORKER>.workers.dev/health'
unset VPN_ORBIT_TOKEN
```

No Cloudflare resource is created by the GitHub changes.
Remote Profile refresh in sing-box MT is still not runtime-verified.

## GitHub Actions deployment (preferred; 2026-11-13)

Use **GitHub Actions, not local `wrangler deploy`**. After merging this
branch into `master`, open **Actions > VPN Orbit Worker > Run workflow**
on `master`. `pull_request` only runs `npm test`; the deployment job
cannot run on pull requests, pushes or non-master manual dispatches.

Under **Repository Settings > Secrets and variables > Actions**, add:

| Setting type | Name | Value |
|---|---|---|
| Secret | `CLOUDFLARE_API_TOKEN` | Account-scoped **Edit Cloudflare Workers** token, limited to the target account |
| Secret | `PROFILE_ACCESS_TOKEN` | 64 hex characters from `openssl rand -hex 32`; keep a private local copy for iOS |
| Variable | `CLOUDFLARE_ACCOUNT_ID` | 32-character Cloudflare account ID |
| Variable | `CLOUDFLARE_KV_NAMESPACE_ID` | `8c2f963fe91f48b493d068d0a0fb7493` |

The existing KV namespace is **reused** (even if renamed to
`vpn-orbit-tokyo-profiles`); the Worker binding stays `PROFILE_KV`.
No GitHub Variable is needed for the pinned Tokyo candidates; those exact
IP:port/protocol pairs are in the committed Wrangler example.

The workflow generates an ignored `worker/wrangler.jsonc` from the committed
example, substitutes only the existing KV namespace ID, and sets
`ALLOW_PUBLIC_CLIENT_KEYS=true` for the **already independently confirmed
public shared VPN Gate key**. It validates the exact two authorized remotes,
requires tests to pass, and uploads the `PROFILE_ACCESS_TOKEN` secret
**atomically with the Worker deployment** using Wrangler `--secrets-file`.
Temporary secret files are not committed and are deleted on step exit.
Missing or malformed settings prevent deployment. The GitHub token is never
written to the repo; it is used by Wrangler in the runner environment.

The Worker still rejects unknown ports, different TLS profiles, stale KV
snapshots and unauthenticated profile requests. If the VPN Gate public client
key changes or the operator-verified pair becomes unavailable, no new
profile is published. Auto-discovery of fresh Tokyo exit IPs and instantaneous
iOS kill-switch safety are NOT established.

The workflow becomes manually runnable only after it exists on the default
branch (`master`). The GitHub integration does not deploy anything merely
by adding this file to a feature branch. **Do not run a separate local
`wrangler secret put`**, because that operation immediately deploys.
