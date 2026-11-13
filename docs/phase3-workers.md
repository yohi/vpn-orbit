# Phase 3 — Cloudflare Workers candidate refresh and remote profile distribution

## Goal / completion boundary

Implement a **Cloudflare Worker source module**, deterministic tests, and a deployment *template* to serve a single sing-box 1.14+ profile from a reviewed list of geographically verified VPN Gate servers. Stack this commit on Phase 2; **do not deploy, create cloud resources, modify accounts, or begin Phase 4**.

**Implementation is not proof of runtime operation.** Phase 1 iPhone single-server OpenVPN connection and changed egress IPv4 were observed on 2026-11-13 using a manually adjusted local JSON (Tokyo was not reached). Regenerated JSON, Phase 2 automatic reconnect/failover, Cloudflare Worker runtime, VPN Gate API accessibility from Cloudflare, and background profile refresh on sing-box MT remain **NOT_TESTED** at integration level.

## Architecture

1. Operator tests a candidate *ingress* IP on an iPhone/iPad, checks its observed *egress* IP and whether the **target app** says Tokyo, and approves the ingress IP explicitly.
2. Worker Cron (every 30 minutes, UTC) requests `https://www.vpngate.net/api/iphone/` with TLS, a short deadline, and a bounded response size.
3. Parse CSV, keep `CountryShort=JP` and `APPROVED_IPS` entries; parse inline `.ovpn` profiles using a conservative directive whitelist. Reject unknown directives, external credential paths, malformed certs, private/reserved addresses, remote-IP mismatches, and insecure TLS options.
4. Group candidates by **identical** TLS roots/control keys/ciphers/identity rules and credentials. Select the largest compatible group, preserving latency ordering; require **at least two distinct servers**. CA union is **not** supported.
5. Generate one OpenVPN Client Endpoint with `servers` and the existing Phase 2 TUN/route/DNS structure. Write a validated snapshot into a single Workers KV key.
6. `GET /profile.json` serves the current profile; `GET /health` reports only its age and number of remotes. A missing snapshot, one older than 2 hours, or one containing a remote no longer present in the current `APPROVED_IPS` receives HTTP 503; the Worker never emits a `direct` fallback route.

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
3. **Independently test at least two different VPN Gate ingress IPs** on iOS and record exit IP + target app Tokyo judgment, then put their *ingress* IPs into `APPROVED_IPS`. Do NOT use the fixture IPs, an IP inferred solely from a CSV `JP` label, or personal secrets.
4. Review the resulting Worker URL and public access exposure. There is no login or API token: **`/profile.json` is public**. VPN Gate profiles may contain dummy inline client certificates **and private keys** published by its official API. The converter preserves this pair; the Worker refuses to publish any profile containing `tls.client_key` unless the Human Owner explicitly approves exposure and sets `ALLOW_PUBLIC_CLIENT_KEYS` to the literal string `"true"`. Its default is `"false"`. With opt-in, the key is stored in KV and served to anyone with the public URL. Do not approve this for personal, uniquely issued, or confidential credentials; do not assume that all keys are dummy merely because an API returned them. Never paste generated JSON into GitHub issues, logs, or support requests.
5. After approval, install a current Wrangler CLI or use the native Cloudflare deployment workflow, deploy the Worker, confirm Cron execution, then test `/health` and `/profile.json`. `/profile.json` initially returns 503 **until the first successful Cron refresh**; this is intentional. Do not make a forced refresh HTTP endpoint.
6. Import the deployed HTTPS URL as a **Remote Profile** in sing-box MT; record whether iOS actually refreshes and activates it while the VPN is running. The new profile URL can be public; **do not assume** it forces the app to reload its live VPN configuration.

The config template intentionally contains nonfunctional placeholders and does **not** deploy as-is.

## Stop conditions / risk decisions

- `<2` compatible, distinct approved servers: **no new KV write**. The previous snapshot can be served until its two-hour expiry only while every remote in it remains in the current `APPROVED_IPS`; removing any remote from that list makes both `/profile.json` and `/health` return HTTP 503 immediately. This does **not** disconnect a device that already cached a profile — actual fail-closed network behavior requires an independent iOS leak test.
- Unexpected API redirect, timeout, HTTP error, malformed CSV, unknown/malicious OpenVPN directive: **no new KV write**. Do not silently drop TLS checks or promote all JP servers to Tokyo-approved.
- iOS Phase 2 failover is still NOT_TESTED: this Phase 3 is a *config distribution layer*, not an independent runtime failover solution.
- Server's IP may be a data-center IP or its egress differs from its ingress. Tokyo classification can change at any time; Workers cannot certify the target app's current GeoIP interpretation. `APPROVED_IPS` is a human attestation, not self-healing Tokyo discovery.
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
