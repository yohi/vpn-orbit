# Phase 2 — sing-box OpenVPN native server failover PoC

## Scope and limitations

Phase 2 adds an **offline generator** for one OpenVPN Client Endpoint with a `servers` list. sing-box 1.14+ documents that it tries the next remote when a connection fails. Unlike an `urltest` outbound, this uses OpenVPN's **native connection/reconnection** behavior. No server is managed and no Worker is deployed.

**Not verified:** iPhone/iPad sing-box MT actually loads the multi-remote profile, the server in use changes without interaction after a *live* disconnect, the location resolves to Tokyo, and traffic cannot escape during VPN restart. A local test run is not evidence of those properties. Do not call Phase 2 complete at the runtime level without these observations.

## Generate the test config

Default (strict): only profiles with identical CA, TLS wrap, identity checks, cipher/auth and credentials can be placed in the same Endpoint:

```bash
python3 -m vpn_orbit.phase2 \
  --ovpn /path/to/vpn-a.ovpn /path/to/vpn-b.ovpn \
  --output /tmp/vpn-orbit-phase2.json
```

Catalog-driven selection from Japanese VPN Gate servers (cannot guarantee Tokyo geolocation):

```bash
python3 -m vpn_orbit.phase2 --from-vpngate \
  --max-servers 5 --output /tmp/vpn-orbit-phase2.json
```

If different CAs mean strict selection finds fewer than two compatible servers, the process exits with code 1 and **does not generate a config**. The first-ranked server is not mandatory: the converter selects the largest compatible group, ordered by catalog rank.

### Explicit *experimental* CA-union mode

```bash
python3 -m vpn_orbit.phase2 \
  --ovpn /path/to/vpn-a.ovpn /path/to/vpn-b.ovpn \
  --allow-ca-union --output /tmp/vpn-orbit-phase2-experimental.json
```

This combines the CA trust bundles of the selected peers only if **all other** TLS settings, server-name checks, control keys, data cipher/auth and credentials are identical. It does **not** pin a CA to an individual remote IP. Any selected CA could authenticate a certificate at any configured IP (subject to the shared name/EKU conditions). The converter prints a warning when trust expands. **This mode is for an explicitly accepted PoC risk, not secure production deployment.** If the source lacks `verify-x509-name`, the resulting endpoint has no explicit hostname pinning. Do not disable certificate verification to make profiles compatible.

In particular, mutually incompatible `tls-auth` / `tls-crypt`, authentication, or identity checks remain an error even with this flag. No separate protocol-specific session credentials can be bound per remote in this configuration.

## How to test on iOS/iPadOS

1. Keep the Phase 1 single-server test as the **baseline**. If Phase 1 cannot connect, Phase 2 network results are inconclusive.
2. Install sing-box MT 1.14+ and turn OFF other device VPNs such as WARP during this test. Import the locally generated JSON using a private transfer (AirDrop/Files). Do not upload live profiles or credentials to GitHub/public URLs.
3. Connect and record the visible server IP / session status, external IPv4, city reported by two GeoIP services, and the target app's location judgment. Confirm at least one working connection first.
4. While the device remains connected to the same Wi-Fi/mobile network, arrange a **controlled outage** of the current OpenVPN remote (if possible, use test endpoints you control, not a destructive action against public VPN Gate servers). Alternatively, wait for a natural failure and record it. Do not interfere with a volunteer-operated public server.
5. Observe whether sing-box reconnects to a *different* server from `servers` without user action. Measure outage duration and whether the VPN UI and app networking recover. Compare the observed exit IP to each source server. Repeat once on Wi-Fi and once on cellular if practical.
6. During the interruption, verify that traffic is blocked rather than silently using the original carrier IP; also check IPv6 and DNS behavior. Phase 2's `block_ipv6` applies to the OpenVPN Endpoint only and **is not** a verified OS-level kill switch. If direct traffic is observed, stop the experiment before using an IP-sensitive application.
7. If it does not switch, collect only redacted sing-box logs, app version, protocol/port, OpenVPN/TLS error, and whether the error occurred at initial connection versus after an established tunnel. Do **not** disable TLS verification or expand to Phase 3 automatically.

## Judgment checkpoint

| Observation | Meaning |
|---|---|
| JSON generated, 22 unit tests PASS | Converter logic verified offline only |
| sing-box loads config | Schema compatibility proven for tested app version |
| VPN establishes | At least one remote and TLS settings work |
| Different exit IP after outage with no taps | Failover behavior observed (network test) |
| No direct egress on outage | Must be independently checked; not implied by failover success |
| No supported remote group even with safe constraints | Do not claim Phase 2 accomplished the automatic-switch goal |

**Stop after the first live iOS result and ask the Human Owner to decide** whether the functionality is sufficient. No Phase 3 Workers work or unrelated review process is authorized by this task.

Official references:
- https://sing-box.sagernet.org/configuration/endpoint/openvpn-client/
- https://sing-box.sagernet.org/configuration/endpoint/
- https://sing-box.sagernet.org/configuration/outbound/urltest/
