# VPN Orbit Cloudflare Worker — Phase 3

Workers-side distribution of a Phase 2-compatible sing-box MT OpenVPN profile. This code **does not** establish a VPN connection, verify Tokyo GeoIP automatically, or switch active iOS VPN connections itself.

Run local tests (no dependencies):

```bash
cd worker && npm test
```

Routes after approved deployment: `GET /health` and `GET /profile.json`.

Scheduled refresh uses Cron + KV and requires **at least two** explicitly approved, mutually compatible VPN Gate server IPs. This repository contains only a nonfunctional configuration template; nothing has been deployed. See [Phase 3 documentation](../docs/phase3-workers.md).
