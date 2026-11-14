#!/usr/bin/env node
/**
 * Run locally ONLY against the previously verified iPhone merged JSON.
 * Prints one GitHub Actions Variable value; no certificates or private keys.
 */
import {readFileSync} from 'node:fs';
import {sharedIdentitySha256} from '../src/identity.mjs';

const sourcePath=process.argv[2];
if (!sourcePath || process.argv.length!==3) {
  console.error('Usage: node scripts/approved-identities.mjs /path/to/verified-phase2.json');
  process.exitCode=2;
} else {
  try {
    const cfg=JSON.parse(readFileSync(sourcePath,'utf8'));
    const ep=cfg?.endpoints?.length===1 ? cfg.endpoints[0] : null;
    const expected=new Map([
      ['119.105.93.237',{port:1279,network:'tcp'}],
      ['126.234.242.57',{port:1281,network:'tcp'}]
    ]);
    if (ep?.type!=='openvpn-client' || !Array.isArray(ep.servers) ||
        ep.servers.length!==expected.size || cfg.route?.final!=='vpn-gate') {
      throw new Error('not the verified two-remote sing-box profile shape');
    }
    for (const remote of ep.servers) {
      const pin=expected.get(remote.server);
      if (!pin || pin.port!==remote.server_port || pin.network!==remote.network) {
        throw new Error('remote differs from the verified Tokyo pair');
      }
    }
    const digest=await sharedIdentitySha256(ep);
    console.log('APPROVED_IDENTITY_SHA256='+ep.servers.map(remote=>
      remote.server+':'+remote.server_port+'/'+remote.network+'='+digest
    ).join(','));
  } catch {
    // Never print path content, certificate, private key or a token.
    console.error('Could not derive approvals from the selected verified profile');
    process.exitCode=1;
  }
}
