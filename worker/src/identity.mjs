/**
 * Stable SHA-256 approval of shared OpenVPN TLS material, client identity and
 * authentication settings. Never store or log the raw client private key.
 * The remote address list is pinned separately with APPROVED_REMOTES.
 */
const REMOTE_ONLY = new Set(['server','server_port','network','servers','tag','ping_interval','ping_restart']);

function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new Error('unsupported identity object');
    return '{' + Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',') + '}';
  }
  throw new Error('unsupported identity value');
}

export async function sharedIdentitySha256(endpoint) {
  if (!endpoint || Array.isArray(endpoint) || endpoint.type !== 'openvpn-client' ||
      !endpoint.tls || !Array.isArray(endpoint.tls.certificate) || !endpoint.tls.certificate.length) {
    throw new Error('invalid OpenVPN identity');
  }
  const shared = Object.fromEntries(Object.entries(endpoint).filter(([k])=>!REMOTE_ONLY.has(k)));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical(shared)));
  return [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

export function parseIdentityApprovals(raw,remotePins) {
  if (!(remotePins instanceof Map) || typeof raw !== 'string') throw new Error('identity approval missing');
  const entries=raw.split(/[\s,]+/).filter(Boolean);
  if (entries.length !== remotePins.size) throw new Error('identity approval cardinality mismatch');
  const pins=new Map();
  for (const entry of entries) {
    const m=/^((?:\d{1,3}\.){3}\d{1,3}):([1-9]\d{0,4})\/(tcp|udp)=([a-fA-F0-9]{64})$/.exec(entry);
    if (!m) throw new Error('invalid identity approval');
    const remote=remotePins.get(m[1]);
    if (!remote || remote.port !== Number(m[2]) || remote.network !== m[3] || pins.has(m[1])) {
      throw new Error('identity approval does not match approved remote');
    }
    pins.set(m[1],m[4].toLowerCase());
  }
  return pins;
}
