/**
 * Phase 3: parse VPN Gate's UNTRUSTED public catalog and construct a minimal
 * sing-box 1.14 OpenVPN endpoint. No downloaded OpenVPN directives are executed.
 * Keep behavior aligned with vpn_orbit.phase1 / phase2 (strict CA group only).
 */
export const API_URL = 'https://www.vpngate.net/api/iphone/';
export const MAX_CATALOG_BYTES = 16 * 1024 * 1024;
export const MAX_PROFILE_BYTES = 128 * 1024;
const CIPHERS = new Set(['AES-128-CBC', 'AES-256-CBC', 'AES-128-GCM', 'AES-256-GCM']);
const AUTHS = new Set(['SHA1', 'SHA256', 'SHA384', 'SHA512']);
const IGNORED = new Set([
  'client','dev','dev-type','nobind','persist-key','persist-tun',
  'resolv-retry','verb','mute','remote-random','remote-random-hostname',
  'connect-retry','connect-retry-max','server-poll-timeout','ping','ping-restart',
  'ping-timer-rem','explicit-exit-notify','reneg-sec','sndbuf','rcvbuf',
  'auth-nocache','route-delay','setenv','setenv-safe','pull','tls-client'
]);
const ALLOWED = new Set([
  'proto','remote','cipher','data-ciphers','data-ciphers-fallback','auth',
  'auth-user-pass','key-direction','remote-cert-tls','verify-x509-name',
  'tls-auth','tls-crypt',...IGNORED
]);

export function isPublicIPv4(input) {
  if (typeof input !== 'string' || !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) return false;
  const octets = input.split('.').map(Number);
  if (octets.some(n => n < 0 || n > 255 || !Number.isInteger(n))) return false;
  if (octets.some((n,i) => String(n) !== input.split('.')[i])) return false;
  const [a,b,c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 192 && b === 0 && c === 0) || (a === 192 && b === 0 && c === 2) ||
      (a === 198 && b === 18) || (a === 198 && b === 19) ||
      (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113) ||
      (a === 192 && b === 88 && c === 99)) return false;
  // 192.0.0.0/24 has standards exceptions, but excluding it is safer for public VPN access.
  return true;
}

export function parseCsvLine(line) {
  const fields = []; let value = ''; let quote = false;
  for (let i=0; i<line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (quote && line[i+1] === '"') { value += '"'; i++; }
      else if (quote || value === '') quote = !quote;
      else throw new Error('bad CSV quote');
    } else if (char === ',' && !quote) { fields.push(value); value = ''; }
    else { value += char; }
  }
  if (quote) throw new Error('unclosed CSV quote');
  fields.push(value);
  return fields;
}

function decodeBase64(input) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(input)) throw new Error('invalid base64');
  const binary = atob(input);
  if (binary.length > MAX_PROFILE_BYTES) throw new Error('profile too large');
  return Uint8Array.from(binary, ch => ch.charCodeAt(0));
}

function one(map, key, fallback) {
  const all = map.get(key) || [];
  if (all.length > 1) throw new Error(`duplicate ${key}`);
  return all.length ? all[0] : fallback;
}

function pemBody(body, begin, end, linePattern, maxLines) {
  const lines = body.replace(/\r\n/g, '\n').split('\n');
  while (lines.length && lines[0] === '') lines.shift();
  while (lines.length && lines.at(-1) === '') lines.pop();
  if (lines.length < 3 || lines[0] !== begin || lines.at(-1) !== end) throw new Error('invalid PEM boundaries');
  const encoded = lines.slice(1, -1);
  if (encoded.length > maxLines || encoded.some(line => line.length > 64 || !linePattern.test(line))) throw new Error('invalid PEM body');
  return encoded;
}

function validateCerts(body) {
  const certs = [];
  const lines = body.replace(/\r\n/g, '\n').split('\n');
  let index = 0;
  while (index < lines.length) {
    if (lines[index] === '') { index++; continue; }
    if (lines[index] !== '-----BEGIN CERTIFICATE-----') throw new Error('inline CA must contain certificates only');
    const end = lines.indexOf('-----END CERTIFICATE-----', index + 1);
    if (end < 0) throw new Error('invalid certificate boundaries');
    const encodedLines = pemBody(lines.slice(index, end + 1).join('\n'), '-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', /^[A-Za-z0-9+/]+={0,2}$/, 2048);
    const joined = encodedLines.join('');
    const bytes = decodeBase64(joined);
    if (bytes.length < 64 || bytes[0] !== 0x30) throw new Error('invalid certificate DER');
    certs.push(`-----BEGIN CERTIFICATE-----\n${joined.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`);
    index = end + 1;
  }
  if (!certs.length || certs.length > 6) throw new Error('inline CA must contain certificates only');
  return certs;
}

function validateStaticKey(body) {
  const lines = pemBody(body.trim(), '-----BEGIN OpenVPN Static key V1-----', '-----END OpenVPN Static key V1-----', /^[0-9a-fA-F]+$/, 16);
  const hex = lines.join('');
  if (hex.length !== 512) throw new Error('invalid static key');
  return `-----BEGIN OpenVPN Static key V1-----\n${lines.join('\n')}\n-----END OpenVPN Static key V1-----\n`;
}

function validateClientKey(body) {
  const trimmed = body.trim();
  const first = trimmed.split(/\r?\n/, 1)[0];
  const algorithm = first === '-----BEGIN RSA PRIVATE KEY-----' ? 'RSA ' : first === '-----BEGIN PRIVATE KEY-----' ? '' : null;
  if (algorithm === null) throw new Error('invalid client identity key');
  const lines = pemBody(trimmed, `-----BEGIN ${algorithm}PRIVATE KEY-----`, `-----END ${algorithm}PRIVATE KEY-----`, /^[A-Za-z0-9+/]+={0,2}$/, 2048);
  const der = decodeBase64(lines.join(''));
  if (der.length < 32 || der[0] !== 0x30) throw new Error('invalid client identity key');
}

export function convertOvpn(profile, expectedIp) {
  if (typeof profile !== 'string' || new TextEncoder().encode(profile).length > MAX_PROFILE_BYTES) throw new Error('profile too large');
  const blocks = new Map();
  const restLines = [];
  const lines = profile.replace(/\r\n/g, '\n').split('\n');
  for (let i=0; i<lines.length; i++) {
    const open = /^<(ca|tls-auth|tls-crypt|cert|key)>$/.exec(lines[i]);
    if (!open) { restLines.push(lines[i]); continue; }
    const key = open[1];
    if (blocks.has(key)) throw new Error('duplicate inline block');
    const close = `</${key}>`;
    const end = lines.indexOf(close, i + 1);
    if (end < 0) throw new Error('invalid inline block boundaries');
    blocks.set(key, lines.slice(i + 1, end).join('\n'));
    i = end;
  }
  const rest = restLines.join('\n');
  if (/^\s*<\/?[a-z]/im.test(rest)) throw new Error('unsupported inline block');
  if (blocks.has('cert') !== blocks.has('key')) throw new Error('client identity certificate and key must be paired');
  if (blocks.has('cert')) {
    try {
      validateCerts(blocks.get('cert'));
      validateClientKey(blocks.get('key'));
    } catch {
      throw new Error('invalid client identity certificate or key');
    }
  }
  const directives = new Map();
  for (const raw of rest.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || /^[#;]/.test(line)) continue;
    const [name, ...args] = line.split(/\s+/);
    const key = name.toLowerCase();
    if (!ALLOWED.has(key)) throw new Error(`unsupported directive: ${key}`);
    if (!IGNORED.has(key)) directives.set(key, [...(directives.get(key) || []), args]);
  }
  const remote = one(directives, 'remote');
  if (!remote || remote.length < 2 || remote.length > 3) throw new Error('one remote required');
  const [ip, portRaw] = remote;
  if (!isPublicIPv4(ip) || ip !== expectedIp) throw new Error('remote != approved public IPv4');
  const port = Number(portRaw);
  if (!/^\d{1,5}$/.test(portRaw) || port < 1 || port > 65535) throw new Error('invalid remote port');
  const proto = one(directives, 'proto', ['udp']);
  if (proto.length !== 1) throw new Error('invalid protocol');
  const protocol = (remote.length === 3 ? remote[2] : proto[0]).toLowerCase();
  if (!['udp','udp4','tcp','tcp-client','tcp4','tcp4-client'].includes(protocol)) throw new Error('unsupported protocol');
  if (!blocks.has('ca')) throw new Error('inline CA required');
  const tls = {certificate: validateCerts(blocks.get('ca')), remote_certificate_tls:'server'};
  const certName = one(directives, 'verify-x509-name');
  if (certName) {
    if (certName.length < 1 || certName.length > 2 || !/^[A-Za-z0-9_.-]{1,256}$/.test(certName[0]) ||
      (certName[1] && !['name','subject','name-prefix'].includes(certName[1]))) throw new Error('invalid certificate name');
    tls.server_name = certName[0];
    tls.server_name_type = certName[1] || 'name';
  }
  const remoteCert = one(directives, 'remote-cert-tls');
  if (remoteCert && (remoteCert.length !== 1 || remoteCert[0] !== 'server')) throw new Error('invalid remote-cert-tls');
  if (blocks.has('tls-auth') && blocks.has('tls-crypt')) throw new Error('conflicting TLS keys');
  const direction = one(directives, 'key-direction');
  if (blocks.has('tls-auth')) {
    if (direction && JSON.stringify(direction) !== '["1"]') throw new Error('unsupported key-direction');
    tls.control_wrap = {type:'tls_auth',key:validateStaticKey(blocks.get('tls-auth'))};
    if (direction) tls.control_wrap.direction = 'client';
  } else if (blocks.has('tls-crypt')) {
    if (direction) throw new Error('key-direction for tls-crypt');
    tls.control_wrap = {type:'tls_crypt',key:validateStaticKey(blocks.get('tls-crypt'))};
  } else if (direction) throw new Error('orphan key-direction');
  if (directives.has('tls-auth') || directives.has('tls-crypt')) throw new Error('external control key not allowed');
  const cipher = one(directives,'cipher',['AES-128-CBC']);
  const auth = one(directives,'auth',['SHA1']);
  if (cipher.length !== 1 || !CIPHERS.has(cipher[0].toUpperCase()) || auth.length !== 1 || !AUTHS.has(auth[0].toUpperCase())) throw new Error('unsupported cipher/auth');
  const requested = one(directives,'data-ciphers');
  if (requested && requested.length !== 1) throw new Error('invalid data-ciphers');
  const ciphers = requested ? requested[0].toUpperCase().split(':') : ['AES-256-GCM','AES-128-GCM',cipher[0].toUpperCase()];
  if (ciphers.some(c => !CIPHERS.has(c))) throw new Error('unsupported data-ciphers');
  const fallback = one(directives,'data-ciphers-fallback',[cipher[0]]);
  if (fallback.length !== 1 || !CIPHERS.has(fallback[0].toUpperCase())) throw new Error('unsupported data fallback');
  const userPass = one(directives,'auth-user-pass');
  if (userPass && userPass.length) throw new Error('external credentials not supported');
  const endpoint = {
    type:'openvpn-client',tag:'vpn-gate',mode:'tls',server:ip,server_port:port,
    network:protocol.startsWith('udp')?'udp':'tcp',tls,
    data_ciphers:[...new Set(ciphers)],data_ciphers_fallback:fallback[0].toUpperCase(),
    auth:auth[0].toUpperCase(),ping_interval:'10s',ping_restart:'40s',block_ipv6:true
  };
  if (userPass) { endpoint.username = 'vpn'; endpoint.password = 'vpn'; } // Public VPN Gate credentials only.
  return endpoint;
}

export function parseCatalog(csv, approvedIps) {
  if (!(approvedIps instanceof Set) || approvedIps.size < 2 || [...approvedIps].some(ip=>!isPublicIPv4(ip))) throw new Error('at least two valid approved IPv4s required');
  if (new TextEncoder().encode(csv).length > MAX_CATALOG_BYTES) throw new Error('catalog too large');
  const lines = csv.replace(/^\uFEFF/,'').split(/\r?\n/);
  const pos = lines.findIndex(s=>s.startsWith('#HostName,') || s.startsWith('HostName,'));
  if (pos < 0) throw new Error('catalog header missing');
  const keys = parseCsvLine(lines[pos].replace(/^#/,'')).map(s=>s.trim());
  for (const k of ['HostName','IP','CountryShort','Ping','Speed','Score','OpenVPN_ConfigData_Base64']) {
    if (!keys.includes(k)) throw new Error(`catalog missing ${k}`);
  }
  const results = []; const seen = new Set();
  for (const line of lines.slice(pos+1)) {
    if (!line || line.startsWith('*')) continue;
    try {
      const cells = parseCsvLine(line);
      if (cells.length !== keys.length) continue;
      const row = Object.fromEntries(keys.map((k,i)=>[k,cells[i]]));
      if (row.CountryShort.toUpperCase() !== 'JP' || !approvedIps.has(row.IP) || seen.has(row.IP)) continue;
      if (row.OpenVPN_ConfigData_Base64.length > MAX_PROFILE_BYTES * 2) continue;
      const raw = decodeBase64(row.OpenVPN_ConfigData_Base64);
      const profile = new TextDecoder('utf-8',{fatal:true}).decode(raw);
      const endpoint = convertOvpn(profile, row.IP);
      results.push({ip:row.IP,hostname:row.HostName,endpoint,
        ping:Number.isFinite(+row.Ping)?+row.Ping:9999,
        speed:Number.isFinite(+row.Speed)?+row.Speed:0,
        score:Number.isFinite(+row.Score)?+row.Score:0});
      seen.add(row.IP);
    } catch { /* Untrusted volunteer server profile rejected, never relaxed. */ }
  }
  results.sort((a,b)=>(a.ping>0?a.ping:9999)-(b.ping>0?b.ping:9999) || b.speed-a.speed || b.score-a.score || a.ip.localeCompare(b.ip));
  return results;
}

function comparisonKey(ep) {
  const {server,server_port,network,tag,ping_interval,ping_restart,...shared}=ep;
  return JSON.stringify(shared);
}

export function selectGroup(candidates, maxServers=5) {
  if (!Number.isInteger(maxServers) || maxServers < 2 || maxServers > 20) throw new Error('invalid max servers');
  let best = [];
  for (const reference of candidates) {
    const key = comparisonKey(reference.endpoint);
    const group = candidates.filter(c=>comparisonKey(c.endpoint) === key);
    if (group.length > best.length) best = group;
  }
  best = best.slice(0,maxServers);
  if (best.length < 2) throw new Error('fewer than two compatible approved VPN Gate servers');
  const merged = structuredClone(best[0].endpoint);
  delete merged.server;
  delete merged.server_port;
  delete merged.network;
  merged.servers = best.map(c=>({server:c.endpoint.server,server_port:c.endpoint.server_port,network:c.endpoint.network}));
  return {endpoint:merged,selected:best.map(c=>c.ip)};
}

export function buildConfig(endpoint) {
  return {
    log:{level:'warn'},
    dns:{servers:[{type:'udp',tag:'vpn-dns',server:'1.1.1.1',server_port:53,detour:'vpn-gate'}],final:'vpn-dns'},
    inbounds:[{type:'tun',tag:'tun-in',address:['172.28.250.1/30'],auto_route:true,dns_mode:'hijack',mtu:1400}],
    endpoints:[endpoint],
    route:{rules:[{protocol:'dns',action:'hijack-dns'}],final:'vpn-gate'}
  };
}
