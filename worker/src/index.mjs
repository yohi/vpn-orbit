import {API_URL,MAX_CATALOG_BYTES,isPublicIPv4,parseCatalog,selectGroup,buildConfig} from './catalog.mjs';
import {sharedIdentitySha256,parseIdentityApprovals} from './identity.mjs';


/* Human-approved remote identity: IP + port + transport verified on iPhone. */
export function parseApprovedRemotes(raw) {
  if (typeof raw!=='string') throw Error('APPROVED_REMOTES requires 2-20 entries');
  const items=raw.split(/[\s,]+/).filter(Boolean);
  if (items.length<2 || items.length>20) throw Error('APPROVED_REMOTES requires 2-20 entries');
  const pins=new Map();
  for (const item of items) {
    const m=/^((?:\d{1,3}\.){3}\d{1,3}):([1-9]\d{0,4})\/(tcp|udp)$/.exec(item);
    if (!m || !isPublicIPv4(m[1])) throw Error('invalid approved remote');
    const port=Number(m[2]);
    if (port>65535 || pins.has(m[1])) throw Error('duplicate or invalid approved remote');
    pins.set(m[1],{port,network:m[3]});
  }
  return pins;
}
const validToken=t=>typeof t==='string' && /^[a-fA-F0-9]{64}$/.test(t);
function authorized(request,secret) {
  const url=new URL(request.url), tokens=url.searchParams.getAll('token');
  const header=request.headers.get('Authorization');
  if (tokens.length>1 || (header && tokens.length)) return false;
  const m=header && /^Bearer ([a-fA-F0-9]{64})$/.exec(header);
  const supplied=tokens.length?tokens[0]:m?.[1];
  if (!validToken(supplied)) return false;
  let diff=0;
  for(let i=0;i<64;i++) diff|=secret.charCodeAt(i)^supplied.charCodeAt(i);
  return diff===0;
}

const SNAPSHOT_KEY = 'profile-v1';
const MAX_AGE_MS = 2 * 60 * 60 * 1000; // Serve nothing if last refresh is older than 2h.
const MAX_PROFILE_JSON = 512 * 1024;
const PROBE_TIMEOUT_MS = 14000;
const REFRESH_ERROR_CODES = new Set([
  'PROFILE_KV_MISSING','APPROVED_REMOTES_INVALID','APPROVED_IDENTITIES_INVALID','PROFILE_TOKEN_MISSING','MAX_SERVERS_INVALID',
  'API_FETCH_FAILED','API_RESPONSE_INVALID','CATALOG_TOO_LARGE',
  'CATALOG_BODY_MISSING','CATALOG_ENCODING_INVALID','CATALOG_INVALID',
  'INSUFFICIENT_COMPATIBLE_SERVERS','GROUP_SELECTION_FAILED',
  'PROFILE_BUILD_FAILED','PROFILE_TOO_LARGE','SNAPSHOT_WRITE_FAILED',
  'CLIENT_KEY_PUBLICATION_NOT_ALLOWED',
]);

class RefreshError extends Error {
  constructor(code,message,options) {
    super(message,options);
    this.code=code;
  }
}

function refreshErrorCode(error) {
  return error instanceof RefreshError && REFRESH_ERROR_CODES.has(error.code)
    ? error.code
    : 'REFRESH_FAILED';
}

function response(message,status,headers={}) {
  return new Response(message,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Robots-Tag':'noindex, nofollow',...headers}});
}

export async function refreshProfile(env, fetchFn=fetch, now=Date.now()) {
  if (!env?.PROFILE_KV?.put) throw new RefreshError('PROFILE_KV_MISSING','PROFILE_KV is required');
  if (!validToken(env.PROFILE_ACCESS_TOKEN)) throw new RefreshError('PROFILE_TOKEN_MISSING','profile token required');
  let pins;
  try {pins=parseApprovedRemotes(env.APPROVED_REMOTES);}
  catch(error) {throw new RefreshError('APPROVED_REMOTES_INVALID','invalid approved remote identities',{cause:error});}
  let approvedIdentities;
  try {approvedIdentities=parseIdentityApprovals(env.APPROVED_IDENTITY_SHA256,pins);}
  catch(error) {throw new RefreshError('APPROVED_IDENTITIES_INVALID','missing or invalid approved identities',{cause:error});}
  const approved=new Set(pins.keys());
  const count = env.MAX_SERVERS === undefined ? 5 : Number(env.MAX_SERVERS);
  if (!Number.isInteger(count) || count < 2 || count > 20) throw new RefreshError('MAX_SERVERS_INVALID','MAX_SERVERS must be 2-20');
  const controller = new AbortController();
  const timeout = setTimeout(()=>controller.abort(),PROBE_TIMEOUT_MS);
  let csv;
  try {
    const res = await fetchFn(API_URL,{signal:controller.signal,headers:{Accept:'text/plain'}});
    if (!res.ok || new URL(res.url || API_URL).href !== API_URL) throw new RefreshError('API_RESPONSE_INVALID','unexpected API response or redirect');
    if (Number(res.headers?.get('content-length') || 0) > MAX_CATALOG_BYTES) throw new RefreshError('CATALOG_TOO_LARGE','catalog too large');
    const reader = res.body?.getReader();
    if (!reader) throw new RefreshError('CATALOG_BODY_MISSING','catalog response body missing');
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const {done,value} = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_CATALOG_BYTES) {
          await reader.cancel();
          throw new RefreshError('CATALOG_TOO_LARGE','catalog too large');
        }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.byteLength; }
    try {
      csv = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    } catch (error) {
      throw new RefreshError('CATALOG_ENCODING_INVALID','catalog is not valid UTF-8',{cause:error});
    }
  } catch (error) {
    if (error instanceof RefreshError) throw error;
    throw new RefreshError('API_FETCH_FAILED','catalog fetch failed',{cause:error});
  } finally { clearTimeout(timeout); }
  let candidates;
  try {
    // Keep duplicate approved transports until identity verification completes.
    // An unapproved earlier TLS profile must not reserve an IP against a later valid row.
    candidates=[];
    const acceptedIps=new Set();
    for (const c of parseCatalog(csv,approved,pins,true)) {
      if (acceptedIps.has(c.ip)) continue;
      if (await sharedIdentitySha256(c.endpoint) !== approvedIdentities.get(c.ip)) continue;
      candidates.push(c);
      acceptedIps.add(c.ip);
    }
  } catch (error) {
    throw new RefreshError('CATALOG_INVALID','catalog could not be parsed',{cause:error});
  }
  let endpoint,selected;
  try {
    ({endpoint,selected} = selectGroup(candidates,count));
  } catch (error) {
    const code = error instanceof Error && error.message === 'fewer than two compatible approved VPN Gate servers'
      ? 'INSUFFICIENT_COMPATIBLE_SERVERS'
      : 'GROUP_SELECTION_FAILED';
    const message = code === 'INSUFFICIENT_COMPATIBLE_SERVERS'
      ? 'fewer than two compatible approved VPN Gate servers'
      : 'compatible approved server selection failed';
    throw new RefreshError(code,message,{cause:error});
  }
  let config;
  try {
    config = buildConfig(endpoint);
  } catch (error) {
    throw new RefreshError('PROFILE_BUILD_FAILED','profile generation failed',{cause:error});
  }
  // Only operator-verified, already public shared test keys may be distributed.
  // An independent access token is required to retrieve the profile.
  if (endpoint.tls?.client_key?.length && env.ALLOW_PUBLIC_CLIENT_KEYS !== 'true') {
    throw new RefreshError('CLIENT_KEY_PUBLICATION_NOT_ALLOWED',
      'distribution of embedded client keys requires explicit opt-in');
  }
  const profile = JSON.stringify(config);
  if (profile.length > MAX_PROFILE_JSON) throw new RefreshError('PROFILE_TOO_LARGE','generated profile too large');
  const snapshot = JSON.stringify({updatedAt:now,profile});
  // A failed refresh must never overwrite the previous valid snapshot.
  try {
    await env.PROFILE_KV.put(SNAPSHOT_KEY,snapshot);
  } catch (error) {
    throw new RefreshError('SNAPSHOT_WRITE_FAILED','profile snapshot write failed',{cause:error});
  }
  return {updatedAt:now,selectedCount:selected.length};
}

async function readSnapshot(raw,now,pins,approvedIdentities,allowPublicClientKeys=false) {
  if (!raw || raw.length > MAX_PROFILE_JSON + 1000) return null;
  try {
    const s = JSON.parse(raw);
    if (typeof s.updatedAt !== 'number' || !Number.isFinite(s.updatedAt) ||
        s.updatedAt > now + 60000 || now - s.updatedAt > MAX_AGE_MS ||
        typeof s.profile !== 'string' || s.profile.length > MAX_PROFILE_JSON) return null;
    const cfg = JSON.parse(s.profile);
    if (cfg?.endpoints?.length !== 1 || cfg.endpoints[0].type !== 'openvpn-client' ||
        !Array.isArray(cfg.endpoints[0].servers) || cfg.endpoints[0].servers.length < 2 ||
        cfg.route?.final !== 'vpn-gate' || !cfg.endpoints[0].block_ipv6 || cfg.outbounds?.length) return null;
    if (cfg.endpoints[0].servers.some(server=>{
      const pin=pins.get(server.server);
      return !pin || pin.port!==server.server_port || pin.network!==server.network;
    })) return null;
    // Revalidate the stored snapshot against CURRENT operator-approved identity pins.
    const storedIdentity=await sharedIdentitySha256(cfg.endpoints[0]);
    if (cfg.endpoints[0].servers.some(server=>approvedIdentities.get(server.server)!==storedIdentity)) return null;
    // Never serve a profile that routes its own VPN transport back into the TUN.
    const tun = cfg.inbounds?.length === 1 ? cfg.inbounds[0] : null;
    const excluded = cfg.endpoints[0].servers.map(remote => remote.server + '/32');
    if (!tun || tun.type !== 'tun' || tun.auto_route !== true ||
        !Array.isArray(tun.route_exclude_address) ||
        tun.route_exclude_address.length !== excluded.length ||
        excluded.some((ip, i) => tun.route_exclude_address[i] !== ip) ||
        ['route_address', 'inet4_route_address', 'inet6_route_address',
         'inet4_route_exclude_address', 'inet6_route_exclude_address'].some(key => key in tun)) return null;
    const tls = cfg.endpoints[0].tls;
    if (Boolean(tls?.client_certificate?.length) !== Boolean(tls?.client_key?.length)) return null;
    if (tls?.client_key?.length && !allowPublicClientKeys) return null;
    return s;
  } catch { return null; }
}

export async function handleRequest(request, env, now=Date.now()) {
  const url = new URL(request.url);
  if (request.method !== 'GET') return response('Method Not Allowed',405,{Allow:'GET'});
  if (url.pathname !== '/profile.json' && url.pathname !== '/health') return response('Not Found',404);
  if (!env?.PROFILE_KV?.get || !validToken(env?.PROFILE_ACCESS_TOKEN)) return response('Not configured',503);
  if (!authorized(request,env.PROFILE_ACCESS_TOKEN)) return response('Unauthorized',401);
  let pins;
  try {pins=parseApprovedRemotes(env.APPROVED_REMOTES);} catch {return response('No current approved profile',503);}
  let approvedIdentities;
  try {approvedIdentities=parseIdentityApprovals(env.APPROVED_IDENTITY_SHA256,pins);}
  catch {return response('No current approved profile',503);}
  const snapshot=await readSnapshot(await env.PROFILE_KV.get(SNAPSHOT_KEY),now,pins,approvedIdentities,
    env.ALLOW_PUBLIC_CLIENT_KEYS === 'true');
  if (!snapshot) return response('No current approved profile',503);
  if (url.pathname === '/health') return response(JSON.stringify({status:'ready',ageSeconds:Math.floor((now-snapshot.updatedAt)/1000),
    servers:JSON.parse(snapshot.profile).endpoints[0].servers.length}),200,{'Content-Type':'application/json; charset=utf-8'});
  return response(snapshot.profile,200,{'Content-Type':'application/json; charset=utf-8'});
}

export default {
  async fetch(request,env) { return handleRequest(request,env); },
  async scheduled(_controller,env,ctx) {
    ctx.waitUntil(refreshProfile(env).catch(err=>{
      // Avoid logging candidate profiles, CA contents, secrets or query parameters.
      console.error('Profile refresh failed:',refreshErrorCode(err));
    }));
  }
};
