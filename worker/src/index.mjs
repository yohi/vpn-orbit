import {API_URL,MAX_CATALOG_BYTES,isPublicIPv4,parseCatalog,selectGroup,buildConfig} from './catalog.mjs';

const SNAPSHOT_KEY = 'profile-v1';
const MAX_AGE_MS = 2 * 60 * 60 * 1000; // Serve nothing if last refresh is older than 2h.
const MAX_PROFILE_JSON = 512 * 1024;
const PROBE_TIMEOUT_MS = 14000;
const REFRESH_ERROR_CODES = new Set([
  'PROFILE_KV_MISSING','APPROVED_IPS_INVALID','MAX_SERVERS_INVALID',
  'API_FETCH_FAILED','API_RESPONSE_INVALID','CATALOG_TOO_LARGE',
  'CATALOG_BODY_MISSING','CATALOG_ENCODING_INVALID','CATALOG_INVALID',
  'INSUFFICIENT_COMPATIBLE_SERVERS','GROUP_SELECTION_FAILED',
  'PROFILE_BUILD_FAILED','PROFILE_TOO_LARGE','SNAPSHOT_WRITE_FAILED',
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
  return new Response(message,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers}});
}

export async function refreshProfile(env, fetchFn=fetch, now=Date.now()) {
  if (!env?.PROFILE_KV?.put) throw new RefreshError('PROFILE_KV_MISSING','PROFILE_KV is required');
  const approved = new Set((env.APPROVED_IPS || '').split(/[\s,]+/).filter(Boolean));
  if (approved.size < 2 || [...approved].some(ip=>!isPublicIPv4(ip))) throw new RefreshError('APPROVED_IPS_INVALID','APPROVED_IPS requires at least 2 valid public IPv4 addresses');
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
    candidates = parseCatalog(csv,approved);
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

function readSnapshot(raw,now) {
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
    return s;
  } catch { return null; }
}

export async function handleRequest(request, env, now=Date.now()) {
  const url = new URL(request.url);
  if (request.method !== 'GET') return response('Method Not Allowed',405,{Allow:'GET'});
  if (url.pathname !== '/profile.json' && url.pathname !== '/health') return response('Not Found',404);
  if (!env?.PROFILE_KV?.get) return response('Not configured',503);
  const snapshot = readSnapshot(await env.PROFILE_KV.get(SNAPSHOT_KEY),now);
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
