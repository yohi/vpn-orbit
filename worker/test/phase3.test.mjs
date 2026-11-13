import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {convertOvpn,parseCatalog,selectGroup,buildConfig,isPublicIPv4,parseCsvLine} from '../src/catalog.mjs';
import worker,{refreshProfile,handleRequest,parseApprovedRemotes} from '../src/index.mjs';
const fixture = (name)=>readFileSync(new URL(`./fixtures/${name}`,import.meta.url),'utf8');
const cert = fixture('a.pem');
const cert2 = fixture('b.pem');
const ipA = '8.8.8.8', ipB = '9.9.9.9', ipC = '1.1.1.1';
const accessToken='b'.repeat(64);
const req=(p,o={})=>new Request('https://example.com'+p,{...o,headers:{Authorization:'Bearer '+accessToken,...o.headers}});
function ovpn(ip,{ca=cert,script='',control='',auth=''}={}) {
  return `client\nproto udp\nremote ${ip} 1195\ncipher AES-128-CBC\nauth SHA1\nremote-cert-tls server\n${auth}\n<ca>\n${ca}</ca>\n${control}\n${script}`;
}
const encoded = text => Buffer.from(text).toString('base64');
const row = (ip,p=ovpn(ip),country='JP',ping=10)=>`test.opengw.net,${ip},100,${ping},25000000,${country},${encoded(p)}`;
const csv = (...rows)=> '*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryShort,OpenVPN_ConfigData_Base64\n'+rows.join('\n');
function env(approved='8.8.8.8,9.9.9.9') {
  const values=new Map(); const writes=[];
  return {APPROVED_REMOTES:approved.split(',').map(ip=>ip+':1195/udp').join(','),PROFILE_ACCESS_TOKEN:accessToken,MAX_SERVERS:'5',PROFILE_KV:{
    get:async key=>values.get(key)||null,
    put:async (key,value)=>{writes.push(value);values.set(key,value);}
  }, values,writes};
}
const fakeFetch=(contents,status=200)=>async (_url,options)=>new Response(contents,{status,headers:{'content-type':'text/plain'}});
const t0=1_800_000_000_000;

test('public IPv4 validation rejects private, reserved, and suspicious notation',()=>{
  for(const val of ['192.168.0.1','10.1.2.3','127.0.0.1','169.254.2.3','100.64.0.1','203.0.113.1','198.51.100.10','1.01.1.1','1.1.1.999']) assert.equal(isPublicIPv4(val),false,val);
  assert.equal(isPublicIPv4(ipA),true);
});
test('CSV quoted field parsing',()=>assert.deepEqual(parseCsvLine('"foo,bar",qux,"a""b"'),['foo,bar','qux','a"b']));
test('OpenVPN profile generates independently verified CA and no unsafe directives',()=>{
  const e=convertOvpn(ovpn(ipA),ipA);
  assert.equal(e.server,ipA);assert.equal(e.tls.remote_certificate_tls,'server');
  assert.equal(e.block_ipv6,true);
  assert.ok(e.tls.certificate[0].includes('BEGIN CERTIFICATE'));
  const cfg=buildConfig(e);
  assert.equal(cfg.route.final,'vpn-gate');
  assert.deepEqual(cfg.inbounds[0].route_exclude_address,[ipA+'/32']);
  assert.deepEqual(cfg.inbounds[0].address,['172.28.250.1/30','fd28:250::1/126']);
  assert.equal(Object.hasOwn(cfg.inbounds[0],'route_address'),false);
  assert.equal(Object.hasOwn(cfg.inbounds[0],'inet6_route_address'),false);
});
test('SoftEther inline client identity is preserved for sing-box',()=>{
  const clientCert=cert;
  const encodedKey=Buffer.concat([Buffer.from([0x30,0x1e]),Buffer.alloc(30,1)]).toString('base64');
  const clientKey='-----BEGIN RSA PRIVATE KEY-----\n'+encodedKey+'\n-----END RSA PRIVATE KEY-----';
  const profile=ovpn(ipA).replace('</ca>',`</ca>\n<cert>\n${clientCert}</cert>\n<key>\n${clientKey}\n</key>`);
  const endpoint=convertOvpn(profile,ipA);
  assert.equal(endpoint.tls.client_certificate.length,1);
  assert.equal(endpoint.tls.client_key[0],clientKey+'\n');
  assert.equal(parseCatalog(csv(row(ipA,profile)),new Set([ipA,ipB])).length,1);
});
test('client identity blocks must be paired and contain valid PEM encoding',()=>{
  const certOnly=ovpn(ipA).replace('</ca>',`</ca>\n<cert>\n${cert}</cert>`);
  const malformed=ovpn(ipA).replace('</ca>',`</ca>\n<cert>\nnot a certificate\n</cert>\n<key>\nnot a key\n</key>`);
  assert.throws(()=>convertOvpn(certOnly,ipA),/client identity/);
  assert.throws(()=>convertOvpn(malformed,ipA),/client identity/);
});
test('publication of a client private key requires an explicit Worker opt-in',async()=>{
  const encodedKey=Buffer.concat([Buffer.from([0x30,0x1e]),Buffer.alloc(30,1)]).toString('base64');
  const identity='<cert>\n'+cert+'</cert>\n<key>\n-----BEGIN RSA PRIVATE KEY-----\n'+
    encodedKey+'\n-----END RSA PRIVATE KEY-----\n</key>\n';
  const first=ovpn(ipA,{control:identity});
  const second=ovpn(ipB,{control:identity});
  const e=env();
  await assert.rejects(()=>refreshProfile(e,fakeFetch(csv(row(ipA,first),row(ipB,second))),t0),
    /explicit opt-in/);
  assert.equal(e.writes.length,0);
  e.ALLOW_PUBLIC_CLIENT_KEYS='true';
  await refreshProfile(e,fakeFetch(csv(row(ipA,first),row(ipB,second))),t0);
  const res=await handleRequest(req('/profile.json'),e,t0+1000);
  assert.equal(res.status,200);
  assert.equal((await res.json()).endpoints[0].tls.client_key.length,1);
  e.ALLOW_PUBLIC_CLIENT_KEYS='false';
  assert.equal((await handleRequest(req('/profile.json'),e,t0+1000)).status,503);
});
test('different embedded client keys are never grouped as one OpenVPN endpoint',()=>{
  const makeKey=n=>'-----BEGIN RSA PRIVATE KEY-----\n'+
    Buffer.concat([Buffer.from([0x30,0x1e]),Buffer.alloc(30,n)]).toString('base64')+
    '\n-----END RSA PRIVATE KEY-----\n';
  const wrap=k=>'<cert>\n'+cert+'</cert>\n<key>\n'+k+'</key>\n';
  const candidates=parseCatalog(csv(
    row(ipA,ovpn(ipA,{control:wrap(makeKey(1))})),
    row(ipB,ovpn(ipB,{control:wrap(makeKey(2))}))
  ),new Set([ipA,ipB]));
  assert.equal(candidates.length,2);
  assert.throws(()=>selectGroup(candidates),/fewer than two/);
});
test('remote-cert-eku is rejected as an unsupported directive',()=>{
  assert.throws(()=>convertOvpn(ovpn(ipA,{script:'remote-cert-eku \\ TLS Web Server Authentication'}),ipA),/unsupported directive: remote-cert-eku/);
});
test('PEM bodies reject overlong base64 lines and malformed boundary lines',()=>{
  const longLine='A'.repeat(65);
  const badLineBreaks=cert.replace('-----BEGIN CERTIFICATE-----','-----BEGIN CERTIFICATE----- extra');
  const payload=cert.split('\n').slice(1,-2).join('');
  const overlongLines=`-----BEGIN CERTIFICATE-----\n${payload.match(/.{1,65}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  for(const ca of [cert.replace(/\n[^\n]+\n/,`\n${longLine}\n`),overlongLines,badLineBreaks]) {
    assert.throws(()=>convertOvpn(ovpn(ipA,{ca}),ipA));
  }
});
test('static keys reject invalid line structure and excessive line lengths',()=>{
  const keyBody='a'.repeat(512);
  const validKey=`-----BEGIN OpenVPN Static key V1-----\n${keyBody.match(/.{1,64}/g).join('\n')}\n-----END OpenVPN Static key V1-----`;
  const invalidKey=`-----BEGIN OpenVPN Static key V1-----\n${keyBody}\n-----END OpenVPN Static key V1-----`;
  for(const control of [validKey,invalidKey]) {
    const profile=ovpn(ipA,{control:`<tls-crypt>\n${control}\n</tls-crypt>`});
    if(control===validKey) assert.doesNotThrow(()=>convertOvpn(profile,ipA));
    else assert.throws(()=>convertOvpn(profile,ipA));
  }
});
test('client private keys reject base64 lines longer than 64 characters',()=>{
  const payload=Buffer.concat([Buffer.from([0x30]),Buffer.alloc(99,1)]).toString('base64');
  const key=`-----BEGIN RSA PRIVATE KEY-----\n${payload.match(/.{1,65}/g).join('\n')}\n-----END RSA PRIVATE KEY-----`;
  const profile=ovpn(ipA).replace('</ca>',`</ca>\n<cert>\n${cert}</cert>\n<key>\n${key}\n</key>`);
  assert.throws(()=>convertOvpn(profile,ipA),/client identity/);
});
test('incompatible/tricky OpenVPN profiles fail closed',()=>{
  const bad=[
    ovpn(ipA,{script:'up /tmp/evil.sh'}),
    ovpn(ipA,{script:'script-security 3'}),
    ovpn(ipA,{script:'<script>\nevil\n</script>'}),
    ovpn(ipA,{auth:'auth-user-pass /tmp/password'}),
    ovpn(ipA).replace('remote-cert-tls server','remote-cert-tls none'),
    ovpn(ipA).replace('remote 8.8.8.8','remote 1.1.1.1'),
    ovpn(ipA).replace(/<ca>[\s\S]*?<\/ca>/,'<ca>\nnot a cert\n</ca>'),
    ovpn(ipA,{script:'remote 8.8.8.8 9999'}),
    ovpn(ipA,{script:'key-direction 1'}),
  ];
  bad.forEach((value,i)=>assert.throws(()=>convertOvpn(value,ipA),`bad profile ${i}`));
});
test('client credentials are fixed to public VPN Gate defaults; no external filename',()=>{
  const e=convertOvpn(ovpn(ipA,{auth:'auth-user-pass'}),ipA);
  assert.equal(e.username,'vpn');assert.equal(e.password,'vpn');
});
test('approved JP-only candidates are selected by ping then only exact TLS groups',()=>{
  const data=csv(row(ipA,ovpn(ipA), 'JP',8),row(ipB,ovpn(ipB),'JP',9),row(ipC,ovpn(ipC),'JP',2));
  const opts=parseCatalog(data,new Set([ipA,ipB]));
  assert.deepEqual(opts.map(c=>c.ip),[ipA,ipB]);
  const {endpoint,selected}=selectGroup(opts);
  assert.deepEqual(selected,[ipA,ipB]);assert.deepEqual(endpoint.servers.map(x=>x.server),[ipA,ipB]);
  assert.equal(endpoint.server,undefined);assert.equal(endpoint.block_ipv6,true);
});
test('different CA certificates are never unioned',()=>{
  const candidates=parseCatalog(csv(row(ipA),row(ipB,ovpn(ipB,{ca:cert2}))),new Set([ipA,ipB]));
  assert.equal(candidates.length,2);
  assert.throws(()=>selectGroup(candidates),/fewer than two/);
});
test('invalid country/mismatched IP/unsafe script omitted',()=>{
  const opts=parseCatalog(csv(row(ipA),row(ipB,ovpn(ipA)),row(ipC,ovpn(ipC),'KR')),
    new Set([ipA,ipB,ipC]));
  assert.deepEqual(opts.map(x=>x.ip),[ipA]);
});
test('cron refresh publishes fresh validated config without leaking candidates in health',async()=>{
  const e=env();
  const result=await refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0);
  assert.equal(result.selectedCount,2);
  assert.equal(e.writes.length,1);
  const res=await handleRequest(req('/profile.json'),e,t0+1000);
  assert.equal(res.status,200);
  assert.equal(res.headers.get('cache-control'),'no-store');
  const profile=await res.json();
  assert.deepEqual(profile.endpoints[0].servers.map(x=>x.server),[ipA,ipB]);
  assert.deepEqual(profile.inbounds[0].route_exclude_address,[ipA+'/32',ipB+'/32']);
  assert.equal(Object.hasOwn(profile.inbounds[0],'route_address'),false);
  const health=await handleRequest(req('/health'),e,t0+1000);
  assert.equal(health.status,200);
  assert.deepEqual(await health.json(),{status:'ready',ageSeconds:1,servers:2});
});
test('builder rejects invalid or duplicate transport addresses',()=>{
  const e=convertOvpn(ovpn(ipA),ipA);
  assert.throws(()=>buildConfig({...e,server:'192.168.1.1'}),/invalid OpenVPN remote/);
  assert.throws(()=>buildConfig({...e,servers:[{server:ipA}]}),/exactly one OpenVPN remote/);
  const multi={...e};delete multi.server;delete multi.server_port;delete multi.network;
  multi.servers=[{server:ipA},{server:ipA}];
  assert.throws(()=>buildConfig(multi),/duplicate OpenVPN server/);
});
test('stale or tampered route exclusions fail closed on public profile read',async()=>{
  const e=env();
  await refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0);
  const original=e.values.get('profile-v1');
  for (const mutation of [
    cfg=>{cfg.inbounds[0].route_exclude_address.pop();},
    cfg=>{cfg.inbounds[0].route_address=['0.0.0.0/1','128.0.0.0/1'];}
  ]) {
    const snapshot=JSON.parse(original), cfg=JSON.parse(snapshot.profile);
    mutation(cfg);
    snapshot.profile=JSON.stringify(cfg);
    e.values.set('profile-v1',JSON.stringify(snapshot));
    assert.equal((await handleRequest(req('/profile.json'),e,t0+1000)).status,503);
  }
  e.values.set('profile-v1',original);
  assert.equal((await handleRequest(req('/profile.json'),e,t0+1000)).status,200);
});
test('unapproved or single approved IP cannot trigger publication',async()=>{
  const e=env(ipA);
  await assert.rejects(()=>refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0),
    error=>error.code==='APPROVED_REMOTES_INVALID');
  assert.equal(e.writes.length,0);
});
test('scheduled refresh logs fixed failure codes without exception details',async()=>{
  const originalError=console.error;
  const logged=[];
  console.error=(...args)=>logged.push(args);
  try {
    const promises=[];
    await worker.scheduled({},env(ipA),{waitUntil:promise=>promises.push(promise)});
    await Promise.all(promises);
  } finally {
    console.error=originalError;
  }
  assert.deepEqual(logged,[['Profile refresh failed:','APPROVED_REMOTES_INVALID']]);
});
test('scheduled refresh identifies insufficient compatible servers without profile details',async()=>{
  const originalError=console.error;
  const originalFetch=globalThis.fetch;
  const logged=[];
  console.error=(...args)=>logged.push(args);
  globalThis.fetch=fakeFetch(csv(row(ipA)));
  try {
    const promises=[];
    await worker.scheduled({},env(),{waitUntil:promise=>promises.push(promise)});
    await Promise.all(promises);
  } finally {
    console.error=originalError;
    globalThis.fetch=originalFetch;
  }
  assert.deepEqual(logged,[['Profile refresh failed:','INSUFFICIENT_COMPATIBLE_SERVERS']]);
});
test('scheduled refresh maps transport errors to a fixed code',async()=>{
  const originalError=console.error;
  const originalFetch=globalThis.fetch;
  const logged=[];
  console.error=(...args)=>logged.push(args);
  globalThis.fetch=async()=>{throw new Error('sensitive transport detail');};
  try {
    const promises=[];
    await worker.scheduled({},env(),{waitUntil:promise=>promises.push(promise)});
    await Promise.all(promises);
  } finally {
    console.error=originalError;
    globalThis.fetch=originalFetch;
  }
  assert.deepEqual(logged,[['Profile refresh failed:','API_FETCH_FAILED']]);
});
test('API outage does not erase last valid record, but stale record is not served',async()=>{
  const e=env();
  await refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0);
  await assert.rejects(()=>refreshProfile(e,fakeFetch('unavailable',502),t0+60000));
  assert.equal(e.writes.length,1);
  assert.equal((await handleRequest(req('/profile.json'),e,t0+120000)).status,200);
  assert.equal((await handleRequest(req('/profile.json'),e,t0+7200001)).status,503);
});
test('no KV snapshot = fail-closed (503); no direct fallback; only GET',async()=>{
  const e=env();
  assert.equal((await handleRequest(req('/profile.json'),e,t0)).status,503);
  assert.equal((await handleRequest(req('/profile.json',{method:'POST'}),e,t0)).status,405);
  assert.equal((await handleRequest(req('/admin'),e,t0)).status,404);
});
test('malformed KV snapshot never served',async()=>{
  const e=env();e.values.set('profile-v1','{"bad":true}');
  assert.equal((await handleRequest(req('/profile.json'),e,t0)).status,503);
});
test('snapshot containing an IP removed from current approvals is not served',async()=>{
  const e=env();
  await refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0);
  e.APPROVED_REMOTES=ipA+':1195/udp';

  assert.equal((await handleRequest(req('/profile.json'),e,t0+1000)).status,503);
  assert.equal((await handleRequest(req('/health'),e,t0+1000)).status,503);
});
test('snapshot is served when every remote remains currently approved',async()=>{
  const e=env();
  await refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0);
  e.APPROVED_REMOTES=`${ipA}:1195/udp,${ipB}:1195/udp,${ipC}:1195/udp`;

  assert.equal((await handleRequest(req('/profile.json'),e,t0+1000)).status,200);
});
test('less than two compatible approved remotes never replaced last good snapshot',async()=>{
  const e=env();
  await refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0);
  await assert.rejects(()=>refreshProfile(e,fakeFetch(csv(row(ipA))),t0+30000),/fewer than two/);
  assert.equal(e.writes.length,1);
});
test('API redirect to untrusted origin rejected before any KV write',async()=>{
  const e=env();
  const evil = async () => ({ok:true,url:'https://evil.example/poison.csv',headers:new Headers(),arrayBuffer:async()=>new TextEncoder().encode(csv(row(ipA),row(ipB))).buffer});
  await assert.rejects(()=>refreshProfile(e,evil,t0),/unexpected API response/);
  assert.equal(e.writes.length,0);
});
test('catalog stream exceeding the byte limit is cancelled before publication',async()=>{
  const e=env();
  let chunks=0;
  const oversized = new ReadableStream({
    pull(controller) {
      if (chunks++ === 0) controller.enqueue(new Uint8Array(16 * 1024 * 1024));
      else if (chunks === 2) controller.enqueue(new Uint8Array([1]));
      else controller.close();
    },
  },{highWaterMark:0});
  const fetchOversized = async () => new Response(oversized,{status:200});

  await assert.rejects(()=>refreshProfile(e,fetchOversized,t0),/catalog too large/);
  assert.equal(chunks,2);
  assert.equal(e.writes.length,0);
});

test('pin parser rejects invalid, duplicate or private entries',()=>{
  assert.equal(parseApprovedRemotes(ipA+':1195/udp,'+ipB+':1195/udp').size,2);
  for(const pins of [ipA+':1195/udp',ipA+':1195/udp,'+ipA+':1195/udp',
     ipA+':0/udp,'+ipB+':1195/udp',ipA+':65536/udp,'+ipB+':1195/udp',
     '192.168.1.1:1195/udp,'+ipB+':1195/udp',ipA+':1195/other,'+ipB+':1195/udp'])
     assert.throws(()=>parseApprovedRemotes(pins));
});
test('changed transport and port fail closed both on refresh and read',async()=>{
  const e=env();
  e.APPROVED_REMOTES=ipA+':1195/udp,'+ipB+':443/tcp';
  await assert.rejects(()=>refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0),/fewer than two/);
  assert.equal(e.writes.length,0);
  e.APPROVED_REMOTES=ipA+':1195/udp,'+ipB+':1195/udp';
  await refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0);
  e.APPROVED_REMOTES=ipA+':443/tcp,'+ipB+':1195/udp';
  assert.equal((await handleRequest(req('/profile.json'),e,t0+1000)).status,503);
});
test('private access token is required on both endpoints',async()=>{
  const e=env();
  await refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0);
  assert.equal((await handleRequest(new Request('https://example.com/profile.json'),e,t0+1000)).status,401);
  assert.equal((await handleRequest(new Request('https://example.com/health'),e,t0+1000)).status,401);
  assert.equal((await handleRequest(new Request('https://example.com/profile.json?token='+accessToken),e,t0+1000)).status,200);
  assert.equal((await handleRequest(new Request('https://example.com/profile.json?token=wrong'),e,t0+1000)).status,401);
  delete e.PROFILE_ACCESS_TOKEN;
  assert.equal((await handleRequest(req('/profile.json'),e,t0+1000)).status,503);
  await assert.rejects(()=>refreshProfile(e,fakeFetch(csv(row(ipA),row(ipB))),t0+2000),/profile token required/);
});
