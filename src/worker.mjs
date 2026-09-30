const ASSETS = null; // ASSET_INJECTION
const MAX_BODY = 3_000_000;
const MAX_SUBDOMAINS = 300;
const MAX_DEEP_SUBDOMAINS = 1000;
const MAX_SCANNER_DNS = 32;
const MAX_MAPPED_IPS = 8;
const MAX_REVERSE_IPS = 4;
const visits = new Map();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }
  });
}

function parseIp(value) {
  if (!value || value.length > 45) return null;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
    const p = value.split('.');
    if (p.some(x => x.length > 1 && x[0] === '0' || Number(x) > 255)) return null;
    return { value, version: 4, octets: p.map(Number) };
  }
  if (/^[a-f0-9:.]+$/i.test(value) && value.includes(':')) {
    try {
      const host = new URL(`http://[${value}]/`).hostname;
      if (host.startsWith('[')) return { value: host.slice(1, -1), version: 6 };
    } catch { /* invalid IPv6 */ }
  }
  return null;
}

function isPublicIp(ip) {
  if (ip.version === 6) {
    const s = ip.value.toLowerCase();
    return /^[23]/.test(s) && !s.startsWith('2001:db8:');
  }
  const [a, b, c] = ip.octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2) || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113) return false;
  return true;
}

function parseDomain(value) {
  if (!value || value.length > 350) return null;
  let host;
  try { host = new URL(value.includes('://') ? value : `https://${value}`).hostname.toLowerCase().replace(/\.$/, ''); }
  catch { return null; }
  if (host.length > 253 || !host.includes('.') || parseIp(host)) return null;
  const labels = host.split('.');
  if (labels.some(x => !x || x.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x))) return null;
  if (/^\d+$/.test(labels.at(-1))) return null;
  return host;
}

async function readLimited(response, limit = MAX_BODY) {
  const reader = response.body?.getReader();
  if (!reader) {
    const value = await response.text();
    if (value.length > limit) throw new Error('Response exceeded size limit');
    return value;
  }
  let size = 0;
  const chunks = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) { await reader.cancel(); throw new Error('Response exceeded size limit'); }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(out);
}

async function sourceRequest(name, url, evidence, { text = false, headers = {}, timeoutMs = 8500, limit = MAX_BODY } = {}) {
  const checkedAt = new Date().toISOString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { headers: { accept: text ? 'text/plain' : 'application/json', ...headers }, signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await readLimited(response, limit);
    const data = text ? body : JSON.parse(body);
    evidence.push({ name, url, checkedAt, status: 'ok' });
    return data;
  } catch (error) {
    evidence.push({ name, url, checkedAt, status: 'unavailable', detail: error.name === 'AbortError' ? 'Timed out' : String(error.message).slice(0, 100) });
    return null;
  } finally { clearTimeout(timeout); }
}

async function dnsRecords(domain, evidence) {
  const queries = [
    ...['A', 'AAAA'].map(type => ({ name: `Google DNS ${type}`, type, url: `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}` })),
    ...['A', 'AAAA'].map(type => ({ name: `Cloudflare DNS ${type}`, type, url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}` }))
  ];
  const results = await Promise.all(queries.map(query => sourceRequest(query.name, query.url, evidence, { headers: query.name.startsWith('Cloudflare') ? { accept: 'application/dns-json' } : {} })));
  const addresses = new Set();
  results.forEach((r, i) => {
    const expected = queries[i].type === 'A' ? 1 : 28;
    for (const answer of r?.Answer || []) if (answer.type === expected && parseIp(answer.data)) addresses.add(answer.data);
  });
  return [...addresses];
}

function normalizeGeo(name, data, url, checkedAt) {
  if (!data || data.error || data.success === false) return null;
  let latitude, longitude, city, region, country, org, asn;
  if (name === 'IPWhois') {
    ({ latitude, longitude, city, region, country } = data);
    org = data.connection?.org || data.connection?.isp;
    asn = data.connection?.asn;
  } else if (name === 'ipapi.co') {
    ({ latitude, longitude, city, region } = data);
    country = data.country_name;
    org = data.org;
    asn = data.asn;
  } else if (name === 'ipapi.is') {
    latitude = data.lat; longitude = data.lon;
    ({ city, region, country } = data);
    org = data.company; asn = data.asn;
  } else if (name === 'GeoJS') {
    ({ latitude, longitude, city, region, country, asn } = data);
    org = data.organization_name;
  } else if (name === 'FreeIPAPI') {
    ({ latitude, longitude, asn } = data);
    city = data.cityName; region = data.regionName; country = data.countryName;
    org = data.asnOrganization;
  } else {
    if (typeof data.loc !== 'string' || !data.loc.includes(',')) return null;
    const loc = data.loc.split(',');
    latitude = Number(loc[0]); longitude = Number(loc[1]);
    ({ city, region, country, org } = data);
  }
  if (latitude == null || longitude == null || latitude === '' || longitude === '') return null;
  latitude = Number(latitude); longitude = Number(longitude);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude) || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) return null;
  const reportedAccuracyKm = name === 'GeoJS' && Number.isFinite(Number(data.accuracy)) && Number(data.accuracy) > 0 ? Number(data.accuracy) : null;
  return { name, latitude, longitude, city: city || null, region: region || null, country: country || null, org: org || null, asn: asn || null, reportedAccuracyKm, sourceUrl: url, checkedAt };
}

function haversine(a, b) {
  const rad = Math.PI / 180;
  const dLat = (b.latitude - a.latitude) * rad;
  const dLon = (b.longitude - a.longitude) * rad;
  const c = 2 * Math.asin(Math.min(1, Math.sqrt(Math.sin(dLat / 2) ** 2 + Math.cos(a.latitude * rad) * Math.cos(b.latitude * rad) * Math.sin(dLon / 2) ** 2)));
  return 6371.0088 * c;
}

function buildLocation(providers) {
  if (!providers.length) return { providers: [], center: null, radiusKm: null, radiusKind: 'unavailable' };
  const center = providers.reduce((best, point) => {
    const distance = providers.reduce((sum, other) => sum + haversine(point, other), 0);
    return !best || distance < best.distance ? { point, distance } : best;
  }, null).point;
  const spreadKm = providers.length > 1 ? Math.max(...providers.map(p => haversine(center, p))) : null;
  const nearbyCount = providers.filter(p => haversine(center, p) <= 50).length;
  const agreement = providers.length < 2 ? 'single source' : nearbyCount === providers.length ? 'close agreement' : nearbyCount >= 2 && nearbyCount > providers.length / 2 ? 'mixed agreement' : 'low agreement';
  return {
    providers,
    center: { latitude: center.latitude, longitude: center.longitude, city: center.city, region: center.region, country: center.country },
    radiusKm: spreadKm == null ? null : Math.max(1, Math.ceil(spreadKm)),
    measuredSpreadKm: spreadKm == null ? null : Number(spreadKm.toFixed(1)),
    nearestConsensusSource: agreement === 'low agreement' ? null : center.name,
    agreement,
    nearbyCount,
    radiusKind: spreadKm == null ? 'unavailable' : 'provider-spread',
    explanation: spreadKm == null ? 'One source reported coordinates; no multi-source radius can be calculated.' : 'The circle contains the reported centers of available providers. It is not a statistical accuracy or device-location radius.'
  };
}

async function geolocate(ip, evidence) {
  const endpoints = [
    ['IPWhois', `https://ipwho.is/${encodeURIComponent(ip)}`],
    ['GeoJS', `https://get.geojs.io/v1/ip/geo/${encodeURIComponent(ip)}.json`],
    ['ipapi.is', `https://api.ipapi.is/?q=${encodeURIComponent(ip)}`],
    ['FreeIPAPI', `https://free.freeipapi.com/api/v1/json/${encodeURIComponent(ip)}`]
  ];
  const replies = await Promise.all(endpoints.map(([name, url]) => sourceRequest(`${name} (${ip})`, url, evidence)));
  const providers = endpoints.map(([name, url], i) => normalizeGeo(name, replies[i], url, evidence.findLast(x => x.name === `${name} (${ip})`)?.checkedAt)).filter(Boolean);
  return buildLocation(providers);
}

async function networkInfo(ip, evidence) {
  const rdapUrl = `https://rdap.arin.net/registry/ip/${encodeURIComponent(ip)}`;
  const ripeUrl = `https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(ip)}`;
  const [rdap, ripe] = await Promise.all([sourceRequest('RDAP', rdapUrl, evidence), sourceRequest('RIPEstat', ripeUrl, evidence)]);
  let registration = rdap?.objectClassName === 'ip network' ? { handle: rdap.handle || null, name: rdap.name || null, country: rdap.country || null, startAddress: rdap.startAddress || null, endAddress: rdap.endAddress || null, sourceUrl: rdapUrl, sourceName: 'RDAP' } : null;
  if (!registration) {
    const whoisUrl = `https://stat.ripe.net/data/whois/data.json?resource=${encodeURIComponent(ip)}`;
    const whois = await sourceRequest('RIPEstat WHOIS', whoisUrl, evidence);
    const fields = new Map((whois?.data?.records || []).flat().filter(x => x?.key).map(x => [x.key.toLowerCase(), x.value]));
    const range = fields.get('netrange') || fields.get('inetnum') || fields.get('inet6num') || '';
    const [startAddress, endAddress] = range.split(/\s+-\s+/);
    if (fields.size) registration = { handle: fields.get('nethandle') || null, name: fields.get('netname') || fields.get('descr') || null, country: fields.get('country') || null, startAddress: startAddress || null, endAddress: endAddress || null, sourceUrl: whoisUrl, sourceName: 'RIPEstat WHOIS' };
  }
  return {
    rdap: registration,
    routing: ripe?.data ? { prefix: ripe.data.prefix || null, asns: ripe.data.asns || [], sourceUrl: ripeUrl } : null
  };
}

function addSubdomain(map, raw, domain, source) {
  const name = String(raw || '').trim().toLowerCase().replace(/\.$/, '');
  if (name.startsWith('*.') || name === domain || !name.endsWith(`.${domain}`) || !parseDomain(name)) return;
  const found = map.get(name) || { name, sources: [], observedIps: [] };
  if (!found.sources.includes(source)) found.sources.push(source);
  map.set(name, found);
}

async function discoverSubdomains(domain, evidence, deep = false) {
  const crtUrl = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
  const certUrl = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`;
  const hostUrl = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
  const base = [
    sourceRequest('crt.sh CT', crtUrl, evidence, { limit: 4_000_000, timeoutMs: 11000 }),
    sourceRequest('Cert Spotter CT', certUrl, evidence, { limit: 2_000_000 }),
    sourceRequest('HackerTarget host search', hostUrl, evidence, { text: true, limit: 1_000_000 })
  ];
  const extra = deep ? [
    sourceRequest('AlienVault OTX passive DNS', `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`, evidence, { limit: 2_000_000 }),
    sourceRequest('urlscan.io public scans', `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`domain:${domain}`)}&size=100`, evidence, { limit: 2_000_000 })
  ] : [];
  const [crt, cert, host, otx, urlscan] = await Promise.all([...base, ...extra]);
  const map = new Map();
  if (Array.isArray(crt)) for (const row of crt) for (const name of String(row.name_value || '').split('\n')) addSubdomain(map, name, domain, 'crt.sh CT');
  if (Array.isArray(cert)) for (const row of cert) for (const name of row.dns_names || []) addSubdomain(map, name, domain, 'Cert Spotter CT');
  if (typeof host === 'string' && !host.startsWith('error')) for (const row of host.split('\n')) {
    const [name, address] = row.split(',');
    addSubdomain(map, name, domain, 'HackerTarget host search');
    const found = map.get(String(name || '').trim().toLowerCase());
    if (found && parseIp(String(address || '').trim()) && !found.observedIps.includes(address.trim())) found.observedIps.push(address.trim());
  }
  if (deep && Array.isArray(otx?.passive_dns)) for (const record of otx.passive_dns) {
    addSubdomain(map, record.hostname, domain, 'AlienVault OTX passive DNS');
    const name = String(record.hostname || '').trim().toLowerCase().replace(/\.$/, '');
    const found = map.get(name), address = String(record.address || '').trim();
    const parsed = parseIp(address);
    if (found && parsed && isPublicIp(parsed) && !found.observedIps.includes(address)) found.observedIps.push(address);
  }
  if (deep && Array.isArray(urlscan?.results)) for (const record of urlscan.results) {
    for (const raw of [record.page?.domain, record.task?.domain]) addSubdomain(map, raw, domain, 'urlscan.io public scans');
  }
  const all = [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
  const limit = deep ? MAX_DEEP_SUBDOMAINS : MAX_SUBDOMAINS;
  return { items: all.slice(0, limit), observedCount: all.length, truncated: all.length > limit, note: 'Passive sources can miss private or recent names. Certificate, passive DNS, and public scan records may be historical and do not prove a host is currently online.' };
}

async function discoverIpHosts(ip, evidence) {
  const url = `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`;
  const body = await sourceRequest(`HackerTarget reverse IP (${ip})`, url, evidence, { text: true, limit: 1_000_000 });
  const names = typeof body === 'string' && !body.toLowerCase().startsWith('error') ? [...new Set(body.split('\n').map(x => x.trim().toLowerCase()).filter(x => parseDomain(x)))] : [];
  const items = names.slice(0, MAX_SUBDOMAINS).map(name => ({ name, sources: ['HackerTarget reverse IP'], observedIps: [ip] }));
  return { items, observedCount: names.length, truncated: names.length > MAX_SUBDOMAINS, kind: 'reverse-ip-hosts', note: 'These hostnames were observed on the same public IP. Shared hosting and CDNs can mix unrelated organizations; this is not a list of subdomains for one website.' };
}

async function discoverRelatedHosts(ips, evidence) {
  const checkedIps = ips.slice(0, MAX_REVERSE_IPS);
  const results = await Promise.all(checkedIps.map(ip => discoverIpHosts(ip, evidence)));
  const map = new Map();
  for (const result of results) for (const item of result.items) {
    const found = map.get(item.name) || { name: item.name, observedIps: [], sources: [] };
    for (const ip of item.observedIps) if (!found.observedIps.includes(ip)) found.observedIps.push(ip);
    for (const source of item.sources) if (!found.sources.includes(source)) found.sources.push(source);
    map.set(item.name, found);
  }
  const all = [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
  return { items: all.slice(0, MAX_SUBDOMAINS), observedCount: all.length, truncated: all.length > MAX_SUBDOMAINS, checkedIps, note: 'Reverse-IP observations can include unrelated organizations on shared hosting or CDN infrastructure. This is not an ownership claim or complete domain inventory.' };
}

function publicAnswers(reply) {
  return [...new Set((reply?.Answer || []).filter(item => item.type === 1 || item.type === 28).map(item => String(item.data || '')).filter(value => {
    const parsed = parseIp(value); return parsed && isPublicIp(parsed);
  }))];
}

async function scanSubdomains(request) {
  if (!rateAllowed(request)) return json({ error: 'Please wait before making more lookups.' }, 429);
  const domain = parseDomain(new URL(request.url).searchParams.get('domain')?.trim() || '');
  if (!domain) return json({ error: 'Enter a valid domain for subdomain discovery.' }, 400);
  const evidence = [];
  const subdomains = await discoverSubdomains(domain, evidence, true);
  const check = [...subdomains.items].sort((a, b) => b.sources.length - a.sources.length || a.name.localeCompare(b.name)).slice(0, MAX_SCANNER_DNS);
  const wildcardName = `ipinsight-${crypto.randomUUID().slice(0, 12)}.${domain}`;
  const queryA = name => sourceRequest(`DNS A (${name})`, `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=A`, evidence, { timeoutMs: 6500, limit: 250_000 });
  const wildcard = await queryA(wildcardName);
  const replies = new Array(check.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(5, check.length) }, async () => {
    while (next < check.length) {
      const index = next++;
      replies[index] = await queryA(check[index].name);
    }
  }));
  const wildcardIps = publicAnswers(wildcard);
  const checked = new Map(check.map((item, index) => {
    const reply = replies[index], currentIps = publicAnswers(reply);
    const aliases = (reply?.Answer || []).filter(answer => answer.type === 5).map(answer => String(answer.data || '').replace(/\.$/, '')).filter(parseDomain).slice(0, 5);
    return [item.name, { status: !reply ? 'unavailable' : currentIps.length ? 'resolves-a' : 'no-public-a', currentIps, aliases, wildcardMatch: wildcardIps.length > 0 && currentIps.length > 0 && currentIps.length === wildcardIps.length && currentIps.every(ip => wildcardIps.includes(ip)) }];
  }));
  subdomains.items = subdomains.items.map(item => ({ ...item, dnsCheck: checked.get(item.name) || { status: 'not-checked', currentIps: [], aliases: [], wildcardMatch: false } }));
  return json({ domain, scannedAt: new Date().toISOString(), subdomains, checkedCount: check.length, wildcardIps, evidence });
}

function normalizeExposure(ip, data) {
  if (!data || !Array.isArray(data.ports)) return { status: 'no-record', ip, sourceUrl: `https://internetdb.shodan.io/${encodeURIComponent(ip)}` };
  const strings = (list, check, limit) => Array.isArray(list) ? [...new Set(list.filter(value => typeof value === 'string' && check(value)).map(value => value.slice(0, 180)))].slice(0, limit) : [];
  return {
    status: 'ok', ip,
    ports: [...new Set(data.ports.filter(port => Number.isInteger(port) && port >= 1 && port <= 65535))].slice(0, 100),
    cpes: strings(data.cpes, value => value.length < 180, 60),
    hostnames: strings(data.hostnames, value => !!parseDomain(value), 60),
    tags: strings(data.tags, value => value.length < 80, 30),
    vulns: strings(data.vulns, value => /^CVE-\d{4}-\d{4,}$/i.test(value), 60),
    sourceUrl: `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
    note: 'Shodan InternetDB is a passive snapshot. Ports and CVE associations are leads to verify, not a live scan or a confirmed vulnerability.'
  };
}

async function ipExposure(ip, evidence) {
  const url = `https://internetdb.shodan.io/${encodeURIComponent(ip)}`;
  const data = await sourceRequest(`Shodan InternetDB (${ip})`, url, evidence, { timeoutMs: 6500, limit: 400_000 });
  if (!data) return { status: evidence.at(-1)?.detail === 'HTTP 404' ? 'no-record' : 'unavailable', ip, sourceUrl: url };
  return normalizeExposure(ip, data);
}

async function exposureRoute(request) {
  if (!rateAllowed(request)) return json({ error: 'Please wait before making more lookups.' }, 429);
  const ip = parseIp(new URL(request.url).searchParams.get('ip') || '');
  if (!ip || !isPublicIp(ip)) return json({ error: 'Enter a valid public IP address.' }, 400);
  const evidence = [];
  const exposure = await ipExposure(ip.value, evidence);
  return json({ exposure, evidence });
}

async function dnsPosture(domain, evidence) {
  const requests = [
    ...['NS', 'MX', 'TXT', 'CAA'].map(type => ({ type, name: domain })),
    { type: 'TXT', name: `_dmarc.${domain}`, label: 'DMARC' }
  ];
  const replies = await Promise.all(requests.map(query => sourceRequest(`DNS ${query.label || query.type} (${domain})`, `https://dns.google/resolve?name=${encodeURIComponent(query.name)}&type=${query.type}`, evidence, { limit: 250_000 })));
  const typeNumber = { NS: 2, MX: 15, TXT: 16, CAA: 257 };
  const values = (reply, type) => (reply?.Answer || []).filter(answer => answer.type === typeNumber[type]).map(answer => String(answer.data || '').slice(0, 600)).slice(0, 30);
  const [ns, mx, txt, caa, dmarcTxt] = replies.map((reply, index) => values(reply, requests[index].type));
  return { ns, mx, spf: txt.filter(value => /v=spf1\b/i.test(value)).slice(0, 3), dmarc: dmarcTxt.filter(value => /v=DMARC1\b/i.test(value)).slice(0, 3), caa, available: { ns: !!replies[0], mx: !!replies[1], spf: !!replies[2], caa: !!replies[3], dmarc: !!replies[4] }, checkedAt: new Date().toISOString(), note: 'DNS records are current resolver observations. Missing SPF, DMARC, or CAA records are review leads, not proof of a vulnerability.' };
}

async function dnsPostureRoute(request) {
  if (!rateAllowed(request)) return json({ error: 'Please wait before making more lookups.' }, 429);
  const domain = parseDomain(new URL(request.url).searchParams.get('domain')?.trim() || '');
  if (!domain) return json({ error: 'Enter a valid domain.' }, 400);
  const evidence = [];
  return json({ domain, posture: await dnsPosture(domain, evidence), evidence });
}

async function threatContext(ip, env, evidence) {
  if (!env?.ABUSEIPDB_API_KEY) return { status: 'not-configured', provider: 'AbuseIPDB', note: 'Import a STIX bundle for local matching. Live AbuseIPDB enrichment needs a server-side API key.' };
  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
  const response = await sourceRequest('AbuseIPDB', url, evidence, { headers: { Key: env.ABUSEIPDB_API_KEY, Accept: 'application/json' } });
  const data = response?.data;
  return data ? { status: 'ok', provider: 'AbuseIPDB', score: data.abuseConfidenceScore ?? null, reports: data.totalReports ?? null, lastReportedAt: data.lastReportedAt || null, sourceUrl: 'https://www.abuseipdb.com/' } : { status: 'unavailable', provider: 'AbuseIPDB' };
}

function rateAllowed(request) {
  const key = request.headers.get('cf-connecting-ip') || 'unknown';
  const now = Date.now();
  if (visits.size > 800) for (const [k, v] of visits) if (now - v.start > 60_000) visits.delete(k);
  const entry = visits.get(key);
  if (!entry || now - entry.start > 60_000) { visits.set(key, { start: now, count: 1 }); return true; }
  entry.count++;
  return entry.count <= 15;
}

function ownerId(request) { return request.headers.get('oai-authenticated-user-id') || null; }
function sameOrigin(request) { return request.headers.get('origin') === new URL(request.url).origin; }
function b64url(value) { return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')), char => char.charCodeAt(0)); }
async function nonceHash(value) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map(byte => byte.toString(16).padStart(2, '0')).join(''); }
let googleKeys = null;
let googleKeysAt = 0;

async function verifyGoogleToken(token, clientId) {
  const parts = token.split('.');
  if (parts.length !== 3 || token.length > 12000) throw new Error('Invalid Google credential');
  const header = JSON.parse(new TextDecoder().decode(b64url(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(b64url(parts[1])));
  if (header.alg !== 'RS256' || !header.kid) throw new Error('Unsupported Google credential');
  if (!googleKeys || Date.now() - googleKeysAt > 600_000) {
    const response = await fetch('https://www.googleapis.com/oauth2/v3/certs', { signal: AbortSignal.timeout(7000) });
    if (!response.ok) throw new Error('Google verification keys unavailable');
    googleKeys = (await response.json()).keys;
    googleKeysAt = Date.now();
  }
  const jwk = googleKeys.find(key => key.kid === header.kid && key.kty === 'RSA');
  if (!jwk) throw new Error('Google signing key not found');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64url(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  const now = Math.floor(Date.now() / 1000);
  if (!valid || !['https://accounts.google.com', 'accounts.google.com'].includes(claims.iss) || claims.aud !== clientId || claims.exp <= now || claims.iat > now + 120 || !claims.sub || !claims.nonce || claims.email_verified !== true) throw new Error('Google credential verification failed');
  return claims;
}

async function linkedGoogle(env, owner) {
  if (!env?.DB || !owner) return null;
  return env.DB.prepare('SELECT google_sub, email, display_name FROM google_links WHERE owner_id = ?').bind(owner).first();
}

async function saveInvestigation(request, env, result) {
  const owner = ownerId(request);
  if (!owner || !env?.DB) return { status: 'unavailable', id: null };
  try {
    if (!await linkedGoogle(env, owner)) return { status: 'sign-in-required', id: null };
    const id = crypto.randomUUID();
    const snapshot = JSON.stringify(result);
    if (snapshot.length > 750_000) return { status: 'too-large', id: null };
    await env.DB.prepare('INSERT INTO investigations (id, owner_id, target, selected_ip, result_json, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, owner, result.input.domain || result.selectedIp, result.selectedIp, snapshot, '', Date.now()).run();
    await env.DB.prepare('DELETE FROM investigations WHERE owner_id = ? AND id NOT IN (SELECT id FROM investigations WHERE owner_id = ? ORDER BY created_at DESC LIMIT 50)').bind(owner, owner).run();
    return { status: 'saved', id };
  } catch (error) { console.error('History save failed', error); return { status: 'unavailable', id: null }; }
}

async function authRoute(request, env, path) {
  const owner = ownerId(request);
  if (path === '/api/me' && request.method === 'GET') {
    if (!owner) return json({ siteSignedIn: false, googleSignedIn: false, clientId: env?.GOOGLE_CLIENT_ID || null, storageAvailable: !!env?.DB });
    try {
      const link = await linkedGoogle(env, owner);
      return json({ siteSignedIn: true, googleSignedIn: !!link, email: link?.email || request.headers.get('oai-authenticated-user-email') || null, name: link?.display_name || null, clientId: env?.GOOGLE_CLIENT_ID || null, storageAvailable: !!env?.DB });
    } catch { return json({ siteSignedIn: true, googleSignedIn: false, clientId: env?.GOOGLE_CLIENT_ID || null, storageAvailable: false }); }
  }
  if (!owner) return json({ error: 'Site sign-in is required.' }, 401);
  if (!env?.DB) return json({ error: 'Saved history is currently unavailable.' }, 503);
  if (request.method !== 'POST' || !sameOrigin(request)) return json({ error: 'Invalid request origin or method.' }, 403);
  if (path === '/api/auth/challenge') {
    if (!env.GOOGLE_CLIENT_ID) return json({ error: 'Google sign-in is not configured.' }, 503);
    const nonce = crypto.randomUUID() + crypto.randomUUID();
    const now = Date.now();
    await env.DB.prepare('DELETE FROM auth_challenges WHERE expires_at < ?').bind(now).run();
    await env.DB.prepare('INSERT INTO auth_challenges (nonce_hash, owner_id, expires_at) VALUES (?, ?, ?)').bind(await nonceHash(nonce), owner, now + 300_000).run();
    return json({ nonce });
  }
  if (path === '/api/auth/google') {
    if (!env.GOOGLE_CLIENT_ID) return json({ error: 'Google sign-in is not configured.' }, 503);
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid credential request.' }, 400); }
    if (typeof body?.credential !== 'string') return json({ error: 'Missing Google credential.' }, 400);
    let claims;
    try { claims = await verifyGoogleToken(body.credential, env.GOOGLE_CLIENT_ID); }
    catch (error) { return json({ error: error.message }, 401); }
    const challenge = await env.DB.prepare('DELETE FROM auth_challenges WHERE nonce_hash = ? AND owner_id = ? AND expires_at > ? RETURNING nonce_hash').bind(await nonceHash(claims.nonce), owner, Date.now()).first();
    if (!challenge) return json({ error: 'Sign-in challenge expired. Please try again.' }, 401);
    try {
      await env.DB.prepare('INSERT INTO google_links (owner_id, google_sub, email, display_name, linked_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(owner_id) DO UPDATE SET google_sub = excluded.google_sub, email = excluded.email, display_name = excluded.display_name, linked_at = excluded.linked_at').bind(owner, claims.sub, claims.email || null, claims.name || null, Date.now()).run();
    } catch { return json({ error: 'That Google account is already linked to another Site user.' }, 409); }
    return json({ signedIn: true, email: claims.email || null, name: claims.name || null });
  }
  if (path === '/api/auth/signout') {
    await env.DB.prepare('DELETE FROM google_links WHERE owner_id = ?').bind(owner).run();
    return json({ signedIn: false });
  }
  return json({ error: 'Not found.' }, 404);
}

async function historyRoute(request, env, path) {
  const owner = ownerId(request);
  if (!owner) return json({ error: 'Site sign-in is required.' }, 401);
  if (!env?.DB) return json({ error: 'Saved history is currently unavailable.' }, 503);
  if (!await linkedGoogle(env, owner)) return json({ error: 'Sign in with Google to view saved history.' }, 401);
  if (path === '/api/history' && request.method === 'GET') {
    const result = await env.DB.prepare('SELECT id, target, selected_ip, created_at FROM investigations WHERE owner_id = ? ORDER BY created_at DESC LIMIT 50').bind(owner).all();
    return json({ items: result.results || [] });
  }
  const match = /^\/api\/history\/([0-9a-f-]{36})(?:\/notes)?$/.exec(path);
  if (!match) return json({ error: 'Not found.' }, 404);
  const id = match[1];
  if (request.method === 'GET' && !path.endsWith('/notes')) {
    const item = await env.DB.prepare('SELECT result_json, notes FROM investigations WHERE id = ? AND owner_id = ?').bind(id, owner).first();
    return item ? json({ result: JSON.parse(item.result_json), notes: item.notes || '' }) : json({ error: 'History item not found.' }, 404);
  }
  if (!sameOrigin(request)) return json({ error: 'Invalid request origin.' }, 403);
  if (request.method === 'DELETE' && !path.endsWith('/notes')) {
    await env.DB.prepare('DELETE FROM investigations WHERE id = ? AND owner_id = ?').bind(id, owner).run();
    return json({ deleted: true });
  }
  if (request.method === 'PATCH' && path.endsWith('/notes')) {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid notes.' }, 400); }
    if (typeof body?.notes !== 'string' || body.notes.length > 20_000) return json({ error: 'Notes must be under 20,000 characters.' }, 400);
    await env.DB.prepare('UPDATE investigations SET notes = ? WHERE id = ? AND owner_id = ?').bind(body.notes, id, owner).run();
    return json({ saved: true });
  }
  return json({ error: 'Method not allowed.' }, 405);
}

async function investigate(request, env) {
  if (!rateAllowed(request)) return json({ error: 'Please wait before making more lookups.' }, 429);
  const params = new URL(request.url).searchParams;
  const domainInput = params.get('domain')?.trim() || '';
  const ipInput = params.get('ip')?.trim() || '';
  const domain = domainInput ? parseDomain(domainInput) : null;
  const requestedIp = ipInput ? parseIp(ipInput) : null;
  if (!domain && !requestedIp) return json({ error: 'Enter a valid domain or public IP address.' }, 400);
  if (domainInput && !domain || ipInput && !requestedIp) return json({ error: 'Check the domain or IP address format.' }, 400);
  if (requestedIp && !isPublicIp(requestedIp)) return json({ error: 'Only public IP addresses can be investigated.' }, 400);
  const evidence = [];
  const startedAt = new Date().toISOString();
  const summary = params.get('summary') === '1';
  const resolvedIps = domain ? await dnsRecords(domain, evidence) : [];
  const ip = requestedIp?.value || resolvedIps.find(x => { const p = parseIp(x); return p && isPublicIp(p); }) || null;
  const allPublicIps = [...new Set([ip, ...resolvedIps].filter(value => { const parsed = parseIp(value); return parsed && isPublicIp(parsed); }))];
  const mappedIps = allPublicIps.slice(0, summary ? 1 : MAX_MAPPED_IPS);
  const [ipLocations, network, subdomains, relatedHosts, threat] = await Promise.all([
    Promise.all(mappedIps.map(async address => ({ ip: address, location: await geolocate(address, evidence) }))),
    ip ? networkInfo(ip, evidence) : null,
    summary || !domain ? null : discoverSubdomains(domain, evidence),
    summary || !mappedIps.length ? null : discoverRelatedHosts(mappedIps, evidence),
    summary ? null : ip ? threatContext(ip, env, evidence) : null
  ]);
  const location = ipLocations.find(item => item.ip === ip)?.location || null;
  const result = { input: { domain, requestedIp: requestedIp?.value || null }, resolvedIps, selectedIp: ip, domainResolvesToSelectedIp: domain && ip ? resolvedIps.includes(ip) : null, startedAt, completedAt: new Date().toISOString(), location, ipLocations, ipLocationsTruncated: allPublicIps.length > mappedIps.length, network, subdomains, relatedHosts, threat, exposures: {}, dnsPosture: null, evidence, limits: { subdomains: MAX_SUBDOMAINS, deepSubdomains: MAX_DEEP_SUBDOMAINS, scannerDnsChecks: MAX_SCANNER_DNS, mappedIps: MAX_MAPPED_IPS, reverseIps: MAX_REVERSE_IPS, ratePerMinutePerInstance: 15 } };
  if (!summary) {
    const history = await saveInvestigation(request, env, result);
    result.historyId = history.id;
    result.historyStatus = history.status;
  }
  return json(result);
}

export { parseIp, isPublicIp, parseDomain, normalizeGeo, buildLocation, haversine, networkInfo, addSubdomain, normalizeExposure, verifyGoogleToken };
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/investigate') return investigate(request, env);
    if (url.pathname === '/api/subdomains') return scanSubdomains(request);
    if (url.pathname === '/api/exposure') return exposureRoute(request);
    if (url.pathname === '/api/dns-posture') return dnsPostureRoute(request);
    if (url.pathname === '/api/me' || url.pathname.startsWith('/api/auth/')) {
      try { return await authRoute(request, env, url.pathname); }
      catch (error) { console.error('Authentication storage failed', error); return json({ error: 'Sign-in is temporarily unavailable.' }, 503); }
    }
    if (url.pathname === '/api/history' || url.pathname.startsWith('/api/history/')) {
      try { return await historyRoute(request, env, url.pathname); }
      catch (error) { console.error('History storage failed', error); return json({ error: 'Saved history is temporarily unavailable.' }, 503); }
    }
    if (url.pathname === '/api/self') return json({ ip: request.headers.get('cf-connecting-ip') || null });
    const asset = ASSETS?.[url.pathname];
    if (!asset) return new Response('Not found', { status: 404 });
    return new Response(asset.body, { headers: { 'content-type': asset.type, 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'cache-control': 'no-cache' } });
  }
};
