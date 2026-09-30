import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { parseIp, isPublicIp, parseDomain, normalizeGeo, buildLocation, networkInfo, addSubdomain, normalizeExposure } from '../src/worker.mjs';

test('only public targets are accepted and domain URLs are normalized', () => {
  assert.equal(parseDomain('https://Sub.Example.COM/path'), 'sub.example.com');
  assert.equal(parseDomain('localhost'), null);
  assert.equal(isPublicIp(parseIp('8.8.8.8')), true);
  assert.equal(isPublicIp(parseIp('192.168.1.2')), false);
  assert.equal(isPublicIp(parseIp('2001:db8::1')), false);
});

test('provider radius measures reported-point spread and is unavailable with one source', () => {
  const a = { name: 'A', latitude: 0, longitude: 0 };
  const b = { name: 'B', latitude: 0, longitude: 1 };
  const result = buildLocation([a, b]);
  assert.equal(result.radiusKind, 'provider-spread');
  assert.ok(result.radiusKm >= 111 && result.radiusKm <= 113);
  assert.equal(result.agreement, 'low agreement');
  assert.equal(result.nearestConsensusSource, null);
  assert.equal(buildLocation([a]).radiusKm, null);
});

test('missing provider coordinates cannot be interpreted as zero, zero', () => {
  assert.equal(normalizeGeo('IPWhois', { city: 'Unknown' }, 'https://ipwho.is/', new Date().toISOString()), null);
  const geojs = normalizeGeo('GeoJS', { latitude: '37.1', longitude: '-122.2', city: 'A', accuracy: 150 }, 'https://get.geojs.io/', new Date().toISOString());
  assert.equal(geojs.latitude, 37.1);
  assert.equal(geojs.reportedAccuracyKm, 150);
  assert.equal(normalizeGeo('FreeIPAPI', { latitude: 37.2, longitude: -122.3, cityName: 'B' }, 'https://free.freeipapi.com/', new Date().toISOString()).city, 'B');
});

test('registry ownership falls back to public WHOIS when RDAP fails', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async url => {
    const path = String(url);
    if (path.includes('rdap.arin.net')) return new Response('', { status: 525 });
    if (path.includes('network-info')) return Response.json({ data: { prefix: '104.20.16.0/20', asns: [13335] } });
    return Response.json({ data: { records: [[{ key: 'NetName', value: 'CLOUDFLARENET' }, { key: 'NetRange', value: '104.16.0.0 - 104.31.255.255' }]] } });
  };
  try {
    const evidence = [];
    const result = await networkInfo('104.20.23.154', evidence);
    assert.equal(result.rdap.name, 'CLOUDFLARENET');
    assert.equal(result.rdap.sourceName, 'RIPEstat WHOIS');
    assert.equal(result.rdap.startAddress, '104.16.0.0');
    assert.equal(evidence.find(x => x.name === 'RDAP').status, 'unavailable');
    assert.equal(evidence.find(x => x.name === 'RIPEstat WHOIS').status, 'ok');
  } finally { globalThis.fetch = original; }
});

test('certificate wildcard and unrelated names are not reported as observed hosts', () => {
  const map = new Map();
  addSubdomain(map, '*.example.com', 'example.com', 'CT');
  addSubdomain(map, 'login.other.com', 'example.com', 'CT');
  addSubdomain(map, 'api.example.com', 'example.com', 'CT');
  addSubdomain(map, 'api.example.com', 'example.com', 'second source');
  assert.deepEqual([...map.keys()], ['api.example.com']);
  assert.deepEqual(map.get('api.example.com').sources, ['CT', 'second source']);
});

test('InternetDB exposure keeps valid passive leads and rejects malformed values', () => {
  const record = normalizeExposure('8.8.8.8', { ports: [443, 443, -1, 70000], cpes: ['cpe:/a:example:web'], hostnames: ['api.example.com', 'localhost'], vulns: ['CVE-2024-12345', 'not-a-cve'], tags: ['cdn'] });
  assert.deepEqual(record.ports, [443]);
  assert.deepEqual(record.hostnames, ['api.example.com']);
  assert.deepEqual(record.vulns, ['CVE-2024-12345']);
});

test('deep discovery merges passive sources and labels wildcard DNS matches', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async url => {
    const value = String(url);
    if (value.includes('crt.sh')) return Response.json([{ name_value: 'api.example.com\n*.example.com' }]);
    if (value.includes('certspotter')) return Response.json([{ dns_names: ['api.example.com', 'shop.example.com'] }]);
    if (value.includes('hackertarget.com/hostsearch')) return new Response('shop.example.com,1.1.1.1');
    if (value.includes('otx.alienvault.com')) return Response.json({ passive_dns: [{ hostname: 'old.example.com', address: '8.8.4.4' }] });
    if (value.includes('urlscan.io')) return Response.json({ results: [{ page: { domain: 'admin.example.com' } }, { page: { domain: 'unrelated.net' } }] });
    if (value.includes('dns.google')) {
      const name = new URL(value).searchParams.get('name');
      return Response.json({ Answer: name.startsWith('ipinsight-') || name === 'api.example.com' ? [{ type: 1, data: '8.8.8.8' }] : name === 'shop.example.com' ? [{ type: 1, data: '1.1.1.1' }] : [] });
    }
    throw new Error(`Unexpected URL: ${value}`);
  };
  try {
    const response = await worker.fetch(new Request('https://unit.test/api/subdomains?domain=example.com'), {});
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.deepEqual(result.subdomains.items.map(item => item.name), ['admin.example.com','api.example.com','old.example.com','shop.example.com']);
    assert.equal(result.subdomains.items.find(item => item.name === 'api.example.com').dnsCheck.wildcardMatch, true);
    assert.equal(result.subdomains.items.find(item => item.name === 'shop.example.com').dnsCheck.status, 'resolves-a');
    assert.equal(result.subdomains.items.find(item => item.name === 'old.example.com').observedIps[0], '8.8.4.4');
    assert.equal(result.checkedCount, 4);
  } finally { globalThis.fetch = original; }
});

test('IP exposure lookup accepts only public addresses and returns source evidence', async () => {
  const blocked = await worker.fetch(new Request('https://unit.test/api/exposure?ip=192.168.1.2'), {});
  assert.equal(blocked.status, 400);
  const original = globalThis.fetch;
  globalThis.fetch = async url => {
    assert.equal(String(url), 'https://internetdb.shodan.io/8.8.8.8');
    return Response.json({ ports: [53, 443], cpes: ['cpe:/a:example:dns'], vulns: ['CVE-2024-12345'], hostnames: ['dns.example.com'], tags: [] });
  };
  try {
    const response = await worker.fetch(new Request('https://unit.test/api/exposure?ip=8.8.8.8'), {});
    const data = await response.json();
    assert.equal(data.exposure.status, 'ok');
    assert.deepEqual(data.exposure.ports, [53, 443]);
    assert.equal(data.evidence[0].status, 'ok');
  } finally { globalThis.fetch = original; }
});

test('DNS posture keeps unavailable lookups distinct from absent records', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async url => {
    const value = String(url), params = new URL(value).searchParams;
    if (params.get('name') === '_dmarc.example.com') throw new Error('Resolver unavailable');
    if (params.get('type') === 'TXT') return Response.json({ Answer: [{ type: 16, data: '"v=spf1 -all"' }] });
    if (params.get('type') === 'MX') return Response.json({ Answer: [{ type: 15, data: '10 mail.example.com.' }] });
    return Response.json({ Answer: [] });
  };
  try {
    const response = await worker.fetch(new Request('https://unit.test/api/dns-posture?domain=example.com'), {});
    const data = await response.json();
    assert.deepEqual(data.posture.spf, ['"v=spf1 -all"']);
    assert.equal(data.posture.available.dmarc, false);
    assert.equal(data.posture.available.caa, true);
  } finally { globalThis.fetch = original; }
});

test('domain investigation keeps source evidence and uses DNS selected IP', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async url => {
    const u = String(url);
    let data;
    if (u.includes('dns.google') && u.endsWith('type=A')) data = { Answer: [{ type: 1, data: '8.8.8.8' }, { type: 1, data: '9.9.9.9' }] };
    else if (u.includes('dns.google')) data = { Answer: [] };
    else if (u.includes('ipwho.is')) data = { success: true, latitude: 37, longitude: -122, city: 'A', country: 'US', connection: { org: 'Example' } };
    else if (u.includes('get.geojs.io')) data = { latitude: '37.1', longitude: '-122', city: 'B', country: 'US' };
    else if (u.includes('api.ipapi.is')) data = { lat: 37.15, lon: -122, city: 'D', country: 'US' };
    else if (u.includes('free.freeipapi.com')) data = { latitude: 37.2, longitude: -122, cityName: 'C', countryName: 'US' };
    else if (u.includes('rdap.arin.net')) data = { objectClassName: 'ip network', name: 'Example network', startAddress: '8.8.8.0', endAddress: '8.8.8.255' };
    else if (u.includes('stat.ripe.net')) data = { data: { prefix: '8.8.8.0/24', asns: [15169] } };
    else if (u.includes('crt.sh')) data = [{ name_value: 'api.example.com\n*.example.com' }];
    else if (u.includes('certspotter')) data = [{ dns_names: ['api.example.com', 'mail.example.com'] }];
    else if (u.includes('hackertarget.com/hostsearch')) return new Response('www.example.com,8.8.8.8', { status: 200 });
    else if (u.includes('hackertarget.com/reverseiplookup')) return new Response('', { status: 200 });
    else throw new Error(`Unexpected URL: ${u}`);
    return new Response(JSON.stringify(data), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    const response = await worker.fetch(new Request('https://unit.test/api/investigate?domain=example.com'), {});
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.selectedIp, '8.8.8.8');
    assert.equal(result.domainResolvesToSelectedIp, true);
    assert.deepEqual(result.resolvedIps, ['8.8.8.8', '9.9.9.9']);
    assert.deepEqual(result.ipLocations.map(x => x.ip), ['8.8.8.8', '9.9.9.9']);
    assert.ok(result.ipLocations.every(x => x.location.providers.length === 4));
    assert.ok(result.location.radiusKm > 0);
    assert.deepEqual(result.subdomains.items.map(x => x.name), ['api.example.com', 'mail.example.com', 'www.example.com']);
    assert.equal(result.network.routing.prefix, '8.8.8.0/24');
    assert.deepEqual(result.exposures, {});
    assert.equal(result.dnsPosture, null);
    assert.ok(result.evidence.length >= 8);
  } finally { globalThis.fetch = original; }
});
