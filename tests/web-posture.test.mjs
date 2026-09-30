import test from 'node:test';
import assert from 'node:assert/strict';
import { publicIpv4, assessHeaders, checkWebPosture } from '../src/web-posture.mjs';

test('web check accepts public IPv4 only and stops before any private-address request', async () => {
  assert.equal(publicIpv4('8.8.8.8'), true);
  for (const ip of ['127.0.0.1','10.2.3.4','172.16.0.1','192.168.1.1','169.254.1.1','100.64.0.1','192.0.0.8','198.51.100.1']) assert.equal(publicIpv4(ip), false, ip);
  let called = false;
  await assert.rejects(checkWebPosture('example.com', { resolve: async () => [{ address: '8.8.8.8' }, { address: '127.0.0.1' }], request: async () => { called = true; } }), /exclusively public/);
  assert.equal(called, false);
});

test('web check records headers, certificate, and disclosure contacts', async () => {
  const calls = [];
  const result = await checkWebPosture('example.com', {
    resolve: async () => [{ address: '93.184.215.14' }],
    request: async (_domain, address, path, method) => {
      calls.push([address,path,method]);
      if (path === '/') return { status: 200, headers: { 'strict-transport-security': 'max-age=31536000', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" }, certificate: { subject: 'example.com', issuer: 'Example CA', validTo: '2030-01-01' } };
      return { status: 200, body: 'Contact: mailto:security@example.com\nPolicy: https://example.com/policy\nExpires: 2030-01-01T00:00:00Z\n' };
    }
  });
  assert.deepEqual(calls, [['93.184.215.14','/','HEAD'],['93.184.215.14','/.well-known/security.txt','GET']]);
  assert.deepEqual(result.securityTxt.contact, ['mailto:security@example.com']);
  assert.equal(result.headerChecks.find(x => x.name === 'Frame protection').status, 'observed');
  assert.equal(result.headerChecks.find(x => x.name === 'Referrer-Policy').status, 'review');
  assert.equal(result.homepage.certificate.subject, 'example.com');
});

test('missing header is a review lead rather than a vulnerability claim', () => {
  const checks = assessHeaders({});
  assert.ok(checks.every(item => item.status === 'review'));
  assert.ok(checks.every(item => !('severity' in item)));
});
