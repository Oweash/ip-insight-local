import { lookup } from 'node:dns/promises';
import https from 'node:https';
import { parseDomain } from './worker.mjs';

export function publicIpv4(address) {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168) return false;
  if (a === 192 && (b === 0 || b === 88 && c === 99) || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113) return false;
  return true;
}

export function assessHeaders(headers) {
  const checks = [
    ['Strict-Transport-Security', !!headers['strict-transport-security'], 'Helps browsers keep using HTTPS.'],
    ['Content-Security-Policy', !!headers['content-security-policy'], 'Can limit injected content when configured for this application.'],
    ['X-Content-Type-Options', headers['x-content-type-options']?.toLowerCase() === 'nosniff', 'The expected value is nosniff.'],
    ['Referrer-Policy', !!headers['referrer-policy'], 'Controls referrer information shared with other sites.'],
    ['Permissions-Policy', !!headers['permissions-policy'], 'Can restrict browser features.'],
    ['Frame protection', !!headers['x-frame-options'] || /frame-ancestors\b/i.test(headers['content-security-policy'] || ''), 'Review framing policy for this application.']
  ];
  return checks.map(([name, present, meaning]) => ({ name, status: present ? 'observed' : 'review', value: String(headers[name.toLowerCase()] || (name === 'Frame protection' && present ? 'CSP frame-ancestors or X-Frame-Options' : '')).slice(0, 500), meaning }));
}

function requestPinned(domain, address, path, method) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: domain, servername: domain, port: 443, path, method, timeout: 6500,
      maxHeaderSize: 16_384, headers: { 'user-agent': 'IP-Insight-local/1.0', accept: 'text/plain, */*' },
      lookup: (_host, _options, callback) => callback(null, address, 4)
    }, response => {
      const headers = Object.fromEntries(Object.entries(response.headers).map(([key, value]) => [key, Array.isArray(value) ? value.join('; ') : String(value || '')]));
      const certificate = response.socket.getPeerCertificate?.();
      let body = '';
      response.on('data', chunk => { if (body.length < 16_384) body += chunk.toString('utf8').slice(0, 16_384 - body.length); });
      response.on('end', () => resolve({ status: response.statusCode, headers, body, certificate: certificate && Object.keys(certificate).length ? {
        subject: String(certificate.subject?.CN || ''), issuer: String(certificate.issuer?.CN || ''), validTo: String(certificate.valid_to || ''), fingerprint256: String(certificate.fingerprint256 || '')
      } : null }));
      if (method === 'HEAD') response.resume();
    });
    req.on('timeout', () => req.destroy(new Error('HTTPS request timed out')));
    req.on('error', reject);
    req.end();
  });
}

export async function checkWebPosture(rawDomain, { resolve = lookup, request = requestPinned } = {}) {
  const domain = parseDomain(rawDomain);
  if (!domain) throw new Error('Enter a valid domain.');
  const addresses = await resolve(domain, { family: 4, all: true, verbatim: true });
  const publicAddresses = addresses.map(item => item.address).filter(publicIpv4);
  if (!addresses.length || publicAddresses.length !== addresses.length) throw new Error('The domain has no exclusively public IPv4 DNS answers. Web checks were stopped.');
  const address = publicAddresses[0];
  const homepage = await request(domain, address, '/', 'HEAD');
  const disclosure = await request(domain, address, '/.well-known/security.txt', 'GET').catch(error => ({ status: null, error: error.message, body: '' }));
  const fields = {};
  if (disclosure.status === 200) for (const line of disclosure.body.split(/\r?\n/)) {
    const match = /^(Contact|Policy|Expires):\s*(.+)$/i.exec(line.trim());
    if (match) (fields[match[1].toLowerCase()] ||= []).push(match[2].slice(0, 400));
  }
  const headers = Object.fromEntries(Object.entries(homepage.headers).filter(([name]) => ['server', 'x-powered-by', 'strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'x-frame-options'].includes(name)));
  return {
    domain, checkedAt: new Date().toISOString(), connectedIp: address, homepage: { url: `https://${domain}/`, status: homepage.status, headers, certificate: homepage.certificate },
    headerChecks: assessHeaders(homepage.headers),
    securityTxt: { url: `https://${domain}/.well-known/security.txt`, status: disclosure.status, ...fields, error: disclosure.error || null },
    note: 'Two read-only HTTPS requests were made to the specified hostname. Redirects were not followed. Headers and security.txt are configuration and disclosure leads, not proof of a vulnerability. The address was pinned after public DNS validation.'
  };
}
