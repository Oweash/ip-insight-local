import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import worker from './src/worker.mjs';
import { checkWebPosture } from './src/web-posture.mjs';
import { connectedNetworks, scanConnectedNetwork } from './src/local-network.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.IP_INSIGHT_PORT || 4173);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('IP_INSIGHT_PORT must be between 1024 and 65535.');
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ...Object.entries({ 'styles.css': 'text/css', 'app.js': 'text/javascript', 'workspace-nav.mjs': 'text/javascript', 'connection-scanner.mjs': 'text/javascript', 'local-history.mjs': 'text/javascript', 'map-ui.mjs': 'text/javascript', 'maplibre-gl.mjs': 'text/javascript', 'maplibre-gl-shared.mjs': 'text/javascript', 'maplibre-gl-worker.mjs': 'text/javascript', 'maplibre-gl.css': 'text/css', 'jszip.js': 'text/javascript', 'docx.js': 'text/javascript', 'leaflet.css': 'text/css', 'leaflet.js': 'text/javascript', 'licenses.txt': 'text/plain', 'logo.png': 'image/png' }).map(([name, type]) => [`/${name}`, [name, type]])
]);

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' });
  res.end(body);
}
const errorJson = message => JSON.stringify({ error: message });
let networkScanRunning = false;
async function readJson(req) {
  let size = 0, body = '';
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 4096) throw new Error('Request body is too large.');
    body += chunk.toString('utf8');
  }
  return JSON.parse(body);
}

const server = http.createServer(async (req, res) => {
  try {
    const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
    if (!allowedHosts.has(req.headers.host)) return send(res, 403, errorJson('Invalid local host.'));
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    if (url.pathname === '/api/local-network/scan') {
      if (req.method !== 'POST') return send(res, 405, errorJson('Method not allowed.'));
      if (req.headers.origin !== `http://${req.headers.host}` || !String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 403, errorJson('Invalid local request origin.'));
      if (networkScanRunning) return send(res, 429, errorJson('A local network scan is already running.'));
      try {
        const body = await readJson(req);
        if (body.authorized !== true) return send(res, 403, errorJson('Confirm you are authorized to scan this connected network.'));
        networkScanRunning = true;
        if (String(req.headers.accept || '').includes('application/x-ndjson')) {
          const aborter = new AbortController();
          res.on('close', () => aborter.abort());
          res.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
          const emit = event => { if (!res.destroyed) res.write(`${JSON.stringify(event)}\n`); };
          try {
            const result = await scanConnectedNetwork(body.networkId, body.scan, { signal: aborter.signal, onProgress: event => emit({ type: 'progress', ...event }) });
            emit({ type: 'result', data: result });
          } catch (error) { emit({ type: 'error', message: error.message }); }
          res.end();
          return;
        }
        return send(res, 200, JSON.stringify(await scanConnectedNetwork(body.networkId, body.scan || body.ports)));
      } catch (error) { return send(res, 400, errorJson(error.message)); }
      finally { networkScanRunning = false; }
    }
    if (url.pathname === '/api/web-posture') {
      if (req.method !== 'POST') return send(res, 405, errorJson('Method not allowed.'));
      if (req.headers.origin !== `http://${req.headers.host}` || !String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 403, errorJson('Invalid local request origin.'));
      try {
        const body = await readJson(req);
        if (body.authorized !== true) return send(res, 403, errorJson('Confirm you are authorized to test this domain.'));
        return send(res, 200, JSON.stringify({ posture: await checkWebPosture(body.domain || '') }));
      } catch (error) { return send(res, 400, errorJson(error.message)); }
    }
    if (req.method !== 'GET') return send(res, 405, errorJson('Method not allowed.'));
    if (url.pathname === '/api/local-network/interfaces') return send(res, 200, JSON.stringify({ networks: connectedNetworks() }));
    if (url.pathname === '/api/me') return send(res, 200, JSON.stringify({ siteSignedIn: true, googleSignedIn: false, clientId: null, storageAvailable: false, localOnly: true }));
    if (url.pathname === '/api/self') return send(res, 200, JSON.stringify({ ip: null }));
    if (url.pathname.startsWith('/api/')) {
      const request = new Request(url, { method: 'GET', headers: { 'cf-connecting-ip': '127.0.0.1' } });
      const response = await worker.fetch(request, { ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY || undefined });
      return send(res, response.status, Buffer.from(await response.arrayBuffer()), response.headers.get('content-type') || 'application/json; charset=utf-8');
    }
    const asset = assets.get(url.pathname);
    if (!asset) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    const [filename, type] = asset;
    return send(res, 200, await readFile(path.join(root, 'dist', filename)), type);
  } catch (error) {
    console.error(error);
    return send(res, 500, errorJson('Local server error.'));
  }
});
server.listen(port, '127.0.0.1', () => console.log(`IP Insight is running at http://127.0.0.1:${port}`));
