import worker from './worker-browser.mjs';

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8' }
});

export async function browserApi(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.pathname === '/api/me') {
    return json({ siteSignedIn: true, googleSignedIn: false, clientId: null, storageAvailable: false, localOnly: true });
  }
  if (url.pathname === '/api/web-posture') {
    return json({ error: 'The HTTPS header and certificate check requires the localhost server.' }, 501);
  }
  if (url.pathname === '/api/self') return json({ ip: null });
  try {
    return await worker.fetch(new Request(url, options), {});
  } catch (error) {
    return json({ error: `Browser lookup failed: ${error.message || 'unknown error'}` }, 503);
  }
}
