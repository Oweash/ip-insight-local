import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';

const base = '/ip-insight-local/';
const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.txt': 'text/plain' };
createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1:4174');
  const relative = url.pathname.startsWith(base) ? url.pathname.slice(base.length) || 'index.html' : null;
  if (!relative || !/^[a-zA-Z0-9._-]+$/.test(relative)) { response.writeHead(404).end(); return; }
  try {
    const data = await readFile(join('pages', relative));
    response.writeHead(200, { 'content-type': `${types[extname(relative)] || 'application/octet-stream'}; charset=utf-8` }).end(data);
  } catch { response.writeHead(404).end(); }
}).listen(4174, '127.0.0.1', () => console.log(`Preview at http://127.0.0.1:4174${base}`));
