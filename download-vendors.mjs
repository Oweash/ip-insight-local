import { writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const assets = [
  ['leaflet.css', 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css', 'p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY='],
  ['leaflet.js', 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js', '20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo='],
  ['docx.js', 'https://cdn.jsdelivr.net/npm/docx@9.7.1/dist/index.iife.js', null]
];
for (const [name, url, integrity] of assets) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
  const body = Buffer.from(await response.arrayBuffer());
  const digest = createHash('sha256').update(body).digest('base64');
  if (integrity && digest !== integrity) throw new Error(`${name}: integrity mismatch`);
  await writeFile(`dist/${name}`, body);
  console.log(`${name}: ${body.length} bytes, sha256-${digest}`);
}
const licenseUrls = [
  ['Leaflet 1.9.4', 'https://unpkg.com/leaflet@1.9.4/LICENSE'],
  ['docx 9.7.1', 'https://unpkg.com/docx@9.7.1/LICENSE']
];
let licenses = '';
for (const [name, url] of licenseUrls) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${name} license: HTTP ${response.status}`);
  licenses += `${name}\n${url}\n\n${await response.text()}\n\n`;
}
await writeFile('dist/licenses.txt', licenses);
