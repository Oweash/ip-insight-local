import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';

await mkdir('pages', { recursive: true });
await cp('dist', 'pages', { recursive: true, force: true });
await cp('src/worker.mjs', 'pages/worker-browser.mjs');
await cp('src/browser-api.mjs', 'pages/browser-api.mjs');

let html = await readFile('pages/index.html', 'utf8');
html = html.replaceAll('href="/', 'href="./').replaceAll('src="/', 'src="./');
const appTag = '<script type="module" src="./app.js?v=13"></script>';
if (!html.includes(appTag)) throw new Error('Could not find the app entry script in the Pages bundle.');
html = html.replace(appTag, `<script>window.IP_INSIGHT_STATIC = true;</script>\n  ${appTag}`);
html = html.replace('/ local v13', '/ GitHub Pages');
html = html.replace('Makes two HTTPS requests to the entered domain:', 'In the localhost edition, this makes two HTTPS requests to the entered domain:');
await writeFile('pages/index.html', html);

console.log('GitHub Pages static bundle ready in pages/');
