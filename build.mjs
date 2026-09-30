import { readFile, mkdir, writeFile, copyFile } from 'node:fs/promises';
for (const [from, to] of [
  ['node_modules/maplibre-gl/dist/maplibre-gl.mjs', 'dist/maplibre-gl.mjs'],
  ['node_modules/maplibre-gl/dist/maplibre-gl-shared.mjs', 'dist/maplibre-gl-shared.mjs'],
  ['node_modules/maplibre-gl/dist/maplibre-gl-worker.mjs', 'dist/maplibre-gl-worker.mjs'],
  ['node_modules/maplibre-gl/dist/maplibre-gl.css', 'dist/maplibre-gl.css'],
  ['node_modules/jszip/dist/jszip.min.js', 'dist/jszip.js']
]) await copyFile(from, to);
const vendorLicenses = [
  ['MapLibre GL JS', 'node_modules/maplibre-gl/LICENSE.txt'],
  ['JSZip', 'node_modules/jszip/LICENSE.markdown']
];
let licenses = await readFile('vendor-licenses-base.txt', 'utf8');
for (const [name, path] of vendorLicenses) licenses += `\n\n${name}\n\n${await readFile(path, 'utf8')}`;
await writeFile('dist/licenses.txt', licenses);
await copyFile('src/local-history.mjs', 'dist/local-history.mjs');
