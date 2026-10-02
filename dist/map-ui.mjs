import * as maplibregl from './maplibre-gl.mjs';
maplibregl.setWorkerUrl(new URL('./maplibre-gl-worker.mjs', import.meta.url).href);
window.maplibregl = maplibregl;
window.dispatchEvent(new Event('maplibre-ready'));
