import * as maplibregl from './maplibre-gl.mjs';
maplibregl.setWorkerUrl('/maplibre-gl-worker.mjs');
window.maplibregl = maplibregl;
window.dispatchEvent(new Event('maplibre-ready'));
