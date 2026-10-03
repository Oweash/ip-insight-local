const $ = id => document.getElementById(id);
const showStatus = (message, error = false) => {
  const node = $('local-scan-status');
  node.textContent = message;
  node.hidden = !message;
  node.classList.toggle('error', error);
};
async function jsonWithTimeout(url, options = {}) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error(`Service returned HTTP ${response.status}.`);
  return response.json();
}
async function loadPublicConnection() {
  $('self-refresh').disabled = true;
  $('self-public-ip').textContent = 'Checking public IP…';
  $('self-public-area').textContent = 'Checking location…';
  $('self-public-source').textContent = 'IP geolocation is approximate';
  try {
    let ip;
    try { ip = (await jsonWithTimeout('https://api64.ipify.org?format=json')).ip; }
    catch { ip = (await jsonWithTimeout('https://ipwho.is/')).ip; }
    if (!ip) throw new Error('Public IP unavailable.');
    $('self-public-ip').textContent = ip;
    const providers = [
      ['IPWhois', `https://ipwho.is/${encodeURIComponent(ip)}`, data => data.success !== false && [data.city, data.region, data.country]],
      ['GeoJS', `https://get.geojs.io/v1/ip/geo/${encodeURIComponent(ip)}.json`, data => !data.error && [data.city, data.region, data.country]],
      ['ipapi.is', `https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, data => !data.error && [data.city, data.region, data.country]],
      ['FreeIPAPI', `https://free.freeipapi.com/api/v1/json/${encodeURIComponent(ip)}`, data => !data.error && [data.cityName, data.regionName, data.countryName]]
    ];
    for (const [name, url, area] of providers) {
      try {
        const data = await jsonWithTimeout(url);
        const parts = area(data);
        if (!parts || !parts.some(Boolean)) continue;
        $('self-public-area').textContent = parts.filter(Boolean).join(', ');
        $('self-public-source').textContent = `Approximate area from ${name} · VPNs and mobile networks can differ`;
        return;
      } catch { /* Try the next location provider. */ }
    }
    $('self-public-area').textContent = 'Location unavailable';
    $('self-public-source').textContent = 'Public IP from ipify · location providers unavailable';
  } catch {
    $('self-public-ip').textContent = 'Unavailable';
    $('self-public-area').textContent = 'Unavailable';
    $('self-public-source').textContent = 'Public lookup services could not be reached';
  } finally { $('self-refresh').disabled = false; }
}
async function loadNetworks() {
  const select = $('local-network-select');
  select.replaceChildren();
  try {
    const response = await fetch('/api/local-network/interfaces');
    if (!response.ok) throw new Error('Could not list connected networks.');
    const data = await response.json();
    for (const network of data.networks || []) {
      const option = document.createElement('option');
      option.value = network.id;
      option.textContent = `${network.name} · ${network.cidr}${network.limitedTo24 ? ' (local /24 segment)' : ''}`;
      select.append(option);
    }
    if (!select.options.length) {
      $('local-scan-button').disabled = true;
      showStatus('No connected private IPv4 network was found. Connect to your Wi-Fi or LAN, then reload.', true);
    }
  } catch (error) { showStatus(error.message, true); }
}
function updateScanPlan() {
  const profile = $('local-port-profile').value;
  const protocol = $('local-protocol').value;
  $('local-custom-ports-field').hidden = profile !== 'custom';
  $('local-target-ip').required = profile === 'all';
  const count = profile === 'all' ? '65,535 ports per selected protocol on one device' : profile === 'common' ? '30 common TCP ports and/or 8 common UDP ports on discovered devices' : 'only the ports you mention (up to 128)';
  $('local-scan-plan').textContent = `${count}. ${protocol === 'udp' || protocol === 'both' ? 'UDP silence is uncertain. ' : ''}${profile === 'all' ? 'A full scan can take many minutes; progress and cancellation are available. ' : ''}Version clues come from limited read-only probes and may be absent or inaccurate.`;
}
let scanController;
let lastScanResult;
function renderScan(data) {
  lastScanResult = data;
  $('local-scan-export').hidden = false;
  const body = $('local-scan-body');
  body.replaceChildren();
  const totals = { tcpOpen: 0, tcpClosed: 0, tcpFiltered: 0, udpOpen: 0, udpClosed: 0, udpUncertain: 0 };
  for (const device of data.devices) {
    for (const key of Object.keys(totals)) totals[key] += device.counts[key] || 0;
    const findings = device.findings.length ? device.findings : [null];
    for (const finding of findings) {
      const row = document.createElement('tr');
      const identity = finding ? [finding.service, [finding.product, finding.version].filter(Boolean).join(' ')].filter(Boolean).join(' · ') : 'No confirmed open ports in selected set';
      const cells = [`${device.ip}${device.isThisDevice ? ' · this computer' : ''}\nMAC: ${device.mac || 'Not available'}`, finding ? `${finding.port}/${finding.protocol}` : '—', finding?.state || '—', identity, finding ? `${finding.evidence || 'No evidence'}${finding.latencyMs == null ? '' : ` · ${finding.latencyMs} ms`}` : device.discovery];
      for (const value of cells) { const td = document.createElement('td'); td.textContent = value; row.append(td); }
      body.append(row);
    }
  }
  $('local-scan-summary').textContent = `${data.network.cidr} · ${data.scannedHosts} device addresses checked · ${data.devices.length} devices included · ${data.portCountPerDevice.toLocaleString()} port checks per device. TCP: ${totals.tcpOpen} open, ${totals.tcpClosed} refused, ${totals.tcpFiltered} filtered/no reply. UDP: ${totals.udpOpen} responses, ${totals.udpClosed} refused, ${totals.udpUncertain} unanswered. ${data.note}`;
  $('local-scan-summary').hidden = false;
  $('local-scan-results').hidden = !data.devices.length;
  $('local-scan-log').hidden = data.verbosity !== 'detailed';
  $('local-scan-log-content').textContent = data.devices.map(device => `${device.ip} (${device.discovery})\n${device.logs.length ? device.logs.join('\n') : 'No responsive ports recorded.'}`).join('\n\n');
}
async function scan() {
  if (!$('local-scan-authorized').checked) return showStatus('Confirm you have permission to scan this network.', true);
  if (!$('local-network-select').value) return showStatus('Select a connected private network.', true);
  if ($('local-port-profile').value === 'all' && !$('local-target-ip').value.trim()) return showStatus('Enter one device IP from the connected subnet for an all-ports scan.', true);
  const button = $('local-scan-button');
  button.disabled = true;
  $('local-scan-cancel').hidden = false;
  scanController = new AbortController();
  showStatus('Starting connected-network scan…');
  $('local-scan-results').hidden = true;
  $('local-scan-summary').hidden = true;
  $('local-scan-log').hidden = true;
  $('local-scan-export').hidden = true;
  $('local-scan-progress').hidden = false;
  $('local-scan-progress').value = 0;
  try {
    const response = await fetch('/api/local-network/scan', {
      method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/x-ndjson' }, signal: scanController.signal,
      body: JSON.stringify({ networkId: $('local-network-select').value, authorized: true, scan: {
        profile: $('local-port-profile').value, protocols: $('local-protocol').value === 'both' ? ['tcp', 'udp'] : [$('local-protocol').value],
        ports: $('local-ports').value, targetIp: $('local-target-ip').value.trim(), verbosity: $('local-verbosity').value,
        identifyServices: $('local-identify-services').checked
      } })
    });
    if (!response.ok) { const data = await response.json(); throw new Error(data.error || 'Scan failed.'); }
    const reader = response.body.getReader(), decoder = new TextDecoder();
    let pending = '', completed = false;
    const handle = line => {
      if (!line.trim()) return;
      const event = JSON.parse(line);
      if (event.type === 'error') throw new Error(event.message || 'Scan failed.');
      if (event.type === 'progress') {
        const percent = event.stage === 'discovery' ? Math.round(10 * event.completed / Math.max(1, event.total)) : 10 + Math.round(90 * event.completed / Math.max(1, event.total));
        $('local-scan-progress').value = Math.max($('local-scan-progress').value, Math.min(99, percent));
        showStatus(event.message);
      }
      if (event.type === 'result') { renderScan(event.data); completed = true; }
    };
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      pending += decoder.decode(value, { stream: true });
      const lines = pending.split('\n');
      pending = lines.pop();
      for (const line of lines) handle(line);
    }
    if (pending.trim()) handle(pending);
    if (!completed) throw new Error('The scan ended before results were returned.');
    $('local-scan-progress').value = 100;
    showStatus('Local scan complete. Review service clues and uncertain UDP results below.');
  } catch (error) { showStatus(error.name === 'AbortError' ? 'Scan cancelled.' : error.message, error.name !== 'AbortError'); }
  finally { button.disabled = false; $('local-scan-cancel').hidden = true; scanController = undefined; $('local-scan-progress').hidden = true; }
}

$('self-refresh').addEventListener('click', loadPublicConnection);
$('local-scan-button').addEventListener('click', scan);
$('local-scan-cancel').addEventListener('click', () => scanController?.abort());
function escapeHtml(value) { return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])); }
function csv(rows) { return rows.map(row => row.map(value => { const raw = String(value ?? ''); const safe = /^[\s]*[=+\-@]/.test(raw) ? `'${raw}` : raw; return `"${safe.replaceAll('"', '""')}"`; }).join(',')).join('\r\n') + '\r\n'; }
$('local-scan-export').addEventListener('click', async () => {
  if (!lastScanResult || !window.JSZip) return showStatus('ZIP export is unavailable in this browser.', true);
  const data = lastScanResult;
  const rows = data.devices.flatMap(device => device.findings.map(item => [device.ip, device.mac, item.protocol, item.port, item.state, item.service, item.product, item.version, item.evidence, item.latencyMs]));
  const headers = ['device_ip', 'mac', 'protocol', 'port', 'state', 'service_guess', 'product_clue', 'version_clue', 'evidence', 'latency_ms'];
  const table = `<table><thead><tr>${headers.map(value => `<th>${escapeHtml(value)}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(value => `<td>${escapeHtml(value)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>IP Insight local scan</title><style>body{font:14px/1.5 Arial,sans-serif;max-width:1100px;margin:40px auto;color:#203042}header{background:#12313a;color:#fff;padding:25px;border-radius:8px}main{padding:22px}h1{margin:0}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #bdcbd0;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#e6f1ef}.note{background:#fff3d8;padding:12px}@media print{body{margin:0}tr{break-inside:avoid}}</style></head><body><header><h1>IP Insight connected-network scan</h1><p>${escapeHtml(data.network.cidr)} · ${escapeHtml(data.scannedAt)}</p></header><main><p>${escapeHtml(data.devices.length)} devices · ${escapeHtml(data.portCountPerDevice)} selected ports per device · ${escapeHtml(data.protocols.join(' + ').toUpperCase())} · ${escapeHtml(data.portSelection)} profile</p><p class="note">${escapeHtml(data.note)} Closed and unanswered ports are summarized in scan.json. This report is evidence from the scan time, not a vulnerability finding.</p>${table}</main></body></html>`;
  const zip = new JSZip();
  zip.file('report.html', html);
  zip.file('scan.json', JSON.stringify(data, null, 2));
  zip.file('ports.csv', csv([headers, ...rows]));
  zip.file('README.txt', 'IP Insight connected-network scan. Open report.html for a formatted report and print it to PDF. scan.json contains counts, device metadata, and all recorded findings. ports.csv contains responsive or uncertain port rows. Service versions are clues from self-reported banners or headers and require validation.\n');
  const blob = await zip.generateAsync({ type: 'blob' });
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = `ip-insight-local-scan-${new Date(data.scannedAt).toISOString().slice(0, 10)}.zip`;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
});
for (const id of ['local-port-profile', 'local-protocol']) $(id).addEventListener('change', updateScanPlan);
updateScanPlan();
loadPublicConnection();
if (window.IP_INSIGHT_STATIC) {
  $('local-scan-controls').hidden = true;
  showStatus('Open the localhost edition on a computer connected to the network to run a local scan. GitHub Pages cannot access local devices.');
} else loadNetworks();
