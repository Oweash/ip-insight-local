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
async function scan() {
  if (!$('local-scan-authorized').checked) return showStatus('Confirm you have permission to scan this network.', true);
  if (!$('local-network-select').value) return showStatus('Select a connected private network.', true);
  const button = $('local-scan-button');
  button.disabled = true;
  showStatus('Discovering local devices and checking the selected TCP ports…');
  $('local-scan-results').hidden = true;
  $('local-scan-summary').hidden = true;
  try {
    const response = await fetch('/api/local-network/scan', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ networkId: $('local-network-select').value, ports: $('local-ports').value, authorized: true })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Scan failed.');
    const body = $('local-scan-body');
    body.replaceChildren();
    for (const device of data.devices) {
      const row = document.createElement('tr');
      const cells = [device.ip + (device.isThisDevice ? ' · this computer' : ''), device.mac || 'Not available', device.ports.length ? device.ports.join(', ') : 'None of the selected ports responded'];
      for (const value of cells) { const td = document.createElement('td'); td.textContent = value; row.append(td); }
      body.append(row);
    }
    $('local-scan-summary').textContent = `${data.network.cidr} · ${data.scannedHosts} addresses checked · ${data.devices.length} devices observed · ${data.portsChecked.length} TCP ports selected. ${data.note}`;
    $('local-scan-summary').hidden = false;
    $('local-scan-results').hidden = !data.devices.length;
    showStatus(data.devices.length ? 'Local scan complete.' : 'Scan complete. No devices responded to discovery probes.');
  } catch (error) { showStatus(error.message, true); }
  finally { button.disabled = false; }
}

$('self-refresh').addEventListener('click', loadPublicConnection);
$('local-scan-button').addEventListener('click', scan);
loadPublicConnection();
if (window.IP_INSIGHT_STATIC) {
  $('local-scan-controls').hidden = true;
  showStatus('Open the localhost edition on a computer connected to the network to run a local scan. GitHub Pages cannot access local devices.');
} else loadNetworks();
