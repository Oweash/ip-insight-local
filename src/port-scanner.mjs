import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';

export const COMMON_TCP = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587, 631, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017];
export const COMMON_UDP = [53, 69, 123, 137, 161, 500, 1900, 5353];
const SERVICES = new Map([[21,'FTP'],[22,'SSH'],[23,'Telnet'],[25,'SMTP'],[53,'DNS'],[69,'TFTP'],[80,'HTTP'],[110,'POP3'],[123,'NTP'],[137,'NetBIOS'],[139,'NetBIOS'],[143,'IMAP'],[161,'SNMP'],[443,'HTTPS'],[445,'SMB'],[500,'IKE'],[587,'SMTP submission'],[631,'IPP'],[993,'IMAPS'],[995,'POP3S'],[1433,'SQL Server'],[1521,'Oracle DB'],[1900,'SSDP'],[3306,'MySQL'],[3389,'RDP'],[5353,'mDNS'],[5432,'PostgreSQL'],[5900,'VNC'],[6379,'Redis'],[8000,'HTTP alternate'],[8080,'HTTP alternate'],[8443,'HTTPS alternate'],[8888,'HTTP alternate'],[9200,'Elasticsearch'],[27017,'MongoDB']]);
const HTTP_PORTS = new Set([80, 8000, 8080, 8888, 9200]);
const HTTPS_PORTS = new Set([443, 8443]);
const clean = value => String(value || '').replace(/[^\x20-\x7e]/g, ' ').trim().slice(0, 160);
export const serviceGuess = port => SERVICES.get(port) || 'Unknown service';

export function selectPortTasks(profile, protocols, customPorts) {
  if (!['common', 'custom', 'all'].includes(profile)) throw new Error('Choose common, mentioned, or all ports.');
  if (!Array.isArray(protocols) || !protocols.length || protocols.some(p => p !== 'tcp' && p !== 'udp') || new Set(protocols).size !== protocols.length) throw new Error('Choose TCP, UDP, or both.');
  const selected = profile === 'all' ? Array.from({ length: 65535 }, (_, index) => index + 1) : profile === 'common' ? null : customPorts;
  if (profile === 'custom' && (!Array.isArray(selected) || !selected.length || selected.length > 128)) throw new Error('Choose 1 to 128 mentioned ports.');
  return protocols.flatMap(protocol => (selected || (protocol === 'tcp' ? COMMON_TCP : COMMON_UDP)).map(port => ({ protocol, port })));
}

export function checkTcpPort(ip, port, timeoutMs = 500) {
  return new Promise(resolve => {
    const started = Date.now();
    const socket = net.createConnection({ host: ip, port });
    let finished = false;
    const finish = state => { if (finished) return; finished = true; socket.destroy(); resolve({ state, latencyMs: Date.now() - started }); };
    socket.setTimeout(timeoutMs, () => finish('filtered'));
    socket.once('connect', () => finish('open'));
    socket.once('error', error => finish(error.code === 'ECONNREFUSED' ? 'closed' : 'filtered'));
  });
}

function udpPayload(port) {
  if (port === 53) return Buffer.from('1234010000010000000000000000020001', 'hex'); // Root NS query.
  if (port === 123) { const data = Buffer.alloc(48); data[0] = 0x1b; return data; }
  return Buffer.from([0]);
}
export function checkUdpPort(ip, port, timeoutMs = 700) {
  return new Promise(resolve => {
    const started = Date.now();
    const socket = dgram.createSocket('udp4');
    let finished = false;
    const finish = (state, evidence = null) => { if (finished) return; finished = true; clearTimeout(timer); socket.close(); resolve({ state, latencyMs: Date.now() - started, evidence }); };
    const timer = setTimeout(() => finish('open|filtered'), timeoutMs);
    socket.once('message', message => finish('open', `UDP response (${message.length} bytes)`));
    socket.once('error', error => finish(error.code === 'ECONNREFUSED' ? 'closed' : 'filtered', clean(error.code)));
    try { socket.connect(port, ip, () => socket.send(udpPayload(port), error => { if (error) finish('filtered', clean(error.code)); })); }
    catch (error) { finish('filtered', clean(error.code)); }
  });
}

function readBanner(ip, port, httpMode) {
  return new Promise(resolve => {
    const secure = HTTPS_PORTS.has(port);
    const socket = secure ? tls.connect({ host: ip, port, rejectUnauthorized: false }) : net.createConnection({ host: ip, port });
    let finished = false, buffer = '', tlsInfo = '';
    const finish = () => { if (finished) return; finished = true; socket.destroy(); resolve({ text: buffer.slice(0, 2048), tlsInfo }); };
    socket.setTimeout(1200, finish);
    socket.once('error', finish);
    socket.once(secure ? 'secureConnect' : 'connect', () => {
      if (secure) {
        const certificate = socket.getPeerCertificate();
        tlsInfo = `TLS ${socket.getProtocol() || 'unknown'}${certificate?.subject?.CN ? ` · Certificate CN: ${clean(certificate.subject.CN)}` : ''}`;
      }
      if (httpMode) socket.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\nConnection: close\r\n\r\n`);
    });
    socket.on('data', chunk => {
      buffer += chunk.toString('latin1');
      if (buffer.length > 2048 || buffer.includes('\r\n\r\n') || (!httpMode && buffer.includes('\n'))) finish();
    });
    socket.once('end', finish);
  });
}
export async function fingerprintTcp(ip, port) {
  const service = serviceGuess(port);
  if (port === 9100) return { service, product: null, version: null, evidence: 'Probe skipped for printer safety; port name is a guess.' };
  const httpMode = HTTP_PORTS.has(port) || HTTPS_PORTS.has(port);
  const response = await readBanner(ip, port, httpMode);
  if (!response.text && !response.tlsInfo) return { service, product: null, version: null, evidence: 'No readable banner or HTTP header returned.' };
  const server = response.text.match(/(?:^|\n)Server:\s*([^\r\n]+)/i)?.[1];
  const poweredBy = response.text.match(/(?:^|\n)X-Powered-By:\s*([^\r\n]+)/i)?.[1];
  const banner = server || poweredBy || response.text.split(/\r?\n/)[0];
  const candidate = httpMode && !server && !poweredBy ? '' : clean(banner).replace(/^SSH-\d+\.\d+-/, '');
  const productVersion = candidate.match(/([A-Za-z][\w.-]*)[\/_ ]v?(\d+(?:\.\d+){0,3})/);
  return { service, product: productVersion?.[1] || null, version: productVersion?.[2] || null,
    evidence: clean([server ? `Server: ${server}` : poweredBy ? `X-Powered-By: ${poweredBy}` : banner ? `Banner: ${banner}` : null, response.tlsInfo].filter(Boolean).join(' · ')) };
}

export async function scanHostPorts(ip, tasks, { signal, onProgress = () => {}, portCheck = checkTcpPort, udpCheck = checkUdpPort, fingerprint = fingerprintTcp, identifyServices = true, verbosity = 'summary', allPorts = false } = {}) {
  let cursor = 0, finished = 0;
  const counts = { tcpOpen: 0, tcpClosed: 0, tcpFiltered: 0, udpOpen: 0, udpClosed: 0, udpUncertain: 0 };
  const findings = [];
  const logs = [];
  const concurrency = allPorts ? 48 : 12;
  const workers = Array.from({ length: Math.min(concurrency, tasks.length) }, async () => {
    while (cursor < tasks.length && !signal?.aborted) {
      const task = tasks[cursor++];
      let result = task.protocol === 'tcp' ? await portCheck(ip, task.port) : await udpCheck(ip, task.port);
      if (typeof result === 'boolean') result = { state: result ? 'open' : 'closed', latencyMs: null };
      const state = result?.state || 'filtered';
      if (task.protocol === 'tcp') counts[state === 'open' ? 'tcpOpen' : state === 'closed' ? 'tcpClosed' : 'tcpFiltered']++;
      else counts[state === 'open' ? 'udpOpen' : state === 'closed' ? 'udpClosed' : 'udpUncertain']++;
      if (state === 'open' || (task.protocol === 'udp' && state === 'open|filtered' && !allPorts)) {
        const identity = task.protocol === 'tcp' && state === 'open' && identifyServices ? await fingerprint(ip, task.port) : { service: serviceGuess(task.port), product: null, version: null, evidence: result?.evidence || (state === 'open|filtered' ? 'No UDP response; open or filtered.' : 'Service name inferred from port number only.') };
        findings.push({ protocol: task.protocol, port: task.port, state, latencyMs: result?.latencyMs ?? null, ...identity });
        if (verbosity === 'detailed' && logs.length < 500) logs.push(`${task.port}/${task.protocol} ${state} · ${identity.evidence}`);
      }
      finished++;
      if (finished % 256 === 0 || finished === tasks.length) onProgress({ stage: 'ports', ip, completed: finished, total: tasks.length, message: `${ip}: ${finished.toLocaleString()} of ${tasks.length.toLocaleString()} port checks` });
    }
  });
  await Promise.all(workers);
  if (signal?.aborted) throw new Error('Scan cancelled.');
  findings.sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));
  return { findings, counts, logs };
}
