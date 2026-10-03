import os from 'node:os';
import net from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const MAX_HOSTS = 254;
const DEFAULT_PORTS = [21, 22, 53, 80, 139, 443, 445, 3389, 8080, 8443];

function toNumber(ip) {
  return ip.split('.').reduce((value, octet) => ((value << 8) | Number(octet)) >>> 0, 0);
}
function toIp(value) {
  return [24, 16, 8, 0].map(shift => (value >>> shift) & 255).join('.');
}
function privateIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const n = toNumber(ip);
  return (n >>> 24) === 10 || (n >>> 20) === 0xac1 || (n >>> 16) === 0xc0a8;
}
function maskPrefix(mask) {
  const bits = toNumber(mask).toString(2).padStart(32, '0');
  if (!/^1*0*$/.test(bits)) return null;
  return bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
}
export function connectedNetworks(interfaces = os.networkInterfaces()) {
  const found = [];
  for (const [name, addresses] of Object.entries(interfaces)) {
    for (const item of addresses || []) {
      if (item.family !== 'IPv4' || item.internal || !privateIPv4(item.address)) continue;
      const prefix = maskPrefix(item.netmask);
      if (prefix == null) continue;
      const effectivePrefix = Math.max(prefix, 24);
      const mask = effectivePrefix === 0 ? 0 : (0xffffffff << (32 - effectivePrefix)) >>> 0;
      const network = toIp(toNumber(item.address) & mask);
      const cidr = `${network}/${effectivePrefix}`;
      found.push({ id: `${name}|${item.address}|${cidr}`, name, address: item.address, cidr, mac: item.mac && item.mac !== '00:00:00:00:00:00' ? item.mac.toLowerCase() : null,
        hostCount: effectivePrefix === 32 ? 1 : effectivePrefix === 31 ? 2 : Math.min(MAX_HOSTS, (2 ** (32 - effectivePrefix)) - 2),
        limitedTo24: prefix < 24 });
    }
  }
  return found;
}
export function parsePorts(value) {
  if (value == null || String(value).trim() === '') return DEFAULT_PORTS;
  if (typeof value !== 'string' || !/^\s*\d{1,5}(\s*,\s*\d{1,5})*\s*$/.test(value)) throw new Error('Enter ports as comma-separated numbers.');
  const ports = [...new Set(value.split(',').map(Number))];
  if (ports.length > 20 || ports.some(port => port < 1 || port > 65535)) throw new Error('Choose up to 20 ports between 1 and 65535.');
  return ports;
}
export function hostsInCidr(cidr) {
  const [address, rawPrefix] = cidr.split('/');
  const prefix = Number(rawPrefix), network = toNumber(address);
  if (!Number.isInteger(prefix) || prefix < 24 || prefix > 32 || !privateIPv4(address)) throw new Error('Invalid connected private subnet.');
  const count = 2 ** (32 - prefix);
  const start = prefix >= 31 ? 0 : 1;
  const end = prefix >= 31 ? count : count - 1;
  return Array.from({ length: end - start }, (_, index) => toIp(network + start + index));
}
async function runLimited(items, limit, operation) {
  let cursor = 0;
  const results = new Array(items.length);
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await operation(items[index]);
    }
  }));
  return results;
}
async function pingHost(ip) {
  const args = process.platform === 'win32' ? ['-n', '1', '-w', '500', ip] : ['-c', '1', '-W', '1', ip];
  try { await execFileAsync('ping', args, { timeout: 2200, windowsHide: true, maxBuffer: 8192 }); return true; }
  catch { return false; }
}
function checkPort(ip, port) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host: ip, port, timeout: 450 });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
    socket.once('error', () => { socket.destroy(); resolve(false); });
  });
}
async function neighborMacs() {
  let output = '';
  try {
    const command = process.platform === 'win32' ? 'arp' : 'ip';
    const args = process.platform === 'win32' ? ['-a'] : ['neigh', 'show'];
    output = (await execFileAsync(command, args, { timeout: 3000, windowsHide: true, maxBuffer: 256000 })).stdout;
  } catch { return new Map(); }
  const found = new Map();
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(/(?:^|\s)(\d{1,3}(?:\.\d{1,3}){3})\s+.*?\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b/i);
    if (match && privateIPv4(match[1])) found.set(match[1], match[2].replaceAll('-', ':').toLowerCase());
  }
  return found;
}
export async function scanConnectedNetwork(id, rawPorts, { networks = connectedNetworks(), ping = pingHost, portCheck = checkPort, macs = neighborMacs } = {}) {
  const selected = networks.find(network => network.id === id);
  if (!selected) throw new Error('Select a currently connected private network.');
  const ports = parsePorts(rawPorts);
  const candidates = hostsInCidr(selected.cidr);
  const alive = await runLimited(candidates, 16, async ip => ip === selected.address || await ping(ip));
  const neighbors = await macs();
  const targets = candidates.filter((ip, index) => alive[index] || neighbors.has(ip));
  const devices = await runLimited(targets, 8, async ip => {
    const open = await runLimited(ports, 4, async port => await portCheck(ip, port) ? port : null);
    return { ip, mac: ip === selected.address ? selected.mac || null : neighbors.get(ip) || null, ports: open.filter(Boolean), isThisDevice: ip === selected.address };
  });
  return { scannedAt: new Date().toISOString(), network: selected, scannedHosts: candidates.length, portsChecked: ports,
    devices: devices.sort((a, b) => toNumber(a.ip) - toNumber(b.ip)),
    note: 'Devices that block discovery probes may be missing. MAC addresses come from this computer’s local neighbor table and may be unavailable.' };
}
