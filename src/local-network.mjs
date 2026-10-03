import os from 'node:os';
import net from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { selectPortTasks, scanHostPorts } from './port-scanner.mjs';

const execFileAsync = promisify(execFile);
const MAX_HOSTS = 254;

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
  if (typeof value !== 'string' || !/^\s*\d{1,5}(?:\s*-\s*\d{1,5})?(?:\s*,\s*\d{1,5}(?:\s*-\s*\d{1,5})?)*\s*$/.test(value)) throw new Error('Enter ports as numbers or ranges, separated by commas.');
  const ports = new Set();
  for (const part of value.split(',')) {
    const [first, last = first] = part.split('-').map(Number);
    if (first < 1 || last > 65535 || last < first || last - first > 127) throw new Error('Choose valid ports between 1 and 65535.');
    for (let port = first; port <= last; port++) ports.add(port);
    if (ports.size > 128) throw new Error('Mention up to 128 ports in one scan.');
  }
  return [...ports].sort((a, b) => a - b);
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
async function runLimited(items, limit, operation, signal) {
  let cursor = 0;
  const results = new Array(items.length);
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length && !signal?.aborted) {
      const index = cursor++;
      results[index] = await operation(items[index]);
    }
  }));
  if (signal?.aborted) throw new Error('Scan cancelled.');
  return results;
}
async function pingHost(ip) {
  const args = process.platform === 'win32' ? ['-n', '1', '-w', '500', ip] : ['-c', '1', '-W', '1', ip];
  try { await execFileAsync('ping', args, { timeout: 2200, windowsHide: true, maxBuffer: 8192 }); return true; }
  catch { return false; }
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
export async function scanConnectedNetwork(id, rawOptions, { networks = connectedNetworks(), ping = pingHost, portCheck, udpCheck, fingerprint, macs = neighborMacs, onProgress = () => {}, signal } = {}) {
  const selected = networks.find(network => network.id === id);
  if (!selected) throw new Error('Select a currently connected private network.');
  const options = typeof rawOptions === 'string' ? { profile: 'custom', protocols: ['tcp'], ports: rawOptions, identifyServices: false } : rawOptions || {};
  const profile = options.profile || 'common';
  const protocols = options.protocols || ['tcp'];
  const verbosity = options.verbosity === 'detailed' ? 'detailed' : 'summary';
  const identifyServices = options.identifyServices === true;
  const customPorts = profile === 'custom' ? parsePorts(options.ports) : null;
  const tasks = selectPortTasks(profile, protocols, customPorts);
  const subnetHosts = hostsInCidr(selected.cidr);
  const targetIp = String(options.targetIp || '').trim();
  if (targetIp && !subnetHosts.includes(targetIp)) throw new Error('The device IP must be within the selected connected private subnet.');
  if (profile === 'all' && !targetIp) throw new Error('Enter one device IP in the connected subnet for an all-ports scan.');
  const candidates = targetIp ? [targetIp] : subnetHosts;
  onProgress({ stage: 'discovery', completed: 0, total: candidates.length, message: targetIp ? `Checking selected device ${targetIp}` : `Discovering up to ${candidates.length} local addresses` });
  let discovered = 0;
  const alive = await runLimited(candidates, 16, async ip => {
    const present = ip === selected.address || await ping(ip);
    discovered++;
    if (discovered % 32 === 0 || discovered === candidates.length) onProgress({ stage: 'discovery', completed: discovered, total: candidates.length, message: `${discovered} of ${candidates.length} addresses checked` });
    return present;
  }, signal);
  const neighbors = await macs();
  const targets = targetIp ? [targetIp] : candidates.filter((ip, index) => alive[index] || neighbors.has(ip));
  onProgress({ stage: 'ports', completed: 0, total: tasks.length * targets.length, message: `${targets.length} device(s) observed; checking ${tasks.length.toLocaleString()} ports per device` });
  const completedByDevice = new Map(targets.map(ip => [ip, 0]));
  const devices = await runLimited(targets, profile === 'all' ? 1 : 3, async ip => {
    const result = await scanHostPorts(ip, tasks, { signal, portCheck, udpCheck, fingerprint, identifyServices, verbosity, allPorts: profile === 'all', onProgress: event => {
      completedByDevice.set(ip, event.completed);
      onProgress({ ...event, completed: [...completedByDevice.values()].reduce((sum, value) => sum + value, 0), total: tasks.length * targets.length });
    } });
    completedByDevice.set(ip, tasks.length);
    const done = [...completedByDevice.values()].reduce((sum, value) => sum + value, 0);
    onProgress({ stage: 'ports', ip, completed: done, total: tasks.length * targets.length, message: `${done.toLocaleString()} of ${(tasks.length * targets.length).toLocaleString()} port checks finished` });
    return { ip, mac: ip === selected.address ? selected.mac || null : neighbors.get(ip) || null, ports: result.findings.filter(item => item.protocol === 'tcp' && item.state === 'open').map(item => item.port), ...result, isThisDevice: ip === selected.address, discovery: alive[candidates.indexOf(ip)] ? 'Responded' : 'No ping response; selected or in neighbor table' };
  }, signal);
  return { scannedAt: new Date().toISOString(), network: selected, scannedHosts: candidates.length, portCountPerDevice: tasks.length, portSelection: profile, protocols, verbosity, identifyServices,
    devices: devices.sort((a, b) => toNumber(a.ip) - toNumber(b.ip)),
    note: 'Device discovery can miss hosts that ignore probes. A UDP nonresponse is open or filtered, not confirmed open. Service and version clues come from port conventions or self-reported banners/headers.' };
}
