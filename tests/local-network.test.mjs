import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { connectedNetworks, hostsInCidr, parsePorts, scanConnectedNetwork } from '../src/local-network.mjs';
import { selectPortTasks, scanHostPorts, fingerprintTcp } from '../src/port-scanner.mjs';

test('only connected private IPv4 interfaces are offered, with large networks bounded to /24', () => {
  const networks = connectedNetworks({
    WiFi: [{ family: 'IPv4', internal: false, address: '192.168.5.10', netmask: '255.255.0.0', mac: 'AA:BB:CC:DD:EE:FF' }],
    Public: [{ family: 'IPv4', internal: false, address: '8.8.8.8', netmask: '255.255.255.0' }],
    Loopback: [{ family: 'IPv4', internal: true, address: '127.0.0.1', netmask: '255.0.0.0' }]
  });
  assert.equal(networks.length, 1);
  assert.equal(networks[0].cidr, '192.168.5.0/24');
  assert.equal(networks[0].hostCount, 254);
  assert.equal(networks[0].limitedTo24, true);
});

test('network targets are bounded and ports are validated', () => {
  assert.deepEqual(hostsInCidr('10.0.0.0/30'), ['10.0.0.1', '10.0.0.2']);
  assert.throws(() => hostsInCidr('8.8.8.0/24'));
  assert.deepEqual(parsePorts('80, 443,80'), [80, 443]);
  assert.deepEqual(parsePorts('80-82,443'), [80, 81, 82, 443]);
  assert.throws(() => parsePorts('80-400'));
  assert.throws(() => parsePorts('0,65536'));
});

test('port profiles cover common, mentioned, and all ports for selected protocols', () => {
  assert.equal(selectPortTasks('common', ['tcp', 'udp']).length, 38);
  assert.deepEqual(selectPortTasks('custom', ['udp'], [53, 123]), [{ protocol: 'udp', port: 53 }, { protocol: 'udp', port: 123 }]);
  const all = selectPortTasks('all', ['tcp'], null);
  assert.equal(all.length, 65535);
  assert.deepEqual(all[0], { protocol: 'tcp', port: 1 });
  assert.deepEqual(all.at(-1), { protocol: 'tcp', port: 65535 });
});

test('UDP silence remains uncertain and TCP version clues retain their evidence', async () => {
  const result = await scanHostPorts('10.0.0.2', [{ protocol: 'tcp', port: 53 }, { protocol: 'udp', port: 53 }], {
    portCheck: async () => ({ state: 'open', latencyMs: 2 }),
    udpCheck: async () => ({ state: 'open|filtered', latencyMs: 50 }),
    fingerprint: async () => ({ service: 'DNS', product: 'ExampleDNS', version: '1.2', evidence: 'Banner: ExampleDNS/1.2' }),
    identifyServices: true, verbosity: 'detailed'
  });
  assert.equal(result.counts.tcpOpen, 1);
  assert.equal(result.counts.udpUncertain, 1);
  assert.equal(result.findings[0].product, 'ExampleDNS');
  assert.equal(result.findings[1].state, 'open|filtered');
  assert.match(result.findings[1].evidence, /No UDP response/);
});

test('a self-reported SSH banner is labeled as a clue with product and version', async () => {
  const server = createServer(socket => socket.end('SSH-2.0-OpenSSH_9.3\r\n'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await fingerprintTcp('127.0.0.1', server.address().port);
    assert.equal(result.product, 'OpenSSH');
    assert.equal(result.version, '9.3');
    assert.match(result.evidence, /Banner: SSH-2.0-OpenSSH_9.3/);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('scan rejects an arbitrary network and reports only observed connected devices', async () => {
  const network = connectedNetworks({ WiFi: [{ family: 'IPv4', internal: false, address: '10.0.0.1', netmask: '255.255.255.252', mac: 'AA:BB:CC:DD:EE:FF' }] })[0];
  const options = { networks: [network], ping: async ip => ip === '10.0.0.2', portCheck: async (_ip, port) => port === 443, macs: async () => new Map([['10.0.0.2', '11:22:33:44:55:66']]) };
  await assert.rejects(scanConnectedNetwork('other-network', '443', options));
  const result = await scanConnectedNetwork(network.id, '80,443', options);
  assert.equal(result.scannedHosts, 2);
  assert.deepEqual(result.devices.map(x => x.ip), ['10.0.0.1', '10.0.0.2']);
  assert.deepEqual(result.devices[1].ports, [443]);
  assert.equal(result.devices[0].mac, 'aa:bb:cc:dd:ee:ff');
  assert.equal(result.devices[1].mac, '11:22:33:44:55:66');
});

test('an all-ports scan requires one device inside the connected subnet', async () => {
  const network = connectedNetworks({ WiFi: [{ family: 'IPv4', internal: false, address: '10.0.0.1', netmask: '255.255.255.252' }] })[0];
  const deps = { networks: [network], ping: async () => true, macs: async () => new Map() };
  await assert.rejects(scanConnectedNetwork(network.id, { profile: 'all', protocols: ['tcp'] }, deps), /one device IP/);
  await assert.rejects(scanConnectedNetwork(network.id, { profile: 'all', protocols: ['tcp'], targetIp: '10.0.1.2' }, deps), /connected private subnet/);
});

test('an interrupted full-port scan stops before scheduling every port', async () => {
  const controller = new AbortController();
  let checked = 0;
  const tasks = Array.from({ length: 2000 }, (_, index) => ({ protocol: 'tcp', port: index + 1 }));
  await assert.rejects(scanHostPorts('10.0.0.2', tasks, { signal: controller.signal, allPorts: true, identifyServices: false, portCheck: async () => {
    checked++;
    if (checked === 30) controller.abort();
    return false;
  } }), /Scan cancelled/);
  assert.ok(checked < tasks.length);
});
