import test from 'node:test';
import assert from 'node:assert/strict';
import { connectedNetworks, hostsInCidr, parsePorts, scanConnectedNetwork } from '../src/local-network.mjs';

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
  assert.throws(() => parsePorts('80-90'));
  assert.throws(() => parsePorts('0,65536'));
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
