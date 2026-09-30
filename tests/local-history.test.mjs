import test from 'node:test';
import assert from 'node:assert/strict';
import { LocalHistoryManager } from '../src/local-history.mjs';

function storage() {
  const data = new Map();
  return {
    getItem: key => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, value),
    raw: data
  };
}

const investigation = (domain = 'example.com') => ({
  input: { domain }, selectedIp: '93.184.215.14',
  completedAt: '2026-09-30T00:00:00Z',
  ipLocations: [], evidence: [], historyId: 'cloud-123'
});

test('a saved investigation and its notes survive a new manager instance', () => {
  const box = storage();
  const first = new LocalHistoryManager(box);
  const saved = first.save(investigation());
  assert.equal(saved.status, 'saved');
  assert.equal(first.setNotes(saved.id, 'Provider locations conflict.'), true);
  const reopened = new LocalHistoryManager(box).get(saved.id);
  assert.equal(reopened.target, 'example.com');
  assert.equal(reopened.notes, 'Provider locations conflict.');
  assert.equal(reopened.result.historyId, undefined);
  assert.equal(first.updateResult(saved.id, { ...investigation(), subdomains: { items: [{ name: 'api.example.com' }] } }), true);
  assert.equal(new LocalHistoryManager(box).get(saved.id).result.subdomains.items[0].name, 'api.example.com');
});

test('history keeps the newest 30 investigations', () => {
  const history = new LocalHistoryManager(storage());
  for (let n = 0; n < 35; n++) assert.equal(history.save(investigation(`site-${n}.example`)).status, 'saved');
  assert.equal(history.list().length, 30);
  assert.equal(history.list()[0].target, 'site-34.example');
  assert.equal(history.list().at(-1).target, 'site-5.example');
});

test('corrupt and unavailable browser storage do not break investigations', () => {
  const box = storage();
  box.setItem('ip-insight-history-v2', '{bad json');
  const history = new LocalHistoryManager(box);
  assert.deepEqual(history.list(), []);
  assert.equal(history.save(investigation()).status, 'saved');
  assert.equal(new LocalHistoryManager(null).save(investigation()).status, 'error');
});

test('oversized old records are evicted before new snapshots', () => {
  const history = new LocalHistoryManager(storage());
  const large = { ...investigation('large.example'), evidence: [{ detail: 'x'.repeat(1_000_000) }] };
  assert.equal(history.save(large).status, 'saved');
  assert.equal(history.save(investigation('new.example')).status, 'saved');
  assert.equal(history.list()[0].target, 'new.example');
});
