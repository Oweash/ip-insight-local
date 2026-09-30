const STORAGE_KEY = 'ip-insight-history-v2';
const MAX_ITEMS = 30;
const MAX_BYTES = 2_500_000;

export class LocalHistoryManager {
  constructor(storage) {
    try { this.storage = storage === undefined ? globalThis.localStorage : storage; }
    catch { this.storage = null; }
  }

  read() {
    try {
      const value = this.storage?.getItem(STORAGE_KEY);
      const records = value ? JSON.parse(value) : [];
      return Array.isArray(records) ? records.filter(record =>
        record && typeof record.id === 'string' && record.result?.input
      ) : [];
    } catch {
      return [];
    }
  }

  list() {
    return this.read().map(({ id, target, selected_ip, created_at }) =>
      ({ id, target, selected_ip, created_at }));
  }

  get(id) {
    return this.read().find(record => record.id === id) || null;
  }

  write(records) {
    if (!this.storage) return false;
    const retained = records.slice(0, MAX_ITEMS);
    while (retained.length) {
      try {
        const json = JSON.stringify(retained);
        if (json.length * 2 > MAX_BYTES) retained.pop();
        else { this.storage.setItem(STORAGE_KEY, json); return true; }
      } catch {
        retained.pop();
      }
    }
    return false;
  }

  save(result) {
    if (!result?.input) return { status: 'error' };
    const record = {
      id: 'local-' + globalThis.crypto.randomUUID(),
      target: result.input.domain || result.selectedIp || 'Unresolved target',
      selected_ip: result.selectedIp || null,
      created_at: result.completedAt || new Date().toISOString(),
      result: { ...result, historyId: undefined },
      notes: ''
    };
    const saved = this.write([record, ...this.read()]);
    return saved ? { status: 'saved', id: record.id } : { status: 'error' };
  }

  setNotes(id, notes) {
    const records = this.read();
    const record = records.find(item => item.id === id);
    if (!record) return false;
    record.notes = String(notes).slice(0, 10_000);
    return this.write(records);
  }

  updateResult(id, result) {
    const records = this.read();
    const record = records.find(item => item.id === id);
    if (!record || !result?.input) return false;
    record.result = { ...result, historyId: undefined, localHistoryId: undefined };
    return this.write(records);
  }
}
