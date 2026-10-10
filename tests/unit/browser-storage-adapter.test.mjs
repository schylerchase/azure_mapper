import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const createBrowserStorageAdapter = require('../../src/modules/browser-storage-adapter.js');
const adapterSource = readFileSync('src/modules/browser-storage-adapter.js', 'utf8');

function memoryStorage() {
  const data = new Map();
  return {
    getItem: key => data.has(key) ? data.get(key) : null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: key => data.delete(key)
  };
}

describe('AppBrowserStorage', () => {
  it('stays focused on browser storage access only', () => {
    assert.doesNotMatch(adapterSource, /document\./);
    assert.doesNotMatch(adapterSource, /_rlCtx/);
    assert.doesNotMatch(adapterSource, /renderMap/);
    assert.doesNotMatch(adapterSource, /electronAPI/);
  });

  it('reads, writes, and removes local and session values through one adapter', () => {
    const localStorage = memoryStorage();
    const sessionStorage = memoryStorage();
    const storage = createBrowserStorageAdapter({ localStorage, sessionStorage });

    assert.equal(storage.set('notes', 'saved'), true);
    assert.equal(storage.get('notes'), 'saved');
    assert.equal(storage.set('draft', 'open', 'session'), true);
    assert.equal(storage.get('draft', 'session'), 'open');
    assert.equal(storage.remove('notes'), true);
    assert.equal(storage.get('notes'), null);
  });

  it('returns safe fallbacks when storage is unavailable or throws', () => {
    const throwingStorage = {
      getItem: () => { throw new Error('blocked'); },
      setItem: () => { throw new Error('quota'); },
      removeItem: () => { throw new Error('blocked'); }
    };
    const storage = createBrowserStorageAdapter({ localStorage: throwingStorage });

    assert.equal(storage.get('missing'), null);
    assert.equal(storage.set('key', 'value'), false);
    assert.equal(storage.remove('key'), false);
  });
});
