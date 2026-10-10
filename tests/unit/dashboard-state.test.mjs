import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const createDashboardState = require('../../src/modules/dashboard-state.js');
const stateSource = readFileSync('src/modules/dashboard-state.js', 'utf8');

describe('DashboardState', () => {
  it('stays focused on state and filtering, not dashboard rendering', () => {
    assert.doesNotMatch(stateSource, /document\./);
    assert.doesNotMatch(stateSource, /_rlCtx/);
    assert.doesNotMatch(stateSource, /_showToast/);
    assert.doesNotMatch(stateSource, /openUnifiedDash/);
    assert.doesNotMatch(stateSource, /_render[A-Z]/);
  });

  it('tracks current tab and account filter explicitly', () => {
    const state = createDashboardState();

    assert.equal(state.getTab(), null);
    assert.equal(state.getAccountFilter(), 'all');

    assert.equal(state.setTab('inventory'), 'inventory');
    assert.equal(state.getTab(), 'inventory');
    assert.equal(state.setTab(null), null);

    assert.equal(state.setAccountFilter('sub-1'), 'sub-1');
    assert.equal(state.getAccountFilter(), 'sub-1');
    assert.equal(state.setAccountFilter(''), 'all');
  });

  it('owns BUDR dashboard state reset without sharing state objects', () => {
    const state = createDashboardState();
    const current = state.getBudrDashState();
    current.search = 'database';
    current.sort = 'name';

    const reset = state.resetBudrDashState();

    assert.deepEqual(reset, { tierFilter: 'all', search: '', sort: 'tier' });
    assert.notEqual(reset, current);
  });

  it('filters dashboard rows by subscription id, account id, or resolved label', () => {
    const state = createDashboardState();
    state.setAccountFilter('sub-1');
    const rows = [
      { name: 'vnet-a', _subscriptionId: 'sub-1' },
      { name: 'vnet-b', _accountId: 'sub-1' },
      { name: 'vnet-c', account: 'Subscription One' },
      { name: 'vnet-d', account: 'sub-2' }
    ];

    const filtered = state.filterByAccount(rows, id => id === 'sub-1' ? 'Subscription One' : '');

    assert.deepEqual(filtered.map(row => row.name), ['vnet-a', 'vnet-b', 'vnet-c']);
  });

  it('publishes live-state changes through the provided change hook', () => {
    const snapshots = [];
    const state = createDashboardState({
      onChange: snapshot => snapshots.push(snapshot)
    });

    state.setTab('reports');
    state.setAccountFilter('sub-2');
    state.resetBudrDashState();

    assert.deepEqual(snapshots.map(snapshot => snapshot.tab), ['reports', 'reports', 'reports']);
    assert.deepEqual(snapshots.at(-1), {
      tab: 'reports',
      accountFilter: 'sub-2',
      budrDashState: { tierFilter: 'all', search: '', sort: 'tier' }
    });
  });
});
