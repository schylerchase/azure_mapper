import assert from 'node:assert/strict';
import { it } from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';

function folderFixture(usePicker) {
  const button = { style: {}, listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; } };
  let input, imported;
  const file = (name, text) => ({ name, kind: 'file', getFile: async () => ({ text: async () => text }) });
  const dir = (name, children) => ({ name, kind: 'directory', entries: async function* () { yield* children.map(child => [child.name, child]); } });
  const tree = dir('azure-export-multi', [dir('sub-a', ['eastus', 'westus'].map(location => dir(location, [file('vnets.json', JSON.stringify([{ name: location, location }]))]))) ]);
  const context = { console, _isElectron: false,
    document: { getElementById: () => button, createElement() { input = { listeners: {}, setAttribute() {}, addEventListener(name, fn) { this.listeners[name] = fn; }, click() {}, remove() {} }; return input; } },
    AppProjectFiles: { hasDirectoryPicker: () => usePicker, chooseDirectory: async () => tree } };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync('src/modules/folder-import.js', 'utf8'), context);
  context.importFolder = result => { imported = result; };
  return { button, input: () => input, imported: () => imported };
}

for (const usePicker of [true, false]) {
  it(`T05 ${usePicker ? 'directory picker' : 'file-input fallback'} preserves each Azure location under a subscription`, async () => {
    const fixture = folderFixture(usePicker);
    await fixture.button.listeners.click();
    if (!usePicker) {
      const input = fixture.input();
      input.files = ['eastus', 'westus'].map(location => ({ name: 'vnets.json', webkitRelativePath: `azure-export-multi/sub-a/${location}/vnets.json`, text: async () => JSON.stringify([{ name: location, location }]) }));
      input.listeners.change();
      await new Promise(setImmediate);
    }
    const result = fixture.imported();
    assert.equal(result._structure, 'multi-profile');
    assert.deepEqual(Object.keys(result.profiles['sub-a'].regions), ['eastus', 'westus']);
    for (const location of ['eastus', 'westus']) assert.equal(JSON.parse(result.profiles['sub-a'].regions[location]['vnets.json'])[0].location, location);
    assert.equal(Object.keys(result.profiles['sub-a'].files).length, 0);
  });
}
