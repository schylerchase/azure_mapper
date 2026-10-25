const { test, expect } = require('@playwright/test');

const locations = ['eastus', 'westus'];
function vnets(location) {
  return [{ id: `/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-${location}`, name: `vnet-${location}`, location, addressSpace: { addressPrefixes: [location === 'eastus' ? '10.0.0.0/16' : '10.1.0.0/16'] } }];
}

for (const picker of [true, false]) {
  test(`T05 Azure all-location output survives ${picker ? 'directory picker' : 'folder-input fallback'}`, async ({ page }) => {
    await page.goto('http://localhost:8377/index.html', { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => typeof importFolder === 'function');
    await page.evaluate(({ picker, payloads }) => {
      AppProjectFiles.hasDirectoryPicker = () => picker;
      if (picker) {
        const file = (location, payload) => ({ name: 'vnets.json', kind: 'file', getFile: async () => new File([JSON.stringify(payload)], 'vnets.json', { type: 'application/json' }) });
        const dir = (name, children) => ({ name, kind: 'directory', entries: async function* () { yield* children.map(child => [child.name, child]); } });
        AppProjectFiles.chooseDirectory = async () => dir('azure-export-multi', [dir('sub-a', Object.entries(payloads).map(([location, payload]) => dir(location, [file(location, payload)])))]);
      } else {
        HTMLInputElement.prototype.click = function () { window.__folderInput = this; };
      }
    }, { picker, payloads: Object.fromEntries(locations.map(location => [location, vnets(location)])) });
    await page.locator('#importFolderBrowser').click();
    if (!picker) {
      await page.evaluate(payloads => {
        const transfer = new DataTransfer();
        for (const [location, payload] of Object.entries(payloads)) {
          const file = new File([JSON.stringify(payload)], 'vnets.json', { type: 'application/json' });
          Object.defineProperty(file, 'webkitRelativePath', { value: `azure-export-multi/sub-a/${location}/vnets.json` });
          transfer.items.add(file);
        }
        window.__folderInput.files = transfer.files;
        window.__folderInput.dispatchEvent(new Event('change'));
      }, Object.fromEntries(locations.map(location => [location, vnets(location)])));
    }
    await expect.poll(() => page.evaluate(() => (AppRenderContext.createRenderContext().rlCtx?.vnets || []).map(vnet => vnet.name).sort())).toEqual(['vnet-eastus', 'vnet-westus']);
    expect(await page.evaluate(() => _loadedContexts.length)).toBe(2);
    await expect(page.locator('#mapSvg [data-vnet-id]')).toHaveCount(2);
  });
}
