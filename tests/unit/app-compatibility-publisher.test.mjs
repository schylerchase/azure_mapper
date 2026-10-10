import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  ensureLegacyComplianceFindings,
  installLazyBundleLoaders,
  publishLegacyAppModules
} from '../../src/modules/app-compatibility-publisher.js';

function createBrowserRoot(){
  const scripts = [];
  return {
    scripts,
    document: {
      head: {
        appendChild(script){
          scripts.push(script);
        }
      },
      createElement(tag){
        assert.equal(tag, 'script');
        return {};
      }
    }
  };
}

describe('AppCompatibilityPublisher', () => {
  it('publishes AppModules and legacy globals through one owner', () => {
    const root = createBrowserRoot();
    const modules = {
      parseResourceId(){ return 'parsed'; },
      AppDownloads: { saveBlob(){} }
    };

    const result = publishLegacyAppModules(modules, { root });

    assert.equal(result, modules);
    assert.equal(root.AppModules, modules);
    assert.equal(root.parseResourceId, modules.parseResourceId);
    assert.equal(root.AppDownloads, modules.AppDownloads);
  });

  it('initializes the legacy compliance findings bridge only when missing', () => {
    const root = createBrowserRoot();

    const created = ensureLegacyComplianceFindings({ root });
    assert.deepEqual(created, []);
    assert.equal(root._complianceFindings, created);

    root._complianceFindings = [{ id: 'existing' }];
    const existing = ensureLegacyComplianceFindings({ root });
    assert.equal(existing, root._complianceFindings);
    assert.deepEqual(existing, [{ id: 'existing' }]);
  });

  it('installs lazy demo and IaC bundle loaders', async () => {
    const root = createBrowserRoot();
    root.AppModules = {};
    const demoGenerator = () => ({ sample: true });
    const iacModule = { generateTerraform(){ return 'tf'; } };

    const loaders = installLazyBundleLoaders({
      root,
      demoSrc: 'demo-test.bundle.js',
      iacSrc: 'iac-test.bundle.js'
    });

    assert.equal(loaders.loadDemoData, root._loadDemoData);
    assert.equal(loaders.loadIacGenerator, root._loadIacGenerator);

    const demoPromise = root._loadDemoData();
    assert.equal(root.scripts[0].src, 'demo-test.bundle.js');
    root.DemoDataModule = { generateDemo: demoGenerator };
    root.scripts[0].onload();
    assert.equal(await demoPromise, demoGenerator);
    assert.equal(root.generateDemo, demoGenerator);

    const iacPromise = root._loadIacGenerator();
    assert.equal(root.scripts[1].src, 'iac-test.bundle.js');
    root.IacGeneratorModule = iacModule;
    root.scripts[1].onload();
    assert.equal(await iacPromise, iacModule);
    assert.equal(root.IacGenerator, iacModule);
    assert.equal(root.AppModules.IacGenerator, iacModule);
  });
});
