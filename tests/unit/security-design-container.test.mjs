import assert from 'node:assert/strict';
import { it } from 'node:test';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../../src/modules/design-mode-runtime.js', import.meta.url), 'utf8');
const aliases = source.slice(source.indexOf('function designResourceType(type){'), source.indexOf('function designNotify('));
const generator = source.slice(source.indexOf('function _generateCLI(ch){'), source.indexOf('function _generateWarnings(){'));
const context = vm.createContext({});
vm.runInContext(aliases + '\n' + generator, context);
const generate = change => Array.from(context._generateCLI(change));

it('quotes explicit container removal groups for every alias while retaining name and group placeholders', () => {
  // Inert data only: generated command strings are compared and never executed.
  const samples = [
    ['app-rg', "'app-rg'"],
    ["group'quote", "'group'\\''quote'"],
    ['group \t\r\nspace', "'group \t\r\nspace'"],
    ['group; & | $HOME $(inert) \`inert\` > < # * ? [x] " \\', "'group; & | $HOME $(inert) \`inert\` > < # * ? [x] \" \\'"],
    ['$RESOURCE_GROUP', "'$RESOURCE_GROUP'"],
    [undefined, '$RESOURCE_GROUP'],
    ['', '$RESOURCE_GROUP']
  ];
  for (const ResourceType of ["Container","ECS"]) {
    for (const [resourceGroup, expectedGroup] of samples) {
      assert.deepEqual(generate({ action: 'remove_resource', target: { ResourceType }, params: { resourceGroup } }), [
        'az container delete --name $CONTAINER_NAME --resource-group ' + expectedGroup + ' --yes'
      ], ResourceType + ': ' + JSON.stringify(resourceGroup));
    }
    assert.deepEqual(generate({ action: 'remove_resource', target: { ResourceType } }), [
      'az container delete --name $CONTAINER_NAME --resource-group $RESOURCE_GROUP --yes'
    ]);
  }
});
