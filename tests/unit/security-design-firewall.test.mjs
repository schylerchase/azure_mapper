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

it('quotes firewall names, derived names and explicit groups for every gateway alias while retaining placeholders', () => {
  // Inert data only: generated command strings are compared and never executed.
  const samples = [
    ['edge-fw', "'edge-fw'", "'edge-fw-pip'", "'edge-fw-ipconfig'"],
    ["fw'quote", "'fw'\\''quote'", "'fw'\\''quote-pip'", "'fw'\\''quote-ipconfig'"],
    ['fw \t\r\nspace', "'fw \t\r\nspace'", "'fw \t\r\nspace-pip'", "'fw \t\r\nspace-ipconfig'"],
    ['fw; & | $HOME $(inert) \`inert\` > < # * ? [x] " \\', "'fw; & | $HOME $(inert) \`inert\` > < # * ? [x] \" \\'", "'fw; & | $HOME $(inert) \`inert\` > < # * ? [x] \" \\-pip'", "'fw; & | $HOME $(inert) \`inert\` > < # * ? [x] \" \\-ipconfig'"],
    ['$RESOURCE_GROUP', "'$RESOURCE_GROUP'", "'$RESOURCE_GROUP-pip'", "'$RESOURCE_GROUP-ipconfig'"]
  ];
  for (const GatewayType of ['AZFW', 'Firewall', 'Azure Firewall', 'IGW']) {
    for (const [Name, quotedName, quotedPip, quotedConfig] of samples) {
      const commands = generate({ action: 'add_gateway', params: { GatewayType, Name, resourceGroup: Name } });
      assert.deepEqual(commands, [
        'az network public-ip create --name ' + quotedPip + ' --resource-group ' + quotedName + ' --sku Standard',
        'az network firewall create --name ' + quotedName + ' --resource-group ' + quotedName + ' --location $LOCATION --sku AZFW_VNet --tier Standard',
        'az network firewall ip-config create --name ' + quotedConfig + ' --firewall-name ' + quotedName + ' --resource-group ' + quotedName + ' --public-ip-address ' + quotedPip + ' --vnet-name $VNET_NAME'
      ], GatewayType + ': ' + JSON.stringify(Name));
    }
    for (const blank of [undefined, '']) {
      assert.deepEqual(generate({ action: 'add_gateway', params: { GatewayType, Name: blank, resourceGroup: blank } }), [
        "az network public-ip create --name 'new-firewall-pip' --resource-group $RESOURCE_GROUP --sku Standard",
        "az network firewall create --name 'new-firewall' --resource-group $RESOURCE_GROUP --location $LOCATION --sku AZFW_VNet --tier Standard",
        "az network firewall ip-config create --name 'new-firewall-ipconfig' --firewall-name 'new-firewall' --resource-group $RESOURCE_GROUP --public-ip-address 'new-firewall-pip' --vnet-name $VNET_NAME"
      ]);
    }
  }
});
