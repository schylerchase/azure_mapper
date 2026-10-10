import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';
import { splitCIDR, ipInCIDR, parseCIDR, cidrContains, cidrOverlap } from '../../src/modules/cidr-engine.js';
import { generateARM } from '../../src/modules/iac-arm-template-generator.js';

function designFixture() {
  const elements = new Map();
  function element(id) {
    if (elements.has(id)) return elements.get(id);
    const handlers = {};
    const el = { id, value: '', style: {}, options: [], classList: { add() {}, remove() {} },
      addEventListener: (name, callback) => { handlers[name] = callback; },
      click: () => handlers.click?.(), appendChild() {}, handlers };
    Object.defineProperty(el, 'innerHTML', { set(html) {
      el.html = html;
      for (const match of html.matchAll(/<(select|input|div|button)[^>]*\bid="([^"]+)"[^>]*>/g)) {
        const child = element(match[2]);
        child.handlers = child.handlers || {};
        if (match[1] === 'select') {
          const start = match.index + match[0].length;
          const body = html.slice(start, html.indexOf('</select>', start));
          child.options = [...body.matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)].map(option => ({ value: option[1], text: option[2] }));
          child.value = child.options[0]?.value || '';
        }
      }
    }, get: () => el.html || '' });
    elements.set(id, el);
    return el;
  }
  for (const id of ['in_elasticache', 'in_funcapps', 'in_synapse', 'in_azfws', 'in_aks', 'in_vms', 'in_sql', 'in_containers', 'in_subnets', 'in_nsgs', 'in_nics', 'in_vnets', 'in_udrs', 'in_nats']) element(id).value = '{"value":[]}';
  const vnet = { id: 'vnet-1', VpcId: 'vnet-1', name: 'design-vnet' };
  const subnet = { id: 'subnet-1', SubnetId: 'subnet-1', VpcId: 'vnet-1', name: 'AzureFirewallSubnet', CidrBlock: '10.0.0.0/24' };
  const changes = [];
  const context = {
    document: { getElementById: element, createElement: () => element('created-'+elements.size) },
    AppRenderContext: { createRenderContext: () => ({ rlCtx: { vnets: [vnet], subnets: [subnet] } }) },
    AppNotifications: { show() {} },
    safeParse: text => { try { return JSON.parse(text); } catch { return null; } },
    gv: id => element(id).value,
    ext: (value, keys) => Array.isArray(value) ? value : keys.map(key => value?.[key]).find(Array.isArray) || [],
    gn: (value, fallback) => value?.tags?.Name || value?.name || fallback,
    esc: value => String(value), splitCIDR, ipInCIDR, parseCIDR, cidrContains, cidrOverlap, Date, console
  };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync('src/modules/design-mode-runtime.js', 'utf8') + '\nthis.applyFns=_designApplyFns;', context);
  context.addDesignChange = change => { changes.push(change); context.applyFns[change.action](change); };
  return { context, element, changes, vnet, subnet };
}

describe('Design resource form actions', () => {
  it('validates default routes without bypassing the Azure-reserved host guard', () => {
    const fixture = designFixture();
    const rt = { id: 'routes', routes: [] };
    const validate = destination => fixture.context.validateDesignChange({
      action: 'add_route', target: { RouteTableId: rt.id },
      params: { DestinationCidrBlock: destination, nextHopType: 'Internet' }
    }, { udrs: [rt] });
    for (const destination of ['0.0.0.0/0', '168.63.0.0/16', '10.2.0.0/16']) assert.equal(validate(destination).valid, true);
    assert.equal(validate('168.63.129.16/32').valid, false);
    assert.match(validate('168.63.129.16/32').errors.join('\n'), /reserved for Azure health probes/);
    assert.equal(validate('invalid').valid, false);
  });

  for (const nested of [false, true]) {
    it(`accepts a secondary native ${nested ? 'ARM' : 'CLI'} VNet range in the subnet form and final validation`, () => {
      const fixture = designFixture();
      const addressSpace = { addressPrefixes: ['10.0.0.0/16', '10.1.0.0/16'] };
      Object.assign(fixture.vnet, { CidrBlock: '10.0.0.0/16', ...(nested ? { properties: { addressSpace } } : { addressSpace }) });
      const ctx = { vnets: [fixture.vnet], subnets: [fixture.subnet] };
      const validate = cidr => fixture.context.validateDesignChange({
        action: 'add_subnet', params: { VpcId: fixture.vnet.id, CidrBlock: cidr }
      }, ctx);
      fixture.context.showDesignForm('add_subnet', { vpc: fixture.vnet });
      assert.match(fixture.element('dpBody').innerHTML, /10\.0\.0\.0\/16, 10\.1\.0\.0\/16/);
      for (const cidr of ['10.0.2.0/24', '10.1.2.0/24']) {
        fixture.element('df_cidr').value = cidr;
        fixture.element('df_cidr').handlers.input();
        assert.equal(fixture.element('df_ok').disabled, false);
        assert.equal(validate(cidr).valid, true);
      }
      for (const cidr of ['10.2.2.0/24', '10.0.0.0/24']) {
        fixture.element('df_cidr').value = cidr;
        fixture.element('df_cidr').handlers.input();
        assert.equal(fixture.element('df_ok').disabled, true);
        assert.equal(validate(cidr).valid, false);
      }
      fixture.element('df_cidr').value = '10.1.2.0/24';
      fixture.element('df_cidr').handlers.input();
      fixture.element('df_ok').click();
      assert.equal(JSON.parse(fixture.element('in_subnets').value).value[0].addressPrefix, '10.1.2.0/24');
    });
  }

  it('retains the Create VNet location on the VNet, default route table and NSG', () => {
    const fixture = designFixture();
    fixture.context.showDesignForm('add_vpc', {});
    fixture.element('df_vpcname').value = 'west-net';
    fixture.element('df_vpccidr').value = '10.2.0.0/16';
    fixture.element('df_vpclocation').value = 'westus3';
    fixture.element('df_ok').click();
    for (const input of ['in_vnets', 'in_nsgs', 'in_udrs']) assert.equal(JSON.parse(fixture.element(input).value).value[0].location, 'westus3');
    const native = JSON.parse(fixture.element('in_vnets').value).value[0];
    assert.equal(JSON.parse(generateARM({ vnets: [native] }).code).parameters.location.defaultValue, 'westus3');
  });

  for (const nested of [false, true]) {
    it(`stores the firewall's IP and Azure next-hop type in a native ${nested ? 'ARM' : 'CLI'} design route`, () => {
      const fixture = designFixture();
      const rtId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/routeTables/routes';
      const properties = { routes: [] };
      fixture.element('in_udrs').value = JSON.stringify({ value: [{ id: rtId, ...(nested ? { properties } : properties) }] });
      const firewallId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw';
      fixture.context.AppRenderContext.createRenderContext = () => ({ rlCtx: { vnets: [fixture.vnet], subnets: [fixture.subnet], firewalls: [{ id: firewallId, name: 'fw', VpcId: fixture.vnet.id, ipConfigurations: [{ privateIPAddress: '10.0.0.4' }] }] } });
      fixture.context.showDesignForm('add_route', { rtId, vpcId: fixture.vnet.id });
      fixture.element('df_dest').value = '10.20.0.0/16';
      fixture.element('df_ok').click();
      const table = JSON.parse(fixture.element('in_udrs').value).value[0];
      const route = (table.properties || table).routes[0];
      assert.equal(route.nextHopType, 'VirtualAppliance');
      assert.equal(route.nextHopIpAddress, '10.0.0.4');
      const cli = fixture.context._generateCLI(fixture.changes[0]).join('\n');
      assert.match(cli, /--next-hop-type VirtualAppliance --next-hop-ip-address 10\.0\.0\.4/);
      assert.ok(!cli.includes(firewallId));
      fixture.element('df_next_hop_ip').value = 'invalid';
      fixture.element('df_ok').click();
      assert.equal(fixture.changes.length, 1);
    });
  }

  it('omits appliance-IP arguments for Internet routes and rejects legacy resource-ID next hops', () => {
    const fixture = designFixture();
    fixture.element('in_udrs').value = JSON.stringify({ value: [{ id: 'routes', routes: [] }] });
    fixture.context.showDesignForm('add_route', { rtId: 'routes', vpcId: fixture.vnet.id });
    fixture.element('df_target').value = 'Internet';
    fixture.element('df_dest').value = '0.0.0.0/0';
    fixture.element('df_ok').click();
    const cli = fixture.context._generateCLI(fixture.changes[0]).join('\n');
    assert.match(cli, /--next-hop-type Internet/);
    assert.doesNotMatch(cli, /--next-hop-ip-address/);
    assert.match(fixture.context._generateCLI({ action: 'add_route', params: { DestinationCidrBlock: '0.0.0.0/0', TargetId: '/subscriptions/sub/providers/Microsoft.Network/azureFirewalls/fw' } }).join('\n'), /^# Route needs/);
  });

  it('marks design-created VMs as requiring IaC configuration and retains their VM size', () => {
    const fixture = designFixture();
    fixture.context.showDesignForm('add_resource', { subnet: fixture.subnet });
    fixture.element('df_resname').value = 'planned-vm';
    fixture.element('df_ok').click();
    const machine = JSON.parse(fixture.element('in_vms').value).value[0];
    assert.equal(machine._designCreated, true);
    assert.equal(machine.properties.hardwareProfile.vmSize, 'Standard_B2ms');
    assert.equal(generateARM({ vms: [machine] }).blocked, true);
  });
  for (const [label, input, command] of [
    ['Redis Cache', 'in_elasticache', 'az redis'],
    ['Function App', 'in_funcapps', 'az functionapp'],
    ['Synapse Workspace', 'in_synapse', 'az synapse workspace']
  ]) {
    it(`adds and removes ${label} through the actual form callback`, () => {
      const fixture = designFixture();
      fixture.context.showDesignForm('add_resource', { subnet: fixture.subnet });
      const selection = fixture.element('df_restype').options.find(option => option.text === label);
      assert.ok(selection);
      fixture.element('df_restype').value = selection.value;
      fixture.element('df_resname').value = 'new-resource';
      fixture.element('df_ok').click();
      const [change] = fixture.changes;
      const resources = JSON.parse(fixture.element(input).value).value;
      assert.equal(resources.length, 1);
      assert.equal(resources[0].id, change.params.ResourceId);
      assert.equal(change._addedIds[0], resources[0].id);
      assert.equal(resources[0].VpcId, fixture.vnet.id);
      assert.equal(resources[0].SubnetId, fixture.subnet.id);
      assert.match(fixture.context._generateCLI(change).join('\n'), new RegExp(command + ' create'));
      assert.equal(JSON.parse(fixture.element('in_aks').value).value.length, 0);
      const remove = { action: 'remove_resource', target: { ResourceType: selection.value, ResourceId: resources[0].id } };
      fixture.context.applyFns.remove_resource(remove);
      assert.equal(JSON.parse(fixture.element(input).value).value.length, 0);
      assert.equal(remove._removedIds[0], resources[0].id);
      assert.match(fixture.context._generateCLI(remove).join('\n'), new RegExp(command + ' delete'));
    });
  }

  it('adds and removes Azure Firewall with VNet/subnet metadata from the form', () => {
    const fixture = designFixture();
    fixture.context.showDesignForm('add_gateway', { vpc: fixture.vnet });
    assert.equal(fixture.element('df_gwtype').value, 'AZFW');
    assert.equal(fixture.element('df_gwsub').value, fixture.subnet.id);
    fixture.element('df_gwname').value = 'new-firewall';
    fixture.element('df_ok').click();
    const [change] = fixture.changes;
    const [firewall] = JSON.parse(fixture.element('in_azfws').value).value;
    assert.equal(firewall.id, change.params.GatewayId);
    assert.equal(change._addedIds[0], firewall.id);
    assert.equal(firewall.VpcId, fixture.vnet.id);
    assert.equal(firewall.SubnetId, fixture.subnet.id);
    assert.equal(firewall.properties.ipConfigurations[0].subnet.id, fixture.subnet.id);
    assert.match(fixture.context._generateCLI(change).join('\n'), /az network firewall create/);
    assert.match(fixture.context._generateCLI(change).join('\n'), /az network firewall ip-config create/);
    const remove = { action: 'remove_resource', target: { ResourceType: 'AZFW', ResourceId: firewall.id } };
    fixture.context.applyFns.remove_resource(remove);
    assert.equal(JSON.parse(fixture.element('in_azfws').value).value.length, 0);
    assert.match(fixture.context._generateCLI(remove).join('\n'), /az network firewall delete/);
  });

  it('retains entered NSG rules in the native resource and ARM export', () => {
    const fixture = designFixture();
    fixture.context.showDesignForm('add_security_group', { vpc: fixture.vnet });
    fixture.element('df_sgname').value = 'web-nsg';
    fixture.element('df_sgr_proto_0').value = 'tcp';
    fixture.element('df_sgr_port_0').value = '443';
    fixture.element('df_sgr_cidr_0').value = '10.0.0.0/8';
    fixture.element('df_sg_add_rule').click();
    fixture.element('df_sgr_proto_1').value = '-1';
    fixture.element('df_sgr_cidr_1').value = '10.2.0.0/16';
    fixture.element('df_ok').click();
    const [nsg] = JSON.parse(fixture.element('in_nsgs').value).value;
    assert.equal(nsg.securityRules.length, 2);
    assert.equal(nsg.securityRules[0].destinationPortRange, '443');
    assert.equal(nsg.securityRules[0].sourceAddressPrefix, '10.0.0.0/8');
    assert.equal(nsg.securityRules[1].protocol, '*');
    assert.equal(nsg.securityRules[1].destinationPortRange, '*');
    assert.deepEqual(nsg.securityRules.map(rule => rule.priority), [100, 110]);
    const rules = JSON.parse(generateARM({ nsgs: [nsg] }).code).resources[0].properties.securityRules;
    assert.equal(rules[0].properties.destinationPortRange, '443');
    assert.equal(rules[0].properties.sourceAddressPrefix, '10.0.0.0/8');
    assert.match(fixture.context._generateCLI(fixture.changes[0]).join('\n'), /--destination-port-ranges '?443'? --source-address-prefixes '?10.0.0.0\/8'?/);
  });

  for (const nested of [false, true]) {
    it(`splits a native ${nested ? 'ARM properties' : 'CLI flat'} subnet and updates NIC and VNet references`, () => {
      const fixture = designFixture();
      const vnetId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/native';
      const subnetId = vnetId + '/subnets/original';
      const properties = { addressPrefix: '10.0.0.0/24', networkSecurityGroup: { id: 'nsg-existing' } };
      const subnet = { id: subnetId, name: 'original', tags: { Owner: 'retained' }, ...(nested ? { properties } : properties) };
      fixture.element('in_subnets').value = JSON.stringify(nested ? { value: [subnet] } : [subnet]);
      fixture.element('in_vnets').value = JSON.stringify([{ id: vnetId, properties: { subnets: [subnet] } }]);
      fixture.element('in_nics').value = JSON.stringify([{ id: 'nic-a', ipConfigurations: [{ privateIPAddress: '10.0.0.5', subnet: { id: subnetId } }] }, { id: 'nic-b', properties: { ipConfigurations: [{ properties: { privateIPAddress: '10.0.0.200', subnet: { id: subnetId } } }] } }]);
      fixture.element('in_udrs').value = JSON.stringify([{ id: 'rt', properties: { subnets: [{ id: subnetId }] } }]);
      fixture.element('in_vms').value = JSON.stringify([{ id: 'vm-a', SubnetId: subnetId, privateIpAddress: '10.0.0.5' }, { id: 'vm-b', subnetId, PrivateIpAddress: '10.0.0.200' }]);
      fixture.context.AppRenderContext.createRenderContext = () => ({ rlCtx: { subnets: [subnet] } });
      fixture.context.showDesignForm('split_subnet', { subnet });
      fixture.element('df_name_a').value = 'first-half';
      fixture.element('df_name_b').value = 'second-half';
      fixture.element('df_ok').click();
      const [change] = fixture.changes;
      const split = JSON.parse(fixture.element('in_subnets').value).value;
      assert.deepEqual(split.map(s => s.addressPrefix), ['10.0.0.0/25', '10.0.0.128/25']);
      assert.deepEqual(split.map(s => s.id), [vnetId + '/subnets/first-half', vnetId + '/subnets/second-half']);
      assert.deepEqual(Array.from(change._addedIds), split.map(s => s.id));
      assert.deepEqual(Array.from(change._removedIds), [subnetId]);
      assert.ok(split.every(s => s.VpcId === vnetId && s.tags.Owner === 'retained'));
      if (nested) assert.deepEqual(split.map(s => s.properties.addressPrefix), ['10.0.0.0/25', '10.0.0.128/25']);
      const nics = JSON.parse(fixture.element('in_nics').value);
      assert.equal(nics[0].ipConfigurations[0].subnet.id, split[0].id);
      assert.equal(nics[1].properties.ipConfigurations[0].properties.subnet.id, split[1].id);
      assert.deepEqual(JSON.parse(fixture.element('in_vnets').value)[0].properties.subnets.map(s => s.id), split.map(s => s.id));
      assert.deepEqual(JSON.parse(fixture.element('in_udrs').value)[0].properties.subnets.map(s => s.id), split.map(s => s.id));
      assert.deepEqual(JSON.parse(fixture.element('in_vms').value).value.map(s => s.SubnetId), split.map(s => s.id));
      const cli = fixture.context._generateCLI(change).join('\n');
      assert.match(cli, /--name first-half .*--address-prefixes 10.0.0.0\/25/);
      assert.match(cli, /--name second-half .*--address-prefixes 10.0.0.128\/25/);
    });
  }
});

describe('Safe native subnet Split validation', () => {
  function nativeFixture(nested, prefixes = ['10.0.0.0/24']) {
    const fixture = designFixture();
    const vnetId = '/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/native';
    const subnetId = vnetId + '/subnets/original';
    const properties = { addressPrefixes: prefixes, networkSecurityGroup: { id: 'nsg-existing' } };
    const subnet = { id: subnetId, name: 'original', ...(nested ? { properties } : properties) };
    fixture.element('in_subnets').value = JSON.stringify({ value: [subnet] });
    fixture.element('in_vnets').value = JSON.stringify([{ id: vnetId, properties: { subnets: [subnet] } }]);
    fixture.element('in_nics').value = JSON.stringify([{ id: 'nic-a', ipConfigurations: [{ privateIPAddress: '10.0.0.5', subnet: { id: subnetId } }] }, { id: 'nic-b', ipConfigurations: [{ privateIPAddress: '10.0.0.200', subnet: { id: subnetId } }] }]);
    fixture.context.AppRenderContext.createRenderContext = () => ({ rlCtx: { subnets: [subnet] } });
    return { ...fixture, subnet, subnetId, vnetId };
  }

  for (const nested of [false, true]) {
    it(`splits a single native ${nested ? 'ARM' : 'CLI'} addressPrefixes range and migrates both NICs`, () => {
      const fixture = nativeFixture(nested);
      fixture.context.showDesignForm('split_subnet', { subnet: fixture.subnet });
      fixture.element('df_name_a').value = 'first-half';
      fixture.element('df_name_b').value = 'second-half';
      fixture.element('df_ok').click();
      const subnets = JSON.parse(fixture.element('in_subnets').value).value;
      assert.deepEqual(subnets.map(sub => (sub.properties || sub).addressPrefixes), [['10.0.0.0/25'], ['10.0.0.128/25']]);
      assert.deepEqual(JSON.parse(fixture.element('in_nics').value).map(nic => nic.ipConfigurations[0].subnet.id), subnets.map(sub => sub.id));
      assert.equal(new Set(subnets.map(sub => sub.id)).size, 2);
    });

    it(`visibly rejects a native ${nested ? 'ARM' : 'CLI'} dual-stack Split before form or replay mutation`, () => {
      const fixture = nativeFixture(nested, ['10.0.0.0/24', 'fd00:1234:5678:1::/64']);
      const before = ['in_subnets', 'in_vnets', 'in_nics'].map(input => fixture.element(input).value);
      fixture.context.showDesignForm('split_subnet', { subnet: fixture.subnet });
      assert.match(fixture.element('dpBody').innerHTML, /Dual-stack and multiple-prefix subnets cannot be split safely/);
      assert.doesNotMatch(fixture.element('dpBody').innerHTML, /id="df_ok"/);
      const change = { action: 'split_subnet', target: { SubnetId: fixture.subnetId }, params: { names: ['first-half', 'second-half'] } };
      assert.equal(fixture.context.validateDesignChange(change, { subnets: [fixture.subnet] }).valid, false);
      fixture.context.applyFns.split_subnet(change);
      assert.equal(change._invalid, true);
      assert.equal(change._validation.valid, false);
      assert.deepEqual(['in_subnets', 'in_vnets', 'in_nics'].map(input => fixture.element(input).value), before);
    });
  }

  it('blocks duplicate names in the form, including case variants, and leaves the source unchanged', () => {
    const fixture = nativeFixture(false);
    const before = fixture.element('in_subnets').value;
    fixture.context.showDesignForm('split_subnet', { subnet: fixture.subnet });
    fixture.element('df_name_a').value = ' same-name ';
    fixture.element('df_name_b').value = 'SAME-NAME';
    fixture.element('df_name_b').handlers.input();
    assert.equal(fixture.element('df_ok').disabled, true);
    assert.match(fixture.element('df_err').textContent, /distinct names/);
    fixture.element('df_ok').click();
    assert.equal(fixture.changes.length, 0);
    assert.equal(fixture.element('in_subnets').value, before);
    fixture.element('df_name_b').value = 'second-half';
    fixture.element('df_name_b').handlers.input();
    assert.equal(fixture.element('df_ok').disabled, false);
    fixture.element('df_ok').click();
    assert.equal(new Set(JSON.parse(fixture.element('in_subnets').value).value.map(sub => sub.id)).size, 2);
    assert.equal(fixture.changes[0].params.names[0], 'same-name');
  });

  it('blocks replayed duplicate names, duplicate explicit IDs and existing-resource collisions', () => {
    for (const params of [
      { names: ['same-name', 'same-name'] },
      { names: ['first-half', 'second-half'], newIds: ['duplicate', 'duplicate'] },
      { names: ['taken', 'second-half'] },
      { names: ['first-half', 'second-half'], newIds: ['taken-id', 'second-id'] }
    ]) {
      const fixture = nativeFixture(false);
      const existing = { id: 'taken-id', name: 'taken', VpcId: fixture.vnetId, addressPrefix: '10.0.1.0/24' };
      const subnets = [fixture.subnet, existing];
      fixture.element('in_subnets').value = JSON.stringify({ value: subnets });
      const before = fixture.element('in_subnets').value;
      const change = { action: 'split_subnet', target: { SubnetId: fixture.subnetId }, params };
      assert.equal(fixture.context.validateDesignChange(change, { subnets }).valid, false);
      fixture.context.applyFns.split_subnet(change);
      assert.equal(change._invalid, true);
      assert.equal(fixture.element('in_subnets').value, before);
    }
  });
});

describe('Existing design plan type aliases', () => {
  for (const [type, input] of [['Redis Cache', 'in_elasticache'], ['ElastiCache', 'in_elasticache'], ['Function App', 'in_funcapps'], ['Lambda', 'in_funcapps'], ['Redshift', 'in_synapse']]) {
    it(`preserves the ${type} plan value while applying and exporting its Azure resource`, () => {
      const fixture = designFixture();
      const change = { action: 'add_resource', params: { ResourceType: type, ResourceId: 'legacy-resource', VpcId: 'vnet-1', SubnetId: 'subnet-1' } };
      fixture.context.applyFns.add_resource(change);
      assert.equal(change.params.ResourceType, type);
      assert.equal(JSON.parse(fixture.element(input).value).value[0].id, 'legacy-resource');
      assert.ok(fixture.context._generateCLI(change).length);
      fixture.context.applyFns.remove_resource({ action: 'remove_resource', target: { ResourceType: type, ResourceId: 'legacy-resource' } });
      assert.equal(JSON.parse(fixture.element(input).value).value.length, 0);
    });
  }
  it('applies the previous IGW form value as Azure Firewall and keeps AKS separate from Synapse', () => {
    const fixture = designFixture();
    const change = { action: 'add_gateway', params: { GatewayType: 'IGW', GatewayId: 'legacy-firewall', VpcId: 'vnet-1', SubnetId: 'subnet-1' } };
    fixture.context.applyFns.add_gateway(change);
    assert.equal(change.params.GatewayType, 'IGW');
    assert.equal(JSON.parse(fixture.element('in_azfws').value).value[0].id, 'legacy-firewall');
    assert.match(fixture.context._generateCLI(change).join('\n'), /az network firewall create/);
    fixture.context.applyFns.remove_resource({ action: 'remove_resource', target: { ResourceType: 'IGW', ResourceId: 'legacy-firewall' } });
    assert.equal(JSON.parse(fixture.element('in_azfws').value).value.length, 0);
    fixture.context.applyFns.add_resource({ action: 'add_resource', params: { ResourceType: 'AKS', ResourceId: 'aks-resource' } });
    assert.equal(JSON.parse(fixture.element('in_aks').value).value[0].id, 'aks-resource');
    assert.equal(JSON.parse(fixture.element('in_synapse').value).value.length, 0);
  });
});
