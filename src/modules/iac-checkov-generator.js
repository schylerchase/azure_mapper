import { _armTags } from "./iac-resource-formatters.js";

// ============================================================
// 4. CHECKOV POLICY GENERATION (Python checks for ARM/Terraform)
// ============================================================

/**
 * Map compliance finding severity to Checkov check categories.
 */
function _ckCategory(finding) {
  const ctrl = (finding.control || '').toUpperCase();
  if (ctrl.includes('IAM') || ctrl.includes('RBAC')) return 'CheckCategories.IAM';
  if (ctrl.includes('ENCRYPT') || ctrl.includes('CRYPTO') || ctrl.includes('TLS')) return 'CheckCategories.ENCRYPTION';
  if (ctrl.includes('LOG') || ctrl.includes('MONITOR') || ctrl.includes('AUDIT')) return 'CheckCategories.LOGGING';
  return 'CheckCategories.NETWORKING';
}

/**
 * Map finding to the appropriate ARM resource type for Checkov.
 */
function _ckResourceType(finding) {
  const msg = (finding.message || '').toLowerCase();
  const resource = (finding.resource || '').toLowerCase();
  if (msg.includes('nsg') || msg.includes('security group') || resource.includes('networksecuritygroup')) {
    return 'Microsoft.Network/networkSecurityGroups';
  }
  if (msg.includes('vnet') || msg.includes('virtual network') || resource.includes('virtualnetwork')) {
    return 'Microsoft.Network/virtualNetworks';
  }
  if (msg.includes('vm') || msg.includes('virtual machine') || resource.includes('virtualmachine')) {
    return 'Microsoft.Compute/virtualMachines';
  }
  if (msg.includes('disk') || resource.includes('disk')) {
    return 'Microsoft.Compute/disks';
  }
  if (msg.includes('storage') || resource.includes('storageaccount')) {
    return 'Microsoft.Storage/storageAccounts';
  }
  if (msg.includes('sql') || resource.includes('sql')) {
    return 'Microsoft.Sql/servers';
  }
  if (msg.includes('firewall') || resource.includes('azurefirewall')) {
    return 'Microsoft.Network/azureFirewalls';
  }
  if (msg.includes('bastion') || resource.includes('bastionhost')) {
    return 'Microsoft.Network/bastionHosts';
  }
  if (msg.includes('route') || resource.includes('routetable')) {
    return 'Microsoft.Network/routeTables';
  }
  return 'Microsoft.Network/networkSecurityGroups';
}

/**
 * Map finding to a Terraform resource type for Checkov.
 */
function _ckTfResourceType(finding) {
  const msg = (finding.message || '').toLowerCase();
  const resource = (finding.resource || '').toLowerCase();
  if (msg.includes('nsg') || msg.includes('security group') || resource.includes('networksecuritygroup')) {
    return 'azurerm_network_security_group';
  }
  if (msg.includes('vnet') || msg.includes('virtual network') || resource.includes('virtualnetwork')) {
    return 'azurerm_virtual_network';
  }
  if (msg.includes('vm') || msg.includes('virtual machine') || resource.includes('virtualmachine')) {
    return 'azurerm_linux_virtual_machine';
  }
  if (msg.includes('disk') || resource.includes('disk')) {
    return 'azurerm_managed_disk';
  }
  if (msg.includes('storage') || resource.includes('storageaccount')) {
    return 'azurerm_storage_account';
  }
  if (msg.includes('sql') || resource.includes('sql')) {
    return 'azurerm_mssql_server';
  }
  if (msg.includes('firewall') || resource.includes('azurefirewall')) {
    return 'azurerm_firewall';
  }
  if (msg.includes('route') || resource.includes('routetable')) {
    return 'azurerm_route_table';
  }
  return 'azurerm_network_security_group';
}

/**
 * Generate scan logic Python code for a finding.
 */
function _ckScanLogic(finding) {
  const ctrl = (finding.control || '').toUpperCase();
  const msg = (finding.message || '').toLowerCase();

  // NSG: no SSH from internet
  if (msg.includes('ssh') && msg.includes('internet')) {
    return [
      '        rules = conf.get("properties", {}).get("securityRules", [])',
      '        for rule in rules:',
      '            props = rule.get("properties", {})',
      '            if (props.get("direction") == "Inbound" and',
      '                    props.get("access") == "Allow" and',
      '                    props.get("destinationPortRange") in ["22", "*"] and',
      '                    props.get("sourceAddressPrefix") in ["*", "0.0.0.0/0", "Internet"]):',
      '                return CheckResult.FAILED',
      '        return CheckResult.PASSED'
    ];
  }

  // NSG: no RDP from internet
  if (msg.includes('rdp') && msg.includes('internet')) {
    return [
      '        rules = conf.get("properties", {}).get("securityRules", [])',
      '        for rule in rules:',
      '            props = rule.get("properties", {})',
      '            if (props.get("direction") == "Inbound" and',
      '                    props.get("access") == "Allow" and',
      '                    props.get("destinationPortRange") in ["3389", "*"] and',
      '                    props.get("sourceAddressPrefix") in ["*", "0.0.0.0/0", "Internet"]):',
      '                return CheckResult.FAILED',
      '        return CheckResult.PASSED'
    ];
  }

  // NSG: no unrestricted inbound
  if (msg.includes('unrestricted') || msg.includes('all ports')) {
    return [
      '        rules = conf.get("properties", {}).get("securityRules", [])',
      '        for rule in rules:',
      '            props = rule.get("properties", {})',
      '            if (props.get("direction") == "Inbound" and',
      '                    props.get("access") == "Allow" and',
      '                    props.get("destinationPortRange") == "*" and',
      '                    props.get("sourceAddressPrefix") in ["*", "0.0.0.0/0", "Internet"]):',
      '                return CheckResult.FAILED',
      '        return CheckResult.PASSED'
    ];
  }

  // Disk encryption
  if (msg.includes('encrypt') && msg.includes('disk')) {
    return [
      '        encryption = conf.get("properties", {}).get("encryptionSettingsCollection", {})',
      '        if encryption.get("enabled") is True:',
      '            return CheckResult.PASSED',
      '        return CheckResult.FAILED'
    ];
  }

  // Storage encryption
  if (msg.includes('encrypt') && msg.includes('storage')) {
    return [
      '        encryption = conf.get("properties", {}).get("encryption", {})',
      '        if encryption.get("services", {}).get("blob", {}).get("enabled") is True:',
      '            return CheckResult.PASSED',
      '        return CheckResult.FAILED'
    ];
  }

  // Flow logs
  if (msg.includes('flow log')) {
    return [
      '        # Check if NSG has flow logs enabled',
      '        flow_logs = conf.get("properties", {}).get("flowLogs", [])',
      '        if flow_logs:',
      '            return CheckResult.PASSED',
      '        return CheckResult.FAILED'
    ];
  }

  // Default: generic check
  return [
    '        # Implement check logic for: ' + (finding.message || '').replace(/'/g, "\\'"),
    '        # Resource: ' + _ckResourceType(finding),
    '        # Remediation: ' + (finding.remediation || '').replace(/'/g, "\\'"),
    '        return CheckResult.PASSED  # Replace with actual logic'
  ];
}

export function generateCheckov(findings, options) {
  if (!findings || !findings.length) return { code: '# No compliance findings to generate checks for', warnings: [], stats: {} };
  const opts = options || {};

  const lines = [];
  const checks = new Map();
  const warnings = [];
  let checkCount = 0;

  // Header
  lines.push('# Azure Checkov Custom Checks');
  lines.push('# Generated by Azure Mapper on ' + new Date().toISOString().split('T')[0]);
  lines.push('# Install: pip install checkov');
  lines.push('# Usage: checkov -d . --external-checks-dir ./custom_checks');
  lines.push('#');
  lines.push('# These checks scan ARM templates for Azure-specific compliance issues.');
  lines.push('');
  lines.push('from checkov.common.models.enums import CheckResult, CheckCategories');
  lines.push('from checkov.arm.base_resource_check import BaseResourceCheck');
  lines.push('');

  findings.forEach(f => {
    const key = f.control;
    if (checks.has(key)) return;
    checks.set(key, true);

    const className = (f.control || 'Check').replace(/[^a-zA-Z0-9]/g, '') + 'Check';
    const checkId = 'CKV_AZURE_CUSTOM_' + (f.control || 'UNKNOWN').replace(/[^a-zA-Z0-9]/g, '_');
    const armType = _ckResourceType(f);
    const category = _ckCategory(f);
    const scanLogic = _ckScanLogic(f);

    lines.push('');
    lines.push('class ' + className + '(BaseResourceCheck):');
    lines.push('    """');
    lines.push('    ' + (f.message || 'Custom compliance check'));
    lines.push('    Severity: ' + (f.severity || 'MEDIUM'));
    lines.push('    Remediation: ' + (f.remediation || 'See Azure documentation'));
    lines.push('    """');
    lines.push('    def __init__(self):');
    lines.push('        name = "' + (f.message || 'Custom check').replace(/"/g, '\\"') + '"');
    lines.push('        id = "' + checkId + '"');
    lines.push('        supported_resources = [\'' + armType + '\']');
    lines.push('        categories = [' + category + ']');
    lines.push('        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)');
    lines.push('');
    lines.push('    def scan_resource_conf(self, conf):');
    scanLogic.forEach(l => lines.push(l));
    lines.push('');
    lines.push('');
    lines.push('check = ' + className + '()');
    lines.push('');

    checkCount++;
  });

  // Also generate a Terraform variant section
  if (checkCount > 0) {
    lines.push('');
    lines.push('# =============================================');
    lines.push('# Terraform (azurerm) variants');
    lines.push('# =============================================');
    lines.push('from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck as TFBaseResourceCheck');
    lines.push('');

    const tfChecks = new Map();
    findings.forEach(f => {
      const key = f.control + '_tf';
      if (tfChecks.has(key)) return;
      tfChecks.set(key, true);

      const className = 'TF' + (f.control || 'Check').replace(/[^a-zA-Z0-9]/g, '') + 'Check';
      const checkId = 'CKV_AZURE_TF_CUSTOM_' + (f.control || 'UNKNOWN').replace(/[^a-zA-Z0-9]/g, '_');
      const tfType = _ckTfResourceType(f);
      const category = _ckCategory(f);

      lines.push('');
      lines.push('class ' + className + '(TFBaseResourceCheck):');
      lines.push('    def __init__(self):');
      lines.push('        name = "' + (f.message || 'Custom check').replace(/"/g, '\\"') + '"');
      lines.push('        id = "' + checkId + '"');
      lines.push('        supported_resources = [\'' + tfType + '\']');
      lines.push('        categories = [' + category + ']');
      lines.push('        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)');
      lines.push('');
      lines.push('    def scan_resource_conf(self, conf):');
      lines.push('        # Implement Terraform-specific check logic');
      lines.push('        return CheckResult.PASSED');
      lines.push('');
      lines.push('');
      lines.push('tf_check = ' + className + '()');
      lines.push('');
    });
  }

  const code = lines.join('\n');
  return {
    code,
    warnings,
    stats: {
      armChecks: checkCount,
      tfChecks: checkCount,
      total: checkCount * 2
    }
  };
}


// ============================================================
// 5. CHECKOV ARM TEMPLATE GENERATION (for scanning)
// ============================================================

/**
 * Generate an ARM template enriched with security-relevant properties
 * for Checkov scanning.
 */
export function generateCheckovArm(data) {
  if (!data) return null;

  const template = {
    '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
    contentVersion: '1.0.0.0',
    resources: []
  };
  const resources = template.resources;

  const vnets = data.vnets || [];
  const nsgs = (data.nsgs || []).concat(data.subnetNsgs || []);
  const udrs = data.udrs || [];
  const vms = data.vms || [];
  const disks = data.disks || [];
  const storageAccounts = data.storageAccounts || [];
  const sqlServers = data.sqlServers || [];
  const firewalls = data.firewalls || [];
  const bastions = data.bastions || [];

  // Deduplicate NSGs
  const nsgMap = new Map();
  nsgs.forEach(n => { if (n.id) nsgMap.set(n.id.toLowerCase(), n); });
  const uniqueNsgs = Array.from(nsgMap.values());

  // VNets
  vnets.forEach(vnet => {
    resources.push({
      type: 'Microsoft.Network/virtualNetworks',
      apiVersion: '2023-04-01',
      name: vnet.name || 'vnet',
      location: '[resourceGroup().location]',
      tags: _armTags(vnet),
      properties: {
        addressSpace: vnet.properties?.addressSpace || { addressPrefixes: ['10.0.0.0/16'] },
        subnets: (vnet.properties?.subnets || []).map(sub => ({
          name: sub.name,
          properties: {
            addressPrefix: sub.properties?.addressPrefix || '10.0.0.0/24',
            networkSecurityGroup: sub.properties?.networkSecurityGroup || undefined,
            routeTable: sub.properties?.routeTable || undefined,
            serviceEndpoints: sub.properties?.serviceEndpoints || []
          }
        }))
      }
    });
  });

  // NSGs with full rule detail
  uniqueNsgs.forEach(nsg => {
    resources.push({
      type: 'Microsoft.Network/networkSecurityGroups',
      apiVersion: '2023-04-01',
      name: nsg.name || 'nsg',
      location: '[resourceGroup().location]',
      tags: _armTags(nsg),
      properties: {
        securityRules: (nsg.properties?.securityRules || []).map(rule => ({
          name: rule.name,
          properties: rule.properties || {}
        }))
      }
    });
  });

  // Route Tables
  udrs.forEach(udr => {
    resources.push({
      type: 'Microsoft.Network/routeTables',
      apiVersion: '2023-04-01',
      name: udr.name || 'rt',
      location: '[resourceGroup().location]',
      tags: _armTags(udr),
      properties: {
        disableBgpRoutePropagation: udr.properties?.disableBgpRoutePropagation || false,
        routes: (udr.properties?.routes || []).map(r => ({
          name: r.name,
          properties: r.properties || {}
        }))
      }
    });
  });

  // VMs with security-relevant properties
  vms.forEach(vm => {
    const vmp = vm.properties || {};
    resources.push({
      type: 'Microsoft.Compute/virtualMachines',
      apiVersion: '2023-07-01',
      name: vm.name || 'vm',
      location: '[resourceGroup().location]',
      tags: _armTags(vm),
      properties: {
        hardwareProfile: vmp.hardwareProfile || { vmSize: 'Standard_B2s' },
        storageProfile: {
          osDisk: {
            createOption: vmp.storageProfile?.osDisk?.createOption || 'FromImage',
            managedDisk: {
              storageAccountType: vmp.storageProfile?.osDisk?.managedDisk?.storageAccountType || 'Standard_LRS'
            }
          },
          imageReference: vmp.storageProfile?.imageReference || {}
        },
        osProfile: {
          computerName: vm.name || 'vm',
          adminUsername: 'azureadmin'
        },
        networkProfile: vmp.networkProfile || {}
      }
    });
  });

  // Managed Disks
  disks.forEach(disk => {
    const dp = disk.properties || {};
    resources.push({
      type: 'Microsoft.Compute/disks',
      apiVersion: '2023-04-02',
      name: disk.name || 'disk',
      location: '[resourceGroup().location]',
      tags: _armTags(disk),
      sku: { name: dp.accountType || disk.sku?.name || 'Standard_LRS' },
      properties: {
        creationData: dp.creationData || { createOption: 'Empty' },
        diskSizeGB: dp.diskSizeGB || 128,
        encryptionSettingsCollection: dp.encryptionSettingsCollection || { enabled: false }
      }
    });
  });

  // Storage Accounts
  storageAccounts.forEach(sa => {
    const sap = sa.properties || {};
    resources.push({
      type: 'Microsoft.Storage/storageAccounts',
      apiVersion: '2023-01-01',
      name: sa.name || 'storage',
      location: '[resourceGroup().location]',
      tags: _armTags(sa),
      sku: sa.sku || { name: 'Standard_LRS' },
      kind: sa.kind || 'StorageV2',
      properties: {
        supportsHttpsTrafficOnly: sap.supportsHttpsTrafficOnly !== false,
        minimumTlsVersion: sap.minimumTlsVersion || 'TLS1_0',
        allowBlobPublicAccess: sap.allowBlobPublicAccess === true,
        networkAcls: sap.networkAcls || { defaultAction: 'Allow' },
        encryption: sap.encryption || {}
      }
    });
  });

  // SQL Servers
  sqlServers.forEach(sql => {
    const sqlp = sql.properties || {};
    resources.push({
      type: 'Microsoft.Sql/servers',
      apiVersion: '2023-05-01-preview',
      name: sql.name || 'sqlserver',
      location: '[resourceGroup().location]',
      tags: _armTags(sql),
      properties: {
        administratorLogin: sqlp.administratorLogin || 'sqladmin',
        publicNetworkAccess: sqlp.publicNetworkAccess || 'Enabled',
        minimalTlsVersion: sqlp.minimalTlsVersion || '1.0'
      }
    });
  });

  // Azure Firewall
  firewalls.forEach(fw => {
    resources.push({
      type: 'Microsoft.Network/azureFirewalls',
      apiVersion: '2023-04-01',
      name: fw.name || 'firewall',
      location: '[resourceGroup().location]',
      tags: _armTags(fw),
      properties: fw.properties || {}
    });
  });

  // Bastion Hosts
  bastions.forEach(bast => {
    resources.push({
      type: 'Microsoft.Network/bastionHosts',
      apiVersion: '2023-04-01',
      name: bast.name || 'bastion',
      location: '[resourceGroup().location]',
      tags: _armTags(bast),
      properties: bast.properties || {}
    });
  });

  return JSON.stringify(template, null, 2);
}
