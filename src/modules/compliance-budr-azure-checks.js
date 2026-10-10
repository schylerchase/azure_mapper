// Azure backup, uptime, and disaster recovery compliance checks.

import { _rn, _finding, _hasAssessmentEvidence } from './compliance-rule-primitives.js';

export function runBUDRAzureChecks(data) {
  const f = [];
  const vms = data.vms || [];
  const sqlServers = data.sqlServers || [];
  const sqlDatabases = data.sqlDatabases || [];
  const recoveryVaults = data.recoveryVaults || [];
  const vnets = data.vnets || [];
  const availabilitySets = data.availabilitySets || [];
  const managedDisks = data.managedDisks || [];
  const storageAccounts = data.storageAccounts || [];
  const aksClusters = data.aksClusters || [];
  const functionApps = data.functionApps || [];
  const redisCaches = data.redisCaches || [];
  const backupPolicies = data.backupPolicies || [];
  const backupItems = data.backupItems || [];

  // Build set of protected VM IDs
  const protectedVmIds = new Set();
  backupItems.forEach(bi => {
    const props = bi.properties || bi;
    const sourceId = (props.sourceResourceId || props.virtualMachineId || '').toLowerCase();
    if (sourceId) protectedVmIds.add(sourceId);
  });

  // BUDR-VM-BAK: VM without backup policy
  if(_hasAssessmentEvidence(data,'backupItems'))vms.forEach(vm => {
    const vmId = (vm.id || '').toLowerCase();
    if (!protectedVmIds.has(vmId)) {
      f.push(_finding({
        id: 'BUDR-VM-BAK', framework: 'BUDR', severity: 'HIGH',
        title: 'VM without backup policy',
        message: `VM "${_rn(vm)}" is not protected by Azure Backup`,
        resource: _rn(vm), resourceId: vm.id || '', resourceType: 'Microsoft.Compute/virtualMachines',
        remediation: 'Enable Azure Backup for the VM via Recovery Services Vault',
      }));
    }
  });

  // BUDR-SQL-RET: SQL without long-term retention
  sqlDatabases.forEach(db => {
    const props = db.properties || db;
    const ltr = props.longTermRetentionPolicy || props.longTermRetention;
    const hasLtr = ltr && (ltr.weeklyRetention || ltr.monthlyRetention || ltr.yearlyRetention);
    if (!hasLtr) {
      f.push(_finding({
        id: 'BUDR-SQL-RET', framework: 'BUDR', severity: 'MEDIUM',
        title: 'SQL database without long-term retention',
        message: `SQL database "${_rn(db)}" has no long-term backup retention configured`,
        resource: _rn(db), resourceId: db.id || '', resourceType: 'Microsoft.Sql/servers/databases',
        remediation: 'Configure long-term retention (LTR) policy for weekly/monthly/yearly backups',
      }));
    }
  });

  // BUDR-RSV: No Recovery Services Vault
  if (recoveryVaults.length === 0 && vms.length > 0 && _hasAssessmentEvidence(data,'recoveryVaults')) {
    f.push(_finding({
      id: 'BUDR-RSV', framework: 'BUDR', severity: 'HIGH',
      title: 'No Recovery Services Vault',
      message: `${vms.length} VM(s) found but no Recovery Services Vault: no centralized backup infrastructure`,
      resource: 'Subscription', resourceId: '', resourceType: 'Microsoft.RecoveryServices/vaults',
      remediation: 'Create a Recovery Services Vault and configure backup policies for all VMs',
    }));
  }

  // BUDR-REGION: Single-region deployment (no DR)
  const deployedRegions = new Set();
  [...vms, ...vnets, ...sqlServers].forEach(r => {
    if (r.location) deployedRegions.add(r.location.toLowerCase());
  });
  if (deployedRegions.size === 1 && vms.length > 3) {
    const region = [...deployedRegions][0];
    f.push(_finding({
      id: 'BUDR-REGION', framework: 'BUDR', severity: 'HIGH',
      title: 'Single-region deployment',
      message: `All resources deployed in "${region}": no geographic disaster recovery capability`,
      resource: region, resourceId: '', resourceType: 'Various',
      remediation: 'Implement cross-region DR strategy using Azure Site Recovery or geo-replication',
    }));
  }

  // BUDR-AVAIL: Missing availability set/zone
  vms.forEach(vm => {
    const props = vm.properties || vm;
    const hasAvailSet = props.availabilitySet && props.availabilitySet.id;
    const hasZone = (vm.zones || []).length > 0;
    if (!hasAvailSet && !hasZone) {
      f.push(_finding({
        id: 'BUDR-AVAIL', framework: 'BUDR', severity: 'MEDIUM',
        title: 'VM without availability set or zone',
        message: `VM "${_rn(vm)}" has no availability set or availability zone: single point of failure`,
        resource: _rn(vm), resourceId: vm.id || '', resourceType: 'Microsoft.Compute/virtualMachines',
        remediation: 'Deploy VMs in availability zones or availability sets for HA',
      }));
    }
  });

  // BUDR-SNAP: No snapshot policy for disks
  const snapshots = data.snapshots || [];
  const disksWithSnap = new Set(
    snapshots.map(s => {
      const props = s.properties || s;
      return (props.creationData?.sourceResourceId || '').toLowerCase();
    }).filter(Boolean)
  );
  managedDisks.forEach(disk => {
    const diskId = (disk.id || '').toLowerCase();
    const props = disk.properties || disk;
    if (props.diskState === 'Attached' && !disksWithSnap.has(diskId)) {
      f.push(_finding({
        id: 'BUDR-SNAP', framework: 'BUDR', severity: 'MEDIUM',
        title: 'Managed disk without snapshots',
        message: `Attached disk "${_rn(disk)}" has no snapshots: point-in-time recovery unavailable`,
        resource: _rn(disk), resourceId: disk.id || '', resourceType: 'Microsoft.Compute/disks',
        remediation: 'Create a snapshot policy or use Azure Backup for automatic disk snapshots',
      }));
    }
  });

  // BUDR-GEO: Storage account without geo-redundancy
  storageAccounts.forEach(sa => {
    const props = sa.properties || sa;
    const sku = sa.sku || {};
    const replication = (sku.name || sku.tier || '').toUpperCase();
    if (/(?:^|_)(?:LRS|ZRS)$/.test(replication)) {
      f.push(_finding({
        id: 'BUDR-GEO', framework: 'BUDR', severity: 'MEDIUM',
        title: 'Storage account without geo-redundancy',
        message: `Storage account "${_rn(sa)}" uses ${replication}: no geographic redundancy`,
        resource: _rn(sa), resourceId: sa.id || '', resourceType: 'Microsoft.Storage/storageAccounts',
        remediation: 'Use GRS or RA-GRS replication for critical data; GZRS for zone + geo redundancy',
      }));
    }
  });

  // BUDR-AKS-PDB: AKS without pod disruption budget indication
  aksClusters.forEach(aks => {
    const props = aks.properties || aks;
    const agentPools = props.agentPoolProfiles || [];
    const singleNode = agentPools.every(ap => (ap.count || 1) <= 1);
    if (singleNode) {
      f.push(_finding({
        id: 'BUDR-AKS-PDB', framework: 'BUDR', severity: 'MEDIUM',
        title: 'AKS cluster with single-node pools',
        message: `AKS cluster "${_rn(aks)}" has single-node agent pools: no pod disruption budget effective`,
        resource: _rn(aks), resourceId: aks.id || '', resourceType: 'Microsoft.ContainerService/managedClusters',
        remediation: 'Scale agent pools to 2+ nodes and configure PodDisruptionBudgets for workloads',
      }));
    }
  });

  // BUDR-FUNC: Function app without deployment slots
  functionApps.forEach(fa => {
    const props = fa.properties || fa;
    const slots = props.siteConfig?.numberOfWorkers || 0;
    const slotNames = data.deploymentSlots || [];
    const faSlots = slotNames.filter(s => {
      const sId = (s.id || '').toLowerCase();
      const faId = (fa.id || '').toLowerCase();
      return sId.includes(faId);
    });
    if (faSlots.length === 0) {
      f.push(_finding({
        id: 'BUDR-FUNC', framework: 'BUDR', severity: 'LOW',
        title: 'Function app without deployment slots',
        message: `Function app "${_rn(fa)}" has no deployment slots: no zero-downtime deployment`,
        resource: _rn(fa), resourceId: fa.id || '', resourceType: 'Microsoft.Web/sites',
        remediation: 'Create staging deployment slot for blue-green deployments and rollback capability',
      }));
    }
  });

  // BUDR-REDIS: Redis without data persistence
  redisCaches.forEach(rc => {
    const props = rc.properties || rc;
    const sku = rc.sku || props.sku || {};
    const tier = (sku.name || sku.family || '').toLowerCase();
    const rdbEnabled = props.redisConfiguration?.['rdb-backup-enabled'] === 'true';
    const aofEnabled = props.redisConfiguration?.['aof-backup-enabled'] === 'true';
    // Basic/Standard tiers do not support persistence
    if (tier.includes('premium') && !rdbEnabled && !aofEnabled) {
      f.push(_finding({
        id: 'BUDR-REDIS', framework: 'BUDR', severity: 'MEDIUM',
        title: 'Redis cache without data persistence',
        message: `Premium Redis cache "${_rn(rc)}" has no RDB or AOF persistence: data loss on restart`,
        resource: _rn(rc), resourceId: rc.id || '', resourceType: 'Microsoft.Cache/Redis',
        remediation: 'Enable RDB snapshots or AOF persistence for durable caching',
      }));
    }
  });

  return f;
}
