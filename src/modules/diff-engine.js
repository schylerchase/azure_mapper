// Pure Azure snapshot diff engine.
// Runtime DOM wiring lives in diff-mode-runtime.js; this file is intentionally
// importable in Node tests without browser globals.

const _DIFF_KEYS = {
  vnets: 'id',
  subnets: 'id',
  vms: 'id',
  nsgs: 'id',
  udrs: 'id',
  natGateways: 'id',
  privateEndpoints: 'id',
  appGateways: 'id',
  sqlServers: 'id',
  functionApps: 'id',
  containerInstances: 'id',
  redisCaches: 'id',
  synapseWorkspaces: 'id',
  peerings: 'id',
  storageAccounts: 'id',
  aksCluster: 'id',
  firewalls: 'id',
  bastions: 'id',
  loadBalancers: 'id'
};

const _DIFF_TEXTAREA_IDS = {
  vnets: ['in_vnets'],
  subnets: ['in_subnets'],
  vms: ['in_vms'],
  nsgs: ['in_nsgs'],
  udrs: ['in_udrs'],
  natGateways: ['in_nats'],
  privateEndpoints: ['in_pvteps', 'in_privateendpoints', 'in_private_endpoints'],
  appGateways: ['in_albs', 'in_agws', 'in_app_gateways'],
  sqlServers: ['in_sql'],
  functionApps: ['in_funcapps', 'in_functions'],
  containerInstances: ['in_containers'],
  redisCaches: ['in_elasticache', 'in_redis'],
  synapseWorkspaces: ['in_synapse'],
  peerings: ['in_peer', 'in_peerings'],
  storageAccounts: ['in_storage'],
  aksCluster: ['in_aks'],
  firewalls: ['in_azfws', 'in_firewalls'],
  bastions: ['in_bastions'],
  loadBalancers: ['in_tgs', 'in_lbs']
};

const _DIFF_VOLATILE = new Set([
  'createdTime',
  'lastModifiedTime',
  'provisioningTime',
  'startTime',
  'endTime',
  'lastSyncTime',
  'changedTime',
  'etag',
  'managedBy',
  '_accountId',
  '_accountLabel',
  '_sourceFile',
  '_vnetId'
]);

const _DIFF_STRUCTURAL = new Set([
  'addressPrefix',
  'addressSpace',
  'location',
  'vmSize',
  'version',
  'sku',
  'vnetId',
  'subnetId',
  'destinationPortRange',
  'sourceAddressPrefix',
  'destinationAddressPrefix',
  'access',
  'direction',
  'priority',
  'protocol',
  'zones',
  'kubernetesVersion',
  'replicasPerMaster',
  'diskSizeGB',
  'tier'
]);

function normalizeResource(resource) {
  const clone = structuredClone(resource);

  function walk(value) {
    if (!value || typeof value !== 'object') return value;
    if (Array.isArray(value)) {
      return value
        .map(walk)
        .map(item => ({ item, sortKey: JSON.stringify(item) }))
        .sort((a, b) => a.sortKey.localeCompare(b.sortKey))
        .map(row => row.item);
    }

    const output = {};
    Object.keys(value).sort().forEach(key => {
      if (_DIFF_VOLATILE.has(key)) return;
      output[key] = walk(value[key]);
    });
    return output;
  }

  return walk(clone);
}

function normalizeNSG(nsg) {
  const clone = structuredClone(nsg);

  function sortRules(rules) {
    if (!Array.isArray(rules)) return rules;
    return rules.slice().sort((a, b) => {
      const left = (a.properties && a.properties.direction || '') + '-' +
        (a.properties && a.properties.priority || 0);
      const right = (b.properties && b.properties.direction || '') + '-' +
        (b.properties && b.properties.priority || 0);
      return left.localeCompare(right);
    });
  }

  if (clone.properties && clone.properties.securityRules) {
    clone.properties.securityRules = sortRules(clone.properties.securityRules);
  }
  if (clone.properties && clone.properties.defaultSecurityRules) {
    clone.properties.defaultSecurityRules = sortRules(clone.properties.defaultSecurityRules);
  }
  return normalizeResource(clone);
}

function classifyChange(field) {
  if (_DIFF_STRUCTURAL.has(field)) return 'structural';
  if (field === 'tags' || field === 'name' || field === 'description') return 'metadata';
  return 'structural';
}

function _fieldDiff(normA, normB, path) {
  const changes = [];
  if (normA === normB) return changes;

  if (typeof normA !== typeof normB || normA === null || normB === null || typeof normA !== 'object') {
    changes.push({
      field: path,
      old: normA,
      new: normB,
      kind: classifyChange(path.split('.').pop())
    });
    return changes;
  }

  if (Array.isArray(normA) && Array.isArray(normB)) {
    if (JSON.stringify(normA) !== JSON.stringify(normB)) {
      changes.push({
        field: path,
        old: normA,
        new: normB,
        kind: classifyChange(path.split('.').pop())
      });
    }
    return changes;
  }

  const allKeys = new Set([...Object.keys(normA), ...Object.keys(normB)]);
  allKeys.forEach(key => {
    const subPath = path ? path + '.' + key : key;
    if (!(key in normA)) {
      changes.push({ field: subPath, old: undefined, new: normB[key], kind: classifyChange(key) });
      return;
    }
    if (!(key in normB)) {
      changes.push({ field: subPath, old: normA[key], new: undefined, kind: classifyChange(key) });
      return;
    }

    const left = JSON.stringify(normA[key]);
    const right = JSON.stringify(normB[key]);
    if (left === right) return;

    if (typeof normA[key] === 'object' && typeof normB[key] === 'object' && normA[key] && normB[key]) {
      changes.push(..._fieldDiff(normA[key], normB[key], subPath));
    } else {
      changes.push({
        field: subPath,
        old: normA[key],
        new: normB[key],
        kind: classifyChange(key)
      });
    }
  });

  return changes;
}

function computeDiff(baseline, current) {
  const results = {
    added: [],
    removed: [],
    modified: [],
    unchanged: [],
    total: { added: 0, removed: 0, modified: 0, unchanged: 0 }
  };

  Object.entries(_DIFF_KEYS).forEach(([type, primaryKey]) => {
    const baselineItems = baseline[type] || [];
    const currentItems = current[type] || [];
    const baselineByKey = indexByKey(baselineItems, primaryKey);
    const currentByKey = indexByKey(currentItems, primaryKey);

    currentByKey.forEach((resource, key) => {
      if (baselineByKey.has(key)) return;
      results.added.push({ type, key, name: _diffResName(resource, key), resource });
      results.total.added++;
    });

    baselineByKey.forEach((resource, key) => {
      if (currentByKey.has(key)) return;
      results.removed.push({ type, key, name: _diffResName(resource, key), resource });
      results.total.removed++;
    });

    baselineByKey.forEach((baselineResource, key) => {
      if (!currentByKey.has(key)) return;
      const currentResource = currentByKey.get(key);
      const normalizedBaseline = type === 'nsgs'
        ? normalizeNSG(baselineResource)
        : normalizeResource(baselineResource);
      const normalizedCurrent = type === 'nsgs'
        ? normalizeNSG(currentResource)
        : normalizeResource(currentResource);
      const fields = _fieldDiff(normalizedBaseline, normalizedCurrent, '');

      if (!fields.length) {
        results.unchanged.push({ type, key, name: _diffResName(currentResource, key), resource: currentResource });
        results.total.unchanged++;
        return;
      }

      results.modified.push({
        type,
        key,
        name: _diffResName(currentResource, key),
        fields,
        hasStructural: fields.some(field => field.kind === 'structural'),
        resource: currentResource,
        baseline: baselineResource
      });
      results.total.modified++;
    });
  });

  return results;
}

function indexByKey(items, primaryKey) {
  const indexed = new Map();
  items.forEach(item => {
    const key = item && item[primaryKey];
    if (key) indexed.set(key, item);
  });
  return indexed;
}

function _diffResName(resource, fallback) {
  if (!resource) return fallback;
  return resource.name || resource.id || fallback;
}

function _buildCtxFromTextareas(textareas) {
  function parseTextarea(id) {
    const raw = textareas[id];
    if (!raw) return [];
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.value)) return parsed.value;
    return [];
  }

  function parseFirstPresent(type) {
    const ids = _DIFF_TEXTAREA_IDS[type] || [];
    for (const id of ids) {
      if (!Object.prototype.hasOwnProperty.call(textareas, id)) continue;
      if (!textareas[id]) continue;
      return parseTextarea(id);
    }
    return [];
  }

  return Object.fromEntries(
    Object.keys(_DIFF_TEXTAREA_IDS).map(type => [type, parseFirstPresent(type)])
  );
}

export {
  _DIFF_KEYS,
  _DIFF_TEXTAREA_IDS,
  _DIFF_VOLATILE,
  _DIFF_STRUCTURAL,
  normalizeResource,
  normalizeNSG,
  classifyChange,
  _fieldDiff,
  computeDiff,
  _diffResName,
  _buildCtxFromTextareas
};
