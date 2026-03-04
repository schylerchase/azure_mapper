// Azure cloud environment detection and configuration
// Supports: Commercial, GCC, GCC High, DoD

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const CLOUDS = {
  COMMERCIAL: 'commercial',
  GCC:        'gcc',
  GCC_HIGH:   'gcc-high',
  DOD:        'dod'
};

const VALID_CLOUDS = new Set(Object.values(CLOUDS));

// Per-cloud endpoint and compliance metadata
const CLOUD_CONFIG = {
  commercial: {
    name:                'Azure Commercial',
    azCloudName:         'AzureCloud',
    managementEndpoint:  'https://management.azure.com',
    aadEndpoint:         'https://login.microsoftonline.com',
    portalUrl:           'https://portal.azure.com',
    complianceFrameworks: ['CIS', 'CAF', 'SOC2', 'PCI', 'BUDR', 'RBAC']
  },
  gcc: {
    // GCC uses Commercial endpoints but is policy-restricted to US-only tenants
    name:                'Azure Government (GCC)',
    azCloudName:         'AzureCloud',
    managementEndpoint:  'https://management.azure.com',
    aadEndpoint:         'https://login.microsoftonline.com',
    portalUrl:           'https://portal.azure.com',
    complianceFrameworks: ['CIS', 'CAF', 'SOC2', 'PCI', 'BUDR', 'RBAC', 'FEDRAMP_MOD']
  },
  'gcc-high': {
    name:                'Azure Government (GCC High)',
    azCloudName:         'AzureUSGovernment',
    managementEndpoint:  'https://management.usgovcloudapi.net',
    aadEndpoint:         'https://login.microsoftonline.us',
    portalUrl:           'https://portal.azure.us',
    complianceFrameworks: ['CIS', 'CAF', 'SOC2', 'PCI', 'BUDR', 'RBAC', 'FEDRAMP_HIGH', 'NIST_800_171', 'CMMC']
  },
  dod: {
    name:                'Azure Government (DoD)',
    azCloudName:         'AzureUSGovernment',
    managementEndpoint:  'https://management.usgovcloudapi.net',
    aadEndpoint:         'https://login.microsoftonline.us',
    portalUrl:           'https://portal.azure.us',
    complianceFrameworks: ['CIS', 'CAF', 'SOC2', 'PCI', 'BUDR', 'RBAC', 'FEDRAMP_HIGH', 'NIST_800_171', 'CMMC', 'DOD_IL5']
  }
};

// Resource types unavailable in sovereign clouds (not present → fully available)
const RESTRICTED_SERVICES = {
  'gcc-high': new Set([
    'Microsoft.Cdn/profiles',
    'Microsoft.BotService/botServices',
    'Microsoft.Maps/accounts',
    'Microsoft.CognitiveServices/accounts',
    'Microsoft.HealthcareApis/services'
  ]),
  dod: new Set([
    'Microsoft.Cdn/profiles',
    'Microsoft.BotService/botServices',
    'Microsoft.Maps/accounts',
    'Microsoft.CognitiveServices/accounts',
    'Microsoft.HealthcareApis/services',
    'Microsoft.Synapse/workspaces',
    'Microsoft.MachineLearningServices/workspaces',
    'Microsoft.DataFactory/factories'
  ])
};

// Endpoint-to-cloud mapping used by detectCloudFromEndpoint()
const ENDPOINT_CLOUD_MAP = [
  { pattern: 'management.usgovcloudapi.net', cloud: CLOUDS.GCC_HIGH }, // refined later by context
  { pattern: 'management.azure.com',         cloud: CLOUDS.COMMERCIAL }
];

// ---------------------------------------------------------------------------
// Module-level state
// ---------------------------------------------------------------------------

let _currentCloud = CLOUDS.COMMERCIAL;

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/** Returns the currently active cloud environment string. */
export function getCloudEnv() {
  return _currentCloud;
}

/**
 * Sets the active cloud environment.
 * Throws if the value is not a member of CLOUDS.
 */
export function setCloudEnv(env) {
  if (!VALID_CLOUDS.has(env)) {
    throw new Error(`Invalid cloud environment "${env}". Valid values: ${[...VALID_CLOUDS].join(', ')}`);
  }
  _currentCloud = env;
}

/**
 * Returns the full config object for the given cloud.
 * Falls back to the current cloud when env is omitted.
 */
export function getCloudConfig(env = _currentCloud) {
  const config = CLOUD_CONFIG[env];
  if (!config) {
    throw new Error(`No configuration found for cloud "${env}"`);
  }
  return config;
}

/**
 * Returns the array of compliance framework IDs active for the given cloud.
 * Falls back to the current cloud when env is omitted.
 */
export function getComplianceFrameworks(env = _currentCloud) {
  return getCloudConfig(env).complianceFrameworks.slice(); // return a copy
}

/**
 * Returns true when resourceType (e.g. "Microsoft.Cdn/profiles") is available
 * in the given cloud. Falls back to the current cloud when env is omitted.
 */
export function isServiceAvailable(resourceType, env = _currentCloud) {
  const restricted = RESTRICTED_SERVICES[env];
  if (!restricted) return true;                  // Commercial and GCC have no block-list
  return !restricted.has(resourceType);
}

/**
 * Builds the Azure portal deep-link URL for a resource ID.
 * Falls back to the current cloud when env is omitted.
 *
 * @param {string} resourceId  Full ARM resource ID starting with /subscriptions/...
 * @param {string} [env]
 * @returns {string}
 */
export function getPortalUrl(resourceId, env = _currentCloud) {
  const { portalUrl } = getCloudConfig(env);
  const encoded = encodeURIComponent(resourceId);
  return `${portalUrl}/#@/resource${encoded}`;
}

/**
 * Auto-detects the cloud from a management API endpoint URL.
 * Returns null when the endpoint is unrecognised.
 *
 * Note: Both GCC High and DoD share the same management endpoint
 * (usgovcloudapi.net), so this function returns CLOUDS.GCC_HIGH for
 * that endpoint — callers that need DoD precision should check the
 * subscription's offer ID or tenant domain out-of-band.
 *
 * @param {string} managementUrl
 * @returns {string|null}
 */
export function detectCloudFromEndpoint(managementUrl) {
  if (typeof managementUrl !== 'string') return null;
  const url = managementUrl.toLowerCase();
  for (const { pattern, cloud } of ENDPOINT_CLOUD_MAP) {
    if (url.includes(pattern)) return cloud;
  }
  return null;
}
