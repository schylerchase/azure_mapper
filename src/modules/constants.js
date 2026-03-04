// Core constants used across the application
// Azure Network Mapper — rewritten from AWS equivalents

// Severity ordering for sorting findings
export const SEV_ORDER = {
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 3,
  LOW: 4
};

// Framework display labels
export const FW_LABELS = {
  CIS:          'CIS Azure Foundations 3.0',
  WAF:          'Azure CAF (Cloud Adoption Framework)',
  RBAC:         'RBAC (Role-Based Access Control)',
  ARCH:         'Azure Architecture',
  SOC2:         'SOC 2',
  PCI:          'PCI DSS 4.0',
  BUDR:         'Backup & DR (Azure Backup / Recovery Services)',
  FEDRAMP_MOD:  'FedRAMP Moderate',
  FEDRAMP_HIGH: 'FedRAMP High',
  NIST_800_171: 'NIST SP 800-171',
  CMMC:         'CMMC Level 2',
  DOD_IL5:      'DoD Impact Level 5'
};

// End-of-life Azure Function runtimes
export const EOL_RUNTIMES = new Set([
  // Node.js
  'node|14', 'node|16',
  // Python
  'python|3.8', 'python|3.9',
  // .NET
  'dotnet|6',
  // Java
  'java|8'
]);

// Effort estimation labels
export const EFFORT_LABELS = {
  low:  'Low',
  med:  'Med',
  high: 'High'
};

// Effort time estimates
export const EFFORT_TIME = {
  low:  '~5 min',
  med:  '~1-2 hrs',
  high: '~1+ days'
};

// Priority/tier metadata (colors, labels)
export const PRIORITY_META = {
  crit: {
    name:   'Critical',
    color:  '#ef4444',
    bg:     'rgba(239,68,68,.08)',
    border: 'rgba(239,68,68,.3)'
  },
  high: {
    name:   'High',
    color:  '#f97316',
    bg:     'rgba(249,115,22,.08)',
    border: 'rgba(249,115,22,.3)'
  },
  med: {
    name:   'Medium',
    color:  '#f59e0b',
    bg:     'rgba(245,158,11,.08)',
    border: 'rgba(245,158,11,.3)'
  },
  low: {
    name:   'Low',
    color:  '#3b82f6',
    bg:     'rgba(59,130,246,.08)',
    border: 'rgba(59,130,246,.3)'
  }
};

// Alias for backward compatibility
export const TIER_META = PRIORITY_META;

// Priority ordering for sorting
export const PRIORITY_ORDER = {
  crit: 1,
  high: 2,
  med:  3,
  low:  4
};

// Priority keys in order
export const PRIORITY_KEYS = ['crit', 'high', 'med', 'low'];

// LocalStorage keys
export const MUTE_KEY  = 'azureMapper_muted_findings';
export const NOTES_KEY = 'azureMapper_annotations';
export const SNAP_KEY  = 'azureMapper_snapshots';
export const SAVE_KEY  = 'azureMapper_session';

// App configuration
export const MAX_SNAPSHOTS = 30;
export const SAVE_INTERVAL = 30000; // 30 seconds

// Note categories
export const NOTE_CATEGORIES = [
  'owner',
  'status',
  'incident',
  'todo',
  'info',
  'warning'
];
