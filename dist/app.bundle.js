var AppBundle = (() => {
  var __defProp = Object.defineProperty;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };

  // src/modules/constants.js
  var SEV_ORDER = {
    CRITICAL: 1,
    HIGH: 2,
    MEDIUM: 3,
    LOW: 4
  };
  var FW_LABELS = {
    CIS: "CIS Azure Foundations 3.0",
    WAF: "Azure CAF (Cloud Adoption Framework)",
    RBAC: "RBAC (Role-Based Access Control)",
    ARCH: "Azure Architecture",
    SOC2: "SOC 2",
    PCI: "PCI DSS 4.0",
    BUDR: "Backup & DR (Azure Backup / Recovery Services)",
    FEDRAMP_MOD: "FedRAMP Moderate",
    FEDRAMP_HIGH: "FedRAMP High",
    NIST_800_171: "NIST SP 800-171",
    CMMC: "CMMC Level 2",
    DOD_IL5: "DoD Impact Level 5"
  };
  var EOL_RUNTIMES = /* @__PURE__ */ new Set([
    // Node.js
    "node|14",
    "node|16",
    // Python
    "python|3.8",
    "python|3.9",
    // .NET
    "dotnet|6",
    // Java
    "java|8"
  ]);
  var EFFORT_LABELS = {
    low: "Low",
    med: "Med",
    high: "High"
  };
  var EFFORT_TIME = {
    low: "~5 min",
    med: "~1-2 hrs",
    high: "~1+ days"
  };
  var PRIORITY_META = {
    crit: {
      name: "Critical",
      color: "#ef4444",
      bg: "rgba(239,68,68,.08)",
      border: "rgba(239,68,68,.3)"
    },
    high: {
      name: "High",
      color: "#f97316",
      bg: "rgba(249,115,22,.08)",
      border: "rgba(249,115,22,.3)"
    },
    med: {
      name: "Medium",
      color: "#f59e0b",
      bg: "rgba(245,158,11,.08)",
      border: "rgba(245,158,11,.3)"
    },
    low: {
      name: "Low",
      color: "#3b82f6",
      bg: "rgba(59,130,246,.08)",
      border: "rgba(59,130,246,.3)"
    }
  };
  var TIER_META = PRIORITY_META;
  var PRIORITY_ORDER = {
    crit: 1,
    high: 2,
    med: 3,
    low: 4
  };
  var PRIORITY_KEYS = ["crit", "high", "med", "low"];
  var MUTE_KEY = "azureMapper_muted_findings";
  var NOTES_KEY = "azureMapper_annotations";
  var SNAP_KEY = "azureMapper_snapshots";
  var SAVE_KEY = "azureMapper_session";
  var MAX_SNAPSHOTS = 30;
  var SAVE_INTERVAL = 3e4;
  var NOTE_CATEGORIES = [
    "owner",
    "status",
    "incident",
    "todo",
    "info",
    "warning"
  ];

  // src/modules/utils.js
  var MAX_PARSE_BYTES = 50 * 1024 * 1024;
  function safeParse(t) {
    if (!t || !t.trim()) return null;
    if (t.length > MAX_PARSE_BYTES) {
      console.warn(`safeParse: input exceeds ${MAX_PARSE_BYTES / 1024 / 1024} MB limit (${(t.length / 1024 / 1024).toFixed(1)} MB): rejected`);
      return null;
    }
    try {
      return JSON.parse(t.trim());
    } catch (e) {
      const b = [];
      let d = 0, s = -1;
      for (let i = 0; i < t.length; i++) {
        if (t[i] === "{") {
          if (d === 0) s = i;
          d++;
        }
        if (t[i] === "}") {
          d--;
          if (d === 0 && s >= 0) {
            b.push(t.substring(s, i + 1));
            s = -1;
          }
        }
      }
      return b.length ? b.map((x) => {
        try {
          return JSON.parse(x);
        } catch (e2) {
          return null;
        }
      }).filter(Boolean) : null;
    }
  }
  function ext(r, keys) {
    if (!r) return [];
    const a = Array.isArray(r) ? r : [r];
    let res = [];
    for (const i of a) {
      for (const k of keys) {
        if (i[k]) res = res.concat(i[k]);
      }
    }
    if (!res.length && Array.isArray(r) && r.length && typeof r[0] === "object" && r[0] !== null) {
      if (r[0].id || r[0].name || r[0].type) return r;
    }
    return res;
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function gn(resource) {
    const name = resource.name || resource.id?.split("/").pop() || "";
    return esc(name);
  }
  function sid(id) {
    if (!id) return "";
    const segments = id.split("/").filter(Boolean);
    return segments[segments.length - 1] || "";
  }
  function clsGw(type) {
    if (!type) return "GW";
    const t = type.toLowerCase();
    if (t === "microsoft.network/azurefirewalls") return "fw";
    if (t === "microsoft.network/bastionhosts") return "bastion";
    if (t === "microsoft.network/natgateways") return "nat";
    if (t === "microsoft.network/virtualnetworkgateways") return "vpn";
    if (t === "microsoft.network/applicationgateways") return "appgw";
    if (t === "microsoft.network/privatelinkservices") return "pe";
    return "GW";
  }
  function isShared(t) {
    if (!t) return false;
    const lower = t.toLowerCase();
    return lower === "fw" || lower === "bastion" || lower === "vpn" || lower === "nat" || lower === "microsoft.network/azurefirewalls" || lower === "microsoft.network/bastionhosts" || lower === "microsoft.network/virtualnetworkgateways" || lower === "microsoft.network/natgateways";
  }
  function gcv(t) {
    return {
      fw: "var(--fw-color)",
      bastion: "var(--bastion-color)",
      nat: "var(--nat-color)",
      vpn: "var(--vpn-color)",
      appgw: "var(--appgw-color)",
      pe: "var(--pe-color)",
      vwan: "var(--vwan-color)",
      peer: "var(--peer-color)"
    }[t] || "var(--text-muted)";
  }
  function gch(t) {
    return {
      fw: "#ef4444",
      bastion: "#10b981",
      nat: "#f59e0b",
      vpn: "#3b82f6",
      appgw: "#8b5cf6",
      pe: "#a78bfa",
      vwan: "#ec4899",
      peer: "#fb923c"
    }[t] || "#4a5e80";
  }
  function gv(id) {
    return (document.getElementById(id) || {}).value || "";
  }
  function parseResourceId(id) {
    const empty = {
      subscriptionId: "",
      resourceGroup: "",
      provider: "",
      resourceType: "",
      name: "",
      subType: "",
      subName: "",
      raw: id || ""
    };
    if (!id) return empty;
    const parts = id.replace(/^\//, "").split("/");
    if (parts.length < 8 || parts[0].toLowerCase() !== "subscriptions") return empty;
    return {
      subscriptionId: parts[1] || "",
      resourceGroup: parts[3] || "",
      provider: parts[5] || "",
      resourceType: parts[6] || "",
      name: parts[7] || "",
      subType: parts[8] || "",
      subName: parts[9] || "",
      raw: id
    };
  }
  function getTenantFromResource(resource) {
    if (!resource) return "";
    if (resource.tenantId) return resource.tenantId;
    if (resource.identity?.tenantId) return resource.identity.tenantId;
    if (resource.extendedProperties?.tenantId) return resource.extendedProperties.tenantId;
    return "";
  }

  // src/modules/dom-helpers.js
  var _toastEl = null;
  var _toastTimer = null;
  function showToast(msg, duration = 3e3) {
    if (!_toastEl) {
      _toastEl = document.createElement("div");
      _toastEl.style.cssText = `
      position:fixed;bottom:60px;left:50%;transform:translateX(-50%);z-index:300;
      background:var(--accent-green);color:#000;padding:8px 20px;border-radius:6px;
      font-family:Segoe UI,system-ui,sans-serif;font-size:12px;font-weight:600;
      box-shadow:0 4px 12px rgba(0,0,0,.4);transition:opacity .3s
    `;
      document.body.appendChild(_toastEl);
    }
    clearTimeout(_toastTimer);
    _toastEl.textContent = msg;
    _toastEl.style.opacity = "1";
    _toastTimer = setTimeout(() => {
      _toastEl.style.opacity = "0";
    }, duration);
  }
  function closeAllDashboards(except) {
    const ids = ["udash", "diffDash", "notesPanel"];
    ids.forEach(function(id) {
      if (id === except) return;
      const el = document.getElementById(id);
      if (el && el.classList.contains("open")) {
        el.classList.remove("open");
      }
    });
    if (except !== "udash" && typeof window.setUdashTab === "function") {
      window.setUdashTab(null);
    } else if (except !== "udash" && window._udashTab !== void 0) {
      window._udashTab = null;
    }
  }
  function toggleClass(el, className) {
    const element = typeof el === "string" ? document.getElementById(el) : el;
    if (!element) return false;
    const hasClass = element.classList.contains(className);
    element.classList.toggle(className);
    return !hasClass;
  }
  function setVisible(el, visible) {
    const element = typeof el === "string" ? document.getElementById(el) : el;
    if (!element) return;
    element.style.display = visible ? "" : "none";
  }
  function getEl(id) {
    return document.getElementById(id);
  }
  function qs(selector, parent = document) {
    return parent.querySelector(selector);
  }
  function qsa(selector, parent = document) {
    return Array.from(parent.querySelectorAll(selector));
  }

  // src/modules/prefs.js
  var PREFS_KEY = "azureNetMapPrefs";
  function loadPrefs() {
    try {
      const r = localStorage.getItem(PREFS_KEY);
      return r ? JSON.parse(r) : {};
    } catch (e) {
      return {};
    }
  }
  var _prefs = Object.assign(/* @__PURE__ */ Object.create(null), loadPrefs());
  function savePrefs(p) {
    for (const k of Object.keys(p)) {
      if (!Object.hasOwn(p, k)) continue;
      _prefs[k] = p[k];
    }
    try {
      localStorage.setItem(PREFS_KEY, JSON.stringify(_prefs));
    } catch (e) {
    }
  }

  // src/modules/cloud-env.js
  var CLOUDS = {
    COMMERCIAL: "commercial",
    GCC: "gcc",
    GCC_HIGH: "gcc-high",
    DOD: "dod"
  };
  var VALID_CLOUDS = new Set(Object.values(CLOUDS));
  var CLOUD_CONFIG = {
    commercial: {
      name: "Azure Commercial",
      azCloudName: "AzureCloud",
      managementEndpoint: "https://management.azure.com",
      aadEndpoint: "https://login.microsoftonline.com",
      portalUrl: "https://portal.azure.com",
      complianceFrameworks: ["CIS", "CAF", "SOC2", "PCI", "BUDR", "RBAC"]
    },
    gcc: {
      // GCC uses Commercial endpoints but is policy-restricted to US-only tenants
      name: "Azure Government (GCC)",
      azCloudName: "AzureCloud",
      managementEndpoint: "https://management.azure.com",
      aadEndpoint: "https://login.microsoftonline.com",
      portalUrl: "https://portal.azure.com",
      complianceFrameworks: ["CIS", "CAF", "SOC2", "PCI", "BUDR", "RBAC", "FEDRAMP_MOD"]
    },
    "gcc-high": {
      name: "Azure Government (GCC High)",
      azCloudName: "AzureUSGovernment",
      managementEndpoint: "https://management.usgovcloudapi.net",
      aadEndpoint: "https://login.microsoftonline.us",
      portalUrl: "https://portal.azure.us",
      complianceFrameworks: ["CIS", "CAF", "SOC2", "PCI", "BUDR", "RBAC", "FEDRAMP_HIGH", "NIST_800_171", "CMMC"]
    },
    dod: {
      name: "Azure Government (DoD)",
      azCloudName: "AzureUSGovernment",
      managementEndpoint: "https://management.usgovcloudapi.net",
      aadEndpoint: "https://login.microsoftonline.us",
      portalUrl: "https://portal.azure.us",
      complianceFrameworks: ["CIS", "CAF", "SOC2", "PCI", "BUDR", "RBAC", "FEDRAMP_HIGH", "NIST_800_171", "CMMC", "DOD_IL5"]
    }
  };
  var RESTRICTED_SERVICES = {
    "gcc-high": /* @__PURE__ */ new Set([
      "Microsoft.Cdn/profiles",
      "Microsoft.BotService/botServices",
      "Microsoft.Maps/accounts",
      "Microsoft.CognitiveServices/accounts",
      "Microsoft.HealthcareApis/services"
    ]),
    dod: /* @__PURE__ */ new Set([
      "Microsoft.Cdn/profiles",
      "Microsoft.BotService/botServices",
      "Microsoft.Maps/accounts",
      "Microsoft.CognitiveServices/accounts",
      "Microsoft.HealthcareApis/services",
      "Microsoft.Synapse/workspaces",
      "Microsoft.MachineLearningServices/workspaces",
      "Microsoft.DataFactory/factories"
    ])
  };
  var ENDPOINT_CLOUD_MAP = [
    { pattern: "management.usgovcloudapi.net", cloud: CLOUDS.GCC_HIGH },
    // refined later by context
    { pattern: "management.azure.com", cloud: CLOUDS.COMMERCIAL }
  ];
  var _currentCloud = CLOUDS.COMMERCIAL;
  function getCloudEnv() {
    return _currentCloud;
  }
  function setCloudEnv(env) {
    if (!VALID_CLOUDS.has(env)) {
      throw new Error(`Invalid cloud environment "${env}". Valid values: ${[...VALID_CLOUDS].join(", ")}`);
    }
    _currentCloud = env;
  }
  function getCloudConfig(env = _currentCloud) {
    const config = CLOUD_CONFIG[env];
    if (!config) {
      throw new Error(`No configuration found for cloud "${env}"`);
    }
    return config;
  }
  function getComplianceFrameworks(env = _currentCloud) {
    return getCloudConfig(env).complianceFrameworks.slice();
  }
  function isServiceAvailable(resourceType, env = _currentCloud) {
    const restricted = RESTRICTED_SERVICES[env];
    if (!restricted) return true;
    return !restricted.has(resourceType);
  }
  function getPortalUrl(resourceId, env = _currentCloud) {
    const { portalUrl } = getCloudConfig(env);
    const encoded = encodeURIComponent(resourceId);
    return `${portalUrl}/#@/resource${encoded}`;
  }
  function detectCloudFromEndpoint(managementUrl) {
    if (typeof managementUrl !== "string") return null;
    const url = managementUrl.toLowerCase();
    for (const { pattern, cloud } of ENDPOINT_CLOUD_MAP) {
      if (url.includes(pattern)) return cloud;
    }
    return null;
  }

  // src/modules/cidr-engine.js
  var ipToInt = (ip) => {
    if (!ip || typeof ip !== "string") return null;
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    let n = 0;
    for (let i = 0; i < 4; i++) {
      const o = parseInt(parts[i], 10);
      if (isNaN(o) || o < 0 || o > 255 || parts[i] !== String(o)) return null;
      n = n * 256 + o;
    }
    return n >>> 0;
  };
  var intToIp = (n) => {
    n = n >>> 0;
    return `${n >>> 24 & 255}.${n >>> 16 & 255}.${n >>> 8 & 255}.${n & 255}`;
  };
  var parseCIDR = (cidr) => {
    if (!cidr || typeof cidr !== "string") return null;
    const parts = cidr.trim().split("/");
    if (parts.length !== 2) return null;
    const network = ipToInt(parts[0]);
    const prefix = parseInt(parts[1], 10);
    if (network === null || isNaN(prefix) || prefix < 0 || prefix > 32 || parts[1] !== String(prefix)) return null;
    const mask = prefix === 0 ? 0 : 4294967295 << 32 - prefix >>> 0;
    if ((network & mask) >>> 0 !== network) return null;
    const size = prefix === 32 ? 1 : 1 << 32 - prefix >>> 0;
    return { network, prefix, mask, size };
  };
  var cidrToString = (network, prefix) => {
    return `${intToIp(network)}/${prefix}`;
  };
  var splitCIDR = (cidr) => {
    const p = parseCIDR(cidr);
    if (!p || p.prefix >= 32) return null;
    const np = p.prefix + 1;
    const half = p.size >>> 1;
    return [cidrToString(p.network, np), cidrToString(p.network + half >>> 0, np)];
  };
  var cidrContains = (parent, child) => {
    const p = parseCIDR(parent);
    const c = parseCIDR(child);
    if (!p || !c || c.prefix < p.prefix) return false;
    return (c.network & p.mask) >>> 0 === p.network;
  };
  var cidrOverlap = (a, b) => {
    const pa = parseCIDR(a);
    const pb = parseCIDR(b);
    if (!pa || !pb) return false;
    const bigger = pa.prefix <= pb.prefix ? pa : pb;
    const smaller = pa.prefix <= pb.prefix ? pb : pa;
    return (smaller.network & bigger.mask) >>> 0 === bigger.network;
  };
  var ipInCIDR = (ip, cidr) => {
    const n = ipToInt(ip);
    const p = parseCIDR(cidr);
    if (n === null || !p) return false;
    return (n & p.mask) >>> 0 === p.network;
  };

  // src/modules/budr-engine.js
  function _getClassificationData() {
    return window._classificationData || [];
  }
  function _runClassificationEngine(ctx) {
    if (typeof window.runClassificationEngine === "function") window.runClassificationEngine(ctx);
  }
  var _BUDR_STRATEGY = { hot: "Hot", warm: "Warm", pilot: "Pilot Light", cold: "Cold" };
  var _BUDR_STRATEGY_ORDER = { hot: 0, warm: 1, pilot: 2, cold: 3 };
  var _BUDR_STRATEGY_LEGEND = [
    { k: "critical", label: "Critical (Hot)", color: "#ef4444", icon: "", desc: "Active-active: full replica running at all times. Near-zero RTO & RPO." },
    { k: "high", label: "High (Warm)", color: "#f59e0b", icon: "", desc: "Scaled-down replica running. Scale up on failover. Minutes to recover." },
    { k: "medium", label: "Medium (Pilot Light)", color: "#6366f1", icon: "", desc: "Data replicated continuously, compute stopped. Spin up on failover. ~10-30 min." },
    { k: "low", label: "Low (Cold)", color: "#64748b", icon: "", desc: "Backups only, no standby. Rebuild from scratch. Hours to recover." }
  ];
  var _BUDR_RTO_RPO = {
    sql_zone_redundant: { rto: "~5 min", rpo: "~1 min", tier: "protected", strategy: "warm" },
    sql_single_backup: { rto: "~30 min", rpo: "~24 hr", tier: "partial", strategy: "pilot" },
    sql_no_backup: { rto: "~8 hr", rpo: "total loss", tier: "at_risk", strategy: "cold" },
    vm_vmss: { rto: "~3 min", rpo: "0 (stateless)", tier: "protected", strategy: "warm" },
    vm_disk_snap: { rto: "~15 min", rpo: "~7 days", tier: "partial", strategy: "pilot" },
    vm_standalone: { rto: "~8 hr", rpo: "total loss", tier: "at_risk", strategy: "cold" },
    container_multi: { rto: "~1 min", rpo: "0 (stateless)", tier: "protected", strategy: "hot" },
    container_single: { rto: "~5 min", rpo: "0 (stateless)", tier: "partial", strategy: "warm" },
    function_app: { rto: "0 (managed)", rpo: "0 (stateless)", tier: "protected", strategy: "hot" },
    redis_zone_redundant: { rto: "~2 min", rpo: "~seconds", tier: "protected", strategy: "warm" },
    redis_single: { rto: "~15 min", rpo: "~7 days", tier: "partial", strategy: "pilot" },
    redis_no_snap: { rto: "~15 min", rpo: "total loss", tier: "at_risk", strategy: "cold" },
    synapse_snap: { rto: "~30 min", rpo: "~8 hr", tier: "partial", strategy: "pilot" },
    synapse_multi: { rto: "~15 min", rpo: "~5 min", tier: "protected", strategy: "warm" },
    synapse_none: { rto: "~8 hr", rpo: "total loss", tier: "at_risk", strategy: "cold" },
    agw_zone_redundant: { rto: "0 (managed)", rpo: "N/A", tier: "protected", strategy: "hot" },
    agw_single_zone: { rto: "~5 min", rpo: "N/A", tier: "partial", strategy: "warm" },
    storage_grs: { rto: "0 (managed)", rpo: "0 (geo-replicated)", tier: "protected", strategy: "hot" },
    storage_ra_grs: { rto: "0 (managed)", rpo: "0 (read-access geo)", tier: "protected", strategy: "hot" },
    storage_lrs: { rto: "0 (managed)", rpo: "total loss on region failure", tier: "at_risk", strategy: "cold" },
    disk_snapshot: { rto: "~15 min", rpo: "~7 days", tier: "partial", strategy: "pilot" },
    disk_no_snap: { rto: "~8 hr", rpo: "total loss", tier: "at_risk", strategy: "cold" }
  };
  var _BUDR_EST_MINUTES = {
    sql_zone_redundant: { rto: 5, rpo: 1, rtoWhy: "Zone-redundant failover completes in 1-2 min; DNS propagation adds ~3 min", rpoWhy: "Synchronous replication across zones: data loss limited to in-flight transactions (~seconds)" },
    sql_single_backup: { rto: 30, rpo: 1440, rtoWhy: "Restore from automated backup requires server provisioning + data load (~20-30 min)", rpoWhy: "Automated backups run daily: worst case RPO is 24 hours since last backup window" },
    sql_no_backup: { rto: 480, rpo: Infinity, rtoWhy: "No backups: requires manual rebuild from application layer or external source", rpoWhy: "No backup mechanism configured: all data since creation is unrecoverable" },
    vm_vmss: { rto: 3, rpo: 0, rtoWhy: "VMSS health probe detects failure (1-2 min) and launches replacement from image (~1-2 min)", rpoWhy: "Stateless compute: no persistent data on instance; state lives in external stores" },
    vm_disk_snap: { rto: 15, rpo: 10080, rtoWhy: "New VM creation + managed disk restore from snapshot (~10-15 min depending on disk size)", rpoWhy: "Snapshot frequency is typically weekly: worst case RPO is 7 days since last snapshot" },
    vm_standalone: { rto: 480, rpo: Infinity, rtoWhy: "No snapshot: requires full OS install, config, and application deployment from scratch", rpoWhy: "No backup mechanism: managed disk data is unrecoverable if VM or disk is lost" },
    container_multi: { rto: 1, rpo: 0, rtoWhy: "Container group scheduler replaces failed containers in ~30-60 sec from registry image", rpoWhy: "Stateless containers: no persistent data; state lives in external stores (SQL, Storage, etc.)" },
    container_single: { rto: 5, rpo: 0, rtoWhy: "Single container replacement takes ~2-5 min including image pull and health check", rpoWhy: "Stateless containers: no persistent data; state lives in external stores" },
    function_app: { rto: 0, rpo: 0, rtoWhy: "Fully managed: Azure handles all availability; cold start adds <1 sec latency", rpoWhy: "Stateless execution: no persistent data; code stored in Storage Account" },
    redis_zone_redundant: { rto: 2, rpo: 0.1, rtoWhy: "Zone-redundant replica promotion takes 1-2 min; DNS endpoint updates automatically", rpoWhy: "Async replication lag is typically <100ms: data loss limited to replication lag" },
    redis_single: { rto: 15, rpo: 10080, rtoWhy: "Restore from RDB snapshot requires new cache provisioning + data load (~10-15 min)", rpoWhy: "Snapshot frequency is typically daily/weekly: worst case RPO equals snapshot interval" },
    redis_no_snap: { rto: 15, rpo: Infinity, rtoWhy: "New cache provisioning takes ~10-15 min but cache starts cold (empty)", rpoWhy: "No snapshots: entire cache contents are lost; must be rebuilt from source of truth" },
    synapse_snap: { rto: 30, rpo: 1440, rtoWhy: "Restore from snapshot creates new workspace (~20-30 min depending on data size)", rpoWhy: "Automated snapshots run periodically by default: worst case RPO is snapshot interval" },
    synapse_multi: { rto: 15, rpo: 5, rtoWhy: "Zone-redundant workspace redistributes work to surviving zones (~10-15 min recovery)", rpoWhy: "Synchronous replication across zones: RPO limited to in-flight queries (~minutes)" },
    synapse_none: { rto: 480, rpo: Infinity, rtoWhy: "No snapshots: requires full data reload from Storage Account/source systems (hours to days)", rpoWhy: "No backup mechanism: all warehouse data is unrecoverable" },
    agw_zone_redundant: { rto: 0, rpo: 0, rtoWhy: "Fully managed zone-redundant: Azure handles node replacement transparently", rpoWhy: "Stateless gateway: no data to lose; config stored in Azure control plane" },
    agw_single_zone: { rto: 5, rpo: 0, rtoWhy: "Single-zone App Gateway may need DNS failover if zone goes down (~3-5 min)", rpoWhy: "Stateless gateway: no data to lose" },
    storage_grs: { rto: 0, rpo: 0, rtoWhy: "Geo-redundant storage replicates across paired regions: always available", rpoWhy: "Objects replicated synchronously within region and asynchronously to paired region" },
    storage_ra_grs: { rto: 0, rpo: 0, rtoWhy: "Read-access geo-redundant storage provides secondary read endpoint", rpoWhy: "Full GRS replication with additional read availability in secondary region" },
    storage_lrs: { rto: 0, rpo: Infinity, rtoWhy: "Locally redundant storage is always available within a region but not across regions", rpoWhy: "No geo-replication: data loss possible if entire region is lost" },
    disk_snapshot: { rto: 15, rpo: 10080, rtoWhy: "Create new managed disk from snapshot + attach to VM (~10-15 min)", rpoWhy: "Snapshot frequency is typically weekly: worst case RPO is 7 days since last snapshot" },
    disk_no_snap: { rto: 480, rpo: Infinity, rtoWhy: "No snapshots: disk data is unrecoverable if disk fails", rpoWhy: "No backup mechanism: all disk data is permanently lost on failure" }
  };
  var _TIER_TARGETS = {
    critical: { rto: 240, rpo: 60, rtoLabel: "2-4 hours", rpoLabel: "Hourly" },
    high: { rto: 480, rpo: 360, rtoLabel: "4-8 hours", rpoLabel: "6 hours" },
    medium: { rto: 720, rpo: 1440, rtoLabel: "12 hours", rpoLabel: "Daily" },
    low: { rto: 1440, rpo: 10080, rtoLabel: "24 hours", rpoLabel: "Weekly" }
  };
  function _budrTierCompliance(profileKey, classTier) {
    if (!profileKey || !classTier) return { status: "unknown", issues: [] };
    var est = _BUDR_EST_MINUTES[profileKey];
    var target = _TIER_TARGETS[classTier];
    if (!est || !target) return { status: "unknown", issues: [] };
    var issues = [];
    if (est.rpo === Infinity) issues.push({ field: "RPO", severity: "critical", msg: "No backup: RPO unrecoverable (target: " + target.rpoLabel + ")" });
    else if (est.rpo > target.rpo) issues.push({ field: "RPO", severity: "warning", msg: "Est. RPO ~" + _fmtMin(est.rpo) + " exceeds " + classTier + " target of " + target.rpoLabel });
    if (est.rto > target.rto) issues.push({ field: "RTO", severity: "warning", msg: "Est. RTO ~" + _fmtMin(est.rto) + " exceeds " + classTier + " target of " + target.rtoLabel });
    var status = issues.some(function(i) {
      return i.severity === "critical";
    }) ? "fail" : issues.length ? "warn" : "pass";
    return { status, issues, estRto: est.rto, estRpo: est.rpo, targetRto: target.rto, targetRpo: target.rpo, rtoWhy: est.rtoWhy || "", rpoWhy: est.rpoWhy || "" };
  }
  function _fmtMin(m) {
    if (m === 0) return "0";
    if (m === Infinity) return "\u221E";
    if (m < 60) return Math.round(m) + " min";
    if (m < 1440) return Math.round(m / 60 * 10) / 10 + " hr";
    return Math.round(m / 1440 * 10) / 10 + " days";
  }
  var budrFindings = [];
  var budrAssessments = [];
  var budrOverrides = {};
  function setBudrFindings(v) {
    budrFindings = v;
  }
  function setBudrAssessments(v) {
    budrAssessments = v;
  }
  function setBudrOverrides(v) {
    budrOverrides = v;
  }
  function runBUDRChecks(ctx) {
    const f = [];
    const assessments = [];
    const gn2 = (o) => o.name || o.id || "unknown";
    (ctx.sqlServers || []).forEach((sql) => {
      const id = sql.id;
      const name = gn2(sql);
      const hasZoneRedundant = !!(sql.properties && sql.properties.zoneRedundant);
      const backupDays = sql.properties && sql.properties.backupRetentionDays || 0;
      const hasBackup = backupDays > 0;
      const geoRedundant = (sql.properties && sql.properties.geoRedundantBackup) === "Enabled";
      const encrypted = !!(sql.properties && sql.properties.storageEncrypted);
      let profile;
      if (hasZoneRedundant && hasBackup) {
        profile = _BUDR_RTO_RPO.sql_zone_redundant;
      } else if (hasBackup) {
        profile = _BUDR_RTO_RPO.sql_single_backup;
        f.push({ severity: "MEDIUM", control: "BUDR-HA-1", framework: "BUDR", resource: id, resourceName: name, message: "SQL Server not zone-redundant: single point of failure", remediation: "Enable zone-redundant deployment for automatic failover" });
      } else {
        profile = _BUDR_RTO_RPO.sql_no_backup;
        f.push({ severity: "CRITICAL", control: "BUDR-BAK-1", framework: "BUDR", resource: id, resourceName: name, message: "SQL Server has no automated backups (retention=0)", remediation: "Set backupRetentionDays to at least 7" });
      }
      if (!hasZoneRedundant && hasBackup)
        f.push({ severity: "HIGH", control: "BUDR-DR-1", framework: "BUDR", resource: id, resourceName: name, message: "SQL Server single-zone with backups only: extended RTO on zone failure", remediation: "Enable zone-redundant deployment or configure geo-replication" });
      assessments.push({ type: "SQL Server", id, name, profile, signals: { ZoneRedundant: hasZoneRedundant, Backup: hasBackup, BackupDays: backupDays, Encrypted: encrypted, GeoRedundant: geoRedundant } });
    });
    const vmssInstIds = /* @__PURE__ */ new Set();
    (ctx.vms || []).forEach((vm) => {
      const tags = vm.tags || {};
      const vmssTag = tags["vmss-name"] || tags["scale-set-name"] || tags["aks-managed-clustername"];
      if (vmssTag) vmssInstIds.add(vm.id);
    });
    (ctx.vms || []).forEach((vm) => {
      const id = vm.id;
      const name = gn2(vm);
      const inVMSS = vmssInstIds.has(id);
      const attachedDisks = (vm.properties && vm.properties.storageProfile && vm.properties.storageProfile.dataDisks || []).map((d) => d.managedDisk && d.managedDisk.id).filter(Boolean);
      const osDiskId = vm.properties && vm.properties.storageProfile && vm.properties.storageProfile.osDisk && vm.properties.storageProfile.osDisk.managedDisk && vm.properties.storageProfile.osDisk.managedDisk.id;
      if (osDiskId) attachedDisks.push(osDiskId);
      const hasSnaps = attachedDisks.some((did) => {
        const s = (ctx.snapByDisk || {})[did];
        return s && s.length > 0;
      });
      let newestSnap = null;
      attachedDisks.forEach((did) => {
        const ss = (ctx.snapByDisk || {})[did] || [];
        ss.forEach((s) => {
          const d = new Date(s.properties && s.properties.timeCreated || 0);
          if (!newestSnap || d > newestSnap) newestSnap = d;
        });
      });
      const snapAgeDays = newestSnap ? Math.floor((Date.now() - newestSnap.getTime()) / 864e5) : null;
      if (hasSnaps && snapAgeDays !== null && snapAgeDays > 7) {
        f.push({ severity: "MEDIUM", control: "BUDR-AGE-1", framework: "BUDR", resource: id, resourceName: name, message: "Newest disk snapshot is " + snapAgeDays + " days old (>7 days)", remediation: "Configure Azure Backup to take disk snapshots at least weekly" });
      }
      const encrypted = attachedDisks.some((did) => {
        const vs = (ctx.disks || []).filter((d) => d.id === did);
        return vs.length && vs[0].properties && vs[0].properties.encryption && vs[0].properties.encryption.type;
      });
      let profile;
      if (inVMSS) {
        profile = _BUDR_RTO_RPO.vm_vmss;
      } else if (hasSnaps) {
        profile = _BUDR_RTO_RPO.vm_disk_snap;
        f.push({ severity: "LOW", control: "BUDR-HA-2", framework: "BUDR", resource: id, resourceName: name, message: "VM not in a VM Scale Set: manual recovery required", remediation: "Deploy behind VMSS or configure Azure Backup for quick recovery" });
      } else {
        profile = _BUDR_RTO_RPO.vm_standalone;
        f.push({ severity: "HIGH", control: "BUDR-BAK-2", framework: "BUDR", resource: id, resourceName: name, message: "VM standalone with no disk snapshots: unrecoverable on failure", remediation: "Create regular disk snapshots via Azure Backup; consider VMSS" });
        if (!inVMSS) f.push({ severity: "MEDIUM", control: "BUDR-DR-2", framework: "BUDR", resource: id, resourceName: name, message: "VM has no disaster recovery strategy", remediation: "Configure Azure Backup, use VMSS with multiple zones, or take disk snapshots" });
      }
      assessments.push({ type: "VM", id, name, profile, signals: { VMSS: inVMSS, Snapshots: hasSnaps, SnapAgeDays: snapAgeDays, Encrypted: encrypted } });
    });
    (ctx.containerInstances || []).forEach((ci) => {
      const id = ci.id;
      const name = gn2(ci);
      const replicas = (ci.properties && ci.properties.containers || []).length;
      const multi = replicas > 1;
      let profile;
      if (multi) {
        profile = _BUDR_RTO_RPO.container_multi;
      } else {
        profile = _BUDR_RTO_RPO.container_single;
        f.push({ severity: "LOW", control: "BUDR-HA-3", framework: "BUDR", resource: id, resourceName: name, message: "Container instance has only " + replicas + " container(s): no redundancy", remediation: "Deploy multiple container instances across availability zones" });
      }
      assessments.push({ type: "Container Instance", id, name, profile, signals: { Containers: replicas, MultiContainer: multi } });
    });
    (ctx.functionApps || []).forEach((fn) => {
      assessments.push({ type: "Function App", id: fn.id, name: gn2(fn), profile: _BUDR_RTO_RPO.function_app, signals: { Managed: true } });
    });
    (ctx.redisCaches || []).forEach((rc) => {
      const id = rc.id;
      const name = gn2(rc);
      const replicas = rc.properties && rc.properties.replicasPerMaster || 0;
      const hasSnap = !!(rc.properties && (rc.properties.rdbBackupEnabled || rc.properties.aofBackupEnabled));
      const zoneRedundant = !!(rc.properties && rc.properties.replicasPerPrimary > 0);
      let profile;
      if (zoneRedundant || replicas > 0) {
        profile = _BUDR_RTO_RPO.redis_zone_redundant;
      } else if (hasSnap) {
        profile = _BUDR_RTO_RPO.redis_single;
        f.push({ severity: "MEDIUM", control: "BUDR-HA-4", framework: "BUDR", resource: id, resourceName: name, message: "Redis Cache single node: failover requires manual intervention", remediation: "Add replicas or enable zone-redundant configuration for automatic failover" });
      } else {
        profile = _BUDR_RTO_RPO.redis_no_snap;
        f.push({ severity: "HIGH", control: "BUDR-BAK-3", framework: "BUDR", resource: id, resourceName: name, message: "Redis Cache single node with no persistence: data loss risk", remediation: "Enable RDB/AOF persistence and add read replicas" });
      }
      assessments.push({ type: "Redis Cache", id, name, profile, signals: { Replicas: replicas, Snapshots: hasSnap, ZoneRedundant: zoneRedundant } });
    });
    (ctx.synapseWorkspaces || []).forEach((sw) => {
      const id = sw.id;
      const name = gn2(sw);
      const hasSnap = !!(sw.properties && sw.properties.managedResourceGroupName);
      const multiZone = !!(sw.properties && (sw.properties.managedVirtualNetworkSettings || sw.properties.workspaceRepositoryConfiguration));
      let profile;
      if (multiZone && hasSnap) {
        profile = _BUDR_RTO_RPO.synapse_multi;
      } else if (hasSnap) {
        profile = _BUDR_RTO_RPO.synapse_snap;
        f.push({ severity: "MEDIUM", control: "BUDR-HA-5", framework: "BUDR", resource: id, resourceName: name, message: "Synapse Workspace without zone-redundant compute: no compute redundancy", remediation: "Enable zone-redundant SQL pools for HA" });
      } else {
        profile = _BUDR_RTO_RPO.synapse_none;
        f.push({ severity: "HIGH", control: "BUDR-BAK-4", framework: "BUDR", resource: id, resourceName: name, message: "Synapse Workspace with no backup configuration: data loss risk", remediation: "Configure automated backups with adequate retention" });
      }
      assessments.push({ type: "Synapse Workspace", id, name, profile, signals: { Snapshots: hasSnap, MultiZone: multiZone } });
    });
    (ctx.appGateways || []).forEach((agw) => {
      const id = agw.id;
      const name = gn2(agw);
      const zones = (agw.zones || []).length;
      let profile;
      if (zones >= 2) {
        profile = _BUDR_RTO_RPO.agw_zone_redundant;
      } else {
        profile = _BUDR_RTO_RPO.agw_single_zone;
        f.push({ severity: "MEDIUM", control: "BUDR-HA-6", framework: "BUDR", resource: id, resourceName: name, message: "App Gateway in single zone only: no failover", remediation: "Deploy across 2+ availability zones" });
      }
      assessments.push({ type: "App Gateway", id, name, profile, signals: { ZoneCount: zones } });
    });
    (ctx.disks || []).forEach((disk) => {
      if ((disk.properties && disk.properties.diskState) !== "Attached") return;
      const id = disk.id;
      const name = gn2(disk);
      const snaps = (ctx.snapByDisk || {})[id] || [];
      if (snaps.length === 0) {
        f.push({ severity: "MEDIUM", control: "BUDR-BAK-5", framework: "BUDR", resource: id, resourceName: name, message: "Attached managed disk has no snapshots", remediation: "Create snapshot schedule via Azure Backup or disk snapshot policy" });
      }
    });
    (ctx.storageAccounts || []).forEach((sa) => {
      const id = sa.id;
      const name = gn2(sa);
      const skuName = sa.properties && sa.properties.sku && sa.properties.sku.name || sa.sku && sa.sku.name || "LRS";
      const isGRS = skuName.includes("GRS") || skuName.includes("GZRS");
      const isRAGRS = skuName.includes("RA-GRS") || skuName.includes("RA-GZRS");
      let profile;
      if (isRAGRS) {
        profile = _BUDR_RTO_RPO.storage_ra_grs;
      } else if (isGRS) {
        profile = _BUDR_RTO_RPO.storage_grs;
      } else {
        profile = _BUDR_RTO_RPO.storage_lrs;
        f.push({ severity: "HIGH", control: "BUDR-STG-1", framework: "BUDR", resource: id, resourceName: name, message: "Storage Account uses LRS: no geo-redundancy, data loss risk on region failure", remediation: "Upgrade to GRS or RA-GRS to protect against regional outages" });
      }
      assessments.push({ type: "Storage Account", id, name, profile, signals: { SKU: skuName, GeoRedundant: isGRS, ReadAccess: isRAGRS } });
    });
    var _budrLookup = {};
    var _bSubVnet = {};
    (ctx.subnets || []).forEach(function(s) {
      if (s.id) _bSubVnet[s.id] = s.properties && s.properties.vnetId || "";
    });
    (ctx.sqlServers || []).forEach(function(r) {
      _budrLookup["SQL Server:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: r.properties && r.properties.vnetId || "" };
    });
    (ctx.vms || []).forEach(function(r) {
      _budrLookup["VM:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: r.properties && r.properties.vnetId || _bSubVnet[r.properties && r.properties.subnetId] || "" };
    });
    (ctx.containerInstances || []).forEach(function(r) {
      var subId = r.properties && r.properties.subnetId;
      _budrLookup["Container Instance:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: subId ? _bSubVnet[subId] || "" : "" };
    });
    (ctx.functionApps || []).forEach(function(r) {
      _budrLookup["Function App:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: r.properties && r.properties.vnetId || "" };
    });
    (ctx.redisCaches || []).forEach(function(r) {
      _budrLookup["Redis Cache:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: r.properties && r.properties.vnetId || "" };
    });
    (ctx.synapseWorkspaces || []).forEach(function(r) {
      _budrLookup["Synapse Workspace:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: "" };
    });
    (ctx.appGateways || []).forEach(function(r) {
      _budrLookup["App Gateway:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: r.properties && r.properties.vnetId || "" };
    });
    (ctx.storageAccounts || []).forEach(function(r) {
      _budrLookup["Storage Account:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: "" };
    });
    (ctx.disks || []).forEach(function(r) {
      _budrLookup["Managed Disk:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: "" };
    });
    (ctx.snapshots || []).forEach(function(r) {
      _budrLookup["Snapshot:" + r.id] = { a: r._accountId || "", r: r.location || r._region || "", v: "" };
    });
    assessments.forEach(function(a) {
      var info = _budrLookup[a.type + ":" + a.id];
      if (info) {
        a.account = info.a;
        a.region = info.r;
        a.vnetId = info.v;
      }
    });
    var _bAccts = /* @__PURE__ */ new Set();
    (ctx.vnets || []).forEach(function(v) {
      if (v._accountId && v._accountId !== "default") _bAccts.add(v._accountId);
    });
    if (_bAccts.size >= 1) {
      var _bPri = [..._bAccts][0];
      assessments.forEach(function(a) {
        if (!a.account) a.account = _bPri;
      });
    }
    var _bResLookup = {};
    Object.keys(_budrLookup).forEach(function(k) {
      var id = k.split(":").slice(1).join(":");
      _bResLookup[id] = _budrLookup[k];
    });
    f.forEach(function(finding) {
      var info = _bResLookup[finding.resource];
      if (info) {
        finding._accountId = info.a;
        finding._region = info.r;
        finding._vnetId = info.v;
      }
    });
    if (_bAccts.size >= 1) {
      var _bPri2 = [..._bAccts][0];
      f.forEach(function(finding) {
        if (!finding._accountId) finding._accountId = _bPri2;
      });
    }
    ;
    budrFindings = f;
    budrAssessments = assessments;
    _enrichBudrWithClassification(ctx, f);
    return f;
  }
  function _enrichBudrWithClassification(ctx, findings) {
    var classData = _getClassificationData();
    if (!classData.length && ctx) _runClassificationEngine(ctx);
    classData = _getClassificationData();
    var classMap = {};
    var classMapTyped = {};
    classData.forEach(function(c) {
      classMap[c.id] = c;
      classMap[c.name] = c;
      classMapTyped[c.type + "|" + c.id] = c;
      classMapTyped[c.type + "|" + c.name] = c;
    });
    budrAssessments.forEach(function(a) {
      var cls = classMapTyped[a.type + "|" + a.id] || classMapTyped[a.type + "|" + a.name] || classMap[a.id] || classMap[a.name];
      a.classTier = cls ? cls.tier : "low";
      a.classVnetName = cls ? cls.vnetName : "";
      var profileKey = null;
      for (var k in _BUDR_RTO_RPO) {
        if (_BUDR_RTO_RPO[k] === a.profile) {
          profileKey = k;
          break;
        }
      }
      a.profileKey = profileKey;
      a.compliance = _budrTierCompliance(profileKey, a.classTier);
      if (a.compliance.issues.length > 0) {
        a.compliance.issues.forEach(function(issue) {
          var sev = issue.severity === "critical" ? "CRITICAL" : "HIGH";
          findings.push({
            severity: sev,
            control: "BUDR-TIER-" + issue.field,
            framework: "BUDR",
            resource: a.id,
            resourceName: a.name,
            message: issue.msg + " [" + a.classTier + " tier]",
            remediation: issue.field === "RPO" ? "Configure automated backups to meet " + a.classTier + " RPO target" : "Improve HA/DR strategy to meet " + a.classTier + " RTO target"
          });
        });
      }
      var ov = budrOverrides[a.id];
      if (ov) {
        a.overridden = true;
        a.autoProfile = { strategy: a.profile.strategy, rto: a.profile.rto, rpo: a.profile.rpo, tier: a.profile.tier };
        if (ov.strategy) {
          a.profile = Object.assign({}, a.profile);
          var sm = { critical: "hot", high: "warm", medium: "pilot", low: "cold" };
          var tm = { critical: "protected", high: "protected", medium: "partial", low: "at_risk" };
          a.profile.strategy = sm[ov.strategy] || ov.strategy;
          a.profile.tier = tm[ov.strategy] || a.profile.tier;
        }
        if (ov.rto) a.profile.rto = ov.rto;
        if (ov.rpo) a.profile.rpo = ov.rpo;
      }
    });
  }
  function _reapplyBUDROverrides() {
    budrAssessments.forEach(function(a) {
      if (a.autoProfile) {
        a.profile = Object.assign({}, a.profile);
        a.profile.strategy = a.autoProfile.strategy;
        a.profile.rto = a.autoProfile.rto;
        a.profile.rpo = a.autoProfile.rpo;
        a.profile.tier = a.autoProfile.tier;
        a.overridden = false;
      }
      var ov = budrOverrides[a.id];
      if (ov) {
        a.overridden = true;
        if (!a.autoProfile) a.autoProfile = { strategy: a.profile.strategy, rto: a.profile.rto, rpo: a.profile.rpo, tier: a.profile.tier };
        a.profile = Object.assign({}, a.profile);
        if (ov.strategy) {
          var sm = { critical: "hot", high: "warm", medium: "pilot", low: "cold" };
          var tm = { critical: "protected", high: "protected", medium: "partial", low: "at_risk" };
          a.profile.strategy = sm[ov.strategy] || ov.strategy;
          a.profile.tier = tm[ov.strategy] || a.profile.tier;
        }
        if (ov.rto) a.profile.rto = ov.rto;
        if (ov.rpo) a.profile.rpo = ov.rpo;
      }
    });
  }
  function _getBUDRTierCounts() {
    const counts = { protected: 0, partial: 0, at_risk: 0 };
    budrAssessments.forEach((a) => {
      if (a.profile) counts[a.profile.tier] = (counts[a.profile.tier] || 0) + 1;
    });
    return counts;
  }
  function _getBudrComplianceCounts() {
    var counts = { pass: 0, warn: 0, fail: 0, unknown: 0 };
    budrAssessments.forEach(function(a) {
      var s = a.compliance ? a.compliance.status : "unknown";
      counts[s] = (counts[s] || 0) + 1;
    });
    return counts;
  }

  // src/modules/iam-engine.js
  var _rbacData = null;
  function getRbacData() {
    return _rbacData;
  }
  var BUILTIN_ROLES = {
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
    "fb1c8493-542b-48eb-b624-b4c8fea62acd": "Security Admin",
    "39bc4728-0917-49c7-9d2c-d95423bc2eb4": "Security Reader",
    "4a9ae827-6dc8-4573-8ac7-8239d42aa03f": "Tag Contributor",
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
    "de139f84-1756-47ae-9be6-808fbbe84772": "Website Contributor",
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner"
  };
  var HIGH_PRIVILEGE_ROLES = ["Owner", "User Access Administrator", "Role Based Access Control Administrator"];
  var WRITE_DELETE_ROLE_NAMES = ["Contributor", "Owner", "User Access Administrator", "Role Based Access Control Administrator"];
  function getScopeLevel(scope) {
    if (!scope) return "resource";
    const lower = scope.toLowerCase();
    if (lower.startsWith("/providers/microsoft.management/managementgroups/")) return "managementGroup";
    const parts = lower.replace(/^\//, "").split("/");
    if (parts[0] === "subscriptions" && parts.length === 2) return "subscription";
    if (parts[0] === "subscriptions" && parts[2] === "resourcegroups" && parts.length === 4) return "resourceGroup";
    if (parts[0] === "subscriptions" && parts.length > 4) return "resource";
    return "resource";
  }
  function classifyPermission(action) {
    if (!action) return "read";
    const lower = action.toLowerCase();
    if (lower === "*") return "admin";
    if (lower.endsWith("/*")) return "admin";
    if (lower.endsWith("/delete") || lower.includes("/delete/")) return "delete";
    if (lower.endsWith("/write") || lower.includes("/write/") || lower.endsWith("/action") || lower.includes("/action/") || lower.endsWith("/start/action") || lower.endsWith("/restart/action") || lower.endsWith("/deallocate/action")) return "write";
    if (lower.endsWith("/read") || lower.includes("/read/") || lower.endsWith("/listkeys/action") || lower.endsWith("/list/action")) return "read";
    return "write";
  }
  function _isWildcardRole(definition) {
    if (!definition) return false;
    const perms = definition.properties?.permissions || definition.permissions || [];
    return perms.some((p) => {
      const actions = p.actions || [];
      return actions.includes("*");
    });
  }
  function _resolveRoleName(roleDefId, definitions) {
    if (!roleDefId) return "Unknown";
    const parts = roleDefId.split("/");
    const guid = parts[parts.length - 1] || "";
    if (BUILTIN_ROLES[guid]) return BUILTIN_ROLES[guid];
    const def = (definitions || []).find(
      (d) => d.id === roleDefId || d.name === guid || d.properties?.roleName === guid
    );
    if (def) return def.properties?.roleName || def.name || "Unknown";
    return guid.length > 12 ? guid.substring(0, 8) + "..." : guid;
  }
  function _findDefinition(roleDefId, definitions) {
    if (!roleDefId || !definitions) return null;
    const parts = roleDefId.split("/");
    const guid = parts[parts.length - 1] || "";
    return definitions.find(
      (d) => d.id === roleDefId || d.name === guid
    ) || null;
  }
  function analyzeRoleAssignments(assignments, definitions) {
    const findings = [];
    if (!assignments || !assignments.length) return findings;
    const defById = /* @__PURE__ */ new Map();
    (definitions || []).forEach((d) => {
      if (d.id) defById.set(d.id, d);
      if (d.name) defById.set(d.name, d);
    });
    const overPrivileged = findOverPrivileged(assignments, definitions);
    overPrivileged.forEach((f) => findings.push(f));
    const orphaned = findOrphanedAssignments(assignments);
    orphaned.forEach((f) => findings.push(f));
    const ownerCounts = countOwnersPerScope(assignments);
    ownerCounts.forEach((f) => findings.push(f));
    const guestRisks = findGuestPrivileges(assignments, definitions);
    guestRisks.forEach((f) => findings.push(f));
    const spRisks = findServicePrincipalRisks(assignments, definitions);
    spRisks.forEach((f) => findings.push(f));
    assignments.forEach((a) => {
      const props = a.properties || a;
      const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
      if (roleName === "CoAdministrator" || roleName === "ServiceAdministrator") {
        findings.push({
          severity: "HIGH",
          control: "RBAC-6",
          framework: "RBAC",
          resource: props.principalId || "",
          resourceName: props.principalDisplayName || props.principalId || "",
          message: 'Classic administrator role "' + roleName + '" still in use',
          remediation: "Migrate to Azure RBAC roles and remove classic administrator assignments"
        });
      }
    });
    assignments.forEach((a) => {
      const props = a.properties || a;
      const scope = props.scope || a.scope || "";
      if (getScopeLevel(scope) === "managementGroup") {
        const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
        if (HIGH_PRIVILEGE_ROLES.includes(roleName)) {
          findings.push({
            severity: "HIGH",
            control: "RBAC-7",
            framework: "RBAC",
            resource: props.principalId || "",
            resourceName: props.principalDisplayName || props.principalId || "",
            message: roleName + " assigned at management group scope: broad blast radius",
            remediation: "Assign roles at the most restrictive scope needed (subscription or resource group)"
          });
        }
      }
    });
    (definitions || []).forEach((def) => {
      const roleType = def.properties?.type || "";
      if (roleType === "CustomRole" || roleType === "customRole") {
        if (_isWildcardRole(def)) {
          findings.push({
            severity: "HIGH",
            control: "RBAC-8",
            framework: "RBAC",
            resource: def.id || "",
            resourceName: def.properties?.roleName || def.name || "",
            message: 'Custom role "' + (def.properties?.roleName || "") + '" has wildcard (*) actions',
            remediation: "Scope custom role actions to specific resource provider operations"
          });
        }
      }
    });
    const assignmentsByPrincipal = {};
    assignments.forEach((a) => {
      const pid = (a.properties || a).principalId || "";
      if (pid) {
        if (!assignmentsByPrincipal[pid]) assignmentsByPrincipal[pid] = [];
        assignmentsByPrincipal[pid].push(a);
      }
    });
    Object.entries(assignmentsByPrincipal).forEach(([pid, aList]) => {
      if (aList.length > 10) {
        const firstProps = aList[0].properties || aList[0];
        findings.push({
          severity: "LOW",
          control: "RBAC-9",
          framework: "RBAC",
          resource: pid,
          resourceName: firstProps.principalDisplayName || pid,
          message: "Principal has " + aList.length + " direct role assignments: consider using groups",
          remediation: "Use Azure AD groups to consolidate role assignments"
        });
      }
    });
    return findings;
  }
  function findOverPrivileged(assignments, definitions) {
    const findings = [];
    (assignments || []).forEach((a) => {
      const props = a.properties || a;
      const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
      const scope = props.scope || a.scope || "";
      const scopeLevel = getScopeLevel(scope);
      const principalName = props.principalDisplayName || props.principalId || "";
      if (roleName === "Owner" && (scopeLevel === "subscription" || scopeLevel === "managementGroup")) {
        findings.push({
          severity: "CRITICAL",
          control: "RBAC-1",
          framework: "RBAC",
          resource: props.principalId || "",
          resourceName: principalName,
          message: "Owner role at " + scopeLevel + ' scope for "' + principalName + '"',
          remediation: "Apply least-privilege: use Contributor or more specific roles; restrict Owner to break-glass accounts only"
        });
      }
      if (roleName === "User Access Administrator" && scopeLevel === "subscription") {
        findings.push({
          severity: "HIGH",
          control: "RBAC-1",
          framework: "RBAC",
          resource: props.principalId || "",
          resourceName: principalName,
          message: 'User Access Administrator at subscription scope for "' + principalName + '"',
          remediation: "Restrict to resource group scope or use Conditional Access for just-in-time access"
        });
      }
      const def = _findDefinition(props.roleDefinitionId, definitions);
      if (def && _isWildcardRole(def) && roleName !== "Owner" && roleName !== "Contributor") {
        findings.push({
          severity: "HIGH",
          control: "RBAC-1",
          framework: "RBAC",
          resource: props.principalId || "",
          resourceName: principalName,
          message: 'Role "' + roleName + '" has wildcard (*) actions assigned to "' + principalName + '"',
          remediation: "Replace with a scoped role definition that lists specific actions"
        });
      }
    });
    return findings;
  }
  function findOrphanedAssignments(assignments) {
    const findings = [];
    (assignments || []).forEach((a) => {
      const props = a.properties || a;
      const principalType = props.principalType || "";
      if (principalType === "Unknown" || principalType === "") {
        findings.push({
          severity: "MEDIUM",
          control: "RBAC-2",
          framework: "RBAC",
          resource: props.principalId || a.id || "",
          resourceName: props.principalId || "Unknown Principal",
          message: "Orphaned role assignment: principal no longer exists in Azure AD",
          remediation: "Remove the orphaned assignment: az role assignment delete --ids " + (a.id || "$ASSIGNMENT_ID")
        });
      }
    });
    return findings;
  }
  function countOwnersPerScope(assignments) {
    const findings = [];
    const ownersByScope = {};
    (assignments || []).forEach((a) => {
      const props = a.properties || a;
      const roleDefId = props.roleDefinitionId || "";
      const guid = roleDefId.split("/").pop();
      if (guid === "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" || BUILTIN_ROLES[guid] === "Owner") {
        const scope = props.scope || a.scope || "";
        if (!ownersByScope[scope]) ownersByScope[scope] = [];
        ownersByScope[scope].push(props.principalId || "");
      }
    });
    Object.entries(ownersByScope).forEach(([scope, owners]) => {
      if (owners.length > 3) {
        const scopeLevel = getScopeLevel(scope);
        findings.push({
          severity: "MEDIUM",
          control: "RBAC-3",
          framework: "RBAC",
          resource: scope,
          resourceName: scope.split("/").pop() || scope,
          message: owners.length + " Owner assignments at " + scopeLevel + " scope (recommended max: 3)",
          remediation: "Reduce Owner count; use Contributor for day-to-day operations"
        });
      }
    });
    return findings;
  }
  function findGuestPrivileges(assignments, definitions) {
    const findings = [];
    (assignments || []).forEach((a) => {
      const props = a.properties || a;
      if (props.principalType !== "Guest" && props.principalType !== "ForeignGroup") return;
      const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
      const principalName = props.principalDisplayName || props.principalId || "";
      if (WRITE_DELETE_ROLE_NAMES.includes(roleName)) {
        findings.push({
          severity: "HIGH",
          control: "RBAC-4",
          framework: "RBAC",
          resource: props.principalId || "",
          resourceName: principalName,
          message: 'Guest user "' + principalName + '" has "' + roleName + '" role',
          remediation: "Restrict guest users to Reader role or remove access; use Conditional Access policies for guest accounts"
        });
        return;
      }
      const def = _findDefinition(props.roleDefinitionId, definitions);
      if (def) {
        const perms = def.properties?.permissions || def.permissions || [];
        const hasWrite = perms.some(
          (p) => (p.actions || []).some((a2) => classifyPermission(a2) === "write" || classifyPermission(a2) === "delete" || classifyPermission(a2) === "admin")
        );
        if (hasWrite) {
          findings.push({
            severity: "MEDIUM",
            control: "RBAC-4",
            framework: "RBAC",
            resource: props.principalId || "",
            resourceName: principalName,
            message: 'Guest user "' + principalName + '" has custom role "' + roleName + '" with write/delete permissions',
            remediation: "Review guest user access and restrict to read-only roles"
          });
        }
      }
    });
    return findings;
  }
  function findServicePrincipalRisks(assignments, definitions) {
    const findings = [];
    (assignments || []).forEach((a) => {
      const props = a.properties || a;
      if (props.principalType !== "ServicePrincipal") return;
      const roleName = _resolveRoleName(props.roleDefinitionId, definitions);
      const scope = props.scope || a.scope || "";
      const scopeLevel = getScopeLevel(scope);
      const principalName = props.principalDisplayName || props.principalId || "";
      if (roleName === "Owner" && (scopeLevel === "subscription" || scopeLevel === "managementGroup")) {
        findings.push({
          severity: "CRITICAL",
          control: "RBAC-5",
          framework: "RBAC",
          resource: props.principalId || "",
          resourceName: principalName,
          message: 'Service principal "' + principalName + '" has Owner at ' + scopeLevel + " scope",
          remediation: "Use Contributor or a custom role with specific permissions; implement credential rotation and monitoring"
        });
      } else if (roleName === "Contributor" && scopeLevel === "subscription") {
        findings.push({
          severity: "HIGH",
          control: "RBAC-5",
          framework: "RBAC",
          resource: props.principalId || "",
          resourceName: principalName,
          message: 'Service principal "' + principalName + '" has Contributor at subscription scope',
          remediation: "Scope to resource group level; use specific roles matching the workload needs"
        });
      }
      const def = _findDefinition(props.roleDefinitionId, definitions);
      if (def && _isWildcardRole(def) && roleName !== "Owner" && roleName !== "Contributor") {
        findings.push({
          severity: "HIGH",
          control: "RBAC-5",
          framework: "RBAC",
          resource: props.principalId || "",
          resourceName: principalName,
          message: 'Service principal "' + principalName + '" has custom wildcard role "' + roleName + '"',
          remediation: "Replace with scoped permissions; service principals should have minimal required access"
        });
      }
    });
    return findings;
  }
  function parseRBACData(raw) {
    if (!raw) return null;
    const data = {
      roleAssignments: [],
      roleDefinitions: [],
      customRoles: []
    };
    if (raw.roleAssignments) data.roleAssignments = Array.isArray(raw.roleAssignments) ? raw.roleAssignments : raw.roleAssignments.value || [];
    if (raw.value && !raw.roleAssignments) data.roleAssignments = raw.value;
    if (raw.roleDefinitions) data.roleDefinitions = Array.isArray(raw.roleDefinitions) ? raw.roleDefinitions : raw.roleDefinitions.value || [];
    data.customRoles = data.roleDefinitions.filter((d) => {
      const roleType = d.properties?.type || "";
      return roleType === "CustomRole" || roleType === "customRole";
    });
    data.findings = analyzeRoleAssignments(data.roleAssignments, data.roleDefinitions);
    return data;
  }
  function getRBACForScope(rbacData, scope) {
    if (!rbacData || !scope) return [];
    const scopeLower = scope.toLowerCase();
    return (rbacData.findings || []).filter((f) => {
      if (!f.resource) return false;
      return f.resource.toLowerCase().includes(scopeLower) || scopeLower.includes(f.resource.toLowerCase());
    });
  }

  // src/modules/compliance-engine.js
  var CKV_MAP = {
    "CIS-9": "CKV_AZURE_9",
    // NSG allows RDP from 0.0.0.0/0
    "CIS-10": "CKV_AZURE_10",
    // NSG allows SSH from 0.0.0.0/0
    "CIS-12": "CKV_AZURE_12",
    // NSG allows all inbound
    "CIS-34": "CKV_AZURE_34",
    // Storage public blob access
    "CIS-44": "CKV_AZURE_44",
    // Storage min TLS < 1.2
    "CIS-SQL-1": "CKV_AZURE_28",
    // SQL server publicly accessible
    "CIS-REDIS": "CKV_AZURE_88",
    // Redis not using TLS
    "CIS-AKS": "CKV_AZURE_5",
    // AKS RBAC not enabled
    "CIS-DDOS": "CKV_AZURE_57",
    // VNet without DDoS protection
    "CAF-NSG": "CKV_AZURE_160",
    // Subnet without NSG
    "CAF-UDR": "CKV_AZURE_161",
    // Subnet without route table
    "SOC2-TLS": "CKV_AZURE_44",
    // TLS 1.2 minimum on storage
    "SOC2-DISK": "CKV_AZURE_93",
    // Managed disk encryption
    "PCI-WAF": "CKV_AZURE_120",
    // App GW without WAF
    "PE-PENDING": "CKV_AZURE_PE_1",
    // PE connection pending
    "PE-NO-DNS": "CKV_AZURE_PE_2",
    // No matching private DNS zone
    "PE-DNS-UNLINKED": "CKV_AZURE_PE_3",
    // DNS zone not linked to VNet
    "PE-NSG-POLICY": "CKV_AZURE_PE_4",
    // Subnet NSG policies disabled
    "PE-ORPHAN": "CKV_AZURE_PE_5"
    // PE connection failed/disconnected
  };
  var _complianceFindings = [];
  var _complianceCacheData = null;
  function _getRules(nsg) {
    if (!nsg) return [];
    const props = nsg.properties || nsg;
    return props.securityRules || props.SecurityRules || [];
  }
  function _ruleProps(rule) {
    return rule.properties || rule;
  }
  function _isOpenSource(prefix) {
    if (!prefix) return false;
    const p = String(prefix).trim();
    return p === "*" || p === "0.0.0.0/0" || p === "Internet" || p === "Any" || p === "::/0";
  }
  function _hasOpenSourcePrefixes(rule) {
    const rp = _ruleProps(rule);
    if (_isOpenSource(rp.sourceAddressPrefix)) return true;
    const prefixes = rp.sourceAddressPrefixes || [];
    return prefixes.some((p) => _isOpenSource(p));
  }
  function _coversPort(rule, port) {
    const rp = _ruleProps(rule);
    const ranges = _collectPortRanges(rp);
    return ranges.some((range) => _portInRange(range, port));
  }
  function _collectPortRanges(rp) {
    const ranges = [];
    if (rp.destinationPortRange) ranges.push(rp.destinationPortRange);
    if (rp.destinationPortRanges) ranges.push(...rp.destinationPortRanges);
    return ranges;
  }
  function _portInRange(range, port) {
    if (!range) return false;
    const r = String(range).trim();
    if (r === "*") return true;
    if (r.includes("-")) {
      const [lo, hi] = r.split("-").map(Number);
      return port >= lo && port <= hi;
    }
    return Number(r) === port;
  }
  function _isAllPorts(rule) {
    const rp = _ruleProps(rule);
    return rp.destinationPortRange === "*" || (rp.destinationPortRanges || []).includes("*");
  }
  function _isAllProtocols(rule) {
    const rp = _ruleProps(rule);
    return (rp.protocol || "").trim() === "*";
  }
  function _rn(resource, fallback) {
    if (!resource) return fallback || "";
    return resource.name || sid(resource.id) || fallback || "";
  }
  function _finding(opts) {
    return {
      id: opts.id || "",
      framework: opts.framework || "",
      severity: opts.severity || "MEDIUM",
      title: opts.title || "",
      message: opts.message || "",
      resource: opts.resource || "",
      resourceId: opts.resourceId || "",
      resourceType: opts.resourceType || "",
      remediation: opts.remediation || "",
      checkovId: CKV_MAP[opts.id] || opts.checkovId || "",
      control: opts.id || "",
      resourceName: opts.resource || ""
    };
  }
  function _getTags(resource) {
    if (!resource) return {};
    return resource.tags || resource.Tags || (resource.properties || {}).tags || {};
  }
  function _hasTags(resource) {
    const tags = _getTags(resource);
    return Object.keys(tags).length > 0;
  }
  function _getVnetSubnets(vnet) {
    if (!vnet) return [];
    const props = vnet.properties || vnet;
    return props.subnets || [];
  }
  function _subnetProps(subnet) {
    return subnet.properties || subnet;
  }
  function runCISAzureChecks(data) {
    const f = [];
    const nsgs = data.nsgs || [];
    const storageAccounts = data.storageAccounts || [];
    const sqlServers = data.sqlServers || [];
    const redisCaches = data.redisCaches || [];
    const aksClusters = data.aksClusters || [];
    const vnets = data.vnets || [];
    const bastionHosts = data.bastionHosts || [];
    const networkWatchers = data.networkWatchers || [];
    const regions = data._regions || [];
    const dbPorts = [
      { port: 1433, name: "SQL Server" },
      { port: 3306, name: "MySQL" },
      { port: 5432, name: "PostgreSQL" }
    ];
    nsgs.forEach((nsg) => {
      const rules = _getRules(nsg);
      rules.forEach((rule) => {
        const rp = _ruleProps(rule);
        if (rp.direction !== "Inbound" || rp.access !== "Allow") return;
        const openSrc = _hasOpenSourcePrefixes(rule);
        if (!openSrc) return;
        if (_coversPort(rule, 3389)) {
          f.push(_finding({
            id: "CIS-9",
            framework: "CIS_AZURE",
            severity: "HIGH",
            title: "NSG allows RDP from 0.0.0.0/0",
            message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows RDP (3389) from any source`,
            resource: _rn(nsg),
            resourceId: nsg.id || "",
            resourceType: "Microsoft.Network/networkSecurityGroups",
            remediation: "Restrict RDP access to specific CIDR ranges or use Azure Bastion"
          }));
        }
        if (_coversPort(rule, 22)) {
          f.push(_finding({
            id: "CIS-10",
            framework: "CIS_AZURE",
            severity: "HIGH",
            title: "NSG allows SSH from 0.0.0.0/0",
            message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows SSH (22) from any source`,
            resource: _rn(nsg),
            resourceId: nsg.id || "",
            resourceType: "Microsoft.Network/networkSecurityGroups",
            remediation: "Restrict SSH access to specific CIDR ranges or use Azure Bastion"
          }));
        }
        if (_isAllProtocols(rule) && _isAllPorts(rule)) {
          f.push(_finding({
            id: "CIS-12",
            framework: "CIS_AZURE",
            severity: "CRITICAL",
            title: "NSG allows all inbound traffic",
            message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows all traffic from any source`,
            resource: _rn(nsg),
            resourceId: nsg.id || "",
            resourceType: "Microsoft.Network/networkSecurityGroups",
            remediation: "Remove or restrict rule to specific ports and source addresses"
          }));
        }
        dbPorts.forEach((db) => {
          if (_coversPort(rule, db.port)) {
            f.push(_finding({
              id: "CIS-DB-" + db.port,
              framework: "CIS_AZURE",
              severity: "HIGH",
              title: `NSG allows ${db.name} port from 0.0.0.0/0`,
              message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows ${db.name} (${db.port}) from any source`,
              resource: _rn(nsg),
              resourceId: nsg.id || "",
              resourceType: "Microsoft.Network/networkSecurityGroups",
              remediation: `Restrict ${db.name} access to application subnets only`
            }));
          }
        });
        const proto = (rp.protocol || "").toLowerCase();
        if (proto === "udp" && _isAllPorts(rule)) {
          f.push(_finding({
            id: "CIS-UDP",
            framework: "CIS_AZURE",
            severity: "HIGH",
            title: "NSG allows all UDP from 0.0.0.0/0",
            message: `NSG "${_rn(nsg)}" rule "${rp.name || _rn(rule)}" allows all UDP traffic from any source`,
            resource: _rn(nsg),
            resourceId: nsg.id || "",
            resourceType: "Microsoft.Network/networkSecurityGroups",
            remediation: "Restrict UDP access to specific ports and source addresses"
          }));
        }
      });
    });
    storageAccounts.forEach((sa) => {
      const props = sa.properties || sa;
      const pubAccess = props.allowBlobPublicAccess ?? props.AllowBlobPublicAccess;
      if (pubAccess === true) {
        f.push(_finding({
          id: "CIS-34",
          framework: "CIS_AZURE",
          severity: "HIGH",
          title: "Storage account allows public blob access",
          message: `Storage account "${_rn(sa)}" allows anonymous public read access to blobs`,
          resource: _rn(sa),
          resourceId: sa.id || "",
          resourceType: "Microsoft.Storage/storageAccounts",
          remediation: "Set allowBlobPublicAccess to false on the storage account"
        }));
      }
    });
    storageAccounts.forEach((sa) => {
      const props = sa.properties || sa;
      const minTls = props.minimumTlsVersion || props.MinimumTlsVersion || "";
      if (minTls && minTls !== "TLS1_2" && minTls !== "TLS1_3") {
        f.push(_finding({
          id: "CIS-44",
          framework: "CIS_AZURE",
          severity: "HIGH",
          title: "Storage account minimum TLS < 1.2",
          message: `Storage account "${_rn(sa)}" uses ${minTls}: TLS 1.2 is the minimum secure version`,
          resource: _rn(sa),
          resourceId: sa.id || "",
          resourceType: "Microsoft.Storage/storageAccounts",
          remediation: "Set minimumTlsVersion to TLS1_2 on the storage account"
        }));
      }
    });
    sqlServers.forEach((srv) => {
      const props = srv.properties || srv;
      const fwRules = props.firewallRules || [];
      const hasOpenFw = fwRules.some((fw) => {
        const fwp = fw.properties || fw;
        return fwp.startIpAddress === "0.0.0.0" && fwp.endIpAddress === "255.255.255.255";
      });
      const pubAccess = props.publicNetworkAccess || "";
      if (hasOpenFw || pubAccess.toLowerCase() === "enabled") {
        f.push(_finding({
          id: "CIS-SQL-1",
          framework: "CIS_AZURE",
          severity: "CRITICAL",
          title: "SQL server publicly accessible",
          message: `SQL server "${_rn(srv)}" is accessible from the public internet`,
          resource: _rn(srv),
          resourceId: srv.id || "",
          resourceType: "Microsoft.Sql/servers",
          remediation: "Disable public network access; use private endpoints and restrict firewall rules"
        }));
      }
    });
    redisCaches.forEach((rc) => {
      const props = rc.properties || rc;
      const nonSslPort = props.enableNonSslPort ?? props.EnableNonSslPort;
      const minTls = props.minimumTlsVersion || props.MinimumTlsVersion || "";
      if (nonSslPort === true || minTls && minTls !== "1.2" && minTls !== "1.3") {
        f.push(_finding({
          id: "CIS-REDIS",
          framework: "CIS_AZURE",
          severity: "HIGH",
          title: "Redis cache not enforcing TLS",
          message: `Redis cache "${_rn(rc)}" ${nonSslPort ? "has non-SSL port enabled" : "uses TLS version < 1.2"}`,
          resource: _rn(rc),
          resourceId: rc.id || "",
          resourceType: "Microsoft.Cache/Redis",
          remediation: "Disable non-SSL port and set minimumTlsVersion to 1.2"
        }));
      }
    });
    aksClusters.forEach((aks) => {
      const props = aks.properties || aks;
      const rbacEnabled = props.enableRBAC ?? (props.aadProfile && props.aadProfile.enableAzureRBAC);
      if (rbacEnabled === false || rbacEnabled === void 0) {
        f.push(_finding({
          id: "CIS-AKS",
          framework: "CIS_AZURE",
          severity: "HIGH",
          title: "AKS cluster RBAC not enabled",
          message: `AKS cluster "${_rn(aks)}" does not have Kubernetes RBAC enabled`,
          resource: _rn(aks),
          resourceId: aks.id || "",
          resourceType: "Microsoft.ContainerService/managedClusters",
          remediation: "Enable RBAC on the AKS cluster and integrate with Azure AD"
        }));
      }
    });
    vnets.forEach((vnet) => {
      const props = vnet.properties || vnet;
      const ddos = props.enableDdosProtection || props.ddosProtectionPlan;
      if (!ddos) {
        f.push(_finding({
          id: "CIS-DDOS",
          framework: "CIS_AZURE",
          severity: "MEDIUM",
          title: "VNet without DDoS protection plan",
          message: `VNet "${_rn(vnet)}" does not have DDoS Protection Standard enabled`,
          resource: _rn(vnet),
          resourceId: vnet.id || "",
          resourceType: "Microsoft.Network/virtualNetworks",
          remediation: "Enable Azure DDoS Protection Standard on the VNet"
        }));
      }
    });
    const hubVnets = vnets.filter((v) => {
      const n = (_rn(v) || "").toLowerCase();
      return n.includes("hub") || n.includes("shared") || n.includes("core") || n.includes("connectivity");
    });
    if (hubVnets.length > 0 && bastionHosts.length === 0) {
      hubVnets.forEach((hub) => {
        f.push(_finding({
          id: "CIS-BASTION",
          framework: "CIS_AZURE",
          severity: "HIGH",
          title: "Bastion not deployed in hub VNet",
          message: `Hub VNet "${_rn(hub)}" has no Azure Bastion host deployed: RDP/SSH jump host missing`,
          resource: _rn(hub),
          resourceId: hub.id || "",
          resourceType: "Microsoft.Network/virtualNetworks",
          remediation: "Deploy Azure Bastion in the hub VNet for secure remote access without public IPs"
        }));
      });
    }
    if (regions.length > 0) {
      const watcherRegions = new Set(
        networkWatchers.map((nw) => (nw.location || "").toLowerCase())
      );
      regions.forEach((region) => {
        const r = region.toLowerCase();
        if (!watcherRegions.has(r)) {
          f.push(_finding({
            id: "CIS-NW",
            framework: "CIS_AZURE",
            severity: "MEDIUM",
            title: "Network Watcher not deployed in region",
            message: `Region "${region}" does not have a Network Watcher deployed`,
            resource: region,
            resourceId: "",
            resourceType: "Microsoft.Network/networkWatchers",
            remediation: "Deploy Network Watcher in each active region for network monitoring and diagnostics"
          }));
        }
      });
    }
    const privateEndpoints = data.privateEndpoints || data.vpces || [];
    const dnsZones = data.dnsZones || data.zones || [];
    const PE_DNS_MAP = {
      sqlServer: "privatelink.database.windows.net",
      blob: "privatelink.blob.core.windows.net",
      table: "privatelink.table.core.windows.net",
      queue: "privatelink.queue.core.windows.net",
      file: "privatelink.file.core.windows.net",
      web: "privatelink.web.core.windows.net",
      dfs: "privatelink.dfs.core.windows.net",
      vault: "privatelink.vaultcore.azure.net",
      redisCache: "privatelink.redis.cache.windows.net",
      namespace: "privatelink.servicebus.windows.net",
      cosmosdb: "privatelink.documents.azure.com",
      registry: "privatelink.azurecr.io",
      sites: "privatelink.azurewebsites.net",
      mysqlServer: "privatelink.mysql.database.azure.com",
      postgresqlServer: "privatelink.postgres.database.azure.com",
      Sql: "privatelink.sql.azuresynapse.net",
      Dev: "privatelink.dev.azuresynapse.net",
      searchService: "privatelink.search.windows.net",
      account: "privatelink.cognitiveservices.azure.com"
    };
    const dnsZonesByName = {};
    dnsZones.forEach((z) => {
      const props = z.properties || z._azure?.properties || {};
      const name = z.name || z.Name || "";
      if (name) dnsZonesByName[name.toLowerCase()] = { zone: z, links: props.virtualNetworkLinks || [] };
    });
    privateEndpoints.forEach((pe) => {
      const props = pe.properties || pe._azure?.properties || {};
      const conn = (props.privateLinkServiceConnections || [])[0];
      const connProps = conn?.properties || {};
      const state = connProps.privateLinkServiceConnectionState?.status || "";
      const groupId = (connProps.groupIds || [])[0] || "";
      const subnetId = props.subnet?.id || "";
      const vnetId = subnetId ? subnetId.split("/subnets/")[0] : "";
      const peName = _rn(pe);
      if (state === "Pending") {
        f.push(_finding({
          id: "PE-PENDING",
          framework: "CIS_AZURE",
          severity: "HIGH",
          title: "Private Endpoint connection pending approval",
          message: `PE "${peName}" has a pending connection: traffic will not flow until approved`,
          resource: peName,
          resourceId: pe.id || "",
          resourceType: "Microsoft.Network/privateEndpoints",
          remediation: "Approve the private endpoint connection on the target resource or remove the PE if not needed"
        }));
      }
      if (state === "Rejected" || state === "Disconnected" || state === "Failed") {
        f.push(_finding({
          id: "PE-ORPHAN",
          framework: "CIS_AZURE",
          severity: "MEDIUM",
          title: "Private Endpoint connection " + state.toLowerCase(),
          message: `PE "${peName}" has a ${state.toLowerCase()} connection: endpoint is orphaned and should be cleaned up`,
          resource: peName,
          resourceId: pe.id || "",
          resourceType: "Microsoft.Network/privateEndpoints",
          remediation: "Remove the orphaned private endpoint or re-create the connection to the target service"
        }));
      }
      if (groupId) {
        const expectedZone = PE_DNS_MAP[groupId];
        if (expectedZone && !dnsZonesByName[expectedZone.toLowerCase()]) {
          f.push(_finding({
            id: "PE-NO-DNS",
            framework: "CIS_AZURE",
            severity: "HIGH",
            title: "No private DNS zone for Private Endpoint",
            message: `PE "${peName}" (${groupId}) requires DNS zone "${expectedZone}" but none exists: DNS resolution will fail`,
            resource: peName,
            resourceId: pe.id || "",
            resourceType: "Microsoft.Network/privateEndpoints",
            remediation: 'Create private DNS zone "' + expectedZone + `" and link it to the PE's VNet`
          }));
        }
        if (expectedZone && vnetId) {
          const zoneInfo = dnsZonesByName[expectedZone.toLowerCase()];
          if (zoneInfo) {
            const linked = zoneInfo.links.some((link) => {
              const linkVnet = link.properties?.virtualNetwork?.id || link.id || "";
              return linkVnet.toLowerCase() === vnetId.toLowerCase();
            });
            if (!linked) {
              f.push(_finding({
                id: "PE-DNS-UNLINKED",
                framework: "CIS_AZURE",
                severity: "HIGH",
                title: "Private DNS zone not linked to PE VNet",
                message: `PE "${peName}" is in VNet "${vnetId.split("/").pop()}" but DNS zone "${expectedZone}" is not linked to that VNet: resolution will use public DNS`,
                resource: peName,
                resourceId: pe.id || "",
                resourceType: "Microsoft.Network/privateEndpoints",
                remediation: 'Add a virtual network link from "' + expectedZone + '" to VNet "' + vnetId.split("/").pop() + '"'
              }));
            }
          }
        }
      }
      if (subnetId) {
        const subnet = (data.subnets || []).find((s) => (s.id || s.SubnetId || "") === subnetId);
        if (subnet) {
          const subProps = subnet.properties || {};
          const hasNsg = !!subProps.networkSecurityGroup;
          const policyDisabled = subProps.privateEndpointNetworkPolicies === "Disabled" || !subProps.privateEndpointNetworkPolicies;
          if (hasNsg && policyDisabled) {
            f.push(_finding({
              id: "PE-NSG-POLICY",
              framework: "CIS_AZURE",
              severity: "MEDIUM",
              title: "NSG cannot filter Private Endpoint traffic",
              message: `Subnet "${_rn(subnet)}" has an NSG but PE network policies are disabled: NSG rules will not apply to PE "${peName}"`,
              resource: peName,
              resourceId: pe.id || "",
              resourceType: "Microsoft.Network/privateEndpoints",
              remediation: "Enable privateEndpointNetworkPolicies on the subnet to allow NSG filtering of PE traffic"
            }));
          }
        }
      }
    });
    return f;
  }
  function runCAFChecks(data) {
    const f = [];
    const vnets = data.vnets || [];
    const subnets = data.subnets || [];
    const nsgs = data.nsgs || [];
    const routeTables = data.routeTables || [];
    const peerings = data.peerings || [];
    const firewalls = data.firewalls || [];
    const privateDnsZones = data.privateDnsZones || [];
    const vms = data.vms || [];
    const publicIps = data.publicIps || [];
    const loadBalancers = data.loadBalancers || [];
    const appGateways = data.appGateways || [];
    const diagnosticSettings = data.diagnosticSettings || [];
    const resourceLocks = data.resourceLocks || [];
    const allResources = data.allResources || [];
    const subnetNsgMap = /* @__PURE__ */ new Map();
    subnets.forEach((sub) => {
      const sp = _subnetProps(sub);
      const nsgRef = sp.networkSecurityGroup;
      if (nsgRef && nsgRef.id) subnetNsgMap.set(sub.id || sub.name, nsgRef.id);
    });
    const subnetRtMap = /* @__PURE__ */ new Map();
    subnets.forEach((sub) => {
      const sp = _subnetProps(sub);
      const rtRef = sp.routeTable;
      if (rtRef && rtRef.id) subnetRtMap.set(sub.id || sub.name, rtRef.id);
    });
    subnets.forEach((sub) => {
      const subName = sub.name || sid(sub.id) || "";
      const lowerName = subName.toLowerCase();
      if (lowerName === "gatewaysubnet" || lowerName === "azurebastionsubnet" || lowerName === "azurefirewallsubnet" || lowerName === "azurefirewallmanagementsubnet" || lowerName === "routeserversubnet") return;
      const sp = _subnetProps(sub);
      const nsgRef = sp.networkSecurityGroup;
      if (!nsgRef || !nsgRef.id) {
        f.push(_finding({
          id: "CAF-NSG",
          framework: "CAF",
          severity: "HIGH",
          title: "Subnet without NSG",
          message: `Subnet "${subName}" has no Network Security Group associated`,
          resource: subName,
          resourceId: sub.id || "",
          resourceType: "Microsoft.Network/virtualNetworks/subnets",
          remediation: "Associate an NSG with this subnet to enforce network access controls"
        }));
      }
    });
    subnets.forEach((sub) => {
      const subName = sub.name || sid(sub.id) || "";
      const lowerName = subName.toLowerCase();
      if (lowerName === "gatewaysubnet" || lowerName === "azurebastionsubnet" || lowerName === "routeserversubnet") return;
      const sp = _subnetProps(sub);
      const rtRef = sp.routeTable;
      if (!rtRef || !rtRef.id) {
        f.push(_finding({
          id: "CAF-UDR",
          framework: "CAF",
          severity: "MEDIUM",
          title: "Subnet without route table",
          message: `Subnet "${subName}" has no User Defined Route (UDR) table: uses default system routes`,
          resource: subName,
          resourceId: sub.id || "",
          resourceType: "Microsoft.Network/virtualNetworks/subnets",
          remediation: "Associate a route table for traffic control; route Internet traffic through a firewall"
        }));
      }
    });
    vnets.forEach((vnet) => {
      const subs = _getVnetSubnets(vnet);
      if (subs.length === 0) {
        f.push(_finding({
          id: "CAF-EMPTY",
          framework: "CAF",
          severity: "LOW",
          title: "VNet without subnets",
          message: `VNet "${_rn(vnet)}" has no subnets configured: unused VNet`,
          resource: _rn(vnet),
          resourceId: vnet.id || "",
          resourceType: "Microsoft.Network/virtualNetworks",
          remediation: "Add subnets for workload segmentation or remove the unused VNet"
        }));
      }
    });
    const hasHub = vnets.some((v) => {
      const n = (_rn(v) || "").toLowerCase();
      return n.includes("hub") || n.includes("core") || n.includes("connectivity");
    });
    if (vnets.length > 2 && !hasHub && (peerings.length > 0 || vnets.length > 3)) {
      f.push(_finding({
        id: "CAF-HUB",
        framework: "CAF",
        severity: "MEDIUM",
        title: "No hub-spoke topology detected",
        message: `${vnets.length} VNets found but no hub VNet identified: consider hub-spoke architecture`,
        resource: "Topology",
        resourceId: "",
        resourceType: "Microsoft.Network/virtualNetworks",
        remediation: "Implement hub-spoke topology with centralized firewall, DNS, and shared services"
      }));
    }
    peerings.forEach((peer) => {
      const props = peer.properties || peer;
      if (props.allowForwardedTraffic === false) {
        f.push(_finding({
          id: "CAF-PEER",
          framework: "CAF",
          severity: "MEDIUM",
          title: "Peering without forwarded traffic",
          message: `Peering "${_rn(peer)}" does not allow forwarded traffic: spoke-to-spoke routing via hub will fail`,
          resource: _rn(peer),
          resourceId: peer.id || "",
          resourceType: "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
          remediation: "Enable allowForwardedTraffic on peering to support transitive routing via hub firewall"
        }));
      }
    });
    if (hasHub && firewalls.length === 0) {
      f.push(_finding({
        id: "CAF-FW",
        framework: "CAF",
        severity: "HIGH",
        title: "Missing Azure Firewall in hub",
        message: "Hub VNet detected but no Azure Firewall deployed: no centralized traffic inspection",
        resource: "Hub VNet",
        resourceId: "",
        resourceType: "Microsoft.Network/azureFirewalls",
        remediation: "Deploy Azure Firewall (or NVA) in the hub VNet for centralized traffic control"
      }));
    }
    if (privateDnsZones.length === 0 && vnets.length > 0) {
      f.push(_finding({
        id: "CAF-DNS",
        framework: "CAF",
        severity: "LOW",
        title: "No private DNS zones configured",
        message: "No Azure Private DNS zones found: PaaS private endpoints require private DNS for resolution",
        resource: "DNS",
        resourceId: "",
        resourceType: "Microsoft.Network/privateDnsZones",
        remediation: "Create private DNS zones for Azure services (e.g., privatelink.blob.core.windows.net)"
      }));
    }
    const vmPublicIps = /* @__PURE__ */ new Set();
    publicIps.forEach((pip) => {
      const props = pip.properties || pip;
      const ipConfig = props.ipConfiguration;
      if (ipConfig && ipConfig.id && ipConfig.id.toLowerCase().includes("/networkinterfaces/")) {
        vmPublicIps.add(sid(ipConfig.id));
      }
    });
    vms.forEach((vm) => {
      const props = vm.properties || vm;
      const nics = (props.networkProfile || {}).networkInterfaces || [];
      nics.forEach((nic) => {
        const nicName = sid(nic.id);
        if (vmPublicIps.has(nicName)) {
          f.push(_finding({
            id: "CAF-PIP",
            framework: "CAF",
            severity: "MEDIUM",
            title: "VM using public IP directly",
            message: `VM "${_rn(vm)}" has a public IP assigned: use Azure Bastion or Load Balancer instead`,
            resource: _rn(vm),
            resourceId: vm.id || "",
            resourceType: "Microsoft.Compute/virtualMachines",
            remediation: "Remove public IP; access VMs via Azure Bastion, VPN, or Load Balancer"
          }));
        }
      });
    });
    loadBalancers.forEach((lb) => {
      const props = lb.properties || lb;
      const probes = props.probes || [];
      const rules = props.loadBalancingRules || [];
      if (rules.length > 0 && probes.length === 0) {
        f.push(_finding({
          id: "CAF-PROBE",
          framework: "CAF",
          severity: "HIGH",
          title: "Load balancer without health probes",
          message: `Load balancer "${_rn(lb)}" has rules but no health probes configured`,
          resource: _rn(lb),
          resourceId: lb.id || "",
          resourceType: "Microsoft.Network/loadBalancers",
          remediation: "Add health probes to detect unhealthy backends and prevent routing traffic to failed instances"
        }));
      }
    });
    appGateways.forEach((ag) => {
      const props = ag.properties || ag;
      const autoscale = props.autoscaleConfiguration;
      if (!autoscale) {
        f.push(_finding({
          id: "CAF-AGSCALE",
          framework: "CAF",
          severity: "LOW",
          title: "Application Gateway without autoscaling",
          message: `Application Gateway "${_rn(ag)}" does not have autoscaling configured`,
          resource: _rn(ag),
          resourceId: ag.id || "",
          resourceType: "Microsoft.Network/applicationGateways",
          remediation: "Enable autoscaling on Application Gateway v2 for dynamic capacity management"
        }));
      }
    });
    const nsgIds = new Set(nsgs.map((n) => (n.id || "").toLowerCase()));
    const diagResourceIds = new Set(
      diagnosticSettings.map((d) => ((d.properties || d).resourceId || d.resourceId || "").toLowerCase())
    );
    nsgs.forEach((nsg) => {
      const nsgId = (nsg.id || "").toLowerCase();
      if (nsgId && !diagResourceIds.has(nsgId)) {
        f.push(_finding({
          id: "CAF-DIAG",
          framework: "CAF",
          severity: "MEDIUM",
          title: "NSG without diagnostic settings",
          message: `NSG "${_rn(nsg)}" has no diagnostic settings: flow logs and events not captured`,
          resource: _rn(nsg),
          resourceId: nsg.id || "",
          resourceType: "Microsoft.Network/networkSecurityGroups",
          remediation: "Enable diagnostic settings to send NSG flow logs to Log Analytics or Storage"
        }));
      }
    });
    if (resourceLocks.length === 0 && allResources.length > 10) {
      f.push(_finding({
        id: "CAF-LOCK",
        framework: "CAF",
        severity: "MEDIUM",
        title: "No resource locks detected",
        message: "No resource locks found: production resources can be accidentally deleted",
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.Authorization/locks",
        remediation: "Apply CanNotDelete locks on critical resources (VNets, firewalls, databases)"
      }));
    }
    const untagged = [];
    [...vnets, ...vms, ...data.storageAccounts || [], ...nsgs].forEach((r) => {
      if (!_hasTags(r) && r.id) untagged.push(_rn(r));
    });
    if (untagged.length > 0) {
      f.push(_finding({
        id: "CAF-TAG",
        framework: "CAF",
        severity: "LOW",
        title: "Resources without tags",
        message: `${untagged.length} resource(s) missing tags: cost tracking and ownership unclear`,
        resource: "Multiple",
        resourceId: "",
        resourceType: "Various",
        remediation: "Apply tagging policy (Environment, Owner, CostCenter, Application)"
      }));
    }
    const badNames = [];
    [...vnets, ...nsgs].forEach((r) => {
      const name = _rn(r) || "";
      if (name && !/^[a-z]/.test(name) && name.length > 0) {
        badNames.push(name);
      }
    });
    if (badNames.length > 3) {
      f.push(_finding({
        id: "CAF-NAME",
        framework: "CAF",
        severity: "LOW",
        title: "Naming convention non-compliance",
        message: `${badNames.length} resources do not follow lowercase naming convention`,
        resource: "Multiple",
        resourceId: "",
        resourceType: "Various",
        remediation: "Adopt CAF naming convention: {resource-type}-{workload}-{environment}-{region}-{instance}"
      }));
    }
    vnets.forEach((vnet) => {
      const props = vnet.properties || vnet;
      const addrSpaces = props.addressSpace?.addressPrefixes || [];
      addrSpaces.forEach((cidr) => {
        const mask = parseInt((cidr || "").split("/")[1], 10);
        if (mask && mask < 16) {
          f.push(_finding({
            id: "CAF-CIDR",
            framework: "CAF",
            severity: "LOW",
            title: "VNet address space too large",
            message: `VNet "${_rn(vnet)}" uses ${cidr} (/${mask}): larger than /16 wastes IP space`,
            resource: _rn(vnet),
            resourceId: vnet.id || "",
            resourceType: "Microsoft.Network/virtualNetworks",
            remediation: "Use /16 or smaller address spaces; plan CIDR allocation to avoid overlap"
          }));
        }
      });
    });
    return f;
  }
  function runSOC2Checks(data) {
    const f = [];
    const storageAccts = data.storageAccounts || [];
    const managedDisks = data.managedDisks || [];
    const nsgs = data.nsgs || [];
    const monitorConfig = data.monitorConfig || {};
    const keyVaults = data.keyVaults || [];
    const diagnosticSettings = data.diagnosticSettings || [];
    storageAccts.forEach((sa) => {
      const props = sa.properties || sa;
      const minTls = props.minimumTlsVersion || "";
      if (!minTls || minTls !== "TLS1_2" && minTls !== "TLS1_3") {
        f.push(_finding({
          id: "SOC2-TLS",
          framework: "SOC2",
          severity: "HIGH",
          title: "Storage account TLS < 1.2",
          message: `Storage account "${_rn(sa)}" does not enforce TLS 1.2 minimum: data in transit at risk`,
          resource: _rn(sa),
          resourceId: sa.id || "",
          resourceType: "Microsoft.Storage/storageAccounts",
          remediation: "Set minimumTlsVersion to TLS1_2 on all storage accounts"
        }));
      }
    });
    managedDisks.forEach((disk) => {
      const props = disk.properties || disk;
      const encryption = props.encryption || {};
      const encType = encryption.type || props.encryptionSettingsCollection?.enabled;
      if (!encType && !props.encryptionSettingsCollection) {
        f.push(_finding({
          id: "SOC2-DISK",
          framework: "SOC2",
          severity: "HIGH",
          title: "Managed disk without encryption",
          message: `Managed disk "${_rn(disk)}" may not have encryption at rest configured`,
          resource: _rn(disk),
          resourceId: disk.id || "",
          resourceType: "Microsoft.Compute/disks",
          remediation: "Enable server-side encryption with platform-managed or customer-managed keys"
        }));
      }
    });
    const nsgFlowLogs = data.nsgFlowLogs || [];
    const nsgWithFlowLog = new Set(
      nsgFlowLogs.map((fl) => {
        const props = fl.properties || fl;
        return (props.targetResourceId || "").toLowerCase();
      })
    );
    nsgs.forEach((nsg) => {
      const nsgId = (nsg.id || "").toLowerCase();
      if (nsgId && !nsgWithFlowLog.has(nsgId)) {
        f.push(_finding({
          id: "SOC2-FLOWLOG",
          framework: "SOC2",
          severity: "HIGH",
          title: "NSG flow logs not enabled",
          message: `NSG "${_rn(nsg)}" does not have flow logs enabled: insufficient audit trail`,
          resource: _rn(nsg),
          resourceId: nsg.id || "",
          resourceType: "Microsoft.Network/networkSecurityGroups",
          remediation: "Enable NSG flow logs (v2) and send to Log Analytics for retention and analysis"
        }));
      }
    });
    const logAnalytics = data.logAnalyticsWorkspaces || [];
    if (logAnalytics.length === 0 && diagnosticSettings.length === 0) {
      f.push(_finding({
        id: "SOC2-MONITOR",
        framework: "SOC2",
        severity: "HIGH",
        title: "No Azure Monitor / Log Analytics configured",
        message: "No Log Analytics workspaces or diagnostic settings found: insufficient monitoring",
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.OperationalInsights/workspaces",
        remediation: "Deploy Log Analytics workspace and enable diagnostic settings on all resources"
      }));
    }
    keyVaults.forEach((kv) => {
      const props = kv.properties || kv;
      const rbac = props.enableRbacAuthorization;
      if (rbac !== true) {
        f.push(_finding({
          id: "SOC2-KV-RBAC",
          framework: "SOC2",
          severity: "MEDIUM",
          title: "Key Vault not using RBAC authorization",
          message: `Key Vault "${_rn(kv)}" uses access policies instead of RBAC: less auditable`,
          resource: _rn(kv),
          resourceId: kv.id || "",
          resourceType: "Microsoft.KeyVault/vaults",
          remediation: "Enable RBAC authorization mode for centralized access management and audit logging"
        }));
      }
    });
    storageAccts.forEach((sa) => {
      const props = sa.properties || sa;
      const enc = props.encryption || {};
      if (!enc.requireInfrastructureEncryption && !enc.services) {
        f.push(_finding({
          id: "SOC2-SA-ENC",
          framework: "SOC2",
          severity: "MEDIUM",
          title: "Storage account without explicit encryption settings",
          message: `Storage account "${_rn(sa)}" has no explicit encryption configuration`,
          resource: _rn(sa),
          resourceId: sa.id || "",
          resourceType: "Microsoft.Storage/storageAccounts",
          remediation: "Enable infrastructure encryption and customer-managed keys for enhanced protection"
        }));
      }
    });
    return f;
  }
  function runPCIChecks(data) {
    const f = [];
    const nsgs = data.nsgs || [];
    const sqlServers = data.sqlServers || [];
    const sqlDatabases = data.sqlDatabases || [];
    const managedDisks = data.managedDisks || [];
    const appGateways = data.appGateways || [];
    const storageAccounts = data.storageAccounts || [];
    const securityCenter = data.securityCenter || {};
    const nsgFlowLogs = data.nsgFlowLogs || [];
    const logAnalytics = data.logAnalyticsWorkspaces || [];
    const subnets = data.subnets || [];
    const pciSubnets = subnets.filter((s) => {
      const name = (s.name || "").toLowerCase();
      return name.includes("pci") || name.includes("payment") || name.includes("cardholder");
    });
    pciSubnets.forEach((sub) => {
      const sp = _subnetProps(sub);
      const nsgRef = sp.networkSecurityGroup;
      if (!nsgRef || !nsgRef.id) {
        f.push(_finding({
          id: "PCI-SEG",
          framework: "PCI",
          severity: "CRITICAL",
          title: "PCI subnet without NSG",
          message: `PCI-scoped subnet "${sub.name || sid(sub.id)}" has no NSG: network segmentation violation`,
          resource: sub.name || sid(sub.id),
          resourceId: sub.id || "",
          resourceType: "Microsoft.Network/virtualNetworks/subnets",
          remediation: "Apply strict NSG rules isolating cardholder data environment from other subnets"
        }));
      }
    });
    sqlServers.forEach((srv) => {
      const props = srv.properties || srv;
      const pubAccess = props.publicNetworkAccess || "";
      if (pubAccess.toLowerCase() === "enabled") {
        f.push(_finding({
          id: "PCI-SQL",
          framework: "PCI",
          severity: "CRITICAL",
          title: "SQL server publicly accessible",
          message: `SQL server "${_rn(srv)}" has public network access enabled: CDE exposure`,
          resource: _rn(srv),
          resourceId: srv.id || "",
          resourceType: "Microsoft.Sql/servers",
          remediation: "Disable public access; use private endpoints for database connectivity"
        }));
      }
    });
    managedDisks.forEach((disk) => {
      const props = disk.properties || disk;
      const enc = props.encryption || {};
      if (enc.type === "EncryptionAtRestWithPlatformKey" || !enc.type) {
        if (!enc.diskEncryptionSetId) {
          f.push(_finding({
            id: "PCI-ENCRYPT",
            framework: "PCI",
            severity: "HIGH",
            title: "Disk without customer-managed encryption",
            message: `Managed disk "${_rn(disk)}" uses platform-managed keys: CMK required for PCI`,
            resource: _rn(disk),
            resourceId: disk.id || "",
            resourceType: "Microsoft.Compute/disks",
            remediation: "Enable encryption with customer-managed keys via Disk Encryption Set"
          }));
        }
      }
    });
    appGateways.forEach((ag) => {
      const props = ag.properties || ag;
      const sku = props.sku || {};
      const tier = (sku.tier || sku.name || "").toLowerCase();
      if (!tier.includes("waf")) {
        f.push(_finding({
          id: "PCI-WAF",
          framework: "PCI",
          severity: "HIGH",
          title: "Application Gateway without WAF",
          message: `Application Gateway "${_rn(ag)}" uses "${sku.tier || sku.name || "Standard"}" tier: WAF required for PCI`,
          resource: _rn(ag),
          resourceId: ag.id || "",
          resourceType: "Microsoft.Network/applicationGateways",
          remediation: "Upgrade to WAF_v2 SKU and enable OWASP rule sets for web application protection",
          checkovId: "CKV_AZURE_120"
        }));
      }
    });
    const defenderPlans = data.defenderPlans || [];
    if (defenderPlans.length === 0) {
      f.push(_finding({
        id: "PCI-IDS",
        framework: "PCI",
        severity: "HIGH",
        title: "No Microsoft Defender plans enabled",
        message: "No Microsoft Defender for Cloud plans found: intrusion detection requirement unmet",
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.Security/pricings",
        remediation: "Enable Microsoft Defender for Cloud on all resource types (servers, SQL, storage, etc.)"
      }));
    }
    storageAccounts.forEach((sa) => {
      const props = sa.properties || sa;
      const enc = props.encryption || {};
      if (!enc.keySource && !enc.services) {
        f.push(_finding({
          id: "PCI-STORAGE",
          framework: "PCI",
          severity: "CRITICAL",
          title: "Storage account without encryption configuration",
          message: `Storage account "${_rn(sa)}" has no explicit encryption: data at rest violation`,
          resource: _rn(sa),
          resourceId: sa.id || "",
          resourceType: "Microsoft.Storage/storageAccounts",
          remediation: "Enable encryption with customer-managed keys for cardholder data storage"
        }));
      }
    });
    const accessReviews = data.accessReviews || [];
    if (accessReviews.length === 0) {
      f.push(_finding({
        id: "PCI-REVIEW",
        framework: "PCI",
        severity: "MEDIUM",
        title: "No access reviews configured",
        message: "No Azure AD access reviews found: periodic access review required for PCI",
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.Authorization/accessReviewScheduleDefinitions",
        remediation: "Configure quarterly access reviews for privileged roles via Azure AD PIM"
      }));
    }
    if (logAnalytics.length === 0 && nsgFlowLogs.length === 0) {
      f.push(_finding({
        id: "PCI-LOG",
        framework: "PCI",
        severity: "HIGH",
        title: "Insufficient logging for PCI compliance",
        message: "No Log Analytics workspace or NSG flow logs: audit trail requirement unmet",
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.OperationalInsights/workspaces",
        remediation: "Deploy Log Analytics and enable diagnostic settings with 1-year retention"
      }));
    }
    return f;
  }
  function runBUDRAzureChecks(data) {
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
    const protectedVmIds = /* @__PURE__ */ new Set();
    backupItems.forEach((bi) => {
      const props = bi.properties || bi;
      const sourceId = (props.sourceResourceId || props.virtualMachineId || "").toLowerCase();
      if (sourceId) protectedVmIds.add(sourceId);
    });
    vms.forEach((vm) => {
      const vmId = (vm.id || "").toLowerCase();
      if (!protectedVmIds.has(vmId)) {
        f.push(_finding({
          id: "BUDR-VM-BAK",
          framework: "BUDR",
          severity: "HIGH",
          title: "VM without backup policy",
          message: `VM "${_rn(vm)}" is not protected by Azure Backup`,
          resource: _rn(vm),
          resourceId: vm.id || "",
          resourceType: "Microsoft.Compute/virtualMachines",
          remediation: "Enable Azure Backup for the VM via Recovery Services Vault"
        }));
      }
    });
    sqlDatabases.forEach((db) => {
      const props = db.properties || db;
      const ltr = props.longTermRetentionPolicy || props.longTermRetention;
      const hasLtr = ltr && (ltr.weeklyRetention || ltr.monthlyRetention || ltr.yearlyRetention);
      if (!hasLtr) {
        f.push(_finding({
          id: "BUDR-SQL-RET",
          framework: "BUDR",
          severity: "MEDIUM",
          title: "SQL database without long-term retention",
          message: `SQL database "${_rn(db)}" has no long-term backup retention configured`,
          resource: _rn(db),
          resourceId: db.id || "",
          resourceType: "Microsoft.Sql/servers/databases",
          remediation: "Configure long-term retention (LTR) policy for weekly/monthly/yearly backups"
        }));
      }
    });
    if (recoveryVaults.length === 0 && vms.length > 0) {
      f.push(_finding({
        id: "BUDR-RSV",
        framework: "BUDR",
        severity: "HIGH",
        title: "No Recovery Services Vault",
        message: `${vms.length} VM(s) found but no Recovery Services Vault: no centralized backup infrastructure`,
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.RecoveryServices/vaults",
        remediation: "Create a Recovery Services Vault and configure backup policies for all VMs"
      }));
    }
    const deployedRegions = /* @__PURE__ */ new Set();
    [...vms, ...vnets, ...sqlServers].forEach((r) => {
      if (r.location) deployedRegions.add(r.location.toLowerCase());
    });
    if (deployedRegions.size === 1 && vms.length > 3) {
      const region = [...deployedRegions][0];
      f.push(_finding({
        id: "BUDR-REGION",
        framework: "BUDR",
        severity: "HIGH",
        title: "Single-region deployment",
        message: `All resources deployed in "${region}": no geographic disaster recovery capability`,
        resource: region,
        resourceId: "",
        resourceType: "Various",
        remediation: "Implement cross-region DR strategy using Azure Site Recovery or geo-replication"
      }));
    }
    vms.forEach((vm) => {
      const props = vm.properties || vm;
      const hasAvailSet = props.availabilitySet && props.availabilitySet.id;
      const hasZone = (vm.zones || []).length > 0;
      if (!hasAvailSet && !hasZone) {
        f.push(_finding({
          id: "BUDR-AVAIL",
          framework: "BUDR",
          severity: "MEDIUM",
          title: "VM without availability set or zone",
          message: `VM "${_rn(vm)}" has no availability set or availability zone: single point of failure`,
          resource: _rn(vm),
          resourceId: vm.id || "",
          resourceType: "Microsoft.Compute/virtualMachines",
          remediation: "Deploy VMs in availability zones or availability sets for HA"
        }));
      }
    });
    const snapshots2 = data.snapshots || [];
    const disksWithSnap = new Set(
      snapshots2.map((s) => {
        const props = s.properties || s;
        return (props.creationData?.sourceResourceId || "").toLowerCase();
      }).filter(Boolean)
    );
    managedDisks.forEach((disk) => {
      const diskId = (disk.id || "").toLowerCase();
      const props = disk.properties || disk;
      if (props.diskState === "Attached" && !disksWithSnap.has(diskId)) {
        f.push(_finding({
          id: "BUDR-SNAP",
          framework: "BUDR",
          severity: "MEDIUM",
          title: "Managed disk without snapshots",
          message: `Attached disk "${_rn(disk)}" has no snapshots: point-in-time recovery unavailable`,
          resource: _rn(disk),
          resourceId: disk.id || "",
          resourceType: "Microsoft.Compute/disks",
          remediation: "Create a snapshot policy or use Azure Backup for automatic disk snapshots"
        }));
      }
    });
    storageAccounts.forEach((sa) => {
      const props = sa.properties || sa;
      const sku = sa.sku || {};
      const replication = (sku.name || sku.tier || "").toUpperCase();
      if (replication.includes("LRS") || replication.includes("ZRS")) {
        f.push(_finding({
          id: "BUDR-GEO",
          framework: "BUDR",
          severity: "MEDIUM",
          title: "Storage account without geo-redundancy",
          message: `Storage account "${_rn(sa)}" uses ${replication}: no geographic redundancy`,
          resource: _rn(sa),
          resourceId: sa.id || "",
          resourceType: "Microsoft.Storage/storageAccounts",
          remediation: "Use GRS or RA-GRS replication for critical data; GZRS for zone + geo redundancy"
        }));
      }
    });
    aksClusters.forEach((aks) => {
      const props = aks.properties || aks;
      const agentPools = props.agentPoolProfiles || [];
      const singleNode = agentPools.every((ap) => (ap.count || 1) <= 1);
      if (singleNode) {
        f.push(_finding({
          id: "BUDR-AKS-PDB",
          framework: "BUDR",
          severity: "MEDIUM",
          title: "AKS cluster with single-node pools",
          message: `AKS cluster "${_rn(aks)}" has single-node agent pools: no pod disruption budget effective`,
          resource: _rn(aks),
          resourceId: aks.id || "",
          resourceType: "Microsoft.ContainerService/managedClusters",
          remediation: "Scale agent pools to 2+ nodes and configure PodDisruptionBudgets for workloads"
        }));
      }
    });
    functionApps.forEach((fa) => {
      const props = fa.properties || fa;
      const slots = props.siteConfig?.numberOfWorkers || 0;
      const slotNames = data.deploymentSlots || [];
      const faSlots = slotNames.filter((s) => {
        const sId = (s.id || "").toLowerCase();
        const faId = (fa.id || "").toLowerCase();
        return sId.includes(faId);
      });
      if (faSlots.length === 0) {
        f.push(_finding({
          id: "BUDR-FUNC",
          framework: "BUDR",
          severity: "LOW",
          title: "Function app without deployment slots",
          message: `Function app "${_rn(fa)}" has no deployment slots: no zero-downtime deployment`,
          resource: _rn(fa),
          resourceId: fa.id || "",
          resourceType: "Microsoft.Web/sites",
          remediation: "Create staging deployment slot for blue-green deployments and rollback capability"
        }));
      }
    });
    redisCaches.forEach((rc) => {
      const props = rc.properties || rc;
      const sku = rc.sku || props.sku || {};
      const tier = (sku.name || sku.family || "").toLowerCase();
      const rdbEnabled = props.redisConfiguration?.["rdb-backup-enabled"] === "true";
      const aofEnabled = props.redisConfiguration?.["aof-backup-enabled"] === "true";
      if (tier.includes("premium") && !rdbEnabled && !aofEnabled) {
        f.push(_finding({
          id: "BUDR-REDIS",
          framework: "BUDR",
          severity: "MEDIUM",
          title: "Redis cache without data persistence",
          message: `Premium Redis cache "${_rn(rc)}" has no RDB or AOF persistence: data loss on restart`,
          resource: _rn(rc),
          resourceId: rc.id || "",
          resourceType: "Microsoft.Cache/Redis",
          remediation: "Enable RDB snapshots or AOF persistence for durable caching"
        }));
      }
    });
    return f;
  }
  function runFedRAMPChecks(data, framework) {
    const f = [];
    const roleAssignments = data.roleAssignments || [];
    const logAnalytics = data.logAnalyticsWorkspaces || [];
    const nsgs = data.nsgs || [];
    const nsgFlowLogs = data.nsgFlowLogs || [];
    const storageAccounts = data.storageAccounts || [];
    const keyVaults = data.keyVaults || [];
    const vms = data.vms || [];
    const mfaConfig = data.mfaConfig || {};
    const conditionalAccessPolicies = data.conditionalAccessPolicies || [];
    const managedDisks = data.managedDisks || [];
    const firewalls = data.firewalls || [];
    const defenderPlans = data.defenderPlans || [];
    const roleCount = roleAssignments.length;
    if (roleCount > 100) {
      f.push(_finding({
        id: "FEDRAMP-AC2",
        framework,
        severity: "MEDIUM",
        title: "AC-2: Large number of role assignments",
        message: `${roleCount} role assignments found: review for inactive or excessive access`,
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.Authorization/roleAssignments",
        remediation: "Conduct quarterly access reviews; remove stale assignments; use PIM for JIT access"
      }));
    }
    const ownerAssignments = roleAssignments.filter((ra) => {
      const props = ra.properties || ra;
      const roleId = (props.roleDefinitionId || "").toLowerCase();
      return roleId.includes("owner") || roleId.endsWith("/8e3af657-a8ff-443c-a75c-2fe8c4bcb635");
    });
    if (ownerAssignments.length > 5) {
      f.push(_finding({
        id: "FEDRAMP-AC6",
        framework,
        severity: "HIGH",
        title: "AC-6: Excessive Owner role assignments",
        message: `${ownerAssignments.length} Owner role assignments: violates least privilege principle`,
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.Authorization/roleAssignments",
        remediation: "Reduce Owner assignments; use Contributor or custom roles with scoped permissions"
      }));
    }
    if (logAnalytics.length === 0) {
      f.push(_finding({
        id: "FEDRAMP-AU2",
        framework,
        severity: "CRITICAL",
        title: "AU-2: No audit logging infrastructure",
        message: "No Log Analytics workspace found: audit event collection requirement unmet",
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.OperationalInsights/workspaces",
        remediation: "Deploy Log Analytics workspace; enable Azure Activity Log and resource diagnostic settings"
      }));
    }
    let openRuleCount = 0;
    nsgs.forEach((nsg) => {
      const rules = _getRules(nsg);
      rules.forEach((rule) => {
        const rp = _ruleProps(rule);
        if (rp.direction === "Inbound" && rp.access === "Allow" && _isAllProtocols(rule) && _isAllPorts(rule) && _hasOpenSourcePrefixes(rule)) {
          openRuleCount++;
        }
      });
    });
    if (openRuleCount > 0) {
      f.push(_finding({
        id: "FEDRAMP-CM7",
        framework,
        severity: "HIGH",
        title: "CM-7: Overly permissive network rules",
        message: `${openRuleCount} NSG rule(s) allow all inbound traffic: least functionality violated`,
        resource: "NSGs",
        resourceId: "",
        resourceType: "Microsoft.Network/networkSecurityGroups",
        remediation: 'Remove or restrict all "allow any" inbound rules to specific required ports and sources'
      }));
    }
    const hasMfaPolicy = conditionalAccessPolicies.some((p) => {
      const props = p.properties || p;
      const gc = props.grantControls || {};
      return (gc.builtInControls || []).includes("mfa");
    });
    if (!hasMfaPolicy && conditionalAccessPolicies.length > 0) {
      f.push(_finding({
        id: "FEDRAMP-IA2",
        framework,
        severity: "CRITICAL",
        title: "IA-2: No MFA conditional access policy",
        message: "No conditional access policy enforcing MFA found: identification/authentication gap",
        resource: "Azure AD",
        resourceId: "",
        resourceType: "Microsoft.Authorization/conditionalAccessPolicies",
        remediation: "Create conditional access policy requiring MFA for all users on sensitive operations"
      }));
    }
    if (firewalls.length === 0 && nsgs.length > 0) {
      f.push(_finding({
        id: "FEDRAMP-SC7",
        framework,
        severity: "HIGH",
        title: "SC-7: No centralized boundary protection",
        message: "No Azure Firewall deployed: boundary protection relies only on NSGs",
        resource: "Network",
        resourceId: "",
        resourceType: "Microsoft.Network/azureFirewalls",
        remediation: "Deploy Azure Firewall for centralized boundary protection and traffic inspection"
      }));
    }
    const unencryptedDisks = managedDisks.filter((d) => {
      const props = d.properties || d;
      const enc = props.encryption || {};
      return !enc.type && !enc.diskEncryptionSetId;
    });
    if (unencryptedDisks.length > 0) {
      f.push(_finding({
        id: "FEDRAMP-SC28",
        framework,
        severity: "HIGH",
        title: "SC-28: Unprotected data at rest",
        message: `${unencryptedDisks.length} managed disk(s) without explicit encryption: data at rest protection gap`,
        resource: "Multiple",
        resourceId: "",
        resourceType: "Microsoft.Compute/disks",
        remediation: "Enable encryption with customer-managed keys for all managed disks"
      }));
    }
    if (defenderPlans.length === 0) {
      f.push(_finding({
        id: "FEDRAMP-SI4",
        framework,
        severity: "HIGH",
        title: "SI-4: No system monitoring",
        message: "No Microsoft Defender for Cloud plans enabled: continuous monitoring requirement unmet",
        resource: "Subscription",
        resourceId: "",
        resourceType: "Microsoft.Security/pricings",
        remediation: "Enable Microsoft Defender for Cloud on all resource types for continuous monitoring"
      }));
    }
    return f;
  }
  function clearComplianceCache() {
    _complianceCacheData = null;
    _complianceFindings = [];
  }
  function invalidateComplianceCache() {
    clearComplianceCache();
  }
  function runComplianceChecks(data, cloudEnv) {
    if (_complianceCacheData === data && _complianceFindings.length > 0) {
      return _complianceFindings;
    }
    _complianceCacheData = data;
    const env = cloudEnv || getCloudEnv();
    const frameworks = getComplianceFrameworks(env);
    const findings = [];
    if (frameworks.includes("CIS")) {
      findings.push(...runCISAzureChecks(data));
    }
    if (frameworks.includes("CAF")) {
      findings.push(...runCAFChecks(data));
    }
    if (frameworks.includes("SOC2")) {
      findings.push(...runSOC2Checks(data));
    }
    if (frameworks.includes("PCI")) {
      findings.push(...runPCIChecks(data));
    }
    if (frameworks.includes("BUDR")) {
      findings.push(...runBUDRAzureChecks(data));
    }
    if (frameworks.includes("FEDRAMP_MOD")) {
      findings.push(...runFedRAMPChecks(data, "FEDRAMP_MOD"));
    }
    if (frameworks.includes("FEDRAMP_HIGH")) {
      findings.push(...runFedRAMPChecks(data, "FEDRAMP_HIGH"));
    }
    if (frameworks.includes("NIST_800_171")) {
      findings.push(...runFedRAMPChecks(data, "NIST_800_171"));
    }
    if (frameworks.includes("CMMC")) {
      findings.push(...runFedRAMPChecks(data, "CMMC"));
    }
    try {
      const budrFindings2 = runBUDRChecks(data);
      if (budrFindings2 && budrFindings2.length > 0) {
        findings.push(...budrFindings2);
      }
    } catch (e) {
      console.warn("BUDR engine checks failed:", e);
    }
    try {
      const rbacData = getRbacData();
      if (rbacData) {
        const assignments = rbacData.roleAssignments || rbacData;
        const definitions = rbacData.roleDefinitions || [];
        if (Array.isArray(assignments) && assignments.length) {
          const rbacFindings = analyzeRoleAssignments(assignments, definitions);
          findings.push(...rbacFindings);
        }
      }
    } catch (e) {
      console.warn("IAM compliance checks failed:", e);
    }
    findings.forEach((finding) => {
      if (!finding.checkovId && CKV_MAP[finding.id]) {
        finding.checkovId = CKV_MAP[finding.id];
      }
      if (!finding.control) finding.control = finding.id;
      if (!finding.resourceName) finding.resourceName = finding.resource;
    });
    _complianceFindings = findings;
    if (typeof window !== "undefined") {
      window._complianceFindings = _complianceFindings;
    }
    return _complianceFindings;
  }

  // src/modules/network-rules.js
  var DEFAULT_INBOUND_RULES = [
    {
      name: "AllowVNetInBound",
      priority: 65e3,
      direction: "Inbound",
      access: "Allow",
      protocol: "*",
      sourceAddressPrefix: "VirtualNetwork",
      sourcePortRange: "*",
      destinationAddressPrefix: "VirtualNetwork",
      destinationPortRange: "*"
    },
    {
      name: "AllowAzureLoadBalancerInBound",
      priority: 65001,
      direction: "Inbound",
      access: "Allow",
      protocol: "*",
      sourceAddressPrefix: "AzureLoadBalancer",
      sourcePortRange: "*",
      destinationAddressPrefix: "*",
      destinationPortRange: "*"
    },
    {
      name: "DenyAllInBound",
      priority: 65500,
      direction: "Inbound",
      access: "Deny",
      protocol: "*",
      sourceAddressPrefix: "*",
      sourcePortRange: "*",
      destinationAddressPrefix: "*",
      destinationPortRange: "*"
    }
  ];
  var DEFAULT_OUTBOUND_RULES = [
    {
      name: "AllowVNetOutBound",
      priority: 65e3,
      direction: "Outbound",
      access: "Allow",
      protocol: "*",
      sourceAddressPrefix: "VirtualNetwork",
      sourcePortRange: "*",
      destinationAddressPrefix: "VirtualNetwork",
      destinationPortRange: "*"
    },
    {
      name: "AllowInternetOutBound",
      priority: 65001,
      direction: "Outbound",
      access: "Allow",
      protocol: "*",
      sourceAddressPrefix: "*",
      sourcePortRange: "*",
      destinationAddressPrefix: "Internet",
      destinationPortRange: "*"
    },
    {
      name: "DenyAllOutBound",
      priority: 65500,
      direction: "Outbound",
      access: "Deny",
      protocol: "*",
      sourceAddressPrefix: "*",
      sourcePortRange: "*",
      destinationAddressPrefix: "*",
      destinationPortRange: "*"
    }
  ];
  var PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
  function protocolMatch(ruleProtocol, queryProtocol) {
    if (!ruleProtocol || !queryProtocol) return false;
    const rp = String(ruleProtocol).toLowerCase();
    const qp = String(queryProtocol).toLowerCase();
    if (rp === "*" || qp === "*") return true;
    return rp === qp;
  }
  function parsePortToken(token) {
    const t = token.trim();
    if (t === "*") return { low: 0, high: 65535 };
    if (t.includes("-")) {
      const [lo, hi] = t.split("-").map(Number);
      return { low: lo, high: hi };
    }
    const n = Number(t);
    return { low: n, high: n };
  }
  function portMatch(rulePortRange, queryPort) {
    if (rulePortRange === void 0 || rulePortRange === null) return true;
    const rule = String(rulePortRange).trim();
    if (rule === "*" || rule === "") return true;
    const port = Number(queryPort);
    if (isNaN(port)) return false;
    const segments = rule.split(",");
    for (const seg of segments) {
      const { low, high } = parsePortToken(seg);
      if (port >= low && port <= high) return true;
    }
    return false;
  }
  function isPrivateIp(ip) {
    for (const range of PRIVATE_RANGES) {
      if (ipInCIDR(ip, range)) return true;
    }
    return false;
  }
  function addressMatch(ruleAddress, queryAddress, vnetPrefixes) {
    if (!ruleAddress || !queryAddress) return false;
    const addr = ruleAddress.trim();
    const ip = queryAddress.trim();
    if (addr === "*") return true;
    if (addr === "VirtualNetwork") {
      if (Array.isArray(vnetPrefixes) && vnetPrefixes.length > 0) {
        for (const prefix of vnetPrefixes) {
          if (ipInCIDR(ip, prefix)) return true;
        }
        return false;
      }
      return isPrivateIp(ip);
    }
    if (addr === "AzureLoadBalancer") {
      return ip === "168.63.129.16";
    }
    if (addr === "Internet") {
      if (Array.isArray(vnetPrefixes) && vnetPrefixes.length > 0) {
        for (const prefix of vnetPrefixes) {
          if (ipInCIDR(ip, prefix)) return false;
        }
        return true;
      }
      return !isPrivateIp(ip);
    }
    if (addr.includes("/")) {
      return ipInCIDR(ip, addr);
    }
    return addr === ip;
  }
  function collectAddresses(rule, fieldSingle, fieldArray) {
    const addrs = [];
    if (rule[fieldSingle]) addrs.push(rule[fieldSingle]);
    if (Array.isArray(rule[fieldArray])) {
      for (const a of rule[fieldArray]) addrs.push(a);
    }
    return addrs;
  }
  function collectPorts(rule, fieldSingle, fieldArray) {
    const ports = [];
    if (rule[fieldSingle] !== void 0 && rule[fieldSingle] !== null) {
      ports.push(String(rule[fieldSingle]));
    }
    if (Array.isArray(rule[fieldArray])) {
      for (const p of rule[fieldArray]) ports.push(String(p));
    }
    return ports.length > 0 ? ports : ["*"];
  }
  function ruleMatches(rule, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, vnetPrefixes) {
    const ruleDir = (rule.direction || "").toLowerCase();
    if (ruleDir !== direction.toLowerCase()) return false;
    if (!protocolMatch(rule.protocol, protocol)) return false;
    const srcAddrs = collectAddresses(rule, "sourceAddressPrefix", "sourceAddressPrefixes");
    if (srcAddrs.length > 0) {
      let srcMatch = false;
      for (const sa of srcAddrs) {
        if (addressMatch(sa, srcAddr, vnetPrefixes)) {
          srcMatch = true;
          break;
        }
      }
      if (!srcMatch) return false;
    }
    const dstAddrs = collectAddresses(rule, "destinationAddressPrefix", "destinationAddressPrefixes");
    if (dstAddrs.length > 0) {
      let dstMatch = false;
      for (const da of dstAddrs) {
        if (addressMatch(da, dstAddr, vnetPrefixes)) {
          dstMatch = true;
          break;
        }
      }
      if (!dstMatch) return false;
    }
    const srcPorts = collectPorts(rule, "sourcePortRange", "sourcePortRanges");
    let srcPortMatch = false;
    for (const sp of srcPorts) {
      if (portMatch(sp, srcPort)) {
        srcPortMatch = true;
        break;
      }
    }
    if (!srcPortMatch) return false;
    const dstPorts = collectPorts(rule, "destinationPortRange", "destinationPortRanges");
    let dstPortMatch = false;
    for (const dp of dstPorts) {
      if (portMatch(dp, dstPort)) {
        dstPortMatch = true;
        break;
      }
    }
    if (!dstPortMatch) return false;
    return true;
  }
  var _nsgRuleCache = /* @__PURE__ */ new WeakMap();
  function _getCachedRules(nsg, direction) {
    const dirKey = direction.toLowerCase() === "inbound" ? "in" : "out";
    if (nsg && typeof nsg === "object") {
      let cached = _nsgRuleCache.get(nsg);
      if (cached && cached[dirKey]) return cached[dirKey];
      const customRules = nsg.securityRules || [];
      const defaults2 = dirKey === "in" ? DEFAULT_INBOUND_RULES : DEFAULT_OUTBOUND_RULES;
      const allRules = [...customRules, ...defaults2];
      allRules.sort((a, b) => a.priority - b.priority);
      if (!cached) {
        cached = {};
        _nsgRuleCache.set(nsg, cached);
      }
      cached[dirKey] = allRules;
      return allRules;
    }
    const defaults = dirKey === "in" ? DEFAULT_INBOUND_RULES : DEFAULT_OUTBOUND_RULES;
    return [...defaults].sort((a, b) => a.priority - b.priority);
  }
  function evaluateNsgRules(nsg, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, opts) {
    const vnetPrefixes = opts && opts.vnetPrefixes || [];
    const allRules = _getCachedRules(nsg, direction);
    for (const rule of allRules) {
      if (ruleMatches(rule, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, vnetPrefixes)) {
        return {
          action: rule.access,
          rule,
          priority: rule.priority
        };
      }
    }
    const fallback = direction.toLowerCase() === "inbound" ? DEFAULT_INBOUND_RULES[2] : DEFAULT_OUTBOUND_RULES[2];
    return { action: "Deny", rule: fallback, priority: 65500 };
  }
  function evaluateNsgPath(nicNsg, subnetNsg, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, opts) {
    const noNsgResult = { action: "Allow", rule: { name: "NoNsgAttached" }, priority: 0 };
    const nicResult = nicNsg ? evaluateNsgRules(nicNsg, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, opts) : noNsgResult;
    const subnetResult = subnetNsg ? evaluateNsgRules(subnetNsg, direction, protocol, srcAddr, srcPort, dstAddr, dstPort, opts) : noNsgResult;
    const isInbound = direction.toLowerCase() === "inbound";
    if (isInbound) {
      const allowed2 = subnetResult.action === "Allow" && nicResult.action === "Allow";
      return { allowed: allowed2, subnetResult, nicResult };
    }
    const allowed = nicResult.action === "Allow" && subnetResult.action === "Allow";
    return { allowed, nicResult, subnetResult };
  }
  function buildSystemRoutes(vnetPrefixes) {
    const routes = [];
    if (Array.isArray(vnetPrefixes)) {
      for (const prefix of vnetPrefixes) {
        routes.push({
          name: "System-VNetLocal-" + prefix,
          addressPrefix: prefix,
          nextHopType: "VNetLocal",
          nextHopIpAddress: null,
          isSystem: true
        });
      }
    }
    routes.push({
      name: "System-DefaultToInternet",
      addressPrefix: "0.0.0.0/0",
      nextHopType: "Internet",
      nextHopIpAddress: null,
      isSystem: true
    });
    const nullPrefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"];
    for (const np of nullPrefixes) {
      let coveredByVnet = false;
      if (Array.isArray(vnetPrefixes)) {
        for (const vp of vnetPrefixes) {
          const vpParsed = parseCIDR(vp);
          const npParsed = parseCIDR(np);
          if (vpParsed && npParsed) {
            if (ipInCIDR(intToIpSafe(npParsed.network), vp) || ipInCIDR(intToIpSafe(vpParsed.network), np)) {
              coveredByVnet = true;
              break;
            }
          }
        }
      }
      if (!coveredByVnet) {
        routes.push({
          name: "System-Null-" + np.replace(/[/.]/g, "_"),
          addressPrefix: np,
          nextHopType: "None",
          nextHopIpAddress: null,
          isSystem: true
        });
      }
    }
    return routes;
  }
  function intToIpSafe(n) {
    n = n >>> 0;
    return `${n >>> 24 & 255}.${n >>> 16 & 255}.${n >>> 8 & 255}.${n & 255}`;
  }
  function evaluateRoute(routeTable, destinationIp) {
    if (!destinationIp) {
      return { nextHopType: "None", nextHopIpAddress: null, route: null };
    }
    const ip = destinationIp.trim();
    const vnetPrefixes = routeTable && routeTable.vnetPrefixes || [];
    const udrRoutes = routeTable && routeTable.routes || [];
    const systemRoutes = buildSystemRoutes(vnetPrefixes);
    const taggedUdr = udrRoutes.map((r) => ({ ...r, isSystem: false }));
    const allRoutes = [...taggedUdr, ...systemRoutes];
    let bestMatch = null;
    let bestPrefix = -1;
    let bestIsSystem = true;
    for (const route of allRoutes) {
      const prefix = route.addressPrefix;
      if (!prefix) continue;
      let matches = false;
      if (prefix === "0.0.0.0/0") {
        matches = true;
      } else if (prefix.includes("/")) {
        matches = ipInCIDR(ip, prefix);
      } else {
        matches = ip === prefix;
      }
      if (!matches) continue;
      const prefixLen = prefix.includes("/") ? parseInt(prefix.split("/")[1], 10) : 32;
      if (prefixLen > bestPrefix || prefixLen === bestPrefix && !route.isSystem && bestIsSystem) {
        bestPrefix = prefixLen;
        bestMatch = route;
        bestIsSystem = !!route.isSystem;
      }
    }
    if (!bestMatch) {
      return { nextHopType: "None", nextHopIpAddress: null, route: null };
    }
    return {
      nextHopType: bestMatch.nextHopType || "None",
      nextHopIpAddress: bestMatch.nextHopIpAddress || null,
      route: bestMatch
    };
  }
  function classifySubnet(subnet, routeTable) {
    const result = evaluateRoute(routeTable || {}, "8.8.8.8");
    if (result.nextHopType === "Internet") {
      const isDefault = result.route && result.route.isSystem;
      return {
        classification: "public",
        reason: isDefault ? "Default system route sends 0.0.0.0/0 to Internet" : "UDR explicitly routes 0.0.0.0/0 to Internet"
      };
    }
    if (result.nextHopType === "VirtualAppliance") {
      return {
        classification: "private",
        reason: "UDR routes 0.0.0.0/0 through VirtualAppliance (" + (result.nextHopIpAddress || "NVA") + ")"
      };
    }
    if (result.nextHopType === "VirtualNetworkGateway") {
      return {
        classification: "private",
        reason: "UDR routes 0.0.0.0/0 through VirtualNetworkGateway (forced tunneling)"
      };
    }
    if (result.nextHopType === "None") {
      return {
        classification: "private",
        reason: "UDR drops traffic to 0.0.0.0/0 (nextHopType: None)"
      };
    }
    if (result.nextHopType === "VNetLocal") {
      return {
        classification: "private",
        reason: "Traffic routes to VNetLocal, no Internet egress"
      };
    }
    return {
      classification: "private",
      reason: "No route to Internet found (nextHopType: " + result.nextHopType + ")"
    };
  }

  // src/modules/state.js
  var state_exports = {};
  __export(state_exports, {
    complianceFindings: () => complianceFindings,
    detailLevel: () => detailLevel,
    gTxtScale: () => gTxtScale,
    gwNames: () => gwNames,
    mapG: () => mapG,
    mapSvg: () => mapSvg,
    mapZoom: () => mapZoom,
    rlCtx: () => rlCtx,
    sb: () => sb,
    setComplianceFindings: () => setComplianceFindings,
    setDetailLevel: () => setDetailLevel,
    setGTxtScale: () => setGTxtScale,
    setGwNames: () => setGwNames,
    setMapG: () => setMapG,
    setMapSvg: () => setMapSvg,
    setMapZoom: () => setMapZoom,
    setRlCtx: () => setRlCtx,
    setSb: () => setSb,
    setShowNested: () => setShowNested,
    setSubscriptionId: () => setSubscriptionId,
    setTenantId: () => setTenantId,
    showNested: () => showNested,
    subscriptionId: () => subscriptionId,
    tenantId: () => tenantId
  });
  var rlCtx = null;
  var mapSvg = null;
  var mapZoom = null;
  var mapG = null;
  var gwNames = {};
  var detailLevel = 0;
  var showNested = false;
  var gTxtScale = 1;
  var complianceFindings = [];
  var sb = null;
  var tenantId = "";
  var subscriptionId = "";
  function setRlCtx(v) {
    rlCtx = v;
  }
  function setMapSvg(v) {
    mapSvg = v;
  }
  function setMapZoom(v) {
    mapZoom = v;
  }
  function setMapG(v) {
    mapG = v;
  }
  function setGwNames(v) {
    gwNames = v;
  }
  function setDetailLevel(v) {
    detailLevel = v;
  }
  function setShowNested(v) {
    showNested = v;
  }
  function setGTxtScale(v) {
    gTxtScale = v;
  }
  function setComplianceFindings(v) {
    complianceFindings = v;
  }
  function setSb(v) {
    sb = v;
  }
  function setTenantId(v) {
    tenantId = v;
  }
  function setSubscriptionId(v) {
    subscriptionId = v;
  }

  // src/modules/dom-builders.js
  function buildEl(tag, attrs = {}, children = []) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") el.className = v;
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else if (k.startsWith("data-")) el.setAttribute(k, v);
      else el[k] = v;
    }
    for (const child of children) {
      if (typeof child === "string") el.appendChild(document.createTextNode(child));
      else if (child instanceof Node) el.appendChild(child);
    }
    return el;
  }
  function buildOption(value, text, selected = false) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = text;
    if (selected) opt.selected = true;
    return opt;
  }
  function buildSelect(id, options) {
    const sel = document.createElement("select");
    if (id) sel.id = id;
    for (const o of options) sel.appendChild(buildOption(o.value, o.text));
    return sel;
  }
  function buildButton(text, onClick, className) {
    const btn = document.createElement("button");
    btn.textContent = text;
    if (onClick) btn.addEventListener("click", onClick);
    if (className) btn.className = className;
    return btn;
  }
  function setText(el, text) {
    const target = typeof el === "string" ? document.getElementById(el) : el;
    if (target) target.textContent = String(text);
  }
  function replaceChildren(el, children = []) {
    el.textContent = "";
    for (const child of children) el.appendChild(child);
  }
  function safeHtml(strings, ...values) {
    let result = strings[0];
    for (let i = 0; i < values.length; i++) {
      result += esc(String(values[i] ?? "")) + strings[i + 1];
    }
    return result;
  }

  // src/modules/dep-graph.js
  var depGraph = null;
  var blastActive = false;
  function buildDependencyGraph(ctx) {
    if (!ctx) return {};
    const g = {};
    const addEdge = (from, to, rel, strength) => {
      if (!g[from]) g[from] = [];
      g[from].push({ id: to, rel, strength });
    };
    (ctx.vnets || []).forEach((v) => {
      const vnetId = v.id;
      (ctx.subnets || []).filter((s) => s.properties && s.properties.vnetId === vnetId).forEach((s) => addEdge(vnetId, s.id, "contains", "hard"));
      (ctx.natGateways || []).filter((n) => n.properties && n.properties.vnetId === vnetId).forEach((n) => addEdge(vnetId, n.id, "contains", "hard"));
      (ctx.privateEndpoints || []).filter((e) => e.properties && e.properties.vnetId === vnetId).forEach((e) => addEdge(vnetId, e.id, "contains", "soft"));
      (ctx.udrs || []).filter((rt) => rt.properties && rt.properties.vnetId === vnetId).forEach((rt) => addEdge(vnetId, rt.id, "contains", "config"));
      (ctx.subnetNsgs || []).filter((n) => n.properties && n.properties.vnetId === vnetId).forEach((n) => addEdge(vnetId, n.id, "contains", "config"));
      (ctx.nsgs || []).filter((sg) => sg.properties && sg.properties.vnetId === vnetId).forEach((sg) => addEdge(vnetId, sg.id, "contains", "config"));
      (ctx.peerings || []).filter((p) => p.properties && (p.properties.localVnetId === vnetId || p.properties.remoteVnetId === vnetId)).forEach((p) => addEdge(vnetId, p.id, "peered_with", "soft"));
    });
    (ctx.subnets || []).forEach((sub) => {
      const subId = sub.id;
      ((ctx.vmsBySub || {})[subId] || []).forEach((i) => addEdge(subId, i.id, "contains", "hard"));
      ((ctx.sqlBySub || {})[subId] || []).forEach((r) => addEdge(subId, r.id, "contains", "hard"));
      ((ctx.containersBySub || {})[subId] || []).forEach((e) => addEdge(subId, e.id, "contains", "hard"));
      ((ctx.funcAppsBySub || {})[subId] || []).forEach((l) => addEdge(subId, l.id, "contains", "hard"));
      ((ctx.agwBySub || {})[subId] || []).forEach((a) => addEdge(subId, a.id, "contains", "hard"));
      const udr = (ctx.subUdr || {})[subId];
      if (udr) addEdge(subId, udr.id, "associated", "config");
      const nsg = (ctx.subNsg || {})[subId];
      if (nsg) addEdge(subId, nsg.id, "associated", "config");
      (ctx.privateEndpoints || []).filter((e) => e.properties && e.properties.subnetId === subId).forEach((e) => addEdge(subId, e.id, "contains", "soft"));
      const nat = (ctx.subNat || {})[subId];
      if (nat) addEdge(subId, nat.id, "associated", "config");
    });
    (ctx.vms || []).forEach((vm) => {
      const vmId = vm.id;
      (ctx.nics || []).filter((n) => n.properties && n.properties.virtualMachine && n.properties.virtualMachine.id === vmId).forEach((nic) => {
        addEdge(vmId, nic.id, "attached", "hard");
        if (nic.properties && nic.properties.networkSecurityGroup) addEdge(nic.id, nic.properties.networkSecurityGroup.id, "secured_by", "soft");
      });
      (ctx.disks || []).filter((d) => d.properties && d.managedBy === vmId).forEach((d) => addEdge(vmId, d.id, "attached", "hard"));
    });
    (ctx.sqlServers || []).forEach((db) => {
      if (db.properties && db.properties.networkSecurityGroupId) addEdge(db.id, db.properties.networkSecurityGroupId, "secured_by", "soft");
    });
    (ctx.appGateways || []).forEach((agw) => {
      const agwId = agw.id;
      if (agw.properties && agw.properties.networkSecurityGroupId) addEdge(agwId, agw.properties.networkSecurityGroupId, "secured_by", "soft");
    });
    (ctx.nsgs || []).forEach((sg) => {
      const rules = sg.properties && sg.properties.securityRules || [];
      rules.forEach((r) => {
        const src = r.properties && r.properties.sourceAddressPrefix;
        const dst = r.properties && r.properties.destinationAddressPrefix;
        if (src && src.startsWith("/subscriptions/") && src !== sg.id) addEdge(sg.id, src, "references", "config");
        if (dst && dst.startsWith("/subscriptions/") && dst !== sg.id) addEdge(sg.id, dst, "references", "config");
      });
    });
    (ctx.udrs || []).forEach((rt) => {
      const routes = rt.properties && rt.properties.routes || [];
      routes.forEach((r) => {
        const hop = r.properties && r.properties.nextHopIpAddress;
        if (hop && hop !== "VirtualNetworkGateway" && hop !== "Internet") addEdge(rt.id, hop, "routes_through", "config");
        const hopType = r.properties && r.properties.nextHopType;
        if (hopType === "VirtualAppliance" && hop) addEdge(rt.id, hop, "routes_through", "config");
      });
    });
    (ctx.peerings || []).forEach((p) => {
      if (p.properties && p.properties.localVnetId) addEdge(p.id, p.properties.localVnetId, "connects", "soft");
      if (p.properties && p.properties.remoteVnetId) addEdge(p.id, p.properties.remoteVnetId, "connects", "soft");
    });
    (ctx.natGateways || []).forEach((nat) => {
      const subs = nat.properties && nat.properties.subnets || [];
      subs.forEach((s) => addEdge(nat.id, s.id, "attached_to", "hard"));
    });
    depGraph = g;
    return g;
  }
  function getBlastRadius(resourceId, graph, maxDepth) {
    maxDepth = maxDepth || 5;
    const result = { hard: [], soft: [], config: [], all: [] };
    const visited = /* @__PURE__ */ new Set([resourceId]);
    const queue = [{ id: resourceId, depth: 0 }];
    while (queue.length) {
      const { id, depth } = queue.shift();
      if (depth >= maxDepth) continue;
      const edges = graph[id] || [];
      edges.forEach((e) => {
        if (visited.has(e.id)) return;
        visited.add(e.id);
        const entry = { id: e.id, rel: e.rel, strength: e.strength, depth: depth + 1, parent: id };
        result[e.strength] = result[e.strength] || [];
        result[e.strength].push(entry);
        result.all.push(entry);
        queue.push({ id: e.id, depth: depth + 1 });
      });
    }
    return result;
  }
  function getResType(id) {
    if (!id) return "Unknown";
    const low = id.toLowerCase();
    if (low.includes("/virtualnetworks/") && !low.includes("/subnets/")) return "VNet";
    if (low.includes("/subnets/")) return "Subnet";
    if (low.includes("/virtualmachines/")) return "VM";
    if (low.includes("/networkinterfaces/")) return "NIC";
    if (low.includes("/networksecuritygroups/")) return "NSG";
    if (low.includes("/routetables/")) return "UDR";
    if (low.includes("/natgateways/")) return "NAT Gateway";
    if (low.includes("/privateendpoints/")) return "Private Endpoint";
    if (low.includes("/applicationgateways/")) return "App Gateway";
    if (low.includes("/loadbalancers/")) return "Load Balancer";
    if (low.includes("/disks/")) return "Managed Disk";
    if (low.includes("/virtualnetworkpeerings/")) return "VNet Peering";
    if (low.includes("/virtualnetworkgateways/")) return "VPN Gateway";
    const ctx = rlCtx;
    if (ctx) {
      if ((ctx.sqlServers || []).some((r) => r.id === id)) return "SQL Server";
      if ((ctx.functionApps || []).some((f) => f.id === id)) return "Function App";
      if ((ctx.containerInstances || []).some((e) => e.id === id)) return "Container Instance";
      if ((ctx.redisCaches || []).some((c) => c.id === id)) return "Redis Cache";
      if ((ctx.synapseWorkspaces || []).some((c) => c.id === id)) return "Synapse Workspace";
    }
    if (id.startsWith("/subscriptions/")) return "Azure Resource";
    return "Resource";
  }
  function getResName(id) {
    const ctx = rlCtx;
    if (!ctx) return id;
    const v = (ctx.vnets || []).find((x) => x.id === id);
    if (v) return v.name || id;
    const s = (ctx.subnets || []).find((x) => x.id === id);
    if (s) return s.name || id;
    const i = (ctx.vms || []).find((x) => x.id === id);
    if (i) return i.name || id;
    const sg = (ctx.nsgs || []).find((x) => x.id === id);
    if (sg) return sg.name || id;
    return id;
  }
  function clearBlastRadius() {
    const mg = mapG;
    if (!blastActive || !mg) return;
    blastActive = false;
    mg.selectAll(".blast-dimmed,.blast-glow-hard,.blast-glow-soft,.blast-glow-config").classed("blast-dimmed", false).classed("blast-glow-hard", false).classed("blast-glow-soft", false).classed("blast-glow-config", false);
  }
  function resetDepGraph() {
    depGraph = null;
  }
  function isBlastActive() {
    return blastActive;
  }

  // src/modules/timeline.js
  var timeline_exports = {};
  __export(timeline_exports, {
    _MAX_SNAPSHOTS: () => maxSnapshots,
    _NOTE_CATEGORIES: () => NOTE_CATEGORIES,
    _annotationAuthor: () => annotationAuthor,
    _annotations: () => annotations,
    _snapshots: () => snapshots,
    addAnnotation: () => addAnnotation,
    buildComplianceLookup: () => buildComplianceLookup,
    computeChecksum: () => computeChecksum,
    deleteAnnotation: () => deleteAnnotation,
    escHtml: () => escHtml,
    getAllNotes: () => getAllNotes,
    getAnnotationAuthor: () => getAnnotationAuthor,
    getAnnotations: () => getAnnotations,
    getCurrentSnapshot: () => getCurrentSnapshot,
    getLastAutoSnap: () => getLastAutoSnap,
    getResourceName: () => getResourceName,
    getSnapshots: () => getSnapshots,
    isOrphaned: () => isOrphaned,
    isViewingHistory: () => isViewingHistory,
    noteKey: () => noteKey,
    relTime: () => relTime,
    saveAnnotations: () => saveAnnotations,
    saveSnapshots: () => saveSnapshots,
    setAnnotationAuthor: () => setAnnotationAuthor,
    setAnnotations: () => setAnnotations,
    setCurrentSnapshot: () => setCurrentSnapshot,
    setLastAutoSnap: () => setLastAutoSnap,
    setSnapshots: () => setSnapshots,
    setViewingHistory: () => setViewingHistory,
    updateAnnotation: () => updateAnnotation
  });
  var snapshots = [];
  var viewingHistory = false;
  var currentSnapshot = null;
  var lastAutoSnap = 0;
  var annotations = {};
  var annotationAuthor = "";
  try {
    const s = localStorage.getItem(SNAP_KEY);
    if (s) snapshots = JSON.parse(s);
  } catch (e) {
    snapshots = [];
  }
  try {
    const s = localStorage.getItem(NOTES_KEY);
    if (s) annotations = JSON.parse(s);
  } catch (e) {
  }
  try {
    annotationAuthor = localStorage.getItem("azureMapper_note_author") || "";
  } catch (e) {
  }
  var maxSnapshots = typeof window !== "undefined" && window.electronAPI ? 5 : MAX_SNAPSHOTS;
  function getSnapshots() {
    return snapshots;
  }
  function setSnapshots(v) {
    snapshots = v;
  }
  function isViewingHistory() {
    return viewingHistory;
  }
  function setViewingHistory(v) {
    viewingHistory = v;
  }
  function getCurrentSnapshot() {
    return currentSnapshot;
  }
  function setCurrentSnapshot(v) {
    currentSnapshot = v;
  }
  function getLastAutoSnap() {
    return lastAutoSnap;
  }
  function setLastAutoSnap(v) {
    lastAutoSnap = v;
  }
  function getAnnotations() {
    return annotations;
  }
  function setAnnotations(v) {
    annotations = v;
  }
  function getAnnotationAuthor() {
    return annotationAuthor;
  }
  function setAnnotationAuthor(v) {
    annotationAuthor = v;
    try {
      localStorage.setItem("azureMapper_note_author", v);
    } catch (e) {
    }
  }
  function saveSnapshots() {
    try {
      localStorage.setItem(SNAP_KEY, JSON.stringify(snapshots));
    } catch (e) {
      if (snapshots.length > 4) {
        snapshots = snapshots.slice(Math.floor(snapshots.length / 2));
        try {
          localStorage.setItem(SNAP_KEY, JSON.stringify(snapshots));
        } catch (e2) {
        }
      }
    }
  }
  function computeChecksum(textareas) {
    let s = "";
    Object.keys(textareas).sort().forEach((k) => s += k + ":" + String(textareas[k]).length + ";");
    let h = 0;
    for (let i = 0; i < s.length; i++) {
      h = (h << 5) - h + s.charCodeAt(i);
      h |= 0;
    }
    return h;
  }
  function saveAnnotations() {
    try {
      localStorage.setItem(NOTES_KEY, JSON.stringify(annotations));
    } catch (e) {
    }
  }
  function noteKey(resourceId, accountId) {
    return accountId && accountId !== "default" ? accountId + ":" + resourceId : resourceId;
  }
  function getAllNotes() {
    const all = [];
    Object.entries(annotations).forEach(([rid, notes]) => {
      (Array.isArray(notes) ? notes : [notes]).forEach((n, i) => {
        if (n && n.text) all.push({ ...n, resourceId: rid, noteIndex: i });
      });
    });
    return all.sort((a, b) => new Date(b.updated || b.created || 0) - new Date(a.updated || a.created || 0));
  }
  function relTime(iso) {
    if (!iso) return "";
    const ms = Date.now() - new Date(iso).getTime();
    const s = Math.floor(ms / 1e3), m = Math.floor(s / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
    if (d > 30) return Math.floor(d / 30) + "mo ago";
    if (d > 0) return d + "d ago";
    if (h > 0) return h + "h ago";
    if (m > 0) return m + "m ago";
    return "just now";
  }
  var escHtml = esc;
  function isOrphaned(rid, ctx) {
    if (!ctx) return false;
    if (rid.startsWith("canvas:")) return false;
    const all = /* @__PURE__ */ new Set();
    (ctx.vnets || []).forEach((x) => all.add(x.id));
    (ctx.subnets || []).forEach((x) => all.add(x.id));
    (ctx.vms || []).forEach((x) => all.add(x.id));
    (ctx.firewalls || []).forEach((x) => all.add(x.id));
    (ctx.nats || []).forEach((x) => all.add(x.id));
    (ctx.privateEndpoints || []).forEach((x) => all.add(x.id));
    (ctx.sqlServers || []).forEach((x) => all.add(x.id || x.name));
    (ctx.functionApps || []).forEach((x) => all.add(x.id || x.name));
    (ctx.nsgs || []).forEach((x) => all.add(x.id));
    (ctx.loadBalancers || []).forEach((x) => all.add(x.id || x.name));
    (ctx.redisCaches || []).forEach((x) => all.add(x.id || x.name));
    (ctx.synapseWorkspaces || []).forEach((x) => all.add(x.id || x.name));
    return !all.has(rid);
  }
  function getResourceName(rid, ctx) {
    if (!ctx) return rid;
    const v = (ctx.vnets || []).find((x) => x.id === rid);
    if (v) return gn(v, rid);
    const s = (ctx.subnets || []).find((x) => x.id === rid);
    if (s) return gn(s, rid);
    const i = (ctx.vms || []).find((x) => x.id === rid);
    if (i) return gn(i, rid);
    const r = (ctx.sqlServers || []).find((x) => x.id === rid);
    if (r) return r.name || rid;
    const l = (ctx.functionApps || []).find((x) => x.id === rid);
    if (l) return l.name || rid;
    const sg = (ctx.nsgs || []).find((x) => x.id === rid);
    if (sg) return sg.name || rid;
    return rid;
  }
  function buildComplianceLookup(findings, isMutedFn) {
    const lookup = {};
    if (!findings || !findings.length) return lookup;
    const sevOrder = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 };
    findings.forEach((f) => {
      if (isMutedFn && isMutedFn(f)) return;
      const rid = f.resource;
      if (!rid || rid === "Multiple") return;
      if (!lookup[rid]) lookup[rid] = { worst: "LOW", count: 0, findings: [] };
      lookup[rid].count++;
      lookup[rid].findings.push(f);
      if ((sevOrder[f.severity] || 9) < (sevOrder[lookup[rid].worst] || 9)) lookup[rid].worst = f.severity;
    });
    return lookup;
  }
  function addAnnotation(resourceId, text, category, pinned) {
    if (!text || !text.trim()) return;
    const note = {
      text: text.trim(),
      category: category || "info",
      author: annotationAuthor || "",
      created: (/* @__PURE__ */ new Date()).toISOString(),
      updated: (/* @__PURE__ */ new Date()).toISOString(),
      pinned: !!pinned
    };
    if (!annotations[resourceId]) annotations[resourceId] = [];
    if (!Array.isArray(annotations[resourceId])) annotations[resourceId] = [annotations[resourceId]];
    annotations[resourceId].push(note);
    saveAnnotations();
    return note;
  }
  function updateAnnotation(resourceId, noteIndex, text, category, pinned) {
    if (!annotations[resourceId] || !annotations[resourceId][noteIndex]) return;
    const n = annotations[resourceId][noteIndex];
    if (text !== void 0) n.text = text;
    if (category !== void 0) n.category = category;
    if (pinned !== void 0) n.pinned = pinned;
    n.updated = (/* @__PURE__ */ new Date()).toISOString();
    saveAnnotations();
  }
  function deleteAnnotation(resourceId, noteIndex) {
    if (!annotations[resourceId]) return;
    annotations[resourceId].splice(noteIndex, 1);
    if (annotations[resourceId].length === 0) delete annotations[resourceId];
    saveAnnotations();
  }

  // src/modules/design-mode.js
  var design_mode_exports = {};
  __export(design_mode_exports, {
    _azureConstraints: () => _azureConstraints,
    _designApplyFns: () => _designApplyFns,
    _generateCLI: () => _generateCLI,
    _generateWarnings: () => _generateWarnings,
    _locationZones: () => _locationZones,
    getAvailableLocations: () => getAvailableLocations,
    getDesignBaseline: () => getDesignBaseline,
    getDesignChanges: () => getDesignChanges,
    getDesignDebounce: () => getDesignDebounce,
    getDesignLocation: () => getDesignLocation,
    getDesignMode: () => getDesignMode,
    getLastDesignValidation: () => getLastDesignValidation,
    getSidebarWasCollapsed: () => getSidebarWasCollapsed,
    getZoneCount: () => getZoneCount,
    importDesignPlan: () => importDesignPlan,
    setDesignBaseline: () => setDesignBaseline,
    setDesignChanges: () => setDesignChanges,
    setDesignDebounce: () => setDesignDebounce,
    setDesignLocation: () => setDesignLocation,
    setDesignMode: () => setDesignMode,
    setLastDesignValidation: () => setLastDesignValidation,
    setSidebarWasCollapsed: () => setSidebarWasCollapsed,
    validateDesignChange: () => validateDesignChange,
    validateDesignState: () => validateDesignState
  });
  var _designMode = false;
  var _designChanges = [];
  var _designBaseline = null;
  var _designDebounce = null;
  var _lastDesignValidation = null;
  var _sidebarWasCollapsed = false;
  var _designLocation = "eastus";
  function getDesignMode() {
    return _designMode;
  }
  function setDesignMode(v) {
    _designMode = v;
  }
  function getDesignChanges() {
    return _designChanges;
  }
  function setDesignChanges(v) {
    _designChanges = v;
  }
  function getDesignBaseline() {
    return _designBaseline;
  }
  function setDesignBaseline(v) {
    _designBaseline = v;
  }
  function getDesignDebounce() {
    return _designDebounce;
  }
  function setDesignDebounce(v) {
    _designDebounce = v;
  }
  function getLastDesignValidation() {
    return _lastDesignValidation;
  }
  function setLastDesignValidation(v) {
    _lastDesignValidation = v;
  }
  function getSidebarWasCollapsed() {
    return _sidebarWasCollapsed;
  }
  function setSidebarWasCollapsed(v) {
    _sidebarWasCollapsed = v;
  }
  function getDesignLocation() {
    return _designLocation;
  }
  function setDesignLocation(v) {
    _designLocation = v;
  }
  var _locationZones = {
    "eastus": 3,
    "eastus2": 3,
    "westus2": 3,
    "westus3": 3,
    "centralus": 3,
    "northcentralus": 0,
    "southcentralus": 3,
    "westeurope": 3,
    "northeurope": 3,
    "uksouth": 3,
    "ukwest": 0,
    "francecentral": 3,
    "germanywestcentral": 3,
    "swedencentral": 3,
    "norwayeast": 3,
    "switzerlandnorth": 3,
    "southeastasia": 3,
    "eastasia": 3,
    "japaneast": 3,
    "australiaeast": 3,
    "canadacentral": 3,
    "brazilsouth": 3,
    "koreacentral": 3,
    "southafricanorth": 3,
    "qatarcentral": 3,
    "uaenorth": 3,
    "israelcentral": 3,
    "italynorth": 3,
    "polandcentral": 3
  };
  var _azureConstraints = {
    vnet: {
      cidrPrefixMin: 8,
      cidrPrefixMax: 29,
      maxAddressPrefixes: 500,
      maxPerSubscription: 1e3,
      rfc1918: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
      cgnat: "100.64.0.0/10",
      reservedPrefixes: ["224.0.0.0/4", "255.255.255.255/32", "127.0.0.0/8", "169.254.0.0/16", "168.63.129.16/32"]
    },
    subnet: {
      cidrPrefixMin: 8,
      cidrPrefixMax: 29,
      reservedIps: 5,
      // first 4 (network, gateway, 2x Azure DNS) + last (broadcast)
      maxPerVnet: 3e3,
      specialSubnets: {
        AzureFirewallSubnet: { minPrefix: 26, exactName: true },
        AzureFirewallManagementSubnet: { minPrefix: 26, exactName: true },
        AzureBastionSubnet: { minPrefix: 26, exactName: true },
        GatewaySubnet: { minPrefix: 27, exactName: true },
        RouteServerSubnet: { minPrefix: 27, exactName: true }
      }
    },
    nsg: {
      maxPerSubscription: 5e3,
      maxRulesPerNsg: 1e3,
      defaultPriority: { min: 100, max: 4096 },
      reservedPriority: 65e3
      // Azure default rules start at 65000
    },
    routeTable: {
      maxPerSubscription: 200,
      maxRoutesPerTable: 400,
      reservedNextHops: ["VirtualNetworkGateway", "VnetLocal", "Internet", "VirtualAppliance", "None"]
    },
    peering: {
      maxPerVnet: 500,
      noOverlappingCidrs: true,
      onePeerPerVnetPair: true
    },
    natGateway: {
      maxPerSubnet: 1,
      maxPublicIps: 16,
      maxPublicPrefixes: 16
    },
    publicIp: {
      maxPerSubscription: 1e3
    }
  };
  function validateDesignChange(change, ctx) {
    const errors = [], warnings = [];
    const vnets = ctx ? ctx.vnets || [] : [];
    const subnets = ctx ? ctx.subnets || [] : [];
    const nsgs = ctx ? ctx.nsgs || [] : [];
    const routeTables = ctx ? ctx.routeTables || [] : [];
    const natGateways = ctx ? ctx.natGateways || [] : [];
    const peerings = ctx ? ctx.peerings || [] : [];
    if (change.action === "add_vnet") {
      const p = change.params;
      const cidr = parseCIDR(p.addressPrefix);
      if (!cidr) {
        errors.push("Invalid CIDR: " + p.addressPrefix);
        return { valid: false, errors, warnings };
      }
      const prefix = parseInt(p.addressPrefix.split("/")[1], 10);
      if (prefix < _azureConstraints.vnet.cidrPrefixMin || prefix > _azureConstraints.vnet.cidrPrefixMax)
        errors.push("VNet address prefix must be /8 to /29, got /" + prefix);
      const isRfc1918 = _azureConstraints.vnet.rfc1918.some((r) => cidrContains(r, p.addressPrefix));
      const isCgnat = cidrContains(_azureConstraints.vnet.cgnat, p.addressPrefix);
      if (!isRfc1918 && !isCgnat) warnings.push("CIDR " + p.addressPrefix + " is not RFC 1918 or CGNAT range: verify this is intentional for public IP usage");
      const isReserved = _azureConstraints.vnet.reservedPrefixes.some((r) => cidrOverlap(p.addressPrefix, r));
      if (isReserved) errors.push("Address prefix " + p.addressPrefix + " overlaps with a reserved range");
      vnets.forEach((v) => {
        const vnetPrefixes = v.addressSpace?.addressPrefixes || [v.addressPrefix];
        vnetPrefixes.forEach((vp) => {
          if (cidrOverlap(p.addressPrefix, vp))
            errors.push("Overlaps existing VNet " + gn(v) + " (" + vp + ")");
        });
      });
      if (vnets.length >= _azureConstraints.vnet.maxPerSubscription)
        warnings.push("Exceeds default limit of " + _azureConstraints.vnet.maxPerSubscription + " VNets per subscription");
    }
    if (change.action === "add_subnet") {
      const p = change.params;
      const cidr = parseCIDR(p.addressPrefix);
      if (!cidr) {
        errors.push("Invalid CIDR: " + p.addressPrefix);
        return { valid: false, errors, warnings };
      }
      const prefix = parseInt(p.addressPrefix.split("/")[1], 10);
      if (prefix < _azureConstraints.subnet.cidrPrefixMin || prefix > _azureConstraints.subnet.cidrPrefixMax)
        errors.push("Subnet address prefix must be /8 to /29, got /" + prefix);
      const vnet = vnets.find((v) => v.id === p.vnetId || v.name === p.vnetName);
      if (!vnet) {
        errors.push("VNet " + (p.vnetId || p.vnetName) + " not found");
        return { valid: false, errors, warnings };
      }
      const vnetPrefixes = vnet.addressSpace?.addressPrefixes || [vnet.addressPrefix];
      const withinVnet = vnetPrefixes.some((vp) => cidrContains(vp, p.addressPrefix));
      if (!withinVnet) errors.push("Subnet CIDR " + p.addressPrefix + " is not within VNet address space");
      const vnetId = vnet.id || vnet.name;
      const vnetSubs = subnets.filter((s) => s._vnetId === vnetId || s.vnetName === vnet.name);
      vnetSubs.forEach((s) => {
        const subPrefix = s.addressPrefix || s.properties?.addressPrefix;
        if (subPrefix && cidrOverlap(p.addressPrefix, subPrefix))
          errors.push("Overlaps subnet " + gn(s) + " (" + subPrefix + ")");
      });
      if (vnetSubs.length >= _azureConstraints.subnet.maxPerVnet)
        warnings.push("Exceeds limit of " + _azureConstraints.subnet.maxPerVnet + " subnets per VNet");
      const specialSubnet = _azureConstraints.subnet.specialSubnets[p.name];
      if (specialSubnet) {
        if (prefix > specialSubnet.minPrefix)
          errors.push(p.name + " requires minimum /" + specialSubnet.minPrefix + ", got /" + prefix);
      }
      const usable = Math.pow(2, 32 - prefix) - _azureConstraints.subnet.reservedIps;
      warnings.push(usable + " usable IPs (" + _azureConstraints.subnet.reservedIps + " reserved by Azure: first 4 + last 1)");
    }
    if (change.action === "split_subnet") {
      const subPrefix = change.target.addressPrefix || "";
      const prefix = parseInt(subPrefix.split("/")[1], 10);
      if (prefix >= _azureConstraints.subnet.cidrPrefixMax)
        errors.push("Cannot split /" + prefix + " subnet (minimum Azure subnet is /" + _azureConstraints.subnet.cidrPrefixMax + ")");
      else {
        const newPrefix = prefix + 1;
        const usable = Math.pow(2, 32 - newPrefix) - _azureConstraints.subnet.reservedIps;
        warnings.push("Each half: /" + newPrefix + " = " + usable + " usable IPs");
        if (usable < 8) warnings.push("Very small subnets: limited IP capacity");
      }
      const resources = ctx ? (ctx.resourcesBySub || {})[change.target.subnetId] || [] : [];
      if (resources.length) warnings.push(resources.length + " resource(s) will require IP-based migration");
    }
    if (change.action === "add_nat_gateway") {
      const p = change.params;
      if (p.subnetId) {
        const subNats = natGateways.filter((n) => n.subnetId === p.subnetId);
        if (subNats.length >= _azureConstraints.natGateway.maxPerSubnet)
          errors.push("Subnet already has a NAT Gateway (limit: 1 per subnet)");
      }
    }
    if (change.action === "add_route") {
      const p = change.params;
      const t = change.target;
      const dest = p.addressPrefix;
      if (dest !== "0.0.0.0/0" && !parseCIDR(dest)) errors.push("Invalid destination prefix: " + dest);
      const rt = routeTables.find((r) => r.id === t.routeTableId || r.name === t.routeTableName);
      if (rt) {
        const routes = rt.properties?.routes || rt.routes || [];
        if (routes.some((r) => (r.properties?.addressPrefix || r.addressPrefix) === dest))
          errors.push("Route table already has a route for " + dest);
        if (routes.length >= _azureConstraints.routeTable.maxRoutesPerTable)
          warnings.push("Exceeds limit of " + _azureConstraints.routeTable.maxRoutesPerTable + " routes per table");
      }
      if (dest === "0.0.0.0/0" && p.nextHopType === "Internet")
        warnings.push("This will route all internet traffic directly: ensure NSG rules are appropriate");
    }
    if (change.action === "add_nsg") {
      const p = change.params;
      if (nsgs.length >= _azureConstraints.nsg.maxPerSubscription)
        warnings.push("Exceeds limit of " + _azureConstraints.nsg.maxPerSubscription + " NSGs per subscription");
      const rules = [...p.securityRules || []];
      if (rules.length > _azureConstraints.nsg.maxRulesPerNsg)
        errors.push("Exceeds limit of " + _azureConstraints.nsg.maxRulesPerNsg + " rules per NSG");
      rules.forEach((r) => {
        if (r.properties?.sourceAddressPrefix === "*" && r.properties?.access === "Allow") {
          const port = r.properties?.destinationPortRange;
          if (port !== "80" && port !== "443")
            warnings.push('Rule "' + (r.name || "unnamed") + '" allows all sources (*) on port ' + port + ": consider restricting");
        }
      });
    }
    if (change.action === "add_resource") {
      const p = change.params;
      if (p.subnetId) {
        const sub = subnets.find((s) => s.id === p.subnetId || s.name === p.subnetName);
        if (sub) {
          const subAddrPrefix = sub.addressPrefix || sub.properties?.addressPrefix || "";
          const prefix = parseInt(subAddrPrefix.split("/")[1], 10);
          const usable = Math.pow(2, 32 - prefix) - _azureConstraints.subnet.reservedIps;
          const currentResources = (ctx ? (ctx.resourcesBySub || {})[p.subnetId] || [] : []).length;
          const remaining = usable - currentResources;
          if (remaining <= 0) warnings.push("Subnet " + gn(sub) + " has no remaining IP capacity (" + usable + " usable, " + currentResources + " used)");
          else if (remaining < 5) warnings.push("Subnet " + gn(sub) + " has only " + remaining + " IPs remaining");
        }
      }
    }
    if (change.action === "remove_resource") {
      const t = change.target;
      if (t.resourceType === "Microsoft.Network/natGateways") {
        const affectedSubs = subnets.filter(
          (s) => (s.properties?.natGateway?.id || s.natGatewayId) === t.resourceId
        );
        if (affectedSubs.length) warnings.push(affectedSubs.length + " subnet(s) reference this NAT Gateway: they will lose outbound connectivity");
      }
      if (t.resourceType === "subnet") {
        const resources = ctx ? (ctx.resourcesBySub || {})[t.resourceId] || [] : [];
        if (resources.length) warnings.push(resources.length + " resource(s) in this subnet will lose connectivity");
      }
      if (t.resourceType === "Microsoft.Network/networkSecurityGroups") {
        const affectedSubs = subnets.filter(
          (s) => (s.properties?.networkSecurityGroup?.id || s.nsgId) === t.resourceId
        );
        if (affectedSubs.length) warnings.push(affectedSubs.length + " subnet(s) reference this NSG: they will lose security rules");
      }
    }
    if (change.action === "add_peering") {
      const p = change.params;
      const localVnet = vnets.find((v) => v.id === p.localVnetId || v.name === p.localVnetName);
      const remoteVnet = vnets.find((v) => v.id === p.remoteVnetId || v.name === p.remoteVnetName);
      if (localVnet && remoteVnet) {
        const localPrefixes = localVnet.addressSpace?.addressPrefixes || [localVnet.addressPrefix];
        const remotePrefixes = remoteVnet.addressSpace?.addressPrefixes || [remoteVnet.addressPrefix];
        localPrefixes.forEach((lp) => {
          remotePrefixes.forEach((rp) => {
            if (cidrOverlap(lp, rp))
              errors.push("Peering CIDRs overlap: " + lp + " / " + rp);
          });
        });
      }
      const vnetPeerings = peerings.filter(
        (peer) => peer.localVnetId === p.localVnetId || peer.remoteVnetId === p.localVnetId
      );
      if (vnetPeerings.length >= _azureConstraints.peering.maxPerVnet)
        warnings.push("Exceeds limit of " + _azureConstraints.peering.maxPerVnet + " peerings per VNet");
    }
    return { valid: errors.length === 0, errors, warnings };
  }
  function validateDesignState(changes, ctx) {
    const errors = [], warnings = [], stats = {
      subnetsAdded: 0,
      natGatewaysAdded: 0,
      resourcesAdded: 0,
      removed: 0,
      routes: 0,
      nsgs: 0,
      peerings: 0
    };
    changes.forEach((ch) => {
      if (ch.action === "add_subnet") stats.subnetsAdded++;
      if (ch.action === "add_nat_gateway") stats.natGatewaysAdded++;
      if (ch.action === "add_resource") stats.resourcesAdded++;
      if (ch.action === "remove_resource") stats.removed++;
      if (ch.action === "add_route") stats.routes++;
      if (ch.action === "add_nsg") stats.nsgs++;
      if (ch.action === "add_peering") stats.peerings++;
    });
    if (ctx) {
      const subsByVnet = {};
      (ctx.subnets || []).forEach((s) => {
        const vnetId = s._vnetId || s.vnetId || "";
        (subsByVnet[vnetId] = subsByVnet[vnetId] || []).push(s);
      });
      Object.entries(subsByVnet).forEach(([vid, subs]) => {
        for (let i = 0; i < subs.length; i++) {
          for (let j = i + 1; j < subs.length; j++) {
            const cidrA = subs[i].addressPrefix || subs[i].properties?.addressPrefix || "";
            const cidrB = subs[j].addressPrefix || subs[j].properties?.addressPrefix || "";
            if (cidrA && cidrB && cidrOverlap(cidrA, cidrB))
              errors.push("Subnets " + gn(subs[i]) + " and " + gn(subs[j]) + " have overlapping address prefixes");
          }
        }
      });
      const peerPairs = [];
      (ctx.peerings || []).forEach((p) => {
        const localPrefixes = p.localAddressPrefixes || [];
        const remotePrefixes = p.remoteAddressPrefixes || [];
        localPrefixes.forEach((lp) => {
          remotePrefixes.forEach((rp) => {
            if (cidrOverlap(lp, rp))
              errors.push("VNet Peering " + gn(p) + ": address spaces overlap: " + lp + " / " + rp);
          });
        });
        const pair = [p.localVnetId, p.remoteVnetId].filter(Boolean).sort().join(":");
        if (pair && peerPairs.includes(pair)) warnings.push("Duplicate peering between VNets");
        if (pair) peerPairs.push(pair);
      });
      (ctx.subnets || []).forEach((s) => {
        const hasNsg = s.properties?.networkSecurityGroup || s.nsgId;
        if (!hasNsg && s.name !== "GatewaySubnet")
          warnings.push("Subnet " + gn(s) + " has no NSG attached: traffic is unrestricted");
      });
    }
    return { valid: errors.length === 0, errors, warnings, stats };
  }
  function _applyAddVnet(ch, getTa, setTa) {
    const raw = safeParse(getTa("in_vnets"));
    const vnets = raw ? ext(raw, ["value"]) : [];
    const id = ch.params.vnetId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.Network/virtualNetworks/vnet-design-" + Date.now();
    ch.params.vnetId = id;
    const name = ch.params.name || "New-VNet";
    const vnet = {
      id,
      name,
      type: "Microsoft.Network/virtualNetworks",
      location: ch.params.location || _designLocation,
      properties: {
        addressSpace: { addressPrefixes: [ch.params.addressPrefix] },
        subnets: [],
        provisioningState: "Succeeded"
      },
      tags: ch.params.tags || {}
    };
    vnet.addressPrefix = ch.params.addressPrefix;
    vnet.addressSpace = vnet.properties.addressSpace;
    vnets.push(vnet);
    setTa("in_vnets", JSON.stringify({ value: vnets }));
    ch._addedIds = [id];
    const nsgRaw = safeParse(getTa("in_nsgs"));
    const nsgs = nsgRaw ? ext(nsgRaw, ["value"]) : [];
    const nsgId = ch.params._nsgId || id.replace("/virtualNetworks/", "/networkSecurityGroups/").replace(name, name + "-default-nsg");
    ch.params._nsgId = nsgId;
    nsgs.push({
      id: nsgId,
      name: name + "-default-nsg",
      type: "Microsoft.Network/networkSecurityGroups",
      location: ch.params.location || _designLocation,
      properties: {
        securityRules: [],
        defaultSecurityRules: [
          { name: "AllowVnetInBound", properties: { priority: 65e3, direction: "Inbound", access: "Allow", protocol: "*", sourceAddressPrefix: "VirtualNetwork", destinationAddressPrefix: "VirtualNetwork", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "AllowAzureLoadBalancerInBound", properties: { priority: 65001, direction: "Inbound", access: "Allow", protocol: "*", sourceAddressPrefix: "AzureLoadBalancer", destinationAddressPrefix: "*", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "DenyAllInBound", properties: { priority: 65500, direction: "Inbound", access: "Deny", protocol: "*", sourceAddressPrefix: "*", destinationAddressPrefix: "*", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "AllowVnetOutBound", properties: { priority: 65e3, direction: "Outbound", access: "Allow", protocol: "*", sourceAddressPrefix: "VirtualNetwork", destinationAddressPrefix: "VirtualNetwork", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "AllowInternetOutBound", properties: { priority: 65001, direction: "Outbound", access: "Allow", protocol: "*", sourceAddressPrefix: "*", destinationAddressPrefix: "Internet", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "DenyAllOutBound", properties: { priority: 65500, direction: "Outbound", access: "Deny", protocol: "*", sourceAddressPrefix: "*", destinationAddressPrefix: "*", sourcePortRange: "*", destinationPortRange: "*" } }
        ],
        provisioningState: "Succeeded"
      }
    });
    setTa("in_nsgs", JSON.stringify({ value: nsgs }));
  }
  function _applyAddSubnet(ch, getTa, setTa) {
    const raw = safeParse(getTa("in_subnets"));
    const subs = raw ? ext(raw, ["value"]) : [];
    const subId = ch.params.subnetId || ch.params.vnetId + "/subnets/subnet-design-" + Date.now();
    ch.params.subnetId = subId;
    const subnet = {
      id: subId,
      name: ch.params.name || "New-Subnet",
      type: "Microsoft.Network/virtualNetworks/subnets",
      properties: {
        addressPrefix: ch.params.addressPrefix,
        provisioningState: "Succeeded"
      },
      _vnetId: ch.params.vnetId,
      vnetName: ch.params.vnetName,
      addressPrefix: ch.params.addressPrefix
    };
    if (ch.params.nsgId) {
      subnet.properties.networkSecurityGroup = { id: ch.params.nsgId };
      subnet.nsgId = ch.params.nsgId;
    }
    if (ch.params.routeTableId) {
      subnet.properties.routeTable = { id: ch.params.routeTableId };
      subnet.routeTableId = ch.params.routeTableId;
    }
    subs.push(subnet);
    setTa("in_subnets", JSON.stringify({ value: subs }));
    ch._addedIds = [subId];
  }
  function _applySplitSubnet(ch, getTa, setTa) {
    const raw = safeParse(getTa("in_subnets"));
    const subs = raw ? ext(raw, ["value"]) : [];
    const idx = subs.findIndex((s) => s.id === ch.target.subnetId || s.name === ch.target.subnetName);
    if (idx < 0) return;
    const orig = subs[idx];
    const origPrefix = orig.addressPrefix || orig.properties?.addressPrefix || "";
    const halves = splitCIDR(origPrefix);
    if (!halves) return;
    if (!ch.params.newIds) ch.params.newIds = [orig.id + "-a", orig.id + "-b"];
    const sub1 = {
      ...orig,
      id: ch.params.newIds[0],
      name: ch.params.names?.[0] || gn(orig) + "-a",
      addressPrefix: halves[0],
      properties: { ...orig.properties, addressPrefix: halves[0] }
    };
    const sub2 = {
      ...orig,
      id: ch.params.newIds[1],
      name: ch.params.names?.[1] || gn(orig) + "-b",
      addressPrefix: halves[1],
      properties: { ...orig.properties, addressPrefix: halves[1] }
    };
    subs.splice(idx, 1, sub1, sub2);
    setTa("in_subnets", JSON.stringify({ value: subs }));
    ch._removedIds = [ch.target.subnetId];
    ch._addedIds = [sub1.id, sub2.id];
    const vmRaw = safeParse(getTa("in_vms"));
    if (vmRaw) {
      const vms = ext(vmRaw, ["value"]);
      vms.forEach((vm) => {
        const nicIds = vm.properties?.networkProfile?.networkInterfaces || [];
        nicIds.forEach((nicRef) => {
          if (nicRef._subnetId === ch.target.subnetId && nicRef._privateIp) {
            nicRef._subnetId = ipInCIDR(nicRef._privateIp, halves[0]) ? sub1.id : sub2.id;
          }
        });
      });
      setTa("in_vms", JSON.stringify({ value: vms }));
    }
  }
  function _applyAddNatGateway(ch, getTa, setTa) {
    const raw = safeParse(getTa("in_nat_gateways"));
    const nats = raw ? ext(raw, ["value"]) : [];
    const id = ch.params.natGatewayId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.Network/natGateways/nat-design-" + Date.now();
    ch.params.natGatewayId = id;
    nats.push({
      id,
      name: ch.params.name || "New-NAT-Gateway",
      type: "Microsoft.Network/natGateways",
      location: ch.params.location || _designLocation,
      properties: {
        provisioningState: "Succeeded",
        publicIpAddresses: ch.params.publicIpIds ? ch.params.publicIpIds.map((pip) => ({ id: pip })) : [],
        subnets: ch.params.subnetId ? [{ id: ch.params.subnetId }] : []
      },
      subnetId: ch.params.subnetId
    });
    setTa("in_nat_gateways", JSON.stringify({ value: nats }));
    ch._addedIds = [id];
  }
  function _applyAddRoute(ch, getTa, setTa) {
    const raw = safeParse(getTa("in_route_tables"));
    const rts = raw ? ext(raw, ["value"]) : [];
    const rt = rts.find((r) => r.id === ch.target.routeTableId || r.name === ch.target.routeTableName);
    if (!rt) return;
    if (!rt.properties) rt.properties = {};
    if (!rt.properties.routes) rt.properties.routes = [];
    rt.properties.routes.push({
      name: ch.params.routeName || "route-" + Date.now(),
      properties: {
        addressPrefix: ch.params.addressPrefix,
        nextHopType: ch.params.nextHopType,
        nextHopIpAddress: ch.params.nextHopIpAddress || void 0,
        provisioningState: "Succeeded"
      }
    });
    setTa("in_route_tables", JSON.stringify({ value: rts }));
    ch._modifiedIds = [ch.target.routeTableId];
  }
  function _applyAddResource(ch, getTa, setTa) {
    const type = ch.params.resourceType;
    if (type === "VM") {
      const raw = safeParse(getTa("in_vms"));
      const vms = raw ? ext(raw, ["value"]) : [];
      const id = ch.params.resourceId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.Compute/virtualMachines/vm-design-" + Date.now();
      ch.params.resourceId = id;
      vms.push({
        id,
        name: ch.params.name || "New-VM",
        type: "Microsoft.Compute/virtualMachines",
        location: ch.params.location || _designLocation,
        properties: {
          vmId: id,
          hardwareProfile: { vmSize: ch.params.vmSize || "Standard_B2s" },
          storageProfile: { osDisk: { osType: ch.params.osType || "Linux" } },
          networkProfile: {
            networkInterfaces: [{
              id: id.replace("/virtualMachines/", "/networkInterfaces/") + "-nic",
              _subnetId: ch.params.subnetId,
              _privateIp: ch.params.privateIp || ""
            }]
          },
          provisioningState: "Succeeded"
        },
        _subnetId: ch.params.subnetId,
        _vnetId: ch.params.vnetId
      });
      setTa("in_vms", JSON.stringify({ value: vms }));
      ch._addedIds = [id];
    } else if (type === "SQLDatabase") {
      const raw = safeParse(getTa("in_sql"));
      const dbs = raw ? ext(raw, ["value"]) : [];
      const id = ch.params.resourceId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.Sql/servers/sql-design-" + Date.now();
      ch.params.resourceId = id;
      dbs.push({
        id,
        name: ch.params.name || "new-sql-server",
        type: "Microsoft.Sql/servers",
        location: ch.params.location || _designLocation,
        properties: {
          fullyQualifiedDomainName: (ch.params.name || "new-sql-server") + ".database.windows.net",
          administratorLogin: "sqladmin",
          state: "Ready"
        },
        _subnetId: ch.params.subnetId,
        _vnetId: ch.params.vnetId
      });
      setTa("in_sql", JSON.stringify({ value: dbs }));
      ch._addedIds = [id];
    } else if (type === "FunctionApp") {
      const raw = safeParse(getTa("in_functions"));
      const fns = raw ? ext(raw, ["value"]) : [];
      const id = ch.params.resourceId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.Web/sites/func-design-" + Date.now();
      ch.params.resourceId = id;
      fns.push({
        id,
        name: ch.params.name || "new-function",
        type: "Microsoft.Web/sites",
        kind: "functionapp",
        location: ch.params.location || _designLocation,
        properties: {
          state: "Running",
          defaultHostName: (ch.params.name || "new-function") + ".azurewebsites.net",
          virtualNetworkSubnetId: ch.params.subnetId
        },
        _subnetId: ch.params.subnetId,
        _vnetId: ch.params.vnetId
      });
      setTa("in_functions", JSON.stringify({ value: fns }));
      ch._addedIds = [id];
    } else if (type === "AKS") {
      const raw = safeParse(getTa("in_aks"));
      const clusters = raw ? ext(raw, ["value"]) : [];
      const id = ch.params.resourceId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.ContainerService/managedClusters/aks-design-" + Date.now();
      ch.params.resourceId = id;
      clusters.push({
        id,
        name: ch.params.name || "new-aks-cluster",
        type: "Microsoft.ContainerService/managedClusters",
        location: ch.params.location || _designLocation,
        properties: {
          provisioningState: "Succeeded",
          agentPoolProfiles: [{
            name: "nodepool1",
            count: ch.params.nodeCount || 3,
            vmSize: ch.params.vmSize || "Standard_DS2_v2",
            vnetSubnetID: ch.params.subnetId
          }],
          networkProfile: {
            networkPlugin: ch.params.networkPlugin || "azure",
            serviceCidr: ch.params.serviceCidr || "10.0.0.0/16",
            dnsServiceIP: ch.params.dnsServiceIP || "10.0.0.10"
          }
        },
        _subnetId: ch.params.subnetId,
        _vnetId: ch.params.vnetId
      });
      setTa("in_aks", JSON.stringify({ value: clusters }));
      ch._addedIds = [id];
    } else if (type === "AppService") {
      const raw = safeParse(getTa("in_appservices"));
      const apps = raw ? ext(raw, ["value"]) : [];
      const id = ch.params.resourceId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.Web/sites/app-design-" + Date.now();
      ch.params.resourceId = id;
      apps.push({
        id,
        name: ch.params.name || "new-app",
        type: "Microsoft.Web/sites",
        kind: "app",
        location: ch.params.location || _designLocation,
        properties: {
          state: "Running",
          defaultHostName: (ch.params.name || "new-app") + ".azurewebsites.net",
          virtualNetworkSubnetId: ch.params.subnetId
        },
        _subnetId: ch.params.subnetId,
        _vnetId: ch.params.vnetId
      });
      setTa("in_appservices", JSON.stringify({ value: apps }));
      ch._addedIds = [id];
    } else if (type === "Redis") {
      const raw = safeParse(getTa("in_redis"));
      const caches = raw ? ext(raw, ["value"]) : [];
      const id = ch.params.resourceId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.Cache/Redis/redis-design-" + Date.now();
      ch.params.resourceId = id;
      caches.push({
        id,
        name: ch.params.name || "new-redis",
        type: "Microsoft.Cache/Redis",
        location: ch.params.location || _designLocation,
        properties: {
          provisioningState: "Succeeded",
          hostName: (ch.params.name || "new-redis") + ".redis.cache.windows.net",
          port: 6380,
          sku: { name: ch.params.skuName || "Standard", family: "C", capacity: ch.params.capacity || 1 },
          subnetId: ch.params.subnetId
        },
        _subnetId: ch.params.subnetId,
        _vnetId: ch.params.vnetId
      });
      setTa("in_redis", JSON.stringify({ value: caches }));
      ch._addedIds = [id];
    }
  }
  function _applyAddNsg(ch, getTa, setTa) {
    const raw = safeParse(getTa("in_nsgs"));
    const nsgs = raw ? ext(raw, ["value"]) : [];
    const id = ch.params.nsgId || "/subscriptions/design/resourceGroups/" + (ch.params.resourceGroup || "design-rg") + "/providers/Microsoft.Network/networkSecurityGroups/nsg-design-" + Date.now();
    ch.params.nsgId = id;
    const nsg = {
      id,
      name: ch.params.name || "new-nsg",
      type: "Microsoft.Network/networkSecurityGroups",
      location: ch.params.location || _designLocation,
      properties: {
        securityRules: [],
        defaultSecurityRules: [
          { name: "AllowVnetInBound", properties: { priority: 65e3, direction: "Inbound", access: "Allow", protocol: "*", sourceAddressPrefix: "VirtualNetwork", destinationAddressPrefix: "VirtualNetwork", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "DenyAllInBound", properties: { priority: 65500, direction: "Inbound", access: "Deny", protocol: "*", sourceAddressPrefix: "*", destinationAddressPrefix: "*", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "AllowVnetOutBound", properties: { priority: 65e3, direction: "Outbound", access: "Allow", protocol: "*", sourceAddressPrefix: "VirtualNetwork", destinationAddressPrefix: "VirtualNetwork", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "AllowInternetOutBound", properties: { priority: 65001, direction: "Outbound", access: "Allow", protocol: "*", sourceAddressPrefix: "*", destinationAddressPrefix: "Internet", sourcePortRange: "*", destinationPortRange: "*" } },
          { name: "DenyAllOutBound", properties: { priority: 65500, direction: "Outbound", access: "Deny", protocol: "*", sourceAddressPrefix: "*", destinationAddressPrefix: "*", sourcePortRange: "*", destinationPortRange: "*" } }
        ],
        provisioningState: "Succeeded"
      }
    };
    if (ch.params.securityRules) {
      ch.params.securityRules.forEach((r) => {
        nsg.properties.securityRules.push({
          name: r.name || "rule-" + Date.now(),
          properties: {
            priority: r.priority || 100,
            direction: r.direction || "Inbound",
            access: r.access || "Allow",
            protocol: r.protocol || "Tcp",
            sourceAddressPrefix: r.sourceAddressPrefix || "*",
            destinationAddressPrefix: r.destinationAddressPrefix || "*",
            sourcePortRange: r.sourcePortRange || "*",
            destinationPortRange: r.destinationPortRange || "*",
            provisioningState: "Succeeded"
          }
        });
      });
    }
    nsgs.push(nsg);
    setTa("in_nsgs", JSON.stringify({ value: nsgs }));
    ch._addedIds = [id];
  }
  function _applyRemoveResource(ch, getTa, setTa) {
    ch._removedIds = [ch.target.resourceId];
    const type = ch.target.resourceType;
    if (type === "VM" || type === "Microsoft.Compute/virtualMachines") {
      const raw = safeParse(getTa("in_vms"));
      if (!raw) return;
      const vms = ext(raw, ["value"]);
      setTa("in_vms", JSON.stringify({ value: vms.filter((v) => v.id !== ch.target.resourceId) }));
    } else if (type === "SQLDatabase" || type === "Microsoft.Sql/servers") {
      const raw = safeParse(getTa("in_sql"));
      const dbs = raw ? ext(raw, ["value"]) : [];
      setTa("in_sql", JSON.stringify({ value: dbs.filter((d) => d.id !== ch.target.resourceId) }));
    } else if (type === "FunctionApp" || type === "Microsoft.Web/sites") {
      const raw = safeParse(getTa("in_functions"));
      const fns = raw ? ext(raw, ["value"]) : [];
      setTa("in_functions", JSON.stringify({ value: fns.filter((f) => f.id !== ch.target.resourceId) }));
    } else if (type === "subnet") {
      const raw = safeParse(getTa("in_subnets"));
      const subs = raw ? ext(raw, ["value"]) : [];
      setTa("in_subnets", JSON.stringify({ value: subs.filter((s) => s.id !== ch.target.resourceId) }));
    } else if (type === "Microsoft.Network/natGateways") {
      const raw = safeParse(getTa("in_nat_gateways"));
      const nats = raw ? ext(raw, ["value"]) : [];
      setTa("in_nat_gateways", JSON.stringify({ value: nats.filter((n) => n.id !== ch.target.resourceId) }));
    } else if (type === "Microsoft.Network/networkSecurityGroups") {
      const raw = safeParse(getTa("in_nsgs"));
      const nsgs = raw ? ext(raw, ["value"]) : [];
      setTa("in_nsgs", JSON.stringify({ value: nsgs.filter((n) => n.id !== ch.target.resourceId) }));
    } else if (type === "AKS" || type === "Microsoft.ContainerService/managedClusters") {
      const raw = safeParse(getTa("in_aks"));
      const clusters = raw ? ext(raw, ["value"]) : [];
      setTa("in_aks", JSON.stringify({ value: clusters.filter((c) => c.id !== ch.target.resourceId) }));
    } else if (type === "Redis" || type === "Microsoft.Cache/Redis") {
      const raw = safeParse(getTa("in_redis"));
      const caches = raw ? ext(raw, ["value"]) : [];
      setTa("in_redis", JSON.stringify({ value: caches.filter((c) => c.id !== ch.target.resourceId) }));
    } else if (type === "AppService") {
      const raw = safeParse(getTa("in_appservices"));
      const apps = raw ? ext(raw, ["value"]) : [];
      setTa("in_appservices", JSON.stringify({ value: apps.filter((a) => a.id !== ch.target.resourceId) }));
    }
  }
  var _designApplyFns = {
    add_vnet: _applyAddVnet,
    add_subnet: _applyAddSubnet,
    split_subnet: _applySplitSubnet,
    add_nat_gateway: _applyAddNatGateway,
    add_route: _applyAddRoute,
    add_resource: _applyAddResource,
    add_nsg: _applyAddNsg,
    add_peering: null,
    // peering mutations handled inline for now
    remove_resource: _applyRemoveResource
  };
  function _generateCLI(ch) {
    const cmds = [];
    const rg = ch.params.resourceGroup || "$RESOURCE_GROUP";
    const loc = ch.params.location || _designLocation;
    if (ch.action === "add_vnet") {
      cmds.push(`az network vnet create --resource-group ${rg} --name ${ch.params.name || "new-vnet"} --address-prefixes ${ch.params.addressPrefix} --location ${loc}`);
      cmds.push("# Default NSG is NOT created automatically: create one explicitly if needed");
    }
    if (ch.action === "add_subnet") {
      const vnetName = ch.params.vnetName || "$VNET_NAME";
      let cmd = `az network vnet subnet create --resource-group ${rg} --vnet-name ${vnetName} --name ${ch.params.name || "new-subnet"} --address-prefixes ${ch.params.addressPrefix}`;
      if (ch.params.nsgId) cmd += ` --network-security-group ${ch.params.nsgName || ch.params.nsgId}`;
      if (ch.params.routeTableId) cmd += ` --route-table ${ch.params.routeTableName || ch.params.routeTableId}`;
      cmds.push(cmd);
    }
    if (ch.action === "split_subnet") {
      cmds.push("# Split subnet: delete original, create two new");
      const vnetName = ch.params.vnetName || "$VNET_NAME";
      cmds.push(`az network vnet subnet delete --resource-group ${rg} --vnet-name ${vnetName} --name ${ch.target.subnetName || "$SUBNET_NAME"}`);
      const halves = splitCIDR(ch.target.addressPrefix);
      if (halves) {
        cmds.push(`az network vnet subnet create --resource-group ${rg} --vnet-name ${vnetName} --name ${ch.params.names?.[0] || "split-a"} --address-prefixes ${halves[0]}`);
        cmds.push(`az network vnet subnet create --resource-group ${rg} --vnet-name ${vnetName} --name ${ch.params.names?.[1] || "split-b"} --address-prefixes ${halves[1]}`);
      }
    }
    if (ch.action === "add_nat_gateway") {
      cmds.push(`az network public-ip create --resource-group ${rg} --name ${(ch.params.name || "nat") + "-pip"} --sku Standard --location ${loc}`);
      cmds.push(`az network nat gateway create --resource-group ${rg} --name ${ch.params.name || "new-nat-gateway"} --public-ip-addresses ${(ch.params.name || "nat") + "-pip"} --idle-timeout 10 --location ${loc}`);
      if (ch.params.subnetId || ch.params.subnetName) {
        cmds.push(`az network vnet subnet update --resource-group ${rg} --vnet-name $VNET_NAME --name ${ch.params.subnetName || "$SUBNET_NAME"} --nat-gateway ${ch.params.name || "new-nat-gateway"}`);
      }
    }
    if (ch.action === "add_route") {
      const rtName = ch.target.routeTableName || "$ROUTE_TABLE_NAME";
      let cmd = `az network route-table route create --resource-group ${rg} --route-table-name ${rtName} --name ${ch.params.routeName || "new-route"} --address-prefix ${ch.params.addressPrefix} --next-hop-type ${ch.params.nextHopType}`;
      if (ch.params.nextHopIpAddress) cmd += ` --next-hop-ip-address ${ch.params.nextHopIpAddress}`;
      cmds.push(cmd);
    }
    if (ch.action === "add_nsg") {
      cmds.push(`az network nsg create --resource-group ${rg} --name ${ch.params.name || "new-nsg"} --location ${loc}`);
      if (ch.params.securityRules) {
        ch.params.securityRules.forEach((r) => {
          cmds.push(`az network nsg rule create --resource-group ${rg} --nsg-name ${ch.params.name || "new-nsg"} --name ${r.name || "rule"} --priority ${r.priority || 100} --direction ${r.direction || "Inbound"} --access ${r.access || "Allow"} --protocol ${r.protocol || "Tcp"} --source-address-prefixes "${r.sourceAddressPrefix || "*"}" --destination-address-prefixes "${r.destinationAddressPrefix || "*"}" --destination-port-ranges "${r.destinationPortRange || "*"}"`);
        });
      }
    }
    if (ch.action === "add_resource") {
      if (ch.params.resourceType === "VM") {
        cmds.push(`az vm create --resource-group ${rg} --name ${ch.params.name || "new-vm"} --image ${ch.params.image || "Ubuntu2204"} --size ${ch.params.vmSize || "Standard_B2s"} --subnet ${ch.params.subnetName || "$SUBNET_NAME"} --vnet-name ${ch.params.vnetName || "$VNET_NAME"} --admin-username azureuser --generate-ssh-keys --location ${loc}`);
      }
      if (ch.params.resourceType === "SQLDatabase") {
        cmds.push(`az sql server create --resource-group ${rg} --name ${ch.params.name || "new-sql-server"} --admin-user sqladmin --admin-password $SQL_PASSWORD --location ${loc}`);
        cmds.push(`az sql db create --resource-group ${rg} --server ${ch.params.name || "new-sql-server"} --name ${ch.params.dbName || "defaultdb"} --service-objective ${ch.params.serviceObjective || "S0"}`);
      }
      if (ch.params.resourceType === "FunctionApp") {
        cmds.push(`az functionapp create --resource-group ${rg} --name ${ch.params.name || "new-function"} --storage-account $STORAGE_ACCOUNT --runtime ${ch.params.runtime || "node"} --functions-version 4 --os-type ${ch.params.osType || "Linux"}`);
        if (ch.params.subnetId) cmds.push(`az functionapp vnet-integration add --resource-group ${rg} --name ${ch.params.name || "new-function"} --vnet ${ch.params.vnetName || "$VNET_NAME"} --subnet ${ch.params.subnetName || "$SUBNET_NAME"}`);
      }
      if (ch.params.resourceType === "AKS") {
        cmds.push(`az aks create --resource-group ${rg} --name ${ch.params.name || "new-aks"} --node-count ${ch.params.nodeCount || 3} --node-vm-size ${ch.params.vmSize || "Standard_DS2_v2"} --network-plugin ${ch.params.networkPlugin || "azure"} --vnet-subnet-id ${ch.params.subnetId || "$SUBNET_ID"} --generate-ssh-keys --location ${loc}`);
      }
      if (ch.params.resourceType === "AppService") {
        cmds.push(`az webapp create --resource-group ${rg} --name ${ch.params.name || "new-app"} --plan $APP_SERVICE_PLAN`);
        if (ch.params.subnetId) cmds.push(`az webapp vnet-integration add --resource-group ${rg} --name ${ch.params.name || "new-app"} --vnet ${ch.params.vnetName || "$VNET_NAME"} --subnet ${ch.params.subnetName || "$SUBNET_NAME"}`);
      }
      if (ch.params.resourceType === "Redis") {
        cmds.push(`az redis create --resource-group ${rg} --name ${ch.params.name || "new-redis"} --sku ${ch.params.skuName || "Standard"} --vm-size ${ch.params.capacity || "c1"} --location ${loc}`);
        if (ch.params.subnetId) cmds.push(`az redis update --resource-group ${rg} --name ${ch.params.name || "new-redis"} --set subnetId=${ch.params.subnetId}`);
      }
    }
    if (ch.action === "add_peering") {
      const localVnet = ch.params.localVnetName || "$LOCAL_VNET";
      const remoteVnet = ch.params.remoteVnetName || "$REMOTE_VNET";
      const remoteVnetId = ch.params.remoteVnetId || "$REMOTE_VNET_ID";
      cmds.push(`az network vnet peering create --resource-group ${rg} --name ${localVnet}-to-${remoteVnet} --vnet-name ${localVnet} --remote-vnet ${remoteVnetId} --allow-vnet-access`);
      cmds.push(`# Create reverse peering in remote VNet's resource group:`);
      cmds.push(`az network vnet peering create --resource-group $REMOTE_RG --name ${remoteVnet}-to-${localVnet} --vnet-name ${remoteVnet} --remote-vnet ${ch.params.localVnetId || "$LOCAL_VNET_ID"} --allow-vnet-access`);
    }
    if (ch.action === "remove_resource") {
      const id = ch.target.resourceId;
      const name = ch.target.resourceName || id.split("/").pop();
      const t = ch.target.resourceType;
      if (t === "VM" || t === "Microsoft.Compute/virtualMachines")
        cmds.push(`az vm delete --resource-group ${rg} --name ${name} --yes`);
      if (t === "SQLDatabase" || t === "Microsoft.Sql/servers")
        cmds.push(`az sql server delete --resource-group ${rg} --name ${name} --yes`);
      if (t === "FunctionApp" || t === "Microsoft.Web/sites")
        cmds.push(`az functionapp delete --resource-group ${rg} --name ${name}`);
      if (t === "subnet")
        cmds.push(`az network vnet subnet delete --resource-group ${rg} --vnet-name $VNET_NAME --name ${name}`);
      if (t === "Microsoft.Network/natGateways")
        cmds.push(`az network nat gateway delete --resource-group ${rg} --name ${name}`);
      if (t === "Microsoft.Network/networkSecurityGroups")
        cmds.push(`az network nsg delete --resource-group ${rg} --name ${name}`);
      if (t === "AKS" || t === "Microsoft.ContainerService/managedClusters")
        cmds.push(`az aks delete --resource-group ${rg} --name ${name} --yes`);
      if (t === "Redis" || t === "Microsoft.Cache/Redis")
        cmds.push(`az redis delete --resource-group ${rg} --name ${name} --yes`);
      if (t === "AppService")
        cmds.push(`az webapp delete --resource-group ${rg} --name ${name}`);
    }
    return cmds;
  }
  function _generateWarnings() {
    const w = [];
    const splits = _designChanges.filter((c) => c.action === "split_subnet");
    if (splits.length) w.push(splits.length + " subnet split(s) require resource migration");
    const removes = _designChanges.filter((c) => c.action === "remove_resource");
    if (removes.length) w.push(removes.length + " resource removal(s): verify dependencies first");
    const noNsg = _designChanges.filter((c) => c.action === "add_subnet" && !c.params.nsgId);
    if (noNsg.length) w.push(noNsg.length + " new subnet(s) without NSG: consider attaching one");
    return w;
  }
  function importDesignPlan(json, enterFn, addChangeFn) {
    try {
      const plan = typeof json === "string" ? JSON.parse(json) : json;
      if (!plan.changes || !Array.isArray(plan.changes)) {
        alert("Invalid plan format");
        return;
      }
      if (!_designMode) enterFn();
      if (plan.location) _designLocation = plan.location;
      let imported = 0, blocked = 0;
      plan.changes.forEach((ch) => {
        addChangeFn(ch);
        if (ch._invalid) blocked++;
        else imported++;
      });
      if (blocked > 0) alert("Imported " + imported + " changes, " + blocked + " blocked by validation errors. Check the change log for details.");
    } catch (e) {
      alert("Failed to import plan: " + e.message);
    }
  }
  function getAvailableLocations() {
    return Object.keys(_locationZones).sort();
  }
  function getZoneCount(location) {
    return _locationZones[location] || 0;
  }
  Object.defineProperty(window, "_designMode", {
    get() {
      return _designMode;
    },
    set(v) {
      _designMode = v;
    },
    configurable: true
  });
  Object.defineProperty(window, "_designChanges", {
    get() {
      return _designChanges;
    },
    set(v) {
      _designChanges = v;
    },
    configurable: true
  });
  Object.defineProperty(window, "_designBaseline", {
    get() {
      return _designBaseline;
    },
    set(v) {
      _designBaseline = v;
    },
    configurable: true
  });
  Object.defineProperty(window, "_designDebounce", {
    get() {
      return _designDebounce;
    },
    set(v) {
      _designDebounce = v;
    },
    configurable: true
  });
  Object.defineProperty(window, "_lastDesignValidation", {
    get() {
      return _lastDesignValidation;
    },
    set(v) {
      _lastDesignValidation = v;
    },
    configurable: true
  });
  Object.defineProperty(window, "_sidebarWasCollapsed", {
    get() {
      return _sidebarWasCollapsed;
    },
    set(v) {
      _sidebarWasCollapsed = v;
    },
    configurable: true
  });
  Object.defineProperty(window, "_designLocation", {
    get() {
      return _designLocation;
    },
    set(v) {
      _designLocation = v;
    },
    configurable: true
  });
  window._locationZones = _locationZones;
  window._azureConstraints = _azureConstraints;
  window._designApplyFns = _designApplyFns;
  window.validateDesignChange = validateDesignChange;
  window.validateDesignState = validateDesignState;
  window._generateCLI = _generateCLI;
  window._generateWarnings = _generateWarnings;
  window.importDesignPlan = importDesignPlan;
  window.getAvailableLocations = getAvailableLocations;
  window.getZoneCount = getZoneCount;
  window.getDesignMode = getDesignMode;
  window.setDesignMode = setDesignMode;
  window.getDesignChanges = getDesignChanges;
  window.setDesignChanges = setDesignChanges;
  window.getDesignBaseline = getDesignBaseline;
  window.setDesignBaseline = setDesignBaseline;
  window.getDesignDebounce = getDesignDebounce;
  window.setDesignDebounce = setDesignDebounce;
  window.getLastDesignValidation = getLastDesignValidation;
  window.setLastDesignValidation = setLastDesignValidation;
  window.getSidebarWasCollapsed = getSidebarWasCollapsed;
  window.setSidebarWasCollapsed = setSidebarWasCollapsed;
  window.getDesignLocation = getDesignLocation;
  window.setDesignLocation = setDesignLocation;

  // src/modules/flow-tracing.js
  var flow_tracing_exports = {};
  __export(flow_tracing_exports, {
    buildPeRedirectHop: () => buildPeRedirectHop,
    findAlternatePaths: () => findAlternatePaths,
    findPeForTarget: () => findPeForTarget,
    getFlowActiveLeg: () => getFlowActiveLeg,
    getFlowBlocked: () => getFlowBlocked,
    getFlowConfig: () => getFlowConfig,
    getFlowLegs: () => getFlowLegs,
    getFlowMode: () => getFlowMode,
    getFlowPath: () => getFlowPath,
    getFlowSelecting: () => getFlowSelecting,
    getFlowSelectingWaypoint: () => getFlowSelectingWaypoint,
    getFlowSource: () => getFlowSource,
    getFlowStepIndex: () => getFlowStepIndex,
    getFlowSuggestions: () => getFlowSuggestions,
    getFlowTarget: () => getFlowTarget,
    getFlowWaypoints: () => getFlowWaypoints,
    hopTypeLabel: () => hopTypeLabel,
    resetFlowState: () => resetFlowState,
    resolveClickTarget: () => resolveClickTarget,
    resolveNetworkPosition: () => resolveNetworkPosition,
    setFlowActiveLeg: () => setFlowActiveLeg,
    setFlowBlocked: () => setFlowBlocked,
    setFlowConfig: () => setFlowConfig,
    setFlowLegs: () => setFlowLegs,
    setFlowMode: () => setFlowMode,
    setFlowPath: () => setFlowPath,
    setFlowSelecting: () => setFlowSelecting,
    setFlowSelectingWaypoint: () => setFlowSelectingWaypoint,
    setFlowSource: () => setFlowSource,
    setFlowStepIndex: () => setFlowStepIndex,
    setFlowSuggestions: () => setFlowSuggestions,
    setFlowTarget: () => setFlowTarget,
    setFlowWaypoints: () => setFlowWaypoints,
    suggestPort: () => suggestPort,
    traceFlow: () => traceFlow,
    traceFlowLeg: () => traceFlowLeg,
    traceInternetToResource: () => traceInternetToResource,
    traceResourceToInternet: () => traceResourceToInternet
  });
  var _flowMode = false;
  var _flowSource = null;
  var _flowTarget = null;
  var _flowConfig = { protocol: "Tcp", port: 443 };
  var _flowPath = null;
  var _flowBlocked = null;
  var _flowStepIndex = -1;
  var _flowSelecting = null;
  var _flowWaypoints = [];
  var _flowLegs = [];
  var _flowActiveLeg = -1;
  var _flowSelectingWaypoint = -1;
  var _flowSuggestions = [];
  function getFlowMode() {
    return _flowMode;
  }
  function setFlowMode(v) {
    _flowMode = v;
  }
  function getFlowSource() {
    return _flowSource;
  }
  function setFlowSource(v) {
    _flowSource = v;
  }
  function getFlowTarget() {
    return _flowTarget;
  }
  function setFlowTarget(v) {
    _flowTarget = v;
  }
  function getFlowConfig() {
    return _flowConfig;
  }
  function setFlowConfig(v) {
    _flowConfig = v;
  }
  function getFlowPath() {
    return _flowPath;
  }
  function setFlowPath(v) {
    _flowPath = v;
  }
  function getFlowBlocked() {
    return _flowBlocked;
  }
  function setFlowBlocked(v) {
    _flowBlocked = v;
  }
  function getFlowStepIndex() {
    return _flowStepIndex;
  }
  function setFlowStepIndex(v) {
    _flowStepIndex = v;
  }
  function getFlowSelecting() {
    return _flowSelecting;
  }
  function setFlowSelecting(v) {
    _flowSelecting = v;
  }
  function getFlowWaypoints() {
    return _flowWaypoints;
  }
  function setFlowWaypoints(v) {
    _flowWaypoints = v;
  }
  function getFlowLegs() {
    return _flowLegs;
  }
  function setFlowLegs(v) {
    _flowLegs = v;
  }
  function getFlowActiveLeg() {
    return _flowActiveLeg;
  }
  function setFlowActiveLeg(v) {
    _flowActiveLeg = v;
  }
  function getFlowSelectingWaypoint() {
    return _flowSelectingWaypoint;
  }
  function setFlowSelectingWaypoint(v) {
    _flowSelectingWaypoint = v;
  }
  function getFlowSuggestions() {
    return _flowSuggestions;
  }
  function setFlowSuggestions(v) {
    _flowSuggestions = v;
  }
  function resetFlowState() {
    _flowMode = false;
    _flowSource = null;
    _flowTarget = null;
    _flowConfig = { protocol: "Tcp", port: 443 };
    _flowPath = null;
    _flowBlocked = null;
    _flowStepIndex = -1;
    _flowSelecting = null;
    _flowWaypoints = [];
    _flowLegs = [];
    _flowActiveLeg = -1;
    _flowSelectingWaypoint = -1;
    _flowSuggestions = [];
  }
  function ipFromCidr(cidr) {
    if (!cidr || typeof cidr !== "string") return null;
    return cidr.split("/")[0];
  }
  function getVnetPrefixes(vnetId, ctx) {
    if (!vnetId || !ctx) return [];
    var vnet = (ctx.vnets || []).find(function(v) {
      return v.id === vnetId;
    });
    if (!vnet) return [];
    var addrSpace = vnet.addressSpace || vnet.properties?.addressSpace || {};
    return addrSpace.addressPrefixes || [];
  }
  function getNicNsg(nicId, ctx) {
    if (!nicId || !ctx) return null;
    var nic = (ctx.nics || []).find(function(n) {
      return n.id === nicId;
    });
    if (!nic) return null;
    var nsgRef = nic.networkSecurityGroup || nic.properties && nic.properties.networkSecurityGroup;
    if (!nsgRef || !nsgRef.id) return null;
    return (ctx.nsgs || []).find(function(nsg) {
      return nsg.id === nsgRef.id;
    });
  }
  function getSubnetNsg(subnetId, ctx) {
    if (!subnetId || !ctx) return null;
    return (ctx.subnetNsgs || {})[subnetId] || null;
  }
  function getSubnetRouteTable(subnetId, ctx) {
    if (!subnetId || !ctx) return null;
    return (ctx.subRT || {})[subnetId] || null;
  }
  function azureName(resource, fallback) {
    if (!resource) return fallback || "unknown";
    return resource.name || resource.Name || fallback || "unknown";
  }
  function suggestPort(targetType, targetResource) {
    if (targetType === "sqldb") return 1433;
    if (targetType === "mysql") return 3306;
    if (targetType === "postgresql") return 5432;
    if (targetType === "cosmosdb") return 443;
    if (targetType === "redis") return 6380;
    if (targetType === "lb") return 443;
    if (targetType === "appgw") return 443;
    if (targetType === "vm") return 22;
    if (targetType === "functionapp") return 443;
    if (targetType === "containerapp") return 443;
    if (targetType === "aks") return 443;
    return 443;
  }
  var HOP_TYPE_LABELS = {
    "source": "Source",
    "target": "Target",
    "udr": "Route Table (UDR)",
    "nic-nsg-outbound": "NIC NSG Outbound",
    "nic-nsg-inbound": "NIC NSG Inbound",
    "subnet-nsg-outbound": "Subnet NSG Outbound",
    "subnet-nsg-inbound": "Subnet NSG Inbound",
    "peering": "VNet Peering",
    "vnet-gateway": "VNet Gateway",
    "cross-vnet": "Cross-VNet",
    "error": "Error",
    "internet-check": "Internet Route Check",
    "pe-redirect": "Private Endpoint"
  };
  function hopTypeLabel(type) {
    return HOP_TYPE_LABELS[type] || type;
  }
  function resolveNetworkPosition(type, id, ctx) {
    if (!ctx) return null;
    if (type === "internet") {
      return { subnetId: null, vnetId: null, cidr: "0.0.0.0/0", nicNsg: null, subnetNsg: null, name: "Internet", ip: "0.0.0.0" };
    }
    if (type === "subnet") {
      var sub = (ctx.subnets || []).find(function(s) {
        return s.id === id;
      });
      if (!sub) return null;
      return {
        subnetId: sub.id,
        vnetId: sub.vnetId,
        cidr: sub.addressPrefix,
        nicNsg: null,
        subnetNsg: getSubnetNsg(sub.id, ctx),
        name: azureName(sub, sub.id)
      };
    }
    if (type === "vm") {
      var vm = null;
      Object.keys(ctx.vmsBySub || {}).forEach(function(sid2) {
        (ctx.vmsBySub[sid2] || []).forEach(function(v) {
          if (v.id === id || v.name === id) vm = v;
        });
      });
      if (!vm) return null;
      var vmSubnetId = vm.subnetId || null;
      var vmNicId = vm.nicId || null;
      var vmNicNsg = getNicNsg(vmNicId, ctx);
      var vmSubnetNsg = getSubnetNsg(vmSubnetId, ctx);
      var vmVnetId = vmSubnetId ? ((ctx.subnets || []).find(function(s) {
        return s.id === vmSubnetId;
      }) || {}).vnetId : null;
      return {
        subnetId: vmSubnetId,
        vnetId: vmVnetId,
        cidr: vm.privateIpAddress ? vm.privateIpAddress + "/32" : null,
        nicNsg: vmNicNsg,
        subnetNsg: vmSubnetNsg,
        name: azureName(vm, id),
        ip: vm.privateIpAddress,
        nicId: vmNicId
      };
    }
    if (type === "sqldb" || type === "mysql" || type === "postgresql" || type === "cosmosdb") {
      var db = null;
      var dbSid = null;
      Object.keys(ctx.dbBySub || {}).forEach(function(sid2) {
        (ctx.dbBySub[sid2] || []).forEach(function(d) {
          if (d.id === id || d.name === id) {
            db = d;
            dbSid = sid2;
          }
        });
      });
      if (!db) return null;
      var dbVnet = ((ctx.subnets || []).find(function(s) {
        return s.id === dbSid;
      }) || {}).vnetId;
      var dbSubnetNsg = getSubnetNsg(dbSid, ctx);
      var dbSubCidr = dbSid ? ((ctx.subnets || []).find(function(s) {
        return s.id === dbSid;
      }) || {}).addressPrefix : null;
      return { subnetId: dbSid, vnetId: dbVnet, cidr: dbSubCidr, nicNsg: null, subnetNsg: dbSubnetNsg, name: azureName(db, id) };
    }
    if (type === "lb" || type === "appgw") {
      var lb = null;
      var lbSid = null;
      Object.keys(ctx.lbBySub || {}).forEach(function(sid2) {
        (ctx.lbBySub[sid2] || []).forEach(function(a) {
          if (a.id === id || a.name === id) {
            lb = a;
            lbSid = sid2;
          }
        });
      });
      if (!lb) return null;
      var lbVnet = ((ctx.subnets || []).find(function(s) {
        return s.id === lbSid;
      }) || {}).vnetId;
      var lbNicNsg = getNicNsg(lb.nicId, ctx);
      var lbSubnetNsg = getSubnetNsg(lbSid, ctx);
      return { subnetId: lbSid, vnetId: lbVnet, cidr: null, nicNsg: lbNicNsg, subnetNsg: lbSubnetNsg, name: azureName(lb, id) };
    }
    if (type === "functionapp") {
      var fn = null;
      var fnSid = null;
      Object.keys(ctx.funcAppBySub || {}).forEach(function(sid2) {
        (ctx.funcAppBySub[sid2] || []).forEach(function(f) {
          if (f.id === id || f.name === id) {
            fn = f;
            fnSid = sid2;
          }
        });
      });
      if (!fn) return null;
      var fnVnet = ((ctx.subnets || []).find(function(s) {
        return s.id === fnSid;
      }) || {}).vnetId;
      var fnSubnetNsg = getSubnetNsg(fnSid, ctx);
      return { subnetId: fnSid, vnetId: fnVnet, cidr: null, nicNsg: null, subnetNsg: fnSubnetNsg, name: azureName(fn, id) };
    }
    if (type === "containerapp" || type === "aks") {
      var ca = null;
      var caSid = null;
      Object.keys(ctx.containerBySub || {}).forEach(function(sid2) {
        (ctx.containerBySub[sid2] || []).forEach(function(c) {
          if (c.id === id || c.name === id) {
            ca = c;
            caSid = sid2;
          }
        });
      });
      if (!ca) return null;
      var caVnet = ((ctx.subnets || []).find(function(s) {
        return s.id === caSid;
      }) || {}).vnetId;
      var caSubnetNsg = getSubnetNsg(caSid, ctx);
      return { subnetId: caSid, vnetId: caVnet, cidr: null, nicNsg: null, subnetNsg: caSubnetNsg, name: azureName(ca, id) };
    }
    if (type === "redis") {
      var redis = null;
      var redisVnet = null;
      (ctx.redisCaches || []).forEach(function(c) {
        if (c.id === id || c.name === id) redis = c;
      });
      if (!redis) return null;
      var redisMap = ctx.redisByVnet || {};
      var redisKeys = redisMap instanceof Map ? Array.from(redisMap.keys()) : Object.keys(redisMap);
      redisKeys.forEach(function(vid) {
        var arr = redisMap instanceof Map ? redisMap.get(vid) : redisMap[vid];
        (arr || []).forEach(function(c) {
          if (c.id === id || c.name === id) redisVnet = vid;
        });
      });
      var redisSid = null;
      if (redisVnet) (ctx.subnets || []).forEach(function(s) {
        if (!redisSid && s.vnetId === redisVnet) redisSid = s.id;
      });
      var redisSubCidr = redisSid ? ((ctx.subnets || []).find(function(s) {
        return s.id === redisSid;
      }) || {}).addressPrefix : null;
      var redisSubnetNsg = getSubnetNsg(redisSid, ctx);
      return { subnetId: redisSid, vnetId: redisVnet, cidr: redisSubCidr, nicNsg: null, subnetNsg: redisSubnetNsg, name: azureName(redis, id) };
    }
    if (type === "pe") {
      var pe = null;
      (ctx.privateEndpoints || []).forEach(function(p) {
        if (p.id === id || p.name === id) pe = p;
      });
      if (!pe) return null;
      var peProps = pe.properties || {};
      var peSubId = peProps.subnet && peProps.subnet.id || null;
      var peVnetId = peSubId ? peSubId.split("/subnets/")[0] : null;
      var peSubCidr = peSubId ? ((ctx.subnets || []).find(function(s) {
        return s.id === peSubId;
      }) || {}).addressPrefix : null;
      var peSubnetNsg = getSubnetNsg(peSubId, ctx);
      var peIp = peProps.customDnsConfigs && peProps.customDnsConfigs[0] && peProps.customDnsConfigs[0].ipAddresses && peProps.customDnsConfigs[0].ipAddresses[0] || null;
      return { subnetId: peSubId, vnetId: peVnetId, cidr: peIp ? peIp + "/32" : peSubCidr, nicNsg: null, subnetNsg: peSubnetNsg, name: azureName(pe, id), ip: peIp, isPe: true };
    }
    return null;
  }
  function findPeForTarget(targetId, ctx) {
    if (!targetId || !ctx) return null;
    var pes = ctx.privateEndpoints || [];
    for (var i = 0; i < pes.length; i++) {
      var pe = pes[i];
      var props = pe.properties || {};
      var conn = (props.privateLinkServiceConnections || [])[0];
      if (!conn) continue;
      var connProps = conn.properties || {};
      if (connProps.privateLinkServiceId === targetId) {
        var state = (connProps.privateLinkServiceConnectionState || {}).status || "Unknown";
        return { pe, state };
      }
    }
    return null;
  }
  function buildPeRedirectHop(hopN, pe, state) {
    var peName = pe.name || pe.id || "PE";
    var peProps = pe.properties || {};
    var ip = peProps.customDnsConfigs && peProps.customDnsConfigs[0] && peProps.customDnsConfigs[0].ipAddresses && peProps.customDnsConfigs[0].ipAddresses[0] || "";
    var fqdn = peProps.customDnsConfigs && peProps.customDnsConfigs[0] && peProps.customDnsConfigs[0].fqdn || "";
    var action = state === "Approved" ? "allow" : "block";
    var detail = 'Traffic redirected via Private Endpoint "' + peName + '"';
    if (ip) detail += " (IP: " + ip + ")";
    if (fqdn) detail += " FQDN: " + fqdn;
    if (state !== "Approved") detail += " [Connection " + state + "]";
    return { hop: hopN, type: "pe-redirect", id: peName, action, detail, peId: pe.id };
  }
  function resolveClickTarget(el, ctx, buildResTreeFn) {
    if (!ctx) return null;
    var inetNode = el.closest(".internet-node");
    if (inetNode) return { type: "internet", id: "internet" };
    var resNode = el.closest(".res-node");
    var subNode = el.closest(".subnet-node");
    if (resNode && subNode) {
      var subId = subNode.getAttribute("data-subnet-id");
      var resIdx = Array.from(subNode.querySelectorAll(".res-node")).indexOf(resNode);
      var tree = buildResTreeFn ? buildResTreeFn(subId, ctx) : null;
      if (tree && tree[resIdx]) {
        var res = tree[resIdx];
        if (res.type === "VM") return { type: "vm", id: res.rid || "" };
        if (res.type === "LB") return { type: "lb", id: res.rid || res.name };
        if (res.type === "APPGW") return { type: "appgw", id: res.rid || res.name };
        if (res.type === "SQL") return { type: "sqldb", id: res.rid || res.name };
        if (res.type === "MYSQL") return { type: "mysql", id: res.rid || res.name };
        if (res.type === "PGSQL") return { type: "postgresql", id: res.rid || res.name };
        if (res.type === "COSMOS") return { type: "cosmosdb", id: res.rid || res.name };
        if (res.type === "FN") return { type: "functionapp", id: res.rid || res.name };
        if (res.type === "AKS") return { type: "aks", id: res.rid || res.name };
        if (res.type === "CONTAINER") return { type: "containerapp", id: res.rid || res.name };
        if (res.type === "REDIS") return { type: "redis", id: res.rid || res.name };
        if (res.type === "NIC") return { type: "subnet", id: subId };
      }
      return { type: "subnet", id: subId };
    }
    if (subNode) {
      return { type: "subnet", id: subNode.getAttribute("data-subnet-id") };
    }
    return null;
  }
  function evaluateNsgHop(nsg, direction, protocol, port, srcIp, dstIp, vnetPrefixes, opts) {
    if (!nsg) {
      return { action: "allow", detail: "No NSG attached (all traffic allowed)", rule: null };
    }
    var srcPort = "*";
    var evalDirection = direction === "inbound" ? "Inbound" : "Outbound";
    if (opts && opts.assumeAllow) {
      return { action: "allow", detail: "NSG " + azureName(nsg) + " (assumed allow for discovery)", rule: null };
    }
    var result = evaluateNsgRules(nsg, evalDirection, protocol, srcIp, srcPort, dstIp, port, { vnetPrefixes });
    var action = result.action === "Allow" ? "allow" : "deny";
    var ruleName = result.rule ? result.rule.name : "unknown";
    var priority = result.priority || 0;
    var detail = azureName(nsg) + ": " + ruleName + " (priority " + priority + ", " + result.action + ")";
    return { action, detail, rule: result.rule };
  }
  function evaluateUdrHop(routeTable, dstIp, vnetPrefixes) {
    if (!routeTable && (!vnetPrefixes || vnetPrefixes.length === 0)) {
      return { action: "allow", nextHopType: "Internet", detail: "No UDR, default system routes apply", rule: null };
    }
    var rt = routeTable || {};
    if (!rt.vnetPrefixes && vnetPrefixes) {
      rt = Object.assign({}, rt, { vnetPrefixes });
    }
    var result = evaluateRoute(rt, dstIp);
    var nextHop = result.nextHopType || "None";
    var routeName = result.route ? result.route.name : "system";
    var isSystem = result.route ? result.route.isSystem : true;
    if (nextHop === "None") {
      return {
        action: "block",
        nextHopType: "None",
        detail: "Route " + routeName + " drops traffic (nextHopType: None)",
        rule: result.route
      };
    }
    var detail = "Route " + routeName + " -> " + nextHop;
    if (result.nextHopIpAddress) detail += " (" + result.nextHopIpAddress + ")";
    if (isSystem) detail += " [system route]";
    return { action: "allow", nextHopType: nextHop, detail, rule: result.route };
  }
  function traceInternetToResource(target, config, ctx, opts) {
    var path = [];
    var hopN = 1;
    var tgtPos = resolveNetworkPosition(target.type, target.id, ctx);
    if (!tgtPos) return { path: [{ hop: 1, type: "error", id: "-", action: "block", detail: "Cannot resolve target" }], blocked: { hop: 1, reason: "Target not found" } };
    path.push({ hop: hopN++, type: "source", id: "Internet", action: "allow", detail: "Source: Internet (0.0.0.0/0)" });
    var vnetId = tgtPos.vnetId;
    var vnetPrefixes = getVnetPrefixes(vnetId, ctx);
    var tgtRT = getSubnetRouteTable(tgtPos.subnetId, ctx);
    var rtWithPrefixes = tgtRT ? Object.assign({}, tgtRT, { vnetPrefixes }) : { vnetPrefixes };
    var internetRoute = evaluateRoute(rtWithPrefixes, "0.0.0.0");
    var hasInternetRoute = internetRoute.nextHopType === "Internet";
    if (!hasInternetRoute) {
      path.push({ hop: hopN++, type: "internet-check", id: "No Internet route", action: "block", detail: "Target subnet has UDR overriding default Internet route (nextHopType: " + internetRoute.nextHopType + ")" });
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Target unreachable from Internet", subnetId: tgtPos.subnetId });
      return { path, blocked: { hop: 2, reason: "Target subnet default route overridden by UDR", suggestion: "Remove UDR override for 0.0.0.0/0 or use Application Gateway / Load Balancer" } };
    }
    path.push({ hop: hopN++, type: "internet-check", id: "Internet route", action: "allow", detail: "Target subnet has default Internet route" });
    var nsgOpts = opts && opts.discovery ? { assumeAllow: true } : null;
    var tgtIp = tgtPos.ip || ipFromCidr(tgtPos.cidr) || "10.0.0.1";
    var subNsgIn = evaluateNsgHop(tgtPos.subnetNsg, "inbound", config.protocol, config.port, "0.0.0.0", tgtIp, vnetPrefixes, nsgOpts);
    path.push({ hop: hopN++, type: "subnet-nsg-inbound", id: tgtPos.subnetNsg ? azureName(tgtPos.subnetNsg) : "No Subnet NSG", action: subNsgIn.action, detail: "Subnet NSG inbound from Internet", rule: subNsgIn.rule });
    if (subNsgIn.action === "deny") {
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by Subnet NSG", subnetId: tgtPos.subnetId });
      return { path, blocked: { hop: hopN - 2, reason: "Subnet NSG denies inbound from Internet", suggestion: "Add NSG inbound rule allowing " + config.protocol + "/" + config.port + " from Internet" } };
    }
    var nicNsgIn = evaluateNsgHop(tgtPos.nicNsg, "inbound", config.protocol, config.port, "0.0.0.0", tgtIp, vnetPrefixes, nsgOpts);
    path.push({ hop: hopN++, type: "nic-nsg-inbound", id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : "No NIC NSG", action: nicNsgIn.action, detail: "NIC NSG inbound from Internet", rule: nicNsgIn.rule });
    if (nicNsgIn.action === "deny") {
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by NIC NSG", subnetId: tgtPos.subnetId });
      return { path, blocked: { hop: hopN - 2, reason: "NIC NSG denies inbound " + config.protocol + "/" + config.port + " from Internet", suggestion: "Add NIC NSG inbound rule allowing " + config.protocol + "/" + config.port + " from Internet" } };
    }
    path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "allow", detail: "Target: " + (tgtPos.name || target.id) + " (" + target.type + ")", subnetId: tgtPos.subnetId });
    return { path, blocked: null };
  }
  function traceResourceToInternet(source, config, ctx, opts) {
    var path = [];
    var hopN = 1;
    var srcPos = resolveNetworkPosition(source.type, source.id, ctx);
    if (!srcPos) return { path: [{ hop: 1, type: "error", id: "-", action: "block", detail: "Cannot resolve source" }], blocked: { hop: 1, reason: "Source not found" } };
    var vnetPrefixes = getVnetPrefixes(srcPos.vnetId, ctx);
    var srcIp = srcPos.ip || ipFromCidr(srcPos.cidr) || "10.0.0.1";
    path.push({ hop: hopN++, type: "source", id: srcPos.name || source.id, action: "allow", detail: "Source: " + (srcPos.name || source.id) + " (" + source.type + ")", subnetId: srcPos.subnetId });
    var nsgOpts = opts && opts.discovery ? { assumeAllow: true } : null;
    var nicNsgOut = evaluateNsgHop(srcPos.nicNsg, "outbound", config.protocol, config.port, srcIp, "0.0.0.0", vnetPrefixes, nsgOpts);
    path.push({ hop: hopN++, type: "nic-nsg-outbound", id: srcPos.nicNsg ? azureName(srcPos.nicNsg) : "No NIC NSG", action: nicNsgOut.action, detail: "NIC NSG outbound to Internet", rule: nicNsgOut.rule });
    if (nicNsgOut.action === "deny") {
      path.push({ hop: hopN++, type: "target", id: "Internet", action: "block", detail: "Blocked by NIC NSG" });
      return { path, blocked: { hop: 2, reason: "NIC NSG denies outbound", suggestion: "Add NIC NSG outbound rule allowing " + config.protocol + "/" + config.port + " to Internet" } };
    }
    var subNsgOut = evaluateNsgHop(srcPos.subnetNsg, "outbound", config.protocol, config.port, srcIp, "0.0.0.0", vnetPrefixes, nsgOpts);
    path.push({ hop: hopN++, type: "subnet-nsg-outbound", id: srcPos.subnetNsg ? azureName(srcPos.subnetNsg) : "No Subnet NSG", action: subNsgOut.action, detail: "Subnet NSG outbound to Internet", rule: subNsgOut.rule });
    if (subNsgOut.action === "deny") {
      path.push({ hop: hopN++, type: "target", id: "Internet", action: "block", detail: "Blocked by Subnet NSG" });
      return { path, blocked: { hop: hopN - 2, reason: "Subnet NSG denies outbound to Internet", suggestion: "Add Subnet NSG outbound rule allowing " + config.protocol + "/" + config.port + " to Internet" } };
    }
    var srcRT = getSubnetRouteTable(srcPos.subnetId, ctx);
    var udrHop = evaluateUdrHop(srcRT, "8.8.8.8", vnetPrefixes);
    if (udrHop.nextHopType === "Internet") {
      path.push({ hop: hopN++, type: "udr", id: srcRT ? azureName(srcRT) : "System Routes", action: "allow", detail: "Route to Internet via default route", rule: udrHop.rule ? udrHop.rule.addressPrefix + " -> " + udrHop.nextHopType : "0.0.0.0/0 -> Internet" });
    } else if (udrHop.nextHopType === "VirtualAppliance") {
      path.push({ hop: hopN++, type: "udr", id: srcRT ? azureName(srcRT) : "UDR", action: "allow", detail: "Route to Internet via NVA (" + (udrHop.rule && udrHop.rule.nextHopIpAddress || "VirtualAppliance") + ")", rule: udrHop.detail });
    } else if (udrHop.action === "block") {
      path.push({ hop: hopN++, type: "udr", id: "No route", action: "block", detail: "No route to Internet (" + udrHop.detail + ")" });
      path.push({ hop: hopN++, type: "target", id: "Internet", action: "block", detail: "No Internet route" });
      return { path, blocked: { hop: hopN - 2, reason: "No route to Internet in route table", suggestion: "Add UDR route 0.0.0.0/0 with nextHopType Internet or VirtualAppliance" } };
    } else {
      path.push({ hop: hopN++, type: "udr", id: srcRT ? azureName(srcRT) : "UDR", action: "allow", detail: udrHop.detail, rule: udrHop.detail });
    }
    path.push({ hop: hopN++, type: "target", id: "Internet", action: "allow", detail: "Target: Internet (0.0.0.0/0)" });
    return { path, blocked: null };
  }
  function traceFlowLeg(source, target, config, ctx, opts) {
    if (source.type === "internet") return traceInternetToResource(target, config, ctx, opts);
    if (target.type === "internet") return traceResourceToInternet(source, config, ctx, opts);
    return traceFlow(source, target, config, ctx);
  }
  function traceFlow(source, target, config, ctx) {
    var path = [];
    var srcPos = resolveNetworkPosition(source.type, source.id, ctx);
    var tgtPos = resolveNetworkPosition(target.type, target.id, ctx);
    if (!srcPos) {
      return { path: [{ hop: 1, type: "error", id: "-", action: "block", detail: "Cannot resolve source position" }], blocked: { hop: 1, reason: "Source not found" } };
    }
    if (!tgtPos) {
      return { path: [{ hop: 1, type: "error", id: "-", action: "block", detail: "Cannot resolve target position" }], blocked: { hop: 1, reason: "Target not found" } };
    }
    var hopN = 1;
    var srcVnetPrefixes = getVnetPrefixes(srcPos.vnetId, ctx);
    var tgtVnetPrefixes = getVnetPrefixes(tgtPos.vnetId, ctx);
    var srcIp = srcPos.ip || ipFromCidr(srcPos.cidr) || "10.0.0.1";
    var tgtIp = tgtPos.ip || ipFromCidr(tgtPos.cidr) || "10.0.0.2";
    path.push({ hop: hopN++, type: "source", id: srcPos.name || source.id, action: "allow", detail: "Source: " + (srcPos.name || source.id) + " (" + source.type + ") in subnet " + (srcPos.subnetId || "unknown"), subnetId: srcPos.subnetId });
    if (tgtPos.isPe) {
      path.push(buildPeRedirectHop(hopN++, { id: target.id, name: tgtPos.name, properties: {} }, "Approved"));
    } else {
      var peMatch = findPeForTarget(target.id, ctx);
      if (peMatch) {
        path.push(buildPeRedirectHop(hopN++, peMatch.pe, peMatch.state));
        if (peMatch.state !== "Approved") {
          path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "PE connection is " + peMatch.state + ": traffic cannot reach target", subnetId: tgtPos.subnetId });
          return { path, blocked: { hop: hopN - 2, reason: "Private Endpoint connection is " + peMatch.state, suggestion: "Approve the PE connection on the target resource" } };
        }
        var pePos = resolveNetworkPosition("pe", peMatch.pe.id, ctx);
        if (pePos) {
          tgtPos = pePos;
          tgtIp = pePos.ip || tgtIp;
        }
      }
    }
    if (srcPos.subnetId && srcPos.subnetId === tgtPos.subnetId) {
      var nicOut = evaluateNsgHop(srcPos.nicNsg, "outbound", config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
      path.push({ hop: hopN++, type: "nic-nsg-outbound", id: srcPos.nicNsg ? azureName(srcPos.nicNsg) : "No NIC NSG", action: nicOut.action, detail: "Source NIC NSG outbound check", rule: nicOut.rule });
      if (nicOut.action === "deny") {
        var nicInSkip = evaluateNsgHop(tgtPos.nicNsg, "inbound", config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
        path.push({ hop: hopN++, type: "nic-nsg-inbound", id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : "No NIC NSG", action: "skip", detail: "Skipped (blocked upstream)", rule: nicInSkip.rule });
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Target: " + (tgtPos.name || target.id), subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: 2, reason: "Source NIC NSG denies outbound " + config.protocol + "/" + config.port, suggestion: "Add outbound rule to source NIC NSG allowing " + config.protocol + "/" + config.port + " to " + tgtIp } };
      }
      var nicIn = evaluateNsgHop(tgtPos.nicNsg, "inbound", config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
      path.push({ hop: hopN++, type: "nic-nsg-inbound", id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : "No NIC NSG", action: nicIn.action, detail: "Target NIC NSG inbound check", rule: nicIn.rule });
      if (nicIn.action === "deny") {
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Target: " + (tgtPos.name || target.id), subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: hopN - 2, reason: "Target NIC NSG denies inbound " + config.protocol + "/" + config.port, suggestion: "Add inbound rule to target NIC NSG allowing " + config.protocol + "/" + config.port + " from " + srcIp } };
      }
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "allow", detail: "Target: " + (tgtPos.name || target.id) + " (" + target.type + ")", subnetId: tgtPos.subnetId });
      return { path, blocked: null };
    }
    if (srcPos.vnetId && srcPos.vnetId === tgtPos.vnetId) {
      var nicOut2 = evaluateNsgHop(srcPos.nicNsg, "outbound", config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
      path.push({ hop: hopN++, type: "nic-nsg-outbound", id: srcPos.nicNsg ? azureName(srcPos.nicNsg) : "No NIC NSG", action: nicOut2.action, detail: "Source NIC NSG outbound", rule: nicOut2.rule });
      if (nicOut2.action === "deny") {
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by NIC NSG", subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: hopN - 2, reason: "Source NIC NSG denies outbound", suggestion: "Add NIC NSG outbound rule for " + config.protocol + "/" + config.port } };
      }
      var subNsgOut2 = evaluateNsgHop(srcPos.subnetNsg, "outbound", config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
      path.push({ hop: hopN++, type: "subnet-nsg-outbound", id: srcPos.subnetNsg ? azureName(srcPos.subnetNsg) : "No Subnet NSG", action: subNsgOut2.action, detail: "Source Subnet NSG outbound", rule: subNsgOut2.rule });
      if (subNsgOut2.action === "deny") {
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by Subnet NSG", subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: hopN - 2, reason: "Source Subnet NSG denies outbound traffic", suggestion: "Add Subnet NSG outbound rule allowing " + config.protocol + "/" + config.port } };
      }
      var srcRT2 = getSubnetRouteTable(srcPos.subnetId, ctx);
      var udrHop2 = evaluateUdrHop(srcRT2, tgtIp, srcVnetPrefixes);
      path.push({ hop: hopN++, type: "udr", id: srcRT2 ? azureName(srcRT2) : "System Routes", action: udrHop2.action === "block" ? "block" : "allow", detail: "Route table lookup for " + tgtIp + ": " + udrHop2.detail, rule: udrHop2.detail });
      if (udrHop2.action === "block") {
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Target unreachable", subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: hopN - 2, reason: "Route table has no route to destination", suggestion: "Add a UDR route to " + tgtIp } };
      }
      var subNsgIn2 = evaluateNsgHop(tgtPos.subnetNsg, "inbound", config.protocol, config.port, srcIp, tgtIp, tgtVnetPrefixes, null);
      path.push({ hop: hopN++, type: "subnet-nsg-inbound", id: tgtPos.subnetNsg ? azureName(tgtPos.subnetNsg) : "No Subnet NSG", action: subNsgIn2.action, detail: "Target Subnet NSG inbound", rule: subNsgIn2.rule });
      if (subNsgIn2.action === "deny") {
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by Subnet NSG", subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: hopN - 2, reason: "Target Subnet NSG denies inbound traffic", suggestion: "Add Subnet NSG inbound rule allowing " + config.protocol + "/" + config.port + " from " + srcIp } };
      }
      var nicIn2 = evaluateNsgHop(tgtPos.nicNsg, "inbound", config.protocol, config.port, srcIp, tgtIp, tgtVnetPrefixes, null);
      path.push({ hop: hopN++, type: "nic-nsg-inbound", id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : "No NIC NSG", action: nicIn2.action, detail: "Target NIC NSG inbound", rule: nicIn2.rule });
      if (nicIn2.action === "deny") {
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by NIC NSG", subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: hopN - 2, reason: "Target NIC NSG denies inbound", suggestion: "Add NIC NSG inbound rule for " + config.protocol + "/" + config.port + " from source" } };
      }
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "allow", detail: "Target: " + (tgtPos.name || target.id) + " (" + target.type + ")", subnetId: tgtPos.subnetId });
      return { path, blocked: null };
    }
    var nicOutX = evaluateNsgHop(srcPos.nicNsg, "outbound", config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
    path.push({ hop: hopN++, type: "nic-nsg-outbound", id: srcPos.nicNsg ? azureName(srcPos.nicNsg) : "No NIC NSG", action: nicOutX.action, detail: "Source NIC NSG outbound", rule: nicOutX.rule });
    if (nicOutX.action === "deny") {
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by NIC NSG", subnetId: tgtPos.subnetId });
      return { path, blocked: { hop: hopN - 2, reason: "Source NIC NSG denies outbound", suggestion: "Add NIC NSG outbound rule for " + config.protocol + "/" + config.port } };
    }
    var subNsgOutX = evaluateNsgHop(srcPos.subnetNsg, "outbound", config.protocol, config.port, srcIp, tgtIp, srcVnetPrefixes, null);
    path.push({ hop: hopN++, type: "subnet-nsg-outbound", id: srcPos.subnetNsg ? azureName(srcPos.subnetNsg) : "No Subnet NSG", action: subNsgOutX.action, detail: "Source Subnet NSG outbound", rule: subNsgOutX.rule });
    if (subNsgOutX.action === "deny") {
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by Subnet NSG", subnetId: tgtPos.subnetId });
      return { path, blocked: { hop: hopN - 2, reason: "Source Subnet NSG denies outbound traffic", suggestion: "Add Subnet NSG outbound rule allowing " + config.protocol + "/" + config.port } };
    }
    var srcRTx = getSubnetRouteTable(srcPos.subnetId, ctx);
    var udrHopX = evaluateUdrHop(srcRTx, tgtIp, srcVnetPrefixes);
    path.push({ hop: hopN++, type: "udr", id: srcRTx ? azureName(srcRTx) : "System Routes", action: udrHopX.action === "block" ? "block" : "allow", detail: "Route table lookup for " + tgtIp + ": " + udrHopX.detail, rule: udrHopX.detail });
    if (udrHopX.action === "block") {
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Target unreachable", subnetId: tgtPos.subnetId });
      return { path, blocked: { hop: hopN - 2, reason: "Route table has no route to destination", suggestion: "Add a route to " + tgtIp + " via peering or VNet Gateway" } };
    }
    var peeringRoute = null;
    (ctx.peerings || []).forEach(function(p) {
      var remoteVnet = p.remoteVnetId || p.remoteVirtualNetwork && p.remoteVirtualNetwork.id || "";
      var localVnet = p.localVnetId || p.vnetId || "";
      if (localVnet === srcPos.vnetId && remoteVnet === tgtPos.vnetId || localVnet === tgtPos.vnetId && remoteVnet === srcPos.vnetId) {
        peeringRoute = p;
      }
    });
    if (peeringRoute) {
      var peeringState = peeringRoute.peeringState || "Connected";
      if (peeringState !== "Connected") {
        path.push({ hop: hopN++, type: "peering", id: azureName(peeringRoute), action: "block", detail: "VNet Peering exists but state is " + peeringState });
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Target unreachable", subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: hopN - 2, reason: "VNet peering is not in Connected state", suggestion: "Ensure both sides of the peering are in Connected state" } };
      }
      path.push({ hop: hopN++, type: "peering", id: azureName(peeringRoute), action: "allow", detail: "VNet Peering between " + srcPos.vnetId + " and " + tgtPos.vnetId, rule: "Peering: " + azureName(peeringRoute) });
    } else {
      var gatewayRoute = false;
      (ctx.vnetGateways || []).forEach(function(gw) {
        if (gw.vnetId === srcPos.vnetId || gw.vnetId === tgtPos.vnetId) gatewayRoute = true;
      });
      if (gatewayRoute) {
        path.push({ hop: hopN++, type: "vnet-gateway", id: "VNet Gateway", action: "allow", detail: "VNet Gateway route between VNets" });
      } else {
        path.push({ hop: hopN++, type: "cross-vnet", id: "No route", action: "block", detail: "No peering or VNet Gateway connection between VNets" });
        path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Target unreachable", subnetId: tgtPos.subnetId });
        return { path, blocked: { hop: hopN - 2, reason: "No connectivity between VNets", suggestion: "Create a VNet peering or VNet Gateway connection" } };
      }
    }
    var subNsgInX = evaluateNsgHop(tgtPos.subnetNsg, "inbound", config.protocol, config.port, srcIp, tgtIp, tgtVnetPrefixes, null);
    path.push({ hop: hopN++, type: "subnet-nsg-inbound", id: tgtPos.subnetNsg ? azureName(tgtPos.subnetNsg) : "No Subnet NSG", action: subNsgInX.action, detail: "Target Subnet NSG inbound", rule: subNsgInX.rule });
    if (subNsgInX.action === "deny") {
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by Subnet NSG", subnetId: tgtPos.subnetId });
      return { path, blocked: { hop: hopN - 2, reason: "Target Subnet NSG denies inbound traffic", suggestion: "Add Subnet NSG inbound rule allowing " + config.protocol + "/" + config.port + " from " + srcIp } };
    }
    var nicInX = evaluateNsgHop(tgtPos.nicNsg, "inbound", config.protocol, config.port, srcIp, tgtIp, tgtVnetPrefixes, null);
    path.push({ hop: hopN++, type: "nic-nsg-inbound", id: tgtPos.nicNsg ? azureName(tgtPos.nicNsg) : "No NIC NSG", action: nicInX.action, detail: "Target NIC NSG inbound (cross-VNet)", rule: nicInX.rule });
    if (nicInX.action === "deny") {
      path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "block", detail: "Blocked by NIC NSG", subnetId: tgtPos.subnetId });
      return { path, blocked: { hop: hopN - 2, reason: "Target NIC NSG denies inbound from cross-VNet source", suggestion: "Add NIC NSG inbound rule for " + config.protocol + "/" + config.port } };
    }
    path.push({ hop: hopN++, type: "target", id: tgtPos.name || target.id, action: "allow", detail: "Target: " + (tgtPos.name || target.id) + " (" + target.type + ")", subnetId: tgtPos.subnetId });
    return { path, blocked: null };
  }
  function findAlternatePaths(source, target, config, ctx) {
    if (!ctx) return [];
    var tgtPos = resolveNetworkPosition(target.type, target.id, ctx);
    if (!tgtPos) return [];
    var vnetId = tgtPos.vnetId;
    var results = [];
    var candidates = [];
    var isInternet = source.type === "internet";
    (ctx.subnets || []).forEach(function(sub) {
      if (sub.name && sub.name.toLowerCase() === "azurebastionsubnet") {
        var bastionVnet = sub.vnetId;
        if (isInternet || bastionVnet === vnetId) {
          candidates.push({ ref: { type: "bastion", id: sub.id }, name: "Azure Bastion (" + (sub.vnetId || "") + ")", isPub: true, defaultPort: 443 });
        }
      }
    });
    var allVms = [];
    Object.keys(ctx.vmsBySub || {}).forEach(function(sid2) {
      (ctx.vmsBySub[sid2] || []).forEach(function(vm) {
        allVms.push(vm);
      });
    });
    allVms.forEach(function(vm) {
      var vmVnet = vm.vnetId || ((ctx.subnets || []).find(function(s) {
        return s.id === vm.subnetId;
      }) || {}).vnetId;
      if (!isInternet && vmVnet !== vnetId) return;
      if (vm.id === (target.type === "vm" ? target.id : "")) return;
      if (vm.id === (source.type === "vm" ? source.id : "")) return;
      var isPub = vm.publicIpAddress || ctx.pubSubs && ctx.pubSubs.has(vm.subnetId);
      candidates.push({ ref: { type: "vm", id: vm.id || vm.name }, name: azureName(vm, vm.id), isPub: !!isPub, defaultPort: 22 });
    });
    Object.keys(ctx.lbBySub || {}).forEach(function(sid2) {
      var sub = (ctx.subnets || []).find(function(s) {
        return s.id === sid2;
      });
      if (!sub || !isInternet && sub.vnetId !== vnetId) return;
      (ctx.lbBySub[sid2] || []).forEach(function(lb) {
        if (lb.id === (target.type === "lb" ? target.id : "")) return;
        candidates.push({ ref: { type: "lb", id: lb.id || lb.name }, name: azureName(lb, lb.id), isPub: true, defaultPort: 443 });
      });
    });
    candidates.sort(function(a, b) {
      return (b.isPub ? 1 : 0) - (a.isPub ? 1 : 0);
    });
    var tested = 0;
    for (var i = 0; i < candidates.length && tested < 20 && results.length < 5; i++) {
      var cand = candidates[i];
      tested++;
      var leg1Config = { protocol: "Tcp", port: cand.defaultPort };
      var leg1 = traceFlowLeg(source, cand.ref, leg1Config, ctx);
      if (leg1.blocked) continue;
      var leg2 = traceFlowLeg(cand.ref, target, config, ctx);
      if (leg2.blocked) continue;
      results.push({ via: { type: cand.ref.type, id: cand.ref.id, name: cand.name }, leg1Result: leg1, leg2Result: leg2, leg1Config });
    }
    return results;
  }

  // src/modules/flow-analysis.js
  var flow_analysis_exports = {};
  __export(flow_analysis_exports, {
    _faDashRows: () => faDashRows,
    _faDashState: () => faDashState,
    _flowAnalysisCache: () => flowAnalysisCache,
    _flowAnalysisMode: () => flowAnalysisMode,
    classifyAllResources: () => classifyAllResources,
    detectBastions: () => detectBastions,
    discoverTrafficFlows: () => discoverTrafficFlows,
    findBastionChains: () => findBastionChains,
    findEgressPaths: () => findEgressPaths,
    findIngressPaths: () => findIngressPaths,
    getFaDashRows: () => getFaDashRows,
    getFaDashState: () => getFaDashState,
    getFlowAnalysisCache: () => getFlowAnalysisCache,
    getFlowAnalysisMode: () => getFlowAnalysisMode,
    setFaDashRows: () => setFaDashRows,
    setFaDashState: () => setFaDashState,
    setFlowAnalysisCache: () => setFlowAnalysisCache,
    setFlowAnalysisMode: () => setFlowAnalysisMode
  });
  function _traceInbound(target, config, ctx, opts) {
    return typeof traceInternetToResource === "function" ? traceInternetToResource(target, config, ctx, opts) : { blocked: true, path: [] };
  }
  function _traceOutbound(source, config, ctx, opts) {
    return typeof traceResourceToInternet === "function" ? traceResourceToInternet(source, config, ctx, opts) : { blocked: true, path: [] };
  }
  function _traceLeg(source, target, config, ctx, opts) {
    return typeof traceFlowLeg === "function" ? traceFlowLeg(source, target, config, ctx, opts) : { blocked: true, path: [] };
  }
  var flowAnalysisMode = null;
  var flowAnalysisCache = null;
  var faDashState = { section: "all", search: "", sort: "name", sortDir: "asc", page: 1, perPage: 50 };
  var faDashRows = null;
  function getFlowAnalysisMode() {
    return flowAnalysisMode;
  }
  function setFlowAnalysisMode(v) {
    flowAnalysisMode = v;
  }
  function getFlowAnalysisCache() {
    return flowAnalysisCache;
  }
  function setFlowAnalysisCache(v) {
    flowAnalysisCache = v;
  }
  function getFaDashState() {
    return faDashState;
  }
  function setFaDashState(v) {
    faDashState = v;
  }
  function getFaDashRows() {
    return faDashRows;
  }
  function setFaDashRows(v) {
    faDashRows = v;
  }
  function _gn3(resource) {
    return resource.name || resource.Name || resource.id || "unknown";
  }
  function discoverTrafficFlows(ctx) {
    if (!ctx) return null;
    const hasNsgData = (ctx.nsgs || []).length > 0;
    const hasNsgEgress = (ctx.nsgs || []).some(
      (n) => (n.securityRules || []).some(
        (r) => (r.direction || "").toLowerCase() === "outbound"
      )
    );
    const ingressPaths = findIngressPaths(ctx);
    const egressPaths = findEgressPaths(ctx);
    const bastions = detectBastions(ctx);
    const bastionChains = findBastionChains(bastions, ctx);
    const accessTiers = classifyAllResources(ctx, ingressPaths, bastionChains);
    return { ingressPaths, egressPaths, accessTiers, bastionChains, bastions, hasNsgData, hasNsgEgress };
  }
  function findIngressPaths(ctx) {
    const paths = [];
    (ctx.subnets || []).forEach((sub) => {
      const isPublic = ctx.pubSubs && ctx.pubSubs.has(sub.id);
      if (!isPublic) return;
      const vnetId = sub.vnetId;
      (ctx.vmsBySub[sub.id] || []).forEach((vm) => {
        [443, 80, 22].forEach((port) => {
          const r = _traceInbound({ type: "vm", id: vm.id || vm.name }, { protocol: "Tcp", port }, ctx, { discovery: true });
          if (!r.blocked) {
            paths.push({ from: "internet", to: { type: "vm", id: vm.id || vm.name }, toName: _gn3(vm), path: r.path, port, type: "direct", vnetId });
          }
        });
      });
      (ctx.lbBySub[sub.id] || []).forEach((lb) => {
        const r = _traceInbound({ type: "lb", id: lb.id || lb.name }, { protocol: "Tcp", port: 443 }, ctx, { discovery: true });
        if (!r.blocked) {
          paths.push({ from: "internet", to: { type: "lb", id: lb.id || lb.name }, toName: _gn3(lb), path: r.path, port: 443, type: "loadbalancer", vnetId });
        }
      });
    });
    return paths;
  }
  function findEgressPaths(ctx) {
    const paths = [];
    const checked = /* @__PURE__ */ new Set();
    var allVms = [];
    Object.keys(ctx.vmsBySub || {}).forEach((sid2) => {
      (ctx.vmsBySub[sid2] || []).forEach((vm) => allVms.push({ vm, subnetId: sid2 }));
    });
    allVms.forEach(({ vm, subnetId }) => {
      if (checked.has(subnetId)) return;
      const r = _traceOutbound({ type: "vm", id: vm.id || vm.name }, { protocol: "Tcp", port: 443 }, ctx, { discovery: true });
      if (!r.blocked) {
        checked.add(subnetId);
        const viaType = r.path.some((h) => h.detail && h.detail.includes("VirtualAppliance")) ? "nva" : r.path.some((h) => h.detail && h.detail.includes("VirtualNetworkGateway")) ? "gateway" : "internet";
        paths.push({
          from: { type: "vm", id: vm.id || vm.name },
          fromName: _gn3(vm),
          to: "internet",
          subnetId,
          via: viaType
        });
      }
    });
    return paths;
  }
  function detectBastions(ctx) {
    const bastions = [];
    const hasNsgData = (ctx.nsgs || []).length > 0;
    (ctx.subnets || []).forEach((sub) => {
      if (sub.name && sub.name.toLowerCase() === "azurebastionsubnet") {
        bastions.push({
          type: "bastion",
          id: sub.id,
          name: "Azure Bastion (" + (sub.vnetId || "") + ")",
          subnetId: sub.id,
          vnetId: sub.vnetId,
          isAzureBastion: true
        });
      }
    });
    var allVms = [];
    Object.keys(ctx.vmsBySub || {}).forEach((sid2) => {
      (ctx.vmsBySub[sid2] || []).forEach((vm) => allVms.push(vm));
    });
    allVms.forEach((vm) => {
      const isPub = vm.publicIpAddress || ctx.pubSubs && ctx.pubSubs.has(vm.subnetId);
      if (!isPub) return;
      const name = _gn3(vm);
      const nameMatch = /bastion|jump|ssh/i.test(name);
      if (hasNsgData) {
        const nicNsg = vm.nicId ? (ctx.nics || []).find((n) => n.id === vm.nicId) : null;
        const nicNsgRef = nicNsg && (nicNsg.networkSecurityGroup || nicNsg.properties && nicNsg.properties.networkSecurityGroup);
        const nicNsgObj = nicNsgRef ? (ctx.nsgs || []).find((n) => n.id === nicNsgRef.id) : null;
        const subNsg = (ctx.subnetNsgs || {})[vm.subnetId];
        let hasSSH = false;
        [nicNsgObj, subNsg].forEach((nsg) => {
          if (!nsg) return;
          (nsg.securityRules || []).forEach((rule) => {
            if ((rule.direction || "").toLowerCase() !== "inbound") return;
            if ((rule.access || "").toLowerCase() !== "allow") return;
            const dstPorts = rule.destinationPortRange || rule.destinationPortRanges || "*";
            const portStr = Array.isArray(dstPorts) ? dstPorts.join(",") : String(dstPorts);
            if (portStr === "*" || portStr.includes("22")) hasSSH = true;
          });
        });
        if (!hasSSH && !nameMatch) return;
      } else {
        if (!nameMatch) return;
      }
      bastions.push({
        type: "vm",
        id: vm.id || vm.name,
        name,
        subnetId: vm.subnetId,
        vnetId: vm.vnetId || ((ctx.subnets || []).find((s) => s.id === vm.subnetId) || {}).vnetId
      });
    });
    return bastions;
  }
  function findBastionChains(bastions, ctx) {
    const chains = [];
    const hasNsgData = (ctx.nsgs || []).length > 0;
    bastions.forEach((bastion) => {
      const targets = [];
      const testedSubs = /* @__PURE__ */ new Set();
      var allVms = [];
      Object.keys(ctx.vmsBySub || {}).forEach((sid2) => {
        (ctx.vmsBySub[sid2] || []).forEach((vm) => allVms.push(vm));
      });
      allVms.forEach((vm) => {
        if ((vm.id || vm.name) === bastion.id) return;
        const vmVnet = vm.vnetId || ((ctx.subnets || []).find((s) => s.id === vm.subnetId) || {}).vnetId;
        if (vmVnet !== bastion.vnetId) return;
        if (ctx.pubSubs && ctx.pubSubs.has(vm.subnetId)) return;
        const name = _gn3(vm);
        if (!hasNsgData) {
          if (targets.length < 50) targets.push({ type: "vm", id: vm.id || vm.name, name });
        } else if (!testedSubs.has(vm.subnetId)) {
          testedSubs.add(vm.subnetId);
          const sourceRef = bastion.isAzureBastion ? { type: "subnet", id: bastion.subnetId } : { type: "vm", id: bastion.id };
          const r = _traceLeg(sourceRef, { type: "vm", id: vm.id || vm.name }, { protocol: "Tcp", port: 22 }, ctx, { discovery: true });
          if (!r.blocked) targets.push({ type: "vm", id: vm.id || vm.name, name });
        } else {
          targets.push({ type: "vm", id: vm.id || vm.name, name });
        }
      });
      Object.keys(ctx.dbBySub || {}).forEach((sid2) => {
        (ctx.dbBySub[sid2] || []).forEach((db) => {
          const dbVnet = ((ctx.subnets || []).find((s) => s.id === sid2) || {}).vnetId;
          if (dbVnet !== bastion.vnetId) return;
          const dbName = _gn3(db);
          if (!hasNsgData) {
            targets.push({ type: "sqldb", id: db.id || db.name, name: dbName });
          } else {
            const port = db.port || 1433;
            const sourceRef = bastion.isAzureBastion ? { type: "subnet", id: bastion.subnetId } : { type: "vm", id: bastion.id };
            const r = _traceLeg(sourceRef, { type: "sqldb", id: db.id || db.name }, { protocol: "Tcp", port }, ctx, { discovery: true });
            if (!r.blocked) targets.push({ type: "sqldb", id: db.id || db.name, name: dbName });
          }
        });
      });
      if (targets.length > 0) chains.push({ bastion, targets });
    });
    return chains;
  }
  function classifyAllResources(ctx, ingressPaths, bastionChains) {
    const tiers = { internetFacing: [], bastionOnly: [], fullyPrivate: [], database: [] };
    const ingressSet = /* @__PURE__ */ new Set();
    ingressPaths.forEach((p) => {
      ingressSet.add(p.to.type + ":" + p.to.id);
    });
    const bastionSet = /* @__PURE__ */ new Set();
    bastionChains.forEach((ch) => {
      ch.targets.forEach((t) => {
        bastionSet.add(t.type + ":" + t.id);
      });
    });
    var allVms = [];
    Object.keys(ctx.vmsBySub || {}).forEach((sid2) => {
      (ctx.vmsBySub[sid2] || []).forEach((vm) => allVms.push(vm));
    });
    allVms.forEach((vm) => {
      const key = "vm:" + (vm.id || vm.name);
      const ref = { type: "vm", id: vm.id || vm.name, name: _gn3(vm) };
      if (ingressSet.has(key)) {
        tiers.internetFacing.push(ref);
        return;
      }
      if (bastionSet.has(key)) {
        tiers.bastionOnly.push(ref);
        return;
      }
      tiers.fullyPrivate.push(ref);
    });
    Object.keys(ctx.lbBySub || {}).forEach((sid2) => {
      (ctx.lbBySub[sid2] || []).forEach((lb) => {
        const key = "lb:" + (lb.id || lb.name);
        const ref = { type: "lb", id: lb.id || lb.name, name: _gn3(lb) };
        if (ingressSet.has(key)) {
          tiers.internetFacing.push(ref);
          return;
        }
        tiers.fullyPrivate.push(ref);
      });
    });
    Object.keys(ctx.funcAppBySub || {}).forEach((sid2) => {
      (ctx.funcAppBySub[sid2] || []).forEach((fn) => {
        tiers.fullyPrivate.push({ type: "functionapp", id: fn.id || fn.name, name: _gn3(fn) });
      });
    });
    Object.keys(ctx.dbBySub || {}).forEach((sid2) => {
      (ctx.dbBySub[sid2] || []).forEach((db) => {
        tiers.database.push({ type: "sqldb", id: db.id || db.name, name: _gn3(db) });
      });
    });
    (ctx.redisCaches || []).forEach((rc) => {
      tiers.database.push({ type: "redis", id: rc.id || rc.name, name: _gn3(rc) });
    });
    return tiers;
  }

  // src/modules/firewall-editor.js
  var firewall_editor_exports = {};
  __export(firewall_editor_exports, {
    extractResourceGroup: () => extractResourceGroup,
    fwApplyRule: () => fwApplyRule,
    fwCheckNsgShadow: () => fwCheckNsgShadow,
    fwEditCount: () => fwEditCount,
    fwGenNsgCli: () => fwGenNsgCli,
    fwGenUdrCli: () => fwGenUdrCli,
    fwGenerateCli: () => fwGenerateCli,
    fwProtoLabel: () => fwProtoLabel,
    fwRebuildLookups: () => fwRebuildLookups,
    fwRemoveRule: () => fwRemoveRule,
    fwResetAll: () => fwResetAll,
    fwRestoreRule: () => fwRestoreRule,
    fwRuleMatch: () => fwRuleMatch,
    fwTakeSnapshot: () => fwTakeSnapshot,
    fwUndo: () => fwUndo,
    fwValidateAddressPrefix: () => fwValidateAddressPrefix,
    fwValidateCidr: () => fwValidateCidr,
    fwValidateNsgRule: () => fwValidateNsgRule,
    fwValidateRoute: () => fwValidateRoute,
    getFwEdits: () => getFwEdits,
    getFwFpDir: () => getFwFpDir,
    getFwFpLk: () => getFwFpLk,
    getFwFpResId: () => getFwFpResId,
    getFwFpSub: () => getFwFpSub,
    getFwFpType: () => getFwFpType,
    getFwFpVnetId: () => getFwFpVnetId,
    getFwSnapshot: () => getFwSnapshot,
    setFwEdits: () => setFwEdits,
    setFwFpDir: () => setFwFpDir,
    setFwFpLk: () => setFwFpLk,
    setFwFpResId: () => setFwFpResId,
    setFwFpSub: () => setFwFpSub,
    setFwFpType: () => setFwFpType,
    setFwFpVnetId: () => setFwFpVnetId,
    setFwSnapshot: () => setFwSnapshot
  });
  var _fwEdits = [];
  var _fwSnapshot = null;
  var _fwFpType = null;
  var _fwFpResId = null;
  var _fwFpSub = null;
  var _fwFpVnetId = null;
  var _fwFpLk = null;
  var _fwFpDir = "inbound";
  function getFwEdits() {
    return _fwEdits;
  }
  function setFwEdits(v) {
    _fwEdits = v;
  }
  function getFwSnapshot() {
    return _fwSnapshot;
  }
  function setFwSnapshot(v) {
    _fwSnapshot = v;
  }
  function getFwFpType() {
    return _fwFpType;
  }
  function setFwFpType(v) {
    _fwFpType = v;
  }
  function getFwFpResId() {
    return _fwFpResId;
  }
  function setFwFpResId(v) {
    _fwFpResId = v;
  }
  function getFwFpSub() {
    return _fwFpSub;
  }
  function setFwFpSub(v) {
    _fwFpSub = v;
  }
  function getFwFpVnetId() {
    return _fwFpVnetId;
  }
  function setFwFpVnetId(v) {
    _fwFpVnetId = v;
  }
  function getFwFpLk() {
    return _fwFpLk;
  }
  function setFwFpLk(v) {
    _fwFpLk = v;
  }
  function getFwFpDir() {
    return _fwFpDir;
  }
  function setFwFpDir(v) {
    _fwFpDir = v;
  }
  function fwProtoLabel(proto) {
    if (!proto) return "Any";
    const p = String(proto).toLowerCase();
    if (p === "*") return "Any";
    if (p === "tcp") return "TCP";
    if (p === "udp") return "UDP";
    if (p === "icmp") return "ICMP";
    if (p === "esp") return "ESP";
    if (p === "ah") return "AH";
    return proto;
  }
  function fwRuleMatch(a, b) {
    if (!a || !b) return false;
    if (a.name !== b.name) return false;
    if (a.priority !== b.priority) return false;
    if ((a.direction || "").toLowerCase() !== (b.direction || "").toLowerCase()) return false;
    if ((a.access || "").toLowerCase() !== (b.access || "").toLowerCase()) return false;
    if ((a.protocol || "").toLowerCase() !== (b.protocol || "").toLowerCase()) return false;
    if ((a.sourceAddressPrefix || "") !== (b.sourceAddressPrefix || "")) return false;
    if ((a.destinationAddressPrefix || "") !== (b.destinationAddressPrefix || "")) return false;
    if ((a.destinationPortRange || "") !== (b.destinationPortRange || "")) return false;
    return true;
  }
  function fwEditCount(resourceId) {
    return _fwEdits.filter((e) => e.resourceId === resourceId).length;
  }
  function fwValidateCidr(cidr) {
    if (!cidr || typeof cidr !== "string") return false;
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) return false;
    const parts = cidr.split("/");
    const octets = parts[0].split(".");
    for (let i = 0; i < 4; i++) {
      if (parseInt(octets[i], 10) > 255) return false;
    }
    if (parseInt(parts[1], 10) > 32) return false;
    return true;
  }
  function fwValidateAddressPrefix(prefix) {
    if (!prefix || typeof prefix !== "string") return false;
    const val = prefix.trim();
    const serviceTags = ["*", "VirtualNetwork", "AzureLoadBalancer", "Internet"];
    if (serviceTags.includes(val)) return true;
    if (fwValidateCidr(val)) return true;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) {
      const octets = val.split(".");
      for (let i = 0; i < 4; i++) {
        if (parseInt(octets[i], 10) > 255) return false;
      }
      return true;
    }
    if (/^[A-Za-z][A-Za-z0-9.]*$/.test(val)) return true;
    return false;
  }
  function fwValidateNsgRule(rule, existingRules, editingName) {
    const errs = [];
    if (!rule.name || typeof rule.name !== "string" || !rule.name.trim()) {
      errs.push("Rule name is required");
    } else if (!/^[A-Za-z0-9_.-]+$/.test(rule.name.trim())) {
      errs.push("Rule name must contain only alphanumerics, underscores, periods, hyphens");
    }
    const priority = parseInt(rule.priority, 10);
    if (isNaN(priority) || priority < 100 || priority > 4096) {
      errs.push("Priority must be 100-4096");
    }
    if (existingRules && !isNaN(priority)) {
      const dup = existingRules.some(
        (r) => r.priority === priority && (r.direction || "").toLowerCase() === (rule.direction || "").toLowerCase() && r.name !== editingName
      );
      if (dup) errs.push("Duplicate priority " + priority + " in " + rule.direction + " direction");
    }
    const dir = (rule.direction || "").toLowerCase();
    if (dir !== "inbound" && dir !== "outbound") {
      errs.push("Direction must be Inbound or Outbound");
    }
    const access = (rule.access || "").toLowerCase();
    if (access !== "allow" && access !== "deny") {
      errs.push("Access must be Allow or Deny");
    }
    const proto = (rule.protocol || "").toLowerCase();
    const validProtos = ["tcp", "udp", "icmp", "esp", "ah", "*"];
    if (!validProtos.includes(proto)) errs.push("Invalid protocol: " + rule.protocol);
    if (proto === "tcp" || proto === "udp") {
      if (!rule.destinationPortRange && !rule.destinationPortRanges) {
        errs.push("Destination port range required for TCP/UDP");
      } else {
        const portStr = rule.destinationPortRange || "";
        if (portStr && portStr !== "*") {
          const segments = portStr.split(",");
          for (const seg of segments) {
            const s = seg.trim();
            if (s.includes("-")) {
              const [lo, hi] = s.split("-").map(Number);
              if (isNaN(lo) || isNaN(hi) || lo < 0 || lo > 65535 || hi < 0 || hi > 65535 || lo > hi) {
                errs.push("Invalid port range: " + s);
              }
            } else {
              const n = Number(s);
              if (isNaN(n) || n < 0 || n > 65535) errs.push("Invalid port: " + s);
            }
          }
        }
      }
    }
    if (!fwValidateAddressPrefix(rule.sourceAddressPrefix || "")) {
      if (!(rule.sourceAddressPrefixes && rule.sourceAddressPrefixes.length)) {
        errs.push("Invalid source address prefix");
      }
    }
    if (!fwValidateAddressPrefix(rule.destinationAddressPrefix || "")) {
      if (!(rule.destinationAddressPrefixes && rule.destinationAddressPrefixes.length)) {
        errs.push("Invalid destination address prefix");
      }
    }
    return errs;
  }
  function fwValidateRoute(route, existingRoutes, editingName) {
    const errs = [];
    if (!route.name || typeof route.name !== "string" || !route.name.trim()) {
      errs.push("Route name is required");
    }
    if (!fwValidateCidr(route.addressPrefix)) errs.push("Invalid address prefix (CIDR)");
    if (existingRoutes) {
      const dup = existingRoutes.some(
        (r) => r.addressPrefix === route.addressPrefix && r.name !== editingName
      );
      if (dup) errs.push("Duplicate address prefix: " + route.addressPrefix);
    }
    const validHops = ["VirtualNetworkGateway", "VNetLocal", "Internet", "VirtualAppliance", "None"];
    if (!validHops.includes(route.nextHopType)) {
      errs.push("Invalid next hop type. Must be: " + validHops.join(", "));
    }
    if (route.nextHopType === "VirtualAppliance") {
      if (!route.nextHopIpAddress || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(route.nextHopIpAddress)) {
        errs.push("VirtualAppliance requires a valid next hop IP address");
      }
    }
    return errs;
  }
  function fwCheckNsgShadow(nsg, direction) {
    if (!nsg || !nsg.securityRules) return [];
    const dir = (direction || "").toLowerCase();
    const rules = (nsg.securityRules || []).filter((r) => (r.direction || "").toLowerCase() === dir).sort((a, b) => a.priority - b.priority);
    const warnings = [];
    for (let i = 1; i < rules.length; i++) {
      for (let j = 0; j < i; j++) {
        const hi = rules[i];
        const lo = rules[j];
        const sameSrc = (hi.sourceAddressPrefix || "") === (lo.sourceAddressPrefix || "") || lo.sourceAddressPrefix === "*";
        const sameDst = (hi.destinationAddressPrefix || "") === (lo.destinationAddressPrefix || "") || lo.destinationAddressPrefix === "*";
        const sameProto = (hi.protocol || "") === (lo.protocol || "") || lo.protocol === "*";
        const samePort = (hi.destinationPortRange || "") === (lo.destinationPortRange || "") || lo.destinationPortRange === "*";
        if (sameSrc && sameDst && sameProto && samePort && (hi.access || "").toLowerCase() !== (lo.access || "").toLowerCase()) {
          warnings.push(
            'Rule "' + hi.name + '" (priority ' + hi.priority + ", " + hi.access + ') is shadowed by "' + lo.name + '" (priority ' + lo.priority + ", " + lo.access + ") \u2014 same scope, evaluated first"
          );
        }
      }
    }
    return warnings;
  }
  function extractResourceGroup(armId) {
    if (!armId || typeof armId !== "string") return "{resource-group}";
    const match = armId.match(/\/resourceGroups\/([^/]+)/i);
    return match ? match[1] : "{resource-group}";
  }
  function fwGenerateCli(edits) {
    const list = edits || _fwEdits;
    const cmds = [];
    list.forEach((edit) => {
      if (edit.type === "nsg") fwGenNsgCli(edit, cmds);
      else if (edit.type === "udr") fwGenUdrCli(edit, cmds);
    });
    return cmds;
  }
  function fwGenNsgCli(edit, cmds) {
    const nsgName = edit.nsgName || edit.resourceId;
    const rg = edit.resourceGroup || "{resource-group}";
    if (edit.action === "add" || edit.action === "modify") {
      cmds.push(_fwNsgRuleCmd("create", rg, nsgName, edit.rule));
    } else if (edit.action === "delete") {
      cmds.push(
        "az network nsg rule delete --resource-group " + rg + " --nsg-name " + nsgName + " --name " + edit.rule.name
      );
    }
  }
  function _fwNsgRuleCmd(verb, rg, nsgName, rule) {
    let cmd = "az network nsg rule " + verb + " --resource-group " + rg + " --nsg-name " + nsgName + " --name " + rule.name + " --priority " + rule.priority + " --direction " + rule.direction + " --access " + rule.access + " --protocol " + rule.protocol;
    if (rule.sourcePortRange) cmd += " --source-port-ranges " + rule.sourcePortRange;
    else cmd += ' --source-port-ranges "*"';
    if (rule.destinationPortRange) cmd += " --destination-port-ranges " + rule.destinationPortRange;
    else cmd += ' --destination-port-ranges "*"';
    if (rule.sourceAddressPrefix) cmd += " --source-address-prefixes " + rule.sourceAddressPrefix;
    else cmd += ' --source-address-prefixes "*"';
    if (rule.destinationAddressPrefix) cmd += " --destination-address-prefixes " + rule.destinationAddressPrefix;
    else cmd += ' --destination-address-prefixes "*"';
    return cmd;
  }
  function fwGenUdrCli(edit, cmds) {
    const rtName = edit.routeTableName || edit.resourceId;
    const rg = edit.resourceGroup || "{resource-group}";
    if (edit.action === "add" || edit.action === "modify") {
      cmds.push(_fwUdrRouteCmd("create", rg, rtName, edit.rule));
    } else if (edit.action === "delete") {
      cmds.push(
        "az network route-table route delete --resource-group " + rg + " --route-table-name " + rtName + " --name " + edit.rule.name
      );
    }
  }
  function _fwUdrRouteCmd(verb, rg, rtName, route) {
    let cmd = "az network route-table route " + verb + " --resource-group " + rg + " --route-table-name " + rtName + " --name " + route.name + " --address-prefix " + route.addressPrefix + " --next-hop-type " + route.nextHopType;
    if (route.nextHopType === "VirtualAppliance" && route.nextHopIpAddress) {
      cmd += " --next-hop-ip-address " + route.nextHopIpAddress;
    }
    return cmd;
  }
  function fwTakeSnapshot(ctx) {
    if (_fwSnapshot) return;
    if (!ctx) return;
    _fwSnapshot = {
      nsgs: JSON.parse(JSON.stringify(ctx.nsgs || [])),
      udrs: JSON.parse(JSON.stringify(ctx.udrs || []))
    };
  }
  function fwResetAll(ctx) {
    if (!_fwSnapshot || !ctx) return;
    ctx.nsgs.length = 0;
    _fwSnapshot.nsgs.forEach((n) => ctx.nsgs.push(JSON.parse(JSON.stringify(n))));
    ctx.udrs.length = 0;
    _fwSnapshot.udrs.forEach((r) => ctx.udrs.push(JSON.parse(JSON.stringify(r))));
    fwRebuildLookups(ctx);
    _fwEdits = [];
    _fwSnapshot = null;
  }
  function fwRebuildLookups(ctx) {
    if (!ctx) return;
    const subnetNsgs = {};
    (ctx.nsgs || []).forEach((nsg) => {
      (nsg.subnets || []).forEach((subRef) => {
        const subId = typeof subRef === "string" ? subRef : subRef.id || subRef.SubnetId;
        if (subId) subnetNsgs[subId] = nsg;
      });
    });
    ctx.subnetNsgs = subnetNsgs;
    const subRT = {};
    (ctx.udrs || []).forEach((rt) => {
      (rt.subnets || []).forEach((subRef) => {
        const subId = typeof subRef === "string" ? subRef : subRef.id || subRef.SubnetId;
        if (subId) subRT[subId] = rt;
      });
    });
    ctx.subRT = subRT;
    const nsgByVnet = {};
    (ctx.nsgs || []).forEach((nsg) => {
      const vnetId = nsg.vnetId || "";
      (nsgByVnet[vnetId] = nsgByVnet[vnetId] || []).push(nsg);
    });
    ctx.nsgByVnet = nsgByVnet;
  }
  function fwRemoveRule(edit, ctx) {
    if (edit.type === "nsg") {
      const nsg = (ctx.nsgs || []).find((n) => n.id === edit.resourceId || n.name === edit.resourceId);
      if (!nsg) return;
      const idx = (nsg.securityRules || []).findIndex(
        (r) => r.name === edit.rule.name && r.priority === edit.rule.priority
      );
      if (idx >= 0) nsg.securityRules.splice(idx, 1);
    } else if (edit.type === "udr") {
      const rt = (ctx.udrs || []).find((r) => r.id === edit.resourceId || r.name === edit.resourceId);
      if (!rt || !rt.routes) return;
      const idx = rt.routes.findIndex((r) => r.addressPrefix === edit.rule.addressPrefix);
      if (idx >= 0) rt.routes.splice(idx, 1);
    }
  }
  function fwRestoreRule(edit, ctx) {
    if (edit.originalRule) {
      fwApplyRule(edit.type, edit.resourceId, edit.direction, edit.originalRule, ctx);
    }
  }
  function fwApplyRule(type, resourceId, direction, ruleData, ctx) {
    if (type === "nsg") {
      const nsg = (ctx.nsgs || []).find((n) => n.id === resourceId || n.name === resourceId);
      if (!nsg) return;
      if (!nsg.securityRules) nsg.securityRules = [];
      const idx = nsg.securityRules.findIndex(
        (r) => r.name === ruleData.name && r.priority === ruleData.priority
      );
      const entry = Object.assign({}, ruleData);
      if (idx >= 0) nsg.securityRules[idx] = entry;
      else nsg.securityRules.push(entry);
    } else if (type === "udr") {
      const rt = (ctx.udrs || []).find((r) => r.id === resourceId || r.name === resourceId);
      if (!rt) return;
      if (!rt.routes) rt.routes = [];
      const idx = rt.routes.findIndex((r) => r.addressPrefix === ruleData.addressPrefix);
      if (idx >= 0) rt.routes[idx] = Object.assign({}, ruleData);
      else rt.routes.push(Object.assign({}, ruleData));
    }
  }
  function fwUndo(ctx) {
    if (!_fwEdits.length) return null;
    const edit = _fwEdits.pop();
    if (edit.action === "add") fwRemoveRule(edit, ctx);
    else if (edit.action === "delete") fwRestoreRule(edit, ctx);
    else if (edit.action === "modify") {
      fwApplyRule(edit.type, edit.resourceId, edit.direction, edit.originalRule, ctx);
    }
    fwRebuildLookups(ctx);
    return edit;
  }

  // src/modules/multi-tenant.js
  var multi_tenant_exports = {};
  __export(multi_tenant_exports, {
    _loadedContexts: () => loadedContexts,
    _mergedCtx: () => mergedCtx,
    _multiViewMode: () => multiViewMode,
    _singleCtxBackup: () => singleCtxBackup,
    assignTenantColors: () => assignTenantColors,
    buildRlCtxFromData: () => buildRlCtxFromData,
    buildTenantContext: () => buildTenantContext,
    detectLocationFromCtx: () => detectLocationFromCtx,
    getLoadedContexts: () => getLoadedContexts,
    getMergedCtx: () => getMergedCtx,
    getMultiViewMode: () => getMultiViewMode,
    getSingleCtxBackup: () => getSingleCtxBackup,
    getSubscriptionDisplayName: () => getSubscriptionDisplayName,
    getSubscriptions: () => getSubscriptions,
    getTenantDisplayName: () => getTenantDisplayName,
    getTenants: () => getTenants,
    isLighthouse: () => isLighthouse,
    mergeContexts: () => mergeContexts,
    mergeTenantData: () => mergeTenantData,
    setLoadedContexts: () => setLoadedContexts,
    setMergedCtx: () => setMergedCtx,
    setMultiViewMode: () => setMultiViewMode,
    setSingleCtxBackup: () => setSingleCtxBackup
  });
  var TENANT_COLORS = [
    "#3b82f6",
    "#ef4444",
    "#10b981",
    "#f59e0b",
    "#8b5cf6",
    "#ec4899",
    "#14b8a6",
    "#f97316",
    "#6366f1",
    "#84cc16",
    "#06b6d4",
    "#e11d48",
    "#a855f7",
    "#22c55e",
    "#eab308"
  ];
  var multiViewMode = false;
  var loadedContexts = [];
  var mergedCtx = null;
  var singleCtxBackup = null;
  function getMultiViewMode() {
    return multiViewMode;
  }
  function setMultiViewMode(v) {
    multiViewMode = v;
  }
  function getLoadedContexts() {
    return loadedContexts;
  }
  function setLoadedContexts(v) {
    loadedContexts = v;
  }
  function getMergedCtx() {
    return mergedCtx;
  }
  function setMergedCtx(v) {
    mergedCtx = v;
  }
  function getSingleCtxBackup() {
    return singleCtxBackup;
  }
  function setSingleCtxBackup(v) {
    singleCtxBackup = v;
  }
  function _extractSubscriptionId(resourceId) {
    if (!resourceId) return "";
    const match = resourceId.match(/\/subscriptions\/([^/]+)/i);
    return match ? match[1] : "";
  }
  function _extractResourceGroup(resourceId) {
    if (!resourceId) return "";
    const match = resourceId.match(/\/resourceGroups\/([^/]+)/i);
    return match ? match[1] : "";
  }
  function buildTenantContext(resources) {
    const tenants = /* @__PURE__ */ new Map();
    const subscriptionToTenant = /* @__PURE__ */ new Map();
    const resourceGroupIndex = /* @__PURE__ */ new Map();
    (resources || []).forEach((r) => {
      const subId = _extractSubscriptionId(r.id) || r._subscriptionId || "";
      const rgName = _extractResourceGroup(r.id) || r._resourceGroup || "";
      const tenantId2 = getTenantFromResource(r) || r._tenantId || "default";
      const isLighthouse2 = r._isLighthouse === true;
      if (subId && tenantId2) subscriptionToTenant.set(subId, tenantId2);
      if (!tenants.has(tenantId2)) {
        tenants.set(tenantId2, {
          tenantId: tenantId2,
          displayName: r._tenantDisplayName || tenantId2,
          subscriptions: /* @__PURE__ */ new Map(),
          isLighthouse: isLighthouse2
        });
      }
      const tenant = tenants.get(tenantId2);
      if (isLighthouse2) tenant.isLighthouse = true;
      if (subId && !tenant.subscriptions.has(subId)) {
        tenant.subscriptions.set(subId, {
          subscriptionId: subId,
          displayName: r._subscriptionDisplayName || subId,
          resourceGroups: /* @__PURE__ */ new Map(),
          isLighthouse: isLighthouse2
        });
      }
      if (subId && rgName) {
        const sub = tenant.subscriptions.get(subId);
        if (!sub.resourceGroups.has(rgName)) sub.resourceGroups.set(rgName, []);
        sub.resourceGroups.get(rgName).push(r);
        const rgKey = subId + "/" + rgName;
        if (!resourceGroupIndex.has(rgKey)) resourceGroupIndex.set(rgKey, []);
        resourceGroupIndex.get(rgKey).push(r.id || "");
      }
      r._tenantId = tenantId2;
      r._subscriptionId = subId;
      r._resourceGroup = rgName;
      r._isLighthouse = isLighthouse2;
    });
    return { tenants, subscriptionToTenant, resourceGroupIndex };
  }
  function getTenants() {
    const tenantMap = /* @__PURE__ */ new Map();
    loadedContexts.forEach((ctx) => {
      const tid = ctx.tenantId || "default";
      if (!tenantMap.has(tid)) {
        tenantMap.set(tid, {
          tenantId: tid,
          displayName: ctx.tenantDisplayName || tid,
          subscriptions: /* @__PURE__ */ new Set(),
          resourceCount: 0,
          isLighthouse: ctx.isLighthouse || false,
          color: ctx.color || TENANT_COLORS[0]
        });
      }
      const t = tenantMap.get(tid);
      if (ctx.subscriptionId) t.subscriptions.add(ctx.subscriptionId);
      t.resourceCount += (ctx.rlCtx?.vnets?.length || 0) + (ctx.rlCtx?.subnets?.length || 0);
      if (ctx.isLighthouse) t.isLighthouse = true;
    });
    return [...tenantMap.values()].map((t) => ({
      ...t,
      subscriptionCount: t.subscriptions.size,
      subscriptions: [...t.subscriptions]
    }));
  }
  function getSubscriptions(tenantId2) {
    const subMap = /* @__PURE__ */ new Map();
    loadedContexts.forEach((ctx) => {
      if (tenantId2 && ctx.tenantId !== tenantId2) return;
      const sid2 = ctx.subscriptionId || "";
      if (!sid2) return;
      if (!subMap.has(sid2)) {
        subMap.set(sid2, {
          subscriptionId: sid2,
          displayName: ctx.subscriptionDisplayName || ctx.subscriptionLabel || sid2,
          tenantId: ctx.tenantId || "default",
          isLighthouse: ctx.isLighthouse || false,
          color: ctx.color || TENANT_COLORS[0],
          resourceGroups: /* @__PURE__ */ new Set()
        });
      }
      if (ctx.resourceGroup) subMap.get(sid2).resourceGroups.add(ctx.resourceGroup);
    });
    return [...subMap.values()].map((s) => ({
      ...s,
      resourceGroups: [...s.resourceGroups]
    }));
  }
  function assignTenantColors(tenants) {
    const colorMap = /* @__PURE__ */ new Map();
    const ids = tenants.map((t) => typeof t === "string" ? t : t.tenantId);
    ids.forEach((tid, i) => {
      colorMap.set(tid, TENANT_COLORS[i % TENANT_COLORS.length]);
    });
    loadedContexts.forEach((ctx) => {
      if (ctx.tenantId && colorMap.has(ctx.tenantId)) {
        ctx.color = colorMap.get(ctx.tenantId);
      }
    });
    return colorMap;
  }
  function isLighthouse(resource) {
    if (!resource) return false;
    return resource._isLighthouse === true;
  }
  function buildRlCtxFromData(textareas, subscriptionLabel) {
    try {
      let _val = function(id) {
        const v = textareas[id];
        if (!v) return null;
        if (typeof v === "string") {
          const p = safeParse(v);
          if (p !== null) textareas[id] = p;
          return p;
        }
        return v;
      }, tagResource = function(r) {
        if (!r) return r;
        r._subscriptionId = _extractSubscriptionId(r.id) || r._subscriptionId || userSubscription || "default";
        r._resourceGroup = _extractResourceGroup(r.id) || r._resourceGroup || "";
        r._tenantId = getTenantFromResource(r) || r._tenantId || "";
        r._location = r.location || "";
        return r;
      }, fillLocation = function(r) {
        if (r && !r._location && r._vnetId && vnetLocation[r._vnetId]) r._location = vnetLocation[r._vnetId];
      };
      const userSubscription = subscriptionLabel || "";
      let vnets = ext(_val("in_vnets"), ["value"]);
      let subnets = ext(_val("in_subnets"), ["value"]);
      let nsgs = ext(_val("in_nsgs"), ["value"]);
      let routeTables = ext(_val("in_route_tables"), ["value"]);
      let nics = ext(_val("in_nics"), ["value"]);
      let natGateways = ext(_val("in_nat_gateways"), ["value"]);
      let publicIps = ext(_val("in_public_ips"), ["value"]);
      let vms = ext(_val("in_vms"), ["value"]);
      let lbs = ext(_val("in_lbs"), ["value"]);
      let appGateways = ext(_val("in_app_gateways"), ["value"]);
      let peerings = ext(_val("in_peerings"), ["value"]);
      let vpnGateways = ext(_val("in_vpn_gateways"), ["value"]);
      let firewalls = ext(_val("in_firewalls"), ["value"]);
      let bastionHosts = ext(_val("in_bastion"), ["value"]);
      let privateDnsZones = ext(_val("in_private_dns"), ["value"]);
      let sqlServers = ext(_val("in_sql"), ["value"]);
      let aksClusters = ext(_val("in_aks"), ["value"]);
      let functionApps = ext(_val("in_functions"), ["value"]);
      let appServices = ext(_val("in_appservices"), ["value"]);
      let redisCaches = ext(_val("in_redis"), ["value"]);
      let cosmosAccounts = ext(_val("in_cosmos"), ["value"]);
      let storageAccounts = ext(_val("in_storage"), ["value"]);
      let privateEndpoints = ext(_val("in_private_endpoints"), ["value"]);
      let disks = ext(_val("in_disks"), ["value"]);
      let wafPolicies = ext(_val("in_waf"), ["value"]);
      [
        vnets,
        subnets,
        nsgs,
        routeTables,
        nics,
        natGateways,
        publicIps,
        vms,
        lbs,
        appGateways,
        peerings,
        vpnGateways,
        firewalls,
        bastionHosts,
        privateDnsZones,
        sqlServers,
        aksClusters,
        functionApps,
        appServices,
        redisCaches,
        cosmosAccounts,
        storageAccounts,
        privateEndpoints,
        disks,
        wafPolicies
      ].forEach((arr) => arr.forEach(tagResource));
      const vnetLocation = {};
      subnets.forEach((s) => {
        const vnetId = s._vnetId || "";
        if (vnetId && s._location) vnetLocation[vnetId] = s._location;
      });
      [nsgs, routeTables, nics, natGateways].forEach((arr) => arr.forEach(fillLocation));
      const _subscriptions = /* @__PURE__ */ new Set();
      const _tenants = /* @__PURE__ */ new Set();
      vnets.forEach((v) => {
        if (v._subscriptionId && v._subscriptionId !== "default") _subscriptions.add(v._subscriptionId);
        if (v._tenantId) _tenants.add(v._tenantId);
      });
      const _multiSubscription = _subscriptions.size > 1;
      const _multiTenant = _tenants.size > 1;
      const _locations = /* @__PURE__ */ new Set();
      vnets.forEach((v) => {
        if (v._location) _locations.add(v._location);
      });
      const _multiLocation = _locations.size > 1;
      const vnetIds = new Set(vnets.map((v) => v.id));
      subnets.forEach((s) => {
        if (!s._vnetId) {
          const parts = (s.id || "").split("/subnets/");
          if (parts.length === 2) s._vnetId = parts[0];
        }
      });
      const resourcesBySub = {};
      const vmBySub = {};
      const nicBySub = {};
      const lbBySub = {};
      nics.forEach((nic) => {
        const ipConfigs = nic.properties?.ipConfigurations || [];
        ipConfigs.forEach((ipc) => {
          const subnetId = ipc.properties?.subnet?.id || "";
          if (subnetId) {
            if (!nicBySub[subnetId]) nicBySub[subnetId] = [];
            nicBySub[subnetId].push(nic);
          }
        });
      });
      vms.forEach((vm) => {
        const vmNics = vm.properties?.networkProfile?.networkInterfaces || [];
        vmNics.forEach((vmNic) => {
          const nic = nics.find((n) => n.id === vmNic.id);
          if (nic) {
            const ipConfigs = nic.properties?.ipConfigurations || [];
            ipConfigs.forEach((ipc) => {
              const subnetId = ipc.properties?.subnet?.id || "";
              if (subnetId) {
                if (!vmBySub[subnetId]) vmBySub[subnetId] = [];
                vmBySub[subnetId].push(vm);
                if (!resourcesBySub[subnetId]) resourcesBySub[subnetId] = [];
                resourcesBySub[subnetId].push(vm);
              }
            });
          }
        });
      });
      lbs.forEach((lb) => {
        (lb.properties?.frontendIPConfigurations || []).forEach((fip) => {
          const subnetId = fip.properties?.subnet?.id || "";
          if (subnetId) {
            if (!lbBySub[subnetId]) lbBySub[subnetId] = [];
            lbBySub[subnetId].push(lb);
          }
        });
      });
      const nsgBySub = {};
      subnets.forEach((s) => {
        const nsgId = s.properties?.networkSecurityGroup?.id || s.nsgId;
        if (nsgId) {
          const nsg = nsgs.find((n) => n.id === nsgId);
          if (nsg) nsgBySub[s.id] = nsg;
        }
      });
      const rtBySub = {};
      subnets.forEach((s) => {
        const rtId = s.properties?.routeTable?.id || s.routeTableId;
        if (rtId) {
          const rt = routeTables.find((r) => r.id === rtId);
          if (rt) rtBySub[s.id] = rt;
        }
      });
      const nsgByVnet = {};
      nsgs.forEach((nsg) => {
        const vnetId = nsg._vnetId || "";
        if (vnetId) {
          if (!nsgByVnet[vnetId]) nsgByVnet[vnetId] = [];
          nsgByVnet[vnetId].push(nsg);
        }
      });
      const peBySub = {};
      privateEndpoints.forEach((pe) => {
        const subnetId = pe.properties?.subnet?.id || "";
        if (subnetId) {
          if (!peBySub[subnetId]) peBySub[subnetId] = [];
          peBySub[subnetId].push(pe);
        }
      });
      return {
        vnets,
        subnets,
        nsgs,
        routeTables,
        nics,
        natGateways,
        publicIps,
        vms,
        lbs,
        appGateways,
        peerings,
        vpnGateways,
        firewalls,
        bastionHosts,
        privateDnsZones,
        sqlServers,
        aksClusters,
        functionApps,
        appServices,
        redisCaches,
        cosmosAccounts,
        storageAccounts,
        privateEndpoints,
        disks,
        wafPolicies,
        resourcesBySub,
        vmBySub,
        nicBySub,
        lbBySub,
        nsgBySub,
        rtBySub,
        nsgByVnet,
        peBySub,
        _subscriptions,
        _tenants,
        _locations,
        _multiSubscription,
        _multiTenant,
        _multiLocation
      };
    } catch (e) {
      console.warn("buildRlCtxFromData error:", e);
      return null;
    }
  }
  function mergeTenantData(existingCtx, newResources, tenantLabel) {
    if (!existingCtx) {
      const textareas = {};
      newResources.forEach((r) => {
        const type = (r.type || "").toLowerCase();
        let key = "in_misc";
        if (type.includes("virtualnetwork") && !type.includes("subnet")) key = "in_vnets";
        else if (type.includes("subnet")) key = "in_subnets";
        else if (type.includes("networksecuritygroup")) key = "in_nsgs";
        else if (type.includes("routetable")) key = "in_route_tables";
        else if (type.includes("networkinterface")) key = "in_nics";
        else if (type.includes("natgateway")) key = "in_nat_gateways";
        else if (type.includes("publicipaddress")) key = "in_public_ips";
        else if (type.includes("virtualmachine")) key = "in_vms";
        else if (type.includes("loadbalancer")) key = "in_lbs";
        else if (type.includes("applicationgateway")) key = "in_app_gateways";
        if (!textareas[key]) textareas[key] = { value: [] };
        textareas[key].value.push(r);
      });
      return buildRlCtxFromData(textareas, tenantLabel);
    }
    newResources.forEach((r) => {
      r._tenantLabel = tenantLabel;
      const type = (r.type || "").toLowerCase();
      if (type.includes("virtualnetwork") && !type.includes("subnet")) existingCtx.vnets.push(r);
      else if (type.includes("subnet")) existingCtx.subnets.push(r);
      else if (type.includes("networksecuritygroup")) existingCtx.nsgs.push(r);
      else if (type.includes("virtualmachine")) existingCtx.vms.push(r);
    });
    return existingCtx;
  }
  function getTenantDisplayName(tenantId2) {
    if (!tenantId2 || tenantId2 === "default") return "Default Tenant";
    const ctx = loadedContexts.find((c) => c.tenantId === tenantId2);
    if (ctx?.tenantDisplayName) return ctx.tenantDisplayName;
    if (tenantId2.length > 12) return tenantId2.substring(0, 8) + "...";
    return tenantId2;
  }
  function getSubscriptionDisplayName(subId) {
    if (!subId || subId === "default") return "Default Subscription";
    const ctx = loadedContexts.find((c) => c.subscriptionId === subId);
    if (ctx?.subscriptionDisplayName || ctx?.subscriptionLabel) return ctx.subscriptionDisplayName || ctx.subscriptionLabel;
    if (subId.length > 12) return subId.substring(0, 8) + "...";
    return subId;
  }
  function mergeContexts(contexts) {
    const visible = contexts.filter((c) => c.visible);
    if (!visible.length) return null;
    visible.forEach((c) => {
      if (!c.rlCtx && c.textareas) c.rlCtx = buildRlCtxFromData(c.textareas, c.subscriptionLabel);
    });
    if (visible.length === 1) return visible[0].rlCtx;
    const merged = {
      vnets: [],
      subnets: [],
      nsgs: [],
      routeTables: [],
      nics: [],
      natGateways: [],
      publicIps: [],
      vms: [],
      lbs: [],
      appGateways: [],
      peerings: [],
      vpnGateways: [],
      firewalls: [],
      bastionHosts: [],
      privateDnsZones: [],
      sqlServers: [],
      aksClusters: [],
      functionApps: [],
      appServices: [],
      redisCaches: [],
      cosmosAccounts: [],
      storageAccounts: [],
      privateEndpoints: [],
      disks: [],
      wafPolicies: [],
      resourcesBySub: {},
      vmBySub: {},
      nicBySub: {},
      lbBySub: {},
      nsgBySub: {},
      rtBySub: {},
      nsgByVnet: {},
      peBySub: {},
      _subscriptions: /* @__PURE__ */ new Set(),
      _tenants: /* @__PURE__ */ new Set(),
      _locations: /* @__PURE__ */ new Set(),
      _multiSubscription: true,
      _multiTenant: false,
      _multiLocation: false
    };
    visible.forEach((ctx) => {
      const c = ctx.rlCtx;
      if (!c) return;
      const tag = (r) => {
        if (r) {
          r._subscriptionId = r._subscriptionId || ctx.subscriptionId;
          r._tenantId = r._tenantId || ctx.tenantId;
          r._subscriptionLabel = ctx.subscriptionLabel;
          r._ctxColor = ctx.color;
          r._isLighthouse = ctx.isLighthouse || r._isLighthouse || false;
        }
        return r;
      };
      const arrayKeys = [
        "vnets",
        "subnets",
        "nsgs",
        "routeTables",
        "nics",
        "natGateways",
        "publicIps",
        "vms",
        "lbs",
        "appGateways",
        "peerings",
        "vpnGateways",
        "firewalls",
        "bastionHosts",
        "privateDnsZones",
        "sqlServers",
        "aksClusters",
        "functionApps",
        "appServices",
        "redisCaches",
        "cosmosAccounts",
        "storageAccounts",
        "privateEndpoints",
        "disks",
        "wafPolicies"
      ];
      arrayKeys.forEach((k) => {
        if (c[k] && Array.isArray(c[k])) c[k].forEach((r) => {
          tag(r);
          merged[k].push(r);
        });
      });
      if (c._subscriptions) c._subscriptions.forEach((s) => merged._subscriptions.add(s));
      merged._subscriptions.add(ctx.subscriptionId);
      if (c._tenants) c._tenants.forEach((t) => merged._tenants.add(t));
      if (ctx.tenantId) merged._tenants.add(ctx.tenantId);
      if (c._locations) c._locations.forEach((l) => merged._locations.add(l));
      const mapKeys = [
        "resourcesBySub",
        "vmBySub",
        "nicBySub",
        "lbBySub",
        "nsgBySub",
        "rtBySub",
        "nsgByVnet",
        "peBySub"
      ];
      mapKeys.forEach((k) => {
        if (!c[k]) return;
        const src = c[k];
        const keys = src instanceof Map ? [...src.keys()] : Object.keys(src);
        keys.forEach((key) => {
          const val = src instanceof Map ? src.get(key) : src[key];
          if (Array.isArray(val)) {
            if (!merged[k][key]) merged[k][key] = [];
            val.forEach((v) => merged[k][key].push(v));
          } else {
            if (!merged[k][key]) merged[k][key] = val;
          }
        });
      });
    });
    merged._multiTenant = merged._tenants.size > 1;
    merged._multiSubscription = merged._subscriptions.size > 1;
    merged._multiLocation = merged._locations.size > 1;
    return merged;
  }
  function detectLocationFromCtx(ctx) {
    if (!ctx) return "unknown";
    const vnet = (ctx.vnets || [])[0];
    if (vnet && vnet.location) return vnet.location;
    const vm = (ctx.vms || [])[0];
    if (vm && vm.location) return vm.location;
    return "unknown";
  }

  // src/modules/compliance-view.js
  var compliance_view_exports = {};
  __export(compliance_view_exports, {
    EFFORT_MAP: () => EFFORT_MAP,
    _EFFORT_MAP: () => EFFORT_MAP,
    _compDashState: () => _compDashState,
    _complianceRefs: () => complianceRefs,
    _mutedFindings: () => _mutedFindings,
    aggregateTopResources: () => aggregateTopResources,
    buildComplianceView: () => buildComplianceView,
    calcComplianceScore: () => calcComplianceScore,
    classifyTier: () => classifyTier,
    complianceRefs: () => complianceRefs,
    estimateTotalEffort: () => estimateTotalEffort,
    getCompDashState: () => getCompDashState,
    getEffort: () => getEffort,
    getMutedFindings: () => getMutedFindings,
    getSeverityGroups: () => getSeverityGroups,
    getTierGroups: () => getTierGroups,
    groupByResource: () => groupByResource,
    isMuted: () => isMuted,
    muteKey: () => muteKey,
    saveMuted: () => saveMuted,
    setCompDashState: () => setCompDashState,
    setMutedFindings: () => setMutedFindings,
    toggleMute: () => toggleMute
  });
  var EFFORT_MAP = {
    // CIS
    "CIS 5.1": "low",
    "CIS 5.2": "low",
    "CIS 5.3": "low",
    "CIS 5.4": "low",
    "CIS 5.5": "med",
    "NET-1": "med",
    "NET-2": "low",
    // WAF
    "WAF-1": "med",
    "WAF-2": "med",
    "WAF-3": "med",
    "WAF-4": "low",
    // ARCH
    "ARCH-N1": "med",
    "ARCH-N2": "med",
    "ARCH-N3": "high",
    "ARCH-N5": "low",
    "ARCH-C1": "low",
    "ARCH-C2": "low",
    "ARCH-C3": "med",
    "ARCH-C4": "med",
    "ARCH-C5": "low",
    "ARCH-C6": "med",
    "ARCH-D1": "low",
    "ARCH-D2": "med",
    "ARCH-D3": "high",
    "ARCH-D4": "med",
    "ARCH-D5": "high",
    "ARCH-D6": "high",
    "ARCH-D7": "low",
    "ARCH-S1": "low",
    "ARCH-S2": "low",
    "ARCH-E1": "med",
    "ARCH-E2": "low",
    "ARCH-G1": "high",
    "ARCH-G2": "low",
    "ARCH-X1": "med",
    // SOC2
    "SOC2-CC6.1": "low",
    "SOC2-CC6.3": "low",
    "SOC2-CC6.6": "med",
    "SOC2-CC6.7": "med",
    "SOC2-CC6.8": "low",
    "SOC2-CC6.10": "med",
    "SOC2-CC7.2": "med",
    "SOC2-CC7.3": "low",
    "SOC2-CC8.1": "low",
    "SOC2-A1.2": "med",
    "SOC2-A1.3": "low",
    "SOC2-A1.4": "med",
    "SOC2-C1.1": "low",
    "SOC2-C1.2": "low",
    "SOC2-C1.3": "high",
    "SOC2-PI1.1": "med",
    // PCI
    "PCI-1.3.1": "low",
    "PCI-1.3.2": "low",
    "PCI-1.3.4": "med",
    "PCI-2.2.1": "low",
    "PCI-2.3.1": "high",
    "PCI-3.4.1": "med",
    "PCI-3.5.1": "med",
    "PCI-4.2.1": "med",
    "PCI-6.3.1": "med",
    "PCI-6.4.1": "med",
    "PCI-7.2.1": "low",
    "PCI-10.2.1": "med",
    "PCI-11.3.1": "low",
    "PCI-12.10.1": "med",
    // IAM
    "IAM-1": "med",
    "IAM-2": "med",
    "IAM-3": "low",
    "IAM-4": "med",
    "IAM-5": "low",
    "IAM-6": "low",
    "IAM-7": "low",
    "IAM-8": "med",
    "IAM-9": "low",
    "IAM-10": "low",
    "IAM-11": "low",
    "IAM-12": "med",
    "IAM-13": "low",
    // CKV (standalone Checkov checks: Azure equivalents)
    "CKV_AZURE_1": "med",
    "CKV_AZURE_2": "med",
    "CKV_AZURE_3": "low",
    "CKV_AZURE_4": "low",
    "CKV_AZURE_5": "low",
    "CKV_AZURE_6": "low",
    "CKV_AZURE_7": "low",
    // BUDR
    "BUDR-HA-1": "med",
    "BUDR-HA-2": "med",
    "BUDR-HA-3": "low",
    "BUDR-HA-4": "med",
    "BUDR-HA-5": "med",
    "BUDR-HA-6": "low",
    "BUDR-BAK-1": "low",
    "BUDR-BAK-2": "med",
    "BUDR-BAK-3": "med",
    "BUDR-BAK-4": "low",
    "BUDR-BAK-5": "low",
    "BUDR-DR-1": "high",
    "BUDR-DR-2": "med"
  };
  var complianceRefs = {
    "CIS 5.1": { url: "https://learn.microsoft.com/azure/network-security-groups/security-overview", ref: "CIS Azure Foundations 5.1" },
    "CIS 5.2": { url: "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview", ref: "CIS Azure Foundations 5.2" },
    "CIS 5.3": { url: "https://learn.microsoft.com/azure/network-watcher/network-watcher-monitoring-overview", ref: "CIS Azure Foundations 5.3" },
    "CIS 5.4": { url: "https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview", ref: "CIS Azure Foundations 5.4" },
    "CIS 5.5": { url: "https://learn.microsoft.com/azure/virtual-network/virtual-network-peering-overview", ref: "CIS Azure Foundations 5.5" },
    "NET-1": { url: "https://learn.microsoft.com/azure/architecture/reference-architectures/hybrid-networking/hub-spoke", ref: "VNet Hub-Spoke Design" },
    "NET-2": { url: "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview", ref: "NSG Best Practices" },
    "WAF-1": { url: "https://learn.microsoft.com/azure/web-application-firewall/overview", ref: "Azure WAF Rules" },
    "WAF-2": { url: "https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-waf-configuration", ref: "WAF Rate Limiting" },
    "WAF-3": { url: "https://learn.microsoft.com/azure/web-application-firewall/afds/afds-overview", ref: "WAF App Gateway Protection" },
    "WAF-4": { url: "https://learn.microsoft.com/azure/web-application-firewall/ag/policy-overview", ref: "WAF Policy Mode" },
    "ARCH-N1": { url: "https://learn.microsoft.com/azure/architecture/framework/security/security-principles", ref: "Azure CAF SEC05-BP01" },
    "ARCH-N2": { url: "https://learn.microsoft.com/azure/virtual-network/nat-gateway/nat-overview", ref: "Azure CAF REL-10 NAT Gateway" },
    "ARCH-N3": { url: "https://learn.microsoft.com/azure/architecture/framework/reliability/fault-tolerance", ref: "Azure CAF REL-10" },
    "ARCH-N5": { url: "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview", ref: "Azure CAF SEC05-BP02" },
    "ARCH-C1": { url: "https://learn.microsoft.com/azure/virtual-machines/overview", ref: "Azure CAF SEC05-BP01 VM" },
    "ARCH-C2": { url: "https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview", ref: "Azure CAF SEC08-BP02 Disk Encryption" },
    "ARCH-C3": { url: "https://learn.microsoft.com/azure/azure-functions/functions-networking-options", ref: "Function App VNet Integration" },
    "ARCH-D1": { url: "https://learn.microsoft.com/azure/azure-sql/database/security-best-practice", ref: "Azure CAF SEC05-BP01 SQL" },
    "ARCH-D2": { url: "https://learn.microsoft.com/azure/azure-sql/database/high-availability-sla", ref: "Azure CAF REL-09 SQL HA" },
    "ARCH-D3": { url: "https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview", ref: "Azure CAF SEC08-BP02 SQL Encryption" },
    "ARCH-D4": { url: "https://learn.microsoft.com/azure/azure-cache-for-redis/cache-high-availability", ref: "Azure CAF REL-09 Redis HA" },
    "ARCH-D5": { url: "https://learn.microsoft.com/azure/synapse-analytics/security/synapse-workspace-encryption", ref: "Azure CAF SEC08-BP02 Synapse Encryption" },
    "ARCH-S1": { url: "https://learn.microsoft.com/azure/storage/common/storage-service-encryption", ref: "Azure CAF SEC08-BP02 Storage Encryption" },
    "ARCH-S2": { url: "https://learn.microsoft.com/azure/virtual-machines/disks-enable-bursting", ref: "Azure CAF REL-09 Disk Snapshots" },
    "ARCH-E1": { url: "https://learn.microsoft.com/azure/frontdoor/front-door-overview", ref: "Azure CAF PERF04-BP01 Front Door" },
    "ARCH-G1": { url: "https://learn.microsoft.com/azure/virtual-network/nat-gateway/nat-overview", ref: "Azure CAF REL-10 NAT Gateway" },
    "ARCH-G2": { url: "https://learn.microsoft.com/azure/private-link/private-endpoint-overview", ref: "Azure CAF COST07-BP01 Private Endpoint" },
    "ARCH-X1": { url: "https://learn.microsoft.com/azure/virtual-network/virtual-network-peering-overview", ref: "VNet Peering Routing" },
    "SOC2-CC6.1": { url: "https://learn.microsoft.com/azure/virtual-machines/overview", ref: "SOC2 CC6.1 Logical Access Security" },
    "SOC2-CC6.3": { url: "https://learn.microsoft.com/azure/role-based-access-control/best-practices", ref: "SOC2 CC6.3 RBAC" },
    "SOC2-CC6.6": { url: "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview", ref: "SOC2 CC6.6 Network Boundaries" },
    "SOC2-CC6.7": { url: "https://learn.microsoft.com/azure/virtual-machines/security-policy", ref: "SOC2 CC6.7 Data Transmission" },
    "SOC2-CC6.8": { url: "https://learn.microsoft.com/azure/architecture/framework/security/infrastructure-protection", ref: "SOC2 CC6.8 Malicious Software" },
    "SOC2-CC7.2": { url: "https://learn.microsoft.com/azure/defender-for-cloud/defender-for-cloud-introduction", ref: "SOC2 CC7.2 Monitoring" },
    "SOC2-CC8.1": { url: "https://learn.microsoft.com/azure/governance/policy/overview", ref: "SOC2 CC8.1 Change Management" },
    "SOC2-A1.2": { url: "https://learn.microsoft.com/azure/azure-sql/database/high-availability-sla", ref: "SOC2 A1.2 Availability" },
    "SOC2-A1.3": { url: "https://learn.microsoft.com/azure/backup/backup-overview", ref: "SOC2 A1.3 Recovery" },
    "SOC2-C1.1": { url: "https://learn.microsoft.com/azure/storage/common/storage-service-encryption", ref: "SOC2 C1.1 Confidentiality" },
    "SOC2-C1.2": { url: "https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview", ref: "SOC2 C1.2 Data Protection" },
    "SOC2-PI1.1": { url: "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview", ref: "SOC2 PI1.1 Processing Integrity" },
    "PCI-1.3.1": { url: "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview", ref: "PCI DSS 4.0 Req 1.3.1 Inbound Traffic" },
    "PCI-1.3.2": { url: "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview", ref: "PCI DSS 4.0 Req 1.3.2 Outbound Traffic" },
    "PCI-1.3.4": { url: "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview", ref: "PCI DSS 4.0 Req 1.3.4 Network Segmentation" },
    "PCI-2.2.1": { url: "https://learn.microsoft.com/azure/governance/policy/overview", ref: "PCI DSS 4.0 Req 2.2.1 Configuration Standards" },
    "PCI-3.4.1": { url: "https://learn.microsoft.com/azure/virtual-machines/disk-encryption-overview", ref: "PCI DSS 4.0 Req 3.4.1 Data Encryption" },
    "PCI-3.5.1": { url: "https://learn.microsoft.com/azure/key-vault/general/overview", ref: "PCI DSS 4.0 Req 3.5.1 Key Management" },
    "PCI-4.2.1": { url: "https://learn.microsoft.com/azure/application-gateway/ssl-overview", ref: "PCI DSS 4.0 Req 4.2.1 TLS" },
    "PCI-6.4.1": { url: "https://learn.microsoft.com/azure/web-application-firewall/overview", ref: "PCI DSS 4.0 Req 6.4.1 Web App Firewall" },
    "PCI-7.2.1": { url: "https://learn.microsoft.com/azure/role-based-access-control/best-practices", ref: "PCI DSS 4.0 Req 7.2.1 Least Privilege" },
    "PCI-8.3.1": { url: "https://learn.microsoft.com/azure/active-directory/authentication/concept-mfa-howitworks", ref: "PCI DSS 4.0 Req 8.3.1 MFA" },
    "PCI-10.2.1": { url: "https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-overview", ref: "PCI DSS 4.0 Req 10.2.1 Audit Logging" },
    "PCI-11.3.1": { url: "https://learn.microsoft.com/azure/defender-for-cloud/defender-for-servers-introduction", ref: "PCI DSS 4.0 Req 11.3.1 Vulnerability Scanning" },
    "PCI-12.10.1": { url: "https://learn.microsoft.com/azure/sentinel/overview", ref: "PCI DSS 4.0 Req 12.10.1 Incident Response" },
    "IAM-1": { url: "https://learn.microsoft.com/azure/role-based-access-control/best-practices", ref: "RBAC Best Practices" },
    "IAM-2": { url: "https://learn.microsoft.com/azure/role-based-access-control/best-practices#only-grant-the-access-users-need", ref: "RBAC Least Privilege" },
    "IAM-3": { url: "https://learn.microsoft.com/azure/active-directory/external-identities/what-is-b2b", ref: "Cross-Tenant MFA" },
    "IAM-4": { url: "https://learn.microsoft.com/azure/role-based-access-control/best-practices", ref: "RBAC Service Wildcards" },
    "IAM-5": { url: "https://learn.microsoft.com/azure/active-directory/governance/access-reviews-overview", ref: "Unused RBAC Roles" },
    "IAM-6": { url: "https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview", ref: "Managed Identity Best Practice" },
    "IAM-7": { url: "https://learn.microsoft.com/azure/role-based-access-control/custom-roles", ref: "Custom vs Built-in Roles" },
    "IAM-8": { url: "https://learn.microsoft.com/azure/active-directory/privileged-identity-management/pim-configure", ref: "Privileged Identity Management" },
    "CKV_AZURE_1": { url: "https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service", ref: "Checkov CKV_AZURE_1 - VM IMDS" },
    "CKV_AZURE_2": { url: "https://learn.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview", ref: "Checkov CKV_AZURE_2 - NSG Flow Logs" },
    "CKV_AZURE_3": { url: "https://learn.microsoft.com/azure/storage/blobs/versioning-overview", ref: "Checkov CKV_AZURE_3 - Storage Versioning" },
    "CKV_AZURE_4": { url: "https://learn.microsoft.com/azure/storage/common/storage-analytics-logging", ref: "Checkov CKV_AZURE_4 - Storage Logging" },
    "CKV_AZURE_5": { url: "https://learn.microsoft.com/azure/azure-sql/database/automated-backups-overview", ref: "Checkov CKV_AZURE_5 - SQL Backup Retention" },
    "CKV_AZURE_6": { url: "https://learn.microsoft.com/azure/azure-functions/functions-app-settings", ref: "Checkov CKV_AZURE_6 - Function App Settings" },
    "CKV_AZURE_7": { url: "https://learn.microsoft.com/azure/azure-functions/functions-monitoring", ref: "Checkov CKV_AZURE_7 - Function App Monitoring" },
    "BUDR-HA-1": { url: "https://learn.microsoft.com/azure/azure-sql/database/high-availability-sla", ref: "SQL Server Zone-Redundant Deployments" },
    "BUDR-HA-2": { url: "https://learn.microsoft.com/azure/virtual-machine-scale-sets/overview", ref: "VM Scale Sets" },
    "BUDR-HA-3": { url: "https://learn.microsoft.com/azure/container-instances/container-instances-overview", ref: "Container Instance Scaling" },
    "BUDR-HA-4": { url: "https://learn.microsoft.com/azure/azure-cache-for-redis/cache-high-availability", ref: "Redis Cache Replication" },
    "BUDR-HA-5": { url: "https://learn.microsoft.com/azure/synapse-analytics/sql-data-warehouse/sql-data-warehouse-concept-resource-utilization-query-activity", ref: "Synapse Workspace Management" },
    "BUDR-HA-6": { url: "https://learn.microsoft.com/azure/application-gateway/overview", ref: "App Gateway Availability Zones" },
    "BUDR-BAK-1": { url: "https://learn.microsoft.com/azure/azure-sql/database/automated-backups-overview", ref: "SQL Server Automated Backups" },
    "BUDR-BAK-2": { url: "https://learn.microsoft.com/azure/virtual-machines/disks-enable-bursting", ref: "Managed Disk Snapshots" },
    "BUDR-BAK-3": { url: "https://learn.microsoft.com/azure/azure-cache-for-redis/cache-how-to-premium-persistence", ref: "Redis Cache Persistence" },
    "BUDR-BAK-4": { url: "https://learn.microsoft.com/azure/synapse-analytics/sql-data-warehouse/backup-and-restore", ref: "Synapse Snapshots" },
    "BUDR-BAK-5": { url: "https://learn.microsoft.com/azure/backup/disk-backup-overview", ref: "Disk Snapshot Scheduling" },
    "BUDR-DR-1": { url: "https://learn.microsoft.com/azure/azure-sql/database/active-geo-replication-overview", ref: "SQL Server DR Strategy" },
    "BUDR-DR-2": { url: "https://learn.microsoft.com/azure/site-recovery/azure-to-azure-quickstart", ref: "VM DR Strategy" },
    "BUDR-STG-1": { url: "https://learn.microsoft.com/azure/storage/common/storage-redundancy", ref: "Storage Account Geo-Redundancy" }
  };
  var _compDashState = { sevFilter: "ALL", fwFilter: "all", search: "", sort: "severity", showMuted: false, execSummary: false, view: "action" };
  var _mutedFindings = /* @__PURE__ */ new Set();
  try {
    const raw = localStorage.getItem(MUTE_KEY);
    if (raw) _mutedFindings = new Set(JSON.parse(raw));
  } catch (e) {
  }
  function getCompDashState() {
    return _compDashState;
  }
  function setCompDashState(v) {
    _compDashState = v;
  }
  function getMutedFindings() {
    return _mutedFindings;
  }
  function setMutedFindings(v) {
    _mutedFindings = v;
  }
  function saveMuted() {
    try {
      localStorage.setItem(MUTE_KEY, JSON.stringify([..._mutedFindings]));
    } catch (e) {
    }
  }
  function muteKey(f) {
    return f.control + "::" + f.resource;
  }
  function isMuted(f) {
    return _mutedFindings.has(muteKey(f));
  }
  function toggleMute(f) {
    const k = muteKey(f);
    if (_mutedFindings.has(k)) _mutedFindings.delete(k);
    else _mutedFindings.add(k);
    saveMuted();
  }
  function getEffort(f) {
    return EFFORT_MAP[f.control] || "med";
  }
  function classifyTier(f) {
    const e = getEffort(f), s = f.severity;
    if (s === "CRITICAL") return "crit";
    if (s === "HIGH" && e === "low") return "crit";
    if (s === "HIGH") return "high";
    if (s === "MEDIUM" && e === "low") return "high";
    if (s === "MEDIUM") return "med";
    return "low";
  }
  function groupByResource(findings) {
    const map = {};
    findings.forEach((f) => {
      const k = f.resourceId || f.resource;
      if (!map[k]) map[k] = { resource: f.resource, resourceId: f.resourceId || "", resourceName: f.resourceName || f.resource, findings: [], worstSev: "LOW", worstTier: "low", _accountId: f._accountId };
      const tier = classifyTier(f);
      map[k].findings.push(Object.assign({}, f, { effort: getEffort(f), tier }));
      if ((SEV_ORDER[f.severity] || 9) < (SEV_ORDER[map[k].worstSev] || 9)) map[k].worstSev = f.severity;
      if ((PRIORITY_ORDER[tier] || 9) < (PRIORITY_ORDER[map[k].worstTier] || 9)) map[k].worstTier = tier;
    });
    return Object.values(map).sort((a, b) => {
      if (a.worstTier !== b.worstTier) return (PRIORITY_ORDER[a.worstTier] || 9) - (PRIORITY_ORDER[b.worstTier] || 9);
      return (SEV_ORDER[a.worstSev] || 9) - (SEV_ORDER[b.worstSev] || 9);
    });
  }
  function getTierGroups(findings) {
    const g = { crit: [], high: [], med: [], low: [] };
    groupByResource(findings).forEach((rg) => {
      g[rg.worstTier].push(rg);
    });
    return g;
  }
  function getSeverityGroups(findings) {
    const g = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    groupByResource(findings).forEach((rg) => {
      g[rg.worstSev].push(rg);
    });
    return g;
  }
  function estimateTotalEffort(resourceGroups) {
    var mins = 0;
    resourceGroups.forEach((rg) => {
      rg.findings.forEach((f) => {
        if (f.effort === "low") mins += 5;
        else if (f.effort === "med") mins += 90;
        else mins += 480;
      });
    });
    if (mins < 60) return "~" + mins + " min";
    if (mins < 480) return "~" + Math.round(mins / 60) + " hrs";
    return "~" + Math.round(mins / 480) + " days";
  }
  function calcComplianceScore(findings) {
    const active = findings.filter((f) => !isMuted(f));
    if (!active.length) return { score: 100, grade: "A", color: "#22c55e" };
    const w = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 0.5 };
    const penalty = active.reduce((s, f) => s + (w[f.severity] || 0), 0);
    const maxPenalty = active.length * 10;
    const score = Math.max(0, Math.round(100 - penalty / maxPenalty * 100));
    const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 50 ? "D" : "F";
    const color = score >= 90 ? "#22c55e" : score >= 70 ? "#eab308" : score >= 50 ? "#f97316" : "#ef4444";
    return { score, grade, color };
  }
  function aggregateTopResources(findings, limit) {
    const map = {};
    findings.forEach((f) => {
      const r = f.resourceName || f.resource;
      if (!r || r === "Multiple") return;
      if (!map[r]) map[r] = { count: 0, worst: "LOW", sevs: {} };
      map[r].count++;
      map[r].sevs[f.severity] = (map[r].sevs[f.severity] || 0) + 1;
      if ((SEV_ORDER[f.severity] || 9) < (SEV_ORDER[map[r].worst] || 9)) map[r].worst = f.severity;
    });
    return Object.entries(map).sort((a, b) => {
      const sd = (SEV_ORDER[a[1].worst] || 9) - (SEV_ORDER[b[1].worst] || 9);
      return sd !== 0 ? sd : b[1].count - a[1].count;
    }).slice(0, limit);
  }
  function _rptFilterByAccount(items, acctId) {
    if (typeof window !== "undefined" && window._rptFilterByAccount) {
      return window._rptFilterByAccount(items, acctId);
    }
    if (!acctId || acctId === "all") return items;
    return items.filter((item) => (item._accountId || item.account || "") === acctId);
  }
  function buildComplianceView(opts) {
    opts = opts || {};
    var src = (opts.findings || complianceFindings || []).slice();
    if (opts.accountFilter) src = _rptFilterByAccount(src, opts.accountFilter);
    if (Array.isArray(opts.frameworks)) src = src.filter((f) => opts.frameworks.indexOf(f.framework) !== -1);
    else if (opts.frameworks && opts.frameworks !== "all") src = src.filter((f) => f.framework === opts.frameworks);
    if (Array.isArray(opts.severities)) src = src.filter((f) => opts.severities.indexOf(f.severity) !== -1);
    if (opts.search) {
      var q = opts.search.toLowerCase();
      src = src.filter(
        (f) => (f.message || "").toLowerCase().indexOf(q) !== -1 || (f.resource || "").toLowerCase().indexOf(q) !== -1 || (f.resourceName || "").toLowerCase().indexOf(q) !== -1 || (f.control || "").toLowerCase().indexOf(q) !== -1 || (f.ckv || "").toLowerCase().indexOf(q) !== -1 || (f.remediation || "").toLowerCase().indexOf(q) !== -1
      );
    }
    if (!opts.includeMuted) src = src.filter((f) => !isMuted(f));
    var base = src.map((f) => Object.assign({}, f, { _tier: classifyTier(f), _effort: getEffort(f) }));
    var filtered = typeof opts.severity === "string" && opts.severity !== "ALL" ? base.filter((f) => f.severity === opts.severity) : base;
    var sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    var tierCounts = { crit: 0, high: 0, med: 0, low: 0 };
    base.forEach((f) => {
      sevCounts[f.severity]++;
      tierCounts[f._tier]++;
    });
    var filteredTierCounts = { crit: 0, high: 0, med: 0, low: 0 };
    var filteredSevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    filtered.forEach((f) => {
      filteredTierCounts[f._tier]++;
      filteredSevCounts[f.severity]++;
    });
    var tiers = getTierGroups(filtered);
    var baseTiers = typeof opts.severity === "string" && opts.severity !== "ALL" ? getTierGroups(base) : tiers;
    var sevGroups = getSeverityGroups(filtered);
    return {
      base,
      filtered,
      tiers,
      baseTiers,
      sevGroups,
      sevCounts,
      tierCounts,
      filteredTierCounts,
      filteredSevCounts,
      score: calcComplianceScore(base),
      effort: estimateTotalEffort(groupByResource(base)),
      mutedCount: (complianceFindings || []).filter((f) => isMuted(f)).length
    };
  }
  if (typeof window !== "undefined") {
    window._EFFORT_MAP = EFFORT_MAP;
    window._complianceRefs = complianceRefs;
    window._compDashState = _compDashState;
    window._mutedFindings = _mutedFindings;
    window._saveMuted = saveMuted;
    window._muteKey = muteKey;
    window._isMuted = isMuted;
    window._toggleMute = toggleMute;
    window._getEffort = getEffort;
    window._classifyTier = classifyTier;
    window._groupByResource = groupByResource;
    window._getTierGroups = getTierGroups;
    window._getSeverityGroups = getSeverityGroups;
    window._estimateTotalEffort = estimateTotalEffort;
    window._calcComplianceScore = calcComplianceScore;
    window._aggregateTopResources = aggregateTopResources;
    window._buildComplianceView = buildComplianceView;
  }

  // src/modules/unified-dashboard.js
  var unified_dashboard_exports = {};
  __export(unified_dashboard_exports, {
    BUDR_TIER_META: () => BUDR_TIER_META,
    _BUDR_TIER_META: () => BUDR_TIER_META,
    _budrDashState: () => _budrDashState,
    _udashAcctFilter: () => _udashAcctFilter,
    _udashTab: () => _udashTab,
    getBudrDashState: () => getBudrDashState,
    getUdashAcctFilter: () => getUdashAcctFilter,
    getUdashTab: () => getUdashTab,
    setBudrDashState: () => setBudrDashState,
    setUdashAcctFilter: () => setUdashAcctFilter,
    setUdashTab: () => setUdashTab,
    udashFilterByAccount: () => udashFilterByAccount
  });
  var _udashTab = null;
  var _udashAcctFilter = "all";
  var _budrDashState = { tierFilter: "all", search: "", sort: "tier" };
  var BUDR_TIER_META = {
    protected: { name: "Protected", color: "#10b981", icon: "" },
    partial: { name: "Partially Protected", color: "#f59e0b", icon: "" },
    at_risk: { name: "At Risk", color: "#ef4444", icon: "" }
  };
  function getUdashTab() {
    return _udashTab;
  }
  function setUdashTab(v) {
    _udashTab = v;
  }
  function getUdashAcctFilter() {
    return _udashAcctFilter;
  }
  function setUdashAcctFilter(v) {
    _udashAcctFilter = v;
  }
  function getBudrDashState() {
    return _budrDashState;
  }
  function setBudrDashState(v) {
    _budrDashState = v;
  }
  function udashFilterByAccount(items) {
    if (!_udashAcctFilter || _udashAcctFilter === "all") return items;
    var id = _udashAcctFilter;
    var lbl = typeof window !== "undefined" && typeof window._rptAccountLabel === "function" ? window._rptAccountLabel(id) : "";
    return items.filter(function(item) {
      var a = item._accountId || item.account || "";
      return a === id || a === lbl;
    });
  }
  if (typeof window !== "undefined") {
    window._udashTab = _udashTab;
    window._udashAcctFilter = _udashAcctFilter;
    window._budrDashState = _budrDashState;
    window._BUDR_TIER_META = BUDR_TIER_META;
    window._udashFilterByAccount = udashFilterByAccount;
    window.getUdashTab = getUdashTab;
    window.setUdashTab = setUdashTab;
    window.getUdashAcctFilter = getUdashAcctFilter;
    window.setUdashAcctFilter = setUdashAcctFilter;
  }

  // src/modules/governance.js
  var governance_exports = {};
  __export(governance_exports, {
    _APP_TYPE_SUGGESTIONS: () => _APP_TYPE_SUGGESTIONS,
    _DEFAULT_CLASS_RULES: () => _DEFAULT_CLASS_RULES,
    _INV_NO_MAP_TYPES: () => _INV_NO_MAP_TYPES,
    _INV_TYPE_COLORS: () => _INV_TYPE_COLORS,
    _TIER_RPO_RTO: () => _TIER_RPO_RTO,
    _appAutoDiscovered: () => _appAutoDiscovered,
    _appRegistry: () => _appRegistry,
    _appSummaryState: () => _appSummaryState,
    _buildInventoryData: () => _buildInventoryData,
    _classificationData: () => _classificationData,
    _classificationOverrides: () => _classificationOverrides,
    _classificationRules: () => _classificationRules,
    _collectPermissions: () => _collectPermissions,
    _discoverTagKeys: () => _discoverTagKeys,
    _discoveredTags: () => _discoveredTags,
    _filterInventory: () => _filterInventory,
    _getTagMap: () => _getTagMap,
    _govDashState: () => _govDashState,
    _iamDashState: () => _iamDashState,
    _iamReviewData: () => _iamReviewData,
    _invFilterCache: () => _invFilterCache,
    _invFilterKey: () => _invFilterKey,
    _invState: () => _invState,
    _invToolbarRendered: () => _invToolbarRendered,
    _inventoryData: () => _inventoryData,
    _safeRegex: () => _safeRegex,
    _scoreClassification: () => _scoreClassification,
    canDo: () => canDo,
    getAppAutoDiscovered: () => getAppAutoDiscovered,
    getAppRegistry: () => getAppRegistry,
    getAppSummaryState: () => getAppSummaryState,
    getClassificationData: () => getClassificationData,
    getClassificationOverrides: () => getClassificationOverrides,
    getClassificationRules: () => getClassificationRules,
    getDiscoveredTags: () => getDiscoveredTags,
    getGovDashState: () => getGovDashState,
    getIamDashState: () => getIamDashState,
    getIamReviewData: () => getIamReviewData,
    getInvFilterCache: () => getInvFilterCache,
    getInvFilterKey: () => getInvFilterKey,
    getInvState: () => getInvState,
    getInvToolbarRendered: () => getInvToolbarRendered,
    getInventoryData: () => getInventoryData,
    matchAction: () => matchAction,
    prepareIAMReviewData: () => prepareIAMReviewData,
    runClassificationEngine: () => runClassificationEngine,
    scopeContains: () => scopeContains,
    setAppAutoDiscovered: () => setAppAutoDiscovered,
    setAppRegistry: () => setAppRegistry,
    setAppSummaryState: () => setAppSummaryState,
    setClassificationData: () => setClassificationData,
    setClassificationOverrides: () => setClassificationOverrides,
    setClassificationRules: () => setClassificationRules,
    setDiscoveredTags: () => setDiscoveredTags,
    setGovDashState: () => setGovDashState,
    setIamDashState: () => setIamDashState,
    setIamReviewData: () => setIamReviewData,
    setInvFilterCache: () => setInvFilterCache,
    setInvFilterKey: () => setInvFilterKey,
    setInvState: () => setInvState,
    setInvToolbarRendered: () => setInvToolbarRendered,
    setInventoryData: () => setInventoryData,
    summarizePermissions: () => summarizePermissions
  });
  var _govDashState = { tab: "classification", filter: "all", search: "", sort: "tier", sortDir: "asc", page: 1, perPage: 50 };
  var _iamDashState = { filter: "all", search: "", sort: "name", sortDir: "asc", page: 1, perPage: 50 };
  var _classificationData = [];
  var _classificationOverrides = {};
  var _iamReviewData = [];
  var _inventoryData = [];
  var _invState = { typeFilter: "all", regionFilter: "all", accountFilter: "all", vnetFilter: "all", viewMode: "flat", search: "", sort: "type", sortDir: "asc", page: 1, perPage: 50 };
  var _appRegistry = [];
  var _appAutoDiscovered = false;
  var _appSummaryState = { search: "", sort: "tier", sortDir: "asc", adding: false, editing: -1 };
  var _APP_TYPE_SUGGESTIONS = ["Web App", "Database", "Monitoring", "CI/CD", "Security", "Analytics", "Storage", "Infrastructure"];
  var _invToolbarRendered = false;
  var _INV_TYPE_COLORS = {
    "VNet": "#7C3AED",
    "Subnet": "#6366f1",
    "VM": "#f97316",
    "SQL Server": "#22d3ee",
    "Function App": "#f59e0b",
    "Container Instance": "#10b981",
    "App Gateway": "#ec4899",
    "Redis Cache": "#8b5cf6",
    "Synapse Workspace": "#06b6d4",
    "NSG": "#64748b",
    "UDR": "#64748b",
    "NAT Gateway": "#34d399",
    "Private Endpoint": "#34d399",
    "NIC": "#94a3b8",
    "Managed Disk": "#fb923c",
    "Snapshot": "#a78bfa",
    "Storage Account": "#f472b6",
    "DNS Zone": "#38bdf8",
    "WAF Policy": "#fbbf24",
    "Front Door": "#818cf8",
    "VNet Peering": "#c084fc",
    "VPN Connection": "#2dd4bf",
    "vWAN": "#67e8f9",
    "AKS": "#818cf8",
    "Firewall": "#ef4444",
    "Bastion": "#34d399",
    "Load Balancer": "#3b82f6"
  };
  var _INV_NO_MAP_TYPES = { "Storage Account": 1, "DNS Zone": 1, "WAF Policy": 1, "Front Door": 1, "Snapshot": 1, "vWAN": 1 };
  var _invFilterCache = null;
  var _invFilterKey = "";
  var _DEFAULT_CLASS_RULES = [
    { pattern: "prod|production", scope: "vnet", tier: "critical", weight: 100 },
    { pattern: "pci|complian", scope: "vnet", tier: "critical", weight: 95 },
    { pattern: "dr-|disaster|recovery", scope: "vnet", tier: "critical", weight: 90 },
    { pattern: "hub|transit|shared.?serv|data.?platform|security", scope: "vnet", tier: "high", weight: 80 },
    { pattern: "edge|proxy|waf|firewall", scope: "vnet", tier: "high", weight: 75 },
    { pattern: "staging|stage|qa|uat", scope: "vnet", tier: "medium", weight: 50 },
    { pattern: "management|mgmt|monitor", scope: "vnet", tier: "medium", weight: 45 },
    { pattern: "dev|develop|sandbox|test|experiment", scope: "vnet", tier: "low", weight: 20 },
    { pattern: "sql|database|db|synapse", scope: "type", tier: "critical", weight: 90 },
    { pattern: "redis|cache", scope: "type", tier: "high", weight: 70 },
    { pattern: "app.?gateway|loadbalancer|load.?balancer", scope: "type", tier: "high", weight: 65 },
    { pattern: "function.?app|container|aks|kubernetes", scope: "type", tier: "medium", weight: 40 },
    { pattern: "bastion|jump|ssh", scope: "name", tier: "medium", weight: 35 },
    { pattern: "firewall|azure.?firewall", scope: "type", tier: "high", weight: 75 },
    // Tag-based rules: Environment tag is strongest classification signal
    { pattern: "prod|production|prd", scope: "tag:Environment", tier: "critical", weight: 120 },
    { pattern: "staging|stage|uat|qa", scope: "tag:Environment", tier: "medium", weight: 110 },
    { pattern: "dev|develop|sandbox|test", scope: "tag:Environment", tier: "low", weight: 110 }
  ];
  var _classificationRules = structuredClone(_DEFAULT_CLASS_RULES);
  var _discoveredTags = {};
  var _TIER_RPO_RTO = {
    critical: { rpo: "Hourly", rto: "2-4 hours", priority: 1, color: "#ef4444" },
    high: { rpo: "6 hours", rto: "4-8 hours", priority: 2, color: "#f59e0b" },
    medium: { rpo: "Daily", rto: "12 hours", priority: 3, color: "#22d3ee" },
    low: { rpo: "Weekly", rto: "24 hours", priority: 4, color: "#64748b" }
  };
  function getGovDashState() {
    return _govDashState;
  }
  function setGovDashState(v) {
    _govDashState = v;
  }
  function getIamDashState() {
    return _iamDashState;
  }
  function setIamDashState(v) {
    _iamDashState = v;
  }
  function getClassificationData() {
    return _classificationData;
  }
  function setClassificationData(v) {
    _classificationData = v;
  }
  function getClassificationOverrides() {
    return _classificationOverrides;
  }
  function setClassificationOverrides(v) {
    _classificationOverrides = v;
  }
  function getIamReviewData() {
    return _iamReviewData;
  }
  function setIamReviewData(v) {
    _iamReviewData = v;
  }
  function getInventoryData() {
    return _inventoryData;
  }
  function setInventoryData(v) {
    _inventoryData = v;
  }
  function getInvState() {
    return _invState;
  }
  function setInvState(v) {
    _invState = v;
  }
  function getAppRegistry() {
    return _appRegistry;
  }
  function setAppRegistry(v) {
    _appRegistry = v;
  }
  function getAppAutoDiscovered() {
    return _appAutoDiscovered;
  }
  function setAppAutoDiscovered(v) {
    _appAutoDiscovered = v;
  }
  function getAppSummaryState() {
    return _appSummaryState;
  }
  function setAppSummaryState(v) {
    _appSummaryState = v;
  }
  function getInvToolbarRendered() {
    return _invToolbarRendered;
  }
  function setInvToolbarRendered(v) {
    _invToolbarRendered = v;
  }
  function getInvFilterCache() {
    return _invFilterCache;
  }
  function setInvFilterCache(v) {
    _invFilterCache = v;
  }
  function getInvFilterKey() {
    return _invFilterKey;
  }
  function setInvFilterKey(v) {
    _invFilterKey = v;
  }
  function getClassificationRules() {
    return _classificationRules;
  }
  function setClassificationRules(v) {
    _classificationRules = v;
  }
  function getDiscoveredTags() {
    return _discoveredTags;
  }
  function setDiscoveredTags(v) {
    _discoveredTags = v;
  }
  function _buildInventoryData() {
    _inventoryData = [];
    var ctx = rlCtx;
    if (!ctx) return;
    var rows = [];
    var vnetNameMap = {};
    (ctx.vnets || []).forEach(function(v) {
      vnetNameMap[v.id] = v.name || v.id;
    });
    function tags(obj) {
      var m = {};
      var t = obj.tags || {};
      Object.keys(t).forEach(function(k) {
        m[k] = t[k];
      });
      return m;
    }
    function mkRow(id, type, name, obj, extra) {
      return {
        id,
        type,
        name,
        account: obj._accountLabel || obj._accountId || "",
        region: obj.location || obj._region || "",
        vnetId: extra.vnetId || "",
        vnetName: extra.vnetId ? vnetNameMap[extra.vnetId] || "" : "",
        subnetId: extra.subnetId || "",
        az: extra.az || "",
        state: extra.state || "",
        config: extra.config || "",
        tags: tags(obj),
        encrypted: extra.encrypted != null ? extra.encrypted : null,
        nsgCount: extra.nsgCount || 0,
        classificationTier: null,
        budrTier: null,
        budrStrategy: null,
        rto: null,
        rpo: null,
        compliancePass: 0,
        complianceFail: 0,
        _raw: obj,
        _related: extra.related || []
      };
    }
    var subVnetMap = {};
    (ctx.subnets || []).forEach(function(s) {
      if (s.id) subVnetMap[s.id] = s.properties && s.properties.vnetId || "";
    });
    var vmVnetMap = {};
    (ctx.vms || []).forEach(function(i) {
      if (i.id) vmVnetMap[i.id] = i.properties && i.properties.vnetId || subVnetMap[i.properties && i.properties.subnetId] || "";
    });
    (ctx.vnets || []).forEach(function(v) {
      var prefixes = (v.properties && v.properties.addressSpace && v.properties.addressSpace.addressPrefixes || []).join(", ");
      rows.push(mkRow(v.id, "VNet", v.name || v.id, v, { vnetId: v.id, config: prefixes, state: v.properties && v.properties.provisioningState || "" }));
    });
    (ctx.subnets || []).forEach(function(s) {
      var prefix = s.properties && s.properties.addressPrefix || "";
      rows.push(mkRow(s.id, "Subnet", s.name || s.id, s, { vnetId: s.properties && s.properties.vnetId || "", config: prefix, state: s.properties && s.properties.provisioningState || "" }));
    });
    (ctx.vms || []).forEach(function(i) {
      var nsgs = [i.properties && i.properties.nsgId].filter(Boolean);
      rows.push(mkRow(i.id, "VM", i.name || i.id, i, { vnetId: i.properties && i.properties.vnetId || subVnetMap[i.properties && i.properties.subnetId] || "", subnetId: i.properties && i.properties.subnetId || "", az: i.location || "", config: i.properties && i.properties.hardwareProfile && i.properties.hardwareProfile.vmSize || "", state: i.properties && i.properties.provisioningState || "", nsgCount: nsgs.length, related: nsgs }));
    });
    (ctx.sqlServers || []).forEach(function(db) {
      rows.push(mkRow(db.id, "SQL Server", db.name || db.id, db, { vnetId: db.properties && db.properties.vnetId || "", config: db.properties && db.properties.version || "", state: db.properties && db.properties.state || "", encrypted: !!(db.properties && db.properties.storageEncrypted) }));
    });
    (ctx.functionApps || []).forEach(function(fn) {
      var vnetId = fn.properties && fn.properties.vnetId || "";
      var subId = fn.properties && fn.properties.subnetId || "";
      rows.push(mkRow(fn.id, "Function App", fn.name || fn.id, fn, { vnetId, subnetId: subId, config: fn.properties && fn.properties.siteConfig && fn.properties.siteConfig.linuxFxVersion || "", state: fn.properties && fn.properties.state || "Active" }));
    });
    (ctx.containerInstances || []).forEach(function(ci) {
      var subId = ci.properties && ci.properties.subnetId || "";
      var vnetId = subVnetMap[subId] || "";
      var ctCount = (ci.properties && ci.properties.containers || []).length;
      rows.push(mkRow(ci.id, "Container Instance", ci.name || ci.id, ci, { vnetId, subnetId: subId, config: ctCount + " container(s)", state: ci.properties && ci.properties.provisioningState || "" }));
    });
    (ctx.appGateways || []).forEach(function(a) {
      rows.push(mkRow(a.id, "App Gateway", a.name || a.id, a, { vnetId: a.properties && a.properties.vnetId || "", config: a.properties && a.properties.sku && a.properties.sku.name || "", state: a.properties && a.properties.provisioningState || "" }));
    });
    (ctx.redisCaches || []).forEach(function(rc) {
      rows.push(mkRow(rc.id, "Redis Cache", rc.name || rc.id, rc, { vnetId: rc.properties && rc.properties.vnetId || "", config: rc.properties && rc.properties.sku && rc.properties.sku.name || "", state: rc.properties && rc.properties.provisioningState || "" }));
    });
    (ctx.synapseWorkspaces || []).forEach(function(sw) {
      rows.push(mkRow(sw.id, "Synapse Workspace", sw.name || sw.id, sw, { vnetId: "", config: sw.properties && sw.properties.sqlAdministratorLogin || "", state: sw.properties && sw.properties.provisioningState || "", encrypted: !!(sw.properties && sw.properties.encryption) }));
    });
    (ctx.nsgs || []).forEach(function(sg) {
      var rules = sg.properties && sg.properties.securityRules || [];
      var inCt = rules.filter(function(r) {
        return r.properties && r.properties.direction === "Inbound";
      }).length;
      var outCt = rules.filter(function(r) {
        return r.properties && r.properties.direction === "Outbound";
      }).length;
      rows.push(mkRow(sg.id, "NSG", sg.name || sg.id, sg, { vnetId: sg.properties && sg.properties.vnetId || "", config: inCt + " inbound / " + outCt + " outbound" }));
    });
    (ctx.udrs || []).forEach(function(rt) {
      var ct = (rt.properties && rt.properties.routes || []).length;
      rows.push(mkRow(rt.id, "UDR", rt.name || rt.id, rt, { vnetId: rt.properties && rt.properties.vnetId || "", config: ct + " routes" }));
    });
    (ctx.natGateways || []).forEach(function(n) {
      var subs = (n.properties && n.properties.subnets || []).map(function(s) {
        return s.id;
      });
      var vnetId = subs.length ? subVnetMap[subs[0]] || "" : "";
      rows.push(mkRow(n.id, "NAT Gateway", n.name || n.id, n, { vnetId, config: subs.length + " subnet(s)", state: n.properties && n.properties.provisioningState || "" }));
    });
    (ctx.privateEndpoints || []).forEach(function(e) {
      var subId = e.properties && e.properties.subnetId || "";
      rows.push(mkRow(e.id, "Private Endpoint", e.name || e.id, e, { vnetId: e.properties && e.properties.vnetId || subVnetMap[subId] || "", subnetId: subId, config: e.properties && e.properties.privateLinkServiceConnections && e.properties.privateLinkServiceConnections[0] && e.properties.privateLinkServiceConnections[0].properties && e.properties.privateLinkServiceConnections[0].properties.privateLinkServiceId || "", state: e.properties && e.properties.provisioningState || "" }));
    });
    (ctx.nics || []).forEach(function(e) {
      var subId = e.properties && e.properties.ipConfigurations && e.properties.ipConfigurations[0] && e.properties.ipConfigurations[0].properties && e.properties.ipConfigurations[0].properties.subnetId || "";
      rows.push(mkRow(e.id, "NIC", e.name || e.id, e, { vnetId: subVnetMap[subId] || "", subnetId: subId, config: e.properties && e.properties.ipConfigurations && e.properties.ipConfigurations[0] && e.properties.ipConfigurations[0].properties && e.properties.ipConfigurations[0].properties.privateIPAddress || "", state: e.properties && e.properties.provisioningState || "" }));
    });
    (ctx.disks || []).forEach(function(vol) {
      var attVmId = vol.managedBy || "";
      var vnetId = attVmId ? vmVnetMap[attVmId] || "" : "";
      rows.push(mkRow(vol.id, "Managed Disk", vol.name || vol.id, vol, { vnetId, az: vol.location || "", config: (vol.properties && vol.properties.diskSizeGB || "") + "GB " + (vol.properties && vol.properties.sku && vol.properties.sku.name || ""), state: vol.properties && vol.properties.diskState || "", encrypted: !!(vol.properties && vol.properties.encryption && vol.properties.encryption.type), related: attVmId ? [attVmId] : [] }));
    });
    (ctx.snapshots || []).forEach(function(snap) {
      rows.push(mkRow(snap.id, "Snapshot", snap.name || snap.id, snap, { config: (snap.properties && snap.properties.diskSizeGB || "") + "GB", state: snap.properties && snap.properties.diskState || "", encrypted: !!(snap.properties && snap.properties.encryption && snap.properties.encryption.type) }));
    });
    (ctx.storageAccounts || []).forEach(function(b) {
      rows.push(mkRow(b.id, "Storage Account", b.name || b.id, b, { config: b.properties && b.properties.sku && b.properties.sku.name || b.sku && b.sku.name || "" }));
    });
    (ctx.dnsZones || []).forEach(function(z) {
      var recs = ctx.dnsRecords && ctx.dnsRecords[z.id] ? ctx.dnsRecords[z.id].length : z.properties && z.properties.numberOfRecordSets || 0;
      var vis = z.properties && z.properties.zoneType || "Public";
      rows.push(mkRow(z.id, "DNS Zone", z.name || z.id, z, { config: recs + " records " + vis.toLowerCase() }));
    });
    (ctx.wafPolicies || []).forEach(function(w) {
      var ruleCount = (w.properties && w.properties.customRules && w.properties.customRules.rules || []).length;
      rows.push(mkRow(w.id, "WAF Policy", w.name || w.id, w, { config: ruleCount + " custom rules" }));
    });
    (ctx.frontDoors || []).forEach(function(fd) {
      rows.push(mkRow(fd.id, "Front Door", fd.name || fd.id, fd, { config: fd.properties && fd.properties.resourceState || "", state: fd.properties && fd.properties.provisioningState || "" }));
    });
    (ctx.peerings || []).forEach(function(p) {
      var local = p.properties && p.properties.localVnetId || "";
      var remote = p.properties && p.properties.remoteVnetId || "";
      rows.push(mkRow(p.id, "VNet Peering", p.name || p.id, p, { vnetId: local, config: (local ? vnetNameMap[local] || local : "") + "\u2194" + (remote ? vnetNameMap[remote] || remote : ""), state: p.properties && p.properties.peeringState || "" }));
    });
    (ctx.vpnConnections || []).forEach(function(v) {
      rows.push(mkRow(v.id, "VPN Connection", v.name || v.id, v, { config: (v.properties && v.properties.connectionType || "") + " " + (v.properties && v.properties.connectionStatus || ""), state: v.properties && v.properties.connectionStatus || "" }));
    });
    (ctx.vwans || []).forEach(function(t) {
      rows.push(mkRow(t.id, "vWAN", t.name || t.id, t, { config: t.properties && t.properties.type || "", state: t.properties && t.properties.provisioningState || "" }));
    });
    (ctx.aksCluster || []).forEach(function(k) {
      rows.push(mkRow(k.id, "AKS", k.name || k.id, k, { vnetId: k.properties && k.properties.agentPoolProfiles && k.properties.agentPoolProfiles[0] && k.properties.agentPoolProfiles[0].vnetSubnetID && subVnetMap[k.properties.agentPoolProfiles[0].vnetSubnetID] || "", config: k.properties && k.properties.kubernetesVersion || "", state: k.properties && k.properties.provisioningState || "" }));
    });
    (ctx.firewalls || []).forEach(function(fw) {
      rows.push(mkRow(fw.id, "Firewall", fw.name || fw.id, fw, { vnetId: fw.properties && fw.properties.vnetId || "", config: fw.properties && fw.properties.sku && fw.properties.sku.name || "", state: fw.properties && fw.properties.provisioningState || "" }));
    });
    (ctx.bastions || []).forEach(function(b) {
      rows.push(mkRow(b.id, "Bastion", b.name || b.id, b, { vnetId: b.properties && b.properties.vnetId || "", config: b.properties && b.properties.sku && b.properties.sku.name || "", state: b.properties && b.properties.provisioningState || "" }));
    });
    (ctx.loadBalancers || []).forEach(function(lb) {
      rows.push(mkRow(lb.id, "Load Balancer", lb.name || lb.id, lb, { vnetId: lb.properties && lb.properties.vnetId || "", config: lb.sku && lb.sku.name || "", state: lb.properties && lb.properties.provisioningState || "" }));
    });
    var classMap = {};
    (_classificationData || []).forEach(function(c) {
      classMap[c.id] = c;
    });
    var budrAssessments2 = typeof window !== "undefined" && window._budrAssessments || [];
    var budrMap = {};
    (budrAssessments2 || []).forEach(function(a) {
      budrMap[a.id] = { tier: a.profile ? a.profile.tier : null, strategy: a.profile ? a.profile.strategy : null, rto: a.profile ? a.profile.rto : null, rpo: a.profile ? a.profile.rpo : null };
    });
    var compMap = {};
    (complianceFindings || []).forEach(function(f) {
      if (!f.resource) return;
      if (!compMap[f.resource]) compMap[f.resource] = { pass: 0, fail: 0 };
      if (f.status === "PASS") compMap[f.resource].pass++;
      else compMap[f.resource].fail++;
    });
    rows.forEach(function(r) {
      var cls = classMap[r.id];
      if (cls) r.classificationTier = cls.tier;
      var budr = budrMap[r.id];
      if (budr) {
        r.budrTier = budr.tier;
        r.budrStrategy = budr.strategy;
        r.rto = budr.rto;
        r.rpo = budr.rpo;
      }
      var comp = compMap[r.id];
      if (comp) {
        r.compliancePass = comp.pass;
        r.complianceFail = comp.fail;
      }
    });
    _inventoryData = rows;
  }
  function _filterInventory() {
    var st = _invState;
    var filterFn = typeof window !== "undefined" && window._udashFilterByAccount || function(x) {
      return x;
    };
    var items = filterFn(_inventoryData).slice();
    if (st.typeFilter !== "all") items = items.filter(function(r) {
      return r.type === st.typeFilter;
    });
    if (st.regionFilter !== "all") items = items.filter(function(r) {
      return r.region === st.regionFilter;
    });
    if (st.accountFilter !== "all") items = items.filter(function(r) {
      return r.account === st.accountFilter;
    });
    if (st.vnetFilter !== "all") items = items.filter(function(r) {
      return r.vnetId === st.vnetFilter;
    });
    if (st.search) {
      var q = st.search.toLowerCase();
      items = items.filter(function(r) {
        return (r.name || "").toLowerCase().indexOf(q) !== -1 || (r.id || "").toLowerCase().indexOf(q) !== -1 || (r.type || "").toLowerCase().indexOf(q) !== -1 || (r.config || "").toLowerCase().indexOf(q) !== -1 || (r.vnetName || "").toLowerCase().indexOf(q) !== -1 || (r.region || "").toLowerCase().indexOf(q) !== -1 || JSON.stringify(r.tags || {}).toLowerCase().indexOf(q) !== -1;
      });
    }
    var sortKey = st.sort;
    var dir = st.sortDir === "asc" ? 1 : -1;
    items.sort(function(a, b) {
      if (sortKey === "complianceFail") {
        return ((a.complianceFail || 0) - (b.complianceFail || 0)) * dir;
      }
      if (sortKey === "tags") {
        return (Object.keys(a.tags || {}).length - Object.keys(b.tags || {}).length) * dir;
      }
      var av = (a[sortKey] || "").toString().toLowerCase();
      var bv = (b[sortKey] || "").toString().toLowerCase();
      return av < bv ? -dir : av > bv ? dir : 0;
    });
    return items;
  }
  function _getTagMap(obj) {
    var src = obj.tags || {};
    var m = {};
    Object.keys(src).forEach(function(k) {
      m[k] = src[k] || "";
    });
    return m;
  }
  function _safeRegex(pattern) {
    try {
      var re = new RegExp(pattern, "i");
      if (/(\+|\*|\{)\s*\)(\+|\*|\{)/.test(pattern)) return null;
      return re;
    } catch (e) {
      return null;
    }
  }
  function _scoreClassification(name, type, vnetName, rules, tagMap) {
    rules = rules || _classificationRules;
    tagMap = tagMap || {};
    var bestTier = "low";
    var bestWeight = -1;
    rules.forEach(function(rule) {
      if (rule.enabled === false) return;
      var p = rule.pattern;
      if (!p) return;
      p = p.replace(/^\|+|\|+$/g, "").replace(/\|{2,}/g, "|");
      if (!p) return;
      var re = _safeRegex(p);
      if (!re) return;
      var text = "";
      if (rule.scope === "any") text = (name || "") + " " + (type || "") + " " + (vnetName || "") + " " + Object.values(tagMap).join(" ");
      else if (rule.scope === "vnet") text = vnetName || "";
      else if (rule.scope === "type") text = type || "";
      else if (rule.scope === "name") text = name || "";
      else if (rule.scope.indexOf("tag:") === 0) text = tagMap[rule.scope.substring(4)] || "";
      else text = (name || "") + " " + (type || "") + " " + (vnetName || "");
      if (re.test(text) && rule.weight > bestWeight) {
        bestWeight = rule.weight;
        bestTier = rule.tier;
      }
    });
    return { tier: bestTier, weight: bestWeight };
  }
  function _discoverTagKeys(ctx) {
    if (!ctx) return {};
    var disc = {};
    function scan(arr, typeName) {
      (arr || []).forEach(function(obj) {
        var tagObj = obj.tags || {};
        Object.keys(tagObj).forEach(function(k) {
          if (!k || k.indexOf("microsoft:") === 0) return;
          if (!disc[k]) disc[k] = { count: 0, samples: [], types: {} };
          var d = disc[k];
          d.count++;
          d.types[typeName] = true;
          var val = tagObj[k];
          if (d.samples.length < 5 && val && d.samples.indexOf(val) < 0) d.samples.push(val);
        });
      });
    }
    scan(ctx.vms, "VM");
    scan(ctx.sqlServers, "SQL Server");
    scan(ctx.redisCaches, "Redis Cache");
    scan(ctx.appGateways, "App Gateway");
    scan(ctx.functionApps, "Function App");
    scan(ctx.containerInstances, "Container Instance");
    scan(ctx.synapseWorkspaces, "Synapse Workspace");
    scan(ctx.vnets, "VNet");
    scan(ctx.subnets, "Subnet");
    scan(ctx.nsgs, "NSG");
    scan(ctx.storageAccounts, "Storage Account");
    scan(ctx.aksCluster, "AKS");
    scan(ctx.firewalls, "Firewall");
    scan(ctx.bastions, "Bastion");
    scan(ctx.loadBalancers, "Load Balancer");
    Object.keys(disc).forEach(function(k) {
      disc[k].types = Object.keys(disc[k].types);
    });
    return disc;
  }
  function runClassificationEngine(ctx) {
    if (!ctx) return [];
    var results = [];
    var vnetNameMap = {};
    (ctx.vnets || []).forEach(function(v) {
      vnetNameMap[v.id] = v.name || v.id;
    });
    var subnetVnetMap = {};
    (ctx.subnets || []).forEach(function(s) {
      if (s.id && s.properties && s.properties.vnetId) subnetVnetMap[s.id] = s.properties.vnetId;
    });
    function resolveVnet(vnetId, subnetId) {
      return vnetId || subnetVnetMap[subnetId] || "";
    }
    (ctx.vms || []).forEach(function(inst) {
      var id = inst.id;
      var name = inst.name || id;
      var vnetId = resolveVnet(inst.properties && inst.properties.vnetId || "", inst.properties && inst.properties.subnetId || "");
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(inst);
      var sc = _scoreClassification(name, "vm", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "VM", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.sqlServers || []).forEach(function(db) {
      var id = db.id;
      var name = db.name || id;
      var vnetId = db.properties && db.properties.vnetId || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(db);
      var sc = _scoreClassification(name, "sql", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "SQL Server", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.redisCaches || []).forEach(function(rc) {
      var id = rc.id;
      var name = rc.name || id;
      var vnetId = rc.properties && rc.properties.vnetId || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(rc);
      var sc = _scoreClassification(name, "redis", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Redis Cache", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.appGateways || []).forEach(function(agw) {
      var id = agw.id;
      var name = agw.name || id;
      var vnetId = agw.properties && agw.properties.vnetId || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(agw);
      var sc = _scoreClassification(name, "app-gateway", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "App Gateway", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.functionApps || []).forEach(function(fn) {
      var id = fn.id;
      var name = fn.name || id;
      var vnetId = resolveVnet(fn.properties && fn.properties.vnetId || "", fn.properties && fn.properties.subnetId || "");
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(fn);
      var sc = _scoreClassification(name, "function-app", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Function App", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.containerInstances || []).forEach(function(ci) {
      var id = ci.id;
      var name = ci.name || id;
      var subId = ci.properties && ci.properties.subnetId || "";
      var vnetId = resolveVnet("", subId);
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(ci);
      var sc = _scoreClassification(name, "container", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Container Instance", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.synapseWorkspaces || []).forEach(function(sw) {
      var id = sw.id;
      var name = sw.name || id;
      var tm = _getTagMap(sw);
      var sc = _scoreClassification(name, "synapse", "", null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Synapse Workspace", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: "", vnetName: "", tags: tm });
    });
    (ctx.nsgs || []).forEach(function(sg) {
      var id = sg.id;
      var name = sg.name || id;
      var vnetId = sg.properties && sg.properties.vnetId || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(sg);
      var sc = _scoreClassification(name, "nsg", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "NSG", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.vnets || []).forEach(function(v) {
      var id = v.id;
      var name = v.name || id;
      var tm = _getTagMap(v);
      var sc = _scoreClassification(name, "vnet", name, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "VNet", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: id, vnetName: name, tags: tm });
    });
    (ctx.subnets || []).forEach(function(s) {
      var id = s.id;
      var name = s.name || id;
      var vnetId = s.properties && s.properties.vnetId || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(s);
      var sc = _scoreClassification(name, "subnet", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Subnet", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.natGateways || []).forEach(function(ng) {
      var id = ng.id;
      var name = ng.name || id;
      var subs = ng.properties && ng.properties.subnets || [];
      var firstSub = subs.length ? subs[0].id || subs[0] : "";
      var vnetId = subnetVnetMap[firstSub] || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(ng);
      var sc = _scoreClassification(name, "nat-gateway", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "NAT Gateway", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.privateEndpoints || []).forEach(function(pe) {
      var id = pe.id;
      var name = pe.name || id;
      var subId = pe.properties && pe.properties.subnetId || "";
      var vnetId = pe.properties && pe.properties.vnetId || subnetVnetMap[subId] || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(pe);
      var sc = _scoreClassification(name, "private-endpoint", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Private Endpoint", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.storageAccounts || []).forEach(function(b) {
      var id = b.id;
      var name = b.name || id;
      var tm = _getTagMap(b);
      var sc = _scoreClassification(name, "storage", "", null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Storage Account", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId: "", vnetName: "", tags: tm });
    });
    (ctx.aksCluster || []).forEach(function(k) {
      var id = k.id;
      var name = k.name || id;
      var subId = k.properties && k.properties.agentPoolProfiles && k.properties.agentPoolProfiles[0] && k.properties.agentPoolProfiles[0].vnetSubnetID || "";
      var vnetId = subnetVnetMap[subId] || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(k);
      var sc = _scoreClassification(name, "aks", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "AKS", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.firewalls || []).forEach(function(fw) {
      var id = fw.id;
      var name = fw.name || id;
      var vnetId = fw.properties && fw.properties.vnetId || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(fw);
      var sc = _scoreClassification(name, "firewall", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Firewall", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.bastions || []).forEach(function(b) {
      var id = b.id;
      var name = b.name || id;
      var vnetId = b.properties && b.properties.vnetId || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(b);
      var sc = _scoreClassification(name, "bastion", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Bastion", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    (ctx.loadBalancers || []).forEach(function(lb) {
      var id = lb.id;
      var name = lb.name || id;
      var vnetId = lb.properties && lb.properties.vnetId || "";
      var vnetName = vnetNameMap[vnetId] || "";
      var tm = _getTagMap(lb);
      var sc = _scoreClassification(name, "load-balancer", vnetName, null, tm);
      var tier = _classificationOverrides[id] || sc.tier;
      var meta = _TIER_RPO_RTO[tier];
      results.push({ id, name, type: "Load Balancer", tier, rpo: meta.rpo, rto: meta.rto, auto: !_classificationOverrides[id], vnetId, vnetName, tags: tm });
    });
    var _clResAcct = {};
    (ctx.vms || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.sqlServers || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.redisCaches || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.appGateways || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.functionApps || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.containerInstances || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.nsgs || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.vnets || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.subnets || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.storageAccounts || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.aksCluster || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.firewalls || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.bastions || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    (ctx.loadBalancers || []).forEach(function(r) {
      _clResAcct[r.id] = r._accountId;
    });
    results.forEach(function(r) {
      if (_clResAcct[r.id]) r._accountId = _clResAcct[r.id];
    });
    _classificationData = results;
    _discoveredTags = _discoverTagKeys(ctx);
    return results;
  }
  function prepareIAMReviewData(rbacData) {
    if (!rbacData) return [];
    var items = [];
    var assignments = rbacData.roleAssignments || [];
    var definitions = rbacData.roleDefinitions || [];
    var defMap = {};
    definitions.forEach(function(d) {
      defMap[d.id || d.name] = d;
    });
    var OWNER_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
    var CONTRIBUTOR_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c";
    var byPrincipal = {};
    assignments.forEach(function(a) {
      var pid = a.properties?.principalId || a.principalId || "";
      if (!byPrincipal[pid]) byPrincipal[pid] = { assignments: [], principalType: a.properties?.principalType || a.principalType || "Unknown", principalId: pid };
      byPrincipal[pid].assignments.push(a);
    });
    Object.values(byPrincipal).forEach(function(principal) {
      var roleNames = [];
      var isAdmin = false;
      var hasWildcard = false;
      var scopes = [];
      var crossTenants = [];
      principal.assignments.forEach(function(a) {
        var roleDefId = a.properties?.roleDefinitionId || a.roleDefinitionId || "";
        var roleId = roleDefId.split("/").pop();
        var def = defMap[roleDefId] || defMap[roleId];
        var roleName = def?.properties?.roleName || def?.roleName || roleId;
        roleNames.push(roleName);
        var scope = a.properties?.scope || a.scope || "";
        scopes.push(scope);
        var scopeLevel = getScopeLevel(scope);
        if (roleId === OWNER_ID && (scopeLevel === "subscription" || scopeLevel === "managementGroup")) isAdmin = true;
        if (def) {
          var perms = def.properties?.permissions || def.permissions || [];
          perms.forEach(function(p) {
            if ((p.actions || []).includes("*")) hasWildcard = true;
          });
        }
        if (a._isLighthouse || a.properties?._isLighthouse) crossTenants.push(a._tenantId || "");
      });
      var findings = (complianceFindings || []).filter(function(f) {
        return f.framework === "RBAC" && f.resource === principal.principalId;
      });
      items.push({
        name: principal.principalId,
        // Azure doesn't always include display name in assignment data
        arn: principal.principalId,
        // Keep 'arn' field for backward compat with UI
        type: principal.principalType || "Unknown",
        created: null,
        lastUsed: null,
        isAdmin,
        hasWildcard,
        crossAccounts: crossTenants,
        policies: principal.assignments.length,
        policyNames: roleNames,
        permBoundary: "",
        findings,
        _subscriptionId: (scopes[0] || "").split("/")[2] || "",
        _raw: principal
      });
    });
    _iamReviewData = items;
    return items;
  }
  function matchAction(pattern, action) {
    if (!pattern || !action) return false;
    if (pattern === "*") return true;
    const re = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i");
    return re.test(action);
  }
  function scopeContains(parentScope, childScope) {
    if (!parentScope || !childScope) return false;
    if (parentScope === "/") return true;
    return childScope.toLowerCase().startsWith(parentScope.toLowerCase());
  }
  function _collectPermissions(principalId, rbacData) {
    const result = { actions: [], notActions: [], dataActions: [], notDataActions: [], scopes: [] };
    const assignments = (rbacData.roleAssignments || []).filter((a) => (a.properties?.principalId || a.principalId) === principalId);
    const defMap = {};
    (rbacData.roleDefinitions || []).forEach((d) => {
      defMap[d.id || d.name] = d;
    });
    assignments.forEach((a) => {
      const roleDefId = a.properties?.roleDefinitionId || a.roleDefinitionId || "";
      const def = defMap[roleDefId] || defMap[roleDefId.split("/").pop()];
      const scope = a.properties?.scope || a.scope || "";
      result.scopes.push(scope);
      if (def) {
        (def.properties?.permissions || def.permissions || []).forEach((p) => {
          result.actions.push(...p.actions || []);
          result.notActions.push(...p.notActions || []);
          result.dataActions.push(...p.dataActions || []);
          result.notDataActions.push(...p.notDataActions || []);
        });
      }
    });
    return result;
  }
  function canDo(principalId, action, resourceScope, rbacData) {
    const perms = _collectPermissions(principalId, rbacData);
    const coveredScopes = perms.scopes.filter((s) => scopeContains(s, resourceScope));
    if (!coveredScopes.length) return { effect: "IMPLICIT_DENY", reason: "No role assignment at this scope" };
    if (perms.notActions.some((na) => matchAction(na, action))) {
      return { effect: "DENY", reason: "Action excluded by notActions" };
    }
    if (perms.actions.some((a) => matchAction(a, action))) {
      return { effect: "ALLOW", reason: "Allowed by role assignment" };
    }
    return { effect: "IMPLICIT_DENY", reason: "No matching action in assigned roles" };
  }
  function summarizePermissions(principalId, rbacData) {
    const perms = _collectPermissions(principalId, rbacData);
    const services = {};
    let isAdmin = false;
    let hasWildcard = false;
    perms.actions.forEach((a) => {
      if (a === "*") {
        isAdmin = true;
        hasWildcard = true;
        return;
      }
      const parts = a.split("/");
      const provider = parts[0] || "ALL";
      if (!services[provider]) services[provider] = { allowed: [], denied: [] };
      const actionName = parts.slice(1).join("/");
      if (!services[provider].allowed.includes(actionName)) services[provider].allowed.push(actionName);
      if (a.includes("*")) hasWildcard = true;
    });
    perms.notActions.forEach((a) => {
      const parts = a.split("/");
      const provider = parts[0] || "ALL";
      if (!services[provider]) services[provider] = { allowed: [], denied: [] };
      const actionName = parts.slice(1).join("/");
      if (!services[provider].denied.includes(actionName)) services[provider].denied.push(actionName);
    });
    return { services, isAdmin, hasWildcard, permissionBoundary: null };
  }
  if (typeof window !== "undefined") {
    Object.assign(window, {
      // State variables: direct references (for backward compat reading)
      _govDashState,
      _iamDashState,
      _classificationData,
      _classificationOverrides,
      _iamReviewData,
      _inventoryData,
      _invState,
      _appRegistry,
      _appAutoDiscovered,
      _appSummaryState,
      _APP_TYPE_SUGGESTIONS,
      _invToolbarRendered,
      _INV_TYPE_COLORS,
      _INV_NO_MAP_TYPES,
      _invFilterCache,
      _invFilterKey,
      _DEFAULT_CLASS_RULES,
      _classificationRules,
      _discoveredTags,
      _TIER_RPO_RTO,
      // State accessors
      getGovDashState,
      setGovDashState,
      getIamDashState,
      setIamDashState,
      getClassificationData,
      setClassificationData,
      getClassificationOverrides,
      setClassificationOverrides,
      getIamReviewData,
      setIamReviewData,
      getInventoryData,
      setInventoryData,
      getInvState,
      setInvState,
      getAppRegistry,
      setAppRegistry,
      getAppAutoDiscovered,
      setAppAutoDiscovered,
      getAppSummaryState,
      setAppSummaryState,
      getInvToolbarRendered,
      setInvToolbarRendered,
      getInvFilterCache,
      setInvFilterCache,
      getInvFilterKey,
      setInvFilterKey,
      getClassificationRules,
      setClassificationRules,
      getDiscoveredTags,
      setDiscoveredTags,
      // Pure logic functions
      _buildInventoryData,
      _filterInventory,
      _getTagMap,
      _safeRegex,
      _scoreClassification,
      _discoverTagKeys,
      runClassificationEngine,
      prepareIAMReviewData,
      matchAction,
      scopeContains,
      _collectPermissions,
      canDo,
      summarizePermissions
    });
  }

  // src/modules/export-utils.js
  var export_utils_exports = {};
  __export(export_utils_exports, {
    COL_GAP: () => COL_GAP,
    GW_INSIDE_GAP: () => GW_INSIDE_GAP,
    GW_INSIDE_H: () => GW_INSIDE_H,
    GW_INSIDE_W: () => GW_INSIDE_W,
    GW_ROW_H: () => GW_ROW_H,
    LINE_H: () => LINE_H,
    PX: () => PX,
    SUB_GAP: () => SUB_GAP,
    SUB_H_MIN: () => SUB_H_MIN,
    SUB_W: () => SUB_W,
    TOP_MARGIN: () => TOP_MARGIN,
    VNET_HDR: () => VNET_HDR,
    VNET_PAD: () => VNET_PAD,
    addPolyEdge: () => addPolyEdge,
    addRect: () => addRect,
    buildPolyConnector: () => buildPolyConnector,
    buildShape: () => buildShape,
    buildSubText: () => buildSubText,
    buildVsdxXml: () => buildVsdxXml,
    computePageDimensions: () => computePageDimensions,
    computeSubnetHeights: () => computeSubnetHeights,
    downloadBlob: () => downloadBlob,
    getIdMap: () => getIdMap,
    getPolyEdges: () => getPolyEdges,
    getShapes: () => getShapes,
    gwStyles: () => gwStyles,
    resetShapeState: () => resetShapeState,
    resolveColor: () => resolveColor,
    sanitizeName: () => sanitizeName,
    setIdMapEntry: () => setIdMapEntry,
    toIn: () => toIn,
    uid: () => uid,
    xmlEsc: () => xmlEsc
  });
  var PX = 96;
  var SUB_W = 520;
  var SUB_H_MIN = 90;
  var SUB_GAP = 24;
  var VNET_PAD = 50;
  var VNET_HDR = 80;
  var GW_INSIDE_W = 160;
  var GW_INSIDE_H = 50;
  var GW_INSIDE_GAP = 16;
  var GW_ROW_H = 70;
  var COL_GAP = 280;
  var LINE_H = 15;
  var TOP_MARGIN = 80;
  function toIn(px) {
    return px / PX;
  }
  var gwStyles = {
    "FW": { color: "#059669", pattern: 1, label: "Azure Firewall", fill: "#ECFDF5", border: "#059669" },
    "NAT": { color: "#D97706", pattern: 2, label: "NAT Gateway", fill: "#FFFBEB", border: "#D97706" },
    "VHUB": { color: "#2563EB", pattern: 1, label: "Virtual Hub", fill: "#EFF6FF", border: "#2563EB" },
    "VGW": { color: "#7C3AED", pattern: 4, label: "VPN Gateway", fill: "#F5F3FF", border: "#7C3AED" },
    "PCX": { color: "#EA580C", pattern: 2, label: "VNet Peering", fill: "#FFF7ED", border: "#EA580C" },
    "PE": { color: "#0891B2", pattern: 3, label: "Private Endpoint", fill: "#ECFEFF", border: "#0891B2" },
    "BAST": { color: "#0D9488", pattern: 1, label: "Bastion Host", fill: "#F0FDFA", border: "#0D9488" },
    "GW": { color: "#6B7280", pattern: 1, label: "Gateway", fill: "#F9FAFB", border: "#6B7280" }
  };
  var shapeId = 1;
  var shapes = [];
  var polyEdges = [];
  var idMap = {};
  function resetShapeState() {
    shapeId = 1;
    shapes = [];
    polyEdges = [];
    idMap = {};
  }
  function getShapes() {
    return shapes;
  }
  function getPolyEdges() {
    return polyEdges;
  }
  function getIdMap() {
    return idMap;
  }
  function setIdMapEntry(key, value) {
    idMap[key] = value;
  }
  function xmlEsc(s) {
    return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function uid() {
    return "{" + crypto.randomUUID() + "}";
  }
  function sanitizeName(s) {
    if (!s) return "unnamed";
    return s.replace(/[^a-zA-Z0-9_-]/g, "_").replace(/^[0-9]/, "r$&").replace(/-/g, "_").toLowerCase();
  }
  function addRect(x, y, w, h, fill, stroke, strokeW, text, opts = {}) {
    const id = shapeId++;
    shapes.push({
      id,
      type: "rect",
      x,
      y,
      w,
      h,
      fill,
      stroke,
      strokeW,
      text,
      dashed: opts.dashed || false,
      fontSize: opts.fontSize || 11,
      fontColor: opts.fontColor || "#1F2937",
      bold: opts.bold || false,
      topAlign: opts.topAlign || false,
      props: opts.props || [],
      hAlign: opts.hAlign || "left",
      linePattern: opts.linePattern || 1
    });
    return id;
  }
  function addPolyEdge(waypoints, color, width, linePattern, label) {
    polyEdges.push({
      waypoints,
      color,
      width,
      linePattern: linePattern || 1,
      label: label || "",
      id: shapeId++
    });
  }
  function buildSubText(s, ctx) {
    const { pubSubs, instBySub, eniBySub, lbBySub, subRT } = ctx;
    const isPub = pubSubs.has(s.SubnetId);
    const si = instBySub[s.SubnetId] || [];
    const se = eniBySub[s.SubnetId] || [];
    const sa = lbBySub[s.SubnetId] || [];
    const lines = [];
    lines.push((isPub ? "[PUBLIC] " : "[PRIVATE] ") + gn(s, s.SubnetId));
    lines.push(s.CidrBlock + "  |  " + (s.AvailabilityZone || ""));
    const parts = [];
    if (si.length) parts.push(si.length + " VM");
    if (se.length) parts.push(se.length + " NIC");
    if (sa.length) parts.push(sa.length + " LB");
    if (parts.length) lines.push(parts.join(" | "));
    const rt = subRT[s.SubnetId];
    if (rt) {
      const nonLocal = (rt.Routes || []).filter((r) => {
        const t = r.GatewayId || r.NatGatewayId || r.TransitGatewayId || r.VpcPeeringConnectionId;
        return t && t !== "local";
      });
      if (nonLocal.length) {
        lines.push("Routes:");
        nonLocal.forEach((r) => {
          const dest = r.DestinationCidrBlock || r.DestinationPrefixListId || "?";
          const tgt = r.GatewayId || r.NatGatewayId || r.TransitGatewayId || r.VpcPeeringConnectionId;
          lines.push("  " + dest + " -> " + clsGw(tgt || "") + " " + sid(tgt));
        });
      }
    }
    return { text: lines.join("\n"), lineCount: lines.length };
  }
  function buildShape(s, pgH) {
    const wi = toIn(s.w);
    const hi = toIn(s.h);
    const cx = toIn(s.x) + wi / 2;
    const cy = pgH - (toIn(s.y) + hi / 2);
    const lp = s.linePattern || 1;
    const dashXml = s.dashed ? '<Cell N="LinePattern" V="2"/>' : lp !== 1 ? '<Cell N="LinePattern" V="' + lp + '"/>' : "";
    const sw = toIn(s.strokeW || 1);
    const fs = (s.fontSize || 11) / 72;
    const geom = '<Section N="Geometry" IX="0"><Cell N="NoFill" V="0"/><Cell N="NoLine" V="0"/><Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row><Row T="LineTo" IX="2"><Cell N="X" V="' + wi + '"/><Cell N="Y" V="0"/></Row><Row T="LineTo" IX="3"><Cell N="X" V="' + wi + '"/><Cell N="Y" V="' + hi + '"/></Row><Row T="LineTo" IX="4"><Cell N="X" V="0"/><Cell N="Y" V="' + hi + '"/></Row><Row T="LineTo" IX="5"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row></Section>';
    const vAlign = s.topAlign ? 0 : 1;
    const hAlign = s.hAlign === "center" ? 1 : 0;
    const propsXml = s.props && s.props.length ? '<Section N="Property">' + s.props.map(
      (p, i) => '<Row N="Row_' + i + '"><Cell N="Label" V="' + xmlEsc(p.label) + '"/><Cell N="Value" V="' + xmlEsc(p.val) + '"/><Cell N="Type" V="0"/></Row>'
    ).join("") + "</Section>" : "";
    return '<Shape ID="' + s.id + '" NameU="Shape' + s.id + '" Type="Shape" UniqueID="' + uid() + '"><Cell N="PinX" V="' + cx + '"/><Cell N="PinY" V="' + cy + '"/><Cell N="Width" V="' + wi + '"/><Cell N="Height" V="' + hi + '"/><Cell N="LocPinX" V="' + wi / 2 + '"/><Cell N="LocPinY" V="' + hi / 2 + '"/><Cell N="TxtWidth" V="' + wi + '"/><Cell N="TxtHeight" V="' + hi + '"/><Cell N="TxtPinX" V="' + wi / 2 + '"/><Cell N="TxtPinY" V="' + hi / 2 + '"/><Cell N="TxtLocPinX" V="' + wi / 2 + '"/><Cell N="TxtLocPinY" V="' + hi / 2 + '"/><Cell N="FillForegnd" V="' + s.fill + '"/><Cell N="FillBkgnd" V="' + s.fill + '"/><Cell N="LineColor" V="' + s.stroke + '"/><Cell N="LineWeight" V="' + sw + '"/><Cell N="VerticalAlign" V="' + vAlign + '"/><Cell N="HorzAlign" V="' + hAlign + '"/><Cell N="TopMargin" V="0.06"/><Cell N="BottomMargin" V="0.06"/><Cell N="LeftMargin" V="0.1"/><Cell N="RightMargin" V="0.1"/>' + dashXml + '<Section N="Character" IX="0"><Row IX="0"><Cell N="Font" V="Calibri"/><Cell N="Color" V="' + (s.fontColor || "#000000") + '"/><Cell N="Size" V="' + fs + '"/><Cell N="Style" V="' + (s.bold ? 1 : 0) + '"/></Row></Section>' + geom + propsXml + "<Text>" + xmlEsc(s.text) + "</Text></Shape>";
  }
  function buildPolyConnector(e, pgH) {
    const pts = e.waypoints.map((wp) => ({ x: toIn(wp.x), y: pgH - toIn(wp.y) }));
    if (pts.length < 2) return "";
    const p1 = pts[0];
    const pN = pts[pts.length - 1];
    const sw = toIn(e.width || 1);
    const cid = e.id;
    let geomRows = '<Row T="MoveTo" IX="1"><Cell N="X" V="' + p1.x + '"/><Cell N="Y" V="' + p1.y + '"/></Row>';
    for (let i = 1; i < pts.length; i++) {
      geomRows += '<Row T="LineTo" IX="' + (i + 1) + '"><Cell N="X" V="' + pts[i].x + '"/><Cell N="Y" V="' + pts[i].y + '"/></Row>';
    }
    return '<Shape ID="' + cid + '" NameU="Conn.' + cid + '" Type="Shape" UniqueID="' + uid() + '"><Cell N="ObjType" V="2"/><Cell N="BeginX" V="' + p1.x + '"/><Cell N="BeginY" V="' + p1.y + '"/><Cell N="EndX" V="' + pN.x + '"/><Cell N="EndY" V="' + pN.y + '"/><Cell N="LineColor" V="' + (e.color || "#6B7280") + '"/><Cell N="LineWeight" V="' + sw + '"/><Cell N="LinePattern" V="' + (e.linePattern || 1) + '"/><Cell N="BeginArrow" V="0"/><Cell N="EndArrow" V="5"/><Cell N="EndArrowSize" V="2"/><Section N="Geometry" IX="0"><Cell N="NoFill" V="1"/><Cell N="NoLine" V="0"/>' + geomRows + "</Section></Shape>";
  }
  function buildVsdxXml(pgW, pgH) {
    let shapesStr = "";
    shapes.forEach((s) => {
      shapesStr += buildShape(s, pgH);
    });
    polyEdges.forEach((e) => {
      shapesStr += buildPolyConnector(e, pgH);
    });
    const page1 = '<?xml version="1.0" encoding="utf-8"?><PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><Shapes>' + shapesStr + "</Shapes></PageContents>";
    const pagesXml = '<?xml version="1.0" encoding="utf-8"?><Pages xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><Page ID="0" Name="Azure Network Map" NameU="Azure Network Map"><PageSheet><Cell N="PageWidth" V="' + pgW + '"/><Cell N="PageHeight" V="' + pgH + '"/><Cell N="PrintPageOrientation" V="2"/></PageSheet><Rel r:id="rId1"/></Page></Pages>';
    const docXml = '<?xml version="1.0" encoding="utf-8"?><VisioDocument xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><DocumentProperties><Creator>Azure Network Map Tool</Creator><Description>Azure Network Infrastructure Diagram</Description></DocumentProperties></VisioDocument>';
    const contentTypes = '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml"/><Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml"/><Override PartName="/visio/pages/page1.xml" ContentType="application/vnd.ms-visio.page+xml"/></Types>';
    const topRels = '<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/document" Target="visio/document.xml"/></Relationships>';
    const docRels = '<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/pages" Target="pages/pages.xml"/></Relationships>';
    const pagesRels = '<?xml version="1.0" encoding="utf-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/page" Target="page1.xml"/></Relationships>';
    return { page1, pagesXml, docXml, contentTypes, topRels, docRels, pagesRels };
  }
  var _colorCache = /* @__PURE__ */ new Map();
  function resolveColor(cssVar) {
    if (_colorCache.has(cssVar)) return _colorCache.get(cssVar);
    if (typeof document === "undefined") return "#888888";
    const el = document.createElement("div");
    el.style.color = cssVar;
    document.body.appendChild(el);
    const c = getComputedStyle(el).color;
    document.body.removeChild(el);
    const m = c.match(/(\d+)/g);
    if (!m) return "#888888";
    const hex = "#" + m.slice(0, 3).map((x) => (+x).toString(16).padStart(2, "0")).join("");
    _colorCache.set(cssVar, hex);
    return hex;
  }
  function downloadBlob(blob, name) {
    const isElectron = typeof window !== "undefined" && !!window.electronAPI;
    if (isElectron) {
      const ext2 = (name.match(/\.([^.]+)$/) || [])[1] || "*";
      const filters = [
        { name: ext2.toUpperCase() + " Files", extensions: [ext2] },
        { name: "All Files", extensions: ["*"] }
      ];
      if (blob.type && blob.type.startsWith("text")) {
        blob.text().then((text) => {
          window.electronAPI.exportFile(text, name, filters).then((p) => {
            if (p) showToast("Exported: " + p.split("/").pop());
          }).catch((e) => console.error("Export failed:", e));
        });
      } else {
        blob.arrayBuffer().then((ab) => {
          window.electronAPI.exportFile(new Uint8Array(ab), name, filters).then((p) => {
            if (p) showToast("Exported: " + p.split("/").pop());
          }).catch((e) => console.error("Export failed:", e));
        });
      }
      return;
    }
    const a = document.createElement("a");
    const objUrl = URL.createObjectURL(blob);
    a.href = objUrl;
    a.download = name;
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function() {
      URL.revokeObjectURL(objUrl);
    }, 1e3);
  }
  function computeSubnetHeights(subnets, ctx) {
    const heights = {};
    subnets.forEach((s) => {
      const bt = buildSubText(s, ctx);
      heights[s.SubnetId] = Math.max(SUB_H_MIN, bt.lineCount * LINE_H + 30);
    });
    return heights;
  }
  function computePageDimensions(totalWidth, busStartY, busLaneIdx, busLaneH) {
    let pgWpx = totalWidth + 200;
    let pgHpx = busStartY + (busLaneIdx + 2) * busLaneH + 300;
    shapes.forEach((s) => {
      pgWpx = Math.max(pgWpx, s.x + s.w + 120);
      pgHpx = Math.max(pgHpx, s.y + s.h + 120);
    });
    const pgW = toIn(pgWpx) + 2;
    const pgH = toIn(pgHpx) + 2;
    return { pgWpx, pgHpx, pgW, pgH };
  }
  if (typeof window !== "undefined") {
    window.downloadBlob = downloadBlob;
    window.resolveColor = resolveColor;
    window._sanitizeName = sanitizeName;
    let _vsdxCache = null;
    Object.defineProperty(window, "_vsdx", {
      get() {
        if (!_vsdxCache) _vsdxCache = {
          resetShapeState,
          getShapes,
          getPolyEdges,
          getIdMap,
          setIdMapEntry,
          xmlEsc,
          uid,
          addRect,
          addPolyEdge,
          buildSubText,
          buildShape,
          buildPolyConnector,
          buildVsdxXml,
          computeSubnetHeights,
          computePageDimensions,
          gwStyles,
          PX,
          SUB_W,
          SUB_H_MIN,
          SUB_GAP,
          VNET_PAD,
          VNET_HDR,
          GW_INSIDE_W,
          GW_INSIDE_H,
          GW_INSIDE_GAP,
          GW_ROW_H,
          COL_GAP,
          LINE_H,
          TOP_MARGIN,
          toIn
        };
        return _vsdxCache;
      },
      configurable: true
    });
  }

  // src/modules/normalization.js
  function _normTags(r) {
    if (!r) return;
    var tg = r.tags;
    if (tg && !Array.isArray(tg) && typeof tg === "object") r.Tags = Object.keys(tg).map(function(k) {
      return { Key: k, Value: tg[k] || "" };
    });
    if (!r.Tags && !r.tags && r.name) r.Tags = [{ Key: "Name", Value: r.name }];
  }
  function _normalizeAzureResources(d) {
    var allArrays = [d.vpcs, d.subnets, d.rts, d.sgs, d.enis, d.nats, d.vpces, d.instances, d.albs, d.tgs, d.peerings, d.vpns, d.volumes, d.snapshots, d.s3bk, d.zones, d.wafAcls, d.rdsInstances, d.ecsServices, d.lambdaFns, d.ecacheClusters, d.redshiftClusters, d.tgwAttachments, d.cfDistributions];
    allArrays.forEach(function(arr) {
      if (arr) arr.forEach(function(r) {
        _normTags(r);
        if (r && !r.properties) r.properties = r;
        [
          "ipConfigurations",
          "securityRules",
          "defaultSecurityRules",
          "routes",
          "frontendIPConfigurations",
          "gatewayIPConfigurations",
          "backendPools",
          "originGroups",
          "backends",
          "origins",
          "privateLinkServiceConnections",
          "privateEndpointConnections",
          "agentPoolProfiles",
          "virtualNetworkLinks",
          "loadBalancingRules"
        ].forEach(function(k) {
          if (r[k] && Array.isArray(r[k])) r[k].forEach(function(item) {
            if (item && typeof item === "object" && !item.properties) item.properties = item;
          });
        });
      });
    });
    if (d.vpcs) d.vpcs.forEach(function(v) {
      if (!v.VpcId) v.VpcId = v.id || "";
      if (!v.CidrBlock) v.CidrBlock = v.addressSpace && v.addressSpace.addressPrefixes && v.addressSpace.addressPrefixes[0] || "";
    });
    if (d.subnets) d.subnets.forEach(function(s) {
      if (!s.SubnetId) s.SubnetId = s.id || "";
      if (!s.VpcId) s.VpcId = (s.id || "").split("/subnets/")[0] || "";
      if (!s.CidrBlock) s.CidrBlock = s.addressPrefix || "";
    });
    if (d.rts) d.rts.forEach(function(r) {
      if (!r.RouteTableId) r.RouteTableId = r.id || "";
      if (!r.VpcId) {
        var subs = r.subnets || [];
        if (subs[0] && subs[0].id) r.VpcId = subs[0].id.split("/subnets/")[0] || "";
      }
      if (!r.Routes && r.routes) r.Routes = r.routes.map(function(rt) {
        return { DestinationCidrBlock: rt.addressPrefix || "", GatewayId: rt.nextHopType || "", State: "active", _azRoute: rt };
      });
    });
    if (d.sgs) d.sgs.forEach(function(s) {
      if (!s.GroupId) s.GroupId = s.id || "";
      if (!s.GroupName) s.GroupName = s.name || "";
      if (!s.VpcId && s.subnets && s.subnets[0] && s.subnets[0].id) s.VpcId = s.subnets[0].id.split("/subnets/")[0] || "";
      if (!s.IpPermissions && (s.securityRules || s.defaultSecurityRules)) {
        var allRules = [].concat(s.securityRules || []).concat(s.defaultSecurityRules || []);
        s.IpPermissions = allRules.filter(function(r) {
          return (r.direction || "").toLowerCase() === "inbound";
        }).map(function(r) {
          return { IpProtocol: (r.protocol || "*").toLowerCase(), FromPort: r.destinationPortRange === "*" ? 0 : parseInt(r.destinationPortRange) || 0, ToPort: r.destinationPortRange === "*" ? 65535 : parseInt((r.destinationPortRange || "").split("-").pop()) || 0, IpRanges: [{ CidrIp: r.sourceAddressPrefix || "*" }], _azRule: r };
        });
        s.IpPermissionsEgress = allRules.filter(function(r) {
          return (r.direction || "").toLowerCase() === "outbound";
        }).map(function(r) {
          return { IpProtocol: (r.protocol || "*").toLowerCase(), FromPort: r.destinationPortRange === "*" ? 0 : parseInt(r.destinationPortRange) || 0, ToPort: r.destinationPortRange === "*" ? 65535 : parseInt((r.destinationPortRange || "").split("-").pop()) || 0, IpRanges: [{ CidrIp: r.destinationAddressPrefix || "*" }], _azRule: r };
        });
      }
    });
    if (d.enis) d.enis.forEach(function(e) {
      if (!e.NetworkInterfaceId) e.NetworkInterfaceId = e.id || "";
      if (!e.SubnetId && e.ipConfigurations && e.ipConfigurations[0] && e.ipConfigurations[0].subnet) e.SubnetId = e.ipConfigurations[0].subnet.id || "";
      if (!e.VpcId && e.SubnetId) e.VpcId = (e.SubnetId || "").split("/subnets/")[0] || "";
    });
    if (d.nats) d.nats.forEach(function(n) {
      if (!n.NatGatewayId) n.NatGatewayId = n.id || "";
      if (!n.SubnetId && n.subnets && n.subnets[0]) n.SubnetId = n.subnets[0].id || "";
      if (!n.VpcId && n.SubnetId) n.VpcId = (n.SubnetId || "").split("/subnets/")[0] || "";
    });
    if (d.vpces) d.vpces.forEach(function(v) {
      if (!v.VpcEndpointId) v.VpcEndpointId = v.id || "";
      if (!v.ServiceName && v.privateLinkServiceConnections && v.privateLinkServiceConnections[0]) {
        var plc = v.privateLinkServiceConnections[0];
        v.ServiceName = plc.groupIds && plc.groupIds[0] || plc.privateLinkServiceId || "";
      }
      if (!v.SubnetId && v.subnet) v.SubnetId = v.subnet.id || "";
      if (!v.VpcId && v.SubnetId) v.VpcId = (v.SubnetId || "").split("/subnets/")[0] || "";
    });
    if (d.instances) d.instances.forEach(function(i) {
      if (!i.InstanceId) i.InstanceId = i.id || "";
      if (!i.InstanceType && i.hardwareProfile) i.InstanceType = i.hardwareProfile.vmSize || "";
      if (!i.SubnetId && i.networkProfile && i.networkProfile.networkInterfaces && i.networkProfile.networkInterfaces[0]) i._nicId = i.networkProfile.networkInterfaces[0].id || "";
    });
    if (d.albs) d.albs.forEach(function(a) {
      if (!a.LoadBalancerArn) a.LoadBalancerArn = a.id || "";
      if (!a.LoadBalancerName) a.LoadBalancerName = a.name || "";
      if (!a.AvailabilityZones && a.frontendIPConfigurations) a.AvailabilityZones = a.frontendIPConfigurations.filter(function(f) {
        return f.subnet;
      }).map(function(f) {
        return { SubnetId: f.subnet.id || "" };
      });
    });
    if (d.tgs) d.tgs.forEach(function(t) {
      if (!t.TargetGroupArn) t.TargetGroupArn = t.id || "";
      if (!t.TargetGroupName) t.TargetGroupName = t.name || "";
      if (!t.LoadBalancerArns && t.loadBalancingRules) t.LoadBalancerArns = t.loadBalancingRules.map(function(r) {
        return (r.id || "").split("/loadBalancingRules/")[0];
      }).filter(Boolean);
    });
    if (d.peerings) d.peerings.forEach(function(p) {
      if (!p.VpcPeeringConnectionId) p.VpcPeeringConnectionId = p.id || "";
      if (!p.RequesterVpcInfo && p.localVirtualNetwork) p.RequesterVpcInfo = { VpcId: p.localVirtualNetwork.id || "", CidrBlock: p.localAddressSpace && p.localAddressSpace.addressPrefixes && p.localAddressSpace.addressPrefixes[0] || "" };
      if (!p.AccepterVpcInfo && p.remoteVirtualNetwork) p.AccepterVpcInfo = { VpcId: p.remoteVirtualNetwork.id || "", CidrBlock: p.remoteAddressSpace && p.remoteAddressSpace.addressPrefixes && p.remoteAddressSpace.addressPrefixes[0] || "" };
      if (!p.Status && p.peeringState) p.Status = { Code: p.peeringState };
    });
    if (d.vpns) d.vpns.forEach(function(v) {
      if (!v.VpnGatewayId) v.VpnGatewayId = v.virtualNetworkGateway1 && v.virtualNetworkGateway1.id || v.id || "";
      if (!v.State) v.State = v.connectionStatus || v.provisioningState || "";
    });
    if (d.volumes) d.volumes.forEach(function(v) {
      if (!v.VolumeId) v.VolumeId = v.id || "";
      if (!v.Size && v.diskSizeGb) v.Size = v.diskSizeGb;
      if (!v.VolumeType && v.sku) v.VolumeType = v.sku.name || "";
      if (!v.State) v.State = v.diskState || v.provisioningState || "";
      if (!v.Attachments && v.managedBy) v.Attachments = [{ InstanceId: v.managedBy }];
    });
    if (d.snapshots) d.snapshots.forEach(function(s) {
      if (!s.SnapshotId) s.SnapshotId = s.id || "";
      if (!s.VolumeId && s.creationData) s.VolumeId = s.creationData.sourceResourceId || "";
      if (!s.VolumeSize && s.diskSizeGb) s.VolumeSize = s.diskSizeGb;
      if (!s.State) s.State = s.provisioningState || "";
    });
    if (d.s3bk) d.s3bk.forEach(function(s) {
      if (!s.Name) s.Name = s.name || "";
    });
    if (d.zones) d.zones.forEach(function(z) {
      if (!z.Id) z.Id = z.id || "";
      if (!z.Config) z.Config = { PrivateZone: z.zoneType === "Private" };
    });
    if (d.wafAcls) d.wafAcls.forEach(function(w) {
      if (!w.ResourceArns && w.applicationGateways) w.ResourceArns = w.applicationGateways.map(function(a) {
        return a.id || "";
      });
    });
    if (d.rdsInstances) d.rdsInstances.forEach(function(r) {
      if (!r.DBInstanceIdentifier) r.DBInstanceIdentifier = r.name || "";
      if (!r.DBInstanceClass && r.sku) r.DBInstanceClass = r.sku.tier || r.sku.name || "";
      if (!r.Engine) r.Engine = r.version || r.kind || "SQL";
    });
    if (d.ecsServices) d.ecsServices.forEach(function(c) {
      if (!c.serviceName) c.serviceName = c.name || "";
      if (!c.serviceArn) c.serviceArn = c.id || "";
    });
    if (d.lambdaFns) d.lambdaFns.forEach(function(f) {
      if (!f.FunctionName) f.FunctionName = f.name || "";
      if (!f.FunctionArn) f.FunctionArn = f.id || "";
      if (!f.Runtime) {
        var lv = f.siteConfig && f.siteConfig.linuxFxVersion;
        f.Runtime = lv || f.kind || "";
      }
      if (!f.VpcConfig && f.virtualNetworkSubnetId) f.VpcConfig = { SubnetIds: [f.virtualNetworkSubnetId] };
    });
    if (d.ecacheClusters) d.ecacheClusters.forEach(function(c) {
      if (!c.CacheClusterId) c.CacheClusterId = c.name || "";
      if (!c.Engine && c.sku) c.Engine = c.sku.family || "Redis";
      if (!c.CacheNodeType && c.sku) c.CacheNodeType = c.sku.capacity || "";
      if (!c.CacheClusterStatus) c.CacheClusterStatus = c.provisioningState || "";
    });
    if (d.redshiftClusters) d.redshiftClusters.forEach(function(c) {
      if (!c.ClusterIdentifier) c.ClusterIdentifier = c.name || "";
      if (!c.NumberOfNodes && c.agentPoolProfiles && c.agentPoolProfiles[0]) c.NumberOfNodes = c.agentPoolProfiles[0].count || 1;
      if (!c.NodeType && c.agentPoolProfiles && c.agentPoolProfiles[0]) c.NodeType = c.agentPoolProfiles[0].vmSize || "";
      if (!c.ClusterStatus) c.ClusterStatus = c.provisioningState || "";
    });
    if (d.tgwAttachments) d.tgwAttachments.forEach(function(t) {
      if (!t.TransitGatewayId) t.TransitGatewayId = t.id || "";
      if (!t.State) t.State = t.provisioningState || "";
    });
    if (d.cfDistributions) d.cfDistributions.forEach(function(c) {
      if (!c.Id) c.Id = c.id || "";
      if (!c.DomainName && c.frontendEndpoints && c.frontendEndpoints[0]) c.DomainName = c.frontendEndpoints[0].hostName || c.frontendEndpoints[0].name || "";
    });
  }
  var fileMap = [
    { id: "in_vnets", patterns: ["vnet", "vnets", "virtual-network", "virtualnetwork"] },
    { id: "in_subnets", patterns: ["subnet", "subnets"] },
    { id: "in_udrs", patterns: ["route-table", "route_table", "routetable", "udr", "udrs"] },
    { id: "in_nsgs", patterns: ["nsg", "nsgs", "network-security-group", "networksecuritygroup"] },
    { id: "in_nics", patterns: ["nic", "nics", "network-interface", "networkinterface"] },
    { id: "in_pubips", patterns: ["public-ip", "publicip", "pip", "pubip"] },
    { id: "in_nats", patterns: ["nat-gw", "nat_gw", "natgw", "nat-gateway", "nat_gateway", "natgateway"] },
    { id: "in_pvteps", patterns: ["private-endpoint", "privateendpoint", "pvtep", "private_endpoint"] },
    { id: "in_azfws", patterns: ["azfw", "azure-firewall", "azurefirewall", "firewall"] },
    { id: "in_bastions", patterns: ["bastion", "bastions", "azure-bastion"] },
    { id: "in_vms", patterns: ["vm", "vms", "virtual-machine", "virtualmachine"] },
    { id: "in_albs", patterns: ["appgw", "app-gateway", "applicationgateway", "agw"] },
    { id: "in_tgs", patterns: ["lb", "lbs", "load-balancer", "load_balancer", "loadbalancer"] },
    { id: "in_peer", patterns: ["peering", "vnet-peering", "vnetpeering", "peer"] },
    { id: "in_vpn", patterns: ["vpn", "vpn-connection", "vpn_connection"] },
    { id: "in_disks", patterns: ["disk", "disks", "managed-disk", "manageddisk"] },
    { id: "in_snaps", patterns: ["snapshot", "snapshots", "snap"] },
    { id: "in_storage", patterns: ["storage-account", "storageaccount", "storage"] },
    { id: "in_dnsz", patterns: ["dns-zone", "dnszone", "dns"] },
    { id: "in_r53records", patterns: ["record-set", "recordset", "dns-record", "dnsrecord"] },
    { id: "in_waf", patterns: ["waf", "waf-policy", "wafpolicy"] },
    { id: "in_sql", patterns: ["sql", "sql-server", "sqlserver"] },
    { id: "in_containers", patterns: ["container", "containers", "aci", "containerinstance"] },
    { id: "in_funcapps", patterns: ["functionapp", "func", "function-app", "funcapp"] },
    { id: "in_elasticache", patterns: ["redis", "redis-cache", "rediscache"] },
    { id: "in_aks", patterns: ["aks", "kubernetes", "k8s"] },
    { id: "in_tgwatt", patterns: ["vwan", "virtual-wan", "virtualwan"] },
    { id: "in_cf", patterns: ["frontdoor", "front-door", "afd", "front_door"] },
    { id: "in_rbac", patterns: ["rbac", "role-assignment", "roleassignment"] },
    { id: "in_rgs", patterns: ["resource-group", "resourcegroup", "rg"] },
    { id: "in_vnetgw", patterns: ["vnet-gateway", "vnetgateway", "vnet_gateway", "vpn-gateway", "vpngateway"] },
    { id: "in_expressrt", patterns: ["express-route", "expressroute", "express_route", "expressrt"] },
    { id: "in_pdnslinks", patterns: ["private-dns-link", "privatednslink", "pdns-link", "private_dns_link"] },
    { id: "in_aspans", patterns: ["app-service-plan", "appserviceplan", "asp", "app_service_plan"] },
    { id: "in_webapps", patterns: ["webapp", "web-app", "web_app", "webapps", "app-service", "appservice"] },
    { id: "in_cosmosdb", patterns: ["cosmos", "cosmosdb", "cosmos-db", "cosmos_db", "documentdb"] },
    { id: "in_keyvaults", patterns: ["keyvault", "key-vault", "key_vault", "kv"] },
    { id: "in_svcbus", patterns: ["service-bus", "servicebus", "service_bus", "svcbus"] },
    { id: "in_evhubs", patterns: ["event-hub", "eventhub", "event_hub", "eventhubs"] },
    { id: "in_appinsights", patterns: ["app-insight", "appinsight", "application-insight", "app_insight"] },
    { id: "in_acr", patterns: ["acr", "container-registry", "containerregistry", "container_registry"] },
    { id: "in_batch", patterns: ["batch", "batch-account", "batchaccount", "batch_account"] },
    { id: "in_avd", patterns: ["virtual-desktop", "virtualdesktop", "hostpool", "host-pool", "avd"] },
    { id: "in_cdn", patterns: ["cdn", "cdn-profile", "cdnprofile"] },
    { id: "in_trafficmgr", patterns: ["traffic-manager", "trafficmanager", "traffic_manager", "tm-profile"] },
    { id: "in_privlink", patterns: ["private-link-service", "privatelinkservice", "private_link_service", "privlink"] },
    { id: "in_ddos", patterns: ["ddos", "ddos-protection", "ddosprotection", "ddos_protection"] },
    { id: "in_netapp", patterns: ["netapp", "netappfiles", "netapp-files", "netapp_files"] },
    { id: "in_mysql", patterns: ["mysql", "mysql-server", "mysqlserver", "mysql_server"] },
    { id: "in_postgres", patterns: ["postgres", "postgresql", "postgres-server", "postgresserver"] },
    { id: "in_apim", patterns: ["apim", "api-management", "apimanagement", "api_management"] },
    { id: "in_logicapps", patterns: ["logic-app", "logicapp", "logic_app", "logic-workflow"] },
    { id: "in_signalr", patterns: ["signalr", "signal-r", "signal_r"] },
    { id: "in_relay", patterns: ["relay", "relay-namespace", "relaynamespace"] },
    { id: "in_adf", patterns: ["data-factory", "datafactory", "data_factory", "adf"] },
    { id: "in_iothub", patterns: ["iot-hub", "iothub", "iot_hub", "iot"] },
    { id: "in_loganalytics", patterns: ["log-analytics", "loganalytics", "log_analytics", "la-workspace"] },
    { id: "in_actiongroups", patterns: ["action-group", "actiongroup", "action_group"] },
    { id: "in_metricalerts", patterns: ["metric-alert", "metricalert", "metric_alert", "metrics-alert"] },
    { id: "in_automation", patterns: ["automation", "automation-account", "automationaccount"] },
    { id: "in_cognitive", patterns: ["cognitive", "cognitiveservices", "cognitive-services", "cognitive_services"] },
    { id: "in_mlworkspace", patterns: ["ml-workspace", "mlworkspace", "ml_workspace", "machine-learning"] },
    { id: "in_purview", patterns: ["purview", "purview-account", "purviewaccount"] },
    { id: "in_managedid", patterns: ["managed-identity", "managedidentity", "managed_identity", "identity"] },
    { id: "in_policyassign", patterns: ["policy-assignment", "policyassignment", "policy_assignment", "policy"] },
    { id: "in_arcmachines", patterns: ["arc-machine", "arcmachine", "arc_machine", "connectedmachine", "arc"] },
    { id: "in_recoveryvaults", patterns: ["recovery-vault", "recoveryvault", "recovery_vault", "backup-vault"] },
    { id: "in_managedapps", patterns: ["managed-app", "managedapp", "managed_app", "managedapplication"] },
    { id: "in_mapsaccts", patterns: ["maps", "maps-account", "mapsaccount", "azure-maps"] }
  ];
  function matchFile(fname, content) {
    const base = fname.replace(/\.json$/i, "").toLowerCase().replace(/[^a-z0-9-_]/g, "");
    function _hasKey(k) {
      if (!content) return false;
      if (typeof content === "object") return k in content;
      return content.slice(0, 500).includes('"' + k + '"');
    }
    for (const fm of fileMap) {
      for (const p of fm.patterns) {
        if (base === p || base === p + "s") return fm.id;
      }
    }
    const candidates = [];
    for (const fm of fileMap) {
      for (const p of fm.patterns) {
        if (base.includes(p)) candidates.push({ id: fm.id, p, len: p.length });
      }
    }
    if (candidates.length) {
      candidates.sort((a, b) => b.len - a.len);
      const best = candidates[0].id;
      if (content) {
        if (best === "in_vms") {
          if (_hasKey("servers") && !_hasKey("virtualMachines")) return "in_sql";
          if (_hasKey("CacheClusters") || _hasKey("redisConfiguration")) return "in_elasticache";
        }
        const expectedKey = { in_udrs: "value", in_vnets: "value", in_subnets: "value", in_nsgs: "value", in_nics: "value" };
        if (expectedKey[best] && !_hasKey(expectedKey[best])) {
          const trimmed = typeof content === "string" ? content.trimStart() : "";
          if (!trimmed.startsWith("[")) return null;
        }
      }
      return best;
    }
    if (content) {
      if (_hasKey("virtualMachines") || _hasKey("value") && _hasKey("osProfile")) return "in_vms";
      if (_hasKey("servers") && _hasKey("administratorLogin")) return "in_sql";
      if (_hasKey("addressSpace") || _hasKey("value") && _hasKey("addressSpace")) return "in_vnets";
      if (_hasKey("addressPrefix") && _hasKey("networkSecurityGroup")) return "in_subnets";
      if (_hasKey("securityRules")) return "in_nsgs";
      if (_hasKey("routes") && _hasKey("disableBgpRoutePropagation")) return "in_udrs";
      if (_hasKey("privateIPAddress") && _hasKey("macAddress")) return "in_nics";
      if (_hasKey("natRuleCollections")) return "in_azfws";
      if (_hasKey("dnsSettings") && _hasKey("publicIPAllocationMethod")) return "in_pubips";
      if (_hasKey("natGatewayTimeout")) return "in_nats";
      if (_hasKey("privateLinkServiceConnections")) return "in_pvteps";
      if (_hasKey("bastionHostPropertiesFormat")) return "in_bastions";
      if (_hasKey("applicationGatewayIPConfigurations")) return "in_albs";
      if (_hasKey("frontendIPConfigurations") && _hasKey("loadBalancingRules")) return "in_tgs";
      if (_hasKey("peeringState") && _hasKey("remoteVirtualNetwork")) return "in_peer";
      if (_hasKey("vpnConnectionType")) return "in_vpn";
      if (_hasKey("diskSizeGB") && _hasKey("diskState")) return "in_disks";
      if (_hasKey("snapshotType")) return "in_snaps";
      if (_hasKey("primaryEndpoints") && _hasKey("accountType")) return "in_storage";
      if (_hasKey("zoneType") && _hasKey("nameServers")) return "in_dnsz";
      if (_hasKey("TTL") && _hasKey("fqdn")) return "in_r53records";
      if (_hasKey("policySettings") && _hasKey("managedRules")) return "in_waf";
      if (_hasKey("vnetType") && _hasKey("type") && _hasKey("allowVnetToVnetTraffic")) return "in_tgwatt";
      if (_hasKey("frontendEndpoints") && _hasKey("backendPools")) return "in_cf";
      if (_hasKey("hostNames") && _hasKey("functionAppConfig")) return "in_funcapps";
      if (_hasKey("redisConfiguration")) return "in_elasticache";
      if (_hasKey("agentPoolProfiles") && _hasKey("kubernetesVersion")) return "in_aks";
      if (_hasKey("containers") && _hasKey("osType") && !_hasKey("agentPoolProfiles")) return "in_containers";
      if (_hasKey("roleDefinitionId") && _hasKey("principalId")) return "in_rbac";
      if (_hasKey("managedBy") && _hasKey("properties") && _hasKey("provisioningState")) return "in_rgs";
    }
    return null;
  }
  function _friendlyFolderLabel(folderName) {
    if (!folderName) return null;
    var m = folderName.match(/^azure-export-(.+?)-\d{8}-\d{6}$/);
    if (m) {
      var sub = m[1];
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-/.test(sub)) return sub.substring(0, 13) + "...";
      return sub;
    }
    return folderName.length > 30 ? folderName.substring(0, 27) + "..." : folderName;
  }

  // src/main.js
  window.AppModules = {
    // Constants (clean + underscore-prefixed aliases for inline code)
    SEV_ORDER,
    FW_LABELS,
    EOL_RUNTIMES,
    EFFORT_LABELS,
    EFFORT_TIME,
    PRIORITY_META,
    TIER_META,
    PRIORITY_ORDER,
    PRIORITY_KEYS,
    MUTE_KEY,
    NOTES_KEY,
    SNAP_KEY,
    SAVE_KEY,
    MAX_SNAPSHOTS,
    SAVE_INTERVAL,
    NOTE_CATEGORIES,
    _SEV_ORDER: SEV_ORDER,
    _FW_LABELS: FW_LABELS,
    // Utils
    safeParse,
    ext,
    esc,
    gn,
    sid,
    clsGw,
    isShared,
    gcv,
    gch,
    gv,
    parseResourceId,
    getTenantFromResource,
    // Cloud environment
    CLOUDS,
    getCloudEnv,
    setCloudEnv,
    getCloudConfig,
    getComplianceFrameworks,
    isServiceAvailable,
    getPortalUrl,
    detectCloudFromEndpoint,
    // DOM helpers
    showToast,
    closeAllDashboards,
    toggleClass,
    setVisible,
    getEl,
    qs,
    qsa,
    // Prefs
    _prefs,
    loadPrefs,
    savePrefs,
    // CIDR engine
    ipToInt,
    intToIp,
    parseCIDR,
    cidrToString,
    splitCIDR,
    cidrContains,
    cidrOverlap,
    ipInCIDR,
    // Compliance
    runComplianceChecks,
    invalidateComplianceCache,
    // Network rules (Azure NSG + UDR)
    evaluateNsgRules,
    evaluateNsgPath,
    evaluateRoute,
    protocolMatch,
    portMatch,
    addressMatch,
    classifySubnet,
    // Shared state
    State: state_exports,
    // DOM builders
    buildEl,
    buildOption,
    buildSelect,
    buildButton,
    setText,
    replaceChildren,
    safeHtml,
    // BUDR engine
    _BUDR_STRATEGY,
    _BUDR_STRATEGY_ORDER,
    _BUDR_STRATEGY_LEGEND,
    _BUDR_RTO_RPO,
    _BUDR_EST_MINUTES,
    _TIER_TARGETS,
    runBUDRChecks,
    _budrTierCompliance,
    _fmtMin,
    _enrichBudrWithClassification,
    _reapplyBUDROverrides,
    _getBUDRTierCounts,
    _getBudrComplianceCounts,
    _budrFindings: budrFindings,
    _budrAssessments: budrAssessments,
    _budrOverrides: budrOverrides,
    setBudrFindings,
    setBudrAssessments,
    setBudrOverrides,
    // Dependency graph
    buildDependencyGraph,
    getBlastRadius,
    getResType,
    getResName,
    clearBlastRadius,
    resetDepGraph,
    isBlastActive,
    // RBAC engine (Azure role-based access control)
    analyzeRoleAssignments,
    findOverPrivileged,
    findOrphanedAssignments,
    countOwnersPerScope,
    findGuestPrivileges,
    findServicePrincipalRisks,
    classifyPermission,
    getScopeLevel,
    parseRBACData,
    getRBACForScope,
    // Timeline & Annotations
    Timeline: timeline_exports,
    // Phase 3: Feature Engines
    DesignMode: design_mode_exports,
    FlowTracing: flow_tracing_exports,
    FlowAnalysis: flow_analysis_exports,
    FirewallEditor: firewall_editor_exports,
    MultiTenant: multi_tenant_exports,
    // Phase 4: Dashboards & Reports
    ComplianceView: compliance_view_exports,
    UnifiedDashboard: unified_dashboard_exports,
    Governance: governance_exports,
    // Phase 5: Core
    ExportUtils: export_utils_exports,
    // IacGenerator: lazy-loaded via window._loadIacGenerator() — not in AppModules at startup
    // Note: diff-engine and report-builder loaded via separate script tags (DOM-dependent)
    // Normalization (used by app-core.js inline code via window globals)
    _normalizeAzureResources,
    _normTags,
    matchFile,
    fileMap,
    _friendlyFolderLabel
  };
  Object.assign(window, window.AppModules);
  if (!window._complianceFindings) window._complianceFindings = [];
  window._loadDemoData = function() {
    return new Promise(function(resolve) {
      if (window.generateDemo) return resolve(window.generateDemo);
      var s = document.createElement("script");
      s.src = "dist/demo-data.bundle.js";
      s.onload = function() {
        window.generateDemo = window.DemoDataModule && window.DemoDataModule.generateDemo;
        resolve(window.generateDemo);
      };
      s.onerror = function() {
        console.error("Failed to load demo-data.bundle.js");
        resolve(null);
      };
      document.head.appendChild(s);
    });
  };
  window._loadIacGenerator = function() {
    return new Promise(function(resolve) {
      if (window.IacGeneratorModule) return resolve(window.IacGeneratorModule);
      var s = document.createElement("script");
      s.src = "dist/iac-generator.bundle.js";
      s.onload = function() {
        window.IacGenerator = window.IacGeneratorModule;
        if (window.AppModules) window.AppModules.IacGenerator = window.IacGeneratorModule;
        resolve(window.IacGeneratorModule);
      };
      s.onerror = function() {
        console.error("Failed to load iac-generator.bundle.js");
        resolve(null);
      };
      document.head.appendChild(s);
    });
  };
  console.log("Azure Network Mapper modules loaded");
})();
//# sourceMappingURL=app.bundle.js.map
