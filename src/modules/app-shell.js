// #region INITIALIZATION & GLOBALS
var _mainEl=null;function _getMain(){if(!_mainEl)_mainEl=document.querySelector('.main');return _mainEl}

// Preferences: _prefs, loadPrefs, savePrefs provided by bundle (src/modules/prefs.js)
function appShellRenderContext(){
  var root=typeof globalThis!=='undefined'?globalThis:null;
  var adapter=typeof AppRenderContext!=='undefined'?AppRenderContext:(root&&root.AppRenderContext);
  return adapter&&typeof adapter.createRenderContext==='function'?adapter.createRenderContext():null;
}
function appShellHasLoadedContext(){
  var context=appShellRenderContext();
  return !!(context&&context.rlCtx);
}
function appShellSetComplianceFindings(findings){
  var context=appShellRenderContext();
  if(context)context.complianceFindings=findings||[];
}
function appShellEsc(value){
  if(typeof AppHtml!=='undefined'&&AppHtml&&typeof AppHtml.escape==='function')return AppHtml.escape(value);
  return String(value==null?'':value).replace(/[&<>"']/g,function(ch){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]});
}

// Global text size scaling - works on sidebar, canvas, and detail panel
let gTxtScale=_prefs.gTxtScale||1.0;
function applyGlobalTxtScale(){
  document.documentElement.style.setProperty('--txt-scale',gTxtScale);
  document.getElementById('gTxtVal').textContent=Math.round(gTxtScale*100)+'%';
}
document.getElementById('gTxtUp').addEventListener('click',()=>{gTxtScale=Math.min(2.5,gTxtScale+0.15);applyGlobalTxtScale();savePrefs({gTxtScale})});
document.getElementById('gTxtDown').addEventListener('click',()=>{gTxtScale=Math.max(0.5,gTxtScale-0.15);applyGlobalTxtScale();savePrefs({gTxtScale})});

// Sidebar collapse toggle
const _isMobile=()=>document.documentElement.clientWidth<=768;
document.getElementById('sidebarToggle').addEventListener('click',()=>{
  const sb=document.querySelector('.sidebar');
  const btn=document.getElementById('sidebarToggle');
  sb.classList.toggle('collapsed');
  btn.innerHTML=sb.classList.contains('collapsed')?'&#x25B6;':'&#x25C0;';
  // Show/hide mobile backdrop
  const bd=document.getElementById('mobileBackdrop');
  if(bd){bd.style.display=(!sb.classList.contains('collapsed')&&_isMobile())?'block':'none'}
  if(!_isMobile()) savePrefs({sidebarCollapsed:sb.classList.contains('collapsed')});
});
// Mobile backdrop: tap to close sidebar
(function(){
  const bd=document.createElement('div');
  bd.id='mobileBackdrop';
  bd.style.cssText='display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:99;backdrop-filter:blur(2px)';
  document.body.appendChild(bd);
  bd.addEventListener('click',()=>{
    const sb=document.querySelector('.sidebar');
    sb.classList.add('collapsed');
    document.getElementById('sidebarToggle').innerHTML='&#x25B6;';
    bd.style.display='none';
  });
})();
// Restore sidebar state (collapse on mobile by default)
if(_prefs.sidebarCollapsed||_isMobile()){
  document.querySelector('.sidebar').classList.add('collapsed');
  document.getElementById('sidebarToggle').innerHTML='&#x25B6;';
}
// Apply saved text scale on load
if(_prefs.gTxtScale) applyGlobalTxtScale();
// Cloud environment selector
(function(){
  var sel=document.getElementById('cloudEnvSelector');
  if(!sel)return;
  // Restore saved cloud env
  if(_prefs.cloudEnv){
    var savedCloud=_prefs.cloudEnv==='gcchigh'?'gcc-high':_prefs.cloudEnv;
    try{AppModules.setCloudEnv(savedCloud);sel.value=savedCloud}catch(e){sel.value=AppModules.getCloudEnv()}
  }
  sel.addEventListener('change',function(){
    try{AppModules.setCloudEnv(this.value);savePrefs({cloudEnv:this.value})}catch(e){console.warn('Invalid cloud env:',this.value);this.value=AppModules.getCloudEnv();return}
    if(appShellHasLoadedContext())renderMap();// re-render with new cloud context
  });
})();

const inputSections=[
  {t:'Network',open:true,inputs:[
    {id:'in_vnets',l:'VNets',c:'az network vnet list'},
    {id:'in_subnets',l:'Subnets',c:'az network vnet subnet list'},
    {id:'in_udrs',l:'Route Tables / UDRs',c:'az network route-table list'},
    {id:'in_nsgs',l:'NSGs',c:'az network nsg list'},
    {id:'in_nics',l:'NICs',c:'az network nic list'},
    {id:'in_pubips',l:'Public IPs',c:'az network public-ip list'},
  ]},
  {t:'Gateways',open:true,inputs:[
    {id:'in_nats',l:'NAT Gateways',c:'az network nat gateway list'},
    {id:'in_pvteps',l:'Private Endpoints',c:'az network private-endpoint list'},
    {id:'in_azfws',l:'Azure Firewalls',c:'az network firewall list'},
    {id:'in_bastions',l:'Bastions',c:'az network bastion list'},
  ]},
  {t:'Compute',open:false,inputs:[
    {id:'in_vms',l:'Virtual Machines',c:'az vm list --show-details'},
    {id:'in_sql',l:'SQL Servers',c:'az sql server list'},
    {id:'in_containers',l:'Container Instances',c:'az container list'},
    {id:'in_funcapps',l:'Function Apps',c:'az functionapp list'},
    {id:'in_elasticache',l:'Redis Cache',c:'az redis list'},
    {id:'in_aks',l:'AKS Clusters',c:'az aks list'},
    {id:'in_aspans',l:'App Service Plans',c:'az appservice plan list'},
    {id:'in_webapps',l:'Web Apps',c:'az webapp list'},
    {id:'in_acr',l:'Container Registries',c:'az acr list'},
    {id:'in_batch',l:'Batch Accounts',c:'az batch account list'},
    {id:'in_avd',l:'Virtual Desktop Host Pools',c:'az desktopvirtualization hostpool list'},
  ]},
  {t:'Load Balancers',open:false,inputs:[
    {id:'in_albs',l:'App Gateways',c:'az network application-gateway list'},
    {id:'in_tgs',l:'Load Balancers',c:'az network lb list'},
  ]},
  {t:'Connectivity',open:false,inputs:[
    {id:'in_peer',l:'VNet Peerings',c:'az network vnet peering list'},
    {id:'in_vpn',l:'VPN Connections',c:'az network vpn-connection list'},
    {id:'in_tgwatt',l:'Virtual WANs',c:'az network vwan list'},
    {id:'in_vnetgw',l:'VNet Gateways',c:'az network vnet-gateway list'},
    {id:'in_expressrt',l:'Express Route Circuits',c:'az network express-route list'},
  ]},
  {t:'Edge',open:false,inputs:[
    {id:'in_cf',l:'Front Doors',c:'az network front-door list'},
    {id:'in_cdn',l:'CDN Profiles',c:'az cdn profile list'},
    {id:'in_trafficmgr',l:'Traffic Manager',c:'az network traffic-manager profile list'},
    {id:'in_privlink',l:'Private Link Services',c:'az network private-link-service list'},
    {id:'in_ddos',l:'DDoS Protection Plans',c:'az network ddos-protection list'},
  ]},
  {t:'Storage',open:false,inputs:[
    {id:'in_disks',l:'Managed Disks',c:'az disk list'},
    {id:'in_snaps',l:'Snapshots',c:'az snapshot list'},
    {id:'in_storage',l:'Storage Accounts',c:'az storage account list'},
    {id:'in_netapp',l:'NetApp Files',c:'az netappfiles account list'},
  ]},
  {t:'DNS',open:false,inputs:[
    {id:'in_dnsz',l:'DNS Zones',c:'az network dns zone list'},
    {id:'in_r53records',l:'DNS Record Sets',c:'az network dns record-set list --zone-name &lt;zone&gt;'},
    {id:'in_pdnslinks',l:'Private DNS Zone Links',c:'az network private-dns link vnet list'},
  ]},
  {t:'Security',open:false,inputs:[
    {id:'in_waf',l:'WAF Policies',c:'az network application-gateway waf-policy list'},
    {id:'in_keyvaults',l:'Key Vaults',c:'az keyvault list'},
  ]},
  {t:'Database',open:false,inputs:[
    {id:'in_cosmosdb',l:'Cosmos DB Accounts',c:'az cosmosdb list'},
    {id:'in_synapse',l:'Synapse Workspaces',c:'az synapse workspace list'},
    {id:'in_mysql',l:'MySQL Flexible Servers',c:'az mysql flexible-server list'},
    {id:'in_postgres',l:'PostgreSQL Flexible Servers',c:'az postgres flexible-server list'},
  ]},
  {t:'Integration',open:false,inputs:[
    {id:'in_svcbus',l:'Service Bus',c:'az servicebus namespace list'},
    {id:'in_evhubs',l:'Event Hubs',c:'az eventhubs namespace list'},
    {id:'in_apim',l:'API Management',c:'az apim list'},
    {id:'in_logicapps',l:'Logic Apps',c:'az logic workflow list'},
    {id:'in_signalr',l:'SignalR Services',c:'az signalr list'},
    {id:'in_relay',l:'Relay Namespaces',c:'az relay namespace list'},
    {id:'in_adf',l:'Data Factories',c:'az datafactory list'},
    {id:'in_iothub',l:'IoT Hubs',c:'az iot hub list'},
  ]},
  {t:'Observability',open:false,inputs:[
    {id:'in_appinsights',l:'Application Insights',c:'az monitor app-insights component list'},
    {id:'in_loganalytics',l:'Log Analytics Workspaces',c:'az monitor log-analytics workspace list'},
    {id:'in_actiongroups',l:'Monitor Action Groups',c:'az monitor action-group list'},
    {id:'in_metricalerts',l:'Monitor Metric Alerts',c:'az monitor metrics alert list'},
    {id:'in_automation',l:'Automation Accounts',c:'az automation account list'},
  ]},
  {t:'AI &amp; Cognitive',open:false,inputs:[
    {id:'in_cognitive',l:'Cognitive Services',c:'az cognitiveservices account list'},
    {id:'in_mlworkspace',l:'ML Workspaces',c:'az ml workspace list'},
    {id:'in_purview',l:'Purview Accounts',c:'az purview account list'},
  ]},
  {t:'RBAC',open:false,inputs:[
    {id:'in_rbac',l:'RBAC Assignments',c:'az role assignment list --all'},
    {id:'in_managedid',l:'Managed Identities',c:'az identity list'},
    {id:'in_policyassign',l:'Policy Assignments',c:'az policy assignment list'},
  ]},
  {t:'Resource Groups',open:false,inputs:[
    {id:'in_rgs',l:'Resource Groups',c:'az group list'},
    {id:'in_arcmachines',l:'Azure Arc Machines',c:'az connectedmachine list'},
    {id:'in_recoveryvaults',l:'Recovery Services Vaults',c:'az backup vault list'},
    {id:'in_managedapps',l:'Managed Applications',c:'az managedapp list'},
    {id:'in_mapsaccts',l:'Azure Maps',c:'az maps account list'},
  ]},
];

// Subscription/account detection from Azure resource data
function detectAccountId(resource){
  if(!resource)return null;
  // 1. Check subscriptionId field (Azure resources)
  if(resource.subscriptionId)return resource.subscriptionId;
  // 2. Parse subscription from Azure resource ID
  const idFields=['id','resourceId','vnetId','subnetId','nsgId'];
  for(const f of idFields){
    const rid=resource[f];
    if(rid&&typeof rid==='string'){const m=rid.match(/\/subscriptions\/([^\/]+)\//i);if(m)return m[1]}
  }
  // 3. Check nested structures
  if(resource.properties?.subnets?.[0]?.id){const m=resource.properties.subnets[0].id.match(/\/subscriptions\/([^\/]+)\//i);if(m)return m[1]}
  return null;
}
function detectRegion(resource){
  if(!resource)return null;
  // 1. Azure location field
  if(resource.location)return resource.location;
  if(resource.Location)return resource.Location;
  // 2. Parse location from resource group or ID tags
  if(resource.resourceGroup)return resource.resourceGroup;
  // 3. AvailabilityZone fallback (Azure regions like 'eastus2' passed through as-is)
  const az=resource.AvailabilityZone||(resource.Placement&&resource.Placement.AvailabilityZone)||null;
  if(az&&typeof az==='string')return az;
  return null;
}

// Account colors for multi-account visual differentiation
const _accountColors=['#60a5fa','#f59e0b','#10b981','#8b5cf6','#ef4444','#06b6d4','#ec4899','#84cc16'];
let _accountColorMap={};
function getAccountColor(accountId){
  if(!accountId||accountId==='default')return null;
  if(!_accountColorMap[accountId]){
    const idx=Object.keys(_accountColorMap).length%_accountColors.length;
    _accountColorMap[accountId]=_accountColors[idx];
  }
  return _accountColorMap[accountId];
}

function _acctPill(accountId){
  if(!accountId)return'';
  var c=getAccountColor(accountId);
  var lbl=typeof _rptAccountLabel==='function'?_rptAccountLabel(accountId):accountId;
  if(!lbl)return'';
  return '<span class="acct-pill" style="background:'+(c?c+'22':'rgba(255,255,255,.06)')+'"><span class="acct-dot" style="background:'+(c||'var(--text-muted)')+'"></span>'+appShellEsc(lbl)+'</span>';
}
// build sidebar
const sb=document.getElementById('sidebarBody');
// Account label input at top of sidebar
const acctDiv=document.createElement('div');
acctDiv.style.cssText='padding:4px 8px;margin-bottom:4px';
acctDiv.innerHTML='<div style="display:flex;align-items:center;gap:6px"><label style="font-family:Segoe UI,system-ui,sans-serif;font-size:8px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;flex-shrink:0">Account</label><input id="accountLabel" style="flex:1;background:var(--bg-input);border:1px solid var(--border);border-radius:4px;color:var(--text-primary);font-family:Segoe UI,system-ui,sans-serif;font-size:9px;padding:3px 6px" placeholder="Account ID or alias (optional)"></div>';
sb.appendChild(acctDiv);
inputSections.forEach(sec=>{
  const openByDefault=_isMobile()?false:sec.open;
  const h=document.createElement('div');h.className='sec-hdr'+(openByDefault?'':' collapsed');
  const dotColor=sec.t.includes('Network')?'var(--accent-blue)':sec.t.includes('Gateway')?'var(--accent-green)':sec.t.includes('Compute')?'var(--accent-cyan)':sec.t.includes('Load')?'var(--accent-cyan)':sec.t.includes('Connectivity')?'var(--accent-purple)':sec.t.includes('Edge')?'var(--accent-orange)':sec.t.includes('Security')?'var(--accent-red)':sec.t.includes('DNS')?'var(--accent-purple)':sec.t.includes('Storage')?'var(--accent-green)':sec.t.includes('Database')?'var(--accent-orange)':sec.t.includes('IAM')?'var(--accent-orange)':'var(--text-muted)';
  h.innerHTML=`<span class="sec-dot" style="background:${dotColor}"></span><span>${sec.t}</span><span class="arr">&#9660;</span>`;
  const b=document.createElement('div');b.className='sec-body'+(openByDefault?'':' hidden');
  let html='';sec.inputs.forEach(inp=>{html+=`<div class="ig"><div class="ig-lbl"><span>${inp.l}</span><code>${inp.c}</code></div><textarea id="${inp.id}" class="ji" placeholder="Paste ${inp.c} JSON..."></textarea></div>`});b.innerHTML=html;
  h.addEventListener('click',()=>{h.classList.toggle('collapsed');b.classList.toggle('hidden')});
  sb.appendChild(h);sb.appendChild(b);
});
document.querySelectorAll('.ji').forEach(el=>{el.addEventListener('input',function(){_sessionDirty=true;_dirtyInputs.add(this.id);if(!this.value.trim()){this.className='ji';return}try{JSON.parse(this.value);this.className='ji valid'}catch(e){this.className='ji invalid'}})});

// Utility functions and constants now loaded from bundle:
// - constants.js: SEV_ORDER, FW_LABELS, EOL_RUNTIMES, etc.
// - utils.js: safeParse, ext, esc, gn, sid, clsGw, isShared, gcv, gch, gv
// - dom-helpers.js: showToast and small DOM utilities.

// CIDR engine now loaded from bundle (src/modules/cidr-engine.js)

// === CHECKOV (CKV) ID MAPPING ===
// Maps existing control IDs to their Checkov equivalents for unified compliance view
const _CKV_MAP={
  // CIS / NET → Checkov Azure
  'CIS 5.2':'CKV_AZURE_10',  // SSH from 0.0.0.0/0 (NSG SSH access)
  'CIS 5.3':'CKV_AZURE_9',   // RDP from 0.0.0.0/0 (NSG RDP access)
  'CIS 5.4':'CKV_AZURE_77',  // Default NSG restricts all traffic
  'NET-2':'CKV_AZURE_10',    // All traffic from 0.0.0.0/0
  // ARCH → Checkov Azure
  'ARCH-C2':'CKV_AZURE_93',  // Managed Disk encryption
  'ARCH-D1':'CKV_AZURE_43',  // SQL Server publicly accessible
  'ARCH-D2':'CKV_AZURE_95',  // SQL DB geo-redundant backup
  'ARCH-D3':'CKV_AZURE_24',  // SQL Database encryption at rest (TDE)
  'ARCH-D5':'CKV_AZURE_123', // Synapse workspace encryption
  'ARCH-D6':'CKV_AZURE_55',  // Redis Cache at-rest encryption
  'ARCH-D7':'CKV_AZURE_123', // Synapse publicly accessible
  'ARCH-S1':'CKV_AZURE_33',  // Storage Account default encryption
  'ARCH-E2':'CKV_AZURE_15',  // Front Door HTTPS redirect
  'ARCH-C4':'CKV_AZURE_70',  // Function App runtime version
  // SOC2 → Checkov Azure
  'SOC2-CC7.2':'CKV_AZURE_12',// NSG flow logs
  'SOC2-C1.2':'CKV_AZURE_93', // Managed Disk encryption
  'SOC2-C1.3':'CKV_AZURE_91', // Redis Cache TLS
  // PCI → Checkov Azure
  'PCI-3.4.1':'CKV_AZURE_93', // Encryption at rest (Disk/SQL/Storage)
  'PCI-10.2.1':'CKV_AZURE_12',// NSG flow logs
  'PCI-11.3.1':'CKV_AZURE_43',// SQL Server publicly accessible
  // RBAC → Checkov Azure
  'IAM-1':'CKV_AZURE_80',    // Owner role assignment
  'IAM-3':'CKV_AZURE_22',    // MFA for users
  'IAM-11':'CKV_AZURE_22',   // Console without MFA
  'IAM-13':'CKV_AZURE_23',   // Password policy
};

// Shared map/session state lives in render-context.js.
var gwNames={}; // gateway name lookup: populated by _renderMapInner, used globally
let _showNested=false;
let _detailLevel=0; // 0=collapsed(VPC+subnet names), 1=normal(resources), 2=expanded(nested children)
let _dnsRecordsExpanded=false; // DNS zones always show; toggle for individual record rows

// Compliance engine now loaded from bundle (src/modules/compliance-engine.js)
// Content-based compliance cache: prevents recomputation on expand/collapse
let _complianceDataFP='';
let _complianceCachedFindings=null;
let _budrCachedFindings=null;
let _budrCachedAssessments=null;
let _complianceCachedAssessmentGaps=null;
function _dataFingerprint(){
  let fp=JSON.stringify(['cloud',AppModules.getCloudEnv()])+';';
  document.querySelectorAll('.ji').forEach(el=>{fp+=JSON.stringify([el.id,el.value||''])+';'});
  return fp;
}
function _runComplianceWithCache(ctx){
  const fp=_dataFingerprint();
  if(fp===_complianceDataFP&&_complianceCachedFindings){
    ctx.assessmentGaps=Object.assign({},_complianceCachedAssessmentGaps||{});
    // Restore cached BUDR globals
    if(_budrCachedFindings)_budrFindings=_budrCachedFindings;
    if(_budrCachedAssessments)_budrAssessments=_budrCachedAssessments;
    appShellSetComplianceFindings(_complianceCachedFindings);
    return _complianceCachedFindings;
  }
  // Data changed: reset stale classification and recompute
  GovernanceClassification.reset();
  // The renderer retains these collection names; assessment engines use Azure names.
  ctx.storageAccounts=ctx.storageAccounts||ctx.s3bk||[];
  ctx.managedDisks=ctx.managedDisks||ctx.volumes||[];
  if(typeof _compDashState!=='undefined')_compDashState._cachedView=null;
  if(typeof _inventoryData!=='undefined')_inventoryData=[];
  if(typeof invalidateComplianceCache==='function')invalidateComplianceCache();
  // Native CLI exports are assignment arrays, not legacy IAM policy documents.
  if(!(ctx._multiTenant&&ctx.rbac)){
    ctx.rbac=typeof parseRBACData==='function'?parseRBACData(safeParse(gv('in_rbac'))):null;
  }
  // A blank collector input is unknown; a supplied [] is an assessed empty set.
  [['logAnalyticsWorkspaces','in_loganalytics'],['recoveryVaults','in_recoveryvaults']].forEach(function(pair){
    if(ctx._multiTenant)return;
    delete ctx[pair[0]];
    const text=gv(pair[1]);
    if(text&&text.trim()){
      const raw=safeParse(text);
      if(Array.isArray(raw))ctx[pair[0]]=raw;
      else if(raw&&Array.isArray(raw.value))ctx[pair[0]]=raw.value;
    }
  });
  if(typeof _iamReviewData!=='undefined')_iamReviewData=[];
  const findings=runComplianceChecks(ctx);
  // Enrich findings with account/region/vpc from tagged resources
  const _fResLookup={};
  const _fAdd=function(id,r,v){if(id)_fResLookup[String(id).toLowerCase()]={a:r._subscriptionId||((String(id).match(/\/subscriptions\/([^/]+)/i)||[])[1])||'',r:r._region||r.location||'',v:v||''}};
  (ctx.nsgs||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.udrs||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.vms||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.vnets||[]).forEach(r=>{_fAdd(r.id,r,r.id)});
  (ctx.subnets||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.sqlServers||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.functionApps||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.appGateways||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.storageAccounts||[]).forEach(r=>{_fAdd(r.id,r,'')});
  (ctx.redisCaches||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.synapseWorkspaces||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.volumes||[]).forEach(r=>{_fAdd(r.id,r,'')});
  (ctx.snapshots||[]).forEach(r=>{_fAdd(r.id,r,'')});
  (ctx.containerInstances||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId||'')});
  (ctx.nics||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.firewalls||[]).forEach(r=>{_fAdd(r.id,r,'')});
  (ctx.nats||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.privateEndpoints||[]).forEach(r=>{_fAdd(r.id,r,r.vnetId)});
  (ctx.vpnGateways||[]).forEach(r=>{_fAdd(r.id,r,'')});
  (ctx.wafPolicies||[]).forEach(r=>{_fAdd(r.id,r,'')});
  (ctx.peerings||[]).forEach(r=>{_fAdd(r.id,r,'')});
  findings.forEach(f=>{
    const identity=f.resourceId||f.resource||'';
    const info=_fResLookup[String(identity).toLowerCase()];
    if(info){f._subscriptionId=info.a;f._region=info.r;f._vpcId=info.v}
    else if(!f._subscriptionId){const match=String(identity).match(/\/subscriptions\/([^/]+)/i);if(match)f._subscriptionId=match[1]}
  });
  _complianceDataFP=fp;
  _complianceCachedFindings=findings;
  appShellSetComplianceFindings(findings);
  _budrCachedFindings=_budrFindings;
  _budrCachedAssessments=_budrAssessments;
  _complianceCachedAssessmentGaps=Object.assign({},ctx.assessmentGaps||{});
  return findings;
}
// #endregion INITIALIZATION & GLOBALS

