// #region REPORT BUILDER
// === REPORT RENDER FUNCTIONS ===

function reportSectionRuntime(){
  if(typeof AppRenderContext!=='undefined'&&AppRenderContext.createRenderContext){
    return AppRenderContext.createRenderContext();
  }
  return {rlCtx:null,complianceFindings:[]};
}

function reportSectionContext(){
  if(typeof _importedReportData!=='undefined'&&_importedReportData)return null;
  return reportSectionRuntime().rlCtx||null;
}

function reportSectionComplianceRows(){
  return reportSectionRuntime().complianceFindings||[];
}

function _azurePortalUrl(type,id,region){
  if(!id) return '';
  var base='https://portal.azure.com/#resource';
  // Azure resource IDs are full ARM paths; fall back to search if only short id supplied
  var isArmId=id.startsWith('/subscriptions/');
  if(isArmId){
    // Direct deep-link by ARM resource ID
    var bladeMap={
      'VNet':'Microsoft.Network/virtualNetworks',
      'Subnet':'Microsoft.Network/virtualNetworks',
      'VM':'Microsoft.Compute/virtualMachines',
      'SQL':'Microsoft.Sql/servers',
      'SQL Server':'Microsoft.Sql/servers',
      'App Gateway':'Microsoft.Network/applicationGateways',
      'Function App':'Microsoft.Web/sites',
      'Container':'Microsoft.ContainerInstance/containerGroups',
      'Redis Cache':'Microsoft.Cache/Redis',
      'RedisCache':'Microsoft.Cache/Redis',
      'Synapse':'Microsoft.Synapse/workspaces',
      'NSG':'Microsoft.Network/networkSecurityGroups',
      'UDR':'Microsoft.Network/routeTables',
      'Route Table':'Microsoft.Network/routeTables',
      'NAT Gateway':'Microsoft.Network/natGateways',
      'Private Endpoint':'Microsoft.Network/privateEndpoints',
      'Managed Disk':'Microsoft.Compute/disks',
      'Disk':'Microsoft.Compute/disks',
      'Storage Account':'Microsoft.Storage/storageAccounts',
      'StorageAccount':'Microsoft.Storage/storageAccounts',
      'DNS Zone':'Microsoft.Network/privateDnsZones',
      'Front Door':'Microsoft.Cdn/profiles',
      'FrontDoor':'Microsoft.Cdn/profiles',
      'VNet Peering':'Microsoft.Network/virtualNetworks',
      'NIC':'Microsoft.Network/networkInterfaces',
      'Azure Firewall':'Microsoft.Network/azureFirewalls',
      'Firewall':'Microsoft.Network/azureFirewalls',
      'AppGateway':'Microsoft.Network/applicationGateways',
      'FunctionApp':'Microsoft.Web/sites'
    };
    return base+id+'/overview';
  }
  // Fallback: Azure portal search
  return 'https://portal.azure.com/#search/'+encodeURIComponent(id);
}
function _rptLink(type,id,region,text){
  var url=_azurePortalUrl(type,id,region);
  if(!url) return esc(text||id||'');
  return '<a href="'+esc(url)+'" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline dotted;text-underline-offset:2px" title="Open in Azure Portal">'+esc(text||id)+'</a>';
}

function _rptGetAccountFilter(){
  var el=document.getElementById('rptAccountFilter');
  return el?el.value:'all';
}

function _rptAccountLabel(accountId){
  if(!accountId) return '';
  var ctx=_loadedContexts.find(function(c){return c.accountId===accountId});
  if(ctx&&ctx.accountLabel&&ctx.accountLabel!==ctx.accountId) return ctx.accountLabel;
  if(accountId.length>12) return accountId.slice(0,4)+'…'+accountId.slice(-4);
  return accountId;
}

function _rptFilterByAccount(items, acctId){
  if(!acctId||acctId==='all') return items;
  var lbl=_rptAccountLabel(acctId);
  return items.filter(function(item){
    var scopeSubscription=String(item.scope||'').match(/\/subscriptions\/([^/]+)/i);
    var resourceSubscription=String(item.id||item.resourceId||item._raw?.id||'').match(/\/subscriptions\/([^/]+)/i);
    var id=item._subscriptionId||(scopeSubscription?scopeSubscription[1]:'')||(resourceSubscription?resourceSubscription[1]:'');
    if(id)return id===acctId;
    return item.account===acctId||(item.account===lbl&&_loadedContexts.filter(function(c){return(c.accountLabel||c.accountId)===lbl}).length===1);
  });
}

function _rptUniqueAccounts(){
  if(_loadedContexts.length>1){
    return _loadedContexts.map(function(c){return {id:c.accountId,label:c.accountLabel||c.accountId}});
  }
  return [];
}

function _rptExecSummary(ctx, opts){
  var c=ctx||reportSectionContext();
  if(!c&&!_importedReportData) return '<section class="rpt-section" id="s-exec-summary"><h2>Executive Summary</h2><p>No data loaded.</p></section>';
  if(!c&&_importedReportData){
    var h='<section class="rpt-section" id="s-exec-summary"><h2>Executive Summary</h2>';
    h+='<p class="rpt-import-notice">Data imported from previous report'+(_importedReportData.date?' ('+esc(_importedReportData.date)+')':'')+'.</p>';
    var _acctF=_rptGetAccountFilter();
    var _efF=_rptFilterByAccount(reportSectionComplianceRows(),_acctF);
    var _ebF=_rptFilterByAccount(_budrAssessments||[],_acctF);
    var _eiF=_rptFilterByAccount(_inventoryData||[],_acctF);
    h+='<div class="stat-grid">';
    h+='<div class="stat-box"><span class="val">'+_efF.length+'</span><span class="lbl">Findings</span></div>';
    h+='<div class="stat-box"><span class="val">'+_ebF.length+'</span><span class="lbl">BUDR Assessments</span></div>';
    h+='<div class="stat-box"><span class="val">'+_eiF.length+'</span><span class="lbl">Inventory Resources</span></div>';
    h+='</div>';
    h+=_rptExecCompliance();
    h+=_rptExecBUDR();
    h+='</section>';
    return h;
  }
  var counts=[
    {key:'vnets',label:'VNets'},{key:'subnets',label:'Subnets'},
    {key:'vms',label:'VMs'},{key:'sqlServers',label:'SQL'},
    {key:'appGateways',label:'AppGWs'},{key:'containerInstances',label:'Containers'},
    {key:'functionApps',label:'FuncApps'},{key:'nsgs',label:'NSGs'}
  ];
  var h='<section class="rpt-section" id="s-exec-summary"><h2>Executive Summary</h2>';
  h+='<div class="stat-grid">';
  counts.forEach(function(item){
    var v=(c[item.key]||[]).length;
    h+='<div class="stat-box"><span class="val">'+v+'</span>';
    h+='<span class="lbl">'+esc(item.label)+'</span></div>';
  });
  h+='</div>';
  h+=_rptExecCompliance();
  h+=_rptExecBUDR();
  h+='</section>';
  return h;
}

function _rptExecCompliance(){
  var f=_rptFilterByAccount(reportSectionComplianceRows(), _rptGetAccountFilter());
  if(!f||!f.length) return '';
  var sevs={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  f.forEach(function(x){sevs[x.severity]=(sevs[x.severity]||0)+1});
  var h='<h3>Compliance Posture</h3><p>'+f.length+' total findings: ';
  var parts=[];
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(function(s){
    if(sevs[s]>0) parts.push('<span class="sev-badge sev-'+s+'">'+sevs[s]+' '+s+'</span>');
  });
  h+=parts.join(' ')+'</p>';
  return h;
}

function _rptExecBUDR(){
  var filteredBudr=_rptFilterByAccount(_budrAssessments||[], _rptGetAccountFilter());
  if(!filteredBudr.length) return '';
  var counts={protected:0,partial:0,at_risk:0,unknown:0};
  filteredBudr.forEach(function(a){if(a.profile&&counts[a.profile.tier]!==undefined)counts[a.profile.tier]++});
  var h='<h3>BUDR Posture</h3><div class="stat-grid">';
  var tiers=[
    {k:'protected',label:'Protected',cls:'tier-protected',color:'#10b981'},
    {k:'partial',label:'Partial',cls:'tier-partial',color:'#f59e0b'},
    {k:'at_risk',label:'At Risk',cls:'tier-at_risk',color:'#ef4444'}
  ];
  if(counts.unknown)tiers.push({k:'unknown',label:'Not Assessed',color:'#64748b'});
  tiers.forEach(function(t){
    var v=counts[t.k]||0;
    h+='<div class="stat-box" style="border-color:'+t.color+'">';
    h+='<span class="val" style="color:'+t.color+'">'+v+'</span>';
    h+='<span class="lbl">'+esc(t.label)+'</span></div>';
  });
  h+='</div>';
  return h;
}

function _rptAppSummary(ctx, opts){
  var scopedApps=_rptScopedApps();
  if(!scopedApps.length) return '';
  var tierPri={critical:1,high:2,medium:3,low:4};
  var classificationRows=_rptFilterByAccount(GovernanceClassification.data,_rptGetAccountFilter());
  var h='<section class="rpt-section" id="s-app-summary"><h2>Application Summary</h2>';
  h+='<p>'+scopedApps.length+' applications identified across '+classificationRows.length+' resources.</p>';
  // Build app data with matched resources
  var appRows=[];
  scopedApps.forEach(function(app){
    var matched=_rptFilterByAccount(_matchAppResources(app),_rptGetAccountFilter());
    var bestTier='low';
    matched.forEach(function(r){if((tierPri[r.tier]||99)<(tierPri[bestTier]||99)) bestTier=r.tier});
    var tier=app.tier||bestTier;
    appRows.push({name:app.name,type:app.type||'—',tier:tier,matched:matched});
  });
  appRows.sort(function(a,b){return(tierPri[a.tier]||99)-(tierPri[b.tier]||99)});
  // Summary table
  var tierColors={critical:'#ef4444',high:'#f59e0b',medium:'#22d3ee',low:'#64748b'};
  h+='<table class="rpt-tbl" style="width:100%;border-collapse:collapse;margin:12px 0 20px">';
  h+='<thead><tr><th style="text-align:left;padding:6px 10px;border-bottom:2px solid #334155">Application</th>';
  h+='<th style="text-align:left;padding:6px 10px;border-bottom:2px solid #334155">Type</th>';
  h+='<th style="text-align:left;padding:6px 10px;border-bottom:2px solid #334155">Criticality</th>';
  h+='<th style="text-align:center;padding:6px 10px;border-bottom:2px solid #334155">Resources</th>';
  h+='<th style="text-align:left;padding:6px 10px;border-bottom:2px solid #334155">RPO</th>';
  h+='<th style="text-align:left;padding:6px 10px;border-bottom:2px solid #334155">RTO</th></tr></thead><tbody>';
  appRows.forEach(function(a){
    var meta=GovernanceClassification.tierMeta(a.tier);
    h+='<tr><td style="padding:5px 10px;border-bottom:1px solid #1e293b;font-weight:500">'+esc(a.name)+'</td>';
    h+='<td style="padding:5px 10px;border-bottom:1px solid #1e293b">'+esc(a.type)+'</td>';
    h+='<td style="padding:5px 10px;border-bottom:1px solid #1e293b"><span style="color:'+meta.color+';font-weight:600;text-transform:uppercase">'+a.tier+'</span></td>';
    h+='<td style="padding:5px 10px;border-bottom:1px solid #1e293b;text-align:center">'+a.matched.length+'</td>';
    h+='<td style="padding:5px 10px;border-bottom:1px solid #1e293b">'+meta.rpo+'</td>';
    h+='<td style="padding:5px 10px;border-bottom:1px solid #1e293b">'+meta.rto+'</td></tr>';
  });
  h+='</tbody></table>';
  // Per-app resource detail
  appRows.forEach(function(a){
    if(!a.matched.length) return;
    var meta=GovernanceClassification.tierMeta(a.tier);
    h+='<h3 style="margin-top:18px;color:'+meta.color+'">'+esc(a.name)+' <span style="font-weight:normal;font-size:12px;color:#94a3b8">('+a.matched.length+' resources)</span></h3>';
    h+='<table class="rpt-tbl" style="width:100%;border-collapse:collapse;margin:6px 0 16px;font-size:12px">';
    h+='<thead><tr><th style="text-align:left;padding:4px 8px;border-bottom:1px solid #334155">Resource</th>';
    h+='<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #334155">Type</th>';
    h+='<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #334155">Tier</th>';
    h+='<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #334155">VNet</th></tr></thead><tbody>';
    a.matched.forEach(function(r){
      var rm=GovernanceClassification.tierMeta(r.tier);
      h+='<tr><td style="padding:3px 8px;border-bottom:1px solid #1e293b">'+esc(r.name)+'</td>';
      h+='<td style="padding:3px 8px;border-bottom:1px solid #1e293b">'+esc(r.type)+'</td>';
      h+='<td style="padding:3px 8px;border-bottom:1px solid #1e293b;color:'+rm.color+'">'+r.tier+'</td>';
      h+='<td style="padding:3px 8px;border-bottom:1px solid #1e293b">'+esc(r.vpcName||'—')+'</td></tr>';
    });
    h+='</tbody></table>';
  });
  h+='</section>';
  return h;
}

function _rptScopedApps(){
  var account=_rptGetAccountFilter();
  if(!account||account==='all')return _appRegistry;
  return _appRegistry.filter(function(app){return _rptFilterByAccount(_matchAppResources(app),account).length>0});
}

function _rptArchDiagram(ctx, opts){
  var h='<section class="rpt-section" id="s-architecture"><h2>Architecture Diagram</h2>';
  var svgEl=document.getElementById('mapSvg');
  var root=svgEl?svgEl.querySelector('.map-root'):null;
  if(!root){return h+'<p>No map rendered.</p></section>'}
  try{
    var uri=_rptBuildSvgUri(svgEl,root);
    h+='<img class="diagram-img" src="'+uri+'" alt="Architecture diagram">';
  }catch(e){
    h+='<p>Error generating diagram: '+esc(e.message)+'</p>';
  }
  h+='</section>';
  return h;
}

function _rptCompliance(ctx, opts){
  var f=_rptFilterByAccount(reportSectionComplianceRows(), _rptGetAccountFilter());
  var h='<section class="rpt-section" id="s-compliance"><h2 class="rpt-section-toggle">Compliance Findings</h2>';
  var gaps=Object.keys(_importedReportData?_importedReportData.assessmentGaps||{}:(ctx||reportSectionContext()||{}).assessmentGaps||{});
  if(gaps.length)h+='<p>Not assessed (data unavailable): '+gaps.map(esc).join(', ')+'. These controls are excluded from failure counts.</p>';
  if(!f||!f.length){return h+'<p>No compliance findings.</p></section>'}
  var fwMap={};
  f.forEach(function(x){
    var fw=x.framework||'OTHER';
    if(!fwMap[fw]) fwMap[fw]=[];
    fwMap[fw].push(x);
  });
  var fwKeys=Object.keys(fwMap);
  h+='<div class="rpt-section-body">';
  h+='<nav class="rpt-jump-nav">';
  fwKeys.forEach(function(fw){
    var label=_FW_LABELS[fw]||fw;
    h+='<a href="#s-compliance-'+esc(fw)+'" class="rpt-jump-link">'+esc(label)+'<span class="rpt-jump-ct">'+fwMap[fw].length+'</span></a>';
  });
  h+='</nav>';
  fwKeys.forEach(function(fw){
    var label=_FW_LABELS[fw]||fw;
    var items=fwMap[fw];
    var tableId='rpt-tbl-compliance-'+fw;
    h+='<div id="s-compliance-'+esc(fw)+'">';
    h+='<h3>'+esc(label)+' ('+items.length+')</h3>';
    h+='<div class="rpt-table-wrap" id="'+tableId+'">';
    var hasAcctData=items.some(function(f){return!!f._subscriptionId});
    h+=_rptBuildToolbar(tableId,{severities:true,accounts:hasAcctData?_rptUniqueAccounts():[]});
    h+=_rptGroupedFindingsTable(items);
    h+='</div></div>';
  });
  h+='</div>';
  h+='</section>';
  return h;
}

function _rptGroupedFindingsTable(items){
  /* Group findings by control */
  var ctrlMap={};
  items.forEach(function(f){
    var key=f.control||'UNKNOWN';
    if(!ctrlMap[key]) ctrlMap[key]={control:key,severity:f.severity,finding:f.message,resources:[]};
    ctrlMap[key].resources.push(f);
    /* Use highest severity for summary row */
    var cur=_SEV_ORDER[ctrlMap[key].severity]||9;
    var nw=_SEV_ORDER[f.severity]||9;
    if(nw<cur) ctrlMap[key].severity=f.severity;
  });
  var groups=Object.keys(ctrlMap).map(function(k){return ctrlMap[k]});
  groups.sort(function(a,b){
    return (_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9);
  });
  var h='<button class="rpt-expand-all" type="button">Expand All</button>';
  h+='<table><thead class="rpt-sticky"><tr>';
  h+='<th class="rpt-sortable" data-sort-type="severity">Severity</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Control</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Affected</th>';
  h+='<th>Finding</th>';
  h+='</tr></thead><tbody>';
  groups.forEach(function(g){
    var sev=g.severity;
    var accts={};g.resources.forEach(function(f){if(f._subscriptionId)accts[f._subscriptionId]=1});
    var acctStr=Object.keys(accts).join('|');
    h+='<tr class="rpt-ctrl-row" data-sev="'+esc(sev)+'"'+(acctStr?' data-account="'+esc(acctStr)+'"':'')+'>';
    h+='<td><span class="sev-badge sev-'+esc(sev)+'">'+esc(sev)+'</span></td>';
    h+='<td><span class="rpt-ctrl-toggle">&#9654;</span> '+esc(g.control)+'</td>';
    h+='<td>'+g.resources.length+'</td>';
    h+='<td>'+esc(g.finding)+'</td>';
    h+='</tr>';
    /* Detail row: single row with nested table, hidden by default */
    h+='<tr class="rpt-ctrl-detail" data-sev="'+esc(sev)+'" style="display:none">';
    h+='<td colspan="4"><table class="rpt-detail-table"><tbody>';
    g.resources.forEach(function(f){
      h+='<tr>';
      h+='<td><span class="sev-badge sev-'+esc(f.severity)+'">'+esc(f.severity)+'</span></td>';
      h+='<td>'+esc(_rptAccountLabel(f._subscriptionId))+'</td>';
      h+='<td>'+esc(f.resourceName||f.resource)+'</td>';
      h+='<td>'+esc(f.message)+'</td>';
      h+='<td>'+esc(f.remediation)+'</td>';
      h+='</tr>';
    });
    h+='</tbody></table></td></tr>';
  });
  h+='</tbody></table>';
  return h;
}

function _rptFindingsTable(items){
  var h='<table><thead class="rpt-sticky"><tr>';
  h+='<th class="rpt-sortable" data-sort-type="text">Account</th>';
  h+='<th class="rpt-sortable" data-sort-type="severity">Severity</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Framework</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Control</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Resource</th>';
  h+='<th>Finding</th><th>Remediation</th>';
  h+='</tr></thead><tbody>';
  items.forEach(function(f){
    var fw=f.framework||'OTHER';
    h+='<tr data-sev="'+esc(f.severity)+'" data-fw="'+esc(fw)+'" data-account="'+esc(f._subscriptionId||'')+'">';
    h+='<td>'+esc(_rptAccountLabel(f._subscriptionId))+'</td>';
    h+='<td><span class="sev-badge sev-'+esc(f.severity)+'">'+esc(f.severity)+'</span></td>';
    h+='<td>'+esc(_FW_LABELS[fw]||fw)+'</td>';
    h+='<td>'+esc(f.control)+(f.ckv?' <span style="opacity:.5;font-size:9px">('+esc(f.ckv)+')</span>':'')+'</td>';
    h+='<td>'+esc(f.resourceName||f.resource)+'</td>';
    h+='<td>'+esc(f.message)+'</td>';
    h+='<td>'+esc(f.remediation)+'</td>';
    h+='</tr>';
  });
  h+='</tbody></table>';
  return h;
}

function _rptBUDR(ctx, opts){
  var _filteredBudr=_rptFilterByAccount(_budrAssessments||[], _rptGetAccountFilter());
  var h='<section class="rpt-section" id="s-budr"><h2 class="rpt-section-toggle">BUDR Assessment</h2>';
  if(!_filteredBudr||!_filteredBudr.length){
    return h+'<p>No BUDR assessments available.</p></section>';
  }
  // Compute tier counts from filtered data
  var counts={protected:0,partial:0,at_risk:0,unknown:0};
  _filteredBudr.forEach(function(a){if(a.profile&&counts[a.profile.tier]!==undefined)counts[a.profile.tier]++});
  var filteredBudrFindings=_rptFilterByAccount(_budrFindings||[], _rptGetAccountFilter());
  h+='<div class="rpt-section-body">';
  h+='<nav class="rpt-jump-nav">';
  h+='<a href="#s-budr-summary" class="rpt-jump-link">Summary</a>';
  h+='<a href="#s-budr-assessments" class="rpt-jump-link">Assessments<span class="rpt-jump-ct">'+_filteredBudr.length+'</span></a>';
  if(filteredBudrFindings.length) h+='<a href="#s-budr-findings" class="rpt-jump-link">Findings<span class="rpt-jump-ct">'+filteredBudrFindings.length+'</span></a>';
  h+='</nav>';
  h+='<div id="s-budr-summary">';
  h+=_rptBUDRStatGrid(counts);
  h+=_rptBUDRStrategyGrid(_filteredBudr);
  h+='</div>';
  h+=_rptBUDRAssessmentTable(_filteredBudr);
  if(filteredBudrFindings.length){
    h+='<div id="s-budr-findings"><h3>BUDR Findings ('+filteredBudrFindings.length+')</h3>';
    h+='<div class="rpt-table-wrap" id="rpt-tbl-budr-findings">';
    h+=_rptBuildToolbar('rpt-tbl-budr-findings',{severities:true,accounts:_rptUniqueAccounts()});
    h+=_rptGroupedFindingsTable(filteredBudrFindings.slice().sort(function(a,b){
      return (_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9);
    }));
    h+='</div></div>';
  }
  h+='</div></section>';
  return h;
}

function _rptBUDRStatGrid(counts){
  var tiers=[
    {k:'protected',label:'Protected',color:'#10b981'},
    {k:'partial',label:'Partial',color:'#f59e0b'},
    {k:'at_risk',label:'At Risk',color:'#ef4444'}
  ];
  if(counts.unknown)tiers.push({k:'unknown',label:'Not Assessed',color:'#64748b'});
  var h='<div class="stat-grid">';
  tiers.forEach(function(t){
    var v=counts[t.k]||0;
    h+='<div class="stat-box" style="border-color:'+t.color+'">';
    h+='<span class="val" style="color:'+t.color+'">'+v+'</span>';
    h+='<span class="lbl">'+esc(t.label)+'</span></div>';
  });
  h+='</div>';
  return h;
}

function _rptBUDRStrategyGrid(filteredAssessments){
  var strats=[
    {k:'hot',label:'Hot',color:'#ef4444'},
    {k:'warm',label:'Warm',color:'#f59e0b'},
    {k:'pilot',label:'Pilot Light',color:'#6366f1'},
    {k:'cold',label:'Cold',color:'#64748b'}
  ];
  var counts={};
  (filteredAssessments||_budrAssessments).forEach(function(a){
    var s=a.profile?a.profile.strategy:'unknown';
    counts[s]=(counts[s]||0)+1;
  });
  var h='<div class="stat-grid" style="margin-top:12px">';
  strats.forEach(function(s){
    var v=counts[s.k]||0;
    h+='<div class="stat-box" style="border-color:'+s.color+'">';
    h+='<span class="val" style="color:'+s.color+'">'+v+'</span>';
    h+='<span class="lbl">'+esc(s.label)+'</span></div>';
  });
  h+='</div>';
  h+=_rptBUDRStrategyLegend();
  return h;
}

function _rptBUDRStrategyLegend(){
  var h='<div style="margin-top:10px;padding:10px 12px;background:var(--bg-tertiary);border-radius:6px;font-size:11px;font-family:Segoe UI,system-ui,sans-serif">';
  h+='<div style="color:var(--text-muted);font-weight:600;margin-bottom:6px;font-size:10px;letter-spacing:.5px">DR STRATEGY REFERENCE</div>';
  _BUDR_STRATEGY_LEGEND.forEach(function(s){
    h+='<div style="display:flex;align-items:baseline;gap:6px;margin-bottom:3px">';
    h+='<span style="color:'+s.color+';font-weight:700;min-width:100px"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:'+s.color+';margin-right:4px;vertical-align:middle"></span>'+esc(s.label)+'</span>';
    h+='<span style="color:var(--text-secondary)">'+esc(s.desc)+'</span>';
    h+='</div>';
  });
  h+='</div>';
  return h;
}

function _rptBUDRAssessmentTable(assessments){
  var data=assessments||_budrAssessments;
  var tierOrder={at_risk:0,partial:1,protected:2};
  var sorted=data.slice().sort(function(a,b){
    var ta=a.profile?tierOrder[a.profile.tier]:9;
    var tb=b.profile?tierOrder[b.profile.tier]:9;
    if(ta!==tb) return ta-tb;
    var sa=a.profile?(_BUDR_STRATEGY_ORDER[a.profile.strategy]||9):9;
    var sb=b.profile?(_BUDR_STRATEGY_ORDER[b.profile.strategy]||9):9;
    return sa-sb;
  });
  var h='<div id="s-budr-assessments"><h3>Assessments ('+sorted.length+')</h3>';
  h+='<div class="rpt-table-wrap" id="rpt-tbl-budr">';
  h+=_rptBuildToolbar('rpt-tbl-budr',{tiers:true,strategies:true,accounts:_rptUniqueAccounts()});
  h+='<table><thead class="rpt-sticky"><tr>';
  h+='<th class="rpt-sortable" data-sort-type="text">Account</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Type</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Resource</th>';
  h+='<th class="rpt-sortable" data-sort-type="tier">Tier</th>';
  h+='<th class="rpt-sortable" data-sort-type="strategy">Strategy</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">RTO</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">RPO</th>';
  h+='<th>Signals</th>';
  h+='</tr></thead><tbody>';
  sorted.forEach(function(a){
    var tier=a.profile?a.profile.tier:'unknown';
    var cls='tier-'+tier;
    var tierLabel={protected:'Protected',partial:'Partial',at_risk:'At Risk',unknown:'Not Assessed'}[tier]||tier;
    var rto=a.profile?a.profile.rto:'N/A';
    var rpo=a.profile?a.profile.rpo:'N/A';
    var strategy=a.profile?a.profile.strategy:'unknown';
    var stratLabel=_BUDR_STRATEGY[strategy]||strategy;
    var sigs=a.signals?_rptFormatSignals(a.signals):'';
    h+='<tr data-tier="'+esc(tier)+'" data-strategy="'+esc(strategy)+'" data-account="'+esc(a.account||'')+'">';
    h+='<td>'+esc(_rptAccountLabel(a.account))+'</td>';
    h+='<td>'+esc(a.type)+'</td>';
    h+='<td><a href="#res-'+esc(a.id)+'" class="rpt-res-link">'+esc(a.name||a.id)+'</a></td>';
    h+='<td><span class="'+cls+'">'+esc(tierLabel)+'</span></td>';
    h+='<td><span class="strategy-badge strategy-'+esc(strategy)+'">'+esc(stratLabel)+'</span></td>';
    var estM=_BUDR_EST_MINUTES[a.profileKey]||{};
    h+='<td title="'+(estM.rtoWhy?esc(estM.rtoWhy):'')+'">'+esc(rto)+'</td>';
    h+='<td title="'+(estM.rpoWhy?esc(estM.rpoWhy):'')+'">'+esc(rpo)+'</td>';
    h+='<td>'+esc(sigs)+'</td>';
    h+='</tr>';
  });
  h+='</tbody></table></div></div>';
  return h;
}

function _rptFormatSignals(sigs){
  return Object.keys(sigs).map(function(k){
    return k+':'+sigs[k];
  }).join(', ');
}

function _rptIAMReview(ctx, opts){
  // Ensure IAM review data is prepared
  if(!_importedReportData&&!_iamReviewData.length){
    var raw=safeParse(gv('in_rbac'));
    if(raw){var p=parseIAMData(raw);if(p)prepareIAMReviewData(p)}
  }
  var h='<section class="rpt-section" id="s-iam-review"><h2 class="rpt-section-toggle">IAM Review</h2>';
  var iamData=_rptFilterByAccount(_iamReviewData,_rptGetAccountFilter());
  if(!iamData.length){return h+'<p>No IAM data available.</p></section>'}
  h+='<div class="rpt-section-body">';
  var azureAssignments=iamData.filter(function(r){return r.provider==='azure'});
  if(azureAssignments.length){
    h+='<h4>Azure RBAC Assignments ('+azureAssignments.length+')</h4><table><thead><tr><th>Principal</th><th>Type</th><th>Role</th><th>Scope</th><th>Findings</th></tr></thead><tbody>';
    azureAssignments.forEach(function(r){h+='<tr><td>'+esc(r.name)+'</td><td>'+esc(r.type)+'</td><td>'+esc(r.roleName)+'</td><td>'+esc(r.scope)+'</td><td>'+r.findings.length+'</td></tr>'});
    h+='</tbody></table><p>MFA, sign-in history, and credentials were not assessed from role assignment data.</p>';
  }
  var roles=iamData.filter(function(r){return r.type==='Role'});
  var users=iamData.filter(function(r){return r.type==='User'&&r.provider!=='azure'});
  var admins=iamData.filter(function(r){return r.isAdmin});
  var withFindings=iamData.filter(function(r){return r.findings.length>0});
  var crossAcct=iamData.filter(function(r){return r.crossAccounts.length>0});
  // Summary
  h+='<div class="rpt-kv-grid">';
  h+='<div class="rpt-kv"><span class="rpt-kv-label">Total Entities</span><span class="rpt-kv-val">'+iamData.length+'</span></div>';
  h+='<div class="rpt-kv"><span class="rpt-kv-label">Roles</span><span class="rpt-kv-val">'+roles.length+'</span></div>';
  h+='<div class="rpt-kv"><span class="rpt-kv-label">Users</span><span class="rpt-kv-val">'+users.length+'</span></div>';
  h+='<div class="rpt-kv"><span class="rpt-kv-label" style="color:#ef4444">Admin Access</span><span class="rpt-kv-val" style="color:#ef4444">'+admins.length+'</span></div>';
  h+='<div class="rpt-kv"><span class="rpt-kv-label" style="color:#f59e0b">Cross-Account Trusts</span><span class="rpt-kv-val" style="color:#f59e0b">'+crossAcct.length+'</span></div>';
  h+='<div class="rpt-kv"><span class="rpt-kv-label" style="color:#f97316">With Findings</span><span class="rpt-kv-val" style="color:#f97316">'+withFindings.length+'</span></div>';
  h+='</div>';
  // Admin entities table
  if(admins.length){
    h+='<h4 style="color:#ef4444;margin-top:16px">Admin Access Entities ('+admins.length+')</h4>';
    h+='<table><thead><tr><th>Name</th><th>Type</th><th>Created</th><th>Last Used</th><th>Policies</th><th>Findings</th></tr></thead><tbody>';
    admins.forEach(function(r){
      h+='<tr><td>'+esc(r.name)+'</td><td>'+esc(r.type)+'</td>';
      h+='<td>'+(r.created?r.created.toISOString().split('T')[0]:'—')+'</td>';
      h+='<td>'+(r.lastUsed?r.lastUsed.toISOString().split('T')[0]:'Never')+'</td>';
      h+='<td>'+r.policies+'</td>';
      h+='<td>'+(r.findings.length||'—')+'</td></tr>';
    });
    h+='</tbody></table>';
  }
  // Cross-account trusts table
  if(crossAcct.length){
    h+='<h4 style="color:#f59e0b;margin-top:16px">Cross-Account Trust Roles ('+crossAcct.length+')</h4>';
    h+='<table><thead><tr><th>Role</th><th>Trusted Accounts</th><th>Admin</th><th>Findings</th></tr></thead><tbody>';
    crossAcct.forEach(function(r){
      h+='<tr><td>'+esc(r.name)+'</td><td>'+r.crossAccounts.map(esc).join(', ')+'</td>';
      h+='<td>'+(r.isAdmin?'<span style="color:#ef4444">Yes</span>':'No')+'</td>';
      h+='<td>'+(r.findings.length||'—')+'</td></tr>';
    });
    h+='</tbody></table>';
  }
  // Users with findings
  var usersWithIssues=users.filter(function(u){return u.findings.length>0||u.isAdmin||!u.hasMFA&&u.hasConsole});
  if(usersWithIssues.length){
    h+='<h4 style="color:#f97316;margin-top:16px">Users Requiring Attention ('+usersWithIssues.length+')</h4>';
    h+='<table><thead><tr><th>User</th><th>MFA</th><th>Console</th><th>Active Keys</th><th>Admin</th><th>Findings</th></tr></thead><tbody>';
    usersWithIssues.forEach(function(u){
      h+='<tr><td>'+esc(u.name)+'</td>';
      h+='<td>'+(u.hasMFA?'Yes':'<span style="color:#ef4444">No</span>')+'</td>';
      h+='<td>'+(u.hasConsole?'Yes':'No')+'</td>';
      h+='<td>'+(u.activeKeys||0)+'</td>';
      h+='<td>'+(u.isAdmin?'<span style="color:#ef4444">Yes</span>':'No')+'</td>';
      h+='<td>'+(u.findings.length||'—')+'</td></tr>';
    });
    h+='</tbody></table>';
  }
  h+='</div></section>';
  return h;
}

function _rptInventory(ctx, opts){
  var h='<section class="rpt-section" id="s-inventory"><h2 class="rpt-section-toggle">Resource Inventory</h2>';
  var c=ctx||reportSectionContext();
  if(!c&&!_importedReportData){return h+'<p>No data loaded.</p></section>'}
  if(!_inventoryData.length&&c) _buildInventoryData();
  var filteredInv=_rptFilterByAccount(_inventoryData, _rptGetAccountFilter());
  if(!filteredInv.length){return h+'<p>No resources found.</p></section>'}
  h+='<div class="rpt-section-body">';

  // Group rows by type
  var byType={};
  filteredInv.forEach(function(r){
    if(!byType[r.type]) byType[r.type]=[];
    byType[r.type].push(r);
  });
  var typeKeys=Object.keys(byType).sort();

  // Jump nav
  h+='<nav class="rpt-jump-nav">';
  typeKeys.forEach(function(t){
    var cnt=byType[t].length;
    var anchor='s-inv-'+t.toLowerCase().replace(/\s+/g,'-');
    h+='<a href="#'+esc(anchor)+'" class="rpt-jump-link">'+esc(t)+'<span class="rpt-jump-ct">'+cnt+'</span></a>';
  });
  h+='</nav>';

  var accounts=_rptUniqueAccounts();
  // One table per type: skip columns that are entirely empty for this type
  typeKeys.forEach(function(t){
    var items=byType[t];
    var anchor='s-inv-'+t.toLowerCase().replace(/\s+/g,'-');
    var tableId='rpt-tbl-inv-'+t.toLowerCase().replace(/\s+/g,'-');
    // Detect which optional columns have data
    var hasConfig=items.some(function(r){return r.config&&r.config!=='-'});
    var hasState=items.some(function(r){return r.state&&r.state!=='-'});
    var hasVpc=items.some(function(r){return !!r.vpcId});
    h+='<h3 id="'+esc(anchor)+'">'+esc(t)+' ('+items.length+')</h3>';
    h+='<div class="rpt-table-wrap" id="'+esc(tableId)+'">';
    h+=_rptBuildToolbar(tableId,{accounts:accounts});
    h+='<table><thead class="rpt-sticky"><tr>';
    h+='<th class="rpt-sortable" data-sort-type="text">Account</th>';
    h+='<th>Name</th><th>ID</th>';
    if(hasConfig) h+='<th>Config</th>';
    if(hasState) h+='<th>State</th>';
    if(hasVpc) h+='<th>VNet</th>';
    h+='<th>Region</th>';
    h+='</tr></thead><tbody>';
    items.forEach(function(r){
      // Resolve account ID from raw object or from inventory account field
      var acctId=r._raw&&r._raw._subscriptionId?r._raw._subscriptionId:(r.account||'');
      h+='<tr id="res-'+esc(r.id)+'" data-account="'+esc(acctId)+'">';
      h+='<td>'+esc(r.account||'')+'</td>';
      h+='<td>'+esc(r.name||'')+'</td>';
      h+='<td>'+_rptLink(r.type,r.id,r.region,r.id)+'</td>';
      if(hasConfig) h+='<td>'+esc(r.config||'')+'</td>';
      if(hasState) h+='<td>'+esc(r.state||'-')+'</td>';
      if(hasVpc) h+='<td>'+(r.vpcId?_rptLink('VNet',r.vpcId,r.region,r.vpcName||r.vpcId):'-')+'</td>';
      h+='<td>'+esc(r.region||'-')+'</td>';
      h+='</tr>';
    });
    h+='</tbody></table></div>';
  });

  h+='</div></section>';
  return h;
}

function _rptTagName(o){
  var t=(o.Tags||[]).find(function(t){return t.Key==='Name'});
  return t?t.Value:'';
}

function _rptInvVPCs(c){
  var items=c.vpcs||[];
  if(!items.length) return '';
  var h='<h3 id="s-inv-vpcs">VNets ('+items.length+')</h3>';
  h+='<div class="rpt-table-wrap" id="rpt-tbl-inv-vpcs">';
  h+=_rptBuildToolbar('rpt-tbl-inv-vpcs',{});
  h+='<table><thead class="rpt-sticky"><tr><th>Name</th><th>VNet ID</th>';
  h+='<th>CIDR</th><th>State</th></tr></thead><tbody>';
  items.forEach(function(v){
    h+='<tr id="res-'+esc(v.VpcId)+'"><td>'+esc(_rptTagName(v))+'</td>';
    h+='<td>'+_rptLink('VNet',v.VpcId,v._region,v.VpcId)+'</td>';
    h+='<td>'+esc(v.CidrBlock)+'</td>';
    h+='<td>'+esc(v.State)+'</td></tr>';
  });
  h+='</tbody></table></div>';
  return h;
}

function _rptInvSubnets(c){
  var items=c.subnets||[];
  if(!items.length) return '';
  var h='<h3 id="s-inv-subnets">Subnets ('+items.length+')</h3>';
  h+='<div class="rpt-table-wrap" id="rpt-tbl-inv-subnets">';
  h+=_rptBuildToolbar('rpt-tbl-inv-subnets',{});
  h+='<table><thead class="rpt-sticky"><tr><th>Name</th><th>Subnet ID</th>';
  h+='<th>CIDR</th><th>AZ</th><th>Public</th></tr></thead><tbody>';
  items.forEach(function(s){
    var pub=c.pubSubs&&c.pubSubs.has(s.SubnetId)?'Yes':'No';
    h+='<tr id="res-'+esc(s.SubnetId)+'"><td>'+esc(_rptTagName(s))+'</td>';
    h+='<td>'+_rptLink('Subnet',s.SubnetId,s._region,s.SubnetId)+'</td>';
    h+='<td>'+esc(s.CidrBlock)+'</td>';
    h+='<td>'+esc(s.AvailabilityZone)+'</td>';
    h+='<td>'+esc(pub)+'</td></tr>';
  });
  h+='</tbody></table></div>';
  return h;
}

function _rptInvEC2(c){
  var items=c.instances||[];
  if(!items.length) return '';
  var h='<h3 id="s-inv-ec2">Virtual Machines ('+items.length+')</h3>';
  h+='<div class="rpt-table-wrap" id="rpt-tbl-inv-ec2">';
  h+=_rptBuildToolbar('rpt-tbl-inv-ec2',{});
  h+='<table><thead class="rpt-sticky"><tr><th>Name</th><th>Instance ID</th>';
  h+='<th>Type</th><th>State</th><th>AZ</th></tr></thead><tbody>';
  items.forEach(function(i){
    var state=i.State?i.State.Name:'';
    var az=i.Placement?i.Placement.AvailabilityZone:'';
    h+='<tr id="res-'+esc(i.InstanceId)+'"><td>'+esc(_rptTagName(i))+'</td>';
    h+='<td>'+_rptLink('VM',i.InstanceId,i._region,i.InstanceId)+'</td>';
    h+='<td>'+esc(i.InstanceType)+'</td>';
    h+='<td>'+esc(state)+'</td>';
    h+='<td>'+esc(az)+'</td></tr>';
  });
  h+='</tbody></table></div>';
  return h;
}

function _rptInvRDS(c){
  var items=c.rdsInstances||[];
  if(!items.length) return '';
  var h='<h3 id="s-inv-rds">SQL Servers ('+items.length+')</h3>';
  h+='<div class="rpt-table-wrap" id="rpt-tbl-inv-rds">';
  h+=_rptBuildToolbar('rpt-tbl-inv-rds',{});
  h+='<table><thead class="rpt-sticky"><tr><th>Identifier</th><th>Engine</th>';
  h+='<th>Class</th><th>Multi-AZ</th></tr></thead><tbody>';
  items.forEach(function(d){
    h+='<tr id="res-'+esc(d.DBInstanceIdentifier)+'"><td>'+_rptLink('SQL',d.DBInstanceIdentifier,d._region,d.DBInstanceIdentifier)+'</td>';
    h+='<td>'+esc(d.Engine)+'</td>';
    h+='<td>'+esc(d.DBInstanceClass)+'</td>';
    h+='<td>'+esc(d.MultiAZ?'Yes':'No')+'</td></tr>';
  });
  h+='</tbody></table></div>';
  return h;
}

function _rptInvALBs(c){
  var items=c.albs||[];
  if(!items.length) return '';
  var h='<h3 id="s-inv-albs">Load Balancers ('+items.length+')</h3>';
  h+='<div class="rpt-table-wrap" id="rpt-tbl-inv-albs">';
  h+=_rptBuildToolbar('rpt-tbl-inv-albs',{});
  h+='<table><thead class="rpt-sticky"><tr><th>Name</th><th>Type</th>';
  h+='<th>Scheme</th><th>AZs</th></tr></thead><tbody>';
  items.forEach(function(a){
    var azCount=(a.AvailabilityZones||[]).length;
    h+='<tr id="res-'+esc(a.LoadBalancerName||a.LoadBalancerArn)+'"><td>'+_rptLink('ALB',a.LoadBalancerName,a._region,a.LoadBalancerName)+'</td>';
    h+='<td>'+esc(a.Type)+'</td>';
    h+='<td>'+esc(a.Scheme)+'</td>';
    h+='<td>'+azCount+'</td></tr>';
  });
  h+='</tbody></table></div>';
  return h;
}

function _rptInvECS(c){
  var items=c.ecsServices||[];
  if(!items.length) return '';
  var h='<h3 id="s-inv-ecs">Container Instances ('+items.length+')</h3>';
  h+='<div class="rpt-table-wrap" id="rpt-tbl-inv-ecs">';
  h+=_rptBuildToolbar('rpt-tbl-inv-ecs',{});
  h+='<table><thead class="rpt-sticky"><tr><th>Service</th><th>Desired</th>';
  h+='<th>Running</th><th>Launch Type</th></tr></thead><tbody>';
  items.forEach(function(s){
    h+='<tr id="res-'+esc(s.serviceName||s.serviceArn)+'"><td>'+_rptLink('Container',s.serviceName,s._region,s.serviceName)+'</td>';
    h+='<td>'+esc(s.desiredCount)+'</td>';
    h+='<td>'+esc(s.runningCount)+'</td>';
    h+='<td>'+esc(s.launchType||'')+'</td></tr>';
  });
  h+='</tbody></table></div>';
  return h;
}

function _rptInvLambda(c){
  var items=c.lambdaFns||[];
  if(!items.length) return '';
  var h='<h3 id="s-inv-lambda">Function Apps ('+items.length+')</h3>';
  h+='<div class="rpt-table-wrap" id="rpt-tbl-inv-lambda">';
  h+=_rptBuildToolbar('rpt-tbl-inv-lambda',{});
  h+='<table><thead class="rpt-sticky"><tr><th>Function</th><th>Runtime</th>';
  h+='<th>Memory (MB)</th><th>Timeout (s)</th></tr></thead><tbody>';
  items.forEach(function(fn){
    h+='<tr id="res-'+esc(fn.FunctionName)+'"><td>'+_rptLink('FuncApp',fn.FunctionName,fn._region,fn.FunctionName)+'</td>';
    h+='<td>'+esc(fn.Runtime)+'</td>';
    h+='<td>'+esc(fn.MemorySize)+'</td>';
    h+='<td>'+esc(fn.Timeout)+'</td></tr>';
  });
  h+='</tbody></table></div>';
  return h;
}

function _rptActionPlan(ctx, opts){
  var h='<section class="rpt-section" id="s-action-plan"><h2 class="rpt-section-toggle">Action Plan</h2>';
  var view=_buildComplianceView({accountFilter:_rptGetAccountFilter(),includeMuted:true});
  if(!view.filtered.length){return h+'<p>No findings to prioritize.</p></section>'}
  h+='<div class="rpt-section-body">';
  var tiers=view.tiers;
  var tierNames={crit:'critical',high:'high',med:'medium',low:'low'};
  h+='<nav class="rpt-jump-nav">';
  _PRIORITY_KEYS.forEach(function(t){
    var rgs=tiers[t];if(!rgs||!rgs.length) return;
    var total=view.filteredTierCounts[t];
    h+='<a href="#s-action-'+tierNames[t]+'" class="rpt-jump-link" style="color:'+_TIER_META[t].color+'">'+_TIER_META[t].name+'<span class="rpt-jump-ct" style="color:'+_TIER_META[t].color+'">'+total+'</span></a>';
  });
  h+='</nav>';
  _PRIORITY_KEYS.forEach(function(t){
    var rgs=tiers[t];
    if(!rgs||!rgs.length) return;
    var meta=_TIER_META[t];
    h+='<h3 id="s-action-'+tierNames[t]+'" style="color:'+meta.color+'">'+esc(meta.name);
    var total=view.filteredTierCounts[t];
    h+=' ('+total+' findings)</h3>';
    var tableId='rpt-tbl-action-'+t;
    h+='<div class="rpt-table-wrap" id="'+tableId+'">';
    h+=_rptBuildToolbar(tableId,{severities:true,accounts:_rptUniqueAccounts()});
    h+=_rptActionTierTable(rgs);
    h+='</div>';
  });
  h+='</div></section>';
  return h;
}

function _rptActionTierTable(resourceGroups){
  var h='<table><thead class="rpt-sticky"><tr>';
  h+='<th class="rpt-sortable" data-sort-type="text">Account</th>';
  h+='<th class="rpt-sortable" data-sort-type="severity">Severity</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Framework</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Control</th>';
  h+='<th class="rpt-sortable" data-sort-type="text">Resource</th>';
  h+='<th>Finding</th><th>Remediation</th>';
  h+='</tr></thead><tbody>';
  resourceGroups.forEach(function(rg){
    rg.findings.forEach(function(f){
      h+='<tr data-sev="'+esc(f.severity)+'" data-account="'+esc(f._subscriptionId||'')+'">';
      h+='<td>'+esc(_rptAccountLabel(f._subscriptionId))+'</td>';
      h+='<td><span class="sev-badge sev-'+esc(f.severity)+'">'+esc(f.severity)+'</span></td>';
      h+='<td>'+esc(_FW_LABELS[f.framework]||f.framework)+'</td>';
      h+='<td>'+esc(f.control)+(f.ckv?' <span style="opacity:.5;font-size:9px">('+esc(f.ckv)+')</span>':'')+'</td>';
      h+='<td>'+esc(f.resourceName||f.resource)+'</td>';
      h+='<td>'+esc(f.message)+'</td>';
      h+='<td>'+esc(f.remediation)+'</td>';
      h+='</tr>';
    });
  });
  h+='</tbody></table>';
  return h;
}

function _rptIaCRecs(ctx, opts){
  var h='<section class="rpt-section" id="s-iac-recs"><h2>IaC Recommendations</h2>';
  var f=_rptFilterByAccount(reportSectionComplianceRows(), _rptGetAccountFilter()).filter(function(x){
    return x.severity==='CRITICAL'||x.severity==='HIGH';
  });
  if(!f.length){return h+'<p>No critical/high findings.</p></section>'}
  f.sort(function(a,b){
    return (_SEV_ORDER[a.severity]||9)-(_SEV_ORDER[b.severity]||9);
  });
  var limit=f.slice(0,10);
  limit.forEach(function(item){
    h+='<div class="code-block">';
    h+='<span class="sev-badge sev-'+esc(item.severity)+'">'+esc(item.severity)+'</span> ';
    h+=esc(item.control)+' &mdash; '+esc(item.resourceName||item.resource);
    h+='<br><br><strong>Finding:</strong> '+esc(item.message);
    h+='<br><strong>Remediation:</strong> '+esc(item.remediation);
    h+='</div>';
  });
  h+='</section>';
  return h;
}

// === ACTIONABLE REPORT ENGINE ===
const _EFFORT_MAP={
  // CIS
  'CIS 5.1':'low','CIS 5.2':'low','CIS 5.3':'low','CIS 5.4':'low',
  'CIS 5.5':'med','NET-1':'med','NET-2':'low',
  // WAF
  'WAF-1':'med','WAF-2':'med','WAF-3':'med','WAF-4':'low',
  // ARCH
  'ARCH-N1':'med','ARCH-N2':'med','ARCH-N3':'high','ARCH-N5':'low',
  'ARCH-C1':'low','ARCH-C2':'low','ARCH-C3':'med','ARCH-C4':'med','ARCH-C5':'low','ARCH-C6':'med',
  'ARCH-D1':'low','ARCH-D2':'med','ARCH-D3':'high','ARCH-D4':'med','ARCH-D5':'high','ARCH-D6':'high','ARCH-D7':'low',
  'ARCH-S1':'low','ARCH-S2':'low','ARCH-E1':'med','ARCH-E2':'low',
  'ARCH-G1':'high','ARCH-G2':'low','ARCH-X1':'med',
  // SOC2
  'SOC2-CC6.1':'low','SOC2-CC6.3':'low','SOC2-CC6.6':'med','SOC2-CC6.7':'med',
  'SOC2-CC6.8':'low','SOC2-CC6.10':'med','SOC2-CC7.2':'med','SOC2-CC7.3':'low',
  'SOC2-CC8.1':'low','SOC2-A1.2':'med','SOC2-A1.3':'low','SOC2-A1.4':'med',
  'SOC2-C1.1':'low','SOC2-C1.2':'low','SOC2-C1.3':'high','SOC2-PI1.1':'med',
  // PCI
  'PCI-1.3.1':'low','PCI-1.3.2':'low','PCI-1.3.4':'med','PCI-2.2.1':'low',
  'PCI-2.3.1':'high','PCI-3.4.1':'med','PCI-3.5.1':'med',
  'PCI-4.2.1':'med','PCI-6.3.1':'med','PCI-6.4.1':'med','PCI-7.2.1':'low',
  'PCI-10.2.1':'med','PCI-11.3.1':'low','PCI-12.10.1':'med',
  // IAM
  'IAM-1':'med','IAM-2':'med','IAM-3':'low','IAM-4':'med','IAM-5':'low',
  'IAM-6':'low','IAM-7':'low','IAM-8':'med','IAM-9':'low','IAM-10':'low',
  'IAM-11':'low','IAM-12':'med','IAM-13':'low',
  // CKV (standalone Checkov checks)
  'CKV_AZURE_1':'med','CKV_AZURE_18':'med','CKV_AZURE_43':'low','CKV_AZURE_33':'low',
  'CKV_AZURE_28':'low','CKV_AZURE_70':'low','CKV_AZURE_71':'low',
  // BUDR
  'BUDR-HA-1':'med','BUDR-HA-2':'med','BUDR-HA-3':'low','BUDR-HA-4':'med',
  'BUDR-HA-5':'med','BUDR-HA-6':'low',
  'BUDR-BAK-1':'low','BUDR-BAK-2':'med','BUDR-BAK-3':'med','BUDR-BAK-4':'low','BUDR-BAK-5':'low',
  'BUDR-DR-1':'high','BUDR-DR-2':'med'
};
const _EFFORT_LABELS={low:'Low',med:'Med',high:'High'};
const _EFFORT_TIME={low:'~5 min',med:'~1-2 hrs',high:'~1+ days'};
const _PRIORITY_META={
  crit:{name:'Critical',color:'#ef4444',bg:'rgba(239,68,68,.08)',border:'rgba(239,68,68,.3)'},
  high:{name:'High',color:'#f97316',bg:'rgba(249,115,22,.08)',border:'rgba(249,115,22,.3)'},
  med:{name:'Medium',color:'#f59e0b',bg:'rgba(245,158,11,.08)',border:'rgba(245,158,11,.3)'},
  low:{name:'Low',color:'#3b82f6',bg:'rgba(59,130,246,.08)',border:'rgba(59,130,246,.3)'}
};
const _TIER_META=_PRIORITY_META; // alias for backward compat
function _getEffort(f){return _EFFORT_MAP[f.control]||'med'}
function _classifyTier(f){
  const e=_getEffort(f),s=f.severity;
  if(s==='CRITICAL') return 'crit';
  if(s==='HIGH'&&e==='low') return 'crit';
  if(s==='HIGH') return 'high';
  if(s==='MEDIUM'&&e==='low') return 'high';
  if(s==='MEDIUM') return 'med';
  return 'low';
}
const _PRIORITY_ORDER={crit:1,high:2,med:3,low:4};
const _PRIORITY_KEYS=['crit','high','med','low'];
function _groupByResource(findings){
  const map={};
  findings.forEach(f=>{
    const k=f.resource;
    if(!map[k])map[k]={resource:f.resource,resourceName:f.resourceName||f.resource,findings:[],worstSev:'LOW',worstTier:'low',_subscriptionId:f._subscriptionId};
    const tier=_classifyTier(f);
    map[k].findings.push(Object.assign({},f,{effort:_getEffort(f),tier:tier}));
    if((_SEV_ORDER[f.severity]||9)<(_SEV_ORDER[map[k].worstSev]||9))map[k].worstSev=f.severity;
    if((_PRIORITY_ORDER[tier]||9)<(_PRIORITY_ORDER[map[k].worstTier]||9))map[k].worstTier=tier;
  });
  return Object.values(map).sort(function(a,b){
    if(a.worstTier!==b.worstTier)return(_PRIORITY_ORDER[a.worstTier]||9)-(_PRIORITY_ORDER[b.worstTier]||9);
    return(_SEV_ORDER[a.worstSev]||9)-(_SEV_ORDER[b.worstSev]||9);
  });
}
function _getTierGroups(findings){
  const g={crit:[],high:[],med:[],low:[]};
  _groupByResource(findings).forEach(function(rg){g[rg.worstTier].push(rg)});
  return g;
}
function _getSeverityGroups(findings){
  const g={CRITICAL:[],HIGH:[],MEDIUM:[],LOW:[]};
  _groupByResource(findings).forEach(function(rg){g[rg.worstSev].push(rg)});
  return g;
}
function _estimateTotalEffort(resourceGroups){
  var mins=0;
  resourceGroups.forEach(function(rg){rg.findings.forEach(function(f){
    if(f.effort==='low')mins+=5;else if(f.effort==='med')mins+=90;else mins+=480;
  })});
  if(mins<60)return'~'+mins+' min';
  if(mins<480)return'~'+Math.round(mins/60)+' hrs';
  return'~'+Math.round(mins/480)+' days';
}
// Unified compliance view builder: single source of truth for all filter/count consumers
function _buildComplianceView(opts){
  opts=opts||{};
  var allFindings=reportSectionComplianceRows();
  var src=(opts.findings||allFindings||[]).slice();
  // Account filter (reports)
  if(opts.accountFilter)src=_rptFilterByAccount(src,opts.accountFilter);
  // Framework filter: string (dashboard) or array (export modal)
  if(Array.isArray(opts.frameworks))src=src.filter(function(f){return opts.frameworks.indexOf(f.framework)!==-1});
  else if(opts.frameworks&&opts.frameworks!=='all')src=src.filter(function(f){return f.framework===opts.frameworks});
  // Severity pre-filter: array only (export modal multi-select)
  if(Array.isArray(opts.severities))src=src.filter(function(f){return opts.severities.indexOf(f.severity)!==-1});
  // Search filter
  if(opts.search){var q=opts.search.toLowerCase();src=src.filter(function(f){return(f.message||'').toLowerCase().indexOf(q)!==-1||(f.resource||'').toLowerCase().indexOf(q)!==-1||(f.resourceName||'').toLowerCase().indexOf(q)!==-1||(f.control||'').toLowerCase().indexOf(q)!==-1||(f.ckv||'').toLowerCase().indexOf(q)!==-1||(f.remediation||'').toLowerCase().indexOf(q)!==-1})}
  // Mute filter
  if(!opts.includeMuted)src=src.filter(function(f){return!_isMuted(f)});
  // Stamp _tier and _effort on every finding ONCE
  var base=src.map(function(f){return Object.assign({},f,{_tier:_classifyTier(f),_effort:_getEffort(f)})});
  // Severity sub-filter (dashboard pill selection: single string)
  var filtered=(typeof opts.severity==='string'&&opts.severity!=='ALL')?base.filter(function(f){return f.severity===opts.severity}):base;
  // Pre-compute counts from base (before severity pill filter)
  var sevCounts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  var tierCounts={crit:0,high:0,med:0,low:0};
  base.forEach(function(f){sevCounts[f.severity]++;tierCounts[f._tier]++});
  // Filtered tier counts (after severity pill filter)
  var filteredTierCounts={crit:0,high:0,med:0,low:0};
  var filteredSevCounts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  filtered.forEach(function(f){filteredTierCounts[f._tier]++;filteredSevCounts[f.severity]++});
  // Tier-grouped resource groups
  var tiers=_getTierGroups(filtered);
  var baseTiers=(typeof opts.severity==='string'&&opts.severity!=='ALL')?_getTierGroups(base):tiers;
  // Severity-grouped resource groups (for Sort: Severity mode)
  var sevGroups=_getSeverityGroups(filtered);
  return{
    base:base,
    filtered:filtered,
    tiers:tiers,
    baseTiers:baseTiers,
    sevGroups:sevGroups,
    sevCounts:sevCounts,
    tierCounts:tierCounts,
    filteredTierCounts:filteredTierCounts,
    filteredSevCounts:filteredSevCounts,
    score:_calcComplianceScore(base),
    effort:_estimateTotalEffort(_groupByResource(base)),
    mutedCount:allFindings.filter(function(f){return _isMuted(f)}).length
  };
}
// Muted findings stored in localStorage
const _MUTE_KEY=MUTE_KEY;
let _mutedFindings=new Set();
try{const raw=localStorage.getItem(_MUTE_KEY);if(raw)_mutedFindings=new Set(JSON.parse(raw))}catch(e){}
function _saveMuted(){try{localStorage.setItem(_MUTE_KEY,JSON.stringify([..._mutedFindings]))}catch(e){}}
function _muteKey(f){return f.control+'::'+f.resource}
function _isMuted(f){return _mutedFindings.has(_muteKey(f))}
function _toggleMute(f){const k=_muteKey(f);if(_mutedFindings.has(k))_mutedFindings.delete(k);else _mutedFindings.add(k);_saveMuted()}
const _complianceRefs={
  'CIS 5.1':{url:'https://learn.microsoft.com/en-us/azure/security/benchmarks/security-controls-v2-network-security',ref:'CIS Azure Foundations 5.1'},
  'CIS 5.2':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',ref:'CIS Azure Foundations 5.2'},
  'CIS 5.3':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',ref:'CIS Azure Foundations 5.3'},
  'CIS 5.4':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview',ref:'CIS Azure Foundations 5.4'},
  'CIS 5.5':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview',ref:'CIS Azure Foundations 5.5'},
  'NET-1':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview',ref:'VNet Private Subnet Design'},
  'NET-2':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',ref:'NSG Best Practices'},
  'WAF-1':{url:'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-policy-overview',ref:'Azure WAF Rules'},
  'WAF-2':{url:'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/rate-limiting-policy',ref:'WAF Rate-Based Rules'},
  'WAF-3':{url:'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-policy-overview',ref:'WAF Application Gateway Protection'},
  'WAF-4':{url:'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/web-application-firewall-troubleshoot',ref:'WAF Default Action'},
  'ARCH-N1':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview',ref:'Well-Architected SEC05-BP01'},
  'ARCH-N2':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/nat-gateway/nat-overview',ref:'Well-Architected REL-10'},
  'ARCH-N3':{url:'https://learn.microsoft.com/en-us/azure/architecture/framework/resiliency/reliability-patterns',ref:'Well-Architected REL-10'},
  'ARCH-N5':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',ref:'Well-Architected SEC05-BP02'},
  'ARCH-C1':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',ref:'Well-Architected SEC05-BP01'},
  'ARCH-C2':{url:'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview',ref:'Well-Architected SEC08-BP02'},
  'ARCH-C3':{url:'https://learn.microsoft.com/en-us/azure/azure-functions/functions-networking-options',ref:'Function App VNet Integration'},
  'ARCH-D1':{url:'https://learn.microsoft.com/en-us/azure/azure-sql/database/security-best-practice',ref:'Well-Architected SEC05-BP01'},
  'ARCH-D2':{url:'https://learn.microsoft.com/en-us/azure/azure-sql/database/high-availability-sla',ref:'Well-Architected REL-09'},
  'ARCH-D3':{url:'https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview',ref:'Well-Architected SEC08-BP02'},
  'ARCH-D4':{url:'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-high-availability',ref:'Well-Architected REL-09'},
  'ARCH-D5':{url:'https://learn.microsoft.com/en-us/azure/aks/concepts-security',ref:'Well-Architected SEC08-BP02'},
  'ARCH-S1':{url:'https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption',ref:'Well-Architected SEC08-BP02'},
  'ARCH-S2':{url:'https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk',ref:'Well-Architected REL-09'},
  'ARCH-E1':{url:'https://learn.microsoft.com/en-us/azure/frontdoor/front-door-overview',ref:'Well-Architected PERF04-BP01'},
  'ARCH-G1':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/nat-gateway/nat-overview',ref:'Well-Architected REL-10'},
  'ARCH-G2':{url:'https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview',ref:'Well-Architected COST07-BP01'},
  'ARCH-X1':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview',ref:'VNet Peering Routing'},
  'SOC2-CC6.1':{url:'https://learn.microsoft.com/en-us/azure/defender-for-cloud/overview-page',ref:'SOC2 CC6.1 Logical Access Security'},
  'SOC2-CC6.3':{url:'https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices',ref:'SOC2 CC6.3 Role-Based Access'},
  'SOC2-CC6.6':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',ref:'SOC2 CC6.6 Network Boundaries'},
  'SOC2-CC6.7':{url:'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview',ref:'SOC2 CC6.7 Data Transmission'},
  'SOC2-CC6.8':{url:'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-servers-introduction',ref:'SOC2 CC6.8 Malicious Software'},
  'SOC2-CC7.2':{url:'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview',ref:'SOC2 CC7.2 Monitoring'},
  'SOC2-CC8.1':{url:'https://learn.microsoft.com/en-us/azure/governance/policy/overview',ref:'SOC2 CC8.1 Change Management'},
  'SOC2-A1.2':{url:'https://learn.microsoft.com/en-us/azure/azure-sql/database/high-availability-sla',ref:'SOC2 A1.2 Availability'},
  'SOC2-A1.3':{url:'https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk',ref:'SOC2 A1.3 Recovery'},
  'SOC2-C1.1':{url:'https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption',ref:'SOC2 C1.1 Confidentiality'},
  'SOC2-C1.2':{url:'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview',ref:'SOC2 C1.2 Data Protection'},
  'SOC2-PI1.1':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',ref:'SOC2 PI1.1 Processing Integrity'},
  'PCI-1.3.1':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview',ref:'PCI DSS 4.0 Req 1.3.1 Inbound Traffic'},
  'PCI-1.3.2':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works',ref:'PCI DSS 4.0 Req 1.3.2 Outbound Traffic'},
  'PCI-1.3.4':{url:'https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-service-endpoints-overview',ref:'PCI DSS 4.0 Req 1.3.4 Network Segmentation'},
  'PCI-2.2.1':{url:'https://learn.microsoft.com/en-us/azure/governance/policy/overview',ref:'PCI DSS 4.0 Req 2.2.1 Configuration Standards'},
  'PCI-3.4.1':{url:'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview',ref:'PCI DSS 4.0 Req 3.4.1 Data Encryption'},
  'PCI-3.5.1':{url:'https://learn.microsoft.com/en-us/azure/key-vault/general/overview',ref:'PCI DSS 4.0 Req 3.5.1 Key Management'},
  'PCI-4.2.1':{url:'https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-overview',ref:'PCI DSS 4.0 Req 4.2.1 TLS'},
  'PCI-6.4.1':{url:'https://learn.microsoft.com/en-us/azure/web-application-firewall/overview',ref:'PCI DSS 4.0 Req 6.4.1 Web App Firewall'},
  'PCI-7.2.1':{url:'https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices',ref:'PCI DSS 4.0 Req 7.2.1 Least Privilege'},
  'PCI-8.3.1':{url:'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks',ref:'PCI DSS 4.0 Req 8.3.1 MFA'},
  'PCI-10.2.1':{url:'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log',ref:'PCI DSS 4.0 Req 10.2.1 Audit Logging'},
  'PCI-11.3.1':{url:'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-servers-vulnerability-assessment',ref:'PCI DSS 4.0 Req 11.3.1 Vulnerability Scanning'},
  'PCI-12.10.1':{url:'https://learn.microsoft.com/en-us/azure/defender-for-cloud/managing-and-responding-alerts',ref:'PCI DSS 4.0 Req 12.10.1 Incident Response'},
  'IAM-1':{url:'https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices',ref:'Azure RBAC Best Practices'},
  'IAM-2':{url:'https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices',ref:'Azure Least Privilege'},
  'IAM-3':{url:'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks',ref:'Azure MFA'},
  'IAM-4':{url:'https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices',ref:'Azure Role Wildcards'},
  'IAM-5':{url:'https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-use-sign-in-diagnostics',ref:'Unused Azure Role Assignments'},
  'IAM-6':{url:'https://learn.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation',ref:'Workload Identity Federation'},
  'IAM-7':{url:'https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles',ref:'Built-in vs Custom Roles'},
  'IAM-8':{url:'https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure',ref:'Azure Policy Assignments'},
  'CKV_AZURE_1':{url:'https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service',ref:'Checkov CKV_AZURE_1: VM Metadata'},
  'CKV_AZURE_18':{url:'https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview',ref:'Checkov CKV_AZURE_18: NSG Flow Logs'},
  'CKV_AZURE_43':{url:'https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-overview',ref:'Checkov CKV_AZURE_43: Storage Versioning'},
  'CKV_AZURE_33':{url:'https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging',ref:'Checkov CKV_AZURE_33: Storage Logging'},
  'CKV_AZURE_28':{url:'https://learn.microsoft.com/en-us/azure/azure-sql/database/automated-backups-overview',ref:'Checkov CKV_AZURE_28: SQL Backup Retention'},
  'CKV_AZURE_70':{url:'https://learn.microsoft.com/en-us/azure/app-service/configure-common',ref:'Checkov CKV_AZURE_70: Function App Config'},
  'CKV_AZURE_71':{url:'https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview',ref:'Checkov CKV_AZURE_71: Function App Tracing'},
  'BUDR-HA-1':{url:'https://learn.microsoft.com/en-us/azure/azure-sql/database/high-availability-sla',ref:'SQL Database High Availability'},
  'BUDR-HA-2':{url:'https://learn.microsoft.com/en-us/azure/virtual-machine-scale-sets/overview',ref:'VM Scale Sets Auto Scaling'},
  'BUDR-HA-3':{url:'https://learn.microsoft.com/en-us/azure/container-instances/container-instances-overview',ref:'Container Instance Scaling'},
  'BUDR-HA-4':{url:'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-high-availability',ref:'Redis Cache Replication'},
  'BUDR-HA-5':{url:'https://learn.microsoft.com/en-us/azure/aks/availability-zones',ref:'AKS Availability Zones'},
  'BUDR-HA-6':{url:'https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-overview',ref:'Azure Load Balancer Zones'},
  'BUDR-BAK-1':{url:'https://learn.microsoft.com/en-us/azure/azure-sql/database/automated-backups-overview',ref:'SQL Automated Backups'},
  'BUDR-BAK-2':{url:'https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk',ref:'Managed Disk Snapshots'},
  'BUDR-BAK-3':{url:'https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-how-to-export-import-data',ref:'Redis Cache Backup'},
  'BUDR-BAK-4':{url:'https://learn.microsoft.com/en-us/azure/aks/backup-overview',ref:'AKS Backup'},
  'BUDR-BAK-5':{url:'https://learn.microsoft.com/en-us/azure/backup/backup-azure-vms-introduction',ref:'Azure VM Backup Scheduling'},
  'BUDR-DR-1':{url:'https://learn.microsoft.com/en-us/azure/azure-sql/database/high-availability-sla',ref:'SQL DR Strategy'},
  'BUDR-DR-2':{url:'https://learn.microsoft.com/en-us/azure/site-recovery/site-recovery-overview',ref:'Azure Site Recovery'},
};
// #endregion REPORT BUILDER

