// BUDR dashboard owns backup, uptime, disaster-recovery dashboard rendering and exports.
function budrEsc(value){
  var html=typeof AppHtml!=='undefined'?AppHtml:null;
  if(html&&html.escape)return html.escape(value);
  return esc(value);
}

function budrNotify(message,type){
  var notifications=typeof AppNotifications!=='undefined'?AppNotifications:null;
  if(notifications&&notifications.show)return notifications.show(message,type);
}

function budrSaveBlob(blob,name){
  var downloads=typeof AppDownloads!=='undefined'?AppDownloads:null;
  if(downloads&&downloads.saveBlob)return downloads.saveBlob(blob,name);
}

function budrDesktopExportXlsx(jsonText){
  var desktop=typeof DesktopAzureAdapter!=='undefined'?DesktopAzureAdapter:null;
  if(desktop&&desktop.exportBUDRXlsx)return desktop.exportBUDRXlsx(jsonText);
  return Promise.resolve({error:'Desktop XLSX export is not available'});
}

function openBUDRDash(){
  DashboardState.resetBudrDashState();
  openUnifiedDash('budr');
}

function _renderBUDRDash(){
  var tb=document.getElementById('udashToolbar');
  var body=document.getElementById('udashBody');
  var footer=document.getElementById('udashFooter');
  var st=DashboardState.getBudrDashState();
  var _budrFiltered=_udashFilterByAccount(_budrAssessments);
  var counts={protected:0,partial:0,at_risk:0,unknown:0};
  _budrFiltered.forEach(function(a){if(a.profile)counts[a.profile.tier]=(counts[a.profile.tier]||0)+1});
  var total=_budrFiltered.length;
  var th='<input id="budrSearch" type="text" placeholder="Filter by name, ID, type..." value="'+budrEsc(st.search)+'" style="background:var(--bg-tertiary);border:1px solid var(--border);color:var(--text-primary);padding:4px 10px;border-radius:4px;font-size:11px;font-family:Segoe UI,system-ui,sans-serif;width:200px">';
  th+='<select id="budrSort" style="background:var(--bg-tertiary);border:1px solid var(--border);color:var(--text-secondary);padding:4px 8px;border-radius:4px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif">';
  th+='<option value="tier"'+(st.sort==='tier'?' selected':'')+'>Sort: Tier</option>';
  th+='<option value="compliance"'+(st.sort==='compliance'?' selected':'')+'>Sort: Compliance</option>';
  th+='<option value="name"'+(st.sort==='name'?' selected':'')+'>Sort: Name</option>';
  th+='<option value="type"'+(st.sort==='type'?' selected':'')+'>Sort: Type</option>';
  th+='</select>';
  th+='<div id="budrPills" style="display:flex;gap:4px;margin-left:8px"></div>';
  tb.innerHTML=th;

  var pillBox=document.getElementById('budrPills');
  [{tier:'all',label:'All ('+total+')'},{tier:'protected',label:'Protected ('+counts.protected+')'},{tier:'partial',label:'Partial ('+counts.partial+')'},{tier:'at_risk',label:'At Risk ('+counts.at_risk+')'},{tier:'unknown',label:'Not Assessed ('+counts.unknown+')'}].forEach(function(p){
    if(p.tier==='unknown'&&!counts.unknown)return;
    var btn=document.createElement('span');btn.className='budr-pill'+(st.tierFilter===p.tier?' active':'');
    btn.dataset.tier=p.tier;btn.textContent=p.label;
    btn.addEventListener('click',function(){st.tierFilter=p.tier;_renderBUDRDash()});pillBox.appendChild(btn);
  });
  document.getElementById('budrSearch').addEventListener('input',function(){st.search=this.value;_renderBUDRDash()});
  document.getElementById('budrSort').addEventListener('change',function(){st.sort=this.value;_renderBUDRDash()});

  var items=_udashFilterByAccount(_budrAssessments).slice();
  if(st.tierFilter!=='all')items=items.filter(function(a){return a.profile&&a.profile.tier===st.tierFilter});
  if(st.search){var q=st.search.toLowerCase();items=items.filter(function(a){return(a.name||'').toLowerCase().includes(q)||(a.id||'').toLowerCase().includes(q)||(a.type||'').toLowerCase().includes(q)})}
  if(st.sort==='name')items.sort(function(a,b){return(a.name||a.id||'').localeCompare(b.name||b.id||'')});
  else if(st.sort==='type')items.sort(function(a,b){return(a.type||'').localeCompare(b.type||'')});
  else if(st.sort==='compliance'){var co={fail:0,warn:1,pass:2,unknown:3};items.sort(function(a,b){var sa=a.compliance?co[a.compliance.status]:3;var sb=b.compliance?co[b.compliance.status]:3;return sa-sb})}

  var compCounts={pass:0,warn:0,fail:0,unknown:0};
  _budrFiltered.forEach(function(a){var s=a.compliance?a.compliance.status:'unknown';compCounts[s]=(compCounts[s]||0)+1});
  var h='<div class="budr-summary">';
  ['protected','partial','at_risk','unknown'].forEach(function(tier){
    if(tier==='unknown'&&!counts.unknown)return;
    var meta=_BUDR_TIER_META[tier];var c=counts[tier]||0;
    var pct=total>0?Math.round(c/total*100):0;
    h+='<div class="budr-card '+tier+'" data-tier="'+tier+'">';
    h+='<div class="bc-count">'+c+'</div>';
    h+='<div class="bc-label">'+esc(meta.name)+'</div>';
    h+='<div class="bc-rto">'+pct+'% of resources</div>';
    h+='</div>';
  });
  h+='</div>';
  if(compCounts.fail||compCounts.warn){
    h+='<div style="display:flex;gap:8px;padding:6px 12px;margin:0 0 8px;background:var(--bg-tertiary);border-radius:6px;font-family:Segoe UI,system-ui,sans-serif;font-size:10px;align-items:center">';
    h+='<span style="color:var(--text-muted);font-weight:600">Tier Compliance:</span>';
    if(compCounts.pass)h+='<span style="color:#22c55e">'+compCounts.pass+' meet target</span>';
    if(compCounts.warn)h+='<span style="color:#f59e0b">'+compCounts.warn+' warnings</span>';
    if(compCounts.fail)h+='<span style="color:#ef4444">'+compCounts.fail+' gaps</span>';
    h+='</div>';
  }
  h+=_rptBUDRStrategyLegend();

  var groups={protected:[],partial:[],at_risk:[],unknown:[]};
  items.forEach(function(a){if(a.profile)groups[a.profile.tier].push(a)});
  ['at_risk','unknown','partial','protected'].forEach(function(tier){
    var grp=groups[tier];if(!grp.length)return;
    var meta=_BUDR_TIER_META[tier];
    var collapsed=tier==='protected';
    h+='<div class="budr-section" data-tier="'+tier+'">';
    h+='<div class="budr-section-hdr'+(collapsed?' collapsed':'')+'">';
    h+='<span class="bs-chevron">\u25BC</span>';
    h+='<h3 style="color:'+meta.color+'">'+meta.icon+' '+esc(meta.name)+'</h3>';
    h+='<span class="bs-count">'+grp.length+' resource'+(grp.length!==1?'s':'')+'</span>';
    h+='</div>';
    h+='<div class="budr-section-body"'+(collapsed?' style="display:none"':'')+'>';
    grp.forEach(function(a,i){
      var findings=_budrFindings.filter(function(f){return f.resource===a.id});
      var expanded=tier==='at_risk';
      h+='<div class="budr-res'+(expanded?' expanded':'')+'" data-idx="'+tier+'-'+i+'">';
      h+='<div class="budr-res-hdr">';
      h+='<span class="br-dot '+tier+'"></span>';
      h+='<span class="br-type">'+esc(a.type)+'</span>';
      h+='<span class="br-name">'+esc(a.name)+'</span>';
      if(a._subscriptionId)h+=_acctPill(a._subscriptionId);
      var ct=a.classTier||'low';var cc=a.compliance||{status:'unknown'};
      var tierColors={critical:'#ef4444',high:'#f59e0b',medium:'#22d3ee',low:'#64748b'};
      var compIcon=cc.status==='pass'?'✓':cc.status==='warn'?'!':cc.status==='fail'?'✗':'?';
      var compColor=cc.status==='pass'?'#22c55e':cc.status==='warn'?'#f59e0b':cc.status==='fail'?'#ef4444':'#64748b';
      h+='<span style="font-size:9px;padding:1px 5px;border-radius:3px;background:'+tierColors[ct]+'22;color:'+tierColors[ct]+';border:1px solid '+tierColors[ct]+'44;margin-left:auto">'+ct.toUpperCase()+'</span>';
      h+='<span style="font-size:9px;color:'+compColor+';margin-left:4px" title="'+esc(cc.issues?cc.issues.map(function(i){return i.msg}).join('; '):'')+'">'+compIcon+'</span>';
      h+='<span class="br-rto" style="margin-left:6px">RTO: '+esc(a.profile.rto)+' | RPO: '+esc(a.profile.rpo)+'</span>';
      if(a.overridden)h+='<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:rgba(99,102,241,.15);color:#818cf8;margin-left:4px;font-weight:600">✎ OVERRIDE</span>';
      h+='<button class="budr-cfg-btn" data-rid="'+esc(a.id)+'" title="Configure strategy override" style="margin-left:4px;background:none;border:1px solid var(--border);border-radius:4px;cursor:pointer;padding:2px 7px;font-size:15px;color:var(--text-muted);line-height:1">⚙</button>';
      h+='</div>';
      h+='<div class="budr-res-body">';
      var ov=_budrOverrides[a.id]||{};
      h+='<div class="budr-override-form" data-rid="'+esc(a.id)+'" style="display:none;margin-bottom:8px;padding:8px 10px;background:rgba(99,102,241,.06);border:1px solid rgba(99,102,241,.2);border-radius:5px;font-size:11px;font-family:Segoe UI,system-ui,sans-serif">';
      h+='<div style="color:#818cf8;font-weight:600;margin-bottom:6px">Strategy Override</div>';
      h+='<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">';
      h+='<label style="color:var(--text-secondary)">DR Strategy</label>';
      h+='<select class="budr-ov-strategy" style="font-size:11px;padding:2px 4px;border-radius:3px;border:1px solid var(--border);background:var(--bg-secondary);color:var(--text-primary)">';
      var _stratToClass={hot:'critical',warm:'high',pilot:'medium',cold:'low'};
      [{k:'critical',label:'Critical (Hot)'},{k:'high',label:'High (Warm)'},{k:'medium',label:'Medium (Pilot Light)'},{k:'low',label:'Low (Cold)'}].forEach(function(s){
        var cur=ov.strategy||_stratToClass[a.profile.strategy]||'low';
        var sel=cur===s.k?' selected':'';
        h+='<option value="'+s.k+'"'+sel+'>'+s.label+'</option>';
      });
      h+='</select>';
      h+='<label style="color:var(--text-secondary);margin-left:8px">RTO</label>';
      h+='<input class="budr-ov-rto" type="text" value="'+esc(ov.rto||a.profile.rto)+'" style="width:70px;font-size:11px;padding:2px 4px;border-radius:3px;border:1px solid var(--border);background:var(--bg-secondary);color:var(--text-primary)" placeholder="'+esc(a.autoProfile?a.autoProfile.rto:a.profile.rto)+'">';
      h+='<label style="color:var(--text-secondary);margin-left:8px">RPO</label>';
      h+='<input class="budr-ov-rpo" type="text" value="'+esc(ov.rpo||a.profile.rpo)+'" style="width:70px;font-size:11px;padding:2px 4px;border-radius:3px;border:1px solid var(--border);background:var(--bg-secondary);color:var(--text-primary)" placeholder="'+esc(a.autoProfile?a.autoProfile.rpo:a.profile.rpo)+'">';
      h+='</div>';
      h+='<div style="margin-top:6px;display:flex;gap:6px">';
      h+='<button class="budr-ov-save" data-rid="'+esc(a.id)+'" style="font-size:10px;padding:3px 10px;border-radius:3px;border:none;background:#6366f1;color:#fff;cursor:pointer;font-weight:600">Save</button>';
      if(a.overridden)h+='<button class="budr-ov-reset" data-rid="'+esc(a.id)+'" style="font-size:10px;padding:3px 10px;border-radius:3px;border:1px solid var(--border);background:var(--bg-secondary);color:var(--text-secondary);cursor:pointer">Reset to Auto</button>';
      h+='</div>';
      h+='</div>';
      var estM=_BUDR_EST_MINUTES[a.profileKey]||{};
      if(estM.rtoWhy||estM.rpoWhy){
        h+='<div style="margin-bottom:6px;padding:4px 8px;background:rgba(99,102,241,.06);border:1px solid rgba(99,102,241,.15);border-radius:4px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif">';
        h+='<div style="color:#818cf8;font-weight:600;margin-bottom:2px">Est. RTO/RPO Justification</div>';
        if(estM.rtoWhy)h+='<div style="color:var(--text-secondary)"><b>RTO '+esc(a.profile.rto)+'</b>: '+esc(estM.rtoWhy)+'</div>';
        if(estM.rpoWhy)h+='<div style="color:var(--text-secondary)"><b>RPO '+esc(a.profile.rpo)+'</b>: '+esc(estM.rpoWhy)+'</div>';
        h+='</div>';
      }
      if(cc.issues&&cc.issues.length){
        h+='<div style="margin-bottom:6px;padding:4px 8px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:4px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif">';
        h+='<div style="color:#ef4444;font-weight:600;margin-bottom:2px">Tier Compliance Gap: '+ct.toUpperCase()+' tier</div>';
        cc.issues.forEach(function(issue){
          h+='<div style="color:var(--text-secondary)">'+esc(issue.msg)+'</div>';
        });
        var target=_TIER_TARGETS[ct];
        if(target)h+='<div style="color:var(--text-muted);margin-top:2px">Target: RTO ≤ '+target.rtoLabel+' | RPO ≤ '+target.rpoLabel+'</div>';
        h+='</div>';
      }
      if(a.signals){
        h+='<div class="budr-signals">';
        Object.entries(a.signals).forEach(function(entry){
          var k=entry[0],v=entry[1];
          var good=v===true||(typeof v==='number'&&v>1);
          var bad=v===false||v===0;
          var cls=good?'good':bad?'bad':'warn';
          var icon=good?'✓':bad?'✗':'!';
          h+='<span class="budr-sig-badge '+cls+'">'+icon+' '+esc(k)+': '+esc(String(v))+'</span>';
        });
        h+='</div>';
      }
      if(findings.length){
        h+='<div class="budr-findings">';
        findings.forEach(function(f){
          h+='<div class="budr-finding">';
          h+='<span class="bf-sev '+f.severity+'">'+f.severity+'</span>';
          h+='<span class="bf-msg">'+esc(f.message)+'</span>';
          h+='</div>';
          if(f.remediation)h+='<div class="budr-finding"><span class="bf-sev" style="visibility:hidden">.</span><span class="bf-fix">\u21B3 '+esc(f.remediation)+'</span></div>';
        });
        h+='</div>';
      }
      h+='</div></div>';
    });
    h+='</div></div>';
  });
  if(!items.length)h+='<div style="padding:40px;text-align:center;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif">No resources match current filter</div>';
  body.innerHTML=h;
  body.scrollTop=0;
  body.querySelectorAll('.budr-section-hdr').forEach(function(hdr){
    hdr.addEventListener('click',function(){
      var bd=hdr.nextElementSibling;
      if(hdr.classList.contains('collapsed')){hdr.classList.remove('collapsed');bd.style.display=''}
      else{hdr.classList.add('collapsed');bd.style.display='none'}
    });
  });
  body.querySelectorAll('.budr-res-hdr').forEach(function(hdr){
    hdr.addEventListener('click',function(e){
      if(e.target.closest('.budr-cfg-btn'))return;
      hdr.closest('.budr-res').classList.toggle('expanded');
    });
  });
  body.querySelectorAll('.budr-cfg-btn').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var rid=btn.dataset.rid;
      var form=body.querySelector('.budr-override-form[data-rid="'+rid+'"]');
      if(form)form.style.display=form.style.display==='none'?'':'none';
      var card=btn.closest('.budr-res');
      if(card&&!card.classList.contains('expanded'))card.classList.add('expanded');
    });
  });
  body.querySelectorAll('.budr-ov-save').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var rid=btn.dataset.rid;
      var form=btn.closest('.budr-override-form');
      var strategy=form.querySelector('.budr-ov-strategy').value;
      var rto=form.querySelector('.budr-ov-rto').value.trim();
      var rpo=form.querySelector('.budr-ov-rpo').value.trim();
      _budrOverrides[rid]={strategy:strategy,rto:rto||undefined,rpo:rpo||undefined};
      _reapplyBUDROverrides();
      _renderBUDRDash();
      budrNotify('Override saved for '+rid);
    });
  });
  body.querySelectorAll('.budr-ov-reset').forEach(function(btn){
    btn.addEventListener('click',function(e){
      e.stopPropagation();
      var rid=btn.dataset.rid;
      delete _budrOverrides[rid];
      _reapplyBUDROverrides();
      _renderBUDRDash();
      budrNotify('Override removed for '+rid);
    });
  });
  body.querySelectorAll('.budr-card').forEach(function(card){
    card.addEventListener('click',function(){
      var t=card.dataset.tier;
      st.tierFilter=st.tierFilter===t?'all':t;
      _renderBUDRDash();
    });
  });

  var fh='<button id="budrExportCSV">Export CSV</button>';
  fh+='<button id="budrExportJSON">Export JSON</button>';
  if(_isElectron) fh+='<button id="budrExportXLSX">Export XLSX</button>';
  fh+='<span style="margin-left:auto;font-size:10px;color:var(--text-muted)">'+items.length+' of '+total+' resources</span>';
  footer.innerHTML=fh;
  document.getElementById('budrExportCSV').addEventListener('click',function(){
    if(!_budrAssessments.length){budrNotify('No BUDR data');return}
    var csv='Type,Resource,Name,Tier,Strategy,RTO,RPO,Override,Signals\n';
    _budrAssessments.forEach(function(a){
      var tier=a.profile?a.profile.tier:'unknown';
      var strategy=a.profile?(_BUDR_STRATEGY[a.profile.strategy]||a.profile.strategy):'';
      var rto=a.profile?a.profile.rto:'';
      var rpo=a.profile?a.profile.rpo:'';
      var sigs=a.signals?Object.entries(a.signals).map(function(e){return e[0]+'='+e[1]}).join('; '):'';
      var ce=function(s){return String(s||'').replace(/"/g,'""')};
      csv+='"'+ce(a.type)+'","'+ce(a.id)+'","'+ce(a.name)+'","'+ce(tier)+'","'+ce(strategy)+'","'+ce(rto)+'","'+ce(rpo)+'","'+(a.overridden?'Yes':'No')+'","'+ce(sigs)+'"\n';
    });
    budrSaveBlob(new Blob([csv],{type:'text/csv'}),'budr-assessment.csv');
  });
  document.getElementById('budrExportJSON').addEventListener('click',function(){
    if(!_budrAssessments.length){budrNotify('No BUDR data');return}
    var data={timestamp:new Date().toISOString(),summary:_getBUDRTierCounts(),assessments:_budrAssessments,findings:_budrFindings,overrides:_budrOverrides};
    budrSaveBlob(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}),'budr-assessment.json');
  });
  var xlsxBtn=document.getElementById('budrExportXLSX');
  if(xlsxBtn) xlsxBtn.addEventListener('click',async function(){
    if(!_budrAssessments.length){budrNotify('No BUDR data');return}
    var data={timestamp:new Date().toISOString(),summary:_getBUDRTierCounts(),assessments:_budrAssessments,findings:_budrFindings,overrides:_budrOverrides};
    var jsonStr=JSON.stringify(data,null,2);
    budrNotify('Generating XLSX report\u2026');
    try{
      var result=await budrDesktopExportXlsx(jsonStr);
      if(!result){budrNotify('Export cancelled');return}
      if(result.error){budrNotify('Error: '+result.error,'error');return}
      budrNotify('Saved: '+result.path);
    }catch(e){budrNotify('XLSX export failed: '+e.message,'error')}
  });
}

document.getElementById('budrBtn').addEventListener('click',openBUDRDash);
