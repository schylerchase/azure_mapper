// #region REPORT IMPORT
// === Report Import ===
function _reportImportContext(){
  return AppRenderContext.createRenderContext();
}
function _reportImportNotify(message,type){
  AppNotifications.show(message,type);
}
function importReport(file){
  if(!file.name.match(/\.html?$/i)){_reportImportNotify('Please select an HTML report file (.html)');return}
  _reportImportNotify('Loading report: '+file.name+'...');
  var reader=new FileReader();
  reader.onload=function(e){
    try{_parseImportedReport(e.target.result)}
    catch(ex){_reportImportNotify('Failed to import report: '+ex.message);console.error('Report import failed:',ex)}
  };
  reader.readAsText(file);
}
function _parseImportedReport(htmlString){
  var doc=new DOMParser().parseFromString(htmlString,'text/html');
  var jsonEl=doc.getElementById('rpt-embedded-data');
  if(jsonEl){
    try{
      var blob=JSON.parse(jsonEl.textContent);
      if(blob._rptFormat==='azuremapper-report'){_applyImportedData(blob,'json');return}
    }catch(ex){console.warn('Embedded JSON parse failed, falling back to HTML parsing',ex)}
  }
  var parsed=_parseReportHTML(doc);
  if(!parsed.findings.length&&!parsed.budrAssessments.length&&!parsed.inventoryData.length&&!parsed.iamReviewData.length&&!parsed.appRegistry.length){
    _reportImportNotify('No report data found in this HTML file');return;
  }
  _applyImportedData(parsed,'html');
}
function _applyImportedData(data,source){
  var findings=data.findings||[];
  _reportImportContext().complianceFindings=findings;
  _budrAssessments=data.budrAssessments||[];
  _budrFindings=data.budrFindings||[];
  _inventoryData=data.inventoryData||[];
  // IAM review data: from HTML parse or JSON blob
  _iamReviewData=[];
  if(data.iamReviewData&&data.iamReviewData.length){
    _iamReviewData=data.iamReviewData.map(function(r){
      // Restore Date objects from strings if needed
      var copy={};for(let k in r)copy[k]=r[k];
      if(typeof copy.created==='string'&&copy.created&&copy.created!=='—')copy.created=new Date(copy.created);
      else if(typeof copy.created==='string')copy.created=null;
      if(typeof copy.lastUsed==='string'&&copy.lastUsed&&copy.lastUsed!=='Never'&&copy.lastUsed!=='—')copy.lastUsed=new Date(copy.lastUsed);
      else if(typeof copy.lastUsed==='string')copy.lastUsed=null;
      if(!Array.isArray(copy.findings))copy.findings=[];
      if(!Array.isArray(copy.crossAccounts))copy.crossAccounts=[];
      return copy;
    });
  }
  // App registry: from HTML parse or JSON blob
  _appRegistry=data.appRegistry||[];
  _importedReportData={
    title:data.title||'Imported Report',author:data.author||'',date:data.date||'',
    source:source,enabledModules:data.enabledModules||null,
    contexts:data.contexts||[],assessmentGaps:data.assessmentGaps||{},
    findingsCount:findings.length,
    assessmentsCount:_budrAssessments.length,
    inventoryCount:_inventoryData.length,
    iamCount:_iamReviewData.length,
    appCount:_appRegistry.length
  };
  _rptState.title=_importedReportData.title;
  _rptState.author=_importedReportData.author;
  _rptState.date=_importedReportData.date;
  _RPT_MODULES.forEach(function(m){
    if(m.id==='compliance') m.enabled=findings.length>0;
    else if(m.id==='budr') m.enabled=_budrAssessments.length>0;
    else if(m.id==='inventory') m.enabled=_inventoryData.length>0;
    else if(m.id==='action-plan') m.enabled=findings.length>0;
    else if(m.id==='exec-summary') m.enabled=true;
    else if(m.id==='iac-recs') m.enabled=findings.length>0;
    else if(m.id==='iam-review') m.enabled=_iamReviewData.length>0;
    else if(m.id==='app-summary') m.enabled=_appRegistry.length>0;
    else m.enabled=false;
  });
  if(_importedReportData.enabledModules) _rptState.order=_importedReportData.enabledModules;
  // Build _loadedContexts from explicit contexts or auto-discover from data
  var ctxList=data.contexts||[];
  if(!ctxList.length){
    // Auto-discover accounts from parsed data
    var acctSet={};
    findings.forEach(function(f){if(f._subscriptionId)acctSet[f._subscriptionId]=1});
    _budrAssessments.forEach(function(a){if(a.account)acctSet[a.account]=1});
    _inventoryData.forEach(function(r){if(r.account)acctSet[r.account]=1});
    _iamReviewData.forEach(function(r){
      var scoped=String(r.scope||'').match(/\/subscriptions\/([^/]+)/i);
      var account=r._subscriptionId||r.account||(scoped?scoped[1]:'');
      if(account)acctSet[account]=1;
    });
    var acctKeys=Object.keys(acctSet).filter(function(a){return a&&a!=='—'&&a!=='N/A'});
    if(acctKeys.length) ctxList=acctKeys.map(function(id){return{accountId:id,accountLabel:id}});
  }
  _loadedContexts=[];
  if(ctxList.length){
    var colors=['#6366f1','#ec4899','#f59e0b','#10b981','#06b6d4','#8b5cf6'];
    _loadedContexts=ctxList.map(function(c,i){
      return {accountId:c.accountId||'imported-'+i,accountLabel:c.accountLabel||c.accountId||'Imported',
        region:c.region||'',textareas:{},rlCtx:null,color:colors[i%colors.length],visible:true};
    });
  }
  document.getElementById('landingDash').style.display='none';
  var dashboard=document.getElementById('udash');
  var refreshReports=dashboard&&dashboard.classList&&dashboard.classList.contains('open')&&
    typeof DashboardState!=='undefined'&&DashboardState.getTab()==='reports';
  openUnifiedDash('reports');
  if(refreshReports)_renderReportsTab();
  var parts=[];
  if(findings.length) parts.push(findings.length+' findings');
  if(_budrAssessments.length) parts.push(_budrAssessments.length+' assessments');
  if(_inventoryData.length) parts.push(_inventoryData.length+' inventory items');
  if(_iamReviewData.length) parts.push(_iamReviewData.length+' IAM entities');
  if(_appRegistry.length) parts.push(_appRegistry.length+' applications');
  _reportImportNotify('Report imported: '+_importedReportData.title+
    (_importedReportData.date?' ('+_importedReportData.date+')':'')+
    (parts.length?' \u2014 '+parts.join(', '):''));
}
function _reverseFwLabel(label){
  var map={};for(let k in _FW_LABELS){if(_FW_LABELS.hasOwnProperty(k))map[_FW_LABELS[k]]=k}
  return map[label]||label;
}
function _parseSignalText(text){
  if(!text)return {};
  var sigs={};
  text.split(',').forEach(function(p){
    var t=p.trim();
    if(!t)return;
    var ci=t.indexOf(':');
    if(ci>0){sigs[t.slice(0,ci).trim()]=t.slice(ci+1).trim()}
    else{sigs[t]=true}
  });
  return sigs;
}
function _parseReportHTML(doc){
  var result={title:'',author:'',date:'',findings:[],budrAssessments:[],budrFindings:[],inventoryData:[],iamReviewData:[],appRegistry:[]};
  // Metadata from header
  var header=doc.querySelector('.rpt-header');
  if(header){
    var h1=header.querySelector('h1');
    if(h1)result.title=h1.textContent.trim();
    var sub=header.querySelector('.subtitle');
    if(sub){
      var parts=sub.textContent.split('\u2014');
      if(parts.length>=2){result.author=parts[0].trim();result.date=parts[1].trim()}
      else if(parts.length===1){
        var v=parts[0].trim();
        if(/^\d{4}/.test(v))result.date=v;else result.author=v;
      }
    }
  }
  if(!result.title){var te=doc.querySelector('title');if(te)result.title=te.textContent.trim()}
  // Compliance findings: flat table rows with data-sev + data-fw
  // New reports: 7 cols (Account, Severity, Framework, Control, Resource, Finding, Remediation)
  // Old reports: 6 cols (Severity, Framework, Control, Resource, Finding, Remediation)
  doc.querySelectorAll('tr[data-sev][data-fw]').forEach(function(tr){
    var tds=tr.querySelectorAll('td');
    var hasAcct=tds.length>=7;
    if(tds.length<6)return;
    var o=hasAcct?1:0;
    result.findings.push({
      _subscriptionId:tr.dataset.account||(hasAcct?tds[0].textContent.trim():'')||'',
      severity:tr.dataset.sev||tds[o].textContent.trim(),
      framework:_reverseFwLabel(tds[o+1].textContent.trim()),
      control:tds[o+2].textContent.trim().replace(/\s*\([A-Z_]+\d*\)\s*$/,''),
      resource:tds[o+3].textContent.trim(),
      resourceName:tds[o+3].textContent.trim(),
      message:tds[o+4].textContent.trim(),
      remediation:tds[o+5].textContent.trim()
    });
  });
  // Grouped findings fallback (handles old 4-col and new 5-col detail rows)
  if(!result.findings.length){
    doc.querySelectorAll('tr.rpt-ctrl-row').forEach(function(row){
      var sev=row.dataset.sev||'';
      var tds=row.querySelectorAll('td');
      var control=tds.length>=2?tds[1].textContent.replace(/^\u25B6\s*/,'').trim():'';
      // Extract framework from parent section heading (div#s-compliance-XX > h3)
      var fw='';
      var wrap=row.closest('[id^="s-compliance-"]');
      if(wrap){
        var fwId=wrap.id.replace('s-compliance-','');
        fw=fwId||'';
        if(!fw){var h3=wrap.querySelector('h3');if(h3)fw=_reverseFwLabel(h3.textContent.replace(/\s*\(\d+\)\s*$/,'').trim())}
      }
      var detail=row.nextElementSibling;
      if(!detail||!detail.classList.contains('rpt-ctrl-detail'))return;
      detail.querySelectorAll('table tr').forEach(function(ir){
        var itds=ir.querySelectorAll('td');
        if(itds.length<4)return;
        result.findings.push({
          severity:sev,_subscriptionId:itds.length>=5?itds[1].textContent.trim():'',
          resource:itds.length>=5?itds[2].textContent.trim():itds[1].textContent.trim(),
          resourceName:itds.length>=5?itds[2].textContent.trim():itds[1].textContent.trim(),
          message:itds.length>=5?itds[3].textContent.trim():itds[2].textContent.trim(),
          remediation:itds.length>=5?itds[4].textContent.trim():itds[3].textContent.trim(),
          framework:fw,control:control
        });
      });
    });
  }
  // Dedup findings by resource|control|severity
  var seen={};
  result.findings=result.findings.filter(function(f){
    var key=f.resource+'|'+f.control+'|'+f.severity;
    if(seen[key])return false;seen[key]=true;return true;
  });
  // BUDR assessments: rows with data-tier + data-strategy
  // New reports: 8 cols (Account, Type, Name, Tier, Strategy, RTO, RPO, Signals)
  // Old reports: 7 cols (Type, Name, Tier, Strategy, RTO, RPO, Signals)
  doc.querySelectorAll('tr[data-tier][data-strategy]').forEach(function(tr){
    var tds=tr.querySelectorAll('td');
    var hasAcct=tds.length>=8;
    if(tds.length<7)return;
    var o=hasAcct?1:0;
    result.budrAssessments.push({
      account:tr.dataset.account||(hasAcct?tds[0].textContent.trim():'')||'',
      type:tds[o].textContent.trim(),
      name:tds[o+1].textContent.trim(),id:tds[o+1].textContent.trim(),
      profile:{tier:tr.dataset.tier||'',strategy:tr.dataset.strategy||'',
        rto:tds[o+4].textContent.trim(),rpo:tds[o+5].textContent.trim()},
      signals:_parseSignalText(tds[o+6].textContent.trim())
    });
  });
  // Inventory: rows with id="res-*"
  // New reports have Account as first column; old reports start with Name
  doc.querySelectorAll('tr[id^="res-"]').forEach(function(tr){
    var tds=tr.querySelectorAll('td');
    if(tds.length<3)return;
    var type='';
    var wrap=tr.closest('.rpt-table-wrap');
    if(wrap){var prev=wrap.previousElementSibling;
      while(prev){if(prev.tagName==='H3'){type=prev.textContent.replace(/\s*\(\d+\)\s*$/,'').trim();break}prev=prev.previousElementSibling}}
    var hasAcct=!!tr.dataset.account||tds.length>=5;
    var id=tr.id.replace(/^res-/,'');
    var vals=[];for(let i=0;i<tds.length;i++)vals.push(tds[i].textContent.trim());
    result.inventoryData.push({
      id:id,type:type,name:hasAcct?vals[1]||'':vals[0]||'',
      account:hasAcct?vals[0]||'':'',
      region:vals[vals.length-1]||'',vpcId:'',vpcName:'',subnetId:'',az:'',
      state:'',config:vals.length>4?vals[hasAcct?3:2]:'',tags:{},
      encrypted:null,sgCount:0,classificationTier:null,
      budrTier:null,budrStrategy:null,rto:null,rpo:null,
      compliancePass:0,complianceFail:0
    });
  });
  // IAM Review: parse from section #s-iam-review
  _parseReportIAM(doc,result);
  // App Summary: parse from section #s-app-summary
  _parseReportAppSummary(doc,result);
  return result;
}
function _parseReportIAM(doc,result){
  var section=doc.getElementById('s-iam-review');
  if(!section)return;
  var tables=section.querySelectorAll('table');
  tables.forEach(function(tbl){
    var heading=tbl.previousElementSibling;
    while(heading&&heading.tagName!=='H4')heading=heading.previousElementSibling;
    var headingText=heading?heading.textContent.trim().toLowerCase():'';
    var rows=tbl.querySelectorAll('tbody tr');
    if(!rows.length)return;
    if(headingText.indexOf('admin')>=0){
      // Admin Access: Name, Type, Created, Last Used, Policies, Findings
      rows.forEach(function(tr){
        var tds=tr.querySelectorAll('td');
        if(tds.length<6)return;
        result.iamReviewData.push({
          name:tds[0].textContent.trim(),type:tds[1].textContent.trim(),
          created:tds[2].textContent.trim(),lastUsed:tds[3].textContent.trim(),
          isAdmin:true,policies:parseInt(tds[4].textContent.trim())||0,
          findings:_parseFindingsCount(tds[5].textContent.trim()),
          crossAccounts:[],hasMFA:null,hasConsole:null,activeKeys:0
        });
      });
    }else if(headingText.indexOf('cross')>=0){
      // Cross-Account: Role, Trusted Accounts, Admin, Findings
      rows.forEach(function(tr){
        var tds=tr.querySelectorAll('td');
        if(tds.length<4)return;
        var name=tds[0].textContent.trim();
        var existing=result.iamReviewData.find(function(r){return r.name===name});
        var crossAccts=tds[1].textContent.trim().split(',').map(function(s){return s.trim()}).filter(Boolean);
        var isAdmin=tds[2].textContent.trim().toLowerCase()==='yes';
        if(existing){
          existing.crossAccounts=crossAccts;
          if(isAdmin)existing.isAdmin=true;
        }else{
          result.iamReviewData.push({
            name:name,type:'Role',created:'',lastUsed:'',
            isAdmin:isAdmin,policies:0,
            findings:_parseFindingsCount(tds[3].textContent.trim()),
            crossAccounts:crossAccts,hasMFA:null,hasConsole:null,activeKeys:0
          });
        }
      });
    }else if(headingText.indexOf('user')>=0||headingText.indexOf('attention')>=0){
      // Users: User, MFA, Console, Active Keys, Admin, Findings
      rows.forEach(function(tr){
        var tds=tr.querySelectorAll('td');
        if(tds.length<6)return;
        var name=tds[0].textContent.trim();
        var existing=result.iamReviewData.find(function(r){return r.name===name});
        if(existing){
          existing.hasMFA=tds[1].textContent.trim().toLowerCase()==='yes';
          existing.hasConsole=tds[2].textContent.trim().toLowerCase()==='yes';
          existing.activeKeys=parseInt(tds[3].textContent.trim())||0;
        }else{
          result.iamReviewData.push({
            name:name,type:'User',created:'',lastUsed:'',
            isAdmin:tds[4].textContent.trim().toLowerCase()==='yes',
            policies:0,findings:_parseFindingsCount(tds[5].textContent.trim()),
            crossAccounts:[],
            hasMFA:tds[1].textContent.trim().toLowerCase()==='yes',
            hasConsole:tds[2].textContent.trim().toLowerCase()==='yes',
            activeKeys:parseInt(tds[3].textContent.trim())||0
          });
        }
      });
    }
  });
}
function _parseFindingsCount(text){
  var n=parseInt(text);
  if(isNaN(n)||n<=0)return [];
  var arr=[];for(let i=0;i<n;i++)arr.push({message:'Imported finding'});
  return arr;
}
function _parseReportAppSummary(doc,result){
  var section=doc.getElementById('s-app-summary');
  if(!section)return;
  // First table is the summary: Application, Type, Criticality, Resources, RPO, RTO
  var tables=section.querySelectorAll('table');
  if(!tables.length)return;
  var summaryTbl=tables[0];
  summaryTbl.querySelectorAll('tbody tr').forEach(function(tr){
    var tds=tr.querySelectorAll('td');
    if(tds.length<4)return;
    var name=tds[0].textContent.trim();
    var type=tds[1].textContent.trim();
    var tier=tds[2].textContent.trim().toLowerCase();
    result.appRegistry.push({name:name,pattern:name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&').replace(/[\s_-]+/g,'[\\s_-]+'),type:type==='—'?'':type,tier:tier,auto:false});
  });
}
document.getElementById('importReportInput').addEventListener('change',function(){
  if(this.files[0])importReport(this.files[0]);this.value='';
});

// #endregion REPORT IMPORT
