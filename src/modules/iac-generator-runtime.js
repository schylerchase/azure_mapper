// #region IAC GENERATOR
// === TERRAFORM / ARM / BICEP EXPORT ===
let _iacType='terraform'; // 'terraform' | 'arm' | 'bicep'
let _iacOutput=''; // raw generated text

function iacRuntimeContext(){
  if(typeof AppRenderContext!=='undefined'&&AppRenderContext.createRenderContext){
    return AppRenderContext.createRenderContext();
  }
  return null;
}

function iacRuntimeData(){
  var context=iacRuntimeContext();
  return context?context.rlCtx:null;
}

function iacComplianceFindings(){
  var context=iacRuntimeContext();
  return context?context.complianceFindings:[];
}

function iacNotify(message,type){
  var notifications=typeof AppNotifications!=='undefined'?AppNotifications:null;
  if(notifications&&notifications.show)return notifications.show(message,type);
}

function iacDownload(blob,name){
  var downloads=typeof AppDownloads!=='undefined'?AppDownloads:null;
  if(downloads&&downloads.saveBlob)return downloads.saveBlob(blob,name);
}

function iacModules(){
  return (typeof AppModules!=='undefined'?AppModules:null)||{};
}

function iacActiveDashboardTab(){
  return typeof DashboardState!=='undefined'&&DashboardState.getTab?DashboardState.getTab():null;
}

function iacToggleDashboardTab(tabId){
  if(iacActiveDashboardTab()===tabId)closeUnifiedDash();
  else openUnifiedDash(tabId);
}

async function iacEnsureGenerator(){
  var modules=iacModules();
  if(modules.IacGenerator)return modules.IacGenerator;
  var load=typeof _loadIacGenerator!=='undefined'?_loadIacGenerator:null;
  if(load)await load();
  return iacModules().IacGenerator||null;
}

function iacGeneratorOptions(opts){
  var next=Object.assign({},opts);
  next.variables=opts.includeVars!==false;
  next.designOnly=opts.mode==='create';
  if(next.designOnly){
    var changes=typeof _designChanges!=='undefined'?_designChanges:[];
    next.designResourceIds=changes.filter(function(change){return !change._invalid}).flatMap(function(change){
      return [].concat(change._addedIds||[],change._modifiedIds||[],change.params&&change.params._rtId||[],change.params&&change.params._sgId||[]);
    });
  }
  return next;
}

function iacResult(value){
  if(typeof value==='string')return {code:value,warnings:[],stats:{}};
  if(value&&typeof value==='object')return value;
  return {code:'# No IaC output generated',warnings:[],stats:{}};
}

function iacGeneratorFunction(generator,type){
  if(!generator)return null;
  if(type==='terraform')return generator.generateTerraform;
  if(type==='bicep')return generator.generateBicep;
  if(type==='arm')return generator.generateARM;
  return null;
}

function iacGeneratorUnavailable(type){
  var label=type==='terraform'?'Terraform':type==='bicep'?'Bicep':'ARM template';
  iacNotify('IaC generator bundle is unavailable', 'error');
  document.getElementById('iacPreview').innerHTML=
    '<div class="iac-empty">'+label+' generation could not load. Rebuild the app bundle and try again.</div>';
}

// --- Syntax Highlighting (basic HCL) ---
function _highlightHCL(code){
  // Escape HTML first
  code=code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  // Process line-by-line to avoid cross-match issues
  return code.split('\n').map(line=>{
    // Comments take precedence
    if(line.match(/^\s*#/))return '<span class="hcl-cmt">'+line+'</span>';
    // Strings: replace "..." with colored spans
    line=line.replace(/"([^"]*)"/g,function(_,s){return '"<span class="hcl-str">'+s+'</span>"'});
    // Keywords
    line=line.replace(/\b(resource|variable|data|module|provider|output|terraform|required_providers|import|locals|dynamic)\b/g,'<span class="hcl-kw">$1</span>');
    // Types
    line=line.replace(/\b(string|number|bool|list|map|set|object|any)\b/g,'<span class="hcl-type">$1</span>');
    // Numbers (standalone, not inside strings)
    line=line.replace(/= (\d+)$/g,'= <span class="hcl-num">$1</span>');
    // Booleans
    line=line.replace(/\b(true|false|null)\b/g,'<span class="hcl-num">$1</span>');
    // Resource refs
    line=line.replace(/(azurerm_[a-z_]+\.[a-z_0-9]+\.[a-z_]+)/g,'<span class="hcl-ref">$1</span>');
    return line;
  }).join('\n');
}

function _highlightYAML(code){
  code=code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return code.split('\n').map(line=>{
    if(line.match(/^\s*#/))return '<span class="hcl-cmt">'+line+'</span>';
    line=line.replace(/(\[parameters|concat|resourceId|reference|variables|subscription|resourceGroup)\b/g,'<span class="hcl-kw">$1</span>');
    line=line.replace(/(Microsoft\.[A-Za-z0-9./]+)/g,'<span class="hcl-type">$1</span>');
    line=line.replace(/'([^']*)'/g,"'<span class=\"hcl-str\">$1</span>'");
    line=line.replace(/\b(true|false|null)\b/g,'<span class="hcl-num">$1</span>');
    return line;
  }).join('\n');
}

// --- IaC Modal UI ---
function openIacModal(type){
  _iacType=type;
  const modal=document.getElementById('iacModal');
  const title=document.getElementById('iacTitle');
  title.textContent=type==='terraform'?'Export as Terraform HCL':type==='bicep'?'Export as Bicep':'Export as ARM Template';

  // Populate VNet scope dropdown
  const scopeSel=document.getElementById('iacScope');
  scopeSel.innerHTML='<option value="all">All Resources</option>';
  const ctx=iacRuntimeData();
  if(ctx&&ctx.vnets){
    ctx.vnets.forEach(vpc=>{
      const n=(vpc.tags&&(vpc.tags.Name||vpc.tags.name))||vpc.name||vpc.id;
      const label=n||vpc.id||'VNet';
      scopeSel.innerHTML+='<option value="'+esc(vpc.id||vpc.VpcId)+'">'+esc(label)+'</option>';
    });
  }

  // Toggle TF-only options
  const modularLabel=document.getElementById('iacModular').parentElement;
  const formatSel=document.getElementById('iacFormat');
  if(type==='arm'){
    modularLabel.style.display='none';
    formatSel.innerHTML='<option value="json">JSON</option>';
  }else if(type==='bicep'){
    modularLabel.style.display='none';
    formatSel.innerHTML='<option value="bicep">Bicep</option>';
  }else{
    modularLabel.style.display='';
    formatSel.innerHTML='<option value="hcl">HCL</option>';
  }

  // Reset preview
  document.getElementById('iacPreview').innerHTML='<div class="iac-empty">Click Generate to preview code</div>';

  modal.classList.add('open');
}

function closeIacModal(){
  document.getElementById('iacModal').classList.remove('open');
  _iacOutput='';
}

async function generateIacPreview(){
  const ctx=iacRuntimeData();
  const vnetArr=ctx&&(ctx.vnets||ctx.vpcs);
  if(!ctx||!vnetArr||!vnetArr.length){
    document.getElementById('iacPreview').innerHTML='<div class="iac-empty">No data loaded. Render a map first.</div>';
    return;
  }
  const opts={
    mode:document.getElementById('iacMode').value,
    scopeVpcId:document.getElementById('iacScope').value==='all'?null:document.getElementById('iacScope').value,
    includeVars:document.getElementById('iacVars').checked,
    modular:document.getElementById('iacModular').checked,
    format:document.getElementById('iacFormat').value
  };

  const generator=await iacEnsureGenerator();
  const runGenerator=iacGeneratorFunction(generator,_iacType);
  if(!runGenerator){
    iacGeneratorUnavailable(_iacType);
    return;
  }

  let result;
  if(_iacType==='terraform'){
    const tfOptions=iacGeneratorOptions(opts);
    result=iacResult(runGenerator(ctx,tfOptions));
  }else{
    result=iacResult(runGenerator(ctx,iacGeneratorOptions(opts)));
  }
  _iacOutput=result.code||'';

  const preview=document.getElementById('iacPreview');
  let html='';

  // Warnings
  if(result.warnings&&result.warnings.length){
    html+='<div class="iac-warn">'+result.warnings.map(w=>'&#9888; '+esc(w)).join('<br>')+'</div>';
  }
  if(result.blocked){
    preview.innerHTML=html+'<div class="iac-empty">Export blocked. Resolve the requirements above and generate again.</div>';
    return;
  }

  // Stats
  if(result.stats){
    const s=result.stats;
    const parts=[];
    if(s.vpcs)parts.push(s.vpcs+' VNets');
    if(s.subnets)parts.push(s.subnets+' Subnets');
    if(s.sgs)parts.push(s.sgs+' NSGs');
    if(s.instances)parts.push(s.instances+' VMs');
    if(s.total)parts.push(s.total+' total resources');
    if(s.resources)parts.push(s.resources+' ARM resources');
    if(parts.length)html+='<div style="padding:6px 20px;font-family:Segoe UI,system-ui,sans-serif;font-size:10px;color:var(--text-muted);border-bottom:1px solid var(--border)">'+parts.join(' | ')+'</div>';
  }

  // Highlighted code
  const highlighted=(_iacType==='terraform'||_iacType==='bicep')?_highlightHCL(result.code):
    (opts.format==='json'?_highlightHCL(result.code):_highlightYAML(result.code));
  html+='<pre>'+highlighted+'</pre>';

  preview.innerHTML=html;
}

// --- Event listeners ---
document.getElementById('expTerraform').addEventListener('click',()=>openIacModal('terraform'));
document.getElementById('expArmTemplate')?.addEventListener('click',()=>openIacModal('arm'));
document.getElementById('expBicep')?.addEventListener('click',()=>openIacModal('bicep'));
document.getElementById('iacClose').addEventListener('click',closeIacModal);
document.getElementById('iacModal').addEventListener('click',function(e){if(e.target===this)closeIacModal()});
document.getElementById('iacGenerate').addEventListener('click',generateIacPreview);

document.getElementById('iacCopy').addEventListener('click',()=>{
  if(!_iacOutput){iacNotify('Generate code first');return}
  navigator.clipboard.writeText(_iacOutput).then(()=>{
    const btn=document.getElementById('iacCopy');
    btn.textContent='Copied!';
    setTimeout(()=>{btn.textContent='Copy to Clipboard'},1500);
  }).catch(()=>{
    // Fallback
    const ta=document.createElement('textarea');
    ta.value=_iacOutput;document.body.appendChild(ta);ta.select();
    document.execCommand('copy');document.body.removeChild(ta);
    const btn=document.getElementById('iacCopy');
    btn.textContent='Copied!';
    setTimeout(()=>{btn.textContent='Copy to Clipboard'},1500);
  });
});

document.getElementById('iacDownload').addEventListener('click',()=>{
  if(!_iacOutput){iacNotify('Generate code first');return}
  let ext,name;
  if(_iacType==='terraform'){
    ext='.tf';
    name='main'+ext;
  }else if(_iacType==='bicep'){
    name='main.bicep';
  }else{
    ext=document.getElementById('iacFormat').value==='json'?'.json':'.yaml';
    name='template'+ext;
  }
  const blob=new Blob([_iacOutput],{type:'text/plain'});
  iacDownload(blob,name);
});

// Compliance export modal listeners
document.getElementById('compExportClose').addEventListener('click',()=>document.getElementById('compExportModal').classList.remove('open'));
document.getElementById('compExportModal').addEventListener('click',function(e){if(e.target===this)this.classList.remove('open')});
document.getElementById('compExpCancel').addEventListener('click',()=>document.getElementById('compExportModal').classList.remove('open'));
document.querySelectorAll('#compExportModal input[type="checkbox"]').forEach(cb=>cb.addEventListener('change',_updateCompExpPreview));
// Scope toggle: show/hide compliance-specific filters for Full Assessment mode
document.querySelectorAll('input[name="compExpScope"]').forEach(function(r){
  r.addEventListener('change',function(){
    var isFull=document.getElementById('compExpScopeFull').checked;
    document.getElementById('compExpFilters').style.display=isFull?'none':'flex';
    document.getElementById('compExpMutedWrap').style.display=isFull?'none':'';
    document.getElementById('compExpRemWrap').style.display=isFull?'none':'';
    _updateCompExpPreview();
  });
});
document.getElementById('compExpDownload').addEventListener('click',()=>{
  var isFull=document.getElementById('compExpScopeFull').checked;
  var fmt=document.getElementById('compExpFormat').value;
  document.getElementById('compExportModal').classList.remove('open');
  if(isFull){
    if(fmt==='xlsx')_exportFullXlsx();
    else if(fmt==='csv')_exportFullCSV();
    else _exportFullHTML();
  }else{
    var fws=[...document.querySelectorAll('#compExportModal [data-comp-fw]:checked')].map(el=>el.dataset.compFw);
    var sevs=[...document.querySelectorAll('#compExportModal [data-comp-sev]:checked')].map(el=>el.dataset.compSev);
    var opts={frameworks:fws,severities:sevs,includeMuted:document.getElementById('compExpMuted').checked,includeRemediation:document.getElementById('compExpRemediation').checked};
    var findings=iacComplianceFindings();
    if(fmt==='xlsx')_exportComplianceXlsx(opts);
    else if(fmt==='csv')_exportFilteredCSV(findings,opts);
    else _exportComplianceHTML(findings,opts);
  }
});

// Keyboard shortcuts
document.addEventListener('keydown',function(e){
  const tag=e.target.tagName;
  if(e.key==='Escape'){
    if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT')e.target.blur();
    const fwFp=document.getElementById('fwFullPanel');if(fwFp&&fwFp.classList.contains('open')){fwFp.classList.remove('open');return}

    const iacM=document.getElementById('iacModal');if(iacM&&iacM.classList.contains('open')){closeIacModal();return}
    if(document.getElementById('compExportModal').classList.contains('open')){document.getElementById('compExportModal').classList.remove('open');return}
    var govRO=document.getElementById('govRulesOverlay');if(govRO){govRO.remove();return}
    if(document.getElementById('udash').classList.contains('open')){closeUnifiedDash();return}
    const dep=document.getElementById('depOverlay');if(dep&&dep.classList.contains('open')){dep.classList.remove('open');return}
    const np=document.getElementById('notesPanel');if(np&&np.classList.contains('open')){closeNotesPanel();return}
    const ap=document.getElementById('accountPanel');if(ap&&ap.classList.contains('open')){closeAccountPanel();return}
    const so=document.getElementById('searchOverlay'),ho=document.getElementById('helpOverlay');
    if(so&&so.style.display!=='none'){if(typeof SearchPanel!=='undefined')SearchPanel.close();return}
    if(ho&&ho.style.display!=='none'){ho.style.display='none';return}
    document.getElementById('detailPanel').classList.remove('open');
    if(typeof _hlLocked!=='undefined'){_hlLocked=false;_hlKey=null;_hlType=null}
    const lockInd=document.getElementById('hlLockInd');if(lockInd)lockInd.style.display='none';
    if(_flowMode){exitFlowMode();return}
    if(_flowAnalysisMode){exitFlowAnalysis();return}
    if(_diffMode){exitDiffMode();return}
    if(_designMode)exitDesignMode();
    return;
  }
  if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT') return;
  if(_flowMode&&_flowPath&&_flowPath.length>0){
    if(e.key==='ArrowRight'){_stepForward();return}
    if(e.key==='ArrowLeft'){_stepBack();return}
  }
  if(e.ctrlKey||e.metaKey){
    if(e.key==='='||e.key==='+'){e.preventDefault();gTxtScale=Math.min(2.5,gTxtScale+0.15);applyGlobalTxtScale();savePrefs({gTxtScale});return}
    if(e.key==='-'){e.preventDefault();gTxtScale=Math.max(0.5,gTxtScale-0.15);applyGlobalTxtScale();savePrefs({gTxtScale});return}
    if(e.key==='0'){e.preventDefault();gTxtScale=1.0;applyGlobalTxtScale();savePrefs({gTxtScale});return}
  }
  if(e.key==='+'||e.key==='='){d3.select('#zoomIn').dispatch('click');return}
  if(e.key==='-'){d3.select('#zoomOut').dispatch('click');return}
  if(e.key==='f'){d3.select('#zoomFit').dispatch('click');return}
  if(e.key==='T'&&e.shiftKey){if(_flowMode)exitFlowMode();else enterFlowMode();return}
  if(e.key==='F'&&e.shiftKey){if(_flowAnalysisMode)exitFlowAnalysis();else enterFlowAnalysis();return}
  if(e.key==='R'&&e.shiftKey){iacToggleDashboardTab('reports');return}
  if(e.key==='G'&&e.shiftKey){iacToggleDashboardTab('classification');return}
  if(e.key==='B'&&e.shiftKey){iacToggleDashboardTab('budr');return}
  if(e.key==='C'&&e.shiftKey){iacToggleDashboardTab('compliance');return}
  if(e.key==='I'&&e.shiftKey){iacToggleDashboardTab('inventory');return}
  if(e.key==='D'&&e.shiftKey){if(_diffMode)exitDiffMode();else document.getElementById('diffFileInput').click();return}
  if(e.key==='d'&&!e.shiftKey){if(_designMode)exitDesignMode();else enterDesignMode();return}
  if(e.key==='z'&&_designMode){undoLastChange();return}
  if(e.key==='e'&&_designMode&&_designChanges.length){exportDesignPlan('design-plan');return}
  if(e.key==='/'){e.preventDefault();if(document.getElementById('udash').classList.contains('open'))closeUnifiedDash();if(typeof SearchPanel!=='undefined')SearchPanel.open();return}
  if(e.key==='n'){openNotesPanel();return}
  if(e.key==='b'&&!_designMode){if(_blastActive){_clearBlastRadius()}return}
  if(e.key==='h'&&!_designMode){const tb=document.getElementById('timelineBar');if(tb.classList.contains('open'))closeTimeline();else openTimeline();return}

  if(e.key==='A'&&e.shiftKey){_toggleAccountPanel();return}
});

/* Prevent iOS Safari from intercepting pinch/zoom gestures on the map */
(function(){
  var m=_getMain();
  if(!m)return;
  m.addEventListener('gesturestart',function(e){e.preventDefault()},{passive:false});
  m.addEventListener('gesturechange',function(e){e.preventDefault()},{passive:false});
  m.addEventListener('gestureend',function(e){e.preventDefault()},{passive:false});
})();

// #endregion IAC GENERATOR

