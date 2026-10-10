// #region SESSION & EVENT WIRING
// === AUTO-SAVE / CRASH RECOVERY ===
const _SAVE_KEY='azureMapper_session';const _SAVE_INTERVAL=30000;
var _autoSaveDisabled=false;
var _sessionDirty=false;
const _dirtyInputs=new Set();
function sessionRenderContext(){
  return typeof AppRenderContext!=='undefined'?AppRenderContext.createRenderContext():null;
}
function sessionCurrentData(){
  const adapter=sessionRenderContext();
  return adapter?adapter.rlCtx:null;
}
function sessionSetData(value){
  const adapter=sessionRenderContext();
  if(adapter)adapter.rlCtx=value;
}
function sessionResetComplianceRows(){
  const adapter=sessionRenderContext();
  if(adapter)adapter.complianceFindings=[];
}
function sessionNotify(message,type){
  if(typeof AppNotifications!=='undefined'&&AppNotifications.show)AppNotifications.show(message,type);
}
function sessionSaveBlob(blob,name){
  if(typeof AppDownloads!=='undefined'&&AppDownloads.saveBlob)return AppDownloads.saveBlob(blob,name);
}
function sessionViewportWidth(){
  var view=document.defaultView||null;
  return (view&&view.innerWidth)||document.documentElement.clientWidth||0;
}
async function sessionEnsureDemoData(){
  if(typeof generateDemo!=='undefined'&&typeof generateDemo==='function')return;
  const loader=typeof _loadDemoData!=='undefined'?_loadDemoData:null;
  if(typeof loader==='function')await loader();
}
function _autoSaveSession(force){if(_autoSaveDisabled||(typeof _viewingHistory!=='undefined'&&_viewingHistory))return;
  if(force){_sessionDirty=true;document.querySelectorAll('.ji').forEach(el=>_dirtyInputs.add(el.id))}
  if(!_sessionDirty)return;_sessionDirty=false;try{
  let data={};
  const raw=sessionStorage.getItem(_SAVE_KEY);if(raw){try{data=JSON.parse(raw)}catch(e){data={}}}
  _dirtyInputs.forEach(id=>{const el=document.getElementById(id);if(!el)return;if(!el.value.trim()||el.value.length>100000){delete data[id];return}data[id]=el.value});
  _dirtyInputs.clear();
  data._accountLabel=(document.getElementById('accountLabel')||{}).value||'';data._layout=(document.getElementById('layoutMode')||{}).value||'grid';
  if(_rptState.logo)data._rptLogo=_rptState.logo;data._ts=Date.now();
  sessionStorage.setItem(_SAVE_KEY,JSON.stringify(data))}catch(e){if(e.name==='QuotaExceededError'){_autoSaveDisabled=true;console.warn('[auto-save] disabled: session too large for storage')}else{console.warn('[auto-save] failed:',e)}}}
function _restoreSession(){try{const raw=sessionStorage.getItem(_SAVE_KEY);if(!raw)return false;const data=JSON.parse(raw);if(!data._ts)return false;
  if(Date.now()-data._ts>7*24*60*60*1000){sessionStorage.removeItem(_SAVE_KEY);return false}
  let hasData=false;Object.entries(data).forEach(([k,v])=>{if(k.startsWith('_'))return;const el=document.getElementById(k);if(el){el.value=v;el.className='ji valid';hasData=true}});
  if(data._accountLabel){const al=document.getElementById('accountLabel');if(al)al.value=data._accountLabel}
  if(data._layout){const lm=document.getElementById('layoutMode');if(lm)lm.value=data._layout}
  if(data._rptLogo){_rptState.logo=data._rptLogo}
  return hasData}catch(e){console.warn('[session-restore] failed:',e);return false}}
if(_isElectron){_autoSaveDisabled=true}
setInterval(()=>{if(sessionCurrentData())_autoSaveSession()},_SAVE_INTERVAL);
(function(){try{const raw=sessionStorage.getItem(_SAVE_KEY);if(!raw)return;const data=JSON.parse(raw);if(!data._ts||Date.now()-data._ts>7*24*60*60*1000)return;
  let count=Object.keys(data).filter(k=>!k.startsWith('_')).length;if(count===0)return;
  const banner=document.createElement('div');banner.id='restoreBanner';
  banner.style.cssText='position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:200;background:var(--bg-tertiary);border:1px solid var(--accent-cyan);border-radius:8px;padding:12px 20px;display:flex;align-items:center;gap:12px;box-shadow:0 4px 20px rgba(0,0,0,.5)';
  const age=Math.round((Date.now()-data._ts)/60000);const ageStr=age<60?age+'m ago':Math.round(age/60)+'h ago';
  banner.innerHTML='<span style="font-size:12px;color:var(--text-primary)">Recover previous session? ('+count+' inputs, '+ageStr+')</span><button id="restoreYes" style="background:var(--accent-cyan);color:#000;border:none;border-radius:4px;padding:6px 14px;font-size:11px;font-weight:600;cursor:pointer">Restore</button><button id="restoreNo" style="background:none;border:1px solid var(--border);border-radius:4px;color:var(--text-muted);padding:6px 14px;font-size:11px;cursor:pointer">Dismiss</button>';
  document.body.appendChild(banner);
  document.getElementById('restoreYes').addEventListener('click',()=>{if(_restoreSession()){renderMap(()=>{_autoSaveSession()})}banner.remove()});
  document.getElementById('restoreNo').addEventListener('click',()=>{banner.remove()});
  setTimeout(()=>{if(banner.parentNode)banner.remove()},15000);
}catch(e){console.warn('[session-restore] banner failed:',e)}})();

// Design mode toggle
document.getElementById('designToggle').addEventListener('click',()=>{
  if(_designMode)exitDesignMode();else enterDesignMode();
});
// Design banner close
document.getElementById('designBannerClose').addEventListener('click',()=>{
  document.getElementById('designBanner').classList.remove('visible');
});
// Design help tooltip on hover
(function(){
  const btn=document.getElementById('designToggle');
  const help=document.getElementById('designHelp');
  let hoverTimeout=null;
  btn.addEventListener('mouseenter',()=>{
    if(_designMode)return;
    hoverTimeout=setTimeout(()=>{help.classList.add('visible')},400);
  });
  btn.addEventListener('mouseleave',()=>{
    clearTimeout(hoverTimeout);
    setTimeout(()=>{help.classList.remove('visible')},200);
  });
  help.addEventListener('mouseenter',()=>{clearTimeout(hoverTimeout)});
  help.addEventListener('mouseleave',()=>{help.classList.remove('visible')});
})();

// Export bar collapse toggle
document.getElementById('ebToggle').addEventListener('click',function(){
  const eb=document.getElementById('exportBar');
  eb.classList.toggle('collapsed');
  this.innerHTML=eb.classList.contains('collapsed')?'Export &#9654;':'Export &#9660;';
});

// Highlight lock indicator click to unlock
document.getElementById('hlLockInd').addEventListener('click',function(){
  document.dispatchEvent(new CustomEvent('hl-unlock'));
});

// Fullscreen icon helper: expand arrows vs collapse arrows
function _setDpFullscreenIcon(isFs){
  var el=document.getElementById('dpFullscreen');
  while(el.firstChild)el.removeChild(el.firstChild);
  var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('viewBox','0 0 16 16');svg.setAttribute('width','12');svg.setAttribute('height','12');
  svg.setAttribute('fill','none');svg.setAttribute('stroke','currentColor');svg.setAttribute('stroke-width','1.5');
  var p=document.createElementNS('http://www.w3.org/2000/svg','path');
  p.setAttribute('d',isFs?'M6 1H1v5M10 1h5v5M6 15H1v-5M10 15h5v-5':'M1 6V1h5M15 6V1h-5M1 10v5h5M15 10v5h-5');
  svg.appendChild(p);el.appendChild(svg);
}
// detail panel close handlers
document.getElementById('dpClose').addEventListener('click',()=>{
  var dp=document.getElementById('detailPanel');
  dp.classList.remove('open','fullscreen');
  _setDpFullscreenIcon(false);
  document.getElementById('dpExpandAll').style.display='none';
  document.getElementById('dpCollapseAll').style.display='none';
  document.getElementById('dpTraceFrom').style.display='none';
});
document.getElementById('dpExpandAll').addEventListener('click',()=>{
  document.getElementById('dpBody').querySelectorAll('.dp-sec-hdr.collapsed').forEach(el=>{el.classList.remove('collapsed');el.nextElementSibling.classList.remove('hidden')});
});
document.getElementById('dpCollapseAll').addEventListener('click',()=>{
  document.getElementById('dpBody').querySelectorAll('.dp-sec-hdr:not(.collapsed)').forEach(el=>{el.classList.add('collapsed');el.nextElementSibling.classList.add('hidden')});
});
document.getElementById('dpTraceFrom').addEventListener('click',()=>{
  const traceCtx=DetailTraceSelection.get();
  if(!traceCtx) return;
  if(_flowMode) exitFlowMode();
  document.getElementById('detailPanel').classList.remove('open');
  enterFlowMode(traceCtx);
});
document.getElementById('dpFullscreen').addEventListener('click',()=>{
  var dp=document.getElementById('detailPanel');
  dp.classList.toggle('fullscreen');
  _setDpFullscreenIcon(dp.classList.contains('fullscreen'));
});
document.getElementById('dpBody').addEventListener('click',function(e){
  const c=e.target.closest('.copyable');
  if(c){e.stopPropagation();copyText(c.dataset.copy||c.textContent.trim());return}
  const v=e.target.closest('.dp-kv .v');
  if(v&&v.textContent.trim()){e.stopPropagation();copyText(v.textContent.trim())}
});
// Full panel editor event handlers
document.getElementById('fwFpClose').addEventListener('click',function(){
  document.getElementById('fwFullPanel').classList.remove('open');
});
document.getElementById('fwFpTabs').addEventListener('click',function(e){
  var tab=e.target.closest('.fw-fp-tab');
  if(!tab) return;
  _fwFpDir=tab.getAttribute('data-dir');
  _fwRefreshFullPanel();
});
document.getElementById('fwFpRetrace').addEventListener('click',function(){
  if(_flowMode&&typeof _executeTrace==='function') _executeTrace();
});
document.getElementById('fwFpCopy').addEventListener('click',function(){
  var cliEl=document.getElementById('fwFpCli');
  var txt=cliEl.textContent||'';
  if(!txt||txt==='No pending edits'){
    var btn=this;btn.textContent='No edits';setTimeout(function(){btn.textContent='Copy CLI'},1500);
    return;
  }
  var btn=this;
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).then(function(){
      btn.textContent='Copied!';setTimeout(function(){btn.textContent='Copy CLI'},1500);
    }).catch(function(){btn.textContent='Copy failed';setTimeout(function(){btn.textContent='Copy CLI'},1500)});
  } else {
    btn.textContent='No clipboard';setTimeout(function(){btn.textContent='Copy CLI'},1500);
  }
});
_getMain().addEventListener('click',function(e){
  if(!e.target.closest('.detail-panel')&&!e.target.closest('.fw-full-panel')&&!e.target.closest('.dep-overlay')&&!e.target.closest('.subnet-node')&&!e.target.closest('.gw-node')&&!e.target.closest('.lz-gw-node')&&!e.target.closest('.lz-tgw-node')&&!e.target.closest('.export-bar')&&!e.target.closest('.zoom-controls')&&!e.target.closest('.stats-bar')&&!e.target.closest('.diff-summary')&&!e.target.closest('.diff-banner')){
    document.getElementById('detailPanel').classList.remove('open');
    _clearBlastRadius();
  }
});

// Mobile swipe-down to close detail panel
(function(){
  const dp=document.getElementById('detailPanel');
  const dh=document.getElementById('dpDragHandle');
  let startY=0,currentY=0,dragging=false;
  dh.addEventListener('touchstart',function(e){startY=e.touches[0].clientY;currentY=startY;dragging=true;dp.style.transition='none'},{passive:true});
  dh.addEventListener('touchmove',function(e){
    if(!dragging)return;currentY=e.touches[0].clientY;
    const dy=currentY-startY;if(dy>0)dp.style.transform='translateY('+dy+'px)';
  },{passive:true});
  dh.addEventListener('touchend',function(){
    if(!dragging)return;dragging=false;dp.style.transition='transform .25s ease';
    if(currentY-startY>80){dp.classList.remove('open');dp.style.transform=''}
    else{dp.style.transform=''}
  });
})();

// Desktop detail panel resize (drag left edge)
(function(){
  const rh=document.getElementById('dpResizeHandle');
  const dp=document.getElementById('detailPanel');
  if(!rh||!dp)return;
  let resizing=false,startX=0,startW=0;
  const minW=280,maxW=Math.min(900,sessionViewportWidth()*0.7);
  // Restore saved width
  const savedW=_prefs.dpWidth;
  if(savedW&&savedW>=minW&&savedW<=maxW){dp.style.width=savedW+'px';}
  function onDpResizeMove(e){
    const dx=startX-e.clientX;
    const nw=Math.max(minW,Math.min(maxW,startW+dx));
    dp.style.width=nw+'px';
  }
  function onDpResizeUp(){
    document.removeEventListener('mousemove',onDpResizeMove);
    document.removeEventListener('mouseup',onDpResizeUp);
    resizing=false;
    rh.classList.remove('active');document.body.style.cursor='';document.body.style.userSelect='';
    savePrefs({dpWidth:dp.offsetWidth});
  }
  rh.addEventListener('mousedown',function(e){
    if(sessionViewportWidth()<=768)return;
    e.preventDefault();resizing=true;startX=e.clientX;startW=dp.offsetWidth;
    rh.classList.add('active');document.body.style.cursor='col-resize';document.body.style.userSelect='none';
    document.addEventListener('mousemove',onDpResizeMove);
    document.addEventListener('mouseup',onDpResizeUp);
  });
})();

// detail panel text size
let dpScale=_prefs.dpScale||1.0;
function applyDpScale(){
  document.documentElement.style.setProperty('--dp-txt-scale',dpScale);
}
if(_prefs.dpScale) applyDpScale();
document.getElementById('dpSizeUp').addEventListener('click',()=>{dpScale=Math.min(2.0,dpScale+0.15);applyDpScale();savePrefs({dpScale})});
document.getElementById('dpSizeDown').addEventListener('click',()=>{dpScale=Math.max(0.5,dpScale-0.15);applyDpScale();savePrefs({dpScale})});
document.getElementById('dpSizeReset').addEventListener('click',()=>{dpScale=1.0;applyDpScale();savePrefs({dpScale})});

// fileMap + matchFile — extracted to src/modules/normalization.js

document.getElementById('uploadBtn').addEventListener('click',()=>document.getElementById('fileInput').click());
// Export script dropdown
(function(){
  var menu=document.getElementById('exportScriptMenu');
  document.getElementById('dlExportScript').addEventListener('click',function(e){
    e.stopPropagation();
    menu.style.display=menu.style.display==='none'?'block':'none';
  });
  document.addEventListener('click',function(){menu.style.display='none'});
  menu.addEventListener('click',function(e){e.stopPropagation()});
  ['dlBash','dlPowershell'].forEach(function(id){
    document.getElementById(id).addEventListener('mouseenter',function(){this.style.background='rgba(99,102,241,.15)'});
    document.getElementById(id).addEventListener('mouseleave',function(){this.style.background='none'});
  });
})();
async function sessionDownloadExportScript(name,mimeType){
  document.getElementById("exportScriptMenu").style.display="none";
  try{
    let text=null;
    if(typeof DesktopAzureAdapter!=='undefined'&&DesktopAzureAdapter.isAvailable()&&DesktopAzureAdapter.readExportScript)text=await DesktopAzureAdapter.readExportScript(name);
    if(typeof text!=='string'){
      const response=await fetch("./"+name);
      if(!response.ok)throw new Error("Could not load export script ("+response.status+")");
      text=await response.text();
    }
    sessionSaveBlob(new Blob([text],{type:mimeType}),name);
    sessionNotify("Export script downloaded: "+name);
  }catch(error){sessionNotify("Export script download failed: "+error.message,"error")}
}
document.getElementById("dlBash").addEventListener("click",()=>sessionDownloadExportScript("export-azure-data.sh","text/x-shellscript"));
document.getElementById("dlPowershell").addEventListener("click",()=>sessionDownloadExportScript("export-azure-data.ps1","text/plain"));
document.getElementById('fileInput').addEventListener('change',async function(){
  const files=[...this.files];
  if(!files.length)return;
  const status=document.getElementById('uploadStatus');
  status.style.display='block';
  status.textContent=`Reading ${files.length} file(s)...`;
  let matched=0,skipped=[];
  for(const f of files){
    let text;
    try{text=await f.text();JSON.parse(text)}catch(e){skipped.push(f.name+' (invalid JSON)');continue}
    const inputId=matchFile(f.name, text);
    if(!inputId){skipped.push(f.name);continue}
    const el=document.getElementById(inputId);
    if(el){el.value=text;el.className='ji valid';matched++}
  }
  // expand sections with data
  document.querySelectorAll('.sec-hdr.collapsed').forEach(h=>{
    const body=h.nextElementSibling;
    if(body){const ta=body.querySelectorAll('.ji.valid');if(ta.length)h.click()}
  });
  let msg=matched+' of '+files.length+' files loaded';
  if(skipped.length)msg+=' | Skipped: '+skipped.join(', ');
  status.textContent=msg;
  status.style.color=skipped.length?'var(--accent-orange)':'var(--accent-green)';
  this.value='';
  if(matched>0){_iamData=null;_parseCache={};renderMap(()=>_autoSaveSession(true))}
});
function clearLoadedSession(){
  if(typeof _discardHistoryView==='function')_discardHistoryView();
  if(_designMode||_designBaseline||_designDebounce)exitDesignMode({restore:false,render:false});
  document.querySelectorAll('.ji').forEach(el=>{el.value='';el.className='ji'});
  d3.select('#mapSvg').selectAll('*').remove();
  d3.select('#mapSvg').style('display','none');
  document.getElementById('emptyState').style.display='none';
  document.getElementById('landingDash').style.display='flex';
  document.getElementById('statsBar').style.display='none';
  document.getElementById('legend').style.display='none';
  document.getElementById('bottomToolbar').style.display='none';
  document.getElementById('detailPanel').classList.remove('open');
  _closeAllDashboardsExcept(null);
  document.getElementById('uploadStatus').style.display='none';

  var al=document.getElementById('accountLabel');
  if(al)al.value='';

  if(_multiViewMode){
    _multiViewMode=false;
    _singleCtxBackup=null;
    var mergeBtn=document.getElementById('mergeViewBtn');
    if(mergeBtn)mergeBtn.textContent='Merge View';
  }
  _loadedContexts=[];
  _mergedCtx=null;
  sessionSetData(null);
  _prebuiltCtx=null;
  _parseCache={};
  _iamData=null;
  _iamReviewData=[];
  _inventoryData=[];
  demo=null;

  _complianceDataFP='';
  _complianceCachedFindings=null;
  _budrCachedFindings=null;
  _budrCachedAssessments=null;
  GovernanceClassification.reset();
  _budrFindings=[];
  _budrAssessments=[];
  sessionResetComplianceRows();
  _appRegistry=[];
  _appAutoDiscovered=false;

  _flowAnalysisCache=null;
  if(typeof FlowAnalysisDashboard !== 'undefined') FlowAnalysisDashboard.reset();
  _depGraph=null;
  _diffBaseline=null;
  _diffResults=null;
  _diffFlatRows=null;
  _snapshots=[];
  _iacOutput='';
  _tfIdMap={};
  if(typeof invalidateComplianceCache==='function')invalidateComplianceCache();
  document.getElementById('mergeBanner').style.display='none';
  var mainEl=_getMain();if(mainEl)mainEl.classList.remove('merge-active');
  _renderAccountPanel();
}
document.getElementById('clearBtn').addEventListener('click',clearLoadedSession);
document.getElementById('landingDemo').addEventListener('click',function(){document.getElementById('loadDemo').click()});
document.getElementById('landingImport').addEventListener('click',function(){document.getElementById('uploadBtn').click()});
document.getElementById('landingImportReport').addEventListener('click',function(){document.getElementById('importReportInput').click()});
// Landing card navigation: import data first, then open the feature
var _lcActions={
  'lc-topology':function(){document.getElementById('uploadBtn').click()},
  'lc-compliance':function(){if(sessionCurrentData())openUnifiedDash('compliance');else{document.getElementById('uploadBtn').click()}},
  'lc-flow':function(){if(sessionCurrentData()){document.getElementById('flowAnalysisBtn').click()}else{document.getElementById('uploadBtn').click()}},
  'lc-design':function(){if(sessionCurrentData()&&typeof enterDesignMode==='function')enterDesignMode();else{document.getElementById('uploadBtn').click()}},
  'lc-multisub':function(){document.getElementById('uploadBtn').click()},
  'lc-budr':function(){if(sessionCurrentData())openUnifiedDash('budr');else{document.getElementById('uploadBtn').click()}},
  'lc-reports':function(){if(sessionCurrentData())openUnifiedDash('reports');else{document.getElementById('uploadBtn').click()}},
  'lc-iac':function(){if(sessionCurrentData()&&typeof openIacModal==='function')openIacModal('arm');else{document.getElementById('uploadBtn').click()}},
  'lc-governance':function(){if(sessionCurrentData())openUnifiedDash('classification');else{document.getElementById('uploadBtn').click()}}
};
Object.keys(_lcActions).forEach(function(id){var el=document.getElementById(id);if(el)el.addEventListener('click',_lcActions[id])});
document.getElementById('loadDemo').addEventListener('click',async()=>{
  try{
  // OPTIMIZED: Lazy-load demo module then generate demo data
  await sessionEnsureDemoData();
  if(typeof _discardHistoryView==='function')_discardHistoryView();
  if(typeof demo==='undefined'||!demo)demo=generateDemo();
  // Split demo data into 2 accounts for multi-account view
  // ext() helper: extract arrays from wrapper objects (checks 'value' + named keys)
  const _dext=(obj,...keys)=>{if(!obj)return[];for(const k of ['value',...keys]){if(obj[k])return Array.isArray(obj[k])?obj[k]:[obj[k]]}return Array.isArray(obj)?obj:[]};
  const allVpcs=_dext(demo.vnets,'VirtualNetworks');
  const allSubs=_dext(demo.subnets,'Subnets');
  const allInsts=_dext(demo.vms,'Instances');
  const splitIdx=Math.ceil(allVpcs.length/2);
  const acct1Vpcs=new Set(allVpcs.slice(0,splitIdx).map(v=>v.VpcId));
  const acct2Vpcs=new Set(allVpcs.slice(splitIdx).map(v=>v.VpcId));
  const byVpc=(arr,vpcSet,field)=>arr.filter(r=>vpcSet.has(r[field||'VpcId']));
  const allRts=_dext(demo.udrs,'RouteTables');
  const allSgs=_dext(demo.nsgs,'SecurityGroups');
  const allNacls=_dext(demo.nacls);
  const allIgws=_dext(demo.igws);
  const allNats=_dext(demo.nats,'NatGateways');
  const allAlbs=_dext(demo.albs,'LoadBalancers');
  const allVpces=_dext(demo.pvteps,'VpcEndpoints');
  const allEnis=_dext(demo.nics,'NetworkInterfaces');
  const allVols=_dext(demo.disks,'Volumes');
  const allSnaps=_dext(demo.snaps,'Snapshots');
  const allTgs=_dext(demo.tgs,'TargetGroups');
  const allRds=_dext(demo.sql,'DBInstances');
  const allEcs=_dext(demo.containers,'services');
  const allLambda=_dext(demo.funcapps,'Functions');
  const allEcache=_dext(demo.elasticache,'CacheClusters');
  const allRedshift=_dext(demo.aks,'Clusters');
  // Subnet -> VPC lookup
  const subVpc={};allSubs.forEach(s=>{subVpc[s.SubnetId]=s.VpcId});
  // Instance -> subnet VPC
  const instVpc=(inst)=>{const enis2=(inst.NetworkInterfaces||[]);if(enis2.length)return enis2[0].VpcId||subVpc[enis2[0].SubnetId]||'';return subVpc[inst.SubnetId]||''};
  // ALB -> VPC via AZs
  const albVpc=(alb)=>{const azs=alb.AvailabilityZones||[];if(azs.length&&azs[0].SubnetId)return subVpc[azs[0].SubnetId]||'';return alb.VpcId||''};
  // IGW -> VPC via attachments
  const igwVpc=(igw)=>{const att=igw.Attachments||[];return att.length?att[0].VpcId||'':''};
  // Build split textarea objects
  function buildAcctTextareas(vpcSet){
    const subs=allSubs.filter(s=>vpcSet.has(s.VpcId));
    const subIds=new Set(subs.map(s=>s.SubnetId));
    const insts=allInsts.filter(i=>vpcSet.has(instVpc(i)));
    const instIds=new Set(insts.map(i=>i.InstanceId));
    const vols2=allVols.filter(v=>v.Attachments&&v.Attachments.some(a=>instIds.has(a.InstanceId)));
    const volIds=new Set(vols2.map(v=>v.VolumeId));
    const snaps2=allSnaps.filter(s=>volIds.has(s.VolumeId));
    const ta={};
    ta.in_vnets=JSON.stringify({value:allVpcs.filter(v=>vpcSet.has(v.id||v.VpcId))});
    ta.in_subnets=JSON.stringify({value:subs});
    ta.in_udrs=JSON.stringify({value:byVpc(allRts,vpcSet)});
    ta.in_nsgs=JSON.stringify({value:byVpc(allSgs,vpcSet)});
    ta.in_nats=JSON.stringify({value:byVpc(allNats,vpcSet)});
    ta.in_vms=JSON.stringify({value:insts});
    ta.in_albs=JSON.stringify({value:allAlbs.filter(a=>vpcSet.has(albVpc(a)))});
    ta.in_pvteps=JSON.stringify({value:byVpc(allVpces,vpcSet)});
    ta.in_nics=JSON.stringify({value:allEnis.filter(e=>vpcSet.has(e.VpcId||e.id))});
    ta.in_disks=JSON.stringify({value:vols2});
    ta.in_snaps=JSON.stringify({value:snaps2});
    ta.in_tgs=JSON.stringify({value:allTgs.filter(t=>subIds.has(t.TargetGroupArn?.split('/')[1])||true)});
    ta.in_sql=JSON.stringify({value:allRds.filter(r=>{const sg=r.DBSubnetGroup;return sg&&sg.Subnets&&sg.Subnets.some(s=>subIds.has(s.SubnetIdentifier))})});
    ta.in_containers=JSON.stringify({value:allEcs.filter(s=>{const nc=s.networkConfiguration;if(!nc)return false;return nc.subnets&&nc.subnets.some(sid=>subIds.has(sid))})});
    ta.in_funcapps=JSON.stringify({value:allLambda.filter(f=>f.VpcConfig&&vpcSet.has(f.VpcConfig.VpcId))});
    ta.in_elasticache=JSON.stringify({value:allEcache.filter(e=>e.CacheSubnetGroupName?true:false)});
    ta.in_aks=JSON.stringify({value:allRedshift.filter(r=>r.ClusterSubnetGroupName?true:false)});
    // Shared non-VNet data: give to both subscriptions
    if(demo.storage)ta.in_storage=JSON.stringify(demo.storage);
    if(demo.dnsz)ta.in_dnsz=JSON.stringify(demo.dnsz);
    if(demo.r53records)ta.in_r53records=JSON.stringify(demo.r53records);
    if(demo.waf)ta.in_waf=JSON.stringify(demo.waf);
    if(demo.cf)ta.in_cf=JSON.stringify(demo.cf);
    if(demo.rbac)ta.in_rbac=JSON.stringify(demo.rbac);
    if(demo.peer)ta.in_peer=JSON.stringify(demo.peer);
    if(demo.vpn)ta.in_vpn=JSON.stringify(demo.vpn);
    if(demo.tgwatt)ta.in_tgwatt=JSON.stringify(demo.tgwatt);
    return ta;
  }
  // Reset any existing multi-account state
  if(_multiViewMode)exitMultiView();
  _loadedContexts=[];
  // Add two account contexts
  addAccountContext({textareas:buildAcctTextareas(acct1Vpcs),accountLabel:'Production (a1b2c3d4)'},'Production (a1b2c3d4)');
  addAccountContext({textareas:buildAcctTextareas(acct2Vpcs),accountLabel:'Security-Ops (c9d8e7f6)'},'Security-Ops (c9d8e7f6)');
  // Fill textareas with full demo for single-view fallback
  const m={in_vnets:'vnets',in_subnets:'subnets',in_udrs:'udrs',in_nsgs:'nsgs',in_nats:'nats',in_azfws:'azfws',in_bastions:'bastions',in_vms:'vms',in_albs:'albs',in_peer:'peer',in_vpn:'vpn',in_pvteps:'pvteps',in_disks:'disks',in_storage:'storage',in_dnsz:'dnsz',in_r53records:'r53records',in_tgs:'tgs',in_snaps:'snaps',in_nics:'nics',in_waf:'waf',in_sql:'sql',in_containers:'containers',in_funcapps:'funcapps',in_elasticache:'elasticache',in_aks:'aks',in_tgwatt:'tgwatt',in_cf:'cf',in_rbac:'rbac'};
  Object.entries(m).forEach(([id,k])=>{if(demo[k])document.getElementById(id).value=JSON.stringify(demo[k],null,2)});
  document.querySelectorAll('.ji').forEach(el=>{if(el.value.trim())el.className='ji valid'});
  document.querySelectorAll('.sec-hdr.collapsed').forEach(h=>{h.click()});
  // Load demo annotations
  _annotations={};
  const dVpcs=allVpcs; const dInsts=allInsts; const dSubs=allSubs;
  if(dVpcs[0])addAnnotation(dVpcs[0].VpcId,'Primary production environment - all changes require CAB approval','warning',true);
  if(dVpcs[1])addAnnotation(dVpcs[1].VpcId,'Staging environment - auto-deploy from main branch','status',false);
  if(dVpcs.length>6)addAnnotation(dVpcs[6].VpcId,'Legacy DR environment - migrating to new region Q3 2026','status',false);
  if(dSubs[0])addAnnotation(dSubs[0].SubnetId,'Owner: Platform Team (platform@company.com)','owner',false);
  if(dInsts[0])addAnnotation(dInsts[0].InstanceId,'CRITICAL: Unpatched since January - CVE-2026-1234','incident',true);
  if(dInsts[0])addAnnotation(dInsts[0].InstanceId,'Scheduled for replacement in Sprint 47','todo',false);
  if(dInsts.length>5)addAnnotation(dInsts[5].InstanceId,'This instance handles payment processing - PCI scope','warning',true);
  // Enter multi-account view
  enterMultiView();
  // MEMORY: Release demo data: now stored in _loadedContexts textareas
  demo=null;
  }catch(e){console.error('Demo load error:',e)}
});

// store layout data globally for export
let exportData={vL:[],gwP:new Map(),allS:[],tG:{},peerings:[],shGws:[]};

// #endregion SESSION & EVENT WIRING

