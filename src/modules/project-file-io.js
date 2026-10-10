// #region PROJECT FILE IO
// === SAVE / LOAD PROJECT ===
function _projectFilePlainValue(value, seen){
  if(typeof value==='string'){
    const text=value.trim();
    if(!text)return '';
    try{return JSON.parse(text)}catch(e){return value}
  }
  if(!value||typeof value!=='object')return value;
  if(!seen)seen=new WeakSet();
  if(seen.has(value))return undefined;
  seen.add(value);
  if(Array.isArray(value)){
    const arr=value.map(v=>_projectFilePlainValue(v,seen)).filter(v=>v!==undefined);
    seen.delete(value);
    return arr;
  }
  const out={};
  Object.entries(value).forEach(([k,v])=>{
    const plain=_projectFilePlainValue(v,seen);
    if(plain!==undefined)out[k]=plain;
  });
  seen.delete(value);
  return out;
}

function _projectFileTextareaMap(textareas){
  const out={};
  Object.entries(textareas||{}).forEach(([id,value])=>{
    if(value===undefined||value===null||value==='')return;
    out[id]=_projectFilePlainValue(value);
  });
  return out;
}

function projectFileRenderState(){
  return AppRenderContext.createRenderContext();
}

function projectFileDesignLocation(){
  return typeof _designRegion!=='undefined'?_designRegion:'eastus';
}

function saveProject(filePath){
  const project={_format:'azuremap',_version:_loadedContexts.length>1?'2.0':'1.0',created:new Date().toISOString(),
    accountLabel:(document.getElementById('accountLabel')||{}).value||'',
    layout:(document.getElementById('layoutMode')||{}).value||'grid',
    hubVpcName:(document.getElementById('hubVpcName')||{}).value||'',
    textareas:{},preferences:loadPrefs(),
    designChanges:_designMode?_designChanges.filter(c=>!c._invalid).map(c=>({id:c.id,action:c.action,target:c.target,params:c.params,timestamp:c.timestamp})):[],
    designMode:_designMode,designLocation:projectFileDesignLocation(),
    annotations:_annotations,
    budrOverrides:Object.keys(_budrOverrides).length?_budrOverrides:undefined};
  const inputs=_designMode&&_designBaseline?_designBaseline:_snapshotTextareas();
  project.textareas=_projectFileTextareaMap(inputs);
  // v2.0: include loaded account contexts
  if(_loadedContexts.length>1){
    project.accounts=_loadedContexts.map(c=>({id:c.accountId,label:c.accountLabel,region:c.region,textareas:_projectFileTextareaMap(c.textareas)}));
    project.multiViewMode=_multiViewMode;
  }
  const name=(project.accountLabel||'azure-project').replace(/[^a-zA-Z0-9_-]/g,'_');
  const json=JSON.stringify(project,null,2);
  const fileName=name+'.azuremap';
  const nativeFileAccess=AppProjectFiles.hasNativeFileAccess();
  return AppProjectFiles.saveText(json,fileName,'application/json',typeof filePath==='string'?filePath:undefined)
    .then(p=>{if(p)AppNotifications.show(nativeFileAccess?'Saved: '+p.split(/[\\/]/).pop():'Project saved: '+fileName)})
    .catch(e=>{console.error('Save failed:',e);AppNotifications.show('Save failed: '+e.message,'error')});
}
function _loadProjectData(project){
  if(!project.textareas&&!project._format){AppNotifications.show('Invalid project file');return false}
  if(typeof _discardHistoryView==='function')_discardHistoryView();
  // End the previous sessions before writing the incoming project's inputs.
  if(_designMode||_designBaseline||_designDebounce)exitDesignMode({restore:false,render:false});
  if(_multiViewMode)exitMultiView({render:false});
  _loadedContexts=[];_mergedCtx=null;_singleCtxBackup=null;_prebuiltCtx=null;
  _renderAccountPanel();
  AppProjectFiles.setNativePath(null);
  // MEMORY: Reset state from previous load
  _importedReportData=null;
  _iamData=null;_iamReviewData=[];_appRegistry=[];_parseCache={};
  projectFileRenderState().rlCtx=null;
  _complianceDataFP='';_complianceCachedFindings=null;
  _budrFindings=[];_budrAssessments=[];
  _budrCachedFindings=null;_budrCachedAssessments=null;
  if(typeof _closeAllDashboardsExcept==='function')_closeAllDashboardsExcept(null);
  _snapshots=[];_saveSnapshots();
  document.querySelectorAll('.ji').forEach(el=>{el.value='';el.className='ji'});
  const ta=project.textareas||project.json_data||{};
  Object.entries(ta).forEach(([id,val])=>{const el=document.getElementById(id);if(el){el.value=typeof val==='string'?val:JSON.stringify(val,null,2);try{JSON.parse(el.value);el.className='ji valid'}catch(ex){el.className='ji invalid'}}});
  const al=document.getElementById('accountLabel');if(al)al.value=project.accountLabel||'';
  if(project.layout){const lm=document.getElementById('layoutMode');if(lm){lm.value=project.layout;lm.dispatchEvent(new Event('change'))}}
  const hv=document.getElementById('hubVpcName');if(hv)hv.value=project.hubVpcName||'';
  if(project.preferences){Object.entries(project.preferences).forEach(([k,v])=>savePrefs({[k]:v}))}
  if(project.annotations){_annotations=project.annotations;_saveAnnotations()}
  _budrOverrides=project.budrOverrides||{};
  if(project._version==='2.0'&&project.accounts&&project.accounts.length){
    project.accounts.forEach(acct=>{
      addAccountContext({textareas:acct.textareas,accountLabel:acct.label||acct.id},acct.label||acct.id);
    });
    if(project.multiViewMode&&_loadedContexts.length>1){
      enterMultiView();
      AppNotifications.show('Loaded '+_loadedContexts.length+' accounts in merge view');
      return;
    }
  }
  renderMap(()=>{_autoSaveSession(true);_renderNoteBadges();_renderComplianceBadges();
    if(project.designMode!==false&&(project.designMode||project.designChanges?.length)){enterDesignMode();if(project.designLocation||project.designRegion)_designRegion=project.designLocation||project.designRegion;(project.designChanges||[]).forEach(ch=>addDesignChange(ch));AppNotifications.show(project.designChanges?.length?'Loaded with '+project.designChanges.length+' design changes':'Project loaded in Design Mode')}
    else{AppNotifications.show('Project loaded')}
  });
}
function loadProject(file){
  const reader=new FileReader();
  reader.onload=function(e){
    try{_loadProjectData(JSON.parse(e.target.result))}catch(ex){AppNotifications.show('Failed to load: '+ex.message)}
  };reader.readAsText(file);
}
document.getElementById('saveProjectBtn').addEventListener('click',saveProject);
document.getElementById('loadProjectBtn').addEventListener('click',()=>{
  if(AppProjectFiles.hasNativeFileAccess()){
    AppProjectFiles.openText().then(c=>{if(c){try{_loadProjectData(JSON.parse(c))}catch(ex){AppNotifications.show('Failed to load: '+ex.message)}}}).catch(e=>console.error('Open failed:',e));
  } else {AppProjectFiles.chooseBrowserFile('loadProjectInput')}
});
document.getElementById('loadProjectInput').addEventListener('change',function(){if(this.files[0])loadProject(this.files[0]);this.value=''});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='s'){e.preventDefault();saveProject()}
  if(_isElectron&&(e.ctrlKey||e.metaKey)&&e.key==='o'){e.preventDefault();document.getElementById('loadProjectBtn').click()}
});

// #endregion PROJECT FILE IO
