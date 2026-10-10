// #region ELECTRON AZURE ACTIONS
// === ELECTRON: Scan Azure + Menu Listeners ===
if(_isElectron){
  // Show scan button
  document.getElementById('scanAzureBtn').style.display='flex';

  // Scan Azure modal
  document.getElementById('scanAzureBtn').addEventListener('click',()=>{
    document.getElementById('scanModal').style.display='flex';
    document.getElementById('scanForm').style.display='block';
    document.getElementById('scanProgress').style.display='none';
    document.getElementById('scanLog').textContent='';
  });
  function _openScanModal(){document.getElementById('scanAzureBtn').click()}
  document.getElementById('scanCancel').addEventListener('click',()=>{document.getElementById('scanModal').style.display='none'});
  document.getElementById('scanStart').addEventListener('click',()=>{
    const subscription=document.getElementById('scanProfile').value.trim();
    const resourceGroup=document.getElementById('scanRegion').value.trim()||undefined;
    if(!subscription){
      AppNotifications.show('Subscription is required','error');
      return;
    }
    document.getElementById('scanForm').style.display='none';
    document.getElementById('scanProgress').style.display='block';
    const log=document.getElementById('scanLog');
    log.textContent='Starting scan...\n';
    DesktopAzureAdapter.scanAzure({subscription,resourceGroup}).then(result=>{
      if(result&&!result.success&&result.error){
        const log=document.getElementById('scanLog');
        log.textContent+='\\nERROR: '+result.error+'\\n';
        log.style.color='#ef4444';
      }
    }).catch(e=>{
      const log=document.getElementById('scanLog');
      log.textContent+='\\nERROR: '+e.message+'\\n';
      log.style.color='#ef4444';
    });
  });
  document.getElementById('scanAbort').addEventListener('click',()=>{
    DesktopAzureAdapter.abortScan();
    document.getElementById('scanLog').textContent+='\\n--- Scan aborted ---\\n';
    setTimeout(()=>{document.getElementById('scanModal').style.display='none'},1000);
  });

  // Scan event listeners (guarded: methods may be missing in web/older preload)
  const _unsubs=[];
  const _safeOn=(name,cb)=>{const u=DesktopAzureAdapter.subscribe(name,cb);if(u)_unsubs.push(u)};
  _safeOn('onScanProgress',(text)=>{
    const log=document.getElementById('scanLog');
    log.textContent+=text;log.scrollTop=log.scrollHeight;
  });
  _safeOn('onScanComplete',({code,outDir,files})=>{
    const log=document.getElementById('scanLog');
    log.textContent+='\\n--- Scan complete ---\\n';
    if(files){
      let matched=0;
      const textareas={};
      Object.entries(files).forEach(([fname,content])=>{
        const inputId=matchFile(fname,content);
        if(inputId&&document.getElementById(inputId)){textareas[inputId]=content;matched++}
      });
      log.textContent+=matched+' files loaded into map.\\n';
      setTimeout(()=>{
        document.getElementById('scanModal').style.display='none';
        _loadProjectData({_format:'azuremap',_version:'1.0',textareas,
          accountLabel:document.getElementById('scanProfile').value.trim(),
          layout:document.getElementById('layoutMode').value,annotations:{},designMode:false});
        AppNotifications.show('Azure scan complete: '+matched+' datasets loaded');
      },1500);
    } else {
      log.textContent+='No output files found. Check export-azure-data.sh output.\\n';
    }
  });
  _safeOn('onScanError',(msg)=>{
    const log=document.getElementById('scanLog');
    log.textContent+='\\nERROR: '+msg+'\\n';
    log.style.color='#ef4444';
  });

  // Menu event listeners
  _safeOn('onMenuSave',()=>saveProject());
  _safeOn('onMenuSaveAs',(filePath)=>saveProject(filePath));
  _safeOn('onMenuScanAzure',()=>_openScanModal());
  _safeOn('onProjectLoad',(payload)=>{
    try{if(_loadProjectData(JSON.parse(payload.data))!==false)AppProjectFiles.setNativePath(payload.filePath)}catch(ex){AppNotifications.show('Failed to load file: '+ex.message)}
  });
  _safeOn('onImportFolder',(files)=>importFolder(files));

  // Update available: show persistent banner with download/install controls
  _safeOn('onUpdateAvailable',({version,currentVersion})=>{
    var banner=document.getElementById('updateBanner');
    if(!banner){
      banner=document.createElement('div');banner.id='updateBanner';
      banner.style.cssText='position:fixed;top:0;left:0;right:0;z-index:99999;background:#1e40af;color:#fff;padding:8px 16px;display:flex;align-items:center;justify-content:center;gap:12px;font-size:13px;font-family:inherit';
      document.body.appendChild(banner);
    }
    banner.textContent='';
    var txt=document.createElement('span');
    txt.textContent='Update available: v'+version+' (current: v'+(currentVersion||'?')+')';
    var btn=document.createElement('button');
    btn.textContent='Download';
    btn.style.cssText='background:#fff;color:#1e40af;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-weight:600;font-size:12px';
    btn.onclick=function(){
      btn.disabled=true;btn.textContent='Downloading...';
      DesktopAzureAdapter.downloadUpdate();
    };
    var dismiss=document.createElement('button');
    dismiss.textContent='\u2715';
    dismiss.style.cssText='background:none;border:none;color:#fff;cursor:pointer;font-size:16px;padding:0 4px;opacity:.7';
    dismiss.onclick=function(){banner.remove()};
    banner.appendChild(txt);banner.appendChild(btn);banner.appendChild(dismiss);
  });
  _safeOn('onUpdateDownloadProgress',({percent})=>{
    var banner=document.getElementById('updateBanner');
    if(!banner) return;
    var btn=banner.querySelector('button');
    if(btn) btn.textContent='Downloading... '+percent+'%';
  });
  _safeOn('onUpdateDownloaded',()=>{
    var banner=document.getElementById('updateBanner');
    if(!banner) return;
    banner.textContent='';
    var txt=document.createElement('span');txt.textContent='Update downloaded and ready to install.';
    var btn=document.createElement('button');
    btn.textContent='Restart & Install';
    btn.style.cssText='background:#fff;color:#1e40af;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-weight:600;font-size:12px';
    btn.onclick=function(){DesktopAzureAdapter.installUpdate()};
    var later=document.createElement('button');
    later.textContent='Later';
    later.style.cssText='background:none;border:1px solid rgba(255,255,255,.4);color:#fff;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px';
    later.onclick=function(){banner.remove()};
    banner.appendChild(txt);banner.appendChild(btn);banner.appendChild(later);
  });
  _safeOn('onUpdateError',(msg)=>{
    var banner=document.getElementById('updateBanner');
    if(banner) banner.remove();
    AppNotifications.show('Update error: '+msg);
  });

  // Import Folder button (native folder picker)
  document.getElementById('importFolderBtn').style.display='inline-block';
  document.getElementById('importFolderBtn').addEventListener('click',async()=>{
    const result=await DesktopAzureAdapter.openFolder();
    importFolder(result);
  });
}

// #endregion ELECTRON AZURE ACTIONS
