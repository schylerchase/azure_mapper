// #region FOLDER IMPORT
// === Folder Import (shared by Electron + browser) ===
function _folderImportNotify(message,type){
  AppNotifications.show(message,type);
}
function _isValidData(content){
  var obj=null;
  if(typeof content==='object'&&content!==null)obj=content;
  else if(typeof content==='string'){try{obj=JSON.parse(content)}catch(e){return false}}
  if(!obj)return false;
  // Reject scan metadata/progress objects (numeric keys with label/status/bytes)
  var keys=Object.keys(obj);
  if(keys.length>2&&keys.every(function(k){return/^\d+$/.test(k)})){
    var vals=Object.values(obj);
    if(vals[0]&&typeof vals[0]==='object'&&'label' in vals[0]&&'status' in vals[0])return false;
  }
  return true;
}
// _friendlyFolderLabel — extracted to src/modules/normalization.js
function importFolder(result){
  if(!result)return;
  // Extract folder name before restructuring
  var _folderLabel=_friendlyFolderLabel(result._folderName||'');
  // Legacy format: plain object without _structure (old Electron handler)
  if(!result._structure){
    result={_structure:'flat',files:result};
  }
  if(result._structure==='multi-region'&&result.regions){
    const regionNames=Object.keys(result.regions).sort();
    let loaded=0;
    regionNames.forEach(regionName=>{
      const regionFiles=result.regions[regionName];
      const textareas={};
      Object.entries(regionFiles).forEach(([fname,content])=>{
        if(!_isValidData(content))return
        const inputId=matchFile(fname,content);
        if(inputId)textareas[inputId]=content;
      });
      if(Object.keys(textareas).length){
        addAccountContext({textareas,accountLabel:regionName,_isRegion:true},regionName);
        loaded++;
      }
    });
    // Also load any flat (global) files alongside regions
    const globalFiles=result.files||{};
    Object.entries(globalFiles).forEach(([fname,content])=>{
      if(!_isValidData(content))return
      const inputId=matchFile(fname,typeof content==='object'?JSON.stringify(content):content);
      if(inputId){const el=document.getElementById(inputId);if(el){el.value=typeof content==='string'?content:JSON.stringify(content,null,2);el.className='ji valid'}}
    });
    if(loaded>0){
      if(!_multiViewMode)enterMultiView();
      else _remergeAndRender();
      _folderImportNotify(loaded+' region'+(loaded>1?'s':'')+' imported'+(Object.keys(globalFiles).length?' + global files':''));
    }else{
      _folderImportNotify('No valid data found in region folders');
    }
  }else if(result._structure==='multi-profile'&&result.profiles){
    const profileNames=Object.keys(result.profiles).sort();
    let totalLoaded=0;
    profileNames.forEach(profileName=>{
      const prof=result.profiles[profileName];
      const profRegions=prof.regions||{};
      const profFlat=prof.files||{};
      const regionNames=Object.keys(profRegions).sort();
      if(regionNames.length){
        regionNames.forEach(regionName=>{
          const regionFiles=profRegions[regionName];
          const textareas={};
          Object.entries(regionFiles).forEach(([fname,content])=>{
            if(!_isValidData(content))return
            const inputId=matchFile(fname,content);
            if(inputId)textareas[inputId]=content;
          });
          if(Object.keys(textareas).length){
            addAccountContext({textareas,accountLabel:profileName+' / '+regionName,_isRegion:true},profileName+' / '+regionName);
            totalLoaded++;
          }
        });
      }else if(Object.keys(profFlat).length){
        const textareas={};
        Object.entries(profFlat).forEach(([fname,content])=>{
          if(!_isValidData(content))return
          const inputId=matchFile(fname,content);
          if(inputId)textareas[inputId]=content;
        });
        if(Object.keys(textareas).length){
          addAccountContext({textareas,accountLabel:profileName},profileName);
          totalLoaded++;
        }
      }
    });
    const globalFiles=result.files||{};
    Object.entries(globalFiles).forEach(([fname,content])=>{
      if(!_isValidData(content))return
      const inputId=matchFile(fname,typeof content==='object'?JSON.stringify(content):content);
      if(inputId){const el=document.getElementById(inputId);if(el){el.value=typeof content==='string'?content:JSON.stringify(content,null,2);el.className='ji valid'}}
    });
    if(totalLoaded>0){
      if(!_multiViewMode)enterMultiView();
      else _remergeAndRender();
      _folderImportNotify(totalLoaded+' context'+(totalLoaded>1?'s':'')+' imported from '+profileNames.length+' profile'+(profileNames.length>1?'s':''));
    }else{
      _folderImportNotify('No valid data found in profile folders');
    }
  }else{
    // Flat structure: load into textareas + optional multi-view context
    const files=result.files||result;
    const entries=Object.entries(files).filter(([k])=>!k.startsWith('_'));
    let matched=0,skipped=[];
    const textareas={};
    for(const [fname,content] of entries){
      if(!_isValidData(content)){skipped.push(fname+' (invalid JSON)');continue}
      const contentStr=typeof content==='string'?content:JSON.stringify(content,null,2);
      const inputId=matchFile(fname,contentStr);
      if(!inputId){skipped.push(fname);continue}
      const el=document.getElementById(inputId);
      if(el){el.value=contentStr;el.className='ji valid';matched++}
      textareas[inputId]=contentStr;
    }
    document.querySelectorAll('.sec-hdr.collapsed').forEach(h=>{
      const body=h.nextElementSibling;
      if(body&&body.querySelectorAll('.ji.valid').length)h.click();
    });
    const status=document.getElementById('uploadStatus');
    status.style.display='block';
    let msg=matched+' of '+entries.length+' files loaded';
    if(skipped.length)msg+=' | Skipped: '+skipped.join(', ');
    status.textContent=msg;
    status.style.color=skipped.length?'var(--accent-orange)':'var(--accent-green)';
    // Register as account context for multi-view (enables multi-folder import)
    // Derive label from folder name or subscription ID in the data
    if(matched>0){
      var autoLabel=_folderLabel||'';
      if(!autoLabel){
        // Try to extract subscription ID from VNet data
        var vnetVal=textareas['in_vnets']||'';
        var subMatch=vnetVal.match(/\/subscriptions\/([0-9a-f-]{36})/);
        if(subMatch)autoLabel=subMatch[1].substring(0,13)+'...';
      }
      if(autoLabel){
        addAccountContext({textareas,accountLabel:autoLabel},autoLabel);
      }else{
        renderMap();
      }
    }
  }
  _autoSaveSession(true);
}


// Browser folder import (File System Access API: Chrome/Edge, webkitdirectory fallback)
{
  const bfBtn=document.getElementById('importFolderBrowser');
  if(_isElectron)bfBtn.style.display='none';
  // Fallback: webkitdirectory input for when showDirectoryPicker is unavailable
  function _folderFallback(){
    const inp=document.createElement('input');inp.type='file';
    inp.setAttribute('webkitdirectory','');inp.setAttribute('directory','');inp.multiple=true;
    inp.addEventListener('change',()=>{
      if(!inp.files||!inp.files.length){inp.remove();return}
      const regionRe=/^[a-z]{2}-(north|south|east|west|central|northeast|southeast|northwest|southwest)-\d+$/;
      const regions={},flatFiles={},profiles={};
      const pending=[];
      for(const file of inp.files){
        if(!file.name.endsWith('.json'))continue;
        const parts=(file.webkitRelativePath||file.name).split('/');
        pending.push(file.text().then(txt=>{
          if(parts.length===2){
            // root/file.json: flat
            flatFiles[parts[1]]=txt;
          }else if(parts.length===3){
            // root/region/file.json or root/profile/file.json
            const dir=parts[1];
            if(regionRe.test(dir)){
              if(!regions[dir])regions[dir]={};
              regions[dir][parts[2]]=txt;
            }else{
              if(!profiles[dir])profiles[dir]={regions:{},files:{}};
              profiles[dir].files[parts[2]]=txt;
            }
          }else if(parts.length===4){
            // root/profile/region/file.json
            const prof=parts[1],reg=parts[2];
            if(!profiles[prof])profiles[prof]={regions:{},files:{}};
            // The collector's profile/location layout is structural; Azure
            // location names do not use the legacy AWS region syntax.
            if(!profiles[prof].regions[reg])profiles[prof].regions[reg]={};
            profiles[prof].regions[reg][parts[3]]=txt;
          }
        }));
      }
      Promise.all(pending).then(()=>{
        // Extract folder name from first file's webkitRelativePath
        var folderName=(inp.files[0]&&inp.files[0].webkitRelativePath||'').split('/')[0]||'';
        if(Object.keys(profiles).length){
          importFolder({_structure:'multi-profile',profiles,files:flatFiles,_folderName:folderName});
        }else if(Object.keys(regions).length){
          importFolder({_structure:'multi-region',regions,files:flatFiles,_folderName:folderName});
        }else{
          importFolder({_structure:'flat',files:flatFiles,_folderName:folderName});
        }
        inp.remove();
      });
    });
    inp.addEventListener('cancel',()=>inp.remove());
    inp.click();
  }
  bfBtn.addEventListener('click',async()=>{
    if(!AppProjectFiles.hasDirectoryPicker()){_folderFallback();return}
    try{
      const dirHandle=await AppProjectFiles.chooseDirectory({mode:'read'});
      if(!dirHandle){_folderFallback();return}
      const regionRe=/^[a-z]{2}-(north|south|east|west|central|northeast|southeast|northwest|southwest)-\d+$/;
      const regions={},flatFiles={},profiles={};
      for await(const [name,handle] of dirHandle.entries()){
        if(handle.kind==='directory'){
          if(regionRe.test(name)){
            const regionFiles={};
            for await(const [fname,fhandle] of handle.entries()){
              if(fhandle.kind==='file'&&fname.endsWith('.json')){
                const file=await fhandle.getFile();
                regionFiles[fname]=await file.text();
              }
            }
            if(Object.keys(regionFiles).length)regions[name]=regionFiles;
          }else{
            // Potential profile folder
            const profRegions={},profFlat={};
            for await(const [subName,subHandle] of handle.entries()){
              if(subHandle.kind==='directory'){
                const regFiles={};
                for await(const [fname,fhandle] of subHandle.entries()){
                  if(fhandle.kind==='file'&&fname.endsWith('.json')){
                    const file=await fhandle.getFile();
                    regFiles[fname]=await file.text();
                  }
                }
                if(Object.keys(regFiles).length)profRegions[subName]=regFiles;
              }else if(subHandle.kind==='file'&&subName.endsWith('.json')){
                const file=await subHandle.getFile();
                profFlat[subName]=await file.text();
              }
            }
            if(Object.keys(profRegions).length||Object.keys(profFlat).length){
              profiles[name]={regions:profRegions,files:profFlat};
            }
          }
        }else if(handle.kind==='file'&&name.endsWith('.json')){
          const file=await handle.getFile();
          flatFiles[name]=await file.text();
        }
      }
      var dirName=dirHandle.name||'';
      if(Object.keys(profiles).length){
        importFolder({_structure:'multi-profile',profiles,files:flatFiles,_folderName:dirName});
      }else if(Object.keys(regions).length){
        importFolder({_structure:'multi-region',regions,files:flatFiles,_folderName:dirName});
      }else{
        importFolder({_structure:'flat',files:flatFiles,_folderName:dirName});
      }
    }catch(e){
      if(e.name==='AbortError')return;// user cancelled
      console.warn('showDirectoryPicker failed, using file input fallback:',e.message);
      _folderFallback();
    }
  });
}

// #endregion FOLDER IMPORT
