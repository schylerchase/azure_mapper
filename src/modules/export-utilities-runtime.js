// #region EXPORT ADAPTERS AND TOOLBAR
function exportUtilitiesNotify(message,type){
  AppNotifications.show(message,type);
}
function exportUtilitiesDownload(blob,name){
  AppDownloads.saveBlob(blob,name);
}
// helper: resolve CSS vars to hex for SVG serialization (cached)
const _resolveColorCache=new Map();
function resolveColor(cssVar){
  if(_resolveColorCache.has(cssVar))return _resolveColorCache.get(cssVar);
  const el=document.createElement('div');el.style.color=cssVar;document.body.appendChild(el);
  const c=getComputedStyle(el).color;document.body.removeChild(el);
  const m=c.match(/(\d+)/g);if(!m)return'#888';
  const hex='#'+m.slice(0,3).map(x=>(+x).toString(16).padStart(2,'0')).join('');
  _resolveColorCache.set(cssVar,hex);
  return hex;
}

// Layout mode selector
if(_prefs.layoutMode){document.getElementById('layoutMode').value=_prefs.layoutMode;const hi=document.getElementById('hubVpcName');if(hi)hi.style.display=_prefs.layoutMode==='landingzone'?'block':'none';document.getElementById('detailBtns').style.display=_prefs.layoutMode==='executive'?'none':'flex';document.getElementById('flowBtn').style.display=_prefs.layoutMode==='executive'?'none':''}
document.getElementById('layoutMode').addEventListener('change',function(){
  const hubInput=document.getElementById('hubVpcName');
  hubInput.style.display=this.value==='landingzone'?'block':'none';
  document.getElementById('detailBtns').style.display=this.value==='executive'?'none':'flex';
  document.getElementById('flowBtn').style.display=this.value==='executive'?'none':'';
  savePrefs({layoutMode:this.value});
  const svg=d3.select('#mapSvg');
  if(svg.node()&&svg.style('display')!=='none'){
    renderMap();
  }
});
document.getElementById('hubVpcName').addEventListener('change',function(){
  const svg=d3.select('#mapSvg');
  if(svg.node()&&svg.style('display')!=='none'){
    renderMap();
  }
});

// Map detail level toggle
function updateDetailBtns(){
  document.getElementById('btnExpand').classList.toggle('active',_detailLevel>=1);
  document.getElementById('btnCollapse').classList.toggle('active',_detailLevel===0);
}
document.getElementById('btnExpand').addEventListener('click',function(){
  if(_detailLevel===0){_detailLevel=1;_showNested=false}
  else if(_detailLevel===1){_detailLevel=2;_showNested=true}
  updateDetailBtns();savePrefs({detailLevel:_detailLevel});
  const svg=d3.select('#mapSvg');
  if(svg.node()&&svg.style('display')!=='none') renderMap();
});
document.getElementById('btnCollapse').addEventListener('click',function(){
  if(_detailLevel===2){_detailLevel=1;_showNested=false}
  else{_detailLevel=0;_showNested=false}
  updateDetailBtns();savePrefs({detailLevel:_detailLevel});
  const svg=d3.select('#mapSvg');
  if(svg.node()&&svg.style('display')!=='none') renderMap();
});

// Initialize button state on load
updateDetailBtns();

// #endregion EXPORT ADAPTERS AND TOOLBAR

