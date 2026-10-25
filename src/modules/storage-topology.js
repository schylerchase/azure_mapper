// Azure storage topology owns storage-account network links, access posture, and map card rendering.
function _storageEsc(value){
  if(typeof esc==='function')return esc(value);
  return String(value??'').replace(/[&<>"']/g,function(ch){
    return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[ch];
  });
}
function _storageShortId(id){
  if(typeof sid==='function')return sid(id);
  return String(id||'').split('/').filter(Boolean).pop()||'';
}
function _saAzure(sa){return(sa&&sa._azure)||sa||{}}
function _saProps(sa){
  const a=_saAzure(sa);
  const own=sa&&sa.properties;
  if(own&&own!==sa)return own;
  if(a&&a.properties&&a.properties!==a)return a.properties;
  return a||{};
}
function _saId(sa){const a=_saAzure(sa);return(sa&&sa.id)||a.id||sa?.ResourceId||sa?.Arn||''}
function _saName(sa){const a=_saAzure(sa);return(sa&&sa.Name)||sa?.name||a.name||_storageShortId(_saId(sa))||'storage'}
function _saSku(sa){const a=_saAzure(sa);return(sa&&sa.sku&&sa.sku.name)||a.sku?.name||sa?.accountType||_saProps(sa).accountType||''}
function _saKind(sa){const a=_saAzure(sa);return(sa&&sa.kind)||a.kind||'StorageV2'}
function _saEndpointKeys(sa){
  const eps=_saProps(sa).primaryEndpoints||_saAzure(sa).primaryEndpoints||{};
  const keys=Object.keys(eps).filter(k=>eps[k]);
  return keys.length?keys:['blob'];
}
function _saAcls(sa){return _saProps(sa).networkAcls||_saAzure(sa).networkAcls||{}}
function _saDefaultAction(sa){return(_saAcls(sa).defaultAction||'Allow')}
function _saHttpsOnly(sa){const p=_saProps(sa);return p.supportsHttpsTrafficOnly!==false&&p.enableHttpsTrafficOnly!==false}
function _saTls(sa){return _saProps(sa).minimumTlsVersion||_saAzure(sa).minimumTlsVersion||''}
function _saPublicBlob(sa){const p=_saProps(sa);return p.allowBlobPublicAccess===true||p.allowBlobPublicAccess==='true'}
function _saPrivateLinkTarget(pe){
  const list=pe?.privateLinkServiceConnections||pe?.properties?.privateLinkServiceConnections||[];
  const conn=list[0]||{};
  const cp=conn.properties||conn;
  return cp.privateLinkServiceId||conn.privateLinkServiceId||'';
}
function _saPrivateLinkGroup(pe){
  const list=pe?.privateLinkServiceConnections||pe?.properties?.privateLinkServiceConnections||[];
  const conn=list[0]||{};
  const cp=conn.properties||conn;
  const groups=cp.groupIds||conn.groupIds||[];
  return groups[0]||'privateEndpoint';
}
function _buildStorageTopology(storageAccounts,privateEndpoints){
  const bySub={},linksByStorageId={};
  const addLink=function(sa,subnetId,via,detail,pe){
    if(!sa||!subnetId)return;
    const id=_saId(sa).toLowerCase()||_saName(sa).toLowerCase();
    if(!id)return;
    const link={account:sa,subnetId,via,detail:detail||'',pe};
    linksByStorageId[id]=linksByStorageId[id]||[];
    if(!linksByStorageId[id].some(l=>l.subnetId===subnetId&&l.via===via))linksByStorageId[id].push(link);
    bySub[subnetId]=bySub[subnetId]||[];
    if(!bySub[subnetId].some(l=>((_saId(l.account)||_saName(l.account))===(_saId(sa)||_saName(sa)))))bySub[subnetId].push(link);
  };
  const byId=new Map();
  (storageAccounts||[]).forEach(sa=>{
    const id=_saId(sa).toLowerCase();
    if(id)byId.set(id,sa);
    const props=_saProps(sa);
    const rules=(props.networkAcls?.virtualNetworkRules)||(_saAzure(sa).networkAcls?.virtualNetworkRules)||[];
    rules.forEach(rule=>addLink(sa,rule.id||rule.subnet?.id||rule, 'VNet rule', rule.action||'Allow'));
  });
  (privateEndpoints||[]).forEach(pe=>{
    const target=_saPrivateLinkTarget(pe).toLowerCase();
    if(!target||!target.includes('/microsoft.storage/storageaccounts/'))return;
    const sa=byId.get(target);
    if(!sa)return;
    const subnetId=pe.SubnetId||pe.subnet?.id||pe.properties?.subnet?.id||'';
    addLink(sa,subnetId,'Private Endpoint',_saPrivateLinkGroup(pe),pe);
  });
  return{bySub,linksByStorageId};
}
function _storageInfo(sa,topology){
  const idKey=(_saId(sa).toLowerCase()||_saName(sa).toLowerCase());
  const links=(topology?.linksByStorageId?.[idKey]||[]);
  const props=_saProps(sa);
  const rules=(props.networkAcls?.virtualNetworkRules)||(_saAzure(sa).networkAcls?.virtualNetworkRules)||[];
  const hasPe=links.some(l=>l.via==='Private Endpoint');
  const hasRules=links.some(l=>l.via==='VNet rule')||rules.length>0;
  const defaultAction=_saDefaultAction(sa);
  const tls=_saTls(sa);
  const publicBlob=_saPublicBlob(sa);
  const httpsOnly=_saHttpsOnly(sa);
  const publicDisabled=String(props.publicNetworkAccess||'').toLowerCase()==='disabled';
  let access=publicDisabled?'Public network disabled':defaultAction==='Deny'?(hasRules?'VNet restricted':'Deny by default'):publicBlob?'Public blob':'Public network';
  if(hasPe)access+=' + Private Endpoint';
  let color='#ea580c',bg='rgba(234,88,12,.10)',severity='neutral';
  if(publicBlob||!httpsOnly||(tls&&tls!=='TLS1_2')){color='#ef4444';bg='rgba(239,68,68,.12)';severity='risk'}
  else if(!publicDisabled&&defaultAction==='Allow'){color='#f59e0b';bg='rgba(245,158,11,.12)';severity='open'}
  else if(publicDisabled||defaultAction==='Deny'){color='#10b981';bg='rgba(16,185,129,.12)';severity='private'}
  return{links,hasPe,hasRules,publicDisabled,access,color,bg,severity,tls,httpsOnly,publicBlob,sku:_saSku(sa),kind:_saKind(sa),services:_saEndpointKeys(sa)};
}
function _storageTooltipHtml(sa,topology){
  const info=_storageInfo(sa,topology);
  let h='<div class="tt-title" style="color:'+info.color+'">Storage Account</div>';
  h+='<div class="tt-sub">'+_storageEsc(_saName(sa))+'</div><div class="tt-sec">';
  h+='<div class="tt-r"><span class="i">Access</span> '+_storageEsc(info.access)+'</div>';
  if(info.sku)h+='<div class="tt-r"><span class="i">SKU</span> '+_storageEsc(info.sku)+'</div>';
  if(info.kind)h+='<div class="tt-r"><span class="i">Kind</span> '+_storageEsc(info.kind)+'</div>';
  if(info.tls)h+='<div class="tt-r"><span class="i">TLS</span> '+_storageEsc(info.tls)+'</div>';
  h+='<div class="tt-r"><span class="i">HTTPS only</span> '+(info.httpsOnly?'Yes':'No')+'</div>';
  h+='<div class="tt-r"><span class="i">Services</span> '+_storageEsc(info.services.join(', '))+'</div>';
  if(info.links.length){
    h+='<div class="tt-sh" style="margin-top:6px">Topology links</div>';
    info.links.slice(0,6).forEach(l=>{h+='<div class="tt-r"><span class="i">'+_storageEsc(l.via)+'</span> '+_storageEsc(_storageShortId(l.subnetId)||l.subnetId)+' '+_storageEsc(l.detail||'')+'</div>'});
  }
  h+='</div>';
  return h;
}
function _drawStorageGlyph(g,x,y,size){
  const blue='#0078d4',cyan='#50e6ff';
  const icon=g.append('g').attr('class','azure-storage-icon');
  icon.append('rect').attr('x',x).attr('y',y).attr('width',size).attr('height',size).attr('rx',3)
    .attr('fill',blue).attr('stroke','rgba(255,255,255,.32)').attr('stroke-width',0.7);
  icon.append('rect').attr('x',x+size*.13).attr('y',y+size*.14).attr('width',size*.74).attr('height',size*.72).attr('rx',2)
    .attr('fill','rgba(255,255,255,.10)').attr('stroke','rgba(255,255,255,.26)').attr('stroke-width',0.5);
  icon.append('ellipse').attr('cx',x+size*.50).attr('cy',y+size*.34).attr('rx',size*.25).attr('ry',size*.085)
    .attr('fill','none').attr('stroke','#fff').attr('stroke-width',1.45).attr('opacity',.96);
  icon.append('path').attr('d','M'+(x+size*.25)+' '+(y+size*.34)+' v'+(size*.28)+' c0 '+(size*.075)+' '+(size*.50)+' '+(size*.075)+' '+(size*.50)+' 0 v-'+(size*.28))
    .attr('fill','none').attr('stroke','#fff').attr('stroke-width',1.45).attr('opacity',.96);
  icon.append('path').attr('d','M'+(x+size*.25)+' '+(y+size*.48)+' c0 '+(size*.075)+' '+(size*.50)+' '+(size*.075)+' '+(size*.50)+' 0')
    .attr('fill','none').attr('stroke','#fff').attr('stroke-width',1.2).attr('opacity',.86);
  icon.append('rect').attr('x',x+size*.18).attr('y',y+size*.72).attr('width',size*.16).attr('height',size*.08).attr('rx',1)
    .attr('fill',cyan).attr('opacity',.95);
  icon.append('rect').attr('x',x+size*.42).attr('y',y+size*.72).attr('width',size*.16).attr('height',size*.08).attr('rx',1)
    .attr('fill',cyan).attr('opacity',.95);
  icon.append('rect').attr('x',x+size*.66).attr('y',y+size*.72).attr('width',size*.16).attr('height',size*.08).attr('rx',1)
    .attr('fill',cyan).attr('opacity',.95);
}
function _drawServicePill(g,x,y,w,h,label,color){
  const pill=g.append('g').attr('class','storage-pill');
  pill.append('rect').attr('x',x).attr('y',y).attr('width',w).attr('height',h).attr('rx',h/2)
    .attr('fill','rgba(0,120,212,.12)').attr('stroke',color).attr('stroke-width',0.5).attr('opacity',.95);
  pill.append('text').attr('x',x+w/2).attr('y',y+h/2).attr('text-anchor','middle')
    .attr('dominant-baseline','central').attr('alignment-baseline','middle').attr('dy','0.02em')
    .attr('font-family','Segoe UI,system-ui,sans-serif').style('font-size','calc(6.5px * var(--txt-scale,1))')
    .attr('font-weight','700').attr('fill',color).attr('pointer-events','none').text(label);
}
function _drawStorageAccountCard(parent,bk,info,topology,bx,by,w,h){
  const azureBlue='#0078d4';
  const bG=parent.append('g').style('cursor','pointer');
  bG.append('rect').attr('x',bx).attr('y',by).attr('width',w).attr('height',h).attr('rx',4)
    .attr('fill','rgba(8,28,50,.92)').attr('stroke',azureBlue).attr('stroke-width',0.9).attr('stroke-opacity',.9);
  bG.append('rect').attr('x',bx+1).attr('y',by+1).attr('width',3).attr('height',h-2).attr('rx',1.5)
    .attr('fill',info.color).attr('opacity',.95);
  bG.append('rect').attr('x',bx+8).attr('y',by+8).attr('width',32).attr('height',32).attr('rx',5)
    .attr('fill','rgba(0,120,212,.14)').attr('stroke','rgba(0,120,212,.36)').attr('stroke-width',0.7);
  _drawStorageGlyph(bG,bx+12,by+12,24);

  const textX=bx+46;
  const maxChars=Math.max(12,Math.floor((w-142)/6));
  const saName=_saName(bk);
  const dispName=saName.length>maxChars?saName.substring(0,maxChars-2)+'..':saName;
  bG.append('text').attr('x',textX).attr('y',by+16).attr('font-family','Segoe UI,system-ui,sans-serif')
    .style('font-size','calc(10px * var(--txt-scale,1))').attr('font-weight','700').attr('fill','var(--text-primary)').text(dispName);
  bG.append('text').attr('x',textX).attr('y',by+30).attr('font-family','Segoe UI,system-ui,sans-serif')
    .style('font-size','calc(8px * var(--txt-scale,1))').attr('fill','var(--text-secondary)')
    .text([info.sku,info.tls].filter(Boolean).join(' · ').substring(0,Math.max(20,maxChars+10)));

  const accessW=Math.min(86,Math.max(54,info.access.length*5.2+14));
  _drawServicePill(bG,bx+w-accessW-8,by+8,accessW,15,info.access.length>14?info.access.substring(0,12)+'..':info.access,info.color);

  const badgeY=by+h-20;
  const pillW=38,pillGap=5;
  info.services.slice(0,4).forEach((svc,si)=>{
    _drawServicePill(bG,textX+si*(pillW+pillGap),badgeY,pillW,14,svc.toUpperCase().slice(0,5),azureBlue);
  });
  if(info.links.length){
    _drawServicePill(bG,bx+w-54,badgeY,46,14,info.links.length+' LINK'+(info.links.length>1?'S':''),info.color);
  }

  bG.on('mouseenter',function(){
    const tt=document.getElementById('tooltip');
    tt.innerHTML=_storageTooltipHtml(bk,topology);tt.style.display='block';
  }).on('mousemove',function(event){positionTooltip(event,document.getElementById('tooltip'))})
    .on('mouseleave',()=>{document.getElementById('tooltip').style.display='none'})
    .on('click',function(event){
      event.stopPropagation();
      document.getElementById('tooltip').style.display='none';
      if(typeof resetDetailNavigation==='function')resetDetailNavigation();
      openResourceList('S3');
    });
  return bG;
}

if(typeof module!=='undefined'&&module.exports){
  module.exports={
    _saId,
    _saName,
    _buildStorageTopology,
    _storageInfo,
    _storageTooltipHtml
  };
}
