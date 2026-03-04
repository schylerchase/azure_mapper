// NSG / UDR editor and analysis engine for Azure
// Manages NSG rules (priority-based, Allow/Deny) and UDR routes
// Extracted from index.html for modularization
// Note: innerHTML usage matches existing codebase patterns with _escHtml sanitization

// === NSG/UDR EDITOR DATA MODEL ===
let _fwEdits=[];
let _fwSnapshot=null;

function _fwTakeSnapshot(){
  if(_fwSnapshot) return;
  if(!_rlCtx) return;
  _fwSnapshot={
    nsgs:structuredClone(_rlCtx.nsgs||[]),
    udrs:structuredClone(_rlCtx.udrs||[])
  };
}

function _fwResetAll(){
  if(!_fwSnapshot||!_rlCtx) return;
  _rlCtx.nsgs.length=0;
  _fwSnapshot.nsgs.forEach(n=>_rlCtx.nsgs.push(structuredClone(n)));
  _rlCtx.udrs.length=0;
  _fwSnapshot.udrs.forEach(r=>_rlCtx.udrs.push(structuredClone(r)));
  _fwRebuildLookups();
  _fwEdits=[];
  _fwSnapshot=null;
}

function _fwRebuildLookups(){
  if(!_rlCtx) return;
  const subnetNsgs={};
  (_rlCtx.nsgs||[]).forEach(nsg=>{
    (nsg.subnets||[]).forEach(subRef=>{
      const subId=typeof subRef==='string'?subRef:(subRef.id||subRef.SubnetId);
      if(subId) subnetNsgs[subId]=nsg;
    });
  });
  _rlCtx.subnetNsgs=subnetNsgs;
  const subRT={};
  (_rlCtx.udrs||[]).forEach(rt=>{
    (rt.subnets||[]).forEach(subRef=>{
      const subId=typeof subRef==='string'?subRef:(subRef.id||subRef.SubnetId);
      if(subId) subRT[subId]=rt;
    });
  });
  _rlCtx.subRT=subRT;
  const nsgByVnet={};
  (_rlCtx.nsgs||[]).forEach(nsg=>{
    const vnetId=nsg.vnetId||'';
    (nsgByVnet[vnetId]=nsgByVnet[vnetId]||[]).push(nsg);
  });
  _rlCtx.nsgByVnet=nsgByVnet;
}

function _fwUndo(){
  if(!_fwEdits.length) return null;
  const edit=_fwEdits.pop();
  if(edit.action==='add') _fwRemoveRule(edit);
  else if(edit.action==='delete') _fwRestoreRule(edit);
  else if(edit.action==='modify'){
    _fwApplyRule(edit.type, edit.resourceId, edit.direction, edit.originalRule);
  }
  _fwRebuildLookups();
  return edit;
}

function _fwRemoveRule(edit){
  if(edit.type==='nsg'){
    const nsg=(_rlCtx.nsgs||[]).find(n=>n.id===edit.resourceId||n.name===edit.resourceId);
    if(!nsg) return;
    const idx=(nsg.securityRules||[]).findIndex(r=>
      r.name===edit.rule.name && r.priority===edit.rule.priority
    );
    if(idx>=0) nsg.securityRules.splice(idx,1);
  } else if(edit.type==='udr'){
    const rt=(_rlCtx.udrs||[]).find(r=>r.id===edit.resourceId||r.name===edit.resourceId);
    if(!rt||!rt.routes) return;
    const idx=rt.routes.findIndex(r=>r.addressPrefix===edit.rule.addressPrefix);
    if(idx>=0) rt.routes.splice(idx,1);
  }
}

function _fwRestoreRule(edit){
  if(edit.originalRule){
    _fwApplyRule(edit.type, edit.resourceId, edit.direction, edit.originalRule);
  }
}

function _fwApplyRule(type, resourceId, direction, ruleData){
  if(type==='nsg'){
    const nsg=(_rlCtx.nsgs||[]).find(n=>n.id===resourceId||n.name===resourceId);
    if(!nsg) return;
    if(!nsg.securityRules) nsg.securityRules=[];
    const idx=nsg.securityRules.findIndex(r=>
      r.name===ruleData.name && r.priority===ruleData.priority
    );
    const entry=Object.assign({}, ruleData);
    if(idx>=0) nsg.securityRules[idx]=entry;
    else nsg.securityRules.push(entry);
  } else if(type==='udr'){
    const rt=(_rlCtx.udrs||[]).find(r=>r.id===resourceId||r.name===resourceId);
    if(!rt) return;
    if(!rt.routes) rt.routes=[];
    const idx=rt.routes.findIndex(r=>r.addressPrefix===ruleData.addressPrefix);
    if(idx>=0) rt.routes[idx]=Object.assign({},ruleData);
    else rt.routes.push(Object.assign({},ruleData));
  }
}

function _fwRuleMatch(a, b){
  if(!a||!b) return false;
  if(a.name!==b.name) return false;
  if(a.priority!==b.priority) return false;
  if((a.direction||'').toLowerCase()!==(b.direction||'').toLowerCase()) return false;
  if((a.access||'').toLowerCase()!==(b.access||'').toLowerCase()) return false;
  if((a.protocol||'').toLowerCase()!==(b.protocol||'').toLowerCase()) return false;
  if((a.sourceAddressPrefix||'')!==(b.sourceAddressPrefix||'')) return false;
  if((a.destinationAddressPrefix||'')!==(b.destinationAddressPrefix||'')) return false;
  if((a.destinationPortRange||'')!==(b.destinationPortRange||'')) return false;
  return true;
}

function _fwEditCount(resourceId){
  return _fwEdits.filter(e=>e.resourceId===resourceId).length;
}

// --- Validation ---
function _fwValidateCidr(cidr){
  if(!cidr||typeof cidr!=='string') return false;
  if(!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) return false;
  const parts=cidr.split('/');
  const octets=parts[0].split('.');
  for(let i=0;i<4;i++){if(parseInt(octets[i],10)>255) return false}
  if(parseInt(parts[1],10)>32) return false;
  return true;
}

function _fwValidateAddressPrefix(prefix){
  if(!prefix||typeof prefix!=='string') return false;
  const val=prefix.trim();
  const serviceTags=['*','VirtualNetwork','AzureLoadBalancer','Internet'];
  if(serviceTags.includes(val)) return true;
  if(_fwValidateCidr(val)) return true;
  if(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)){
    const octets=val.split('.');
    for(let i=0;i<4;i++){if(parseInt(octets[i],10)>255) return false}
    return true;
  }
  if(/^[A-Za-z][A-Za-z0-9.]*$/.test(val)) return true;
  return false;
}

function _fwValidateNsgRule(rule, existingRules, editingName){
  const errs=[];
  if(!rule.name||typeof rule.name!=='string'||!rule.name.trim()){
    errs.push('Rule name is required');
  } else if(!/^[A-Za-z0-9_.-]+$/.test(rule.name.trim())){
    errs.push('Rule name must contain only alphanumerics, underscores, periods, hyphens');
  }
  const priority=parseInt(rule.priority,10);
  if(isNaN(priority)||priority<100||priority>4096){
    errs.push('Priority must be 100-4096');
  }
  if(existingRules&&!isNaN(priority)){
    const dup=existingRules.some(r=>
      r.priority===priority &&
      (r.direction||'').toLowerCase()===(rule.direction||'').toLowerCase() &&
      r.name!==editingName
    );
    if(dup) errs.push('Duplicate priority '+priority+' in '+rule.direction+' direction');
  }
  const dir=(rule.direction||'').toLowerCase();
  if(dir!=='inbound'&&dir!=='outbound'){
    errs.push('Direction must be Inbound or Outbound');
  }
  const access=(rule.access||'').toLowerCase();
  if(access!=='allow'&&access!=='deny'){
    errs.push('Access must be Allow or Deny');
  }
  const proto=(rule.protocol||'').toLowerCase();
  const validProtos=['tcp','udp','icmp','esp','ah','*'];
  if(!validProtos.includes(proto)) errs.push('Invalid protocol: '+rule.protocol);
  if(proto==='tcp'||proto==='udp'){
    if(!rule.destinationPortRange&&!rule.destinationPortRanges){
      errs.push('Destination port range required for TCP/UDP');
    } else {
      const portStr=rule.destinationPortRange||'';
      if(portStr&&portStr!=='*'){
        const segments=portStr.split(',');
        for(const seg of segments){
          const s=seg.trim();
          if(s.includes('-')){
            const [lo,hi]=s.split('-').map(Number);
            if(isNaN(lo)||isNaN(hi)||lo<0||lo>65535||hi<0||hi>65535||lo>hi){
              errs.push('Invalid port range: '+s);
            }
          } else {
            const n=Number(s);
            if(isNaN(n)||n<0||n>65535) errs.push('Invalid port: '+s);
          }
        }
      }
    }
  }
  if(!_fwValidateAddressPrefix(rule.sourceAddressPrefix||'')){
    if(!(rule.sourceAddressPrefixes&&rule.sourceAddressPrefixes.length)){
      errs.push('Invalid source address prefix');
    }
  }
  if(!_fwValidateAddressPrefix(rule.destinationAddressPrefix||'')){
    if(!(rule.destinationAddressPrefixes&&rule.destinationAddressPrefixes.length)){
      errs.push('Invalid destination address prefix');
    }
  }
  return errs;
}

function _fwValidateRoute(route, existingRoutes, editingName){
  const errs=[];
  if(!route.name||typeof route.name!=='string'||!route.name.trim()){
    errs.push('Route name is required');
  }
  if(!_fwValidateCidr(route.addressPrefix)) errs.push('Invalid address prefix (CIDR)');
  if(existingRoutes){
    const dup=existingRoutes.some(r=>
      r.addressPrefix===route.addressPrefix && r.name!==editingName
    );
    if(dup) errs.push('Duplicate address prefix: '+route.addressPrefix);
  }
  const validHops=['VirtualNetworkGateway','VNetLocal','Internet','VirtualAppliance','None'];
  if(!validHops.includes(route.nextHopType)){
    errs.push('Invalid next hop type. Must be: '+validHops.join(', '));
  }
  if(route.nextHopType==='VirtualAppliance'){
    if(!route.nextHopIpAddress||!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(route.nextHopIpAddress)){
      errs.push('VirtualAppliance requires a valid next hop IP address');
    }
  }
  return errs;
}

function _fwCheckNsgShadow(nsg, direction){
  if(!nsg||!nsg.securityRules) return [];
  const dir=(direction||'').toLowerCase();
  const rules=(nsg.securityRules||[])
    .filter(r=>(r.direction||'').toLowerCase()===dir)
    .sort((a,b)=>a.priority-b.priority);
  const warnings=[];
  for(let i=1;i<rules.length;i++){
    for(let j=0;j<i;j++){
      const hi=rules[i], lo=rules[j];
      const sameSrc=(hi.sourceAddressPrefix||'')===(lo.sourceAddressPrefix||'')||lo.sourceAddressPrefix==='*';
      const sameDst=(hi.destinationAddressPrefix||'')===(lo.destinationAddressPrefix||'')||lo.destinationAddressPrefix==='*';
      const sameProto=(hi.protocol||'')===(lo.protocol||'')||lo.protocol==='*';
      const samePort=(hi.destinationPortRange||'')===(lo.destinationPortRange||'')||lo.destinationPortRange==='*';
      if(sameSrc&&sameDst&&sameProto&&samePort&&(hi.access||'').toLowerCase()!==(lo.access||'').toLowerCase()){
        warnings.push(
          'Rule "'+hi.name+'" (priority '+hi.priority+', '+hi.access+') is shadowed by "'+
          lo.name+'" (priority '+lo.priority+', '+lo.access+') \u2014 same scope, evaluated first'
        );
      }
    }
  }
  return warnings;
}

// --- CLI generation ---
function _fwGenerateCli(edits){
  const list=edits||_fwEdits;
  const cmds=[];
  list.forEach(edit=>{
    if(edit.type==='nsg') _fwGenNsgCli(edit, cmds);
    else if(edit.type==='udr') _fwGenUdrCli(edit, cmds);
  });
  return cmds;
}

function _fwGenNsgCli(edit, cmds){
  const nsgName=edit.nsgName||edit.resourceId;
  const rg=edit.resourceGroup||'{resource-group}';
  if(edit.action==='add'||edit.action==='modify'){
    cmds.push(_fwNsgRuleCmd('create', rg, nsgName, edit.rule));
  } else if(edit.action==='delete'){
    cmds.push(
      'az network nsg rule delete'+
      ' --resource-group '+rg+
      ' --nsg-name '+nsgName+
      ' --name '+edit.rule.name
    );
  }
}

function _fwNsgRuleCmd(verb, rg, nsgName, rule){
  let cmd='az network nsg rule '+verb+
    ' --resource-group '+rg+
    ' --nsg-name '+nsgName+
    ' --name '+rule.name+
    ' --priority '+rule.priority+
    ' --direction '+rule.direction+
    ' --access '+rule.access+
    ' --protocol '+rule.protocol;
  if(rule.sourcePortRange) cmd+=' --source-port-ranges '+rule.sourcePortRange;
  else cmd+=' --source-port-ranges "*"';
  if(rule.destinationPortRange) cmd+=' --destination-port-ranges '+rule.destinationPortRange;
  else cmd+=' --destination-port-ranges "*"';
  if(rule.sourceAddressPrefix) cmd+=' --source-address-prefixes '+rule.sourceAddressPrefix;
  else cmd+=' --source-address-prefixes "*"';
  if(rule.destinationAddressPrefix) cmd+=' --destination-address-prefixes '+rule.destinationAddressPrefix;
  else cmd+=' --destination-address-prefixes "*"';
  return cmd;
}

function _fwGenUdrCli(edit, cmds){
  const rtName=edit.routeTableName||edit.resourceId;
  const rg=edit.resourceGroup||'{resource-group}';
  if(edit.action==='add'||edit.action==='modify'){
    cmds.push(_fwUdrRouteCmd('create', rg, rtName, edit.rule));
  } else if(edit.action==='delete'){
    cmds.push(
      'az network route-table route delete'+
      ' --resource-group '+rg+
      ' --route-table-name '+rtName+
      ' --name '+edit.rule.name
    );
  }
}

function _fwUdrRouteCmd(verb, rg, rtName, route){
  let cmd='az network route-table route '+verb+
    ' --resource-group '+rg+
    ' --route-table-name '+rtName+
    ' --name '+route.name+
    ' --address-prefix '+route.addressPrefix+
    ' --next-hop-type '+route.nextHopType;
  if(route.nextHopType==='VirtualAppliance'&&route.nextHopIpAddress){
    cmd+=' --next-hop-ip-address '+route.nextHopIpAddress;
  }
  return cmd;
}

function _fwProtoLabel(proto){
  if(!proto) return 'Any';
  const p=String(proto).toLowerCase();
  if(p==='*') return 'Any';
  if(p==='tcp') return 'TCP';
  if(p==='udp') return 'UDP';
  if(p==='icmp') return 'ICMP';
  if(p==='esp') return 'ESP';
  if(p==='ah') return 'AH';
  return proto;
}

// === NSG/UDR EDITOR RENDERING ===
// Note: All user-provided data is sanitized via _escHtml before insertion.

function _fwRenderNsgInline(nsg, sub){
  const nsgId=nsg.id||nsg.name;
  const nsgName=nsg.name||nsgId;
  const ec=_fwEditCount(nsgId);
  let h='<div class="dp-kv"><span class="k">NSG</span><span class="v">'+_escHtml(nsgName)+(ec?'<span class="fw-badge edits">'+ec+' edit'+(ec>1?'s':'')+'</span>':'')+'</span></div>';
  h+=_fwRenderNsgDirection(nsg, 'Inbound', sub);
  h+=_fwRenderNsgDirection(nsg, 'Outbound', sub);
  const iWarn=_fwCheckNsgShadow(nsg,'inbound');
  const eWarn=_fwCheckNsgShadow(nsg,'outbound');
  const allWarn=iWarn.concat(eWarn);
  if(allWarn.length){
    h+='<div style="margin-top:6px;padding:4px 6px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:4px;font-size:calc(8px * var(--txt-scale) * var(--dp-txt-scale));font-family:Segoe UI,system-ui,sans-serif">';
    h+='<div style="color:var(--accent-orange);font-weight:600;margin-bottom:2px">Shadow Warnings</div>';
    allWarn.forEach(function(w){h+='<div style="color:var(--text-muted);margin:1px 0">'+_escHtml(w)+'</div>'});
    h+='</div>';
  }
  h+='<div class="fw-toolbar">';
  h+='<button data-fw-action="full-editor" data-nsg-id="'+_escHtml(nsgId)+'">Full Editor</button>';
  h+='<button data-fw-action="export-cli" data-fw-type="nsg" data-nsg-id="'+_escHtml(nsgId)+'">Export CLI</button>';
  h+='<button data-fw-action="undo">Undo</button>';
  h+='<button data-fw-action="reset">Reset</button>';
  h+='</div>';
  return h;
}

function _fwRenderNsgDirection(nsg, direction, sub){
  const nsgId=nsg.id||nsg.name;
  const label=direction==='Inbound'?'INBOUND RULES':'OUTBOUND RULES';
  const dir=direction.toLowerCase();
  const rules=(nsg.securityRules||[])
    .filter(function(r){return (r.direction||'').toLowerCase()===dir})
    .sort(function(a,b){return a.priority-b.priority});
  let h='<div style="margin-top:6px"><div class="dp-row"><span class="lbl">'+label+'</span></div>';
  rules.forEach(function(r){
    const cls=(r.access||'').toLowerCase()==='allow'?'allow':'deny';
    const proto=_fwProtoLabel(r.protocol);
    const port=r.destinationPortRange||'*';
    const src=r.sourceAddressPrefix||'*';
    h+='<div class="fw-edit-row">';
    h+='<div class="fw-arrow '+cls+'"><div class="fw-arrow-line"></div><div class="fw-arrow-head"></div></div>';
    h+='<span class="fw-proto">'+proto+'</span>';
    h+='<span class="fw-port '+cls+'">P'+r.priority+' '+_escHtml(port)+'</span>';
    h+='<span class="fw-src">'+_escHtml(src)+'</span>';
    h+='<span style="margin-left:auto;display:flex;gap:2px">';
    h+='<button class="fw-edit-btn edit" data-fw-action="edit-nsg" data-nsg-id="'+_escHtml(nsgId)+'" data-rule-name="'+_escHtml(r.name)+'" data-direction="'+_escHtml(direction)+'" title="Edit">&#9998;</button>';
    h+='<button class="fw-edit-btn del" data-fw-action="delete-nsg" data-nsg-id="'+_escHtml(nsgId)+'" data-rule-name="'+_escHtml(r.name)+'" data-direction="'+_escHtml(direction)+'" title="Delete">&#10005;</button>';
    h+='</span></div>';
  });
  h+='<div class="fw-edit-row" style="opacity:.4">';
  h+='<div class="fw-arrow deny"><div class="fw-arrow-line"></div><div class="fw-arrow-head"></div></div>';
  h+='<span class="fw-proto">Any</span>';
  h+='<span class="fw-port deny">P65500 DenyAll</span>';
  h+='<span class="fw-src">*</span>';
  h+='</div>';
  h+='<button class="fw-edit-btn add" data-fw-action="add-nsg" data-nsg-id="'+_escHtml(nsgId)+'" data-direction="'+_escHtml(direction)+'">+ Add Rule</button>';
  h+='</div>';
  return h;
}

function _fwShowNsgEditForm(nsgId, ruleName, direction, container){
  const nsg=(_rlCtx.nsgs||[]).find(function(n){return (n.id||n.name)===nsgId});
  if(!nsg) return;
  const dir=(direction||'Inbound');
  let existing=null;
  if(ruleName){
    existing=(nsg.securityRules||[]).find(function(r){return r.name===ruleName});
  }
  const name=existing?existing.name:'';
  const priority=existing?existing.priority:'';
  const access=existing?(existing.access||'Allow'):'Allow';
  const proto=existing?(existing.protocol||'*'):'Tcp';
  const dstPort=existing?(existing.destinationPortRange||'*'):'';
  const srcAddr=existing?(existing.sourceAddressPrefix||'*'):'*';
  const dstAddr=existing?(existing.destinationAddressPrefix||'*'):'*';
  const disablePorts=(proto.toLowerCase()==='*'||proto.toLowerCase()==='icmp')?'disabled':'';

  const row=document.createElement('div');
  row.className='fw-edit-row new-rule';
  row.setAttribute('data-fw-form','nsg');
  const formHtml=
    '<input class="fw-input" data-field="name" placeholder="Rule name" value="'+_escHtml(name)+'" style="width:90px" title="Rule Name">'+
    '<input class="fw-input" data-field="priority" type="number" min="100" max="4096" placeholder="Priority" value="'+priority+'" style="width:55px" title="Priority (100-4096)">'+
    '<select class="fw-select" data-field="access" title="Access">'+
      '<option value="Allow"'+(access==='Allow'?' selected':'')+'>Allow</option>'+
      '<option value="Deny"'+(access==='Deny'?' selected':'')+'>Deny</option>'+
    '</select>'+
    '<select class="fw-select" data-field="protocol" title="Protocol">'+
      '<option value="Tcp"'+(proto.toLowerCase()==='tcp'?' selected':'')+'>TCP</option>'+
      '<option value="Udp"'+(proto.toLowerCase()==='udp'?' selected':'')+'>UDP</option>'+
      '<option value="Icmp"'+(proto.toLowerCase()==='icmp'?' selected':'')+'>ICMP</option>'+
      '<option value="Esp"'+(proto.toLowerCase()==='esp'?' selected':'')+'>ESP</option>'+
      '<option value="Ah"'+(proto.toLowerCase()==='ah'?' selected':'')+'>AH</option>'+
      '<option value="*"'+(proto==='*'?' selected':'')+'>Any</option>'+
    '</select>'+
    '<input class="fw-input" data-field="dstPort" placeholder="Dst Port" value="'+_escHtml(dstPort)+'" style="width:60px" '+disablePorts+' title="Destination port (e.g. 80, 80-443, *)">'+
    '<input class="fw-input" data-field="srcAddr" placeholder="Source" value="'+_escHtml(srcAddr)+'" style="width:90px" title="Source (CIDR, service tag, or *)">'+
    '<input class="fw-input" data-field="dstAddr" placeholder="Destination" value="'+_escHtml(dstAddr)+'" style="width:90px" title="Destination (CIDR, service tag, or *)">'+
    '<button class="fw-edit-btn save" data-fw-action="save-nsg" data-nsg-id="'+_escHtml(nsgId)+'" data-direction="'+_escHtml(dir)+'"'+(existing?' data-editing="'+_escHtml(existing.name)+'"':'')+'>Save</button>'+
    '<button class="fw-edit-btn cancel" data-fw-action="cancel-edit">Cancel</button>';
  row.innerHTML=formHtml;
  container.appendChild(row);
  const protoSel=row.querySelector('[data-field="protocol"]');
  protoSel.addEventListener('change',function(){
    const v=protoSel.value;
    const dpEl=row.querySelector('[data-field="dstPort"]');
    if(v==='*'||v==='Icmp'||v==='Esp'||v==='Ah'){dpEl.disabled=true;dpEl.value='*'}
    else{dpEl.disabled=false}
  });
}

function _fwRenderUdrInline(rt, vnetId, lk){
  const rtId=rt.id||rt.name;
  const rtName=rt.name||rtId;
  const ec=_fwEditCount(rtId);
  let h='<div class="dp-kv"><span class="k">Route Table</span><span class="v">'+_escHtml(rtName)+(ec?'<span class="fw-badge edits">'+ec+' edit'+(ec>1?'s':'')+'</span>':'')+'</span></div>';
  (rt.routes||[]).forEach(function(r,idx){
    const dest=r.addressPrefix||'?';
    const hop=r.nextHopType||'None';
    const hopAddr=r.nextHopIpAddress?' ('+r.nextHopIpAddress+')':'';
    const isSystem=r.isSystem;
    h+='<div class="fw-edit-row">';
    h+='<span style="color:var(--text-primary);min-width:100px">'+_escHtml(dest)+'</span>';
    h+='<span class="p" style="margin:0 4px">-&gt;</span>';
    h+='<span>'+_escHtml(hop+hopAddr)+'</span>';
    if(!isSystem){
      h+='<span style="margin-left:auto;display:flex;gap:2px">';
      h+='<button class="fw-edit-btn edit" data-fw-action="edit-udr" data-udr-id="'+_escHtml(rtId)+'" data-rule-idx="'+idx+'" title="Edit">&#9998;</button>';
      h+='<button class="fw-edit-btn del" data-fw-action="delete-udr" data-udr-id="'+_escHtml(rtId)+'" data-rule-idx="'+idx+'" title="Delete">&#10005;</button>';
      h+='</span>';
    }
    h+='</div>';
  });
  h+='<button class="fw-edit-btn add" data-fw-action="add-udr" data-udr-id="'+_escHtml(rtId)+'">+ Add Route</button>';
  h+='<div class="fw-toolbar">';
  h+='<button data-fw-action="full-editor" data-udr-id="'+_escHtml(rtId)+'">Full Editor</button>';
  h+='<button data-fw-action="export-cli" data-fw-type="udr" data-udr-id="'+_escHtml(rtId)+'">Export CLI</button>';
  h+='<button data-fw-action="undo">Undo</button>';
  h+='<button data-fw-action="reset">Reset</button>';
  h+='</div>';
  return h;
}

function _fwShowUdrEditForm(rtId, routeIdx, container){
  const rt=(_rlCtx.udrs||[]).find(function(r){return (r.id||r.name)===rtId});
  if(!rt) return;
  const existing=(routeIdx!==null&&routeIdx!==undefined)?(rt.routes||[])[parseInt(routeIdx,10)]:null;
  const name=existing?existing.name:'';
  const dest=existing?existing.addressPrefix||'':'';
  const hopType=existing?existing.nextHopType||'Internet':'Internet';
  const hopAddr=existing?existing.nextHopIpAddress||'':'';

  const hopTypes=['VirtualNetworkGateway','VNetLocal','Internet','VirtualAppliance','None'];
  let hopOpts='';
  hopTypes.forEach(function(ht){
    hopOpts+='<option value="'+ht+'"'+(hopType===ht?' selected':'')+'>'+ht+'</option>';
  });

  const row=document.createElement('div');
  row.className='fw-edit-row new-rule';
  row.setAttribute('data-fw-form','udr');
  const formHtml=
    '<input class="fw-input" data-field="name" placeholder="Route name" value="'+_escHtml(name)+'" style="width:90px" title="Route Name">'+
    '<input class="fw-input" data-field="dest" placeholder="Address Prefix" value="'+_escHtml(dest)+'" style="width:110px" title="Destination CIDR">'+
    '<span class="p" style="margin:0 4px">-&gt;</span>'+
    '<select class="fw-select" data-field="nextHopType" style="width:140px" title="Next Hop Type">'+hopOpts+'</select>'+
    '<input class="fw-input" data-field="nextHopIp" placeholder="Next Hop IP" value="'+_escHtml(hopAddr)+'" style="width:100px"'+(hopType!=='VirtualAppliance'?' disabled':'')+' title="Next Hop IP (required for VirtualAppliance)">'+
    '<button class="fw-edit-btn save" data-fw-action="save-udr" data-udr-id="'+_escHtml(rtId)+'"'+(existing?' data-editing="'+_escHtml(String(routeIdx))+'"':'')+'>Save</button>'+
    '<button class="fw-edit-btn cancel" data-fw-action="cancel-edit">Cancel</button>';
  row.innerHTML=formHtml;
  container.appendChild(row);
  const hopSel=row.querySelector('[data-field="nextHopType"]');
  hopSel.addEventListener('change',function(){
    const ipEl=row.querySelector('[data-field="nextHopIp"]');
    if(hopSel.value==='VirtualAppliance'){ipEl.disabled=false}
    else{ipEl.disabled=true;ipEl.value=''}
  });
}

// === FULL PANEL EDITOR ===
let _fwFpType=null, _fwFpResId=null, _fwFpSub=null, _fwFpVnetId=null, _fwFpLk=null, _fwFpDir='Inbound';

function _fwOpenFullEditor(type, resourceId, sub, vnetId, lk){
  _fwFpType=type;
  _fwFpResId=resourceId;
  _fwFpSub=sub;
  _fwFpVnetId=vnetId;
  _fwFpLk=lk;
  _fwFpDir='Inbound';

  const titleEl=document.getElementById('fwFpTitle');
  const label=type==='nsg'?'NSG':'Route Table (UDR)';
  let name='';
  if(type==='nsg'){
    const nsg=(_rlCtx.nsgs||[]).find(function(n){return (n.id||n.name)===resourceId});
    if(nsg) name=nsg.name||resourceId;
  } else if(type==='udr'){
    const rt=(_rlCtx.udrs||[]).find(function(r){return (r.id||r.name)===resourceId});
    if(rt) name=rt.name||resourceId;
  }
  const vnetObj=vnetId?(_rlCtx.vnets||[]).find(function(v){return v.id===vnetId}):null;
  const vnetLabel=vnetObj?(vnetObj.name||vnetId):(vnetId||'');
  titleEl.textContent=label+': '+(name||resourceId);
  if(vnetId){
    const vnetSpan=document.createElement('span');
    vnetSpan.className='fw-link';
    vnetSpan.id='fwFpVnetLink';
    vnetSpan.style.cssText='font-size:10px;font-weight:400;margin-left:6px';
    vnetSpan.textContent=vnetLabel;
    titleEl.appendChild(vnetSpan);
  }
  const vnetLink=document.getElementById('fwFpVnetLink');
  if(vnetLink){vnetLink.addEventListener('click',function(e){
    e.stopPropagation();
    document.getElementById('fwFullPanel').classList.remove('open');
    closeUnifiedDash();
    setTimeout(function(){_zoomToElement(vnetId)},250);
  })}

  const tabsEl=document.getElementById('fwFpTabs');
  tabsEl.style.display=(type==='udr')?'none':'flex';

  const retraceBtn=document.getElementById('fwFpRetrace');
  retraceBtn.style.display=_flowMode?'inline-block':'none';

  _fwRefreshFullPanel();
  document.getElementById('fwFullPanel').classList.add('open');
}

function _fwRefreshFullPanel(){
  if(!_fwFpType||!_fwFpResId) return;
  const bodyEl=document.getElementById('fwFpBody');
  const visualEl=document.getElementById('fwFpVisual');
  const cliEl=document.getElementById('fwFpCli');
  let h='';

  const tabs=document.querySelectorAll('#fwFpTabs .fw-fp-tab');
  tabs.forEach(function(t){
    t.classList.toggle('active', t.getAttribute('data-dir')===_fwFpDir);
  });

  if(_fwFpType==='nsg'){
    const nsg=(_rlCtx.nsgs||[]).find(function(n){return (n.id||n.name)===_fwFpResId});
    if(!nsg){ bodyEl.textContent='NSG not found'; return; }
    h+=_fwRenderNsgDirection(nsg, _fwFpDir, _fwFpSub);
    const warns=_fwCheckNsgShadow(nsg, _fwFpDir.toLowerCase());
    if(warns.length){
      h+='<div style="margin-top:6px;padding:4px 6px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:4px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif">';
      h+='<div style="color:var(--accent-orange);font-weight:600;margin-bottom:2px">Shadow Warnings</div>';
      warns.forEach(function(w){h+='<div style="color:var(--text-muted);margin:1px 0">'+_escHtml(w)+'</div>'});
      h+='</div>';
    }
  } else if(_fwFpType==='udr'){
    const rt=(_rlCtx.udrs||[]).find(function(r){return (r.id||r.name)===_fwFpResId});
    if(!rt){ bodyEl.textContent='Route Table not found'; return; }
    const rtId=rt.id||rt.name;
    (rt.routes||[]).forEach(function(r,idx){
      const dest=r.addressPrefix||'?';
      const hop=r.nextHopType||'None';
      const hopAddr=r.nextHopIpAddress?' ('+r.nextHopIpAddress+')':'';
      const isSystem=r.isSystem;
      h+='<div class="fw-edit-row">';
      h+='<span style="color:var(--text-primary);min-width:100px">'+_escHtml(dest)+'</span>';
      h+='<span class="p" style="margin:0 4px">-&gt;</span>';
      h+='<span>'+_escHtml(hop+hopAddr)+'</span>';
      if(!isSystem){
        h+='<span style="margin-left:auto;display:flex;gap:2px">';
        h+='<button class="fw-edit-btn edit" data-fw-action="edit-udr" data-udr-id="'+_escHtml(rtId)+'" data-rule-idx="'+idx+'" title="Edit">&#9998;</button>';
        h+='<button class="fw-edit-btn del" data-fw-action="delete-udr" data-udr-id="'+_escHtml(rtId)+'" data-rule-idx="'+idx+'" title="Delete">&#10005;</button>';
        h+='</span>';
      }
      h+='</div>';
    });
    h+='<button class="fw-edit-btn add" data-fw-action="add-udr" data-udr-id="'+_escHtml(rtId)+'">+ Add Route</button>';
  }

  const _fpCompLookup=_buildComplianceLookup();
  const _fpResComp=_fpCompLookup[_fwFpResId];
  if(_fpResComp&&_fpResComp.findings.length){
    h+='<div class="fw-fp-compliance">';
    h+='<div style="font-size:11px;font-weight:600;color:var(--accent-orange);margin-bottom:8px">Compliance Findings ('+_fpResComp.count+')</div>';
    _fpResComp.findings.forEach(function(f){
      h+='<div class="fw-fp-finding sev-'+f.severity+'">';
      h+='<span class="sev-badge sev-'+f.severity+'" style="font-size:8px;padding:1px 5px;margin-right:6px">'+f.severity+'</span>';
      h+='<span class="fw-finding-ctrl" data-fw-ctrl="'+_escHtml(f.control)+'">'+_escHtml(f.control)+'</span>';
      if(f.ckv) h+=' <span style="opacity:.5;font-size:8px">('+_escHtml(f.ckv)+')</span>';
      h+='<div style="margin:4px 0 2px;color:var(--text-secondary);font-size:10px">'+_escHtml(f.message)+'</div>';
      h+='<div style="color:var(--text-muted);font-size:9px">Remediation: '+_escHtml(f.remediation)+'</div>';
      h+='</div>';
    });
    h+='</div>';
  }

  bodyEl.innerHTML=h;

  bodyEl.querySelectorAll('.fw-finding-ctrl').forEach(function(el){
    el.addEventListener('click',function(e){
      e.stopPropagation();
      const ctrl=this.dataset.fwCtrl;
      document.getElementById('fwFullPanel').classList.remove('open');
      _compDashState={sevFilter:'ALL',fwFilter:'all',search:ctrl,sort:'severity',showMuted:false,execSummary:false,view:_compDashState.view||'action'};
      _compToolbarTab=null;
      _switchUdashTab('compliance');
    });
  });

  bodyEl.onclick=function(ev){
    if(ev.target.closest('.fw-finding-ctrl'))return;
    _fwHandleAction(ev, _fwFpSub, _fwFpVnetId, _fwFpLk);
  };

  let vH='';
  if(_fwFpType==='nsg'){
    const vNsg=(_rlCtx.nsgs||[]).find(function(n){return (n.id||n.name)===_fwFpResId});
    if(vNsg){
      const vDir=_fwFpDir.toLowerCase();
      const vRules=(vNsg.securityRules||[])
        .filter(function(r){return (r.direction||'').toLowerCase()===vDir})
        .sort(function(a,b){return a.priority-b.priority});
      const vLabel=_fwFpDir==='Inbound'?'INBOUND':'OUTBOUND';
      vH+='<div style="font-size:10px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;font-family:Segoe UI,system-ui,sans-serif">'+vLabel+' FLOW</div>';
      vRules.forEach(function(r){
        const cls=(r.access||'').toLowerCase()==='allow'?'allow':'deny';
        const proto=_fwProtoLabel(r.protocol);
        const port=r.destinationPortRange||'*';
        vH+='<div class="fw-edit-row" style="padding:2px 0">';
        vH+='<div class="fw-arrow '+cls+'"><div class="fw-arrow-line"></div><div class="fw-arrow-head"></div></div>';
        vH+='<span style="font-size:9px;color:var(--text-muted)">P'+r.priority+' '+proto+' '+_escHtml(port)+' '+r.access+'</span>';
        vH+='</div>';
      });
      vH+='<div class="fw-edit-row" style="padding:2px 0;opacity:.4"><div class="fw-arrow deny"><div class="fw-arrow-line"></div><div class="fw-arrow-head"></div></div><span style="font-size:9px;color:var(--text-muted)">P65500 DENY ALL</span></div>';
    }
  } else if(_fwFpType==='udr'){
    const vRt=(_rlCtx.udrs||[]).find(function(r){return (r.id||r.name)===_fwFpResId});
    if(vRt){
      vH+='<div style="font-size:10px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;font-family:Segoe UI,system-ui,sans-serif">ROUTE FLOW</div>';
      (vRt.routes||[]).forEach(function(r){
        const dest=r.addressPrefix||'?';
        const hop=r.nextHopType||'None';
        const hopAddr=r.nextHopIpAddress?' ('+r.nextHopIpAddress+')':'';
        vH+='<div class="fw-edit-row" style="padding:2px 0">';
        vH+='<div class="fw-arrow allow"><div class="fw-arrow-line"></div><div class="fw-arrow-head"></div></div>';
        vH+='<span style="font-size:9px;color:var(--text-muted)">'+_escHtml(dest)+' &rarr; '+_escHtml(hop+hopAddr)+'</span>';
        vH+='</div>';
      });
    }
  }
  visualEl.innerHTML=vH;

  const filtered=_fwEdits.filter(function(ed){return ed.resourceId===_fwFpResId});
  const cmds=_fwGenerateCli(filtered);
  if(cmds.length){
    cliEl.textContent=cmds.join('\n');
  } else {
    cliEl.textContent='No pending edits';
  }
}

// === EVENT HANDLER ===

function _fwHandleAction(e, sub, vnetId, lk){
  const el=e.target.closest('[data-fw-action]');
  if(!el) return;
  e.stopPropagation();
  const action=el.getAttribute('data-fw-action');
  const _inFullPanel=!!el.closest('#fwFpBody');
  const dpBody=_inFullPanel?document.getElementById('fwFpBody'):document.getElementById('dpBody');

  if(action==='cancel-edit'){
    const form=el.closest('[data-fw-form]');
    if(form) form.remove();
    return;
  }
  if(action==='undo'){
    _fwUndo();
    if(sub && lk) openSubnetPanel(sub, vnetId, lk);
    if(typeof _fwDashRender==='function' && _udashTab==='firewall' && document.getElementById('udash') && document.getElementById('udash').classList.contains('open')) _fwDashRender();
    if(document.getElementById('fwFullPanel').classList.contains('open')) _fwRefreshFullPanel();
    return;
  }
  if(action==='reset'){
    _fwResetAll();
    if(sub && lk) openSubnetPanel(sub, vnetId, lk);
    if(typeof _fwDashRender==='function' && _udashTab==='firewall' && document.getElementById('udash') && document.getElementById('udash').classList.contains('open')) _fwDashRender();
    if(document.getElementById('fwFullPanel').classList.contains('open')) _fwRefreshFullPanel();
    return;
  }
  if(action==='export-cli'){
    const fwType=el.getAttribute('data-fw-type');
    const resId=el.getAttribute('data-nsg-id')||el.getAttribute('data-udr-id');
    const filtered=_fwEdits.filter(function(ed){return ed.type===fwType&&ed.resourceId===resId});
    const cmds=_fwGenerateCli(filtered);
    if(cmds.length){
      const txt=cmds.join('\n');
      if(navigator.clipboard&&navigator.clipboard.writeText){
        navigator.clipboard.writeText(txt).then(function(){
          el.textContent='Copied!';
          setTimeout(function(){el.textContent='Export CLI'},1500);
        }).catch(function(){el.textContent='Copy failed';setTimeout(function(){el.textContent='Export CLI'},1500)});
      } else {
        el.textContent=cmds.length+' cmd(s)';
        setTimeout(function(){el.textContent='Export CLI'},1500);
      }
    } else {
      el.textContent='No edits';
      setTimeout(function(){el.textContent='Export CLI'},1500);
    }
    return;
  }
  if(action==='full-editor'){
    const feNsgId=el.getAttribute('data-nsg-id');
    const feUdrId=el.getAttribute('data-udr-id');
    const feType=feNsgId?'nsg':'udr';
    const feId=feNsgId||feUdrId;
    _fwOpenFullEditor(feType, feId, sub, vnetId, lk);
    return;
  }

  // NSG actions
  if(action==='edit-nsg'){
    dpBody.querySelectorAll('[data-fw-form]').forEach(function(f){f.remove()});
    const nsgId=el.getAttribute('data-nsg-id');
    const ruleName=el.getAttribute('data-rule-name');
    const dir=el.getAttribute('data-direction');
    const parentRow=el.closest('.fw-edit-row');
    const insertAfter=parentRow||el.closest('.dp-row');
    if(insertAfter&&insertAfter.parentNode){
      _fwShowNsgEditForm(nsgId, ruleName, dir, insertAfter.parentNode);
    }
    return;
  }
  if(action==='add-nsg'){
    dpBody.querySelectorAll('[data-fw-form]').forEach(function(f){f.remove()});
    const nsgId2=el.getAttribute('data-nsg-id');
    const dir2=el.getAttribute('data-direction');
    const parent2=el.parentNode;
    if(parent2){
      _fwShowNsgEditForm(nsgId2, null, dir2, parent2);
    }
    return;
  }
  if(action==='delete-nsg'){
    const dNsgId=el.getAttribute('data-nsg-id');
    const dRuleName=el.getAttribute('data-rule-name');
    const dDirection=el.getAttribute('data-direction');
    const dNsg=(_rlCtx.nsgs||[]).find(function(n){return (n.id||n.name)===dNsgId});
    if(!dNsg) return;
    const dRule=(dNsg.securityRules||[]).find(function(r){return r.name===dRuleName});
    if(!dRule) return;
    _fwTakeSnapshot();
    const dIdx=(dNsg.securityRules||[]).findIndex(function(r){return r.name===dRuleName});
    if(dIdx>=0) dNsg.securityRules.splice(dIdx,1);
    const rg=_extractResourceGroup(dNsg.id);
    _fwEdits.push({type:'nsg',resourceId:dNsgId,nsgName:dNsg.name||dNsgId,resourceGroup:rg,direction:dDirection,action:'delete',rule:Object.assign({},dRule),originalRule:Object.assign({},dRule)});
    _fwRebuildLookups();
    if(sub && lk) openSubnetPanel(sub, vnetId, lk);
    if(typeof _fwDashRender==='function' && _udashTab==='firewall' && document.getElementById('udash') && document.getElementById('udash').classList.contains('open')) _fwDashRender();
    if(document.getElementById('fwFullPanel').classList.contains('open')) _fwRefreshFullPanel();
    return;
  }
  if(action==='save-nsg'){
    const sNsgId=el.getAttribute('data-nsg-id');
    const sDirection=el.getAttribute('data-direction');
    const sEditing=el.getAttribute('data-editing');
    const formRow=el.closest('[data-fw-form]');
    if(!formRow) return;
    const rName=formRow.querySelector('[data-field="name"]').value.trim();
    const rPriority=parseInt(formRow.querySelector('[data-field="priority"]').value,10);
    const rAccess=formRow.querySelector('[data-field="access"]').value;
    const rProto=formRow.querySelector('[data-field="protocol"]').value;
    const rDstPort=formRow.querySelector('[data-field="dstPort"]').value.trim()||'*';
    const rSrcAddr=formRow.querySelector('[data-field="srcAddr"]').value.trim()||'*';
    const rDstAddr=formRow.querySelector('[data-field="dstAddr"]').value.trim()||'*';
    const ruleObj={
      name:rName,
      priority:rPriority,
      direction:sDirection,
      access:rAccess,
      protocol:rProto,
      sourcePortRange:'*',
      destinationPortRange:rDstPort,
      sourceAddressPrefix:rSrcAddr,
      destinationAddressPrefix:rDstAddr
    };
    const sNsg=(_rlCtx.nsgs||[]).find(function(n){return (n.id||n.name)===sNsgId});
    const otherRules=sNsg?(sNsg.securityRules||[]).filter(function(r){
      if(sEditing&&r.name===sEditing) return false;
      return true;
    }):[];
    const errs=_fwValidateNsgRule(ruleObj, otherRules, sEditing);
    formRow.querySelectorAll('.fw-input,.fw-select').forEach(function(inp){inp.classList.remove('invalid')});
    if(errs.length){
      errs.forEach(function(er){
        if(er.indexOf('name')>=0||er.indexOf('Name')>=0) formRow.querySelector('[data-field="name"]').classList.add('invalid');
        if(er.indexOf('riority')>=0) formRow.querySelector('[data-field="priority"]').classList.add('invalid');
        if(er.indexOf('port')>=0||er.indexOf('Port')>=0){
          const dpEl=formRow.querySelector('[data-field="dstPort"]');
          if(dpEl) dpEl.classList.add('invalid');
        }
        if(er.indexOf('ource address')>=0) formRow.querySelector('[data-field="srcAddr"]').classList.add('invalid');
        if(er.indexOf('estination address')>=0) formRow.querySelector('[data-field="dstAddr"]').classList.add('invalid');
      });
      return;
    }
    _fwTakeSnapshot();
    let editAction='add';
    let origRule=null;
    if(sEditing&&sNsg){
      origRule=(sNsg.securityRules||[]).find(function(r){return r.name===sEditing});
      if(origRule) origRule=Object.assign({},origRule);
      const oldIdx=(sNsg.securityRules||[]).findIndex(function(r){return r.name===sEditing});
      if(oldIdx>=0) sNsg.securityRules.splice(oldIdx,1);
      editAction='modify';
    }
    _fwApplyRule('nsg', sNsgId, sDirection, ruleObj);
    const rg=sNsg?_extractResourceGroup(sNsg.id):'';
    const editObj={type:'nsg',resourceId:sNsgId,nsgName:sNsg?sNsg.name:sNsgId,resourceGroup:rg,direction:sDirection,action:editAction,rule:Object.assign({},ruleObj)};
    if(origRule) editObj.originalRule=origRule;
    _fwEdits.push(editObj);
    _fwRebuildLookups();
    if(sub && lk) openSubnetPanel(sub, vnetId, lk);
    if(typeof _fwDashRender==='function' && _udashTab==='firewall' && document.getElementById('udash') && document.getElementById('udash').classList.contains('open')) _fwDashRender();
    if(document.getElementById('fwFullPanel').classList.contains('open')) _fwRefreshFullPanel();
    return;
  }

  // UDR actions
  if(action==='edit-udr'){
    dpBody.querySelectorAll('[data-fw-form]').forEach(function(f){f.remove()});
    const rtId5=el.getAttribute('data-udr-id');
    const rIdx5=el.getAttribute('data-rule-idx');
    const parentRow5=el.closest('.fw-edit-row');
    if(parentRow5&&parentRow5.parentNode){
      _fwShowUdrEditForm(rtId5, rIdx5, parentRow5.parentNode);
    }
    return;
  }
  if(action==='add-udr'){
    dpBody.querySelectorAll('[data-fw-form]').forEach(function(f){f.remove()});
    const rtId6=el.getAttribute('data-udr-id');
    const parent6=el.parentNode;
    if(parent6){
      _fwShowUdrEditForm(rtId6, null, parent6);
    }
    return;
  }
  if(action==='delete-udr'){
    const dRtId=el.getAttribute('data-udr-id');
    const dRtIdx=parseInt(el.getAttribute('data-rule-idx'),10);
    const dRt=(_rlCtx.udrs||[]).find(function(r){return (r.id||r.name)===dRtId});
    if(!dRt||!dRt.routes||dRtIdx>=dRt.routes.length) return;
    const dRoute=Object.assign({},dRt.routes[dRtIdx]);
    _fwTakeSnapshot();
    dRt.routes.splice(dRtIdx,1);
    const rg=_extractResourceGroup(dRt.id);
    _fwEdits.push({type:'udr',resourceId:dRtId,routeTableName:dRt.name||dRtId,resourceGroup:rg,direction:'',action:'delete',rule:dRoute,originalRule:dRoute});
    _fwRebuildLookups();
    if(sub && lk) openSubnetPanel(sub, vnetId, lk);
    if(typeof _fwDashRender==='function' && _udashTab==='firewall' && document.getElementById('udash') && document.getElementById('udash').classList.contains('open')) _fwDashRender();
    if(document.getElementById('fwFullPanel').classList.contains('open')) _fwRefreshFullPanel();
    return;
  }
  if(action==='save-udr'){
    const sRtId=el.getAttribute('data-udr-id');
    const sRtEdit=el.getAttribute('data-editing');
    const rtForm=el.closest('[data-fw-form]');
    if(!rtForm) return;
    const rtName=rtForm.querySelector('[data-field="name"]').value.trim();
    const rtDest=rtForm.querySelector('[data-field="dest"]').value.trim();
    const rtHopType=rtForm.querySelector('[data-field="nextHopType"]').value;
    const rtHopIp=rtForm.querySelector('[data-field="nextHopIp"]').value.trim();
    const routeObj={
      name:rtName,
      addressPrefix:rtDest,
      nextHopType:rtHopType
    };
    if(rtHopType==='VirtualAppliance'&&rtHopIp){
      routeObj.nextHopIpAddress=rtHopIp;
    }
    const sRt=(_rlCtx.udrs||[]).find(function(r){return (r.id||r.name)===sRtId});
    const editingRouteName=sRtEdit!==null&&sRtEdit!==undefined&&sRt?(sRt.routes||[])[parseInt(sRtEdit,10)]:'';
    const existingName=editingRouteName?editingRouteName.name:null;
    const otherRoutes=sRt?(sRt.routes||[]).filter(function(r,ri){
      if(sRtEdit!==null&&sRtEdit!==undefined&&ri===parseInt(sRtEdit,10)) return false;
      return true;
    }):[];
    const rtErrs=_fwValidateRoute(routeObj, otherRoutes, existingName);
    rtForm.querySelectorAll('.fw-input,.fw-select').forEach(function(inp){inp.classList.remove('invalid')});
    if(rtErrs.length){
      rtErrs.forEach(function(er){
        if(er.indexOf('name')>=0||er.indexOf('Name')>=0) rtForm.querySelector('[data-field="name"]').classList.add('invalid');
        if(er.indexOf('address prefix')>=0||er.indexOf('CIDR')>=0) rtForm.querySelector('[data-field="dest"]').classList.add('invalid');
        if(er.indexOf('hop type')>=0) rtForm.querySelector('[data-field="nextHopType"]').classList.add('invalid');
        if(er.indexOf('hop IP')>=0) rtForm.querySelector('[data-field="nextHopIp"]').classList.add('invalid');
      });
      return;
    }
    _fwTakeSnapshot();
    let rtEditAct='add';
    let rtOrig=null;
    if(sRtEdit!==null&&sRtEdit!==undefined&&sRt){
      const rtEIdx=parseInt(sRtEdit,10);
      if(sRt.routes&&rtEIdx<sRt.routes.length){
        rtOrig=Object.assign({},sRt.routes[rtEIdx]);
        sRt.routes.splice(rtEIdx,1);
        rtEditAct='modify';
      }
    }
    _fwApplyRule('udr', sRtId, '', routeObj);
    const rg=sRt?_extractResourceGroup(sRt.id):'';
    const rtEditObj={type:'udr',resourceId:sRtId,routeTableName:sRt?sRt.name:sRtId,resourceGroup:rg,direction:'',action:rtEditAct,rule:Object.assign({},routeObj)};
    if(rtOrig) rtEditObj.originalRule=rtOrig;
    _fwEdits.push(rtEditObj);
    _fwRebuildLookups();
    if(sub && lk) openSubnetPanel(sub, vnetId, lk);
    if(typeof _fwDashRender==='function' && _udashTab==='firewall' && document.getElementById('udash') && document.getElementById('udash').classList.contains('open')) _fwDashRender();
    if(document.getElementById('fwFullPanel').classList.contains('open')) _fwRefreshFullPanel();
    return;
  }
}

function _extractResourceGroup(armId){
  if(!armId||typeof armId!=='string') return '{resource-group}';
  const match=armId.match(/\/resourceGroups\/([^/]+)/i);
  return match?match[1]:'{resource-group}';
}

// === FIREWALL DASHBOARD ===
let _fwDashFilter='all';
let _fwDashState={search:'',vnetFilter:'all',sort:'type',sortDir:'asc',cardFilter:null};

function openFirewallDash(){
  _fwDashState={search:'',vnetFilter:'all',sort:'type',sortDir:'asc',cardFilter:null};
  _fwDashFilter='all';
  openUnifiedDash('firewall');
}

function _renderFirewallTab(){
  const tb=document.getElementById('udashToolbar');
  if(!_rlCtx){tb.textContent='No data loaded';return}
  const nsgs=_rlCtx.nsgs||[],udrs=_rlCtx.udrs||[];
  let vnetOpts='<option value="all">All VNets</option>';
  (_rlCtx.vnets||[]).forEach(function(v){
    vnetOpts+='<option value="'+esc(v.id)+'">'+esc(v.name||v.id)+'</option>';
  });
  const sortOpts=[{k:'type',l:'Sort: Type'},{k:'name',l:'Sort: Name'},{k:'severity',l:'Sort: Severity'},{k:'rules',l:'Sort: Rules'}];
  let sortHtml='';sortOpts.forEach(function(o){sortHtml+='<option value="'+o.k+'"'+(_fwDashState.sort===o.k?' selected':'')+'>'+o.l+'</option>'});
  tb.innerHTML='<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
    '<input id="fwDashSearch" type="text" placeholder="Search resources..." value="'+_escHtml(_fwDashState.search)+'" style="background:var(--bg-tertiary);border:1px solid var(--border);color:var(--text-primary);padding:4px 10px;border-radius:4px;font-size:11px;font-family:Segoe UI,system-ui,sans-serif;width:180px">'+
    '<select id="fwDashVnetFilter" style="background:var(--bg-tertiary);border:1px solid var(--border);color:var(--text-secondary);padding:4px 8px;border-radius:4px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif">'+vnetOpts+'</select>'+
    '<select id="fwDashSort" style="background:var(--bg-tertiary);border:1px solid var(--border);color:var(--text-secondary);padding:4px 8px;border-radius:4px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif">'+sortHtml+'</select>'+
    '<div id="fwDashPills" style="display:flex;gap:4px;margin-left:auto"></div>'+
    '</div>';
  document.getElementById('fwDashVnetFilter').value=_fwDashState.vnetFilter;
  const pills=document.getElementById('fwDashPills');
  [{t:'all',l:'All'},{t:'nsg',l:'NSG'},{t:'udr',l:'UDR'}].forEach(function(p){
    const el=document.createElement('span');el.className='fw-dash-pill'+(p.t===_fwDashFilter?' active':'');
    el.dataset.type=p.t;el.textContent=p.l;
    el.addEventListener('click',function(){
      _fwDashFilter=p.t;_fwDashState.cardFilter=null;
      pills.querySelectorAll('.fw-dash-pill').forEach(function(x){x.classList.remove('active')});el.classList.add('active');
      _fwDashRender();
    });
    pills.appendChild(el);
  });
  document.getElementById('fwDashSearch').addEventListener('input',function(){
    _fwDashState.search=this.value.toLowerCase();_fwDashRender();
  });
  document.getElementById('fwDashVnetFilter').addEventListener('change',function(){
    _fwDashState.vnetFilter=this.value;_fwDashRender();
  });
  document.getElementById('fwDashSort').addEventListener('change',function(){
    _fwDashState.sort=this.value;_fwDashRender();
  });
  _fwDashRender();
}

function _fwDashRender(){
  const body=document.getElementById('udashBody');if(body)body.scrollTop=0;
  if(!_rlCtx){if(body)body.textContent='No data loaded';return}
  const nsgs=_rlCtx.nsgs||[],udrs=_rlCtx.udrs||[];
  const compLookup=_buildComplianceLookup();
  const sevOrder={CRITICAL:1,HIGH:2,MEDIUM:3,LOW:4};

  const rows=[];
  nsgs.forEach(function(nsg){
    const nsgId=nsg.id||nsg.name;
    const name=nsg.name||nsgId;
    const rules=nsg.securityRules||[];
    const inCount=rules.filter(function(r){return (r.direction||'').toLowerCase()==='inbound'}).length;
    const outCount=rules.filter(function(r){return (r.direction||'').toLowerCase()==='outbound'}).length;
    const ec=_fwEditCount(nsgId);
    const cf=compLookup[nsgId]||null;
    let hasOpen=false;
    rules.forEach(function(r){
      if((r.direction||'').toLowerCase()!=='inbound') return;
      if((r.access||'').toLowerCase()!=='allow') return;
      if(r.sourceAddressPrefix==='*'||r.sourceAddressPrefix==='Internet'||r.sourceAddressPrefix==='0.0.0.0/0') hasOpen=true;
    });
    rows.push({type:'nsg',id:nsgId,name:name,vnet:nsg.vnetId||'',rules:inCount+outCount,rulesLabel:inCount+' in / '+outCount+' out',edits:ec,desc:'',obj:nsg,comp:cf,openIngress:hasOpen});
  });
  udrs.forEach(function(rt){
    const rtId=rt.id||rt.name;
    const name=rt.name||rtId;
    const rc=(rt.routes||[]).length;
    const ec=_fwEditCount(rtId);
    const cf=compLookup[rtId]||null;
    rows.push({type:'udr',id:rtId,name:name,vnet:rt.vnetId||'',rules:rc,rulesLabel:rc+' routes',edits:ec,desc:'',obj:rt,comp:cf,openIngress:false});
  });

  let totalFindings=0,worstSev='LOW',openIngress=0,totalEdits=_fwEdits?_fwEdits.length:0;
  rows.forEach(function(r){
    if(r.comp){totalFindings+=r.comp.count;if((sevOrder[r.comp.worst]||9)<(sevOrder[worstSev]||9))worstSev=r.comp.worst}
    if(r.openIngress)openIngress++;
  });

  const cf=_fwDashState.cardFilter;
  let h='<div class="fw-summary-cards">';
  h+='<div class="fw-summary-card'+(cf==='resources'?' active':'')+'">';
  h+='<div class="fw-card-count">'+(nsgs.length+udrs.length)+'</div>';
  h+='<div class="fw-card-label">Resources</div>';
  h+='<div class="fw-card-sub">'+nsgs.length+' NSG / '+udrs.length+' UDR</div></div>';
  const findCls=totalFindings?'severity-'+worstSev.toLowerCase():'clean';
  h+='<div class="fw-summary-card '+findCls+(cf==='findings'?' active':'')+'" data-card="findings">';
  h+='<div class="fw-card-count">'+totalFindings+'</div>';
  h+='<div class="fw-card-label">Findings</div>';
  h+='<div class="fw-card-sub">'+(totalFindings?worstSev+' worst':'All clear')+'</div></div>';
  const openCls=openIngress?'severity-critical':'clean';
  h+='<div class="fw-summary-card '+openCls+(cf==='open'?' active':'')+'" data-card="open">';
  h+='<div class="fw-card-count">'+openIngress+'</div>';
  h+='<div class="fw-card-label">Open */Internet Ingress</div>';
  h+='<div class="fw-card-sub">'+(openIngress?'Unrestricted ingress':'None detected')+'</div></div>';
  const editCls=totalEdits?'severity-medium':'clean';
  h+='<div class="fw-summary-card '+editCls+(cf==='edits'?' active':'')+'" data-card="edits">';
  h+='<div class="fw-card-count">'+totalEdits+'</div>';
  h+='<div class="fw-card-label">Pending Edits</div>';
  h+='<div class="fw-card-sub">'+(totalEdits?totalEdits+' rule'+(totalEdits>1?'s':'')+' modified':'No changes')+'</div></div>';
  h+='</div>';

  let filtered=rows.slice();
  if(cf==='findings') filtered=filtered.filter(function(r){return r.comp});
  if(cf==='open') filtered=filtered.filter(function(r){return r.openIngress});
  if(cf==='edits') filtered=filtered.filter(function(r){return r.edits>0});
  if(_fwDashFilter!=='all') filtered=filtered.filter(function(r){return r.type===_fwDashFilter});
  if(_fwDashState.vnetFilter!=='all') filtered=filtered.filter(function(r){return r.vnet===_fwDashState.vnetFilter});
  if(_fwDashState.search) filtered=filtered.filter(function(r){return (r.name+' '+r.id+' '+r.vnet+' '+r.desc).toLowerCase().indexOf(_fwDashState.search)!==-1});

  const sortBy=_fwDashState.sort;const dir=_fwDashState.sortDir==='asc'?1:-1;
  filtered.sort(function(a,b){
    if(sortBy==='type') return (a.type.localeCompare(b.type)||a.name.localeCompare(b.name))*dir;
    if(sortBy==='name') return a.name.localeCompare(b.name)*dir;
    if(sortBy==='rules') return (b.rules-a.rules)*dir;
    if(sortBy==='severity'){const sa=a.comp?(sevOrder[a.comp.worst]||9):99;const sb=b.comp?(sevOrder[b.comp.worst]||9):99;return (sa-sb)*dir}
    return 0;
  });

  if(!filtered.length){
    const emptyMsg=cf==='edits'?'No resources with pending edits':
      cf==='findings'?'No resources with compliance findings':
      cf==='open'?'No NSGs with open Internet ingress':
      _fwDashState.search?'No resources match "'+_escHtml(_fwDashState.search)+'"':
      'No firewall resources found';
    body.innerHTML=h+'<div style="padding:60px 20px;text-align:center;color:var(--text-muted);font-family:Segoe UI,system-ui,sans-serif;font-size:12px">'+emptyMsg+'</div>';
    _fwWireCards(body);_fwRenderFooter(filtered.length,rows.length);
    return;
  }

  const cols=[{k:'type',l:'Type'},{k:'name',l:'Name'},{k:'vnet',l:'VNet'},{k:'rules',l:'Rules'},{k:'severity',l:'Compliance'},{k:'edits',l:'Edits',nosort:true}];
  h+='<table class="fw-dash-table"><thead><tr>';
  cols.forEach(function(c){
    let cls='';if(!c.nosort&&_fwDashState.sort===c.k) cls=_fwDashState.sortDir==='asc'?' sort-asc':' sort-desc';
    h+='<th'+(c.nosort?'':' data-fw-sort="'+c.k+'"')+' class="'+cls+'">'+c.l+'</th>';
  });
  h+='</tr></thead><tbody>';

  filtered.forEach(function(r,idx){
    let trCls='';if(r.edits)trCls+=' has-edits';if(r.comp)trCls+=' has-findings';
    const sevColor=r.comp?({CRITICAL:'#dc2626',HIGH:'#f59e0b',MEDIUM:'#3b82f6',LOW:'#10b981'}[r.comp.worst]||'transparent'):'transparent';
    h+='<tr class="'+trCls+'" style="cursor:pointer;border-left-color:'+sevColor+'" data-fw-idx="'+idx+'">';
    h+='<td><span class="fw-type-badge '+r.type+'">'+(r.type==='nsg'?'NSG':'UDR')+'</span></td>';
    h+='<td><span class="fw-link" data-fw-action="open" data-fw-type="'+r.type+'" data-fw-id="'+esc(r.id)+'" data-fw-vnet="'+esc(r.vnet||'')+'">'+esc(r.name)+'</span>';
    if(r.desc) h+='<br><span style="font-size:9px;color:var(--text-muted)">'+esc(r.desc.substring(0,60))+'</span>';
    h+='</td>';
    const vnetObj=(_rlCtx.vnets||[]).find(function(v){return v.id===r.vnet});
    const vnetLabel=vnetObj?(vnetObj.name||r.vnet):(r.vnet||'--');
    h+='<td><span class="fw-link" data-fw-action="zoom-vnet" data-fw-vnet="'+esc(r.vnet||'')+'">'+esc(vnetLabel)+'</span></td>';
    h+='<td style="font-size:10px">'+r.rulesLabel+'</td>';
    if(r.comp){
      h+='<td><span class="sev-badge sev-'+r.comp.worst+'" style="font-size:8px;padding:1px 5px">'+r.comp.worst+'</span> <span style="font-size:9px;color:var(--text-muted)">'+r.comp.count+'</span></td>';
    } else {
      h+='<td><span style="color:var(--text-muted);font-size:9px">--</span></td>';
    }
    if(r.edits){
      h+='<td><span class="fw-edit-badge">'+r.edits+'</span></td>';
    } else {
      h+='<td></td>';
    }
    h+='</tr>';
  });
  h+='</tbody></table>';

  body.innerHTML=h;
  _fwWireCards(body);

  body.querySelectorAll('.fw-dash-table th[data-fw-sort]').forEach(function(th){
    th.addEventListener('click',function(){
      const col=this.dataset.fwSort;
      if(_fwDashState.sort===col){_fwDashState.sortDir=_fwDashState.sortDir==='asc'?'desc':'asc'}
      else{_fwDashState.sort=col;_fwDashState.sortDir='asc'}
      _fwDashRender();
    });
  });

  body.onclick=function(e){
    const link=e.target.closest('[data-fw-action]');
    if(!link)return;
    e.stopPropagation();
    const action=link.dataset.fwAction;
    if(action==='open'){
      _fwOpenFullEditor(link.dataset.fwType,link.dataset.fwId,null,link.dataset.fwVnet,null);
    } else if(action==='zoom-vnet'){
      const vid=link.dataset.fwVnet;if(!vid)return;
      closeUnifiedDash();
      setTimeout(function(){_zoomToElement(vid)},250);
    }
  };

  body.querySelectorAll('.fw-dash-table tbody tr[data-fw-idx]').forEach(function(tr){
    tr.addEventListener('click',function(e){
      if(e.target.closest('[data-fw-action]'))return;
      const idx=parseInt(this.dataset.fwIdx);
      const r=filtered[idx];if(!r)return;
      _fwOpenFullEditor(r.type,r.id,null,r.vnet,null);
    });
  });

  _fwRenderFooter(filtered.length,rows.length);
}

function _fwWireCards(container){
  container.querySelectorAll('.fw-summary-card').forEach(function(card){
    card.addEventListener('click',function(){
      const f=this.dataset.card;
      _fwDashState.cardFilter=(_fwDashState.cardFilter===f)?null:f;
      _fwDashRender();
    });
  });
}

function _fwRenderFooter(shown,total){
  const totalEdits=_fwEdits?_fwEdits.length:0;
  const footer=document.getElementById('udashFooter');
  footer.innerHTML='<div style="display:flex;align-items:center;justify-content:space-between;width:100%">'+
    '<span style="font-size:10px;color:var(--text-muted)">'+(totalEdits?totalEdits+' edit'+(totalEdits>1?'s':'')+' pending':'No pending edits')+
    ' | '+shown+' of '+total+' resources</span>'+
    '<div style="display:flex;gap:6px">'+
      '<button id="fwDashExportAll" style="background:rgba(34,211,238,.1);border:1px solid var(--accent-cyan);color:var(--accent-cyan);padding:4px 10px;border-radius:4px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">Export All CLI</button>'+
      '<button id="fwDashResetAll" style="background:rgba(239,68,68,.1);border:1px solid var(--accent-red);color:var(--accent-red);padding:4px 10px;border-radius:4px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">Reset All</button>'+
    '</div></div>';
  document.getElementById('fwDashExportAll').addEventListener('click',function(){
    if(!_fwEdits||!_fwEdits.length){alert('No edits to export');return}
    const cmds=_fwGenerateCli(_fwEdits);
    if(cmds.length&&navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(cmds.join('\n')).then(function(){
        let btn=document.getElementById('fwDashExportAll');if(!btn)return;btn.textContent='Copied!';setTimeout(function(){if(btn.parentNode)btn.textContent='Export All CLI'},1500);
      }).catch(function(){const btn=document.getElementById('fwDashExportAll');if(!btn)return;btn.textContent='Copy failed';setTimeout(function(){if(btn.parentNode)btn.textContent='Export All CLI'},1500)});
    }
  });
  document.getElementById('fwDashResetAll').addEventListener('click',function(){
    if(!_fwEdits||!_fwEdits.length){alert('No edits to reset');return}
    if(!confirm('Reset all '+_fwEdits.length+' firewall edits?'))return;
    _fwResetAll();_fwDashRender();
  });
}

document.getElementById('firewallBtn').addEventListener('click',openFirewallDash);
