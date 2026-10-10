// Governance IAM review preparation, effective permissions, and principal detail panels.
// Loaded after governance-inventory-runtime.js so it can reuse governance adapters.

let _iamDashState={filter:'all',search:'',sort:'name',sortDir:'asc',page:1,perPage:50};
let _iamReviewData=[];

// === GOVERNANCE: IAM REVIEW PREPARATION ===
function prepareIAMReviewData(iamData){
  if(!iamData) return[];
  var items=[];
  if(iamData.provider==='azure'){
    _iamReviewData=(iamData.principals||[]).map(function(p){
      return {name:p.name,arn:p.id,type:p.principalType,created:null,lastUsed:null,
        isAdmin:p.isAdmin,hasWildcard:p.hasWildcard,crossAccounts:[],policies:1,
        policyNames:[p.roleName+' @ '+p.scope],permBoundary:'',
        findings:(iamData.findings||[]).filter(function(f){return f.assignmentId?f.assignmentId===p.id:(f.resource===p.principalId||f.resource===p.id)}),
        _subscriptionId:p.subscriptionId,provider:'azure',scope:p.scope,roleName:p.roleName,
        hasMFA:null,hasConsole:null,activeKeys:null,_raw:p.assignment};
    });
    return _iamReviewData;
  }
  // Process roles
  (iamData.roles||[]).forEach(function(role){
    var created=role.CreateDate?new Date(role.CreateDate):null;
    var lastUsed=role.RoleLastUsed&&role.RoleLastUsed.LastUsedDate?new Date(role.RoleLastUsed.LastUsedDate):null;
    var trustDoc=role.AssumeRolePolicyDocument;
    var trustParsed={};
    if(typeof trustDoc==='string'){try{trustParsed=JSON.parse(trustDoc)}catch(e){}}
    else if(trustDoc) trustParsed=trustDoc;
    var crossAccts=[];
    _stmtArr(trustParsed.Statement).forEach(function(stmt){
      if(stmt.Effect==='Allow'&&stmt.Principal){
        var aws=stmt.Principal.AWS;
        if(aws){(Array.isArray(aws)?aws:[aws]).forEach(function(arn){var m=String(arn).match(/:(\d{12}):/);if(m)crossAccts.push(m[1])})}
      }
    });
    var findings=(governanceFindings()||[]).filter(function(f){return f.framework==='IAM'&&(f.resource===role.RoleName||f.resource===(role.Arn||''))});
    var policyCount=(role.RolePolicyList||[]).length+(role.AttachedManagedPolicies||[]).length;
    var policyNames=(role.AttachedManagedPolicies||[]).map(function(p){return p.PolicyName||p.PolicyArn||''});
    var roleAcct=(role.Arn||'').match(/:(\d{12}):/);
    items.push({name:role.RoleName||'',arn:role.Arn||'',type:'Role',created:created,lastUsed:lastUsed,isAdmin:role._isAdmin||false,hasWildcard:role._hasWildcard||false,crossAccounts:crossAccts,policies:policyCount,policyNames:policyNames,permBoundary:role.PermissionsBoundary?role.PermissionsBoundary.PermissionsBoundaryArn:'',findings:findings,_subscriptionId:roleAcct?roleAcct[1]:'',_raw:role});
  });
  // Process users
  (iamData.users||[]).forEach(function(user){
    var created=user.CreateDate?new Date(user.CreateDate):null;
    var lastUsed=user.PasswordLastUsed?new Date(user.PasswordLastUsed):null;
    var hasMFA=(user.MFADevices||[]).length>0;
    var hasConsole=!!user.LoginProfile;
    var activeKeys=(user.AccessKeys||[]).filter(function(k){return k.Status==='Active'}).length;
    var findings=(governanceFindings()||[]).filter(function(f){return f.framework==='IAM'&&(f.resource===user.UserName||f.resource===(user.Arn||''))});
    var policyCount=(user.UserPolicyList||[]).length+(user.AttachedManagedPolicies||[]).length;
    var policyNames=(user.AttachedManagedPolicies||[]).map(function(p){return p.PolicyName||p.PolicyArn||''});
    // Detect admin for users by analyzing actual policy documents (not just name heuristic)
    var uIsAdmin=false;
    // Check inline policies
    (user.UserPolicyList||[]).forEach(function(p){if(uIsAdmin)return;var doc=_safePolicyParse(p.PolicyDocument);_stmtArr(doc.Statement).forEach(function(s){if(s.Effect==='Allow'){var a=Array.isArray(s.Action)?s.Action:[s.Action||''];var r=Array.isArray(s.Resource)?s.Resource:[s.Resource||''];if(a.some(function(x){return x==='*'})&&r.some(function(x){return x==='*'}))uIsAdmin=true}})});
    // Check managed policies
    (user.AttachedManagedPolicies||[]).forEach(function(mp){if(uIsAdmin)return;var pol=(iamData.policies||[]).find(function(p){return p.Arn===mp.PolicyArn||p.PolicyName===mp.PolicyName});if(pol){var ver=(pol.PolicyVersionList||[]).find(function(v){return v.IsDefaultVersion});if(ver){_stmtArr((_safePolicyParse(ver.Document)).Statement).forEach(function(s){if(s.Effect==='Allow'){var a=Array.isArray(s.Action)?s.Action:[s.Action||''];var r=Array.isArray(s.Resource)?s.Resource:[s.Resource||''];if(a.some(function(x){return x==='*'})&&r.some(function(x){return x==='*'}))uIsAdmin=true}})}}});
    var userAcct=(user.Arn||'').match(/:(\d{12}):/);
    items.push({name:user.UserName||'',arn:user.Arn||'',type:'User',created:created,lastUsed:lastUsed,isAdmin:uIsAdmin,hasWildcard:false,crossAccounts:[],policies:policyCount,policyNames:policyNames,permBoundary:user.PermissionsBoundary?user.PermissionsBoundary.PermissionsBoundaryArn:'',findings:findings,_subscriptionId:userAcct?userAcct[1]:'',hasMFA:hasMFA,hasConsole:hasConsole,activeKeys:activeKeys,_raw:user});
  });
  _iamReviewData=items;
  return items;
}

function renderIAMPanel(vpcId){
  if(!_iamData){
    const raw=safeParse(gv('in_rbac'));
    if(!raw){governanceNotify('No IAM data loaded. Paste IAM auth details in the IAM section first.');return}
    _iamData=parseIAMData(raw);
  }
  const roles=getIAMAccessForVpc(_iamData,vpcId);
  const dp=document.getElementById('detailPanel');const dpTitle=document.getElementById('dpTitle');const dpSub=document.getElementById('dpSub');const dpBody=document.getElementById('dpBody');
  dpTitle.textContent='IAM Access';dpSub.textContent='VNet: '+vpcId;
  let h='<div style="font-family:Segoe UI,system-ui,sans-serif;font-size:calc(9px * var(--txt-scale,1) * var(--dp-txt-scale,1))">';
  if(!roles.length){h+='<div style="color:var(--text-muted);padding:12px">No roles with direct VNet access found</div>'}
  else{
    h+='<div style="color:var(--text-muted);margin-bottom:8px">'+roles.length+' role(s) with access:</div>';
    roles.forEach(r=>{
      const badges=[];
      if(r._isAdmin)badges.push('<span class="sev-badge sev-CRITICAL">ADMIN</span>');
      if(r._hasWildcard)badges.push('<span class="sev-badge sev-HIGH">WILDCARD</span>');
      h+='<div style="padding:4px 0;border-bottom:1px solid var(--border)">'+badges.join(' ')+' <span style="color:var(--accent-cyan)">'+r.RoleName+'</span></div>';
    });
  }
  h+='</div>';
  dpBody.innerHTML=h;dp.classList.add('open');
}

// === EFFECTIVE PERMISSIONS ENGINE ===
function matchAction(pattern,action){
  if(!pattern||!action)return false;
  if(pattern==='*')return true;
  const re=new RegExp('^'+pattern.replace(/[.+^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*')+'$','i');
  return re.test(action);
}

function matchResource(pattern,arn){
  if(!pattern||!arn)return false;
  if(pattern==='*')return true;
  const pParts=pattern.split(':');const aParts=arn.split(':');
  if(pParts.length!==aParts.length&&pParts.length<6)return false;
  const reStr=pParts.map((p,i)=>{
    if(p==='*'&&i===pParts.length-1)return '.*';
    if(p==='*')return '[^:]*';
    return p.replace(/[.+^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*');
  }).join(':');
  return new RegExp('^'+reStr+'$','i').test(arn);
}

function evaluateCondition(condBlock,context){
  if(!condBlock||Object.keys(condBlock).length===0)return true;
  for(const[op,keys]of Object.entries(condBlock)){
    for(const[ck,cv]of Object.entries(keys)){
      if(op==='Bool'&&ck==='aws:MultiFactorAuthPresent'){
        if(context&&context.mfa!==undefined)return String(context.mfa)===String(cv);
      }
      if(op==='StringEquals'||op==='StringLike'){
        if(context&&context[ck]){const vals=Array.isArray(cv)?cv:[cv];if(!vals.some(v=>v===context[ck]))return false}
      }
    }
  }
  return true;
}

function _collectStatements(principal,iamData){
  const stmts=[];
  const policyLists=principal.RolePolicyList||principal.UserPolicyList||[];
  policyLists.forEach(p=>{
    let doc=p.PolicyDocument;
    if(typeof doc==='string'){try{doc=JSON.parse(decodeURIComponent(doc))}catch(e){try{doc=JSON.parse(doc)}catch(e2){doc={}}}}
    if(!doc)doc={};
    _stmtArr(doc.Statement).forEach(st=>stmts.push(st));
  });
  (principal.AttachedManagedPolicies||[]).forEach(mp=>{
    const pol=(iamData.policies||[]).find(p=>p.Arn===mp.PolicyArn||p.PolicyName===mp.PolicyName);
    if(pol){
      const ver=(pol.PolicyVersionList||[]).find(v=>v.IsDefaultVersion);
      if(ver){
        let dd=ver.Document;
        if(typeof dd==='string'){try{dd=JSON.parse(decodeURIComponent(dd))}catch(e){try{dd=JSON.parse(dd)}catch(e2){dd={}}}}
        if(dd){_stmtArr(dd.Statement).forEach(st=>stmts.push(st))}
      }
    }
  });
  return stmts;
}

function canDo(principal,action,resource,iamData){
  const stmts=_collectStatements(principal,iamData);
  for(const s of stmts){
    if(s.Effect!=='Deny')continue;
    const acts=Array.isArray(s.Action)?s.Action:[s.Action||''];
    const res=Array.isArray(s.Resource)?s.Resource:[s.Resource||''];
    if(acts.some(a=>matchAction(a,action))&&res.some(r=>matchResource(r,resource))){
      if(evaluateCondition(s.Condition))return{effect:'DENY',reason:'Explicit deny in policy',statements:[s]};
    }
  }
  if(principal.PermissionsBoundary){
    const bArn=principal.PermissionsBoundary.PermissionsBoundaryArn||principal.PermissionsBoundary;
    const bPol=(iamData.policies||[]).find(p=>p.Arn===bArn);
    if(bPol){
      const ver=(bPol.PolicyVersionList||[]).find(v=>v.IsDefaultVersion);
      if(ver){
        const dd=_safePolicyParse(ver.Document);
        const bStmts=_stmtArr(dd.Statement);
        const allowed=bStmts.some(s=>{
          if(s.Effect!=='Allow')return false;
          const ba=Array.isArray(s.Action)?s.Action:[s.Action||''];
          const br=Array.isArray(s.Resource)?s.Resource:[s.Resource||''];
          return ba.some(a=>matchAction(a,action))&&br.some(r=>matchResource(r,resource));
        });
        if(!allowed)return{effect:'IMPLICIT_DENY',reason:'Not allowed by permission boundary',statements:[]};
      }
    }
  }
  const matchedStmts=[];
  for(const s of stmts){
    if(s.Effect!=='Allow')continue;
    const acts=Array.isArray(s.Action)?s.Action:[s.Action||''];
    const res=Array.isArray(s.Resource)?s.Resource:[s.Resource||''];
    if(acts.some(a=>matchAction(a,action))&&res.some(r=>matchResource(r,resource))){
      if(evaluateCondition(s.Condition))matchedStmts.push(s);
    }
  }
  if(matchedStmts.length)return{effect:'ALLOW',reason:'Allowed by policy',statements:matchedStmts};
  return{effect:'IMPLICIT_DENY',reason:'No matching allow statement',statements:[]};
}

function summarizePermissions(principal,iamData){
  const stmts=_collectStatements(principal,iamData);
  const services={};let isAdmin=false;let hasWildcard=false;
  const boundaryArn=principal.PermissionsBoundary?.PermissionsBoundaryArn||null;
  stmts.forEach(s=>{
    const acts=Array.isArray(s.Action)?s.Action:[s.Action||''];
    const res=Array.isArray(s.Resource)?s.Resource:[s.Resource||''];
    if(s.NotAction){const na=Array.isArray(s.NotAction)?s.NotAction:[s.NotAction];na.forEach(a=>{const svc=a.includes(':')?a.split(':')[0]:'ALL';if(!services[svc])services[svc]={allowed:[],denied:[],resources:{}};services[svc].notActions=(services[svc].notActions||[]).concat(a)});return}
    acts.forEach(a=>{
      if(a==='*'||a==='*:*'){isAdmin=true;return}
      const svc=a.includes(':')?a.split(':')[0]:'ALL';
      if(!services[svc])services[svc]={allowed:[],denied:[],resources:{}};
      const actionName=a.includes(':')?a.split(':')[1]:a;
      if(s.Effect==='Allow'){
        if(!services[svc].allowed.includes(actionName))services[svc].allowed.push(actionName);
        res.forEach(r=>{services[svc].resources[actionName]=r});
      }else if(s.Effect==='Deny'){
        if(!services[svc].denied.includes(actionName))services[svc].denied.push(actionName);
      }
    });
    if(res.some(r=>r==='*'))hasWildcard=true;
  });
  if(boundaryArn){
    const bPol=(iamData.policies||[]).find(p=>p.Arn===boundaryArn);
    if(bPol){
      const ver=(bPol.PolicyVersionList||[]).find(v=>v.IsDefaultVersion);
      if(ver){
        const dd=_safePolicyParse(ver.Document);
        const bStmts=_stmtArr(dd.Statement);
        const bAllowed=new Set();
        bStmts.forEach(s=>{
          if(s.Effect!=='Allow')return;
          const ba=Array.isArray(s.Action)?s.Action:[s.Action||''];
          ba.forEach(a=>bAllowed.add(a));
        });
        if(!bAllowed.has('*')){
          Object.keys(services).forEach(svc=>{
            services[svc].allowed=services[svc].allowed.filter(a=>{
              const full=svc+':'+a;
              return Array.from(bAllowed).some(b=>matchAction(b,full));
            });
          });
        }
      }
    }
  }
  return{services,isAdmin,hasWildcard,permissionBoundary:boundaryArn};
}

// === IAM PRINCIPAL DETAIL PANEL ===
function openIAMPrincipalPanel(principal,iamData,ctx){
  const dp=document.getElementById('detailPanel');
  const dpTitle=document.getElementById('dpTitle');
  const dpSub=document.getElementById('dpSub');
  const dpBody=document.getElementById('dpBody');
  const isRole=!!principal.RoleName;
  const name=principal.RoleName||principal.UserName||'Unknown';
  const arn=principal.Arn||'';
  if(_lastRlType){const savedType=_lastRlType;_navStack.push({fn:()=>openResourceList(savedType,false)})}
  const backBtn=_navStack.length>0?'<span id="dpBack" style="cursor:pointer;color:var(--accent-blue);font-size:calc(10px * var(--txt-scale) * var(--dp-txt-scale));font-family:Segoe UI,system-ui,sans-serif;margin-right:8px" title="Back">&lt; Back</span>':'';
  const badges=[];
  if(principal._isAdmin)badges.push('<span class="sev-badge sev-CRITICAL">ADMIN</span>');
  if(principal._hasWildcard&&!principal._isAdmin)badges.push('<span class="sev-badge sev-HIGH">WILDCARD</span>');
  if(principal.PermissionsBoundary)badges.push('<span class="sev-badge sev-LOW" style="background:rgba(16,185,129,.15);color:#10b981;border-color:rgba(16,185,129,.3)">BOUNDARY</span>');
  if(!isRole&&!(principal.MFADevices||[]).length)badges.push('<span class="sev-badge sev-HIGH">NO MFA</span>');
  dpTitle.innerHTML=backBtn+esc(name)+' '+badges.join(' ');
  dpSub.innerHTML='<span class="copyable" data-copy="'+esc(arn)+'">'+esc(arn)+'</span>';
  let h='<div style="font-family:Segoe UI,system-ui,sans-serif;font-size:calc(9px * var(--txt-scale,1) * var(--dp-txt-scale,1))">';
  function sec(title,count,bodyHtml,startOpen){
    return '<div class="dp-section"><div class="dp-sec-hdr'+(startOpen?'':' collapsed')+'" onclick="this.classList.toggle(\'collapsed\');this.nextElementSibling.classList.toggle(\'hidden\')"><span class="dp-sec-title">'+title+'</span><span><span class="dp-sec-count">'+count+'</span><span class="dp-sec-arr">&#9660;</span></span></div><div class="dp-sec-body'+(startOpen?'':' hidden')+'">'+bodyHtml+'</div></div>';
  }
  // Trust Policy (roles only)
  if(isRole&&principal.AssumeRolePolicyDocument){
    const trust=_safePolicyParse(principal.AssumeRolePolicyDocument);
    const stmts=_stmtArr(trust.Statement);
    let tb='<div class="fw-legend"><span><span class="fw-dot" style="background:var(--accent-green)"></span>Allow</span><span><span class="fw-dot" style="background:var(--accent-red)"></span>Deny</span></div>';
    stmts.forEach(s=>{
      const isAllow=s.Effect==='Allow';
      const pr=s.Principal||{};
      let src='';
      if(pr.Service)src=Array.isArray(pr.Service)?pr.Service.join(', '):pr.Service;
      else if(pr.AWS)src=Array.isArray(pr.AWS)?pr.AWS.join(', '):pr.AWS;
      else if(pr.Federated)src=Array.isArray(pr.Federated)?pr.Federated.join(', '):pr.Federated;
      else if(pr==='*')src='* (anyone)';
      const condStr=s.Condition?'<br><span style="color:var(--text-muted);font-size:7px">Cond: '+esc(JSON.stringify(s.Condition).substring(0,80))+'</span>':'';
      tb+='<div class="fw-rule-bar"><span class="fw-arrow" style="color:'+(isAllow?'var(--accent-green)':'var(--accent-red)')+'">&#9654;</span><span class="fw-proto">TRUST</span><span class="fw-port '+(isAllow?'allow':'deny')+'">AssumeRole</span><span class="fw-src">'+esc(src)+condStr+'</span></div>';
    });
    h+=sec('Trust Policy',stmts.length+' statement(s)',tb,true);
  }
  // Effective Permissions
  const perms=summarizePermissions(principal,iamData);
  let pb='';
  if(perms.isAdmin){
    pb+='<div style="padding:8px;background:rgba(220,38,38,.1);border:1px solid rgba(220,38,38,.3);border-radius:4px;color:#dc2626;font-weight:700;margin-bottom:6px">FULL ADMIN ACCESS (*:*)</div>';
  }else{
    const svcKeys=Object.keys(perms.services).sort();
    if(!svcKeys.length)pb+='<div style="color:var(--text-muted)">No direct permissions found</div>';
    svcKeys.forEach(svc=>{
      const sd=perms.services[svc];
      pb+='<div style="font-weight:600;color:var(--accent-cyan);margin:6px 0 2px;text-transform:uppercase;font-size:8px;letter-spacing:.5px">'+esc(svc)+' ('+sd.allowed.length+' allowed'+(sd.denied.length?', '+sd.denied.length+' denied':'')+')</div>';
      sd.allowed.forEach(a=>{
        const res=sd.resources[a]||'*';
        pb+='<div class="fw-rule-bar"><span class="fw-arrow" style="color:var(--accent-green)">&#9654;</span><span class="fw-proto">'+esc(svc)+'</span><span class="fw-port allow">'+esc(a)+'</span><span class="fw-src">'+esc(res)+'</span></div>';
      });
      sd.denied.forEach(a=>{
        pb+='<div class="fw-rule-bar"><span class="fw-arrow" style="color:var(--accent-red)">&#9654;</span><span class="fw-proto">'+esc(svc)+'</span><span class="fw-port deny">'+esc(a)+'</span><span class="fw-src">Denied</span></div>';
      });
    });
  }
  pb+='<div style="color:var(--text-muted);font-size:7px;margin-top:6px;padding-top:4px;border-top:1px solid var(--border)">Simplified view. Actual permissions depend on SCPs, session policies, and resource-based policies.</div>';
  const permCount=perms.isAdmin?'ADMIN':Object.values(perms.services).reduce((n,s)=>n+s.allowed.length,0)+' actions';
  h+=sec('Effective Permissions',permCount,pb,true);
  // Permission Boundary
  if(principal.PermissionsBoundary){
    const bArn=principal.PermissionsBoundary.PermissionsBoundaryArn||principal.PermissionsBoundary;
    const bb='<div class="dp-kv"><span class="k">Boundary ARN</span><span class="v copyable" data-copy="'+esc(bArn)+'">'+esc(bArn)+'</span></div>';
    h+=sec('Permission Boundary','1',bb,true);
  }
  // Attached Resources
  if(ctx&&ctx.iamRoleResources){
    const res=ctx.iamRoleResources[name];
    if(res){
      let rb='';let resCount=0;
      if(res.vms&&res.vms.length){
        rb+='<div style="font-weight:600;color:var(--accent-cyan);margin:4px 0 2px;font-size:8px;letter-spacing:.5px">VIRTUAL MACHINES ('+res.vms.length+')</div>';
        res.vms.forEach(i=>{const iName=(i.Tags||[]).find(t=>t.Key==='Name')?.Value||i.InstanceId;rb+='<div class="dp-row" style="border-left:3px solid #3b82f6;padding-left:8px;margin:3px 0">'+esc(iName)+' <span class="k">'+esc(i.InstanceType)+'</span></div>'});
        resCount+=res.vms.length;
      }
      if(res.functionApps&&res.functionApps.length){
        rb+='<div style="font-weight:600;color:var(--accent-cyan);margin:4px 0 2px;font-size:8px;letter-spacing:.5px">FUNCTION APPS ('+res.functionApps.length+')</div>';
        res.functionApps.forEach(fn=>{rb+='<div class="dp-row" style="border-left:3px solid #a855f7;padding-left:8px;margin:3px 0">'+esc(fn.FunctionName)+' <span class="k">'+esc(fn.Runtime)+'</span></div>'});
        resCount+=res.functionApps.length;
      }
      if(res.aks&&res.aks.length){
        rb+='<div style="font-weight:600;color:var(--accent-cyan);margin:4px 0 2px;font-size:8px;letter-spacing:.5px">CONTAINER INSTANCES ('+res.aks.length+')</div>';
        res.aks.forEach(svc=>{rb+='<div class="dp-row" style="border-left:3px solid #f97316;padding-left:8px;margin:3px 0">'+esc(svc.serviceName)+' <span class="k">'+esc(svc.launchType||'')+'</span></div>'});
        resCount+=res.aks.length;
      }
      if(resCount>0)h+=sec('Attached Resources',resCount+' resource(s)',rb,true);
    }
  }
  // Compliance Findings
  if(governanceFindings()&&governanceFindings().length){
    const myFindings=governanceFindings().filter(f=>f.resource===name||f.resourceName===name);
    if(myFindings.length){
      let cb='';
      myFindings.forEach(f=>{cb+='<div class="dp-row" style="border-left:3px solid '+(f.severity==='CRITICAL'?'#dc2626':f.severity==='HIGH'?'#f97316':f.severity==='MEDIUM'?'#f59e0b':'#3b82f6')+';padding-left:8px;margin:3px 0"><span class="sev-badge sev-'+f.severity+'">'+f.severity+'</span> <span class="k">'+esc(f.control)+'</span> '+esc(f.message)+'</div>'});
      h+=sec('Compliance Findings',myFindings.length+' finding(s)',cb,true);
    }
  }
  // Metadata
  let mb='';
  if(principal.CreateDate)mb+='<div class="dp-kv"><span class="k">Created</span><span class="v">'+new Date(principal.CreateDate).toLocaleDateString()+'</span></div>';
  if(principal.RoleLastUsed?.LastUsedDate)mb+='<div class="dp-kv"><span class="k">Last Used</span><span class="v">'+new Date(principal.RoleLastUsed.LastUsedDate).toLocaleDateString()+'</span></div>';
  if(isRole){
    mb+='<div class="dp-kv"><span class="k">Policies</span><span class="v">'+(principal.RolePolicyList||[]).length+' inline, '+(principal.AttachedManagedPolicies||[]).length+' managed</span></div>';
  }else{
    mb+='<div class="dp-kv"><span class="k">Policies</span><span class="v">'+(principal.UserPolicyList||[]).length+' inline, '+(principal.AttachedManagedPolicies||[]).length+' managed</span></div>';
    mb+='<div class="dp-kv"><span class="k">MFA</span><span class="v">'+((principal.MFADevices||[]).length?'Enabled':'Not configured')+'</span></div>';
  }
  if(mb)h+=sec('Metadata','',mb,false);
  h+='</div>';
  dpBody.innerHTML=h;dp.classList.add('open');
  applyDpScale();
  const backEl=document.getElementById('dpBack');
  if(backEl){backEl.addEventListener('click',(e)=>{e.stopPropagation();const prev=_navStack.pop();if(prev&&prev.fn)prev.fn();else dp.classList.remove('open')})}
  dpBody.querySelectorAll('.copyable').forEach(el=>{el.addEventListener('click',function(e){e.stopPropagation();navigator.clipboard.writeText(this.dataset.copy);const t=document.getElementById('copyToast');if(t){t.textContent='Copied!';t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1200)}})});
}

var GovernanceIAMReview={
  prepare:prepareIAMReviewData,
  renderVpcAccessPanel:renderIAMPanel,
  canDo:canDo,
  summarizePermissions:summarizePermissions,
  openPrincipalPanel:openIAMPrincipalPanel
};
