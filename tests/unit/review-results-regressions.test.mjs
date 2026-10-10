import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import { parseRBACData } from '../../src/modules/iam-engine.js';
import { runComplianceChecks, invalidateComplianceCache } from '../../src/modules/compliance-engine.js';
import { runSOC2Checks } from '../../src/modules/compliance-soc2-checks.js';
import { runPCIChecks } from '../../src/modules/compliance-pci-checks.js';
import { runBUDRAzureChecks } from '../../src/modules/compliance-budr-azure-checks.js';
import { getCloudEnv } from '../../src/modules/cloud-env.js';

const require=createRequire(import.meta.url);
const inventory=require('../../src/modules/governance-inventory-model.js');
const source=name=>readFileSync(`src/modules/${name}.js`,'utf8');
function runtime(files, globals={}){
  const context=vm.createContext({console,Date,Set,Map,...globals});
  for(const file of files)vm.runInContext(source(file),context,{filename:file});
  return context;
}
const owner={id:'/subscriptions/sub-b/providers/Microsoft.Authorization/roleAssignments/a',
  principalId:'principal-a',principalName:'Owner principal',principalType:'User',scope:'/subscriptions/sub-b',
  roleDefinitionId:'/subscriptions/sub-b/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'};

describe('review results regressions',()=>{
  it('preserves native CLI role assignments through IAM review and compliance',()=>{
    const ctx=runtime(['iam-overlay-runtime','governance-iam-review'],{parseRBACData});
    ctx.raw=[owner];
    const parsed=vm.runInContext('parseIAMData(raw)',ctx);
    assert.equal(parsed.roleAssignments.length,1);
    assert.equal(parsed.findings.some(f=>f.control==='RBAC-1'),true);
    const rows=ctx.prepareIAMReviewData(parsed);
    assert.equal(rows.length,1);
    assert.equal(rows[0].name,'Owner principal');
    assert.equal(rows[0].roleName,'Owner');
    assert.equal(rows[0]._subscriptionId,'sub-b');
    assert.equal(rows[0].hasMFA,null);
    invalidateComplianceCache();
    const findings=runComplianceChecks({rbac:parsed});
    assert.equal(findings.some(f=>f.control==='RBAC-1'&&f._subscriptionId==='sub-b'),true);
  });

  it('joins inventory findings by ARM identity instead of duplicate friendly names',()=>{
    const ids=['/subscriptions/a/providers/Microsoft.Network/virtualNetworks/shared','/subscriptions/b/providers/Microsoft.Network/virtualNetworks/shared'];
    const rows=inventory.buildInventoryData({vnets:ids.map(id=>({id,VpcId:id,Tags:{Name:'shared'}}))},{
      complianceFindings:[{resource:'shared',resourceId:ids[1].toUpperCase(),severity:'HIGH'}]
    });
    assert.equal(rows[0].complianceFail,0);
    assert.equal(rows[1].complianceFail,1);
  });

  it('keeps individual RBAC finding scopes for the same principal across subscriptions',()=>{
    const second={...owner,id:owner.id.replace('sub-b','sub-c'),scope:'/subscriptions/sub-c'};
    const parsed=parseRBACData([owner,second]);
    const owners=parsed.findings.filter(f=>f.control==='RBAC-1');
    assert.deepEqual(owners.map(f=>f._subscriptionId),['sub-b','sub-c']);
    assert.deepEqual(owners.map(f=>f.resourceId),[owner.id,second.id]);
    const ctx=runtime(['iam-overlay-runtime','governance-iam-review'],{parseRBACData});
    ctx.raw=[owner,second];
    const rows=ctx.prepareIAMReviewData(vm.runInContext('parseIAMData(raw)',ctx));
    assert.equal(rows[0].findings.length,1);
    assert.equal(rows[1].findings.length,1);
  });

  it('recomputes equal-length input edits and leaves unknown ownership unknown',()=>{
    const input={id:'in_sa',value:'TLS1_0'};
    let calls=0;
    const published={};
    const shell=source('app-shell');
    const tail=shell.slice(shell.indexOf('// Content-based compliance cache'));
    const ctx=vm.createContext({document:{querySelectorAll:()=>[input]},AppModules:{getCloudEnv},GovernanceClassification:{reset(){}},
      _compDashState:{_cachedView:{stale:true}},_inventoryData:[{stale:true}],
      _budrFindings:[],_budrAssessments:[],appShellSetComplianceFindings:f=>{published.findings=f},
      safeParse:()=>null,gv:()=>'',parseRBACData,invalidateComplianceCache(){},
      runComplianceChecks:()=>{calls++;return [{resource:'shared',resourceId:'/subscriptions/b/providers/x/shared'},{resource:'Subscription'}]}});
    vm.runInContext(tail,ctx);
    const data={vnets:[{id:'/subscriptions/a/providers/x/shared',_subscriptionId:'a'},{id:'/subscriptions/b/providers/x/shared',_subscriptionId:'b'}]};
    ctx._runComplianceWithCache(data);
    assert.equal(vm.runInContext('_compDashState._cachedView',ctx),null);
    assert.equal(vm.runInContext('_inventoryData.length',ctx),0);
    assert.equal(published.findings[0]._subscriptionId,'b');
    assert.equal(published.findings[1]._subscriptionId,undefined);
    ctx._runComplianceWithCache(data);
    assert.equal(calls,1);
    input.value='TLS1_2';
    ctx._runComplianceWithCache(data);
    assert.equal(calls,2);
  });

  it('assesses renderer storage collections and joins native inventory ARM IDs',()=>{
    const id='/subscriptions/review/resourceGroups/review/providers/Microsoft.Storage/storageAccounts/reviewstore';
    const storage={id,name:'reviewstore',Name:'reviewstore',minimumTlsVersion:'TLS1_0'};
    const input={id:'in_storage',value:JSON.stringify([storage])};
    const data={s3bk:[storage],volumes:[]};
    const ctx=vm.createContext({document:{querySelectorAll:()=>[input]},AppModules:{getCloudEnv},GovernanceClassification:{reset(){}},
      _budrFindings:[],_budrAssessments:[],appShellSetComplianceFindings(){},
      safeParse:()=>null,gv:()=>'',parseRBACData,runComplianceChecks,invalidateComplianceCache});
    const shell=source('app-shell');
    vm.runInContext(shell.slice(shell.indexOf('// Content-based compliance cache')),ctx);
    const findings=ctx._runComplianceWithCache(data);
    assert.equal(data.storageAccounts,data.s3bk);
    assert.equal(data.managedDisks,data.volumes);
    assert.equal(findings.some(f=>f.id==='CIS-44'&&f.resourceId===id),true);
    const row=inventory.buildInventoryData(data,{complianceFindings:findings}).find(r=>r.id===id);
    assert.ok(row);
    assert.ok(row.complianceFail>0);
    storage.minimumTlsVersion='TLS1_2';input.value=JSON.stringify([storage]);
    assert.equal(ctx._runComplianceWithCache(data).some(f=>f.id==='CIS-44'&&f.resourceId===id),false);
  });

  it('keeps report text inside the JSON script and round-trips it exactly',()=>{
    const title='</script><p id="outside">review</p>&<';
    const ctx=runtime(['report-render-functions','report-builder'],{_rptState:{title},_budrAssessments:[],_budrFindings:[],
      _inventoryData:[],_loadedContexts:[],_iamReviewData:[],_appRegistry:[],_importedReportData:null,
      MUTE_KEY:'mute',document:{getElementById:()=>({value:'all'})}});
    const html=ctx._rptEmbedDataBlob([]);
    assert.equal((html.match(/<\/script>/gi)||[]).length,1);
    assert.equal(html.includes('<p id="outside">'),false);
    assert.equal(JSON.parse(html.split('\n')[2]).title,title);
  });

  it('does not claim missing controls from uncollected supplemental evidence',()=>{
    const data={nsgs:[{id:'nsg-a',name:'a'}],vms:[{id:'vm-a',name:'a'}]};
    const findings=[...runSOC2Checks(data),...runPCIChecks(data),...runBUDRAzureChecks(data)];
    const unknownChecks=['SOC2-FLOWLOG','SOC2-MONITOR','PCI-IDS','PCI-REVIEW','PCI-LOG','BUDR-VM-BAK','BUDR-RSV'];
    assert.equal(findings.some(f=>unknownChecks.includes(f.id)),false);
    for(const key of ['nsgFlowLogs','logAnalyticsWorkspaces','diagnosticSettings','defenderPlans','accessReviews','backupItems','recoveryVaults']){
      assert.ok(data.assessmentGaps[key],`${key} should be recorded as unknown`);
    }
    const assessed={...data,nsgFlowLogs:[],logAnalyticsWorkspaces:[],diagnosticSettings:[],defenderPlans:[],accessReviews:[],backupItems:[],recoveryVaults:[]};
    const verified=[...runSOC2Checks(assessed),...runPCIChecks(assessed),...runBUDRAzureChecks(assessed)];
    for(const id of unknownChecks)assert.equal(verified.some(f=>f.id===id),true,`${id} must still find a verified absence`);
    const failed={...assessed,collectionStatus:{defenderPlans:'failed'}};
    assert.equal(runPCIChecks(failed).some(f=>f.id==='PCI-IDS'),false);
  });

  it('clears omitted sections and accounts when importing the next report',()=>{
    const data={};
    const ctx=runtime(['report-import'],{AppRenderContext:{createRenderContext:()=>data},
      _iamReviewData:[{name:'Old principal'}],_appRegistry:[{name:'Old app'}],_loadedContexts:[{accountId:'old'}],
      _rptState:{},_RPT_MODULES:[],_reportImportNotify(){},AppNotifications:{show(){}},
      document:{getElementById:()=>({style:{},addEventListener(){}})},openUnifiedDash(){}});
    ctx._applyImportedData({title:'Fresh report',findings:[]},'json');
    assert.equal(vm.runInContext('_iamReviewData.length',ctx),0);
    assert.equal(vm.runInContext('_appRegistry.length',ctx),0);
    assert.equal(vm.runInContext('_loadedContexts.length',ctx),0);
    assert.equal(vm.runInContext('_importedReportData.title',ctx),'Fresh report');
  });

  it('exports modern context counts in DOCX and orders at-risk BUDR rows first',()=>{
    const data={vnets:[{}],vms:[{},{}],nsgs:[{},{},{}],subnets:[],sqlServers:[],appGateways:[],functionApps:[],containerInstances:[]};
    const ctx=runtime(['report-builder','report-xlsx-export'],{
      AppRenderContext:{createRenderContext:()=>({rlCtx:data,complianceFindings:[]})},
      _rptState:{},_rptFilterByAccount:a=>a,_rptGetAccountFilter:()=> 'all',_importedReportData:null,
      _budrAssessments:['protected','at_risk','partial'].map(tier=>({id:tier,profile:{tier}})),
      _rptAccountLabel:a=>a,_azurePortalUrl:()=>'',_xlsxAddSheet:(wb,name,headers,rows)=>{wb.rows=rows}});
    const docx=ctx._docxExecSummary(false);
    assert.match(docx,/VNets[\s\S]*?>1<\/w:t>/);
    assert.match(docx,/Virtual Machines[\s\S]*?>2<\/w:t>/);
    assert.match(docx,/NSGs[\s\S]*?>3<\/w:t>/);
    ctx.XLSX={utils:{encode_cell:({r,c})=>`${r},${c}`,encode_range:()=> 'A1:D100',
      book_append_sheet:(wb,sheet)=>{wb.Summary=sheet}}};
    const summary={};ctx._rptBuildXlsxSummary(summary,[]);
    for(const [label,count] of [['VNets',1],['Virtual Machines',2],['NSGs',3]]){
      const [address]=Object.entries(summary.Summary).find(([,cell])=>cell.v===label);
      const [r,c]=address.split(',').map(Number);
      assert.equal(summary.Summary[`${r},${c+1}`].v,count);
    }
    // Capture workbook rows through the real builder, without loading Office.
    vm.runInContext('_xlsxAddSheet=(wb,name,headers,rows)=>{wb.rows=rows}',ctx);
    const wb={};ctx._rptBuildXlsxBUDR(wb);
    assert.deepEqual(Array.from(wb.rows,r=>r[6]),['at_risk','partial','protected']);
  });
});
