import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import { _normalizeAzureResources } from '../../src/modules/normalization.js';

const require=createRequire(import.meta.url);
const Inventory=require('../../src/modules/governance-inventory-model.js');
const source=name=>readFileSync(`src/modules/${name}`,'utf8');
const base=sub=>`/subscriptions/${sub}/resourceGroups/rg/providers/`;
const nameForResource=(r,id)=>r.name||r.Name||id;

function nativeContext(){
  const vnets=['sub-A','sub-B'].map(sub=>({id:base(sub)+'Microsoft.Network/virtualNetworks/vnet',name:'vnet',location:'eastus',_subscriptionId:sub,_accountLabel:'Shared',properties:{addressSpace:{addressPrefixes:['10.0.0.0/16']}}}));
  const sqlServers=['sub-A','sub-B'].map(sub=>({id:base(sub)+'Microsoft.Sql/servers/sql',name:'sql',location:'eastus',_subscriptionId:sub,_accountLabel:'Shared',tags:{Environment:sub==='sub-A'?'prod':'dev'},properties:{backupRetentionDays:7}}));
  const subnets=['sub-A','sub-B'].map(sub=>({id:vnets[sub==='sub-A'?0:1].id+'/subnets/app-'+sub.slice(-1)+'-only',name:'app-'+sub.slice(-1)+'-only',_subscriptionId:sub,_accountLabel:'Shared',tags:{Application:'app-'+sub.slice(-1)},properties:{addressPrefix:'10.0.1.0/24'}}));
  const zones=['sub-A','sub-B'].map(sub=>({id:base(sub)+'Microsoft.Network/privateDnsZones/private-'+sub.slice(-1)+'.test',name:'private-'+sub.slice(-1)+'.test',_subscriptionId:sub,_accountLabel:'Shared',location:'global'}));
  const storageAccounts=[{id:base('sub-B')+'Microsoft.Storage/storageAccounts/storage',name:'storage',location:'eastus',sku:{name:'Standard_GRS'},properties:{}}];
  _normalizeAzureResources({vpcs:vnets,rdsInstances:sqlServers,subnets,zones,s3bk:storageAccounts});
  return {vnets,sqlServers,subnets,zones,storageAccounts,s3bk:storageAccounts};
}

function classificationSandbox(){
  const sandbox=vm.createContext({structuredClone,gn:nameForResource});
  vm.runInContext(source('governance-classification.js'),sandbox);
  return sandbox;
}

describe('second rescan native governance and BUDR regressions',()=>{
  it('classifies canonical Azure collections with distinct ARM identities and production tags',()=>{
    const sandbox=classificationSandbox();const ctx=nativeContext();
    const rows=sandbox.GovernanceClassification.classify(ctx);
    assert.equal(rows.filter(r=>r.type==='VNet').length,2);
    const sql=rows.filter(r=>r.type==='SQL');
    assert.equal(sql.length,2);
    assert.equal(sql.find(r=>r.id===ctx.sqlServers[0].id).tier,'critical');
    assert.equal(sql.find(r=>r.id===ctx.sqlServers[1].id).tier,'low');
    sandbox.GovernanceClassification.setOverride(ctx.sqlServers[0].id,'medium');
    const changed=sandbox.GovernanceClassification.classify(ctx);
    assert.equal(changed.find(r=>r.id===ctx.sqlServers[0].id).tier,'medium');
    assert.equal(changed.find(r=>r.id===ctx.sqlServers[1].id).tier,'low');
    assert.equal(sandbox.GovernanceClassification.discoveredTags.Environment.count,2);
  });

  it('joins same-name SQL inventory rows through their full IDs and retains subscription IDs beside duplicate labels',()=>{
    const ctx=nativeContext();
    const rows=Inventory.buildInventoryData(ctx,{budrAssessments:ctx.sqlServers.map(r=>({id:r.id,profile:{tier:'partial'}})),complianceFindings:ctx.sqlServers.map(r=>({resource:'sql',resourceId:r.id,severity:'CRITICAL'}))});
    for(const sql of ctx.sqlServers){
      const row=rows.find(r=>r.id===sql.id);
      assert.equal(row.name,'sql');assert.equal(row.account,'Shared');assert.equal(row._subscriptionId,sql._subscriptionId);
      assert.equal(row.complianceFail,1);assert.equal(row.budrTier,'partial');
    }
    const storage=rows.find(r=>r.type==='Storage Account');
    assert.equal(storage._subscriptionId,'sub-B');
  });

  it('marks absent Blob Service evidence unknown, maps native isVersioningEnabled, and flags confirmed disabled protection',()=>{
    const sandbox=classificationSandbox();vm.runInContext(source('budr-report-registry.js'),sandbox);
    const cases=[
      {props:{},tier:'unknown',version:'Unknown',deleted:'Unknown',finding:false},
      {props:{isVersioningEnabled:false},tier:'unknown',version:false,deleted:'Unknown',finding:false},
      {props:{isVersioningEnabled:true,deleteRetentionPolicy:{enabled:false}},tier:'protected',version:true,deleted:false,finding:false},
      {props:{isVersioningEnabled:false,deleteRetentionPolicy:{enabled:false}},tier:'at_risk',version:false,deleted:false,finding:true},
      {props:{},tier:'unknown',version:'Unknown',deleted:'Unknown',finding:false}
    ];
    for(const c of cases){
      const ctx={storageAccounts:[{id:base('sub-B')+'Microsoft.Storage/storageAccounts/storage',name:'storage',properties:c.props}]};
      sandbox.GovernanceClassification.reset();const findings=sandbox.runBUDRChecks(ctx);
      const assessment=vm.runInContext('_budrAssessments[0]',sandbox);
      assert.equal(assessment.account,'sub-B');assert.equal(assessment.profile.tier,c.tier);
      assert.equal(assessment.signals.Versioned,c.version);assert.equal(assessment.signals.SoftDelete,c.deleted);
      assert.equal(findings.some(f=>f.control==='BUDR-S3-1'),c.finding);
      if(c.tier==='unknown'){
        assert.equal(assessment.compliance.status,'unknown');assert.ok(ctx.assessmentGaps.storageBlobProtection);
        assert.equal(findings.some(f=>f.control==='BUDR-TIER-RPO'),false);
      }
    }
  });
});

describe('second rescan report scope and native workbook regressions',()=>{
  function reportSandbox(){
    const ctx=nativeContext();let account='sub-A';
    const sandbox=vm.createContext({structuredClone,gn:nameForResource,Uint8Array,ArrayBuffer,TextEncoder,TextDecoder,Date,MUTE_KEY:'mute',
      document:{getElementById:id=>id==='rptAccountFilter'?({get value(){return account;}}):null},esc:value=>String(value??''),
      AppRenderContext:{createRenderContext:()=>({rlCtx:ctx,complianceFindings:[]})},GovernanceInventoryModel:Inventory,
      _rptTagName:nameForResource,_importedReportData:null,_loadedContexts:[{accountId:'sub-A',accountLabel:'Shared'},{accountId:'sub-B',accountLabel:'Shared'}],
      _budrAssessments:[],_budrFindings:[],_iamReviewData:[],_inventoryData:Inventory.buildInventoryData(ctx),
      _appRegistry:[{name:'app-A',pattern:'app-A'},{name:'app-B',pattern:'app-B'}],_rptState:{title:'Scoped report'},
      localStorage:{getItem:()=>null}});
    vm.runInContext(readFileSync('libs/xlsx.bundle.min.js','utf8'),sandbox);
    vm.runInContext(source('governance-classification.js'),sandbox);sandbox.GovernanceClassification.classify(ctx);
    const dashboard=source('dashboard-shell.js');
    vm.runInContext(dashboard.slice(dashboard.indexOf('function _matchAppResources('),dashboard.indexOf('function _buildAppRows(')),sandbox);
    vm.runInContext(source('report-html-assets.js')+'\n'+source('report-render-functions.js')+'\n'+source('report-builder.js')+'\n'+source('report-xlsx-export.js'),sandbox);
    return {sandbox,ctx,setAccount:value=>{account=value;}};
  }

  it('filters duplicate labels by canonical subscription in HTML and embedded inventory/application metadata',()=>{
    const {sandbox}=reportSandbox();
    const html=sandbox._rptInventory();assert.ok(html.includes('/subscriptions/sub-A/'));assert.equal(html.includes('/subscriptions/sub-B/'),false);
    const blob=JSON.parse(sandbox._rptEmbedDataBlob(['inventory','app-summary']).match(/\n(\{.*\})\n/)[1]);
    assert.ok(blob.inventoryData.length>0);assert.ok(blob.inventoryData.every(r=>r._subscriptionId==='sub-A'));
    assert.deepEqual(blob.appRegistry.map(a=>a.name),['app-A']);
    assert.equal(sandbox._rptAppSummary().includes('app-B-only'),false);
    assert.equal(sandbox._docxAppSummary(false).includes('app-B-only'),false);
  });

  it('exports all native inventory collections and scopes workbook DNS/application resources',()=>{
    const {sandbox,ctx,setAccount}=reportSandbox();const XLSX=sandbox.XLSX;
    for(const account of ['sub-A','sub-B','all']){
      setAccount(account);const wb=XLSX.utils.book_new();sandbox._rptBuildXlsxInventory(wb);sandbox._rptBuildXlsxAppSummary(wb);
      const readback=XLSX.read(XLSX.write(wb,{type:'array',bookType:'xlsx'}),{type:'array'});
      const inventory=XLSX.utils.sheet_to_json(readback.Sheets.Inventory);
      const wanted=account==='all'?ctx.vnets.concat(ctx.sqlServers):ctx.vnets.concat(ctx.sqlServers).filter(r=>r._subscriptionId===account);
      for(const r of wanted)assert.ok(inventory.some(row=>row.ID===r.id));
      if(account!=='all')assert.ok(inventory.every(row=>row.ID.includes('/subscriptions/'+account+'/')));
      const apps=XLSX.utils.sheet_to_json(readback.Sheets['App Resources']);
      assert.equal(apps.length,account==='all'?2:1);
      if(account!=='all')assert.ok(apps.every(row=>row.ID.includes('/subscriptions/'+account+'/')));
    }
  });

  it('discloses unknown protection in HTML, DOCX and workbook summary counts',()=>{
    const {sandbox}=reportSandbox();
    sandbox._budrAssessments=[{id:base('sub-A')+'Microsoft.Storage/storageAccounts/storage',account:'sub-A',type:'StorageAccount',name:'storage',profile:{tier:'unknown',rto:'Unknown',rpo:'Unknown',strategy:'unknown'},signals:{Versioned:'Unknown',SoftDelete:'Unknown'}}];
    assert.ok(sandbox._rptExecBUDR().includes('Not Assessed'));
    assert.ok(sandbox._docxBUDR(true).includes('Not Assessed'));
    const wb=sandbox.XLSX.utils.book_new();sandbox._rptBuildXlsxSummary(wb);
    const text=sandbox.XLSX.utils.sheet_to_csv(wb.Sheets.Summary);
    assert.ok(text.includes('Not Assessed'));
  });
});
