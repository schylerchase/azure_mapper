// Report dashboard owns report picker UI, preview rendering, and report metadata controls.
function reportDashboardRuntimeContext(){
  return AppRenderContext.createRenderContext();
}
function reportDashboardRuntimeData(){
  return reportDashboardRuntimeContext().rlCtx;
}
function reportDashboardComplianceRows(){
  return reportDashboardRuntimeContext().complianceFindings||[];
}
function reportDashboardNotify(message,type){
  AppNotifications.show(message,type);
}
function _renderReportsTab(){
  document.getElementById('udashToolbar').style.display='none';
  var body=document.getElementById('udashBody');
  body.classList.add('rpt-layout');
  body.innerHTML=
    '<div class="rpt-picker">'+
      '<div class="rpt-meta">'+
        '<label>Report Date</label>'+
        '<input type="date" id="rptDate">'+
        '<label>Report Title</label>'+
        '<input type="text" id="rptTitle" placeholder="Azure Infrastructure Assessment">'+
        '<label>Author</label>'+
        '<input type="text" id="rptAuthor" placeholder="Author name">'+
        '<label>Logo</label>'+
        '<div class="rpt-logo-upload">'+
          '<button class="rpt-logo-btn" id="rptLogoBtn">Upload Logo</button>'+
          '<input type="file" id="rptLogoInput" accept="image/*" style="display:none">'+
          '<button class="rpt-logo-clear" id="rptLogoClear" style="display:none">\u2715</button>'+
          '<div class="rpt-logo-preview" id="rptLogoPreview" style="display:none"></div>'+
        '</div>'+
      '</div>'+
      '<div class="rpt-presets" id="rptPresets"></div>'+
      '<div class="rpt-modules" id="rptModules"></div>'+
    '</div>'+
    '<div class="rpt-preview" id="rptPreview">'+
      '<div class="rpt-preview-frame">'+
        '<div class="rpt-preview-content" id="rptPreviewContent"></div>'+
      '</div>'+
    '</div>';
  var footer=document.getElementById('udashFooter');
  var acctOpts='<option value="all">All Accounts</option>';
  _loadedContexts.forEach(function(c){
    var lbl=c.accountLabel||c.accountId;
    if(lbl!==c.accountId&&/^\d{12}$/.test(c.accountId)){
      acctOpts+='<option value="'+esc(c.accountId)+'">'+esc(lbl)+' ('+c.accountId.slice(-4)+')</option>';
    }else{
      acctOpts+='<option value="'+esc(c.accountId)+'">'+esc(lbl)+'</option>';
    }
  });
  var acctSelect=_loadedContexts.length>1?
    '<select id="rptAccountFilter" style="background:var(--bg-secondary);color:var(--text-primary);border:1px solid var(--border);border-radius:4px;padding:4px 8px;font-size:11px;margin-right:8px">'+acctOpts+'</select>':'';
  footer.innerHTML=
    '<span id="rptFooterStats" style="font-size:11px;color:var(--text-muted);margin-right:auto"></span>'+
    '<button class="udash-btn" id="rptImportReport" style="margin-right:8px;opacity:.8">Load Report</button>'+
    acctSelect+
    '<button class="udash-btn rpt-generate" id="rptExportHTML">Generate HTML Report</button>'+
    '<button class="udash-btn" id="rptExportXLSX">Export XLSX</button>'+
    '<select id="rptDocxTone" style="background:var(--bg-secondary);color:var(--text-primary);border:1px solid var(--border);border-radius:4px;padding:4px 8px;font-size:11px;margin-left:4px">'+
      '<option value="executive">Executive</option><option value="technical">Technical</option>'+
    '</select>'+
    '<button class="udash-btn" id="rptExportDOCX">Export DOCX</button>';
  document.getElementById('rptDate').value=_rptState.date;
  if(_rptState.title) document.getElementById('rptTitle').value=_rptState.title;
  if(_rptState.author) document.getElementById('rptAuthor').value=_rptState.author;
  if(typeof _updateLogoPreview==='function') _updateLogoPreview();

  var _syncAcct=document.getElementById('rptAccountFilter');
  if(_syncAcct&&_udashAcctFilter&&_udashAcctFilter!=='all'){
    for(let i=0;i<_syncAcct.options.length;i++){
      if(_syncAcct.options[i].value===_udashAcctFilter){_syncAcct.value=_udashAcctFilter;break}
    }
  }

  _renderRptPicker();
  _renderRptPreview();

  document.getElementById('rptTitle').addEventListener('input',function(){_rptState.title=this.value;_rptDebouncedPreview()});
  document.getElementById('rptAuthor').addEventListener('input',function(){_rptState.author=this.value;_rptDebouncedPreview()});
  document.getElementById('rptDate').addEventListener('change',function(){_rptState.date=this.value;_renderRptPreview()});
  var acctEl=document.getElementById('rptAccountFilter');
  if(acctEl) acctEl.addEventListener('change',function(){_renderRptPicker();_renderRptPreview()});

  document.getElementById('rptLogoBtn').addEventListener('click',function(){document.getElementById('rptLogoInput').click()});
  document.getElementById('rptLogoInput').addEventListener('change',function(e){
    var file=e.target.files[0];
    if(!file) return;
    if(file.size>500000){reportDashboardNotify('Logo too large (max 500 KB)');this.value='';return;}
    var reader=new FileReader();
    reader.onload=function(ev){
      var img=new Image();
      img.onload=function(){
        var ext=file.type.split('/')[1]||'png';
        _rptState.logo={dataUri:ev.target.result,ext:ext,width:img.width,height:img.height};
        _updateLogoPreview();
        _rptDebouncedPreview();
      };
      img.src=ev.target.result;
    };
    reader.readAsDataURL(file);
  });
  document.getElementById('rptLogoClear').addEventListener('click',function(){
    _rptState.logo=null;
    document.getElementById('rptLogoInput').value='';
    _updateLogoPreview();
    _rptDebouncedPreview();
  });
  document.getElementById('rptImportReport').addEventListener('click',function(){document.getElementById('importReportInput').click()});
  document.getElementById('rptExportHTML').addEventListener('click',function(){_generateReport()});
  document.getElementById('rptExportXLSX').addEventListener('click',function(){_generateXlsx()});
  document.getElementById('rptExportDOCX').addEventListener('click',function(){
    var tone=document.getElementById('rptDocxTone').value;
    _generateDocx(tone);
  });
}

function openReportBuilder(){
  openUnifiedDash('reports');
}

function _renderRptPicker(){
  var presetsEl=document.getElementById('rptPresets');
  var presets=[
    {id:'full',label:'Full Assessment',modules:_RPT_MODULES.map(function(m){return m.id})},
    {id:'compliance',label:'Compliance Only',modules:['exec-summary','compliance','iam-review','action-plan']},
    {id:'budr',label:'BUDR Only',modules:['exec-summary','budr','action-plan']},
    {id:'diagram',label:'Diagram + Inventory',modules:['architecture','inventory']}
  ];
  presetsEl.textContent='';
  presets.forEach(function(p){
    var btn=document.createElement('button');
    btn.className='rpt-preset';
    btn.dataset.preset=p.id;
    btn.textContent=p.label;
    btn.addEventListener('click',function(){
      _RPT_MODULES.forEach(function(m){m.enabled=p.modules.indexOf(m.id)>=0});
      _rptState.order=p.modules.slice();
      _renderRptPicker();
      _renderRptPreview();
    });
    presetsEl.appendChild(btn);
  });
  var container=document.getElementById('rptModules');
  var order=_rptState.order||_RPT_MODULES.map(function(m){return m.id});
  var sorted=order.map(function(id){return _RPT_MODULES.find(function(m){return m.id===id})}).filter(Boolean);
  _RPT_MODULES.forEach(function(m){if(order.indexOf(m.id)<0)sorted.push(m)});
  container.textContent='';
  var dragId=null;
  sorted.forEach(function(m){
    var avail=m.available();
    var card=document.createElement('div');
    card.className='rpt-mod-card'+(avail?'':' disabled');
    card.draggable=avail;
    card.dataset.mod=m.id;
    var grip=document.createElement('span');
    grip.className='rm-grip';grip.textContent='\u2630';
    var cb=document.createElement('input');
    cb.className='rm-check';cb.type='checkbox';
    cb.checked=m.enabled&&avail;cb.disabled=!avail;
    var info=document.createElement('div');
    info.className='rm-info';
    var nm=document.createElement('div');nm.className='rm-name';nm.textContent=m.name;
    var ds=document.createElement('div');ds.className='rm-desc';ds.textContent=m.desc();
    info.appendChild(nm);info.appendChild(ds);
    card.appendChild(grip);card.appendChild(cb);card.appendChild(info);
    cb.addEventListener('change',function(){m.enabled=this.checked;_renderRptPreview()});
    if(avail){
      card.addEventListener('dragstart',function(e){
        dragId=this.dataset.mod;this.classList.add('dragging');e.dataTransfer.effectAllowed='move';
      });
      card.addEventListener('dragend',function(){
        this.classList.remove('dragging');
        container.querySelectorAll('.drag-over').forEach(function(el){el.classList.remove('drag-over')});
      });
      card.addEventListener('dragover',function(e){
        e.preventDefault();e.dataTransfer.dropEffect='move';
        container.querySelectorAll('.drag-over').forEach(function(el){el.classList.remove('drag-over')});
        this.classList.add('drag-over');
      });
      card.addEventListener('drop',function(e){
        e.preventDefault();this.classList.remove('drag-over');
        var targetId=this.dataset.mod;
        if(!dragId||dragId===targetId)return;
        var cards=Array.from(container.querySelectorAll('.rpt-mod-card'));
        var newOrder=cards.map(function(c){return c.dataset.mod});
        var fromIdx=newOrder.indexOf(dragId);
        var toIdx=newOrder.indexOf(targetId);
        newOrder.splice(fromIdx,1);
        newOrder.splice(toIdx,0,dragId);
        _rptState.order=newOrder;
        _renderRptPicker();
        _renderRptPreview();
      });
    }
    container.appendChild(card);
  });
}

function _renderRptPreview(){
  var container=document.getElementById('rptPreviewContent');
  var enabled=_rptEnabledModules();
  if(!enabled.length){
    container.textContent='';
    var p=document.createElement('p');
    p.style.cssText='color:var(--text-muted);text-align:center;padding:60px 20px;font-family:Segoe UI,system-ui,sans-serif';
    p.textContent='Toggle sections on the left to build your report';
    container.appendChild(p);
    return;
  }
  var html='<style>'+_rptCSS()+_rptInteractiveCSS()+'</style>';
  html+=_rptBuildHeader();
  html+=_rptBuildTOC(enabled);
  html+=_rptBuildSections(enabled);
  html+=_rptBuildFooter();
  var wrapper=document.createElement('div');
  wrapper.innerHTML=html;
  container.textContent='';
  container.appendChild(wrapper);
  if(typeof _rptUpdateFooterStats==='function') _rptUpdateFooterStats();
  var scrollBox=document.getElementById('rptPreview');
  wrapper.addEventListener('click',function(e){
    var link=e.target.closest('a[href^="#"]');
    if(!link) return;
    var hash=link.getAttribute('href');
    if(!hash||hash.length<2) return;
    e.preventDefault();
    var target=wrapper.querySelector(hash)||wrapper.querySelector('[id="'+hash.slice(1)+'"]');
    if(!target||!scrollBox) return;
    var boxTop=scrollBox.getBoundingClientRect().top;
    var elTop=target.getBoundingClientRect().top;
    scrollBox.scrollTop+=elTop-boxTop-12;
  });
  _rptInitInteractive(wrapper);
}

function _rptInitInteractive(root){
  var SEV_ORD={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
  var TIER_ORD={at_risk:0,partial:1,protected:2};
  var STRAT_ORD={hot:0,warm:1,pilot:2,cold:3};

  function rptPaginate(tableId){
    var wrap=root.querySelector('#'+CSS.escape(tableId))||document.getElementById(tableId);
    if(!wrap)return;
    var table=wrap.querySelector('table');
    if(!table)return;
    var tbody=table.querySelector(':scope > tbody');
    if(!tbody)return;
    var allRows=[].slice.call(tbody.querySelectorAll(':scope > tr:not(.rpt-ctrl-detail)'));
    var visible=allRows.filter(function(r){return r.dataset.filtered!=='0'});
    var perPage=parseInt(wrap.dataset.perPage)||50;
    if(perPage<=0)perPage=visible.length||1;
    var totalPages=Math.max(1,Math.ceil(visible.length/perPage));
    var page=Math.min(parseInt(wrap.dataset.page)||1,totalPages);
    wrap.dataset.page=page;
    var start=(page-1)*perPage,end=start+perPage;
    allRows.forEach(function(r){r.style.display='none'});
    visible.forEach(function(r,i){r.style.display=(i>=start&&i<end)?'':'none'});
    table.querySelectorAll('.rpt-ctrl-detail').forEach(function(d){
      var p=d.previousElementSibling;
      d.style.display=(p&&p.style.display!=='none'&&p.classList.contains('expanded'))?'table-row':'none';
    });
    var bar=wrap.querySelector('.rpt-pagination');
    if(!bar)return;
    var info=bar.querySelector('.rpt-page-info');
    if(info)info.textContent='Page '+page+' of '+totalPages+' ('+visible.length+' rows)';
    var prev=bar.querySelector('.rpt-page-prev');
    var next=bar.querySelector('.rpt-page-next');
    if(prev)prev.disabled=(page<=1);
    if(next)next.disabled=(page>=totalPages);
  }

  function rptFilter(tableId){
    var wrap=root.querySelector('#'+CSS.escape(tableId))||document.getElementById(tableId);
    if(!wrap)return;
    var pills=wrap.querySelectorAll('.rpt-pill');
    var active={};
    pills.forEach(function(p){
      if(!p.classList.contains('active'))return;
      var attr=p.dataset.attr;
      if(!active[attr])active[attr]=[];
      active[attr].push(p.dataset.val.toUpperCase());
    });
    var si=wrap.querySelector('.rpt-search');
    var query=si?si.value.toLowerCase():'';
    var table=wrap.querySelector('table');
    if(!table)return;
    var tbody=table.querySelector(':scope > tbody');
    if(!tbody)return;
    var rows=tbody.querySelectorAll(':scope > tr:not(.rpt-ctrl-detail)');
    var shown=0,attrCounts={},total=rows.length;
    rows.forEach(function(tr){
      var vis=true;
      Object.keys(active).forEach(function(attr){
        var raw=(tr.dataset[attr]||'').toUpperCase();
        if(attr==='account'&&raw.indexOf('|')!==-1){
          var parts=raw.split('|');
          var match=parts.some(function(p){return active[attr].indexOf(p)!==-1});
          if(!match)vis=false;
        }else{
          if(active[attr].indexOf(raw)===-1)vis=false;
        }
      });
      if(vis&&query){if(tr.textContent.toLowerCase().indexOf(query)===-1)vis=false}
      tr.dataset.filtered=vis?'1':'0';
      if(vis)shown++;
      ['sev','tier','fw','strategy','account'].forEach(function(attr){
        var v=(tr.dataset[attr]||'').toUpperCase();
        if(attr==='account'&&v.indexOf('|')!==-1){
          v.split('|').forEach(function(p){if(p){if(!attrCounts[p])attrCounts[p]=0;if(vis)attrCounts[p]++}});
        }else{
          if(v){if(!attrCounts[v])attrCounts[v]=0;if(vis)attrCounts[v]++}
        }
      });
    });
    var badge=wrap.querySelector('.rpt-row-count');
    if(badge)badge.textContent=shown+' of '+total;
    pills.forEach(function(p){
      var ct=p.querySelector('.rpt-pill-ct');
      if(!ct)return;
      var val=p.dataset.val.toUpperCase();
      ct.textContent=attrCounts[val]||0;
    });
    wrap.dataset.page='1';
    rptPaginate(tableId);
  }

  function rptSort(th){
    var table=th.closest('table');
    if(!table)return;
    var idx=[].indexOf.call(th.parentElement.children,th);
    var type=th.dataset.sortType||'text';
    var dir=th.classList.contains('rpt-sort-asc')?'desc':th.classList.contains('rpt-sort-desc')?'none':'asc';
    th.parentElement.querySelectorAll('th').forEach(function(h){h.classList.remove('rpt-sort-asc','rpt-sort-desc')});
    if(dir!=='none')th.classList.add('rpt-sort-'+dir);
    var tbody=table.querySelector('tbody');
    var rows=[].slice.call(tbody.querySelectorAll(':scope > tr:not(.rpt-ctrl-detail)'));
    if(dir==='none')return;
    rows.sort(function(a,b){
      var av=a.children[idx]?a.children[idx].textContent.trim():'';
      var bv=b.children[idx]?b.children[idx].textContent.trim():'';
      var cmp=0;
      if(type==='severity')cmp=(SEV_ORD[av]===undefined?9:SEV_ORD[av])-(SEV_ORD[bv]===undefined?9:SEV_ORD[bv]);
      else if(type==='tier')cmp=(TIER_ORD[av]===undefined?9:TIER_ORD[av])-(TIER_ORD[bv]===undefined?9:TIER_ORD[bv]);
      else if(type==='strategy')cmp=(STRAT_ORD[av.toLowerCase()]===undefined?9:STRAT_ORD[av.toLowerCase()])-(STRAT_ORD[bv.toLowerCase()]===undefined?9:STRAT_ORD[bv.toLowerCase()]);
      else cmp=av.localeCompare(bv);
      return dir==='desc'?-cmp:cmp;
    });
    var pairs=rows.map(function(r){
      var detail=r.nextElementSibling;
      return {row:r,detail:(detail&&detail.classList.contains('rpt-ctrl-detail'))?detail:null};
    });
    pairs.forEach(function(p){
      tbody.appendChild(p.row);
      if(p.detail)tbody.appendChild(p.detail);
    });
    var wrap=th.closest('.rpt-table-wrap');
    if(wrap){wrap.dataset.page='1';rptPaginate(wrap.id)}
  }

  var _searchTimer=0;
  root.addEventListener('click',function(e){
    var pill=e.target.closest('.rpt-pill');
    if(pill){pill.classList.toggle('active');var w=pill.closest('.rpt-table-wrap');if(w)rptFilter(w.id);return}
    if(e.target.classList.contains('rpt-clear')){
      var w=e.target.closest('.rpt-table-wrap');
      if(!w)return;w.querySelectorAll('.rpt-pill.active').forEach(function(p){p.classList.remove('active')});
      var si=w.querySelector('.rpt-search');if(si)si.value='';rptFilter(w.id);return;
    }
    var th=e.target.closest('th.rpt-sortable');
    if(th){rptSort(th);return}
    var btn=e.target.closest('.rpt-page-prev,.rpt-page-next');
    if(btn){
      var w=btn.closest('.rpt-table-wrap');if(!w)return;
      var pg=parseInt(w.dataset.page)||1;
      w.dataset.page=btn.classList.contains('rpt-page-prev')?Math.max(1,pg-1):pg+1;
      rptPaginate(w.id);return;
    }
    var ctrlRow=e.target.closest('.rpt-ctrl-row');
    if(ctrlRow){
      ctrlRow.classList.toggle('expanded');
      var nx=ctrlRow.nextElementSibling;
      while(nx&&nx.classList.contains('rpt-ctrl-detail')){
        nx.classList.toggle('show');
        nx.style.display=nx.classList.contains('show')?'table-row':'none';
        nx=nx.nextElementSibling;
      }
      return;
    }
    if(e.target.classList.contains('rpt-expand-all')){
      var w=e.target.closest('.rpt-table-wrap');
      if(!w)return;
      var anyCollapsed=w.querySelector('.rpt-ctrl-row:not(.expanded)');
      var expand=!!anyCollapsed;
      w.querySelectorAll('.rpt-ctrl-row').forEach(function(r){r.classList.toggle('expanded',expand)});
      w.querySelectorAll('.rpt-ctrl-detail').forEach(function(d){d.classList.toggle('show',expand);d.style.display=expand?'table-row':'none'});
      e.target.textContent=expand?'Collapse All':'Expand All';
      return;
    }
    var resLink=e.target.closest('.rpt-res-link');
    if(resLink){
      e.preventDefault();
      var href=resLink.getAttribute('href');
      if(href&&href.charAt(0)==='#'){
        var target=root.querySelector(href)||document.querySelector(href);
        if(target){target.scrollIntoView({behavior:'smooth',block:'center'});target.style.outline='2px solid #67e8f9';setTimeout(function(){target.style.outline=''},2000)}
      }
      return;
    }
    var tog=e.target.closest('.rpt-section-toggle');
    if(tog){
      tog.classList.toggle('collapsed');
      var body=tog.parentElement.querySelector('.rpt-section-body');
      if(body)body.classList.toggle('collapsed');
      return;
    }
  });
  root.addEventListener('change',function(e){
    if(!e.target.classList.contains('rpt-per-page'))return;
    var w=e.target.closest('.rpt-table-wrap');if(!w)return;
    w.dataset.perPage=e.target.value;w.dataset.page='1';rptPaginate(w.id);
  });
  root.addEventListener('input',function(e){
    if(!e.target.classList.contains('rpt-search'))return;
    clearTimeout(_searchTimer);
    var w=e.target.closest('.rpt-table-wrap');
    _searchTimer=setTimeout(function(){if(w)rptFilter(w.id)},300);
  });
  root.querySelectorAll('.rpt-table-wrap').forEach(function(w){
    if(!w.dataset.perPage)w.dataset.perPage='50';
    w.dataset.page='1';
    rptFilter(w.id);
  });
}

function _rptEnabledModules(){
  var order=_rptState.order||_RPT_MODULES.map(function(m){return m.id});
  return order.filter(function(id){
    var m=_RPT_MODULES.find(function(x){return x.id===id});
    return m&&m.enabled&&m.available();
  });
}

function _rptUpdateFooterStats(){
  var el=document.getElementById('rptFooterStats');
  if(!el) return;
  var acct=_rptGetAccountFilter();
  var parts=[];
  var ctx=reportDashboardRuntimeData();
  var comp=_rptFilterByAccount(reportDashboardComplianceRows(),acct);
  var budr=_rptFilterByAccount(_budrFindings||[],acct);
  var fLen=comp.length+budr.length;
  if(fLen) parts.push(fLen+' findings');
  if(ctx){
    var rCount=0;
    ['vnets','subnets','vms','sqlServers','appGateways','containerInstances','functionApps'].forEach(function(k){
      rCount+=(ctx[k]||[]).length;
    });
    if(rCount) parts.push(rCount+' resources');
  }
  var all=comp.concat(budr);
  if(all.length) parts.push(all.length+' action items');
  el.textContent=parts.length?parts.join('  |  '):'';
}

var _rptInputTimer=0;
function _rptDebouncedPreview(){clearTimeout(_rptInputTimer);_rptInputTimer=setTimeout(_renderRptPreview,300)}

function _updateLogoPreview(){
  var preview=document.getElementById('rptLogoPreview');
  var clearBtn=document.getElementById('rptLogoClear');
  var uploadBtn=document.getElementById('rptLogoBtn');
  if(_rptState.logo){
    preview.textContent='';
    var img=document.createElement('img');
    img.src=_rptState.logo.dataUri;
    img.alt='Logo';
    preview.appendChild(img);
    preview.style.display='flex';
    clearBtn.style.display='inline-block';
    uploadBtn.textContent='Change';
  }else{
    preview.style.display='none';
    preview.textContent='';
    clearBtn.style.display='none';
    uploadBtn.textContent='Upload Logo';
  }
}
