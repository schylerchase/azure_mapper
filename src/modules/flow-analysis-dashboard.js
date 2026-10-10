// FlowAnalysisDashboard owns the full-screen traffic-flow analysis dashboard.
// Runtime mode control passes in the discovered data and trace-launch callback.
var FlowAnalysisDashboard = (function(){
  var dashState={section:'all',search:'',sort:'name',sortDir:'asc',page:1,perPage:50};
  var dashRows=null;

  var TIER_DEFS=[
    {key:'internetFacing',label:'Internet-Facing',color:'#10b981'},
    {key:'bastionOnly',label:'Bastion-Only',color:'#22d3ee'},
    {key:'fullyPrivate',label:'Fully Private',color:'#8b5cf6'},
    {key:'database',label:'Database Tier',color:'#f59e0b'}
  ];
  var TIER_KEYS=['internetFacing','bastionOnly','fullyPrivate','database'];
  var SECTION_COLORS={ingress:'#10b981',egress:'#f97316',bastion:'#22d3ee',internetFacing:'#10b981',bastionOnly:'#22d3ee',fullyPrivate:'#8b5cf6',database:'#f59e0b'};
  var SECTION_LABELS={ingress:'Ingress',egress:'Egress',bastion:'Bastion',internetFacing:'Internet-Facing',bastionOnly:'Bastion-Only',fullyPrivate:'Fully Private',database:'Database'};
  var SECTION_ORDER={ingress:1,egress:2,internetFacing:3,bastionOnly:4,fullyPrivate:5,database:6,bastion:7};

  function esc(value){
    var html = typeof AppHtml !== 'undefined' ? AppHtml : null;
    if(html && typeof html.escape === 'function') return html.escape(value);
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function reset(){
    dashState={section:'all',search:'',sort:'name',sortDir:'asc',page:1,perPage:50};
    dashRows=null;
  }

  function buildRows(data){
    var rows=[];
    var seenIngress=new Set();
    (data.ingressPaths||[]).forEach(function(path){
      var key=path.to.type+':'+path.to.id+':'+path.port;
      if(seenIngress.has(key)) return;
      seenIngress.add(key);
      rows.push({section:'ingress',name:path.toName||path.to.id,type:path.to.type,id:path.to.id,detail:String(path.port),detail2:path.type||'',via:'',tier:'',tierColor:'',_raw:path});
    });
    (data.egressPaths||[]).forEach(function(path){
      rows.push({section:'egress',name:path.fromName||path.from.id,type:path.from.type,id:path.from.id,detail:path.via||'igw',detail2:'',via:path.via||'igw',tier:'',tierColor:'',_raw:path});
    });
    (data.bastionChains||[]).forEach(function(chain){
      var targetNames=chain.targets.map(function(target){return target.name||target.id}).join(', ');
      rows.push({section:'bastion',name:chain.bastion.name||chain.bastion.id,type:'bastion',id:chain.bastion.id,detail:chain.targets.length+' targets',detail2:targetNames,via:'',tier:'',tierColor:'',_raw:chain});
    });
    TIER_DEFS.forEach(function(tier){
      ((data.accessTiers||{})[tier.key]||[]).forEach(function(ref){
        rows.push({section:tier.key,name:ref.name||ref.id,type:ref.type,id:ref.id,detail:'',detail2:'',via:'',tier:tier.label,tierColor:tier.color,_raw:ref});
      });
    });
    return rows;
  }

  function dashboardShell(data){
    var html='<div class="fa-dash-header">';
    html+='<h2>Traffic Flow Analysis Dashboard</h2>';
    html+='<span style="font-size:10px;color:var(--text-muted)">'+((data.ingressPaths||[]).length)+' ingress · '+((data.egressPaths||[]).length)+' egress · '+((data.bastionChains||[]).length)+' bastion chains</span>';
    html+='<button class="fa-dash-close" id="faDashClose">✕ Close</button>';
    html+='</div>';
    html+='<div class="fa-dash-filters">';
    html+='<input id="faDashSearch" type="text" placeholder="Filter by name, type, port, ID...">';
    html+='<div id="faDashPills" class="fa-dash-pills"></div>';
    html+='<select id="faDashPerPage"><option value="25">25</option><option value="50" selected>50</option><option value="100">100</option><option value="0">All</option></select>';
    html+='</div>';
    html+='<div class="fa-dash-body" id="faDashBody">';
    html+='<div class="fa-dash-grid" style="margin-bottom:16px">';
    TIER_DEFS.forEach(function(tier){
      var items=((data.accessTiers||{})[tier.key]||[]);
      html+='<div class="fa-dash-card"><h4 style="color:'+tier.color+'">'+tier.label+'</h4>';
      html+='<div class="fa-dash-stat" style="color:'+tier.color+'">'+items.length+'</div>';
      html+='<div class="fa-dash-sub">resource'+(items.length!==1?'s':'')+'</div></div>';
    });
    html+='<div class="fa-dash-card"><h4 style="color:#10b981">↓ Ingress</h4>';
    html+='<div class="fa-dash-stat" style="color:#10b981">'+((data.ingressPaths||[]).length)+'</div>';
    html+='<div class="fa-dash-sub">paths from Internet</div></div>';
    html+='<div class="fa-dash-card"><h4 style="color:#f97316">↑ Egress</h4>';
    html+='<div class="fa-dash-stat" style="color:#f97316">'+((data.egressPaths||[]).length)+'</div>';
    html+='<div class="fa-dash-sub">paths to Internet</div></div>';
    html+='</div>';
    html+='<div id="faDashTableWrap"></div>';
    html+='</div>';
    html+='<div class="fa-dash-footer">';
    html+='<span id="faDashRowCount"></span>';
    html+='<button id="faDashPrev">← Prev</button>';
    html+='<span id="faDashPageInfo"></span>';
    html+='<button id="faDashNext">Next →</button>';
    html+='</div>';
    return html;
  }

  function renderPills(closeFn, options){
    var counts={all:dashRows.length,ingress:0,egress:0,bastion:0,tiers:0};
    dashRows.forEach(function(row){
      if(row.section==='ingress') counts.ingress++;
      else if(row.section==='egress') counts.egress++;
      else if(row.section==='bastion') counts.bastion++;
      else counts.tiers++;
    });
    var pillBox=document.getElementById('faDashPills');
    if(!pillBox) return;
    pillBox.textContent='';
    [{key:'all',label:'All'},{key:'ingress',label:'Ingress'},{key:'egress',label:'Egress'},{key:'bastion',label:'Bastion'},{key:'tiers',label:'Tiers'}].forEach(function(pillDef){
      var pill=document.createElement('span');
      pill.className='fa-dash-pill'+(dashState.section===pillDef.key?' active':'');
      pill.textContent=pillDef.label+' ('+counts[pillDef.key]+')';
      pill.addEventListener('click',function(){
        dashState.section=pillDef.key;
        dashState.page=1;
        render(closeFn, options);
      });
      pillBox.appendChild(pill);
    });
  }

  function filteredRows(){
    var section=dashState.section;
    var search=dashState.search;
    return dashRows.filter(function(row){
      if(section!=='all'){
        if(section==='tiers'){
          if(!TIER_KEYS.includes(row.section)) return false;
        } else if(row.section!==section) {
          return false;
        }
      }
      if(search){
        var hay=[row.name,row.type,row.id,row.detail,row.detail2,row.via,row.tier].filter(Boolean).join(' ').toLowerCase();
        if(hay.indexOf(search)===-1) return false;
      }
      return true;
    });
  }

  function sortRows(rows){
    var sortKey=dashState.sort;
    var dir=dashState.sortDir==='asc'?1:-1;
    rows.sort(function(a,b){
      if(sortKey!=='section'){
        var aOrd=SECTION_ORDER[a.section]||99;
        var bOrd=SECTION_ORDER[b.section]||99;
        if(aOrd!==bOrd) return aOrd-bOrd;
      }
      var av=a[sortKey]||'';
      var bv=b[sortKey]||'';
      if(sortKey==='detail'){
        var an=parseFloat(av),bn=parseFloat(bv);
        if(!isNaN(an)&&!isNaN(bn)) return(an-bn)*dir;
      }
      return av<bv?-dir:av>bv?dir:0;
    });
    return rows;
  }

  function pageRows(rows){
    var perPage=dashState.perPage<=0?Math.max(1, rows.length):dashState.perPage;
    var totalPages=Math.max(1,Math.ceil(rows.length/perPage));
    dashState.page=Math.min(Math.max(1,dashState.page),totalPages);
    var start=(dashState.page-1)*perPage;
    return {
      totalPages: totalPages,
      rows: rows.slice(start,start+perPage)
    };
  }

  function tableHtml(rows){
    var cols=[{key:'section',label:'Section'},{key:'name',label:'Name'},{key:'type',label:'Type'},{key:'detail',label:'Detail'},{key:'id',label:'ID',nosort:true},{key:'actions',label:'',nosort:true}];
    var html='<table class="fa-dash-table"><thead><tr>';
    cols.forEach(function(col){
      var cls='';
      if(!col.nosort&&dashState.sort===col.key) cls=dashState.sortDir==='asc'?' dd-sort-asc':' dd-sort-desc';
      html+='<th'+(col.nosort?'':' data-sort-col="'+col.key+'"')+' class="'+cls+'">'+col.label+'</th>';
    });
    html+='</tr></thead><tbody>';
    if(!rows.length){
      html+='<tr><td colspan="'+cols.length+'" style="text-align:center;padding:20px;color:var(--text-muted)">No rows match current filters</td></tr>';
      html+='</tbody></table>';
      return html;
    }
    var prevSection=null;
    rows.forEach(function(row){
      var sectionColor=SECTION_COLORS[row.section]||'var(--text-muted)';
      var sectionLabel=SECTION_LABELS[row.section]||row.section;
      if(row.section!==prevSection){
        var sectionCount=rows.filter(function(candidate){return candidate.section===row.section}).length;
        html+='<tr class="fa-section-divider"><td colspan="'+cols.length+'">';
        html+='<span class="fa-section-label" style="color:'+sectionColor+'">'+esc(sectionLabel)+'</span>';
        html+=' <span style="color:var(--text-muted);font-size:10px;margin-left:6px">'+sectionCount+'</span>';
        html+='</td></tr>';
        prevSection=row.section;
      }
      html+='<tr>';
      html+='<td><span class="fa-section-badge" style="background:'+sectionColor+'22;color:'+sectionColor+'">'+esc(sectionLabel)+'</span></td>';
      html+='<td style="color:var(--accent-cyan)">'+esc(row.name)+'</td>';
      html+='<td>'+esc(row.type)+'</td>';
      html+='<td>'+esc(row.detail)+(row.detail2?' <span style="color:var(--text-muted);font-size:10px">'+esc(row.detail2)+'</span>':'')+'</td>';
      html+='<td style="font-size:10px;color:var(--text-muted)">'+esc(row.id)+'</td>';
      html+='<td>'+traceButtonHtml(row)+'</td>';
      html+='</tr>';
    });
    html+='</tbody></table>';
    return html;
  }

  function traceButtonHtml(row){
    if(row.section==='ingress'){
      var path=row._raw;
      return '<button class="fa-trace-btn" data-trace-src-t="internet" data-trace-src-id="internet" data-trace-tgt-t="'+esc(path.to.type)+'" data-trace-tgt-id="'+esc(path.to.id)+'" data-trace-port="'+esc(path.port)+'">Trace ↗</button>';
    }
    if(row.section==='bastion'&&row._raw.targets&&row._raw.targets.length>0){
      var chain=row._raw;
      var firstTarget=chain.targets[0];
      return '<button class="fa-trace-btn" data-trace-src-t="'+esc(chain.bastion.type)+'" data-trace-src-id="'+esc(chain.bastion.id)+'" data-trace-tgt-t="'+esc(firstTarget.type)+'" data-trace-tgt-id="'+esc(firstTarget.id)+'" data-trace-port="22">Trace ↗</button>';
    }
    return '';
  }

  function updateFooter(filtered, totalPages){
    var rowCount=document.getElementById('faDashRowCount');
    if(rowCount) rowCount.textContent=filtered.length+' of '+dashRows.length;
    var pageInfo=document.getElementById('faDashPageInfo');
    if(pageInfo) pageInfo.textContent='Page '+dashState.page+' of '+totalPages;
    var prev=document.getElementById('faDashPrev');
    if(prev) prev.disabled=(dashState.page<=1);
    var next=document.getElementById('faDashNext');
    if(next) next.disabled=(dashState.page>=totalPages);
  }

  function wireTable(closeFn, options){
    var wrap=document.getElementById('faDashTableWrap');
    if(!wrap) return;
    wrap.querySelectorAll('th[data-sort-col]').forEach(function(th){
      th.addEventListener('click',function(){
        var col=this.dataset.sortCol;
        if(dashState.sort===col) dashState.sortDir=dashState.sortDir==='asc'?'desc':'asc';
        else {
          dashState.sort=col;
          dashState.sortDir='asc';
        }
        dashState.page=1;
        render(closeFn, options);
      });
    });
    wrap.querySelectorAll('.fa-trace-btn').forEach(function(btn){
      btn.addEventListener('click',function(event){
        event.stopPropagation();
        if(options.launchTraceFromButton) options.launchTraceFromButton(btn, closeFn);
      });
    });
  }

  function render(closeFn, options){
    if(!dashRows) return;
    options=options||{};
    renderPills(closeFn, options);
    var filtered=sortRows(filteredRows());
    var page=pageRows(filtered);
    updateFooter(filtered, page.totalPages);
    var wrap=document.getElementById('faDashTableWrap');
    if(wrap) wrap.innerHTML=tableHtml(page.rows);
    wireTable(closeFn, options);
  }

  function wireShell(overlay, closeFn, dashEsc, options){
    document.addEventListener('keydown', dashEsc);
    document.getElementById('faDashClose').addEventListener('click', closeFn);
    document.getElementById('faDashSearch').addEventListener('input',function(){
      dashState.search=this.value.toLowerCase();
      dashState.page=1;
      render(closeFn, options);
    });
    document.getElementById('faDashPerPage').addEventListener('change',function(){
      dashState.perPage=parseInt(this.value,10)||0;
      dashState.page=1;
      render(closeFn, options);
    });
    document.getElementById('faDashPrev').addEventListener('click',function(){
      if(dashState.page>1){
        dashState.page--;
        render(closeFn, options);
      }
    });
    document.getElementById('faDashNext').addEventListener('click',function(){
      dashState.page++;
      render(closeFn, options);
    });
  }

  function open(data, options){
    if(!data) return;
    options=options||{};
    var existing=document.getElementById('faDashOverlay');
    if(existing) existing.remove();
    dashRows=buildRows(data);
    dashState={section:'all',search:'',sort:'name',sortDir:'asc',page:1,perPage:50};
    var overlay=document.createElement('div');
    overlay.id='faDashOverlay';
    overlay.className='fa-dash-overlay';
    overlay.innerHTML=dashboardShell(data);
    document.body.appendChild(overlay);
    function closeDash(){
      overlay.remove();
      document.removeEventListener('keydown', dashEsc);
    }
    function dashEsc(event){
      if(event.key==='Escape'){
        event.stopImmediatePropagation();
        closeDash();
      }
    }
    wireShell(overlay, closeDash, dashEsc, options);
    render(closeDash, options);
  }

  return {
    open: open,
    reset: reset,
    buildRows: buildRows
  };
})();
