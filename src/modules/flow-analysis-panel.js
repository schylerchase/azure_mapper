// FlowAnalysisPanel owns the side detail panel for traffic-flow analysis.
// Discovery and SVG route overlays stay in flow-analysis-runtime.js.
var FlowAnalysisPanel = (function(){
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

  function tierRows(data, mode){
    var tierData=[
      {key:'internetFacing',label:'Internet-Facing',color:'#10b981',icon:'↗'},
      {key:'bastionOnly',label:'Bastion-Only',color:'#22d3ee',icon:''},
      {key:'fullyPrivate',label:'Fully Private',color:'#8b5cf6',icon:''},
      {key:'database',label:'Database Tier',color:'#f59e0b',icon:''}
    ];
    var tiers=data.accessTiers||{};
    var html='<h4>Access Tiers</h4>';
    tierData.forEach(function(td){
      var items=tiers[td.key]||[];
      var count=items.length;
      html+='<div class="fa-tier-row" data-fa-tier="'+td.key+'">';
      html+='<span class="fa-tier-dot" style="background:'+td.color+'"></span>';
      html+='<span style="color:var(--text-primary);font-weight:600">'+td.label+'</span>';
      html+='<span style="margin-left:auto;color:'+td.color+';font-weight:700">'+count+'</span>';
      html+='</div>';
      var expanded=mode==='tiers'&&count<=20;
      html+='<div class="fa-tier-list" data-tier="'+td.key+'" style="display:'+(expanded?'block':'none')+';padding-left:20px;margin-bottom:8px">';
      items.forEach(function(ref){
        html+='<div class="fa-path-item" data-ref-type="'+esc(ref.type)+'" data-ref-id="'+esc(ref.id)+'">';
        html+=esc(ref.name||ref.id)+' <span style="color:var(--text-muted);font-size:9px">('+esc(ref.type)+')</span>';
        html+='</div>';
      });
      html+='</div>';
    });
    return html;
  }

  function ingressRows(data, mode){
    var paths=data.ingressPaths||[];
    if(!paths.length){
      return mode==='ingress'
        ? '<div style="padding:12px;color:var(--text-muted);font-size:10px;text-align:center">No ingress paths discovered</div>'
        : '';
    }
    var html=mode!=='ingress'?'<h4 style="margin-top:14px">Ingress Paths ('+paths.length+')</h4>':'';
    if(mode==='ingress'){
      var byPort={};
      var seenByPort=new Set();
      paths.forEach(function(path){
        var key=path.to.type+':'+path.to.id+':'+path.port;
        if(seenByPort.has(key)) return;
        seenByPort.add(key);
        var portKey=path.port||'other';
        if(!byPort[portKey]) byPort[portKey]=[];
        byPort[portKey].push(path);
      });
      Object.keys(byPort).sort(function(a,b){return byPort[b].length-byPort[a].length}).forEach(function(portKey){
        var portLabel=portKey==='443'?'HTTPS (443)':portKey==='80'?'HTTP (80)':portKey==='22'?'SSH (22)':'Port '+portKey;
        html+='<h4 style="margin-top:10px;color:#10b981">'+portLabel+' <span style="color:var(--text-muted);font-weight:400">('+byPort[portKey].length+' targets)</span></h4>';
        byPort[portKey].forEach(function(path){
          html+=ingressPathRow(path, false);
        });
      });
      return html;
    }

    var seen=new Set();
    paths.forEach(function(path){
      var key=path.to.type+':'+path.to.id;
      if(seen.has(key)) return;
      seen.add(key);
      html+=ingressPathRow(path, true);
    });
    return html;
  }

  function ingressPathRow(path, compact){
    var html='<div class="fa-path-item" data-ref-type="'+esc(path.to.type)+'" data-ref-id="'+esc(path.to.id)+'" style="display:flex;align-items:center">';
    html+='<span style="flex:1"><span style="color:#10b981">↓</span> Internet → <span style="color:var(--accent-cyan)">'+esc(path.toName||path.to.id)+'</span>';
    html+=compact
      ? ' <span style="color:var(--text-muted);font-size:9px">:'+esc(path.port)+' ('+esc(path.type)+')</span></span>'
      : ' <span style="color:var(--text-muted);font-size:9px">('+esc(path.type)+')</span></span>';
    html+='<button class="fa-trace-btn" data-trace-src-t="internet" data-trace-src-id="internet" data-trace-tgt-t="'+esc(path.to.type)+'" data-trace-tgt-id="'+esc(path.to.id)+'" data-trace-port="'+esc(path.port)+'">Trace ↗</button>';
    html+='</div>';
    return html;
  }

  function egressRows(data, mode){
    var paths=data.egressPaths||[];
    if(!paths.length){
      return mode==='egress'
        ? '<div style="padding:12px;color:var(--text-muted);font-size:10px;text-align:center">No egress paths discovered</div>'
        : '';
    }
    var html='<h4 style="margin-top:14px">Egress Paths ('+paths.length+')</h4>';
    if(mode==='egress'){
      var byVia={igw:[],nat:[]};
      paths.forEach(function(path){byVia[path.via||'igw'].push(path)});
      ['igw','nat'].forEach(function(via){
        if(!byVia[via].length) return;
        var label=via==='igw'?'via Internet Gateway':'via NAT Gateway';
        html+='<h4 style="margin-top:10px;color:#f97316">'+label+' <span style="color:var(--text-muted);font-weight:400">('+byVia[via].length+' subnets)</span></h4>';
        byVia[via].forEach(function(path){
          html+=egressPathRow(path, false);
        });
      });
      return html;
    }
    paths.forEach(function(path){
      html+=egressPathRow(path, true);
    });
    return html;
  }

  function egressPathRow(path, compact){
    var html='<div class="fa-path-item" data-ref-type="'+esc(path.from.type)+'" data-ref-id="'+esc(path.from.id)+'">';
    html+='<span style="color:#f97316">↑</span> <span style="color:var(--accent-cyan)">'+esc(path.fromName||path.from.id)+'</span> → Internet';
    if(compact) html+=' <span style="color:var(--text-muted);font-size:9px">('+esc(path.via)+')</span>';
    html+='</div>';
    return html;
  }

  function bastionRows(data, mode){
    var chains=data.bastionChains||[];
    if(!chains.length){
      return mode==='bastion'
        ? '<div style="padding:12px;color:var(--text-muted);font-size:10px;text-align:center">No bastion hosts detected</div>'
        : '';
    }
    var html='<h4 style="margin-top:14px">Bastion Chains ('+chains.length+')</h4>';
    chains.forEach(function(chain){
      html+='<div class="fa-path-item" data-ref-type="'+esc(chain.bastion.type)+'" data-ref-id="'+esc(chain.bastion.id)+'">';
      html+=esc(chain.bastion.name||chain.bastion.id);
      html+=' → <span style="color:var(--text-muted)">'+chain.targets.length+' target'+(chain.targets.length>1?'s':'')+'</span>';
      html+='</div>';
      var showTargets=mode==='bastion';
      html+='<div class="fa-bastion-targets" style="display:'+(showTargets?'block':'none')+';padding-left:24px;margin-bottom:8px">';
      chain.targets.forEach(function(target){
        html+='<div class="fa-path-item" data-ref-type="'+esc(target.type)+'" data-ref-id="'+esc(target.id)+'" style="display:flex;align-items:center">';
        html+='<span style="flex:1">└ '+esc(target.name||target.id)+'</span>';
        html+='<button class="fa-trace-btn" data-trace-src-t="'+esc(chain.bastion.type)+'" data-trace-src-id="'+esc(chain.bastion.id)+'" data-trace-tgt-t="'+esc(target.type)+'" data-trace-tgt-id="'+esc(target.id)+'" data-trace-port="22">Trace ↗</button>';
        html+='</div>';
      });
      html+='</div>';
    });
    return html;
  }

  function panelSubtitle(data, mode){
    var tiers=data.accessTiers||{};
    var total=(tiers.internetFacing||[]).length+(tiers.bastionOnly||[]).length+(tiers.fullyPrivate||[]).length+(tiers.database||[]).length;
    var parts=[];
    if(mode==='tiers'||mode==='all') parts.push(total+' resources classified');
    if(mode==='ingress'||mode==='all') parts.push((data.ingressPaths||[]).length+' ingress paths');
    if(mode==='egress'||mode==='all') parts.push((data.egressPaths||[]).length+' egress paths');
    if(mode==='bastion'||mode==='all') parts.push((data.bastionChains||[]).length+' bastion chains');
    return parts.join(' - ');
  }

  function warningHtml(data){
    var warnings=[];
    if(!data.hasSgData) warnings.push('SG associations');
    if(!data.hasNaclEgress) warnings.push('NACL egress rules');
    if(!warnings.length) return '';
    return '<div style="padding:6px 8px;margin-bottom:10px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.25);border-radius:4px;font-size:9px;color:#fbbf24;font-family:Segoe UI,system-ui,sans-serif">'+warnings.join(' & ')+' missing: results based on available topology data</div>';
  }

  function highlightItem(item, handlers){
    var refType=item.getAttribute('data-ref-type');
    var refId=item.getAttribute('data-ref-id');
    if(!refType||!refId) return;
    if(handlers.clearHighlights) handlers.clearHighlights();
    if(handlers.highlightNode) handlers.highlightNode({type:refType,id:refId}, 'source');
  }

  function wirePanel(dpBody, handlers){
    dpBody.querySelectorAll('.fa-tier-row').forEach(function(row){
      row.addEventListener('click',function(){
        var tier=row.getAttribute('data-fa-tier');
        var list=dpBody.querySelector('.fa-tier-list[data-tier="'+tier+'"]');
        if(list) list.style.display=list.style.display==='none'?'block':'none';
      });
    });
    dpBody.querySelectorAll('.fa-path-item[data-ref-type]').forEach(function(item){
      var next=item.nextElementSibling;
      if(next&&next.classList.contains('fa-bastion-targets')){
        item.addEventListener('click',function(event){
          event.stopPropagation();
          next.style.display=next.style.display==='none'?'block':'none';
          highlightItem(item, handlers);
        });
      } else {
        item.addEventListener('click',function(){
          highlightItem(item, handlers);
        });
      }
    });
    dpBody.querySelectorAll('.fa-trace-btn').forEach(function(btn){
      btn.addEventListener('click',function(event){
        event.stopPropagation();
        if(handlers.launchTraceFromButton) handlers.launchTraceFromButton(btn);
      });
    });
  }

  function render(data, mode, handlers){
    if(!data) return;
    handlers=handlers||{};
    mode=mode||'all';
    var panel=document.getElementById('detailPanel');
    var title=document.getElementById('dpTitle');
    var sub=document.getElementById('dpSub');
    var body=document.getElementById('dpBody');
    if(!panel||!title||!sub||!body) return;
    var titles={tiers:'Access Tiers',ingress:'Ingress Paths',egress:'Egress Paths',bastion:'Bastion Chains',all:'Traffic Flow Analysis'};
    title.textContent=titles[mode]||'Traffic Flow Analysis';
    sub.textContent=panelSubtitle(data, mode);
    var html='<div class="flow-panel">';
    html+=warningHtml(data);
    if(mode==='tiers'||mode==='all') html+=tierRows(data, mode);
    if(mode==='ingress'||mode==='all') html+=ingressRows(data, mode);
    if(mode==='egress'||mode==='all') html+=egressRows(data, mode);
    if(mode==='bastion'||mode==='all') html+=bastionRows(data, mode);
    html+='</div>';
    body.innerHTML=html;
    panel.classList.add('open');
    wirePanel(body, handlers);
  }

  return {
    render: render
  };
})();
