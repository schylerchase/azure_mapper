// FlowTracingPanel owns the traffic-flow detail panel markup and panel events.
// Trace execution and SVG overlay drawing stay in flow-tracing-runtime.js.
var FlowTracingPanel = (function(){
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

  function hopTypeLabel(type){
    var labels={'source':'Source','target':'Target','route-table':'Route Table','nacl-outbound':'NACL Outbound','nacl-inbound':'NACL Inbound','sg-outbound':'SG Outbound','sg-inbound':'SG Inbound','peering':'VNet Peering','tgw':'Virtual WAN','cross-vpc':'Cross-VNet','error':'Error','igw-check':'Firewall Check'};
    return labels[type]||type;
  }

  function panelElements(){
    return {
      panel: document.getElementById('detailPanel'),
      title: document.getElementById('dpTitle'),
      subtitle: document.getElementById('dpSub'),
      body: document.getElementById('dpBody')
    };
  }

  function bannerHtml(state,srcName,tgtName,info){
    var s1='<span class="flow-step-num'+(state>=1?' done':state===0?' active':'')+'">1</span>';
    var s2='<span class="flow-step-num'+(state>=2?' done':state===1?' active':'')+'">2</span>';
    var s3='<span class="flow-step-num'+(state>=3?' done':state===2?' active':'')+'">3</span>';
    if(state===0)return s1+'Click a source resource &nbsp; '+s2+'<span style="color:var(--text-muted)">Target</span> &nbsp; '+s3+'<span style="color:var(--text-muted)">Results</span>';
    if(state===1)return s1+'Source: <span id="flowSrcName" style="text-decoration:underline;cursor:pointer" title="Click to re-select source">'+esc(srcName)+'</span> &nbsp; '+s2+'Click a target';
    return s1+esc(srcName)+' &nbsp; '+s2+esc(tgtName)+' &nbsp; '+s3+(info||'');
  }

  function singleTraceHtml(state){
    var config=state.config||{protocol:'tcp',port:443};
    var path=state.path||[];
    var blocked=state.blocked||null;
    var suggestions=state.suggestions||[];
    var stepIndex=Number.isInteger(state.stepIndex)?state.stepIndex:-1;
    var html='<div class="flow-panel">';
    html+='<h4>Hop-by-Hop Trace</h4>';
    html+='<div style="margin-bottom:10px;font-size:10px;color:var(--text-muted)">Protocol: <span style="color:var(--accent-cyan)">'+esc(config.protocol.toUpperCase())+'</span> &nbsp; Port: <span style="color:var(--accent-cyan)">'+esc(config.port)+'</span></div>';
    html+='<div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;align-items:center">';
    html+='<label style="font-size:9px;color:var(--text-muted)">Protocol:</label>';
    html+='<select id="flowProtoSel" style="background:var(--bg-input);border:1px solid var(--border);color:var(--text-primary);border-radius:3px;padding:2px 6px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif">';
    ['tcp','udp','icmp'].forEach(function(protocol){
      html+='<option value="'+protocol+'"'+(protocol===config.protocol?' selected':'')+'>'+protocol.toUpperCase()+'</option>';
    });
    html+='</select>';
    html+='<label style="font-size:9px;color:var(--text-muted)">Port:</label>';
    html+='<input id="flowPortInput" type="number" min="1" max="65535" value="'+esc(config.port)+'" style="width:60px;background:var(--bg-input);border:1px solid var(--border);color:var(--text-primary);border-radius:3px;padding:2px 6px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif">';
    html+='<label style="font-size:9px;color:var(--text-muted)">Source port:</label><input id="flowSourcePortInput" type="number" min="0" max="65535" placeholder="All" value="'+esc(config.sourcePort??'')+'" style="width:64px;background:var(--bg-input);border:1px solid var(--border);color:var(--text-primary);border-radius:3px;padding:2px 6px;font-size:10px" title="Leave blank to test all source ports; specify a port when policy varies">';
    html+='<button id="flowRetraceBtn" style="background:var(--accent-cyan);color:#000;border:none;border-radius:3px;padding:2px 10px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer;font-weight:600">Re-trace</button>';
    html+='</div>';
    var quickPorts=[{label:'SSH',port:22},{label:'HTTP',port:80},{label:'HTTPS',port:443},{label:'MySQL',port:3306},{label:'Postgres',port:5432},{label:'Redis',port:6379},{label:'RDP',port:3389}];
    html+='<div class="flow-quick-ports">';
    quickPorts.forEach(function(quickPort){
      var active=config.port===quickPort.port&&config.protocol==='tcp';
      html+='<button class="flow-port-btn'+(active?' active':'')+'" data-qp-port="'+quickPort.port+'">'+quickPort.label+' '+quickPort.port+'</button>';
    });
    html+='</div>';
    path.forEach(function(hop, index){
      var active=stepIndex===-1||index===stepIndex;
      var blockedHop=hop.action==='block'||hop.action==='deny';
      var cls='flow-step'+(active?' active':'')+(blockedHop?' blocked':'');
      html+='<div class="'+cls+'" data-hop-idx="'+index+'">';
      html+='<span class="fs-num '+(blockedHop?'block':'allow')+'">'+hop.hop+'</span>';
      html+='<span class="fs-type">'+hopTypeLabel(hop.type)+'</span>';
      html+='<div class="fs-detail">'+esc(hop.detail||'')+'</div>';
      if(hop.rule) html+='<div class="fs-rule">'+esc(hop.rule)+'</div>';
      html+='</div>';
    });
    if(blocked){
      html+='<div class="flow-blocked-box">';
      html+='<div style="font-size:11px;font-weight:600;color:var(--accent-red);margin-bottom:4px">Blocked at Hop '+esc(blocked.hop)+'</div>';
      html+='<div style="font-size:10px;color:var(--text-secondary)">'+esc(blocked.reason||'')+'</div>';
      if(blocked.suggestion) html+='<div style="font-size:9px;color:var(--accent-orange);margin-top:4px">Suggestion: '+esc(blocked.suggestion)+'</div>';
      html+='</div>';
      if(suggestions.length>0){
        html+='<div style="margin-top:10px">';
        html+='<div style="font-size:10px;color:var(--accent-cyan);font-weight:600;margin-bottom:4px">Alternate Paths via Intermediary</div>';
        suggestions.forEach(function(suggestion, index){
          html+='<div class="flow-suggestion" data-sug-idx="'+index+'">';
          html+='<span class="sug-name">'+esc(suggestion.via.name||suggestion.via.id)+'</span>';
          html+=' <button class="flow-apply-sug" data-sug-idx="'+index+'">Apply</button>';
          html+='<div class="sug-detail">';
          html+=esc(suggestion.leg1Config.protocol.toUpperCase()+'/'+suggestion.leg1Config.port)+' → '+esc(suggestion.via.name||suggestion.via.id);
          html+=' → '+esc(config.protocol.toUpperCase()+'/'+config.port);
          html+='</div></div>';
        });
        html+='</div>';
      }
    }
    if(path.length>0){
      html+='<div style="margin-top:12px;display:flex;gap:6px">';
      html+='<button id="flowAddWpBtn2" style="background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);color:#f59e0b;border-radius:4px;padding:4px 12px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer;font-weight:600">+ Add Waypoint</button>';
      html+='</div>';
    }
    html+='</div>';
    return html;
  }

  function renderSingle(state, handlers){
    state=state||{};
    handlers=handlers||{};
    var els=panelElements();
    if(!els.panel||!els.title||!els.subtitle||!els.body) return;
    var config=state.config||{protocol:'tcp',port:443};
    els.title.textContent='Traffic Flow Trace';
    els.subtitle.textContent=config.protocol.toUpperCase()+'/'+config.port+(state.blocked?' — BLOCKED':' — ALLOWED');
    els.body.innerHTML=singleTraceHtml(state);
    els.panel.classList.add('open');
    wireSinglePanel(els.body, handlers);
  }

  function wireSinglePanel(body, handlers){
    var retrace=document.getElementById('flowRetraceBtn');
    if(retrace){
      retrace.addEventListener('click',function(event){
        event.stopPropagation();
        event.preventDefault();
        var proto=document.getElementById('flowProtoSel').value;
        var port=parseInt(document.getElementById('flowPortInput').value,10)||443;
        var source=document.getElementById('flowSourcePortInput').value.trim();
        var sourcePort=/^\d+$/.test(source)&&Number(source)<=65535?Number(source):undefined;
        if(handlers.retrace) handlers.retrace(proto, port, sourcePort);
      });
    }
    body.querySelectorAll('.flow-port-btn').forEach(function(button){
      button.addEventListener('click',function(event){
        event.stopPropagation();
        var port=parseInt(button.getAttribute('data-qp-port'),10);
        if(handlers.quickPort) handlers.quickPort(port);
      });
    });
    body.querySelectorAll('.flow-step').forEach(function(step){
      step.addEventListener('click',function(){
        var index=parseInt(step.getAttribute('data-hop-idx'),10);
        if(handlers.selectHop) handlers.selectHop(index);
      });
    });
    body.querySelectorAll('.flow-apply-sug').forEach(function(button){
      button.addEventListener('click',function(event){
        event.stopPropagation();
        var index=parseInt(button.getAttribute('data-sug-idx'),10);
        if(handlers.applySuggestion) handlers.applySuggestion(index);
      });
    });
    var waypointButton=document.getElementById('flowAddWpBtn2');
    if(waypointButton){
      waypointButton.addEventListener('click',function(event){
        event.stopPropagation();
        if(handlers.addWaypoint) handlers.addWaypoint();
      });
    }
  }

  function waypointName(waypoint, resolvePosition){
    if(!waypoint||!waypoint.ref) return '';
    var pos=resolvePosition ? resolvePosition(waypoint.ref.type, waypoint.ref.id) : null;
    return pos ? pos.name : waypoint.ref.id;
  }

  function multiTraceHtml(state, handlers){
    var legs=state.legs||[];
    var waypoints=state.waypoints||[];
    var activeLeg=Number.isInteger(state.activeLeg)?state.activeLeg:-1;
    var resolvePosition=handlers.resolvePosition;
    var html='<div class="flow-panel">';
    html+='<div style="margin-bottom:12px">';
    html+='<div style="font-size:9px;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">Waypoint Chain</div>';
    html+='<div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap">';
    waypoints.forEach(function(waypoint, index){
      var name=waypointName(waypoint, resolvePosition);
      html+='<span class="flow-wp-chip">';
      html+=esc(name);
      if(index>0&&index<waypoints.length-1){
        html+=' <span class="wp-remove" data-wp-idx="'+index+'" title="Remove waypoint">×</span>';
      }
      html+='</span>';
      if(index<waypoints.length-1){
        var legStatus=legs[index]?legs[index].status:'';
        html+='<span style="color:'+(legStatus==='allowed'?'#10b981':legStatus==='blocked'?'#ef4444':'#6b7280')+';font-size:11px">→</span>';
      }
    });
    html+='</div></div>';
    legs.forEach(function(leg, index){
      var srcPos=resolvePosition ? resolvePosition(leg.source.type, leg.source.id) : null;
      var tgtPos=resolvePosition ? resolvePosition(leg.target.type, leg.target.id) : null;
      var srcName=srcPos?srcPos.name:leg.source.id;
      var tgtName=tgtPos?tgtPos.name:leg.target.id;
      var expanded=activeLeg===-1||activeLeg===index;
      html+='<div class="flow-leg'+(expanded?' expanded':'')+'" data-leg-idx="'+index+'">';
      html+='<div class="flow-leg-hdr" data-leg-idx="'+index+'">';
      html+='<span style="color:var(--text-muted);font-size:9px">Leg '+(index+1)+'</span> ';
      html+=esc(srcName)+' → '+esc(tgtName);
      html+=' <span class="leg-status '+leg.status+'">'+leg.status.toUpperCase()+'</span>';
      html+=' <span style="color:var(--text-muted);font-size:9px;margin-left:auto">'+leg.config.protocol.toUpperCase()+'/'+leg.config.port+'</span>';
      html+='</div>';
      html+='<div class="flow-leg-body">';
      if(leg.status==='skipped'){
        html+='<div style="font-size:10px;color:var(--text-muted);padding:4px">Skipped (prior leg blocked)</div>';
      } else {
        html+=legControlsHtml(leg, index);
        (leg.result.path||[]).forEach(function(hop){
          var isBlocked=hop.action==='block'||hop.action==='deny';
          html+='<div class="flow-step'+(isBlocked?' blocked':'')+'" style="padding:5px 8px;margin-bottom:2px">';
          html+='<span class="fs-num '+(isBlocked?'block':'allow')+'" style="width:16px;height:16px;line-height:16px;font-size:8px">'+hop.hop+'</span>';
          html+='<span class="fs-type" style="font-size:9px">'+hopTypeLabel(hop.type)+'</span>';
          html+='<div class="fs-detail" style="font-size:9px">'+esc(hop.detail||'')+'</div>';
          if(hop.rule) html+='<div class="fs-rule" style="font-size:8px">'+esc(hop.rule)+'</div>';
          html+='</div>';
        });
        if(leg.result.blocked){
          html+='<div style="padding:6px;background:rgba(239,68,68,.06);border-radius:4px;margin-top:4px">';
          html+='<div style="font-size:9px;color:var(--accent-red)">'+esc(leg.result.blocked.reason||'')+'</div>';
          html+='</div>';
        }
      }
      html+='</div></div>';
    });
    html+='<div style="margin-top:10px;display:flex;gap:6px">';
    html+='<button id="mhAddWpBtn" style="background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);color:#f59e0b;border-radius:4px;padding:4px 12px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer;font-weight:600">+ Waypoint</button>';
    html+='<button id="mhClearBtn" style="background:rgba(255,255,255,.04);border:1px solid var(--border);color:var(--text-secondary);border-radius:4px;padding:4px 12px;font-size:10px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer">Clear All</button>';
    html+='</div>';
    html+='</div>';
    return html;
  }

  function legControlsHtml(leg, index){
    var html='<div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;align-items:center">';
    html+='<select class="leg-proto-sel" data-leg-idx="'+index+'" style="background:var(--bg-input);border:1px solid var(--border);color:var(--text-primary);border-radius:3px;padding:2px 4px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif">';
    ['tcp','udp','icmp'].forEach(function(protocol){
      html+='<option value="'+protocol+'"'+(protocol===leg.config.protocol?' selected':'')+'>'+protocol.toUpperCase()+'</option>';
    });
    html+='</select>';
    html+='<input class="leg-port-inp" data-leg-idx="'+index+'" type="number" min="1" max="65535" value="'+esc(leg.config.port)+'" style="width:50px;background:var(--bg-input);border:1px solid var(--border);color:var(--text-primary);border-radius:3px;padding:2px 4px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif">';
    html+='<button class="leg-retrace-btn" data-leg-idx="'+index+'" style="background:var(--accent-cyan);color:#000;border:none;border-radius:3px;padding:2px 8px;font-size:9px;font-family:Segoe UI,system-ui,sans-serif;cursor:pointer;font-weight:600">Re-trace</button>';
    html+='</div>';
    return html;
  }

  function renderMulti(state, handlers){
    state=state||{};
    handlers=handlers||{};
    var els=panelElements();
    if(!els.panel||!els.title||!els.subtitle||!els.body) return;
    var legs=state.legs||[];
    if(!legs.length) return;
    els.body.scrollTop=0;
    els.title.textContent='Multi-Hop Traffic Trace';
    var anyBlocked=legs.some(function(leg){return leg.status==='blocked'});
    els.subtitle.textContent=legs.length+' legs'+(anyBlocked?' — BLOCKED':' — ALL ALLOWED');
    els.body.innerHTML=multiTraceHtml(state, handlers);
    els.panel.classList.add('open');
    wireMultiPanel(els.body, handlers);
  }

  function wireMultiPanel(body, handlers){
    body.querySelectorAll('.flow-leg-hdr').forEach(function(header){
      header.addEventListener('click',function(){
        var index=parseInt(header.getAttribute('data-leg-idx'),10);
        if(handlers.toggleLeg) handlers.toggleLeg(index);
      });
    });
    body.querySelectorAll('.wp-remove').forEach(function(button){
      button.addEventListener('click',function(event){
        event.stopPropagation();
        if(handlers.removeWaypoint) handlers.removeWaypoint(parseInt(button.getAttribute('data-wp-idx'),10));
      });
    });
    body.querySelectorAll('.leg-retrace-btn').forEach(function(button){
      button.addEventListener('click',function(event){
        event.stopPropagation();
        var index=parseInt(button.getAttribute('data-leg-idx'),10);
        var proto=body.querySelector('.leg-proto-sel[data-leg-idx="'+index+'"]');
        var port=body.querySelector('.leg-port-inp[data-leg-idx="'+index+'"]');
        if(handlers.retraceLeg && proto && port){
          handlers.retraceLeg(index, proto.value, parseInt(port.value,10)||443);
        }
      });
    });
    var add=document.getElementById('mhAddWpBtn');
    if(add) add.addEventListener('click',function(event){
      event.stopPropagation();
      if(handlers.addWaypoint) handlers.addWaypoint();
    });
    var clear=document.getElementById('mhClearBtn');
    if(clear) clear.addEventListener('click',function(event){
      event.stopPropagation();
      if(handlers.clearWaypoints) handlers.clearWaypoints();
    });
  }

  return {
    renderSingle: renderSingle,
    renderMulti: renderMulti,
    bannerHtml: bannerHtml,
    hopTypeLabel: hopTypeLabel
  };
})();
