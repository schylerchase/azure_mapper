// Resource navigation owns search result jumps, detail dispatch, and spotlight cards.
var _spotlightActive = false;

var ResourceNavigation = (function(){
  const TYPE_COLORS = {
    'VM':'#f97316',
    'SQL Server':'#a78bfa',
    'Function App':'#10b981',
    'App Gateway':'#3b82f6',
    'Load Balancer':'#3b82f6',
    'Container Instance':'#06b6d4',
    'Redis Cache':'#ef4444',
    'Synapse Workspace':'#ec4899',
    'Subnet':'#22d3ee',
    'VNet':'#60a5fa',
    'NSG':'#f59e0b',
    'NAT Gateway':'#f97316',
    'VPN Gateway':'#8b5cf6',
    'Private Endpoint':'#06b6d4',
    'VNet Peering':'#a78bfa',
    'UDR':'#64748b',
    'Storage Account':'#f472b6',
    'AKS':'#818cf8',
    'Firewall':'#ef4444',
    'Bastion':'#34d399'
  };

  function context(){
    return AppRenderContext.createRenderContext();
  }

  function viewport(){ return typeof MapViewport !== 'undefined' ? MapViewport : null; }
  function ctx(){ return context().rlCtx; }
  function escText(value){ return esc(value); }

  function zoomToResource(id){
    var vp = viewport();
    if(id && vp) return vp.zoomToResource(id);
  }

  function resolveResourceType(id){
    return ResourceProfile.resolveResourceType(ctx(), id);
  }

  function zoomAndOpenDetail(id){
    if(!id || id === 'Multiple') return;
    zoomToResource(id);
    const type = resolveResourceType(id);
    if(type) setTimeout(function(){ openDetailForSearch(type, id); }, 400);
  }

  function openSearchResult(result){
    if(!result) return;
    zoomToResource(result.id);
    openDetailForSearch(result.type || resolveResourceType(result.id), result.id);
  }

  function closeSpotlight(){
    _spotlightActive = false;
    var card = document.getElementById('spotlightCard');
    var backdrop = document.getElementById('spotlightBackdrop');
    if(card){ card.style.opacity = '0'; card.style.transform = 'translateY(20px) scale(.95)'; setTimeout(function(){ card.remove(); }, 300); }
    if(backdrop){ backdrop.classList.remove('active'); setTimeout(function(){ backdrop.remove(); }, 400); }
    var vp = viewport();
    if(vp) vp.clearOverlay('.spotlight-ring');
  }

  function openSpotlight(id){
    const nav = context();
    var vp = viewport();
    if(!id || !nav.rlCtx || !vp) return;
    closeSpotlight();
    var info = gatherResourceInfo(id);
    if(!info) return;
    var api = typeof d3 !== 'undefined' ? d3 : null;
    var target = vp.focusResource(id, {
      duration:900,
      paddingPx:300,
      maxScale:3.5,
      ease:api && api.easeCubicInOut
    });
    if(!target || !target.mapG) return;
    _spotlightActive = true;
    var bb = target.box;
    var mapG = target.mapG;
    mapG.selectAll('.spotlight-ring').remove();
    mapG.append('rect').attr('class','spotlight-ring')
      .attr('x',bb.x - 12).attr('y',bb.y - 12)
      .attr('width',bb.width + 24).attr('height',bb.height + 24)
      .attr('rx',8).attr('ry',8)
      .attr('fill','none').attr('stroke','#22d3ee').attr('stroke-width',2.5)
      .attr('stroke-dasharray','6,3').attr('opacity',0).attr('pointer-events','none')
      .style('animation','spotlightRingPulse 2s ease-in-out infinite')
      .transition().duration(500).delay(400).attr('opacity',1);

    renderSpotlightCard(id, info);
  }

  function renderSpotlightCard(id, info){
    var backdrop = document.createElement('div');
    backdrop.id = 'spotlightBackdrop';
    backdrop.className = 'spotlight-backdrop';
    backdrop.addEventListener('click', closeSpotlight);
    document.body.appendChild(backdrop);
    requestAnimationFrame(function(){ backdrop.classList.add('active'); });

    var card = document.createElement('div');
    card.id = 'spotlightCard';
    card.className = 'spotlight-card';
    var color = TYPE_COLORS[info.type] || '#22d3ee';
    var html = '<div class="spotlight-header">';
    html += '<button class="spotlight-close" data-spotlight-close>&times;</button>';
    html += '<span class="sl-type-badge" style="background:'+color+'22;color:'+color+';border:1px solid '+color+'44">'+escText(info.type)+'</span>';
    html += '<h3>'+escText(info.name)+'</h3>';
    html += '<span class="sl-id" title="Click to copy" data-copy-resource-id="'+escText(id)+'">'+escText(id)+'</span>';
    html += '</div><div class="spotlight-body">';
    if(info.details.length){
      html += '<div class="spotlight-section"><div class="spotlight-section-title">Details</div><dl class="spotlight-kv">';
      info.details.forEach(function(row){ html += '<dt>'+escText(row[0])+'</dt><dd>'+escText(row[1])+'</dd>'; });
      html += '</dl></div>';
    }
    if(info.findings.length){
      html += '<div class="spotlight-section"><div class="spotlight-section-title">Compliance ('+info.findings.length+')</div>';
      info.findings.slice(0,5).forEach(function(f){
        var severityColor = {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#eab308',LOW:'#3b82f6'}[f.severity] || '#64748b';
        html += '<div style="display:flex;align-items:center;gap:6px;padding:4px 0;font-size:calc(10px * var(--txt-scale,1))">';
        html += '<span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:'+severityColor+';flex-shrink:0"></span>';
        html += '<span style="color:'+severityColor+';font-weight:600;width:55px;flex-shrink:0">'+escText(f.severity)+'</span>';
        html += '<span style="color:var(--text-secondary);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+escText(f.message)+'</span></div>';
      });
      if(info.findings.length > 5) html += '<div style="font-size:calc(9px * var(--txt-scale,1));color:var(--text-muted);padding-top:4px">+'+(info.findings.length - 5)+' more findings</div>';
      html += '</div>';
    }
    html += renderResourceList('Related Resources', info.related);
    html += renderResourceList('Nearby Resources', info.nearby);
    html += '</div><div class="spotlight-actions">';
    html += '<button class="primary" data-spotlight-detail="'+escText(id)+'">Full Details</button>';
    html += '<button data-spotlight-deps="'+escText(id)+'">Dependencies</button>';
    html += '</div>';
    card.innerHTML = html;
    document.body.appendChild(card);
    wireSpotlightCard(card);
  }

  function renderResourceList(title, resources){
    if(!resources || !resources.length) return '';
    var html = '<div class="spotlight-section"><div class="spotlight-section-title">'+title+'</div><div class="spotlight-nearby">';
    resources.forEach(function(resource){
      var color = TYPE_COLORS[resource.type] || '#64748b';
      html += '<div class="spotlight-nearby-item" data-spotlight-rid="'+escText(resource.id)+'">';
      html += '<span class="sn-badge" style="background:'+color+'"></span>';
      html += '<span class="sn-name">'+escText(resource.name)+'</span>';
      html += '<span class="sn-type">'+escText(resource.type)+'</span></div>';
    });
    return html + '</div></div>';
  }

  function wireSpotlightCard(card){
    card.querySelector('[data-spotlight-close]').addEventListener('click', closeSpotlight);
    card.querySelectorAll('[data-spotlight-rid]').forEach(function(el){
      el.addEventListener('click', function(){ openSpotlight(this.dataset.spotlightRid); });
    });
    card.querySelector('[data-spotlight-detail]').addEventListener('click', function(){
      var id = this.dataset.spotlightDetail;
      closeSpotlight();
      openDetailForSearch(resolveResourceType(id), id);
    });
    var depsBtn = card.querySelector('[data-spotlight-deps]');
    if(depsBtn) depsBtn.addEventListener('click', function(){
      closeSpotlight();
      if(typeof showDependencies === 'function') showDependencies(this.dataset.spotlightDeps);
    });
    var copyId = card.querySelector('[data-copy-resource-id]');
    if(copyId) copyId.addEventListener('click', function(){
      if(navigator.clipboard) navigator.clipboard.writeText(this.dataset.copyResourceId);
    });
  }

  function gatherResourceInfo(id){
    var nav = context();
    return ResourceProfile.buildResourceProfile(nav.rlCtx, id, nav.complianceFindings, function(finding){
      return typeof _isMuted !== 'function' || !_isMuted(finding);
    });
  }

  function openDetailForSearch(type, id){
    const c = ctx();
    if(!c || !id) return;
    var resolvedType = type || resolveResourceType(id);
    openGenericDetail(resolvedType, id);
  }

  function openGenericDetail(type, id){
    var info = gatherResourceInfo(id);
    if(!info) return;
    const panel = document.getElementById('detailPanel');
    const title = document.getElementById('dpTitle');
    const sub = document.getElementById('dpSub');
    const body = document.getElementById('dpBody');
    if(!panel || !title || !sub || !body) return;
    _navStack = [];
    _lastRlType = null;
    title.innerHTML = escText(info.name);
    sub.innerHTML = '<span class="copyable" data-copy="'+esc(id)+'">'+esc(id)+'</span> &middot; '+escText(info.type);
    var html = '<div class="dp-section"><div class="dp-sec-hdr"><span class="dp-sec-title">Overview</span></div><div class="dp-sec-body"><table class="dp-kv">';
    info.details.forEach(function(row){ html += '<tr><td>'+escText(row[0])+'</td><td>'+escText(row[1])+'</td></tr>'; });
    html += '</table></div></div>';
    html += renderDetailLinks('Related Resources', info.related);
    html += renderDetailLinks('Nearby Resources', info.nearby);
    body.innerHTML = html;
    body.querySelectorAll('[data-resource-nav-id]').forEach(function(el){
      el.addEventListener('click', function(){ zoomAndOpenDetail(this.dataset.resourceNavId); });
    });
    panel.classList.add('open');
  }

  function renderDetailLinks(title, resources){
    if(!resources || !resources.length) return '';
    var html = '<div class="dp-section"><div class="dp-sec-hdr"><span class="dp-sec-title">'+title+'</span></div><div class="dp-sec-body">';
    resources.forEach(function(resource){
      html += '<div class="dp-link" data-resource-nav-id="'+escText(resource.id)+'">'+escText(resource.type)+': '+escText(resource.name)+'</div>';
    });
    return html + '</div></div>';
  }

  function isSpotlightActive(){
    return _spotlightActive;
  }

  return {
    zoomToResource,
    zoomAndOpenDetail,
    openSearchResult,
    resolveResourceType,
    openSpotlight,
    closeSpotlight,
    isSpotlightActive,
    gatherResourceInfo,
    openDetailForSearch
  };
})();
