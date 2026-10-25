// MapViewport owns map zoom, focus, highlight, and zoom toolbar binding.
// It is the named adapter between feature panels and the active D3 viewport.
var MapViewport = (function(global){
  var zoomLabelDirty = false;
  var gatewayHighlighter = null;

  function context(){
    return global.AppRenderContext.createRenderContext();
  }

  function d3Api(){ return global.d3 || (typeof d3 !== 'undefined' ? d3 : null); }
  function mainElement(){ return typeof _getMain === 'function' ? _getMain() : document.querySelector('.main'); }
  function isMobileViewport(){ return typeof _isMobile === 'function' && _isMobile(); }
  function attrValue(value){ return String(value).replace(/\\/g,'\\\\').replace(/"/g,'\\"'); }
  function propsOf(resource){ return resource && (resource.properties || resource._azure && resource._azure.properties) || {}; }

  function findById(items, id){
    return (items || []).find(function(item){
      return item && (item.id === id || item.name === id || item.SubnetId === id ||
        item.VpcId === id || item.InstanceId === id || item.GroupId === id ||
        item.NatGatewayId === id || item.InternetGatewayId === id);
    });
  }

  function resourceSelector(id){
    var q = attrValue(id);
    return '[data-vnet-id="'+q+'"],[data-subnet-id="'+q+'"],[data-gwid="'+q+'"],[data-id="'+q+'"]';
  }

  function safeQuery(root, selector){
    if(!root || !selector) return null;
    try { return root.querySelector(selector); }
    catch(e){ return null; }
  }

  function selectedNode(mapG, selector){
    if(!mapG || !selector) return null;
    try { return mapG.select(selector).node(); }
    catch(e){ return null; }
  }

  function viewportSize(mapSvg){
    var main = mainElement();
    var svgNode = mapSvg && mapSvg.node ? mapSvg.node() : null;
    return {
      width: main && main.clientWidth || svgNode && svgNode.clientWidth || 1,
      height: main && main.clientHeight || svgNode && svgNode.clientHeight || 1
    };
  }

  function setMapRefs(svg, zoom, group){
    var nav = context();
    nav.mapSvg = svg || null;
    nav.mapZoom = zoom || null;
    nav.mapG = group || null;
    return nav;
  }

  function updateZoomLabel(k){
    if(zoomLabelDirty) return;
    zoomLabelDirty = true;
    requestAnimationFrame(function(){
      var label = document.getElementById('zoomLevel');
      if(label) label.textContent = Math.round(k * 100) + '%';
      zoomLabelDirty = false;
    });
  }

  function focusBox(box, options){
    var nav = context();
    var api = d3Api();
    if(!box || !box.width || !box.height || !nav.mapSvg || !nav.mapZoom || !api) return false;
    var opts = Object.assign({ duration:600, maxScale:3, paddingRatio:.85, minScale:0 }, options || {});
    var size = viewportSize(nav.mapSvg);
    var scale = opts.scale;
    if(!scale){
      scale = opts.paddingRatio / Math.max(box.width / size.width, box.height / size.height);
      if(opts.paddingPx){
        scale = Math.min(size.width / (box.width + opts.paddingPx), size.height / (box.height + opts.paddingPx));
      }
    }
    scale = Math.max(opts.minScale, Math.min(opts.maxScale, scale));
    var tx = size.width / 2 - scale * (box.x + box.width / 2);
    var ty = size.height / 2 - scale * (box.y + box.height / 2);
    var transition = nav.mapSvg.transition().duration(opts.duration);
    if(opts.ease) transition = transition.ease(opts.ease);
    transition.call(nav.mapZoom.transform, api.zoomIdentity.translate(tx, ty).scale(scale));
    return true;
  }

  function zoomToSelector(selector, options){
    var nav = context();
    if(!nav.mapG) return false;
    var el = selectedNode(nav.mapG, selector);
    if(!el) return false;
    return focusBox(el.getBBox(), options);
  }

  function flashElement(element){
    var api = d3Api();
    if(!element || !api) return false;
    var shape = element.querySelector && (element.querySelector('rect') || element.querySelector('circle')) || element;
    if(!shape) return false;
    var el = api.select(shape);
    var orig = el.attr('stroke');
    var origW = el.attr('stroke-width') || 1.2;
    el.transition().duration(200).attr('stroke','#fff').attr('stroke-width',3)
      .transition().duration(200).attr('stroke','#facc15').attr('stroke-width',3)
      .transition().duration(200).attr('stroke','#fff').attr('stroke-width',3)
      .transition().duration(400).attr('stroke',orig).attr('stroke-width',origW);
    return true;
  }

  function flashSelector(selector){
    var nav = context();
    if(!nav.mapG) return false;
    var node = selectedNode(nav.mapG, selector);
    return flashElement(node);
  }

  function findResourceElement(id){
    var nav = context();
    if(!id || !nav.mapG) return null;
    var root = nav.mapG.node && nav.mapG.node();
    var el = safeQuery(root, resourceSelector(id));
    if(!el && nav.rlCtx){
      var nsg = findById(nav.rlCtx.nsgs, id);
      var vnetId = nsg && (propsOf(nsg).vnetId || nsg.VpcId);
      if(vnetId) el = safeQuery(root, '[data-vnet-id="'+attrValue(vnetId)+'"]');
    }
    return el ? { nav:nav, element:el, box:el.getBBox(), mapG:nav.mapG } : null;
  }

  function drawBoxHighlight(mapG, box, className, options){
    if(!mapG || !box) return null;
    var opts = Object.assign({ pad:8, stroke:'#22d3ee', pulse:'#06b6d4', width:3 }, options || {});
    mapG.selectAll('.' + className).remove();
    var rect = mapG.append('rect').attr('class',className)
      .attr('x',box.x - opts.pad).attr('y',box.y - opts.pad)
      .attr('width',box.width + opts.pad * 2).attr('height',box.height + opts.pad * 2)
      .attr('rx',6).attr('ry',6)
      .attr('fill','none').attr('stroke',opts.stroke).attr('stroke-width',opts.width)
      .attr('stroke-dasharray','8,4').attr('opacity',0)
      .attr('pointer-events','none');
    rect.transition().duration(300).attr('opacity',1)
      .transition().duration(400).attr('stroke-width',opts.width + 2).attr('stroke',opts.pulse)
      .transition().duration(400).attr('stroke-width',opts.width).attr('stroke',opts.stroke)
      .transition().duration(400).attr('stroke-width',opts.width + 2).attr('stroke',opts.pulse)
      .transition().duration(400).attr('stroke-width',opts.width).attr('stroke',opts.stroke)
      .transition().duration(400).attr('stroke-width',opts.width + 2).attr('stroke',opts.pulse)
      .transition().duration(1500).attr('opacity',0)
      .on('end',function(){ d3Api().select(this).remove(); });
    return rect;
  }

  function zoomToResource(id, options){
    var target = findResourceElement(id);
    if(!target) return null;
    var opts = Object.assign({ duration:750, paddingPx:200, maxScale:2.5, highlight:true }, options || {});
    focusBox(target.box, opts);
    if(opts.highlight) drawBoxHighlight(target.mapG, target.box, 'zoom-highlight');
    return target;
  }

  function focusResource(id, options){
    return zoomToResource(id, Object.assign({ highlight:false }, options || {}));
  }

  function flashResource(id){
    var target = findResourceElement(id);
    return target ? flashElement(target.element) : false;
  }

  function clearOverlay(selector){
    var nav = context();
    if(nav.mapG) nav.mapG.selectAll(selector).remove();
  }

  function highlightGateway(gatewayId){
    if(typeof gatewayHighlighter === 'function'){
      gatewayHighlighter(gatewayId);
      return true;
    }
    return false;
  }

  function setGatewayHighlighter(handler){
    gatewayHighlighter = typeof handler === 'function' ? handler : null;
  }

  function bindZoomButtons(){
    var nav = context();
    var api = d3Api();
    if(!nav.mapSvg || !nav.mapZoom || !nav.mapG || !api) return false;
    var svg = nav.mapSvg;
    var zoom = nav.mapZoom;
    var group = nav.mapG;
    api.select('#zoomIn').on('click',function(){ svg.transition().duration(300).call(zoom.scaleBy,1.4); });
    api.select('#zoomOut').on('click',function(){ svg.transition().duration(300).call(zoom.scaleBy,.7); });
    api.select('#zoomFit').on('click',function(){
      var node = group.node && group.node();
      if(!node) return;
      var box = node.getBBox();
      if(!box.width) return;
      focusBox(box, {
        duration:500,
        paddingRatio:isMobileViewport() ? .82 : .92,
        minScale:.25,
        maxScale:Infinity
      });
    });
    return true;
  }

  return {
    setMapRefs:setMapRefs,
    updateZoomLabel:updateZoomLabel,
    zoomToSelector:zoomToSelector,
    flashSelector:flashSelector,
    bindZoomButtons:bindZoomButtons,
    focusBox:focusBox,
    zoomToResource:zoomToResource,
    focusResource:focusResource,
    flashResource:flashResource,
    clearOverlay:clearOverlay,
    highlightGateway:highlightGateway,
    setGatewayHighlighter:setGatewayHighlighter
  };
})(window);

function zoomToNode(selector){ return MapViewport.zoomToSelector(selector); }
function flashNode(selector){ return MapViewport.flashSelector(selector); }
function bindZoomButtons(){ return MapViewport.bindZoomButtons(); }
function _updateZoomLabel(k){ return MapViewport.updateZoomLabel(k); }
