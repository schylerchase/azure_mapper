// #region FLOW ANALYSIS
// === FLOW ANALYSIS: AUTO-DISCOVERY ENGINE ===
let _flowAnalysisMode=null; // null|'tiers'|'ingress'|'egress'|'bastion'|'all'
let _flowAnalysisCache=null;

function flowAnalysisRuntimeContext(){
  var contextFactory = typeof AppRenderContext !== 'undefined' ? AppRenderContext : null;
  return contextFactory ? contextFactory.createRenderContext() : null;
}

function flowAnalysisRuntimeData(){
  var ctx = flowAnalysisRuntimeContext();
  return ctx ? flowResourceContext(ctx.rlCtx) : null;
}

function flowAnalysisNotify(message, type){
  var notifications = typeof AppNotifications !== 'undefined' ? AppNotifications : null;
  if(notifications && typeof notifications.show === 'function') notifications.show(message, type);
}

function flowAnalysisEsc(value){
  var html = typeof AppHtml !== 'undefined' ? AppHtml : null;
  if(html && typeof html.escape === 'function') return html.escape(value);
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function flowAnalysisSecurityGroup(ctx, groupId){
  if(!ctx||!groupId) return null;
  return (ctx.nsgs||[]).find(function(sg){return sg.GroupId===groupId})||null;
}

function flowAnalysisSecurityGroups(ctx, ids){
  return (ids||[]).map(function(groupId){return flowAnalysisSecurityGroup(ctx, groupId)}).filter(Boolean);
}

function flowAnalysisViewportSize(){
  var root = document.documentElement || document.body;
  var view = document.defaultView || null;
  return {
    width: (root && root.clientWidth) || (view && view.innerWidth) || 0,
    height: (root && root.clientHeight) || (view && view.innerHeight) || 0
  };
}

function discoverTrafficFlows(ctx){
  if(!ctx) return null;
  ctx=flowResourceContext(ctx);
  var hasSgData=(ctx.instances||[]).some(function(i){return (i.SecurityGroups||[]).length>0});
  var hasNaclEgress=(ctx.nacls||[]).some(function(n){return (n.Entries||[]).some(function(e){return e.Egress})});
  var ingressPaths=_findIngressPaths(ctx);
  var egressPaths=_findEgressPaths(ctx);
  var bastions=_detectBastions(ctx);
  var bastionChains=_findBastionChains(bastions,ctx);
  var accessTiers=_classifyAllResources(ctx,ingressPaths,bastionChains);
  return {ingressPaths:ingressPaths,egressPaths:egressPaths,accessTiers:accessTiers,bastionChains:bastionChains,bastions:bastions,hasSgData:hasSgData,hasNaclEgress:hasNaclEgress};
}

function _findIngressPaths(ctx){
  var paths=[];
  // Azure ingress does not require an explicit Internet Gateway resource.
  (ctx.subnets||[]).forEach(function(sub){
      var vpcId=sub.VpcId;
      // Instances in this subnet
      ((ctx.instBySub||{})[sub.SubnetId]||[]).forEach(function(inst){
        // Check common ports
        [443,80,22].forEach(function(port){
          var r=_traceInternetToResource({type:'instance',id:inst.InstanceId},{protocol:'tcp',port:port},ctx,{discovery:true});
          if(!r.blocked){
            var gn3=inst.Tags?((inst.Tags.find(function(t){return t.Key==='Name'})||{}).Value||inst.InstanceId):inst.InstanceId;
            paths.push({from:'internet',to:{type:'instance',id:inst.InstanceId},toName:gn3,path:r.path,port:port,type:'direct',vpcId:vpcId});
          }
        });
      });
      // ALBs in this subnet
      ((ctx.albBySub||{})[sub.SubnetId]||[]).forEach(function(alb){
        var albId=alb.LoadBalancerArn?alb.LoadBalancerArn.split('/').pop():'';
        var r=_traceInternetToResource({type:'alb',id:albId||alb.LoadBalancerName},{protocol:'tcp',port:443},ctx,{discovery:true});
        if(!r.blocked){
          paths.push({from:'internet',to:{type:'alb',id:albId||alb.LoadBalancerName},toName:alb.LoadBalancerName||albId,path:r.path,port:443,type:'loadbalancer',vpcId:vpcId});
        }
      });
  });
  return paths;
}

function _findEgressPaths(ctx){
  var paths=[];
  // Check all resources for egress to internet
  var checked=new Set();
  (ctx.instances||[]).forEach(function(inst){
    if(checked.has(inst.SubnetId)) return; // one per subnet suffices for egress
    var r=_traceResourceToInternet({type:'instance',id:inst.InstanceId},{protocol:'tcp',port:443},ctx,{discovery:true});
    if(!r.blocked){
      checked.add(inst.SubnetId);
      var gn3=inst.Tags?((inst.Tags.find(function(t){return t.Key==='Name'})||{}).Value||inst.InstanceId):inst.InstanceId;
      paths.push({from:{type:'instance',id:inst.InstanceId},fromName:gn3,to:'internet',subnetId:inst.SubnetId,via:r.path.some(function(h){return h.detail&&h.detail.includes('NAT')})?'nat':'igw'});
    }
  });
  return paths;
}

function _detectBastions(ctx){
  var bastions=[];
  var hasSgData=(ctx.instances||[]).some(function(i){return (i.SecurityGroups||[]).length>0});
  (ctx.instances||[]).forEach(function(inst){
    if(!ctx.pubSubs||!ctx.pubSubs.has(inst.SubnetId)) return;
    var gn3=inst.Tags?((inst.Tags.find(function(t){return t.Key==='Name'})||{}).Value||inst.InstanceId):inst.InstanceId;
    var nameMatch=/bastion|jump|ssh/i.test(gn3);
    if(hasSgData){
      var sgs=flowAnalysisSecurityGroups(ctx,(inst.SecurityGroups||[]).map(function(s){return s.GroupId}));
      var hasSSH=sgs.some(function(sg){return (sg.IpPermissions||[]).some(function(r){return r.FromPort<=22&&r.ToPort>=22})});
      if(!hasSSH&&!nameMatch) return;
    } else {
      // No SG associations: use name heuristic only
      if(!nameMatch) return;
    }
    bastions.push({type:'instance',id:inst.InstanceId,name:gn3,subnetId:inst.SubnetId,vpcId:inst.VpcId||((ctx.subnets||[]).find(function(s){return s.SubnetId===inst.SubnetId})||{}).VpcId});
  });
  return bastions;
}

function _findBastionChains(bastions,ctx){
  var chains=[];
  var hasSgData=(ctx.instances||[]).some(function(i){return (i.SecurityGroups||[]).length>0});
  // Pre-build reverse map: DBInstanceIdentifier → subnetId (O(1) lookup instead of O(n*m))
  var _rdsSubMap=new Map();Object.keys(ctx.rdsBySub||{}).forEach(function(sid){(ctx.rdsBySub[sid]||[]).forEach(function(d){_rdsSubMap.set(d.DBInstanceIdentifier,sid)})});
  bastions.forEach(function(bastion){
    var targets=[];
    var testedSubs=new Set(); // one trace per subnet to avoid O(n²)
    // Find private resources in same VPC reachable from this bastion
    (ctx.instances||[]).forEach(function(inst){
      if(inst.InstanceId===bastion.id) return;
      var instVpc=inst.VpcId||((ctx.subnets||[]).find(function(s){return s.SubnetId===inst.SubnetId})||{}).VpcId;
      if(instVpc!==bastion.vpcId) return;
      if(ctx.pubSubs&&ctx.pubSubs.has(inst.SubnetId)) return; // skip public
      var gn3=inst.Tags?((inst.Tags.find(function(t){return t.Key==='Name'})||{}).Value||inst.InstanceId):inst.InstanceId;
      if(!hasSgData){
        // Without SG data, skip trace: just include private-subnet instances (cap at 50)
        if(targets.length<50) targets.push({type:'instance',id:inst.InstanceId,name:gn3});
      } else if(!testedSubs.has(inst.SubnetId)){
        testedSubs.add(inst.SubnetId);
        var r=_traceFlowLeg({type:'instance',id:bastion.id},{type:'instance',id:inst.InstanceId},{protocol:'tcp',port:22},ctx,{discovery:true});
        if(!r.blocked) targets.push({type:'instance',id:inst.InstanceId,name:gn3});
      } else {
        // Same subnet already tested and passed: add without re-tracing
        targets.push({type:'instance',id:inst.InstanceId,name:gn3});
      }
    });
    // Check RDS
    (ctx.rdsInstances||[]).forEach(function(db){
      var rSid=_rdsSubMap.get(db.DBInstanceIdentifier);
      if(!rSid) return;
      var rVpc=((ctx.subnets||[]).find(function(s){return s.SubnetId===rSid})||{}).VpcId;
      if(rVpc!==bastion.vpcId) return;
      if(!hasSgData){
        targets.push({type:'rds',id:db.DBInstanceIdentifier,name:db.DBInstanceIdentifier});
      } else {
        var port=(db.Endpoint&&db.Endpoint.Port)||3306;
        var r=_traceFlowLeg({type:'instance',id:bastion.id},{type:'rds',id:db.DBInstanceIdentifier},{protocol:'tcp',port:port},ctx,{discovery:true});
        if(!r.blocked) targets.push({type:'rds',id:db.DBInstanceIdentifier,name:db.DBInstanceIdentifier});
      }
    });
    if(targets.length>0) chains.push({bastion:bastion,targets:targets});
  });
  return chains;
}

function _classifyAllResources(ctx,ingressPaths,bastionChains){
  var tiers={internetFacing:[],bastionOnly:[],fullyPrivate:[],database:[]};
  var ingressSet=new Set();
  ingressPaths.forEach(function(p){ingressSet.add(p.to.type+':'+p.to.id)});
  var bastionSet=new Set();
  bastionChains.forEach(function(ch){ch.targets.forEach(function(t){bastionSet.add(t.type+':'+t.id)})});
  // Classify instances
  (ctx.instances||[]).forEach(function(inst){
    var key='instance:'+inst.InstanceId;
    var gn3=inst.Tags?((inst.Tags.find(function(t){return t.Key==='Name'})||{}).Value||inst.InstanceId):inst.InstanceId;
    var ref={type:'instance',id:inst.InstanceId,name:gn3};
    if(ingressSet.has(key)){tiers.internetFacing.push(ref);return}
    if(bastionSet.has(key)){tiers.bastionOnly.push(ref);return}
    tiers.fullyPrivate.push(ref);
  });
  // Classify ALBs
  Object.keys(ctx.albBySub||{}).forEach(function(sid){
    (ctx.albBySub[sid]||[]).forEach(function(alb){
      var albId=alb.LoadBalancerArn?alb.LoadBalancerArn.split('/').pop():'';
      var key='alb:'+(albId||alb.LoadBalancerName);
      var ref={type:'alb',id:albId||alb.LoadBalancerName,name:alb.LoadBalancerName||albId};
      if(ingressSet.has(key)){tiers.internetFacing.push(ref);return}
      tiers.fullyPrivate.push(ref);
    });
  });
  // Classify RDS as database tier
  (ctx.rdsInstances||[]).forEach(function(db){
    tiers.database.push({type:'rds',id:db.DBInstanceIdentifier,name:db.DBInstanceIdentifier});
  });
  // ElastiCache as database tier
  (ctx.ecacheClusters||[]).forEach(function(ec){
    tiers.database.push({type:'ecache',id:ec.CacheClusterId,name:ec.CacheClusterId});
  });
  return tiers;
}

// --- Flow Analysis Visualization ---
function _renderFlowAnalysisOverlay(mode){
  var svg=d3.select('#mapSvg');
  svg.selectAll('.flow-analysis-layer').remove();
  // Clean up previous highlight state
  var mapRoot=svg.select('g');
  if(!mapRoot.empty()) mapRoot.classed('fa-active',false);
  document.querySelectorAll('.fa-hl-ingress,.fa-fwd-target,.fa-ingress-target,.fa-egress-source,.fa-bastion-target,.fa-flow-bright').forEach(function(el){
    el.classList.remove('fa-hl-ingress','fa-fwd-target','fa-ingress-target','fa-egress-source','fa-bastion-target','fa-flow-bright');
  });
  var inetNode=document.querySelector('.internet-node');
  if(inetNode) d3.select(inetNode).style('opacity',null).style('filter',null);
  document.querySelectorAll('.gw-node').forEach(function(el){d3.select(el).style('filter',null).style('opacity',null)});
  if(!_flowAnalysisCache||!mode) return;
  var ctx=flowAnalysisRuntimeData();
  if(!ctx) return;
  var g=mapRoot.empty()?svg:mapRoot;
  // Insert flow layer BEFORE nodes-layer so arrows render behind VPCs/subnets/resources
  var nodesLayer=g.select('.nodes-layer');
  var faG=nodesLayer.empty()?g.append('g').attr('class','flow-analysis-layer'):g.insert('g','.nodes-layer').attr('class','flow-analysis-layer');
  // Dim map for modes that highlight route lines
  var needDim=(mode==='ingress'||mode==='egress'||mode==='bastion'||mode==='all');
  if(needDim&&!mapRoot.empty()) mapRoot.classed('fa-active',true);
  if(mode==='tiers'||mode==='all') _renderTierBadges(faG,ctx);
  if(mode==='ingress'||mode==='all') _renderIngressArrows(faG,ctx);
  if(mode==='egress'||mode==='all') _renderEgressArrows(faG,ctx);
  if(mode==='bastion'||mode==='all') _renderBastionArrows(faG,ctx);
}

function _renderTierBadges(faG,ctx){
  var colors={internetFacing:'#10b981',bastionOnly:'#22d3ee',fullyPrivate:'#8b5cf6',database:'#f59e0b'};
  // Deduplicate by subnet: one badge per (subnet, tier) to avoid hundreds of overlapping dots
  var subTierSeen=new Set();
  Object.keys(_flowAnalysisCache.accessTiers).forEach(function(tier){
    (_flowAnalysisCache.accessTiers[tier]||[]).forEach(function(ref){
      var pos=_resolveNetworkPosition(ref.type, ref.id, ctx);
      if(!pos||!pos.subnetId) return;
      var key=pos.subnetId+':'+tier;
      if(subTierSeen.has(key)) return;
      subTierSeen.add(key);
      var c=_getSubnetCenter(pos.subnetId);
      if(!c) return;
      // Offset badges by tier type so they don't overlap
      var idx=['internetFacing','bastionOnly','fullyPrivate','database'].indexOf(tier);
      faG.append('circle').attr('class','tier-badge').attr('cx',c.x+12+idx*14).attr('cy',c.y-12).attr('r',6)
        .attr('fill',colors[tier]||'#6b7280').attr('stroke','#1a1a2e').attr('stroke-width',1.5);
    });
  });
}

function _renderIngressArrows(faG,ctx){
  if(!ctx) return;
  var sg=document.querySelector('.struct-group');
  if(!sg) return;
  // Collect unique (igwId, subnetId, vpcId) combos from ingress paths
  var seen=new Set();
  var hlEls=[];
  // Track ALB→backend forwarding for arrows
  var fwdLinks=[];
  // Track IGW→subnet pairs for flow arrows
  var igwToSubs={};  // igwId → Set of subnetIds
  (_flowAnalysisCache.ingressPaths||[]).forEach(function(p){
    var pos=_resolveNetworkPosition(p.to.type, p.to.id, ctx);
    if(!pos||!pos.subnetId||!pos.vpcId) return;
    var igw=(ctx.firewalls||[]).find(function(g){return (g.Attachments||[]).some(function(a){return a.VpcId===pos.vpcId})});
    if(!igw) return;
    var gid=igw.InternetGatewayId;
    var key=gid+':'+pos.subnetId;
    if(seen.has(key)) return;
    seen.add(key);
    // Track IGW→subnet for flow arrows
    if(!igwToSubs[gid]) igwToSubs[gid]=new Set();
    igwToSubs[gid].add(pos.subnetId);
    // For ALB ingress, trace forwarding to backend subnets
    if(p.type==='loadbalancer'&&p.to.type==='alb'){
      var alb2=null;
      Object.keys(ctx.albBySub||{}).forEach(function(sid){
        (ctx.albBySub[sid]||[]).forEach(function(a){
          var aid=a.LoadBalancerArn?a.LoadBalancerArn.split('/').pop():'';
          if(aid===p.to.id||a.LoadBalancerName===p.to.id) alb2=a;
        });
      });
      if(alb2&&alb2.LoadBalancerArn){
        var tgs2=(ctx.tgByAlb||{})[alb2.LoadBalancerArn]||[];
        var backendSubs=new Set();
        tgs2.forEach(function(tg){
          (tg.Targets||[]).forEach(function(t){
            var tPos=_resolveNetworkPosition('instance',t.Id,ctx);
            if(tPos&&tPos.subnetId&&tPos.subnetId!==pos.subnetId){
              backendSubs.add(tPos.subnetId);
            }
          });
        });
        backendSubs.forEach(function(bSid){
          fwdLinks.push({fromSub:pos.subnetId,toSub:bSid,albName:alb2.LoadBalancerName||p.to.id});
        });
      }
    }
  });
  // Collect ingress subnet IDs and VPC gateway IDs
  var hasIngress=seen.size>0;
  var ingressSubs=new Set();
  var ingressGids=new Set();
  seen.forEach(function(key){var parts=key.split(':');ingressGids.add(parts[0]);ingressSubs.add(parts[1])});
  // Glow on internet node
  var inetNode=document.querySelector('.internet-node');
  if(inetNode&&hasIngress) d3.select(inetNode).style('opacity','1').style('filter','drop-shadow(0 0 6px rgba(16,185,129,.6))');
  // Bright green fill + glow on public subnet boxes
  ingressSubs.forEach(function(sid){
    var subNode=document.querySelector('.subnet-node[data-subnet-id="'+sid+'"]');
    if(!subNode) return;
    d3.select(subNode).classed('fa-flow-bright',true);
    var subEl=subNode.querySelector('rect');
    if(subEl) d3.select(subEl).classed('fa-ingress-target',true);
  });
  // Glow on IGW icons
  ingressGids.forEach(function(gid){
    var gwNode=document.querySelector('.gw-node[data-gwid="'+gid+'"]');
    if(gwNode) d3.select(gwNode).style('filter','drop-shadow(0 0 8px rgba(16,185,129,.8))').style('opacity','1');
  });
  // Draw backbone: Internet → backbone → drops to each gateway
  var inetNode2=document.querySelector('.internet-node');
  var inetCircle=inetNode2?inetNode2.querySelector('circle'):null;
  var inetPos=null;
  if(inetCircle){var ib=inetCircle.getBBox();inetPos={x:ib.x+ib.width/2,y:ib.y+ib.height/2}}
  var gwPosList=[];
  ingressGids.forEach(function(gid){
    var gwNode2=document.querySelector('.gw-node[data-gwid="'+gid+'"]');
    var gwCircle=gwNode2?gwNode2.querySelector('circle'):null;
    if(!gwCircle) return;
    var cb=gwCircle.getBBox();
    gwPosList.push({gid:gid,cx:cb.x+cb.width/2,cy:cb.y+cb.height/2});
  });
  _drawFlowBackbone(faG,gwPosList,inetPos,{
    color:'#10b981',backboneCls:'flow-ingress-backbone',
    dropCls:'flow-ingress-arrow',arrowMarker:'url(#ingress-arrow-head)',
    inbound:true
  });
  // Draw direct per-hop arrows: each gateway → its subnets
  Object.keys(igwToSubs).forEach(function(gid){
    var gwNode2=document.querySelector('.gw-node[data-gwid="'+gid+'"]');
    var gwPos2=null;
    if(gwNode2){var c=gwNode2.querySelector('circle');if(c){var cb2=c.getBBox();gwPos2={x:cb2.x+cb2.width/2,y:cb2.y+cb2.height/2}}}
    if(!gwPos2) return;
    igwToSubs[gid].forEach(function(sid){
      var rect=document.querySelector('.subnet-node[data-subnet-id="'+sid+'"] rect');
      if(!rect) return;
      var bb=rect.getBBox();
      var subCy=bb.y+bb.height/2;
      var subEdgeX=(bb.x+bb.width/2)<gwPos2.x?bb.x+bb.width:bb.x;
      var gwEdge=_circleEdge(gwPos2.x,gwPos2.y,26,subEdgeX,subCy);
      _drawFlowHop(faG,gwEdge,{x:subEdgeX,y:subCy},{
        cssClass:'flow-ingress-arrow',marker:'url(#ingress-branch-head)'
      });
    });
  });
  // Draw ALB→backend forwarding arrows
  if(fwdLinks.length>0) _renderForwardingArrows(faG,fwdLinks);
}

// --- Flow Primitives (composable building blocks) ---

// === Flow Pathing Engine ===
// Data-driven pathing: every path drawn FROM→TO in traffic direction.
// No animation-direction hacks: direction is baked into the SVG `d` attribute.

const FP_GR=20;           // gateway circle radius (matches topology-renderer GR)
const FP_TRUNK_OFFSET=20; // base distance from subnet edge to first trunk
const FP_TRUNK_SPACE=12;  // spacing between parallel trunks
const FP_BUFFER=8;        // minimum clearance from element edges
const FP_JUNC=3;          // junction patch half-size (6x6 squares)

// Layer 1: Build directed flow graph from egress discovery data.
// Returns { gwGroups: {gwId: {subs:[], vpcId, isNat, upstreamIgw}}, internetGids: Set }
function _buildFlowGraph(cache,ctx){
  var gwGroups={};
  var internetGids=new Set();
  var seen=new Set();
  var warnings=[];
  (cache.egressPaths||[]).forEach(function(p){
    var pos=_resolveNetworkPosition(p.from.type,p.from.id,ctx);
    if(!pos||!pos.subnetId||!pos.vpcId) return;
    if(seen.has(pos.subnetId)) return;
    seen.add(pos.subnetId);
    // Primary: evaluate route table for this subnet's default route
    var gid=null;
    var rt=ctx.subRT?ctx.subRT[pos.subnetId]:null;
    if(rt){
      var ev=evaluateRouteTable(rt,'0.0.0.0/0');
      if(ev.type==='igw'||ev.type==='nat') gid=ev.target;
    }
    // Fallback: query structural elements
    if(!gid){
      var sg=document.querySelector('.struct-group');
      if(sg){
        var cands=sg.querySelectorAll('[data-sid="'+pos.subnetId+'"][data-gid]');
        for(let ci=0;ci<cands.length;ci++){
          var cGid=cands[ci].getAttribute('data-gid');
          if(cGid&&(cGid.startsWith('igw')||cGid.startsWith('nat'))){gid=cGid;break}
        }
      }
    }
    // Last resort: VPC-level gateway lookup
    if(!gid){
      if(p.via==='nat'){
        var nat=(ctx.nats||[]).find(function(n){
          var nSub=((ctx.subnets||[]).find(function(s){return s.SubnetId===n.SubnetId})||{});
          return nSub.VpcId===pos.vpcId;
        });
        if(nat) gid=nat.NatGatewayId;
      }
      if(!gid){
        var igw=(ctx.igws||[]).find(function(g){return (g.Attachments||[]).some(function(a){return a.VpcId===pos.vpcId})});
        if(igw) gid=igw.InternetGatewayId;
      }
    }
    if(!gid){warnings.push('No gateway for subnet '+pos.subnetId);return}
    internetGids.add(gid);
    var isNat=gid.startsWith('nat');
    if(!gwGroups[gid]) gwGroups[gid]={subs:[],vpcId:pos.vpcId,isNat:isNat,upstreamIgw:null};
    gwGroups[gid].subs.push(pos.subnetId);
    // For NAT gateways, find upstream IGW
    if(isNat&&!gwGroups[gid].upstreamIgw){
      var uIgw=(ctx.igws||[]).find(function(g){return (g.Attachments||[]).some(function(a){return a.VpcId===pos.vpcId})});
      if(uIgw) gwGroups[gid].upstreamIgw=uIgw.InternetGatewayId;
    }
  });
  // Validation
  if(warnings.length>0) console.warn('[FlowEngine]',warnings.join('; '));
  var gwCount=Object.keys(gwGroups).length;
  if(gwCount===0) console.warn('[FlowEngine] No egress gateways found');
  return {gwGroups:gwGroups,internetGids:internetGids};
}

// Layer 2: Compute positioned path segments from the flow graph.
// Returns array of {d, cssClass, marker, isJunction}
function _layoutFlowPaths(gwGroups){
  var segments=[];
  // Collect ALL gateway circle positions for collision avoidance
  var allGwPos=[];
  document.querySelectorAll('.gw-node').forEach(function(gn){
    var c=gn.querySelector('circle');
    if(!c) return;
    var bb=c.getBBox();
    allGwPos.push({id:gn.getAttribute('data-gwid'),x:bb.x+bb.width/2,y:bb.y+bb.height/2});
  });
  // Process each gateway group
  var gwIds=Object.keys(gwGroups);
  gwIds.forEach(function(gid,gwIdx){
    var grp=gwGroups[gid];
    var cssClass=grp.isNat?'flow-egress-nat':'flow-egress-igw';
    // Query gateway position
    var gwNode=document.querySelector('.gw-node[data-gwid="'+gid+'"]');
    var gwCircle=gwNode?gwNode.querySelector('circle'):null;
    if(!gwCircle) return;
    var gcb=gwCircle.getBBox();
    var gwCX=gcb.x+gcb.width/2,gwCY=gcb.y+gcb.height/2;
    // Query subnet positions
    var subPos=[];
    grp.subs.forEach(function(sid){
      var rect=document.querySelector('.subnet-node[data-subnet-id="'+sid+'"] rect');
      if(!rect) return;
      var bb=rect.getBBox();
      subPos.push({sid:sid,x:bb.x,y:bb.y,w:bb.width,h:bb.height,cy:bb.y+bb.height/2});
    });
    if(subPos.length===0) return;
    // Determine gateway side (left or right of subnets)
    var avgSubCX=0;
    subPos.forEach(function(s){avgSubCX+=s.x+s.w/2});
    avgSubCX/=subPos.length;
    var gwRight=gwCX>avgSubCX;
    // Compute trunk X with per-gateway offset
    var trunkX;
    if(gwRight){
      var maxRight=0;
      subPos.forEach(function(s){if(s.x+s.w>maxRight) maxRight=s.x+s.w});
      trunkX=Math.round(maxRight+FP_TRUNK_OFFSET+gwIdx*FP_TRUNK_SPACE);
    }else{
      var minLeft=Infinity;
      subPos.forEach(function(s){if(s.x<minLeft) minLeft=s.x});
      trunkX=Math.round(minLeft-FP_TRUNK_OFFSET-gwIdx*FP_TRUNK_SPACE);
    }
    // Sort subnets by Y for ordered processing
    subPos.sort(function(a,b){return a.cy-b.cy});
    // Other gateway positions for collision avoidance on branches
    var vpcGwPos=allGwPos.filter(function(g){return g.id!==gid});
    var branchInfos=subPos.map(function(s){
      var subEdgeX=gwRight?(s.x+s.w):(s.x);
      var branchY=s.cy;
      var crossGw=_findFlowBranchCrossing(vpcGwPos,subEdgeX,trunkX,branchY,gwRight);
      var junctionY=branchY;
      var d;
      if(crossGw){
        // Jog around the crossing gateway while keeping the branch orthogonal.
        junctionY=branchY<crossGw.y?(crossGw.y-FP_GR-10):(crossGw.y+FP_GR+10);
        var clearX=gwRight?(crossGw.x+FP_GR+6):(crossGw.x-FP_GR-6);
        d='M'+subEdgeX+','+branchY+' L'+clearX+','+branchY+' L'+clearX+','+junctionY+' L'+trunkX+','+junctionY;
      }else{
        d='M'+subEdgeX+','+branchY+' L'+trunkX+','+branchY;
      }
      return {subnet:s,subEdgeX:subEdgeX,junctionY:junctionY,d:d};
    });
    // --- Generate branch segments (subnet → trunk) ---
    branchInfos.forEach(function(info){
      segments.push({d:info.d,cssClass:cssClass,marker:null,isJunction:false});
      // Junction patch at trunk intersection
      var jY=info.junctionY;
      var jd='M'+(trunkX-FP_JUNC)+','+(jY-FP_JUNC)+' L'+(trunkX+FP_JUNC)+','+(jY-FP_JUNC)+' L'+(trunkX+FP_JUNC)+','+(jY+FP_JUNC)+' L'+(trunkX-FP_JUNC)+','+(jY+FP_JUNC)+' Z';
      segments.push({d:jd,cssClass:cssClass,marker:null,isJunction:true,fill:grp.isNat?'#a78bfa':'#fb923c'});
    });
    // --- Generate clean trunk segments (split once above/below gateway) ---
    // Previous rendering drew one full branch→gateway trunk for each subnet, which
    // stacked duplicate dashed paths on top of each other and made busy branches
    // look thicker/blurry.  Collapse the shared trunk into at most two directed
    // spans: upper branches flowing down to the gateway and lower branches
    // flowing up to the gateway.
    var aboveYs=branchInfos.map(function(i){return i.junctionY}).filter(function(y){return y<gwCY-2});
    var belowYs=branchInfos.map(function(i){return i.junctionY}).filter(function(y){return y>gwCY+2});
    if(aboveYs.length>0){
      var topY=Math.min.apply(null,aboveYs);
      segments.push({d:'M'+trunkX+','+topY+' L'+trunkX+','+gwCY,cssClass:cssClass,marker:null,isJunction:false});
    }
    if(belowYs.length>0){
      var bottomY=Math.max.apply(null,belowYs);
      segments.push({d:'M'+trunkX+','+bottomY+' L'+trunkX+','+gwCY,cssClass:cssClass,marker:null,isJunction:false});
    }
    // --- Gateway connector (trunk → gateway circle edge) ---
    var gwEdge=_circleEdge(gwCX,gwCY,FP_GR+4,trunkX,gwCY);
    var cd='M'+trunkX+','+gwCY+' L'+gwEdge.x+','+gwEdge.y;
    segments.push({d:cd,cssClass:cssClass,marker:'url(#egress-arrow-head)',isJunction:false});
    // Junction patch at gateway connector
    var gjd='M'+(trunkX-FP_JUNC)+','+(gwCY-FP_JUNC)+' L'+(trunkX+FP_JUNC)+','+(gwCY-FP_JUNC)+' L'+(trunkX+FP_JUNC)+','+(gwCY+FP_JUNC)+' L'+(trunkX-FP_JUNC)+','+(gwCY+FP_JUNC)+' Z';
    segments.push({d:gjd,cssClass:cssClass,marker:null,isJunction:true,fill:grp.isNat?'#a78bfa':'#fb923c'});
  });
  return segments;
}


function _findFlowBranchCrossing(gatewayPositions,subEdgeX,trunkX,branchY,gwRight){
  var crossGw=null;
  gatewayPositions.forEach(function(g){
    if(Math.abs(g.y-branchY)>=FP_GR+FP_BUFFER) return;
    if(gwRight&&g.x>subEdgeX&&g.x<trunkX) crossGw=g;
    if(!gwRight&&g.x<subEdgeX&&g.x>trunkX) crossGw=g;
  });
  return crossGw;
}

// Layer 3: Render path segments as SVG elements.
// Every d attribute is FROM→TO: animation is always 'normal'.
function _renderFlowSegments(faG,segments){
  segments.forEach(function(seg){
    var p=faG.append('path').attr('class',seg.cssClass).attr('d',seg.d);
    if(seg.marker) p.attr('marker-end',seg.marker);
    if(seg.isJunction){
      p.style('stroke-dasharray','none').style('opacity','1');
      if(seg.fill) p.attr('fill',seg.fill);
    }
  });
}

// Draw an L-shaped flow arrow between two points.
// from/to: {x,y}: start and end positions
// opts: {cssClass, marker}
function _drawFlowHop(faG,from,to,opts){
  if(!from||!to) return;
  var cls=opts.cssClass||'flow-ingress-arrow';
  var marker=opts.marker||null;
  var d;
  if(Math.abs(from.y-to.y)<3||Math.abs(from.x-to.x)<3){
    // Nearly aligned: straight line
    d='M'+from.x+','+from.y+' L'+to.x+','+to.y;
  } else {
    // Stepped orthogonal: horizontal → vertical → horizontal through midpoint
    var midX=(from.x+to.x)/2;
    d='M'+from.x+','+from.y+' L'+midX+','+from.y+' L'+midX+','+to.y+' L'+to.x+','+to.y;
  }
  var p=faG.append('path').attr('class',cls).attr('d',d);
  if(marker) p.attr('marker-end',marker);
  return p;
}

// Draw a backbone + drops + internet icon connecting gateways to the internet.
// gwPositions: [{gid, cx, cy}]: gateway icon centers
// inetPos: {x,y} or null: internet node center
// opts: {color, backboneCls, dropCls, arrowMarker, backboneYOffset, inbound}
function _drawFlowBackbone(faG,gwPositions,inetPos,opts){
  if(!gwPositions||gwPositions.length===0) return;
  var color=opts.color||'#10b981';
  var bbCls=opts.backboneCls||'flow-ingress-backbone';
  var dropCls=opts.dropCls||'flow-ingress-arrow';
  var marker=opts.arrowMarker||null;
  var yOffset=opts.backboneYOffset||0;
  var inbound=opts.inbound||false;
  // Backbone Y from net-vert element
  var backboneY=-20;
  var netVert=document.querySelector('[data-net-vert]');
  if(netVert){var dd=netVert.getAttribute('d');var mm=dd.match(/[ML][\d.]+,([-\d.]+)/);if(mm) backboneY=parseFloat(mm[1])}
  backboneY+=yOffset;
  gwPositions.sort(function(a,b){return a.cx-b.cx});
  var inetX=inetPos?inetPos.x:gwPositions[0].cx;
  var inetY=inetPos?inetPos.y:backboneY;
  var farGwX=gwPositions[gwPositions.length-1].cx;
  // Horizontal backbone (direction matches traffic flow)
  var hBB=inbound?('M'+inetX+','+backboneY+' L'+farGwX+','+backboneY):('M'+farGwX+','+backboneY+' L'+inetX+','+backboneY);
  var bbPath=faG.append('path').attr('class',bbCls).attr('d',hBB);
  if(marker) bbPath.attr('marker-end',marker);
  // Vertical leg between backbone and internet icon
  if(inetPos&&Math.abs(inetY-backboneY)>2){
    var vLeg=inbound?('M'+inetX+','+inetY+' L'+inetX+','+backboneY):('M'+inetX+','+backboneY+' L'+inetX+','+inetY);
    faG.append('path').attr('class',bbCls).attr('d',vLeg);
  }
  // Internet icon
  if(inetPos){
    var ig=faG.append('g').attr('class','flow-inet-icon');
    ig.append('circle').attr('cx',inetPos.x).attr('cy',inetPos.y).attr('r',42)
      .attr('fill','none').attr('stroke',color).attr('stroke-width',2).attr('opacity',.3);
    ig.append('circle').attr('cx',inetPos.x).attr('cy',inetPos.y).attr('r',36)
      .attr('fill','rgba('+_hexToRgb(color)+',.1)').attr('stroke',color).attr('stroke-width',2);
    ig.append('circle').attr('cx',inetPos.x).attr('cy',inetPos.y).attr('r',5)
      .attr('fill',color);
    ig.append('text').attr('x',inetPos.x).attr('y',inetPos.y+52)
      .attr('text-anchor','middle').attr('fill',color).attr('font-size','11px')
      .attr('font-family','Segoe UI,system-ui,sans-serif').text('Internet');
    ig.style('filter','drop-shadow(0 0 10px rgba('+_hexToRgb(color)+',.8))');
  }
  // Drop lines between each gateway and backbone
  gwPositions.forEach(function(p){
    faG.append('circle').attr('cx',p.cx).attr('cy',backboneY).attr('r',4)
      .attr('fill',color).attr('stroke','none');
    var dropD=inbound?('M'+p.cx+','+backboneY+' L'+p.cx+','+p.cy):('M'+p.cx+','+p.cy+' L'+p.cx+','+backboneY);
    var dropPath=faG.append('path').attr('class',dropCls).attr('d',dropD);
    if(marker) dropPath.attr('marker-end',marker);
  });
}

// Helper: convert hex color to r,g,b string
function _hexToRgb(hex){
  var r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);
  return r+','+g+','+b;
}

// Helper: compute point on circle boundary closest to a target point.
// Used so arrows start/end at the circle edge, not the center.
function _circleEdge(cx,cy,r,tx,ty){
  var dx=tx-cx,dy=ty-cy,dist=Math.sqrt(dx*dx+dy*dy)||1;
  return {x:cx+(dx/dist)*r,y:cy+(dy/dist)*r};
}

function _drawBusTopology(faG,opts){
  var subs=opts.subnets;
  if(!subs||subs.length===0) return;
  var tx=opts.trunkX;
  // Compute trunk Y range: always includes gateway to prevent dead ends
  var ys=subs.map(function(s){return s.cy});
  if(opts.gwPos) ys.push(opts.gwPos.y);
  var startY=opts.trunkStartY!=null?Math.min(opts.trunkStartY,Math.min.apply(null,ys)):Math.min.apply(null,ys);
  var endY=opts.trunkEndY!=null?Math.max(opts.trunkEndY,Math.max.apply(null,ys)):Math.max.apply(null,ys);
  // 1. Vertical trunk: split at gateway Y so dashes converge toward the gateway
  var gwY=opts.gwPos?opts.gwPos.y:null;
  if(gwY!=null&&startY<gwY&&endY>gwY){
    // Split: upper half (top→gwY, dashes flow down) + lower half (bottom→gwY, dashes flow up)
    var upperD='M'+tx+','+startY+' L'+tx+','+gwY;
    var lowerD='M'+tx+','+endY+' L'+tx+','+gwY;
    var up=faG.append('path').attr('class',opts.pathClass).attr('d',upperD);
    var lo=faG.append('path').attr('class',opts.pathClass).attr('d',lowerD);
    if(opts.trunkStyle){Object.keys(opts.trunkStyle).forEach(function(k){up.style(k,opts.trunkStyle[k]);lo.style(k,opts.trunkStyle[k])})}
  } else {
    // Single segment: draw toward gateway end if trunkReverse set
    var trunkD=opts.trunkReverse?('M'+tx+','+endY+' L'+tx+','+startY):('M'+tx+','+startY+' L'+tx+','+endY);
    var trunkPath=faG.append('path').attr('class',opts.pathClass).attr('d',trunkD);
    if(opts.trunkStyle){Object.keys(opts.trunkStyle).forEach(function(k){trunkPath.style(k,opts.trunkStyle[k])})}
  }
  // 2. Gateway connector
  if(opts.gwPos){
    var gwFromX,gwToX;
    if(opts.gwDirection==='toTrunk'){gwFromX=opts.gwPos.x;gwToX=tx}
    else{gwFromX=tx;gwToX=opts.gwPos.x}
    var gp=faG.append('path').attr('class',opts.gwClass||opts.pathClass)
      .attr('d','M'+gwFromX+','+opts.gwPos.y+' L'+gwToX+','+opts.gwPos.y);
    if(opts.gwMarker) gp.attr('marker-end',opts.gwMarker);
  }
  // 3. Branches: continuous from trunk to subnet edge (no gaps)
  subs.forEach(function(sp,idx){
    var subEdgeX=(sp.x+sp.w/2)<tx?sp.x+sp.w:sp.x;
    var fromX,toX;
    if(opts.branchDirection==='toTrunk'){fromX=subEdgeX;toX=tx}
    else{fromX=tx;toX=subEdgeX}
    var bp=faG.append('path').attr('class',opts.pathClass)
      .attr('d','M'+fromX+','+sp.cy+' L'+toX+','+sp.cy);
    if(opts.branchMarker) bp.attr('marker-end',opts.branchMarker);
    if(opts.onBranch) opts.onBranch(sp,idx,subEdgeX);
  });
}

function _renderForwardingArrows(faG,fwdLinks){
  var drawn=new Set();
  var targetSubs=new Set();
  // Cache VPC bounding boxes for spatial lookup
  var vpcBounds=[];
  document.querySelectorAll('.vpc-group').forEach(function(vg){
    var r=vg.querySelector('rect');
    if(r){var b=r.getBBox();vpcBounds.push({left:b.x,right:b.x+b.width,top:b.y,bottom:b.y+b.height})}
  });
  function findVpcBB(pt){
    for(let i=0;i<vpcBounds.length;i++){
      var v=vpcBounds[i];
      if(pt.x>=v.left&&pt.x<=v.right&&pt.y>=v.top&&pt.y<=v.bottom) return v;
    }
    return null;
  }
  fwdLinks.forEach(function(lnk){
    var key=lnk.fromSub+'>'+lnk.toSub;
    if(drawn.has(key)) return;
    drawn.add(key);
    var fc=_getSubnetCenter(lnk.fromSub);
    var tc=_getSubnetCenter(lnk.toSub);
    if(!fc||!tc) return;
    targetSubs.add(lnk.toSub);
    var fromRect=document.querySelector('.subnet-node[data-subnet-id="'+lnk.fromSub+'"] rect');
    var toRect=document.querySelector('.subnet-node[data-subnet-id="'+lnk.toSub+'"] rect');
    var fBB=fromRect?fromRect.getBBox():null;
    var tBB=toRect?toRect.getBBox():null;
    // Find VPC boundary spatially
    var vpcBB=findVpcBB(fc);
    var pathD;
    if(vpcBB && Math.abs(fc.x-tc.x)<100){
      // Same column: route outside VPC boundary with L-shape
      var vpcLeft=vpcBB.left;
      var vpcRight=vpcBB.right;
      var distToLeft=fc.x-vpcLeft;
      var distToRight=vpcRight-fc.x;
      var outsideX=distToLeft<distToRight?vpcLeft-30:vpcRight+30;
      var r=16;
      var dirV=tc.y<fc.y?-1:1;
      var dirH=outsideX<fc.x?-1:1;
      var fromEdgeX=fBB?(dirH<0?fBB.x:fBB.x+fBB.width):fc.x;
      var toEdgeX=tBB?(dirH<0?tBB.x:tBB.x+tBB.width):tc.x;
      r=Math.min(r,Math.abs(fc.y-tc.y)/2,Math.abs(outsideX-fromEdgeX)/2);
      if(r<2) r=0;
      pathD='M'+fromEdgeX+','+fc.y;
      if(r>0){
        pathD+=' L'+(outsideX-dirH*r)+','+fc.y;
        pathD+=' Q'+outsideX+','+fc.y+' '+outsideX+','+(fc.y+dirV*r);
      } else { pathD+=' L'+outsideX+','+fc.y; }
      if(r>0){
        pathD+=' L'+outsideX+','+(tc.y-dirV*r);
        pathD+=' Q'+outsideX+','+tc.y+' '+(outsideX-dirH*r)+','+tc.y;
      } else { pathD+=' L'+outsideX+','+tc.y; }
      pathD+=' L'+toEdgeX+','+tc.y;
    } else {
      // Different columns: curved path offset away from center
      var dx=tc.x-fc.x,dy=tc.y-fc.y;
      var dist=Math.sqrt(dx*dx+dy*dy)||1;
      var perpX=(-dy/dist)*30;
      var perpY=(dx/dist)*30;
      var mid={x:(fc.x+tc.x)/2+perpX,y:(fc.y+tc.y)/2+perpY};
      pathD='M'+fc.x+','+fc.y+' Q'+mid.x+','+mid.y+' '+tc.x+','+tc.y;
    }
    faG.append('path').attr('class','flow-fwd-arrow')
      .attr('d',pathD)
      .attr('marker-end','url(#fwd-arrow-head)');
  });
  // Add glow to target subnet boxes
  targetSubs.forEach(function(sid){
    var subNode=document.querySelector('.subnet-node[data-subnet-id="'+sid+'"]');
    if(!subNode) return;
    d3.select(subNode).classed('fa-flow-bright',true);
    var subEl=subNode.querySelector('rect');
    if(subEl) d3.select(subEl).classed('fa-fwd-target',true);
  });
  // Ensure arrowhead marker exists
  var svg=d3.select('#mapSvg');
  var defs=svg.select('defs');
  if(defs.empty()) defs=svg.append('defs');
  if(defs.select('#fwd-arrow-head').empty()){
    defs.append('marker').attr('id','fwd-arrow-head')
      .attr('viewBox','0 0 10 10').attr('refX',9).attr('refY',5)
      .attr('markerWidth',7).attr('markerHeight',7).attr('markerUnits','userSpaceOnUse')
      .attr('orient','auto-start-reverse')
      .append('path').attr('d','M 0 0 L 10 5 L 0 10 z').attr('fill','#10b981');
  }
}

function _renderEgressArrows(faG,ctx){
  if(!ctx) return;
  // Ensure egress arrowhead marker
  var svg=d3.select('#mapSvg');
  var defs=svg.select('defs');
  if(defs.empty()) defs=svg.append('defs');
  if(defs.select('#egress-arrow-head').empty()){
    defs.append('marker').attr('id','egress-arrow-head')
      .attr('viewBox','0 0 10 10').attr('refX',9).attr('refY',5)
      .attr('markerWidth',9).attr('markerHeight',9).attr('markerUnits','userSpaceOnUse')
      .attr('orient','auto-start-reverse')
      .append('path').attr('d','M 0 0 L 10 5 L 0 10 z').attr('fill','#fb923c');
  }
  // Layer 1: Build flow graph from data
  var graph=_buildFlowGraph(_flowAnalysisCache,ctx);
  // Layer 2: Compute path segments
  var segments=_layoutFlowPaths(graph.gwGroups);
  // Layer 3: Render SVG paths
  _renderFlowSegments(faG,segments);
  // Glow on egress gateway icons
  graph.internetGids.forEach(function(gid){
    var gwNode=document.querySelector('.gw-node[data-gwid="'+gid+'"]');
    if(gwNode) d3.select(gwNode).style('filter','drop-shadow(0 0 8px rgba(251,146,60,.8))').style('opacity','1');
  });
  // Highlight egress subnet boxes
  var allSubs=new Set();
  Object.keys(graph.gwGroups).forEach(function(gid){
    graph.gwGroups[gid].subs.forEach(function(sid){allSubs.add(sid)});
  });
  allSubs.forEach(function(sid){
    var subNode=document.querySelector('.subnet-node[data-subnet-id="'+sid+'"]');
    if(!subNode) return;
    d3.select(subNode).classed('fa-flow-bright',true);
    var subEl=subNode.querySelector('rect');
    if(subEl) d3.select(subEl).classed('fa-egress-source',true);
  });
  // Draw egress backbone: gateways → backbone → Internet
  var inetNode2=document.querySelector('.internet-node');
  var inetCircle2=inetNode2?inetNode2.querySelector('circle'):null;
  var inetPos2=null;
  if(inetCircle2){var ib2=inetCircle2.getBBox();inetPos2={x:ib2.x+ib2.width/2,y:ib2.y+ib2.height/2}}
  var gwPosList2=[];
  graph.internetGids.forEach(function(gid){
    if(gid.startsWith('nat')) return; // NAT routes through IGW: skip to avoid overlapping drops
    var gwNode2=document.querySelector('.gw-node[data-gwid="'+gid+'"]');
    var gwCircle2=gwNode2?gwNode2.querySelector('circle'):null;
    if(!gwCircle2) return;
    var cb2=gwCircle2.getBBox();
    gwPosList2.push({gid:gid,cx:cb2.x+cb2.width/2,cy:cb2.y+cb2.height/2});
  });
  _drawFlowBackbone(faG,gwPosList2,inetPos2,{
    color:'#fb923c',backboneCls:'flow-egress-backbone',
    dropCls:'flow-egress-arrow',arrowMarker:'url(#egress-arrow-head)',
    backboneYOffset:16
  });
  // Redraw TGW connections into flow layer so they appear above dimmed structural routes
  var tgwPaths=document.querySelectorAll('.route-group path.route-trunk[stroke="var(--tgw-color)"]');
  if(tgwPaths.length>0){
    var tgwG=faG.append('g').attr('class','flow-tgw-overlay');
    tgwPaths.forEach(function(p){
      tgwG.append('path').attr('d',p.getAttribute('d'))
        .attr('class','flow-egress-tgw')
        .attr('stroke-width',p.getAttribute('stroke-width')||2)
        .attr('fill','none');
    });
  }
}

function _renderBastionArrows(faG,ctx){
  if(!ctx) return;
  // Ensure bastion arrowhead markers
  var svg=d3.select('#mapSvg');
  var defs=svg.select('defs');
  if(defs.empty()) defs=svg.append('defs');
  if(defs.select('#bastion-arrow-head').empty()){
    defs.append('marker').attr('id','bastion-arrow-head')
      .attr('viewBox','0 0 10 10').attr('refX',9).attr('refY',5)
      .attr('markerWidth',7).attr('markerHeight',7).attr('markerUnits','userSpaceOnUse')
      .attr('orient','auto-start-reverse')
      .append('path').attr('d','M 0 0 L 10 5 L 0 10 z').attr('fill','#22d3ee');
  }
  // Cache VPC bounding boxes
  var vpcBounds={};
  document.querySelectorAll('.vpc-group').forEach(function(vg){
    var r=vg.querySelector('rect');
    var vid=vg.getAttribute('data-vnet-id');
    if(r&&vid){var b=r.getBBox();vpcBounds[vid]={left:b.x,right:b.x+b.width,top:b.y,bottom:b.y+b.height}}
  });
  (_flowAnalysisCache.bastionChains||[]).forEach(function(ch){
    var bPos=_resolveNetworkPosition(ch.bastion.type, ch.bastion.id, ctx);
    if(!bPos||!bPos.subnetId) return;
    var bastionRect=document.querySelector('.subnet-node[data-subnet-id="'+bPos.subnetId+'"] rect');
    if(!bastionRect) return;
    var bbb=bastionRect.getBBox();
    var bastionSub={x:bbb.x,y:bbb.y,w:bbb.width,h:bbb.height,cy:bbb.y+bbb.height/2};
    // Highlight bastion subnet (cyan)
    var bSubNode=document.querySelector('.subnet-node[data-subnet-id="'+bPos.subnetId+'"]');
    if(bSubNode){
      d3.select(bSubNode).classed('fa-flow-bright',true);
      d3.select(bastionRect).classed('fa-ingress-target',true);
    }
    // Bastion "B" badge on the subnet
    var wg=faG.append('g').attr('class','flow-waypoint-marker');
    wg.append('circle').attr('cx',bastionSub.x+bastionSub.w/2).attr('cy',bastionSub.cy).attr('r',14);
    wg.append('text').attr('x',bastionSub.x+bastionSub.w/2).attr('y',bastionSub.cy+1)
      .attr('text-anchor','middle').attr('dominant-baseline','central')
      .attr('fill','#000').attr('font-size','9px').attr('font-weight','700')
      .attr('font-family','Segoe UI,system-ui,sans-serif').text('B');
    // Deduplicate targets by subnet
    var subSeen=new Set();
    var targetSubs=[];
    ch.targets.forEach(function(tgt){
      var tPos=_resolveNetworkPosition(tgt.type, tgt.id, ctx);
      if(!tPos||!tPos.subnetId) return;
      if(subSeen.has(tPos.subnetId)) return;
      subSeen.add(tPos.subnetId);
      var tRect=document.querySelector('.subnet-node[data-subnet-id="'+tPos.subnetId+'"] rect');
      if(!tRect) return;
      var tb=tRect.getBBox();
      targetSubs.push({sid:tPos.subnetId,x:tb.x,y:tb.y,w:tb.width,h:tb.height,cy:tb.y+tb.height/2});
      // Highlight target subnet (purple)
      var tSubNode=document.querySelector('.subnet-node[data-subnet-id="'+tPos.subnetId+'"]');
      if(tSubNode){
        d3.select(tSubNode).classed('fa-flow-bright',true);
        d3.select(tRect).classed('fa-bastion-target',true);
      }
    });
    if(targetSubs.length===0) return;
    // Bus topology: vertical trunk from bastion to targets
    // Find VPC boundary
    var vpcBB=bPos.vpcId?vpcBounds[bPos.vpcId]:null;
    // Trunk runs to the right of the bastion subnet (between bastion and targets)
    var allSubs=[bastionSub].concat(targetSubs);
    allSubs.sort(function(a,b){return a.cy-b.cy});
    var trunkX;
    if(vpcBB){
      // Place trunk slightly inside VPC, between bastion column and target column
      var midVpcX=(vpcBB.left+vpcBB.right)/2;
      // If bastion is on the left, trunk goes right of it. Otherwise left.
      trunkX=bastionSub.x+bastionSub.w/2<midVpcX?bastionSub.x+bastionSub.w+20:bastionSub.x-20;
    } else {
      trunkX=bastionSub.x+bastionSub.w+20;
    }
    _drawBusTopology(faG,{
      trunkX:trunkX,
      subnets:allSubs,
      pathClass:'flow-path-leg allowed',
      branchMarker:'url(#bastion-arrow-head)',
      trunkStyle:{'opacity':'0.85'},
      branchDirection:'toSubnet',
      onBranch:function(sp,idx,edgeX){
        if(sp===bastionSub) return;
        var hopIdx=idx-(allSubs.indexOf(bastionSub)<idx?1:0);
        var bx=edgeX+(edgeX<trunkX?12:-12);
        var hopG=faG.append('g').attr('class','flow-hop flow-hop-allow');
        hopG.append('circle').attr('cx',bx).attr('cy',sp.cy).attr('r',5);
        hopG.append('text').attr('x',bx).attr('y',sp.cy)
          .style('font-size','6px').text(hopIdx+1);
      }
    });
  });
}



// --- Flow Analysis Detail Panel ---
function _renderFlowAnalysisPanel(){
  if(!_flowAnalysisCache) return;
  FlowAnalysisPanel.render(_flowAnalysisCache, _flowAnalysisMode||'all', {
    clearHighlights: _clearFlowHighlights,
    highlightNode: _highlightFlowNode,
    launchTraceFromButton: _launchTraceFromBtn
  });
}

// --- Flow Analysis Mode Control ---
function enterFlowAnalysis(){
  var ctx=flowAnalysisRuntimeData();
  if(!ctx){flowAnalysisNotify('Load a map first');return}
  if(_flowMode) exitFlowMode();
  _flowAnalysisMode='tiers';
  // Run discovery
  _flowAnalysisCache=discoverTrafficFlows(ctx);
  // Show banner, push stats bar below it
  document.getElementById('flowAnalysisBanner').style.display='flex';
  var mainEl=_getMain();
  if(mainEl) mainEl.classList.add('flow-active');
  var _eb=document.querySelector('.export-bar');if(_eb) _eb.style.top='44px';
  var _mb=document.getElementById('mergeBanner');if(_mb&&_mb.style.display!=='none') _mb.style.display='none';
  // Render
  _renderFlowAnalysisOverlay(_flowAnalysisMode);
  _renderFlowAnalysisPanel();
  // Set active pill
  document.querySelectorAll('.fa-mode-pill').forEach(function(p){
    p.classList.toggle('active',p.getAttribute('data-fa-mode')===_flowAnalysisMode);
  });
}

function exitFlowAnalysis(){
  _flowAnalysisMode=null;
  document.getElementById('flowAnalysisBanner').style.display='none';
  var mainEl=_getMain();
  if(mainEl) mainEl.classList.remove('flow-active');
  var _eb=document.querySelector('.export-bar');if(_eb) _eb.style.top='';
  if(_multiViewMode){var _mb=document.getElementById('mergeBanner');if(_mb) _mb.style.display='flex';}
  var svg=d3.select('#mapSvg');
  svg.selectAll('.flow-analysis-layer').remove();
  // Remove route-line highlight classes and fa-active dim
  var mapRoot=svg.select('g');
  if(!mapRoot.empty()) mapRoot.classed('fa-active',false);
  document.querySelectorAll('.fa-hl-ingress,.fa-fwd-target,.fa-ingress-target,.fa-egress-source,.fa-bastion-target,.fa-flow-bright').forEach(function(el){
    el.classList.remove('fa-hl-ingress','fa-fwd-target','fa-ingress-target','fa-egress-source','fa-bastion-target','fa-flow-bright');
  });
  var inetNode=document.querySelector('.internet-node');
  if(inetNode) d3.select(inetNode).style('opacity',null).style('filter',null);
  document.querySelectorAll('.gw-node').forEach(function(el){d3.select(el).style('filter',null).style('opacity',null)});
  _clearFlowHighlights();
  var dp=document.getElementById('detailPanel');
  if(dp.classList.contains('open')){
    var dpBody=document.getElementById('dpBody');
    if(dpBody&&dpBody.querySelector('.flow-panel')) dp.classList.remove('open');
  }
}

function _setFlowAnalysisMode(mode){
  _flowAnalysisMode=mode;
  _renderFlowAnalysisOverlay(mode);
  _renderFlowAnalysisPanel();
  document.querySelectorAll('.fa-mode-pill').forEach(function(p){
    p.classList.toggle('active',p.getAttribute('data-fa-mode')===mode);
  });
}

// Wire Flow Analysis controls
document.getElementById('flowAnalysisBtn').addEventListener('click',function(){
  if(_flowAnalysisMode) exitFlowAnalysis();
  else enterFlowAnalysis();
});
document.getElementById('faExitBtn').addEventListener('click',exitFlowAnalysis);
document.querySelectorAll('.fa-mode-pill').forEach(function(pill){
  pill.addEventListener('click',function(){
    _setFlowAnalysisMode(pill.getAttribute('data-fa-mode'));
  });
});

// --- Right-Click Context Menu for Flow Tracing ---
var _flowCtxTarget=null;
(function(){
  var ctxMenu=document.getElementById('flowContextMenu');
  function hideCtx(){ctxMenu.style.display='none';_flowCtxTarget=null}
  // Show context menu on right-click of map resources
  document.getElementById('mapSvg').addEventListener('contextmenu',function(e){
    if(_flowMode) return; // existing flow mode handles its own right-click
    var target=_resolveClickTarget(e.target);
    if(!target) return;
    e.preventDefault();
    e.stopPropagation();
    _flowCtxTarget=target;
    ctxMenu.style.display='block';
    // Position near click, clamped to viewport
    var viewport=flowAnalysisViewportSize();
    var x=Math.min(e.clientX,viewport.width-200);
    var y=Math.min(e.clientY,viewport.height-140);
    ctxMenu.style.left=x+'px';
    ctxMenu.style.top=y+'px';
  });
  // Hide on any click outside
  document.addEventListener('click',function(e){
    if(!ctxMenu.contains(e.target)) hideCtx();
  });
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape') hideCtx();
  });
  // Handle menu item clicks
  ctxMenu.querySelectorAll('.flow-ctx-item').forEach(function(item){
    item.addEventListener('click',function(e){
      e.stopPropagation();
      if(!_flowCtxTarget) return;
      var action=item.getAttribute('data-ctx-action');
      var ref={type:_flowCtxTarget.type,id:_flowCtxTarget.id};
      hideCtx();
      if(action==='trace-from'){
        if(_flowMode) exitFlowMode();
        if(_flowAnalysisMode) exitFlowAnalysis();
        enterFlowMode(ref);
      } else if(action==='trace-to'){
        if(_flowMode) exitFlowMode();
        if(_flowAnalysisMode) exitFlowAnalysis();
        enterFlowMode(); // no preset source
        // Store preset target: next source click will auto-advance
        _flowCtxPresetTarget=ref;
      } else if(action==='analyze'){
        if(_flowMode) exitFlowMode();
        if(!_flowAnalysisMode) enterFlowAnalysis();
        // Highlight the resource in the analysis panel
        _clearFlowHighlights();
        _highlightFlowNode(ref,'source');
      }
    });
  });
})();
var _flowCtxPresetTarget=null;

// --- Shared: Launch trace from a discovery button ---
function _launchTraceFromBtn(btn, preCleanup){
  var srcT=btn.getAttribute('data-trace-src-t');
  var srcId=btn.getAttribute('data-trace-src-id');
  var tgtT=btn.getAttribute('data-trace-tgt-t');
  var tgtId=btn.getAttribute('data-trace-tgt-id');
  var port=parseInt(btn.getAttribute('data-trace-port'),10)||443;
  if(preCleanup) preCleanup();
  exitFlowAnalysis();
  enterFlowMode({type:srcT,id:srcId});
  _flowTarget={type:tgtT,id:tgtId};
  _flowSelecting=null;
  var mainEl=_getMain();
  if(mainEl) mainEl.classList.remove('flow-selecting');
  _flowConfig.port=port;
  _flowConfig.protocol='tcp';
  _highlightFlowNode({type:tgtT,id:tgtId},'target');
  _executeTrace();
}

document.getElementById('faDashBtn').addEventListener('click',function(){
  if(_flowAnalysisCache) {
    FlowAnalysisDashboard.open(_flowAnalysisCache, {
      launchTraceFromButton: _launchTraceFromBtn
    });
  }
});

// #endregion FLOW ANALYSIS

