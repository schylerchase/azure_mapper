// Report HTML shell assets: exported CSS, browser-side table controls, and SVG style serialization.

function _rptCSS(){
  var lt=document.documentElement.dataset.theme==='light';
  var bg=lt?'#f1f5f9':'#0f172a';
  var card=lt?'#ffffff':'#1e293b';
  var hd=lt?'#0f172a':'#f8fafc';
  var tx=lt?'#1e293b':'#e2e8f0';
  var mt=lt?'#475569':'#94a3b8';
  var dm=lt?'#64748b':'#64748b';
  var bd=lt?'#cbd5e1':'#334155';
  var link=lt?'#2563eb':'#60a5fa';
  var sub=lt?'#cbd5e1':'#cbd5e1';
  var evenRow=lt?'rgba(0,0,0,.03)':'rgba(30,41,59,.5)';
  var codeBg=lt?'#f8fafc':'#0f172a';
  return [
    '.rpt-preview-content{margin:0;padding:24px 40px;background:'+bg+';color:'+tx+';',
    'font-family:"Segoe UI",system-ui,sans-serif;line-height:1.6}',
    '@media print{body{background:#fff;color:#1e293b}',
    '.rpt-header{background:#1e293b!important;color:#fff!important}',
    'table th{background:#334155!important;color:#fff!important}',
    '.stat-box{border-color:#cbd5e1!important}}',
    '.rpt-header{background:'+card+';padding:32px;border-radius:8px;margin-bottom:32px}',
    '.rpt-header h1{margin:0 0 8px;font-size:28px;color:'+hd+'}',
    '.rpt-header .subtitle{color:'+mt+';font-size:14px}',
    '.rpt-logo{margin-bottom:16px}',
    '.rpt-logo img{max-height:60px;max-width:200px;object-fit:contain}',
    '.rpt-toc{background:'+card+';padding:20px 28px;border-radius:8px;margin-bottom:32px}',
    '.rpt-toc h2{margin:0 0 12px;font-size:18px;color:'+hd+'}',
    '.rpt-toc a{color:'+link+';text-decoration:none;display:block;padding:4px 0;font-size:14px}',
    '.rpt-toc a:hover{text-decoration:underline}',
    '.rpt-section{margin-bottom:40px}',
    '.rpt-section h2{font-size:22px;color:'+hd+';border-bottom:2px solid '+bd+';padding-bottom:8px;margin-bottom:16px}',
    '.rpt-section h3{font-size:16px;color:'+sub+';margin:20px 0 10px}',
    '.rpt-section:not(:first-child){page-break-before:always}',
    'table{width:100%;border-collapse:collapse;margin-bottom:16px;font-size:13px}',
    'th{background:'+card+';color:'+tx+';text-align:left;padding:8px 10px;font-weight:600}',
    'td{padding:8px 10px;border-bottom:1px solid '+bd+'}',
    'tr:nth-child(even){background:'+evenRow+'}',
    '.sev-badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}',
    '.sev-CRITICAL{background:#dc2626;color:#fff}',
    '.sev-HIGH{background:#ea580c;color:#fff}',
    '.sev-MEDIUM{background:#d97706;color:#fff}',
    '.sev-LOW{background:#2563eb;color:#fff}',
    '.tier-protected{color:#10b981;border-left:3px solid #10b981;padding-left:6px}',
    '.tier-partial{color:#f59e0b;border-left:3px solid #f59e0b;padding-left:6px}',
    '.tier-at_risk{color:#ef4444;border-left:3px solid #ef4444;padding-left:6px}',
    '.stat-grid{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}',
    '.stat-box{background:'+card+';border-radius:8px;padding:16px;min-width:120px;',
    'text-align:center;border:2px solid '+bd+'}',
    '.stat-box .val{font-size:28px;font-weight:700;display:block}',
    '.stat-box .lbl{font-size:12px;color:'+mt+';margin-top:4px;display:block}',
    '.rpt-import-notice{background:'+card+';border:1px solid '+bd+';border-radius:6px;padding:8px 12px;font-size:11px;color:'+mt+';margin-bottom:12px}',
    '.code-block{background:'+codeBg+';border:1px solid '+bd+';border-radius:6px;',
    'padding:16px;font-family:"Fira Code",monospace;font-size:12px;',
    'white-space:pre-wrap;margin:8px 0;overflow-x:auto}',
    '.rpt-footer-bar{margin-top:40px;padding:16px;text-align:center;',
    'font-size:12px;color:'+dm+';border-top:1px solid '+bd+'}',
    '.diagram-img{max-width:100%;height:auto;border-radius:8px;margin:16px 0}',
    '.rpt-kv-grid{display:flex;flex-wrap:wrap;gap:16px;margin:16px 0}',
    '.rpt-kv{display:flex;flex-direction:column;min-width:130px;background:'+card+';border:1px solid '+bd+';border-radius:8px;padding:12px 16px}',
    '.rpt-kv-label{font-size:12px;color:'+mt+';margin-bottom:4px}',
    '.rpt-kv-val{font-size:24px;font-weight:700}'
  ].join('\n');
}

function _rptInteractiveCSS(){
  var lt=document.documentElement.dataset.theme==='light';
  // Structural colors: deep bg, card bg, borders, text
  var deepBg=lt?'#f1f5f9':'#0b1120';
  var inputBg=lt?'#ffffff':'#0a0e17';
  var cardBg=lt?'#ffffff':'#1e293b';
  var bd=lt?'#cbd5e1':'#1e2d4a';
  var bdHeavy=lt?'#94a3b8':'#334155';
  var tx=lt?'#1e293b':'#e2e8f0';
  var mt=lt?'#475569':'#94a3b8';
  var dm=lt?'#64748b':'#64748b';
  var link=lt?'#2563eb':'#60a5fa';
  var linkHover=lt?'#1d4ed8':'#93c5fd';
  var linkPale=lt?'#bfdbfe':'#93c5fd';
  var linkBd=lt?'#93c5fd':'#1e3a5f';
  var stickyBg=lt?'#f1f5f9':'#0f172a';
  var sub=lt?'#475569':'#cbd5e1';
  var pillHover=lt?'rgba(0,0,0,.06)':'rgba(30,41,59,.5)';
  var btnShadow=lt?'rgba(0,0,0,.1)':'rgba(0,0,0,.3)';
  var btnShadowHover=lt?'rgba(0,0,0,.15)':'rgba(0,0,0,.4)';
  var detailBg=lt?'#f8fafc':'#0b1120';
  var detailBd=lt?'#e2e8f0':'#0f172a';
  var resLink=lt?'#0891b2':'#67e8f9';
  var resLinkHover=lt?'#06b6d4':'#a5f3fc';
  var resLinkBd=lt?'rgba(8,145,178,.3)':'rgba(103,232,249,.3)';
  // Pill active colors: slightly more saturated on light
  var pillCritActive=lt?'#fecaca':'#991b1b';
  var pillHighActive=lt?'#fed7aa':'#9a3412';
  var pillMedActive=lt?'#fde68a':'#92400e';
  var pillLowActive=lt?'#bfdbfe':'#1e3a5f';
  var pillProtActive=lt?'#a7f3d0':'#064e3b';
  var pillPartActive=lt?'#fde68a':'#78350f';
  var pillRiskActive=lt?'#fecaca':'#7f1d1d';
  var pillHotActive=lt?'#fecaca':'#7f1d1d';
  var pillWarmActive=lt?'#fde68a':'#78350f';
  var pillPilotActive=lt?'#c7d2fe':'#312e81';
  var pillColdActive=lt?'#e2e8f0':'#1e293b';
  // Strategy badge colors: darken text on light for contrast
  var stratHotTx=lt?'#dc2626':'#f87171';
  var stratWarmTx=lt?'#d97706':'#fbbf24';
  var stratPilotTx=lt?'#4f46e5':'#a5b4fc';
  var stratColdTx=lt?'#475569':'#94a3b8';
  var pillDisabledTx=lt?'#cbd5e1':'#334155';
  return [
    '/* === Interactive report controls === */',
    /* -- Anchor jump nav -- */
    '.rpt-jump-nav{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;padding:10px 14px;background:'+deepBg+';border:1px solid '+bd+';border-radius:8px}',
    '.rpt-jump-link{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;color:'+link+';text-decoration:none;border:1px solid '+linkBd+';background:rgba(37,99,235,.08);transition:all .15s;white-space:nowrap;letter-spacing:.2px}',
    '.rpt-jump-link:hover{background:rgba(37,99,235,.18);color:'+linkHover+';border-color:#2563eb}',
    '.rpt-jump-link .rpt-jump-ct{font-size:10px;font-weight:700;color:'+(lt?'#1e40af':'#93c5fd')+';background:rgba(37,99,235,'+(lt?'.15':'.2')+');padding:2px 7px;border-radius:10px;min-width:20px;text-align:center;transition:all .15s}',
    '.rpt-jump-link:hover .rpt-jump-ct{background:rgba(37,99,235,.35);color:#bfdbfe}',
    /* -- Filter toolbar -- */
    '.rpt-toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:8px 12px;margin-bottom:4px;background:'+deepBg+';border:1px solid '+bd+';border-radius:8px}',
    '.rpt-toolbar input[type="text"]{background:'+inputBg+';color:'+tx+';border:1px solid '+bd+';border-radius:6px;padding:5px 10px 5px 28px;font-size:12px;width:180px;outline:none;background-image:url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'14\' height=\'14\' fill=\'%2364748b\' viewBox=\'0 0 24 24\'%3E%3Cpath d=\'M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z\'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:8px center}',
    '.rpt-toolbar input[type="text"]:focus{border-color:#3b82f6;box-shadow:0 0 0 2px rgba(59,130,246,.15)}',
    '.rpt-toolbar input[type="text"]::placeholder{color:'+dm+'}',
    '.rpt-pill-sep{width:1px;height:20px;background:'+bd+';margin:0 2px;flex-shrink:0}',
    '.rpt-pill{display:inline-flex;align-items:center;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid '+bd+';color:'+dm+';background:transparent;transition:all .15s;user-select:none;letter-spacing:.3px}',
    '.rpt-pill:hover{border-color:'+dm+';color:'+mt+';background:'+pillHover+'}',
    '.rpt-pill.active{color:'+(lt?'#1e293b':'#fff')+'}',
    '.rpt-pill-ct{font-size:10px;opacity:.7;margin-left:3px;font-weight:400}',
    '.rpt-pill-ct:empty{display:none}',
    '.rpt-pill-crit{border-color:rgba(220,38,38,.25);color:'+(lt?'#dc2626':'#f87171')+'}',
    '.rpt-pill-crit:hover{background:rgba(220,38,38,.1);border-color:rgba(220,38,38,.4)}',
    '.rpt-pill-crit.active{background:'+pillCritActive+';border-color:#dc2626}',
    '.rpt-pill-high{border-color:rgba(234,88,12,.25);color:'+(lt?'#ea580c':'#fb923c')+'}',
    '.rpt-pill-high:hover{background:rgba(234,88,12,.1);border-color:rgba(234,88,12,.4)}',
    '.rpt-pill-high.active{background:'+pillHighActive+';border-color:#ea580c}',
    '.rpt-pill-med{border-color:rgba(217,119,6,.25);color:'+(lt?'#d97706':'#fbbf24')+'}',
    '.rpt-pill-med:hover{background:rgba(217,119,6,.1);border-color:rgba(217,119,6,.4)}',
    '.rpt-pill-med.active{background:'+pillMedActive+';border-color:#d97706}',
    '.rpt-pill-low{border-color:rgba(37,99,235,.25);color:'+link+'}',
    '.rpt-pill-low:hover{background:rgba(37,99,235,.1);border-color:rgba(37,99,235,.4)}',
    '.rpt-pill-low.active{background:'+pillLowActive+';border-color:#2563eb}',
    '.rpt-pill-protected{border-color:rgba(16,185,129,.25);color:'+(lt?'#059669':'#34d399')+'}',
    '.rpt-pill-protected:hover{background:rgba(16,185,129,.1);border-color:rgba(16,185,129,.4)}',
    '.rpt-pill-protected.active{background:'+pillProtActive+';border-color:#10b981}',
    '.rpt-pill-partial{border-color:rgba(245,158,11,.25);color:'+(lt?'#d97706':'#fbbf24')+'}',
    '.rpt-pill-partial:hover{background:rgba(245,158,11,.1);border-color:rgba(245,158,11,.4)}',
    '.rpt-pill-partial.active{background:'+pillPartActive+';border-color:#f59e0b}',
    '.rpt-pill-atrisk{border-color:rgba(239,68,68,.25);color:'+(lt?'#dc2626':'#f87171')+'}',
    '.rpt-pill-atrisk:hover{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.4)}',
    '.rpt-pill-atrisk.active{background:'+pillRiskActive+';border-color:#ef4444}',
    /* -- Strategy pills -- */
    '.rpt-pill-hot{border-color:rgba(239,68,68,.25);color:'+(lt?'#dc2626':'#f87171')+'}',
    '.rpt-pill-hot:hover{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.4)}',
    '.rpt-pill-hot.active{background:'+pillHotActive+';border-color:#ef4444}',
    '.rpt-pill-warm{border-color:rgba(245,158,11,.25);color:'+(lt?'#d97706':'#fbbf24')+'}',
    '.rpt-pill-warm:hover{background:rgba(245,158,11,.1);border-color:rgba(245,158,11,.4)}',
    '.rpt-pill-warm.active{background:'+pillWarmActive+';border-color:#f59e0b}',
    '.rpt-pill-pilot{border-color:rgba(99,102,241,.25);color:'+(lt?'#4f46e5':'#a5b4fc')+'}',
    '.rpt-pill-pilot:hover{background:rgba(99,102,241,.1);border-color:rgba(99,102,241,.4)}',
    '.rpt-pill-pilot.active{background:'+pillPilotActive+';border-color:#6366f1}',
    '.rpt-pill-cold{border-color:rgba(100,116,139,.25);color:'+mt+'}',
    '.rpt-pill-cold:hover{background:rgba(100,116,139,.1);border-color:rgba(100,116,139,.4)}',
    '.rpt-pill-cold.active{background:'+pillColdActive+';border-color:#64748b}',
    /* -- Strategy badges (in table) -- */
    '.strategy-badge{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;letter-spacing:.5px;text-transform:uppercase}',
    '.strategy-hot{background:rgba(239,68,68,.15);color:'+stratHotTx+';border:1px solid rgba(239,68,68,.3)}',
    '.strategy-warm{background:rgba(245,158,11,.15);color:'+stratWarmTx+';border:1px solid rgba(245,158,11,.3)}',
    '.strategy-pilot{background:rgba(99,102,241,.15);color:'+stratPilotTx+';border:1px solid rgba(99,102,241,.3)}',
    '.strategy-cold{background:rgba(100,116,139,.15);color:'+stratColdTx+';border:1px solid rgba(100,116,139,.3)}',
    '.rpt-res-link{color:'+resLink+';text-decoration:none;border-bottom:1px dashed '+resLinkBd+';transition:all .15s}',
    '.rpt-res-link:hover{color:'+resLinkHover+';border-bottom-color:'+resLink+'}',
    '.rpt-row-count{font-size:10px;color:'+dm+';margin-left:auto;white-space:nowrap;font-weight:500;letter-spacing:.3px}',
    '.rpt-clear{font-size:11px;color:'+dm+';cursor:pointer;border:1px solid '+bd+';background:transparent;padding:4px 10px;border-radius:6px;transition:all .15s;font-weight:500}',
    '.rpt-clear:hover{color:'+mt+';border-color:'+dm+';background:'+pillHover+'}',
    /* -- Sticky header -- */
    'table thead.rpt-sticky{position:sticky;top:0;z-index:2}',
    'table thead.rpt-sticky th{background:'+stickyBg+';border-bottom:2px solid '+bd+'}',
    /* -- Collapsible sections -- */
    '.rpt-section-toggle{cursor:pointer;user-select:none;display:flex;align-items:center;gap:8px}',
    '.rpt-section-toggle::before{content:"";display:inline-block;width:8px;height:8px;border-right:2px solid '+dm+';border-bottom:2px solid '+dm+';transform:rotate(45deg);transition:transform .2s;flex-shrink:0}',
    '.rpt-section-toggle.collapsed::before{transform:rotate(-45deg)}',
    '.rpt-section-body{transition:max-height .3s ease;overflow:hidden}',
    '.rpt-section-body.collapsed{max-height:0!important;overflow:hidden}',
    /* -- Sub-section headings -- */
    '.rpt-section h3{font-size:15px;color:'+sub+';margin:24px 0 8px;padding-bottom:6px;border-bottom:1px solid '+bd+'}',
    /* -- Back to top -- */
    '#rpt-back-top{position:fixed;bottom:24px;right:24px;width:36px;height:36px;border-radius:8px;background:'+cardBg+';border:1px solid '+bdHeavy+';color:'+mt+';font-size:16px;cursor:pointer;display:none;align-items:center;justify-content:center;z-index:100;transition:all .2s;box-shadow:0 4px 12px '+btnShadow+'}',
    '#rpt-back-top:hover{background:'+bdHeavy+';color:'+tx+';transform:translateY(-2px);box-shadow:0 6px 16px '+btnShadowHover+'}',
    /* -- Pagination -- */
    '.rpt-pagination{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px 0;font-size:12px;color:'+mt+'}',
    '.rpt-page-btn{padding:4px 10px;border-radius:5px;border:1px solid '+bd+';background:transparent;color:'+link+';cursor:pointer;font-size:11px;font-weight:500;transition:all .15s}',
    '.rpt-page-btn:hover:not(:disabled){background:rgba(37,99,235,.15);border-color:#2563eb}',
    '.rpt-page-btn:disabled{color:'+pillDisabledTx+';border-color:'+bd+';cursor:default}',
    '.rpt-page-info{color:'+dm+';font-size:11px;min-width:100px;text-align:center}',
    '.rpt-per-page{background:'+inputBg+';color:'+mt+';border:1px solid '+bd+';border-radius:5px;padding:3px 6px;font-size:11px;outline:none}',
    '.rpt-per-page:focus{border-color:#3b82f6}',
    /* -- Sortable columns -- */
    'th.rpt-sortable{cursor:pointer;user-select:none;position:relative;padding-right:18px!important;white-space:nowrap}',
    'th.rpt-sortable:hover{color:'+linkHover+'}',
    'th.rpt-sortable::after{content:"\\2195";position:absolute;right:4px;top:50%;transform:translateY(-50%);font-size:10px;color:'+dm+';transition:color .15s}',
    'th.rpt-sort-asc::after{content:"\\25B2";color:'+link+'}',
    'th.rpt-sort-desc::after{content:"\\25BC";color:'+link+'}',
    /* -- Group-by-control -- */
    '.rpt-ctrl-row{cursor:pointer;transition:background .1s}',
    '.rpt-ctrl-row:hover{background:rgba(37,99,235,.08)!important}',
    '.rpt-ctrl-toggle{display:inline-block;width:16px;font-size:10px;color:'+dm+';transition:transform .15s}',
    '.rpt-ctrl-row.expanded .rpt-ctrl-toggle{transform:rotate(90deg);color:'+link+'}',
    '.rpt-ctrl-detail{display:none}',
    '.rpt-ctrl-detail.show{display:table-row}',
    '.rpt-ctrl-detail>td{padding:0!important}',
    '.rpt-detail-table{width:100%;font-size:12px;margin:0;background:'+detailBg+';border-collapse:collapse}',
    '.rpt-detail-table td{padding:5px 10px!important;border-bottom:1px solid '+detailBd+';color:'+mt+';font-size:11px}',
    '.rpt-detail-table tr:last-child td{border-bottom:none}',
    '.rpt-expand-all{font-size:11px;color:'+dm+';cursor:pointer;border:1px solid '+bd+';background:transparent;padding:4px 10px;border-radius:6px;transition:all .15s;font-weight:500;margin:4px 0 8px;display:inline-block}',
    '.rpt-expand-all:hover{color:'+mt+';border-color:'+dm+'}',
    /* -- Print overrides -- */
    '@media print{.rpt-toolbar,.rpt-clear,.rpt-jump-nav,.rpt-pagination,#rpt-back-top{display:none!important}',
    '.rpt-section-body.collapsed{max-height:none!important;overflow:visible!important}',
    'table thead.rpt-sticky{position:static}',
    '.rpt-ctrl-detail{display:table-row!important}',
    'tr[style*="display: none"]{display:table-row!important}}'
  ].join('\n');
}

function _rptInteractiveJS(){
  return '<scr'+'ipt>\n'+
  '(function(){\n'+
  '  var SEV_ORD={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};\n'+
  '  var TIER_ORD={at_risk:0,partial:1,protected:2};\n'+
  '  var STRAT_ORD={hot:0,warm:1,pilot:2,cold:3};\n'+
  '\n'+
  '  /* -- Pagination -- */\n'+
  '  function rptPaginate(tableId){\n'+
  '    var wrap=document.getElementById(tableId);\n'+
  '    if(!wrap)return;\n'+
  '    var table=wrap.querySelector("table");\n'+
  '    if(!table)return;\n'+
  '    var tbody=table.querySelector(":scope > tbody");\n'+
  '    if(!tbody)return;\n'+
  '    var allRows=Array.prototype.slice.call(tbody.querySelectorAll(":scope > tr:not(.rpt-ctrl-detail)"));\n'+
  '    var visible=allRows.filter(function(r){return r.dataset.filtered!=="0"});\n'+
  '    var perPage=parseInt(wrap.dataset.perPage)||50;\n'+
  '    if(perPage<=0)perPage=visible.length||1;\n'+
  '    var totalPages=Math.max(1,Math.ceil(visible.length/perPage));\n'+
  '    var page=Math.min(parseInt(wrap.dataset.page)||1,totalPages);\n'+
  '    wrap.dataset.page=page;\n'+
  '    var start=(page-1)*perPage,end=start+perPage;\n'+
  '    allRows.forEach(function(r){r.style.display="none"});\n'+
  '    visible.forEach(function(r,i){r.style.display=(i>=start&&i<end)?"":"none"});\n'+
  '    /* hide detail rows for non-visible control rows */\n'+
  '    table.querySelectorAll(".rpt-ctrl-detail").forEach(function(d){var p=d.previousElementSibling;d.style.display=(p&&p.style.display!==""&&p.classList.contains("expanded"))?"table-row":"none"});\n'+
  '    var bar=wrap.querySelector(".rpt-pagination");\n'+
  '    if(!bar)return;\n'+
  '    bar.querySelector(".rpt-page-info").textContent="Page "+page+" of "+totalPages+" ("+visible.length+" rows)";\n'+
  '    bar.querySelector(".rpt-page-prev").disabled=(page<=1);\n'+
  '    bar.querySelector(".rpt-page-next").disabled=(page>=totalPages);\n'+
  '  }\n'+
  '\n'+
  '  /* -- Filter -- */\n'+
  '  function rptFilter(tableId){\n'+
  '    var wrap=document.getElementById(tableId);\n'+
  '    if(!wrap)return;\n'+
  '    var pills=wrap.querySelectorAll(".rpt-pill");\n'+
  '    var active={};\n'+
  '    pills.forEach(function(p){\n'+
  '      if(!p.classList.contains("active"))return;\n'+
  '      var attr=p.dataset.attr;\n'+
  '      if(!active[attr])active[attr]=[];\n'+
  '      active[attr].push(p.dataset.val.toUpperCase());\n'+
  '    });\n'+
  '    var searchInput=wrap.querySelector(".rpt-search");\n'+
  '    var query=searchInput?searchInput.value.toLowerCase():"";\n'+
  '    var table=wrap.querySelector("table");\n'+
  '    if(!table)return;\n'+
  '    var tbody=table.querySelector(":scope > tbody");\n'+
  '    if(!tbody)return;\n'+
  '    var rows=tbody.querySelectorAll(":scope > tr:not(.rpt-ctrl-detail)");\n'+
  '    var shown=0,attrCounts={},total=rows.length;\n'+
  '    rows.forEach(function(tr){\n'+
  '      var vis=true;\n'+
  '      Object.keys(active).forEach(function(attr){\n'+
  '        var raw=(tr.dataset[attr]||"").toUpperCase();\n'+
  '        if(attr==="account"&&raw.indexOf("|")!==-1){\n'+
  '          var parts=raw.split("|");\n'+
  '          var match=parts.some(function(p){return active[attr].indexOf(p)!==-1});\n'+
  '          if(!match)vis=false;\n'+
  '        }else{\n'+
  '          if(active[attr].indexOf(raw)===-1)vis=false;\n'+
  '        }\n'+
  '      });\n'+
  '      if(vis&&query){\n'+
  '        if(tr.textContent.toLowerCase().indexOf(query)===-1)vis=false;\n'+
  '      }\n'+
  '      tr.dataset.filtered=vis?"1":"0";\n'+
  '      if(vis)shown++;\n'+
  '      ["sev","tier","fw","strategy","account"].forEach(function(attr){\n'+
  '        var v=(tr.dataset[attr]||"").toUpperCase();\n'+
  '        if(attr==="account"&&v.indexOf("|")!==-1){\n'+
  '          v.split("|").forEach(function(p){if(p){if(!attrCounts[p])attrCounts[p]=0;if(vis)attrCounts[p]++}});\n'+
  '        }else{\n'+
  '          if(v){if(!attrCounts[v])attrCounts[v]=0;if(vis)attrCounts[v]++}\n'+
  '        }\n'+
  '      });\n'+
  '    });\n'+
  '    var badge=wrap.querySelector(".rpt-row-count");\n'+
  '    if(badge)badge.textContent=shown+" of "+total;\n'+
  '    /* update pill counts */\n'+
  '    pills.forEach(function(p){\n'+
  '      var ct=p.querySelector(".rpt-pill-ct");\n'+
  '      if(!ct)return;\n'+
  '      var val=p.dataset.val.toUpperCase();\n'+
  '      ct.textContent=attrCounts[val]||0;\n'+
  '    });\n'+
  '    wrap.dataset.page="1";\n'+
  '    rptPaginate(tableId);\n'+
  '  }\n'+
  '\n'+
  '  /* -- Sort -- */\n'+
  '  function rptSort(th){\n'+
  '    var table=th.closest("table");\n'+
  '    if(!table)return;\n'+
  '    var idx=Array.prototype.indexOf.call(th.parentElement.children,th);\n'+
  '    var type=th.dataset.sortType||"text";\n'+
  '    var dir=th.classList.contains("rpt-sort-asc")?"desc":th.classList.contains("rpt-sort-desc")?"none":"asc";\n'+
  '    th.parentElement.querySelectorAll("th").forEach(function(h){h.classList.remove("rpt-sort-asc","rpt-sort-desc")});\n'+
  '    if(dir!=="none")th.classList.add("rpt-sort-"+dir);\n'+
  '    var tbody=table.querySelector("tbody");\n'+
  '    var rows=Array.prototype.slice.call(tbody.querySelectorAll(":scope > tr:not(.rpt-ctrl-detail)"));\n'+
  '    if(dir==="none")return;\n'+
  '    rows.sort(function(a,b){\n'+
  '      var av=a.children[idx]?a.children[idx].textContent.trim():"";\n'+
  '      var bv=b.children[idx]?b.children[idx].textContent.trim():"";\n'+
  '      var cmp=0;\n'+
  '      if(type==="severity")cmp=(SEV_ORD[av]===undefined?9:SEV_ORD[av])-(SEV_ORD[bv]===undefined?9:SEV_ORD[bv]);\n'+
  '      else if(type==="tier")cmp=(TIER_ORD[av]===undefined?9:TIER_ORD[av])-(TIER_ORD[bv]===undefined?9:TIER_ORD[bv]);\n'+
  '      else if(type==="strategy")cmp=(STRAT_ORD[av.toLowerCase()]===undefined?9:STRAT_ORD[av.toLowerCase()])-(STRAT_ORD[bv.toLowerCase()]===undefined?9:STRAT_ORD[bv.toLowerCase()]);\n'+
  '      else cmp=av.localeCompare(bv);\n'+
  '      return dir==="desc"?-cmp:cmp;\n'+
  '    });\n'+
  '    var pairs=rows.map(function(r){var d=r.nextElementSibling;return{row:r,detail:(d&&d.classList.contains("rpt-ctrl-detail"))?d:null}});\n'+
  '    pairs.forEach(function(p){tbody.appendChild(p.row);if(p.detail)tbody.appendChild(p.detail)});\n'+
  '    var wrap=th.closest(".rpt-table-wrap");\n'+
  '    if(wrap){wrap.dataset.page="1";rptPaginate(wrap.id)}\n'+
  '  }\n'+
  '\n'+
  '  /* -- Pill click -- */\n'+
  '  document.addEventListener("click",function(e){\n'+
  '    var pill=e.target.closest(".rpt-pill");\n'+
  '    if(!pill)return;\n'+
  '    pill.classList.toggle("active");\n'+
  '    var wrap=pill.closest(".rpt-table-wrap");\n'+
  '    if(wrap)rptFilter(wrap.id);\n'+
  '  });\n'+
  '\n'+
  '  /* -- Clear filters -- */\n'+
  '  document.addEventListener("click",function(e){\n'+
  '    if(!e.target.classList.contains("rpt-clear"))return;\n'+
  '    var wrap=e.target.closest(".rpt-table-wrap");\n'+
  '    if(!wrap)return;\n'+
  '    wrap.querySelectorAll(".rpt-pill.active").forEach(function(p){p.classList.remove("active")});\n'+
  '    var si=wrap.querySelector(".rpt-search");\n'+
  '    if(si)si.value="";\n'+
  '    rptFilter(wrap.id);\n'+
  '  });\n'+
  '\n'+
  '  /* -- Sortable header click -- */\n'+
  '  document.addEventListener("click",function(e){\n'+
  '    var th=e.target.closest("th.rpt-sortable");\n'+
  '    if(!th)return;\n'+
  '    rptSort(th);\n'+
  '  });\n'+
  '\n'+
  '  /* -- Pagination click -- */\n'+
  '  document.addEventListener("click",function(e){\n'+
  '    var btn=e.target.closest(".rpt-page-prev,.rpt-page-next");\n'+
  '    if(!btn)return;\n'+
  '    var wrap=btn.closest(".rpt-table-wrap");\n'+
  '    if(!wrap)return;\n'+
  '    var page=parseInt(wrap.dataset.page)||1;\n'+
  '    wrap.dataset.page=btn.classList.contains("rpt-page-prev")?Math.max(1,page-1):page+1;\n'+
  '    rptPaginate(wrap.id);\n'+
  '  });\n'+
  '  document.addEventListener("change",function(e){\n'+
  '    if(!e.target.classList.contains("rpt-per-page"))return;\n'+
  '    var wrap=e.target.closest(".rpt-table-wrap");\n'+
  '    if(!wrap)return;\n'+
  '    wrap.dataset.perPage=e.target.value;\n'+
  '    wrap.dataset.page="1";\n'+
  '    rptPaginate(wrap.id);\n'+
  '  });\n'+
  '\n'+
  '  /* -- Group-by-control expand/collapse -- */\n'+
  '  document.addEventListener("click",function(e){\n'+
  '    var row=e.target.closest(".rpt-ctrl-row");\n'+
  '    if(!row)return;\n'+
  '    row.classList.toggle("expanded");\n'+
  '    var next=row.nextElementSibling;\n'+
  '    while(next&&next.classList.contains("rpt-ctrl-detail")){\n'+
  '      next.classList.toggle("show");\n'+
  '      next.style.display=next.classList.contains("show")?"table-row":"none";\n'+
  '      next=next.nextElementSibling;\n'+
  '    }\n'+
  '  });\n'+
  '  document.addEventListener("click",function(e){\n'+
  '    if(!e.target.classList.contains("rpt-expand-all"))return;\n'+
  '    var wrap=e.target.closest(".rpt-table-wrap");\n'+
  '    if(!wrap)return;\n'+
  '    var anyCollapsed=wrap.querySelector(".rpt-ctrl-row:not(.expanded)");\n'+
  '    var expand=!!anyCollapsed;\n'+
  '    wrap.querySelectorAll(".rpt-ctrl-row").forEach(function(r){r.classList.toggle("expanded",expand)});\n'+
  '    wrap.querySelectorAll(".rpt-ctrl-detail").forEach(function(d){d.classList.toggle("show",expand);d.style.display=expand?"table-row":"none"});\n'+
  '    e.target.textContent=expand?"Collapse All":"Expand All";\n'+
  '  });\n'+
  '\n'+
  '  /* -- Debounced search -- */\n'+
  '  var _searchTimer=0;\n'+
  '  document.addEventListener("input",function(e){\n'+
  '    if(!e.target.classList.contains("rpt-search"))return;\n'+
  '    clearTimeout(_searchTimer);\n'+
  '    var wrap=e.target.closest(".rpt-table-wrap");\n'+
  '    _searchTimer=setTimeout(function(){if(wrap)rptFilter(wrap.id)},300);\n'+
  '  });\n'+
  '\n'+
  '  /* -- Section collapse/expand -- */\n'+
  '  document.addEventListener("click",function(e){\n'+
  '    var tog=e.target.closest(".rpt-section-toggle");\n'+
  '    if(!tog)return;\n'+
  '    tog.classList.toggle("collapsed");\n'+
  '    var body=tog.parentElement.querySelector(".rpt-section-body");\n'+
  '    if(body)body.classList.toggle("collapsed");\n'+
  '  });\n'+
  '\n'+
  '  /* -- Back to top -- */\n'+
  '  var btn=document.getElementById("rpt-back-top");\n'+
  '  if(btn){\n'+
  '    globalThis.addEventListener("scroll",function(){\n'+
  '      btn.style.display=globalThis.scrollY>400?"flex":"none";\n'+
  '    });\n'+
  '    btn.addEventListener("click",function(){\n'+
  '      globalThis.scrollTo({top:0,behavior:"smooth"});\n'+
  '    });\n'+
  '  }\n'+
  '\n'+
  '  /* -- Init pagination on all tables -- */\n'+
  '  document.querySelectorAll(".rpt-table-wrap").forEach(function(w){\n'+
  '    if(!w.dataset.perPage)w.dataset.perPage="50";\n'+
  '    w.dataset.page="1";\n'+
  '    rptFilter(w.id);\n'+
  '  });\n'+
  '})();\n'+
  '</'+'script>';
}

function _rptBuildToolbar(tableId, opts){
  opts=opts||{};
  var h='<div class="rpt-toolbar">';
  h+='<input type="text" class="rpt-search" placeholder="Search..." aria-label="Search table">';
  var hasPills=opts.severities||opts.frameworks||opts.tiers||opts.strategies||opts.accounts;
  if(hasPills) h+='<span class="rpt-pill-sep"></span>';
  if(opts.severities){
    var sevs=[
      {val:'CRITICAL',cls:'rpt-pill-crit',label:'Critical'},
      {val:'HIGH',cls:'rpt-pill-high',label:'High'},
      {val:'MEDIUM',cls:'rpt-pill-med',label:'Medium'},
      {val:'LOW',cls:'rpt-pill-low',label:'Low'}
    ];
    sevs.forEach(function(s){
      h+='<span class="rpt-pill '+s.cls+'" data-attr="sev" data-val="'+s.val+'">'+s.label+' <span class="rpt-pill-ct"></span></span>';
    });
  }
  if(opts.frameworks){
    if(opts.severities) h+='<span class="rpt-pill-sep"></span>';
    var fws=opts.frameworks;
    fws.forEach(function(fw){
      h+='<span class="rpt-pill" data-attr="fw" data-val="'+esc(fw)+'">'+esc(fw)+'</span>';
    });
  }
  if(opts.tiers){
    var tiers=[
      {val:'protected',cls:'rpt-pill-protected',label:'Protected'},
      {val:'partial',cls:'rpt-pill-partial',label:'Partial'},
      {val:'at_risk',cls:'rpt-pill-atrisk',label:'At Risk'}
    ];
    tiers.forEach(function(t){
      h+='<span class="rpt-pill '+t.cls+'" data-attr="tier" data-val="'+t.val+'">'+t.label+' <span class="rpt-pill-ct"></span></span>';
    });
  }
  if(opts.strategies){
    if(opts.tiers||opts.severities) h+='<span class="rpt-pill-sep"></span>';
    var strats=[
      {val:'hot',cls:'rpt-pill-hot',label:'Hot'},
      {val:'warm',cls:'rpt-pill-warm',label:'Warm'},
      {val:'pilot',cls:'rpt-pill-pilot',label:'Pilot Light'},
      {val:'cold',cls:'rpt-pill-cold',label:'Cold'}
    ];
    strats.forEach(function(s){
      h+='<span class="rpt-pill '+s.cls+'" data-attr="strategy" data-val="'+s.val+'">'+s.label+' <span class="rpt-pill-ct"></span></span>';
    });
  }
  if(opts.accounts&&opts.accounts.length>1){
    if(hasPills) h+='<span class="rpt-pill-sep"></span>';
    opts.accounts.forEach(function(a){
      h+='<span class="rpt-pill" data-attr="account" data-val="'+esc(a.id)+'">'+esc(a.label)+' <span class="rpt-pill-ct"></span></span>';
    });
  }
  if(hasPills) h+='<span class="rpt-pill-sep"></span>';
  h+='<button class="rpt-clear" type="button">Clear</button>';
  h+='<span class="rpt-row-count"></span>';
  h+='</div>';
  /* Pagination bar */
  h+='<div class="rpt-pagination">';
  h+='<button class="rpt-page-btn rpt-page-prev" title="Previous page">&lsaquo; Prev</button>';
  h+='<span class="rpt-page-info">Page 1 of 1</span>';
  h+='<button class="rpt-page-btn rpt-page-next" title="Next page">Next &rsaquo;</button>';
  h+='<select class="rpt-per-page" title="Rows per page">';
  h+='<option value="25">25</option><option value="50" selected>50</option>';
  h+='<option value="100">100</option><option value="0">All</option>';
  h+='</select>';
  h+='</div>';
  return h;
}

function _rptBuildSvgUri(svgEl,root){
  var clone=svgEl.cloneNode(true);
  _rptPrepClone(clone,root);
  var xml=new XMLSerializer().serializeToString(clone);
  return 'data:image/svg+xml;base64,'+btoa(unescape(encodeURIComponent(xml)));
}

var _cachedStyleCss=null;
function _rptCollectStyles(){
  if(_cachedStyleCss!==null) return _cachedStyleCss;
  var css='';
  for(let i=0;i<document.styleSheets.length;i++){
    try{
      var rules=document.styleSheets[i].cssRules;
      if(!rules) continue;
      for(let j=0;j<rules.length;j++) css+=rules[j].cssText+'\n';
    }catch(e){/* cross-origin */}
  }
  _cachedStyleCss=css;
  return css;
}
// Invalidate style cache on theme change
(function(){var tb=document.getElementById('themeToggle');if(tb)tb.addEventListener('click',function(){_cachedStyleCss=null})})();
