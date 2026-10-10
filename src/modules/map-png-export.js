// #region MAP PNG EXPORT
// PNG High-DPI Export
document.getElementById('expPng').addEventListener('click',()=>{
  const svgEl=document.getElementById('mapSvg');
  const root=svgEl.querySelector('.map-root');
  if(!root)return;
  // get untransformed bounding box
  const bb=root.getBBox();
  const pad=60;
  const cw=bb.width+pad,ch=bb.height+pad;
  const maxDim=16000;
  const scale=Math.min(3, maxDim/cw, maxDim/ch);
  const w=Math.round(cw*scale),h=Math.round(ch*scale);
  const clone=svgEl.cloneNode(true);
  clone.setAttribute('xmlns','http://www.w3.org/2000/svg');
  clone.setAttribute('width',w);clone.setAttribute('height',h);
  clone.setAttribute('viewBox',`${bb.x-pad/2} ${bb.y-pad/2} ${cw} ${ch}`);
  // remove zoom/pan transform so content fills viewBox
  const cloneRoot=clone.querySelector('.map-root');
  if(cloneRoot)cloneRoot.removeAttribute('transform');
  // Resolve paint/font rules from external stylesheets before serializing the
  // SVG. Computed values also preserve CSS variable colors in the standalone image.
  const sourceNodes=[svgEl,...svgEl.querySelectorAll('*')];
  const cloneNodes=[clone,...clone.querySelectorAll('*')];
  const paintProperties=['fill','fill-opacity','fill-rule','stroke','stroke-width','stroke-opacity',
    'stroke-dasharray','stroke-dashoffset','stroke-linecap','stroke-linejoin','opacity',
    'font-family','font-size','font-weight','font-style','text-anchor','dominant-baseline',
    'letter-spacing','visibility','display','color'];
  sourceNodes.forEach((node,index)=>{
    const computed=getComputedStyle(node);
    paintProperties.forEach(property=>cloneNodes[index].style.setProperty(property,computed.getPropertyValue(property)));
  });
  // background rect
  const bgR=document.createElementNS('http://www.w3.org/2000/svg','rect');
  bgR.setAttribute('x',bb.x-pad/2);bgR.setAttribute('y',bb.y-pad/2);
  bgR.setAttribute('width',cw);bgR.setAttribute('height',ch);
  var ltExp=document.documentElement.dataset.theme==='light';
  bgR.setAttribute('fill',ltExp?'#f1f5f9':'#0a0e17');
  if(ltExp) clone.setAttribute('data-theme','light');
  if(cloneRoot)cloneRoot.insertBefore(bgR,cloneRoot.firstChild);
  const svgStr=new XMLSerializer().serializeToString(clone);
  const img=new Image();
  img.onload=()=>{
    const canvas=document.createElement('canvas');
    canvas.width=w;canvas.height=h;
    const ctx=canvas.getContext('2d');
    ctx.fillStyle=ltExp?'#f1f5f9':'#0a0e17';ctx.fillRect(0,0,w,h);
    ctx.drawImage(img,0,0,w,h);
    canvas.toBlob(blob=>{if(blob)exportUtilitiesDownload(blob,'azure-network-map.png')},'image/png');
  };
  img.onerror=()=>{exportUtilitiesNotify('PNG render failed - try SVG export instead')};
  img.src='data:image/svg+xml;base64,'+btoa(unescape(encodeURIComponent(svgStr)));
});

// #endregion MAP PNG EXPORT
