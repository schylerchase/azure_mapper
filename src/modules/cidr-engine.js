// CIDR overlap detection and IP address manipulation
// Handles subnet overlap detection, IP range calculations, and CIDR validation
// Extracted from index.html for modularization

export const ipToInt=(ip)=>{if(!ip||typeof ip!=='string')return null;const parts=ip.split('.');if(parts.length!==4)return null;let n=0;for(let i=0;i<4;i++){const o=parseInt(parts[i],10);if(isNaN(o)||o<0||o>255||parts[i]!==String(o))return null;n=(n*256)+o}return n>>>0};
export const intToIp=(n)=>{n=n>>>0;return`${(n>>>24)&0xFF}.${(n>>>16)&0xFF}.${(n>>>8)&0xFF}.${n&0xFF}`};
export const parseCIDR=(cidr)=>{if(!cidr||typeof cidr!=='string')return null;const parts=cidr.trim().split('/');if(parts.length!==2)return null;const network=ipToInt(parts[0]);const prefix=parseInt(parts[1],10);if(network===null||isNaN(prefix)||prefix<0||prefix>32||parts[1]!==String(prefix))return null;const mask=prefix===0?0:(0xFFFFFFFF<<(32-prefix))>>>0;if(((network&mask)>>>0)!==network)return null;const size=prefix===32?1:(1<<(32-prefix))>>>0;return{network,prefix,mask,size}};
export const cidrToString=(network,prefix)=>`${intToIp(network)}/${prefix}`;
export const splitCIDR=(cidr)=>{const p=parseCIDR(cidr);if(!p||p.prefix>=32)return null;const np=p.prefix+1;const half=p.size>>>1;return[cidrToString(p.network,np),cidrToString((p.network+half)>>>0,np)]};
export const cidrContains=(parent,child)=>{const p=parseCIDR(parent);const c=parseCIDR(child);if(!p||!c||c.prefix<p.prefix)return false;return((c.network&p.mask)>>>0)===p.network};
export const cidrOverlap=(a,b)=>{const pa=parseCIDR(a);const pb=parseCIDR(b);if(!pa||!pb)return false;const bigger=pa.prefix<=pb.prefix?pa:pb;const smaller=pa.prefix<=pb.prefix?pb:pa;return((smaller.network&bigger.mask)>>>0)===bigger.network};
export const ipInCIDR=(ip,cidr)=>{const n=ipToInt(ip);const p=parseCIDR(cidr);if(n===null||!p)return false;return((n&p.mask)>>>0)===p.network};
