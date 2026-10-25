// CIDR overlap detection and IP address manipulation
// Handles subnet overlap detection, IP range calculations, and CIDR validation
// Extracted from index.html for modularization

export const ipToInt = (ip) => {
  if (!ip || typeof ip !== 'string') return null;
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (let i = 0; i < 4; i++) {
    const o = parseInt(parts[i], 10);
    if (isNaN(o) || o < 0 || o > 255 || parts[i] !== String(o)) return null;
    n = (n * 256) + o;
  }
  return n >>> 0;
};

export const intToIp = (n) => {
  n = n >>> 0;
  return `${(n >>> 24) & 0xFF}.${(n >>> 16) & 0xFF}.${(n >>> 8) & 0xFF}.${n & 0xFF}`;
};

export const parseCIDR = (cidr) => {
  if (!cidr || typeof cidr !== 'string') return null;
  const parts = cidr.trim().split('/');
  if (parts.length !== 2) return null;
  const network = ipToInt(parts[0]);
  const prefix = parseInt(parts[1], 10);
  if (network === null || isNaN(prefix) || prefix < 0 || prefix > 32 || parts[1] !== String(prefix)) return null;
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  if (((network & mask) >>> 0) !== network) return null;
  const size = prefix === 32 ? 1 : (1 << (32 - prefix)) >>> 0;
  return { network, prefix, mask, size };
};

export const cidrToString = (network, prefix) => {
  return `${intToIp(network)}/${prefix}`;
};

export const splitCIDR = (cidr) => {
  const p = parseCIDR(cidr);
  if (!p || p.prefix >= 32) return null;
  const np = p.prefix + 1;
  const half = p.size >>> 1;
  return [cidrToString(p.network, np), cidrToString((p.network + half) >>> 0, np)];
};

export const cidrContains = (parent, child) => {
  const p = parseCIDR(parent);
  const c = parseCIDR(child);
  if (!p || !c || c.prefix < p.prefix) return false;
  return ((c.network & p.mask) >>> 0) === p.network;
};

export const cidrOverlap = (a, b) => {
  const pa = parseCIDR(a);
  const pb = parseCIDR(b);
  if (!pa || !pb) return false;
  const bigger = pa.prefix <= pb.prefix ? pa : pb;
  const smaller = pa.prefix <= pb.prefix ? pb : pa;
  return ((smaller.network & bigger.mask) >>> 0) === bigger.network;
};

function ipv6ToInt(ip) {
  if (typeof ip !== 'string' || !ip.includes(':')) return null;
  let address = ip;
  if (address.includes('.')) {
    const colon = address.lastIndexOf(':');
    const ipv4 = ipToInt(address.slice(colon + 1));
    if (ipv4 === null) return null;
    address = address.slice(0, colon + 1) + (ipv4 >>> 16).toString(16) + ':' + (ipv4 & 65535).toString(16);
  }
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const words = left.concat(right);
  if (words.some(word => !/^[0-9a-f]{1,4}$/i.test(word))) return null;
  if (halves.length === 1 ? words.length !== 8 : words.length >= 8) return null;
  const expanded = halves.length === 2 ? left.concat(Array(8 - words.length).fill('0'), right) : left;
  return expanded.reduce((value, word) => (value << 16n) | BigInt(parseInt(word, 16)), 0n);
}

export const ipInCIDR = (ip, cidr) => {
  if (typeof cidr !== 'string' || typeof ip !== 'string') return false;
  if (ip.includes(':') || cidr.includes(':')) {
    const parts = cidr.trim().split('/');
    if (parts.length !== 2 || !/^(0|[1-9][0-9]*)$/.test(parts[1])) return false;
    const prefix = Number(parts[1]);
    if (prefix > 128) return false;
    const address = ipv6ToInt(ip.trim());
    const network = ipv6ToInt(parts[0]);
    if (address === null || network === null) return false;
    const shift = BigInt(128 - prefix);
    if ((network >> shift) << shift !== network) return false;
    return address >> shift === network >> shift;
  }
  const n = ipToInt(ip);
  const p = parseCIDR(cidr);
  if (n === null || !p) return false;
  return ((n & p.mask) >>> 0) === p.network;
};
