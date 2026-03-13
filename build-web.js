#!/usr/bin/env node
// Assembles a public/ directory for static web deployment (Vercel, Netlify, etc.)
// Run after build.js --production

const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, 'public');

function mkdirp(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function copyDir(src, dest) {
  mkdirp(dest);
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDir(srcPath, destPath);
    else fs.copyFileSync(srcPath, destPath);
  }
}

// Clean
if (fs.existsSync(OUT)) fs.rmSync(OUT, { recursive: true });
mkdirp(OUT);

// Copy built bundles
mkdirp(path.join(OUT, 'dist'));
fs.copyFileSync('dist/app.bundle.js', path.join(OUT, 'dist/app.bundle.js'));
fs.copyFileSync('dist/app-core.js', path.join(OUT, 'dist/app-core.js'));

// Copy static assets
fs.copyFileSync('index.html', path.join(OUT, 'index.html'));
fs.copyFileSync('logo.png', path.join(OUT, 'logo.png'));
fs.copyFileSync('icon.png', path.join(OUT, 'icon.png'));

// Copy libs
copyDir('libs', path.join(OUT, 'libs'));

// Copy styles
mkdirp(path.join(OUT, 'src/styles'));
copyDir('src/styles', path.join(OUT, 'src/styles'));

// Copy data
mkdirp(path.join(OUT, 'src/data'));
copyDir('src/data', path.join(OUT, 'src/data'));

console.log('  public/ assembled for web deployment');
