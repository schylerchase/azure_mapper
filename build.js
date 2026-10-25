#!/usr/bin/env node
// esbuild configuration for Azure Network Mapper
// Bundles ES modules into single IIFE for Electron app

const esbuild = require('esbuild');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const isProd = process.argv.includes('--production') || process.env.NODE_ENV === 'production';
const isDev = !isProd;
const watch = process.argv.includes('--watch');

const buildConfig = {
  entryPoints: ['src/main.js'],
  bundle: true,
  outfile: 'dist/app.bundle.js',
  format: 'iife',
  globalName: 'AppBundle',
  minify: !isDev,
  sourcemap: isDev,
  target: 'es2022',
  platform: 'browser',
  metafile: isProd,
  define: {
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV || 'development')
  },
  logLevel: 'info'
};

// Build demo-data.js as a separate lazy-loadable bundle (IIFE)
const demoConfig = {
  entryPoints: ['src/modules/demo-data.js'], bundle: true, outfile: 'dist/demo-data.bundle.js',
  format: 'iife', globalName: 'DemoDataModule', minify: isProd, target: 'es2022', platform: 'browser', logLevel: 'silent'
};
async function buildDemoData() {
  await esbuild.build(demoConfig);
  const size = (fs.statSync('dist/demo-data.bundle.js').size / 1024).toFixed(1);
  console.log(`  dist/demo-data.bundle.js    ${size}kb`);
}

// Build iac-generator.js as a separate lazy-loadable bundle (IIFE)
const iacConfig = {
  entryPoints: ['src/modules/iac-generator.js'], bundle: true, outfile: 'dist/iac-generator.bundle.js',
  format: 'iife', globalName: 'IacGeneratorModule', minify: isProd, target: 'es2022', platform: 'browser', logLevel: 'silent'
};
async function buildIacGenerator() {
  await esbuild.build(iacConfig);
  const size = (fs.statSync('dist/iac-generator.bundle.js').size / 1024).toFixed(1);
  console.log(`  dist/iac-generator.bundle.js ${size}kb`);
}

// Build custom D3 bundle (5 modules vs full 30+ module d3.min.js)
const d3Config = {
  entryPoints: ['src/d3-custom.js'], bundle: true, outfile: 'libs/d3.custom.min.js',
  format: 'iife', globalName: 'd3', minify: true, target: 'es2022', platform: 'browser', logLevel: 'silent'
};
async function buildD3() {
  await esbuild.build(d3Config);
  const size = (fs.statSync('libs/d3.custom.min.js').size / 1024).toFixed(1);
  console.log(`  libs/d3.custom.min.js  ${size}kb`);
}

function expandAppCoreRegions(src) {
  return src.replace(/^\/\/ @app-core-region:\s*(.+)$/gm, (match, regionPath) => {
    const fullPath = path.join(__dirname, regionPath.trim());
    if (!fs.existsSync(fullPath)) {
      throw new Error(`Missing app-core region file: ${regionPath}`);
    }
    const region = fs.readFileSync(fullPath, 'utf8').trimEnd();
    return `// BEGIN app-core region: ${regionPath}\n${region}\n// END app-core region: ${regionPath}`;
  });
}

function getAppCoreRegionPaths() {
  const manifest = fs.readFileSync('src/app-core.js', 'utf8');
  return Array.from(manifest.matchAll(/^\/\/ @app-core-region:\s*(.+)$/gm), match => match[1].trim());
}

// Process app-core.js assembly manifest (plain script, not an ES module — minify only)
async function buildCore() {
  const src = expandAppCoreRegions(fs.readFileSync('src/app-core.js', 'utf8'));
  if (isProd) {
    const result = await esbuild.transform(src, { minify: true, target: 'es2022' });
    fs.writeFileSync('dist/app-core.js', result.code);
  } else {
    fs.writeFileSync('dist/app-core.js', src);
  }
}

if (watch) {
  fs.mkdirSync('dist', { recursive: true });
  Promise.all([buildConfig, demoConfig, iacConfig, d3Config].map(async config => {
    const context = await esbuild.context(config);
    await context.watch();
  })).then(() => {
    console.log('Watching for changes...');
  }).catch(() => process.exit(1));

  // Also watch app-core.js assembly and rebuild on change
  buildCore().catch(error => { console.error(error); process.exitCode = 1; });
  const rebuildCore = () => {
    buildCore().then(() => console.log('  Rebuilt app-core.js')).catch(error => console.error(error));
  };
  fs.watch('src/app-core.js', rebuildCore);
  getAppCoreRegionPaths().forEach(regionPath => {
    fs.watch(regionPath, rebuildCore);
  });
} else {
  (async () => {
    fs.mkdirSync('dist', { recursive: true });
    await buildDemoData();
    await buildIacGenerator();
    if (isProd) {
      const hash = file => crypto.createHash('md5').update(fs.readFileSync(file)).digest('hex').slice(0, 8);
      buildConfig.define.__DEMO_BUNDLE_VERSION__ = JSON.stringify(hash(demoConfig.outfile));
      buildConfig.define.__IAC_BUNDLE_VERSION__ = JSON.stringify(hash(iacConfig.outfile));
    }
    const result = await esbuild.build(buildConfig);
    await buildCore();
    await buildD3();

    // Log bundle sizes
    const bundleSize = (fs.statSync('dist/app.bundle.js').size / 1024).toFixed(1);
    console.log(`  dist/app.bundle.js  ${bundleSize}kb`);
    const coreSize = (fs.statSync('dist/app-core.js').size / 1024).toFixed(1);
    console.log(`  dist/app-core.js    ${coreSize}kb`);

    if (!isProd) return;

    // Write metafile for bundle composition analysis
    if (result.metafile) {
      fs.writeFileSync('dist/meta.json', JSON.stringify(result.metafile));
      const text = esbuild.analyzeMetafileSync(result.metafile, { verbose: false });
      console.log(text);
    }

    // Auto-inject content hashes into index.html for cache busting
    const bundleHash = crypto.createHash('md5').update(fs.readFileSync('dist/app.bundle.js')).digest('hex').slice(0, 8);
    const coreHash = crypto.createHash('md5').update(fs.readFileSync('dist/app-core.js')).digest('hex').slice(0, 8);
    const htmlPath = path.join(__dirname, 'index.html');
    let html = fs.readFileSync(htmlPath, 'utf8');
    html = html.replace(/app\.bundle\.js\?v=[^"]+/, `app.bundle.js?v=${bundleHash}`);
    html = html.replace(/app-core\.js\?v=[^"]+/, `app-core.js?v=${coreHash}`);
    fs.writeFileSync(htmlPath, html, 'utf8');
    console.log(`Cache bust: app.bundle.js?v=${bundleHash}, app-core.js?v=${coreHash}`);
  })().catch(error => { console.error(error); process.exit(1); });
}
