// AppCompatibilityPublisher owns legacy browser globals created by the app bundle entrypoint.

function browserGlobal(root){
  return root || (typeof window !== 'undefined' ? window : globalThis);
}

function appendBundleScript(root, src, onLoad, onError){
  var doc=root.document;
  if(!doc||!doc.head){
    onError();
    return;
  }
  var script=doc.createElement('script');
  script.src=src;
  script.onload=onLoad;
  script.onerror=onError;
  doc.head.appendChild(script);
}

function loadDemoDataBundle(root, src){
  return new Promise(function(resolve){
    if(root.generateDemo)return resolve(root.generateDemo);
    appendBundleScript(root, src, function(){
      root.generateDemo=root.DemoDataModule&&root.DemoDataModule.generateDemo;
      resolve(root.generateDemo);
    }, function(){
      console.error('Failed to load '+src);
      resolve(null);
    });
  });
}

function loadIacGeneratorBundle(root, src){
  return new Promise(function(resolve){
    if(root.IacGeneratorModule)return resolve(root.IacGeneratorModule);
    appendBundleScript(root, src, function(){
      root.IacGenerator=root.IacGeneratorModule;
      if(root.AppModules)root.AppModules.IacGenerator=root.IacGeneratorModule;
      resolve(root.IacGeneratorModule);
    }, function(){
      console.error('Failed to load '+src);
      resolve(null);
    });
  });
}

export function publishLegacyAppModules(modules, options){
  var root=browserGlobal(options&&options.root);
  root.AppModules=modules;
  Object.assign(root, modules);
  return modules;
}

export function ensureLegacyComplianceFindings(options){
  var root=browserGlobal(options&&options.root);
  if(!root._complianceFindings)root._complianceFindings=[];
  return root._complianceFindings;
}

export function installLazyBundleLoaders(options){
  var opts=options||{};
  var root=browserGlobal(opts.root);
  var demoVersion=typeof __DEMO_BUNDLE_VERSION__==='undefined'?'':__DEMO_BUNDLE_VERSION__;
  var iacVersion=typeof __IAC_BUNDLE_VERSION__==='undefined'?'':__IAC_BUNDLE_VERSION__;
  var demoSrc=opts.demoSrc||'dist/demo-data.bundle.js'+(demoVersion?'?v='+demoVersion:'');
  var iacSrc=opts.iacSrc||'dist/iac-generator.bundle.js'+(iacVersion?'?v='+iacVersion:'');
  root._loadDemoData=function(){return loadDemoDataBundle(root, demoSrc)};
  root._loadIacGenerator=function(){return loadIacGeneratorBundle(root, iacSrc)};
  return {
    loadDemoData: root._loadDemoData,
    loadIacGenerator: root._loadIacGenerator
  };
}
