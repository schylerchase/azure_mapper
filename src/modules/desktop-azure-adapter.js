// DesktopAzureAdapter owns Electron desktop APIs for Azure scan, exports, menu, folder, and update events.
function createDesktopAzureAdapter(global){
  function api(){
    return global && global.electronAPI || null;
  }

  function call(name, fallback){
    var electron = api();
    if(electron && typeof electron[name] === 'function'){
      return electron[name].apply(electron, Array.prototype.slice.call(arguments, 2));
    }
    return fallback;
  }

  function subscribe(name, callback){
    var electron = api();
    if(electron && typeof electron[name] === 'function'){
      return electron[name](callback);
    }
    return null;
  }

  return {
    isAvailable: function(){ return !!api(); },
    scanAzure: function(options){ return call('scanAzure', Promise.resolve({ success:false, error:'Desktop scan is not available' }), options); },
    abortScan: function(){ return call('abortScan', undefined); },
    readExportScript: function(name){ return call('readExportScript', Promise.resolve(null), name); },
    openFolder: function(){ return call('openFolder', Promise.resolve(null)); },
    exportBUDRXlsx: function(jsonText){ return call('exportBUDRXlsx', Promise.resolve({ error:'Desktop XLSX export is not available' }), jsonText); },
    downloadUpdate: function(){ return call('downloadUpdate', undefined); },
    installUpdate: function(){ return call('installUpdate', undefined); },
    subscribe: subscribe
  };
}

var DesktopAzureAdapter = createDesktopAzureAdapter(typeof window !== 'undefined' ? window : globalThis);
var _isElectron = DesktopAzureAdapter.isAvailable();

if (typeof window !== 'undefined') {
  window.DesktopAzureAdapter = DesktopAzureAdapter;
  if (window.AppModules) window.AppModules.DesktopAzureAdapter = DesktopAzureAdapter;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = createDesktopAzureAdapter;
}
