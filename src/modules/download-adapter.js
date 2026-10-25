// Download adapter owns browser/Electron file-save behavior and the legacy downloadBlob shim.
var AppDownloads = (function(global){
  function filtersForName(name){
    var ext = (String(name || '').match(/\.([^.]+)$/) || [])[1] || '*';
    return [
      { name: ext.toUpperCase() + ' Files', extensions: [ext] },
      { name: 'All Files', extensions: ['*'] }
    ];
  }

  function saveInBrowser(blob, name){
    var anchor = document.createElement('a');
    var objectUrl = URL.createObjectURL(blob);
    anchor.href = objectUrl;
    anchor.download = name;
    anchor.style.display = 'none';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(function(){ URL.revokeObjectURL(objectUrl); }, 1000);
  }

  function saveInElectron(blob, name){
    var filters = filtersForName(name);
    var notify = global.AppNotifications && global.AppNotifications.show
      ? global.AppNotifications.show
      : function(message){ if (typeof global._showToast === 'function') global._showToast(message); };

    function handleSavedPath(path){
      if (path) notify('Exported: ' + path.split('/').pop());
    }

    if (blob.type && blob.type.startsWith('text')) {
      blob.text().then(function(text){
        global.electronAPI.exportFile(text, name, filters).then(handleSavedPath).catch(function(error){
          console.error('Export failed:', error);
        });
      });
      return;
    }

    blob.arrayBuffer().then(function(buffer){
      global.electronAPI.exportFile(new Uint8Array(buffer), name, filters).then(handleSavedPath).catch(function(error){
        console.error('Export failed:', error);
      });
    });
  }

  function saveBlob(blob, name){
    if (global.electronAPI) {
      saveInElectron(blob, name);
      return;
    }
    saveInBrowser(blob, name);
  }

  return { saveBlob: saveBlob };
})(typeof window !== 'undefined' ? window : globalThis);

function downloadBlob(blob, name){
  return AppDownloads.saveBlob(blob, name);
}

if (typeof window !== 'undefined') {
  window.AppDownloads = AppDownloads;
  window.downloadBlob = downloadBlob;
  if (window.AppModules) window.AppModules.AppDownloads = AppDownloads;
}
