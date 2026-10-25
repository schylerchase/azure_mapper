// Project file access owns browser/Electron file picker and save dialog behavior.
var AppProjectFiles = (function(global){
  var nativePath = null;
  function hasNativeFileAccess(){
    return !!(global.electronAPI && global.electronAPI.saveFile && global.electronAPI.openFile);
  }

  function setNativePath(filePath){
    nativePath = typeof filePath === 'string' ? filePath : null;
  }

  async function saveText(text, name, mimeType, filePath){
    if (hasNativeFileAccess()) {
      var target = typeof filePath === 'string' ? filePath : nativePath;
      if (!target) {
        var choice = await global.electronAPI.saveAs(name);
        if (!choice || choice.canceled || !choice.filePath) return null;
        target = choice.filePath;
      }
      var result = await global.electronAPI.saveFile(text, target);
      if (!result || !result.success) throw new Error(result && result.error || 'Could not save project');
      nativePath = target;
      return target;
    }

    var blob = new Blob([text], { type: mimeType || 'text/plain' });
    global.AppDownloads.saveBlob(blob, name);
    return Promise.resolve(name);
  }

  function openText(){
    if (!hasNativeFileAccess()) return Promise.resolve(null);
    return global.electronAPI.openFile().then(function(content){
      if (content) nativePath = null;
      return content;
    });
  }

  function chooseBrowserFile(inputId){
    var input = document.getElementById(inputId);
    if (input) input.click();
  }

  function hasDirectoryPicker(){
    return typeof global.showDirectoryPicker === 'function';
  }

  function chooseDirectory(options){
    if (!hasDirectoryPicker()) return Promise.resolve(null);
    return global.showDirectoryPicker(options || { mode: 'read' });
  }

  return {
    hasNativeFileAccess: hasNativeFileAccess,
    saveText: saveText,
    setNativePath: setNativePath,
    openText: openText,
    chooseBrowserFile: chooseBrowserFile,
    hasDirectoryPicker: hasDirectoryPicker,
    chooseDirectory: chooseDirectory
  };
})(typeof window !== 'undefined' ? window : globalThis);

if (typeof window !== 'undefined') {
  window.AppProjectFiles = AppProjectFiles;
  if (window.AppModules) window.AppModules.AppProjectFiles = AppProjectFiles;
}
