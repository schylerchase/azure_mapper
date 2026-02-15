const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    checkCli: () => ipcRenderer.invoke('azure:check-cli'),
    scanAzure: (opts) => ipcRenderer.invoke('azure:scan', opts),
    saveFile: (filePath, data) => ipcRenderer.invoke('file:save', { filePath, data }),
    saveAs: () => ipcRenderer.invoke('dialog:saveAs'),

    onMenuSave: (cb) => { ipcRenderer.removeAllListeners('menu:save'); ipcRenderer.on('menu:save', cb); },
    onMenuSaveAs: (cb) => { ipcRenderer.removeAllListeners('menu:saveAs'); ipcRenderer.on('menu:saveAs', (_, filePath) => cb(filePath)); },
    onMenuScanAzure: (cb) => { ipcRenderer.removeAllListeners('menu:scanAzure'); ipcRenderer.on('menu:scanAzure', cb); },
    onProjectLoad: (cb) => { ipcRenderer.removeAllListeners('project:load'); ipcRenderer.on('project:load', (_, payload) => cb(payload)); },
    onImportFolder: (cb) => { ipcRenderer.removeAllListeners('import:folder'); ipcRenderer.on('import:folder', (_, data) => cb(data)); },
    onScanProgress: (cb) => { ipcRenderer.removeAllListeners('scan:progress'); ipcRenderer.on('scan:progress', (_, msg) => cb(msg)); }
});
