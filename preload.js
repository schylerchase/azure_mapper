const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    // Azure CLI
    checkCli: () => ipcRenderer.invoke('azure:check-cli'),
    scanAzure: (opts) => ipcRenderer.invoke('azure:scan', opts),
    abortScan: () => ipcRenderer.send('azure:abort-scan'),

    // File operations
    saveFile: (data, name) => ipcRenderer.invoke('file:save', { filePath: name, data }),
    saveAs: () => ipcRenderer.invoke('dialog:saveAs'),
    openFile: () => ipcRenderer.invoke('dialog:openFile'),
    openFolder: () => ipcRenderer.invoke('dialog:openFolder'),
    exportFile: (data, name, filters) => ipcRenderer.invoke('file:export', { data, name, filters }),
    exportBUDRXlsx: (jsonStr) => ipcRenderer.invoke('file:exportBUDRXlsx', jsonStr),

    // Scan events
    onScanProgress: (cb) => { ipcRenderer.removeAllListeners('scan:progress'); ipcRenderer.on('scan:progress', (_, msg) => cb(msg)); },
    onScanComplete: (cb) => { ipcRenderer.removeAllListeners('scan:complete'); ipcRenderer.on('scan:complete', (_, data) => cb(data)); },
    onScanError: (cb) => { ipcRenderer.removeAllListeners('scan:error'); ipcRenderer.on('scan:error', (_, msg) => cb(msg)); },

    // Menu events
    onMenuSave: (cb) => { ipcRenderer.removeAllListeners('menu:save'); ipcRenderer.on('menu:save', cb); },
    onMenuSaveAs: (cb) => { ipcRenderer.removeAllListeners('menu:saveAs'); ipcRenderer.on('menu:saveAs', (_, filePath) => cb(filePath)); },
    onMenuOpen: (cb) => { ipcRenderer.removeAllListeners('menu:open'); ipcRenderer.on('menu:open', cb); },
    onMenuScanAzure: (cb) => { ipcRenderer.removeAllListeners('menu:scanAzure'); ipcRenderer.on('menu:scanAzure', cb); },
    onMenuToggleTheme: (cb) => { ipcRenderer.removeAllListeners('menu:toggleTheme'); ipcRenderer.on('menu:toggleTheme', cb); },

    // Project/file events
    onProjectLoad: (cb) => { ipcRenderer.removeAllListeners('project:load'); ipcRenderer.on('project:load', (_, payload) => cb(payload)); },
    onImportFolder: (cb) => { ipcRenderer.removeAllListeners('import:folder'); ipcRenderer.on('import:folder', (_, data) => cb(data)); },
    onFileOpened: (cb) => { ipcRenderer.removeAllListeners('file:opened'); ipcRenderer.on('file:opened', (_, content) => cb(content)); },

    // Auto-update events
    onUpdateAvailable: (cb) => { ipcRenderer.removeAllListeners('update:available'); ipcRenderer.on('update:available', (_, data) => cb(data)); },
    onUpdateDownloadProgress: (cb) => { ipcRenderer.removeAllListeners('update:downloadProgress'); ipcRenderer.on('update:downloadProgress', (_, data) => cb(data)); },
    onUpdateDownloaded: (cb) => { ipcRenderer.removeAllListeners('update:downloaded'); ipcRenderer.on('update:downloaded', cb); },
    onUpdateError: (cb) => { ipcRenderer.removeAllListeners('update:error'); ipcRenderer.on('update:error', (_, msg) => cb(msg)); },
    downloadUpdate: () => ipcRenderer.send('update:download'),
    installUpdate: () => ipcRenderer.send('update:install'),
});
