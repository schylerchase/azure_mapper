const { contextBridge, ipcRenderer } = require('electron');

function on(channel, mapper) {
    return (cb) => {
        if (typeof cb !== 'function') return () => {};
        const listener = (...args) => cb(mapper(...args));
        ipcRenderer.on(channel, listener);
        return () => ipcRenderer.removeListener(channel, listener);
    };
}

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
    onScanProgress: on('scan:progress', (_, msg) => msg),
    onScanComplete: on('scan:complete', (_, data) => data),
    onScanError: on('scan:error', (_, msg) => msg),

    // Menu events
    onMenuSave: on('menu:save', () => undefined),
    onMenuSaveAs: on('menu:saveAs', (_, filePath) => filePath),
    onMenuScanAzure: on('menu:scanAzure', () => undefined),

    // Project/file events
    onProjectLoad: on('project:load', (_, payload) => payload),
    onImportFolder: on('import:folder', (_, data) => data),

    // Auto-update events
    onUpdateAvailable: on('update:available', (_, data) => data),
    onUpdateDownloadProgress: on('update:downloadProgress', (_, data) => data),
    onUpdateDownloaded: on('update:downloaded', () => undefined),
    onUpdateError: on('update:error', (_, msg) => msg),
    downloadUpdate: () => ipcRenderer.send('update:download'),
    installUpdate: () => ipcRenderer.send('update:install'),
});
