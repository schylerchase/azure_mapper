const { app, BrowserWindow, ipcMain, dialog, Menu, session } = require('electron');
const path = require('path');
const fs = require('fs');
const vm = require('vm');
const { spawn } = require('child_process');
const {
    MAX_IPC_TEXT_BYTES,
    buildScanArgs,
    parseOutputDir,
    resolveOutputDir,
    validateTextPayload
} = require('./main-utils');
const pkg = require('./package.json');

let mainWindow;
let currentScanProc = null;
let autoUpdaterRef = null;
let updateHandlersRegistered = false;

const MAX_EXPORT_BYTES = 100 * 1024 * 1024;

function fail(error) {
    return { success: false, error };
}

function byteLength(data) {
    if (typeof data === 'string') return Buffer.byteLength(data, 'utf8');
    if (Buffer.isBuffer(data)) return data.length;
    if (data instanceof Uint8Array) return data.byteLength;
    return null;
}

function readJsonFolder(folder) {
    const files = fs.readdirSync(folder);
    let totalBytes = 0;
    const data = {};
    for (const file of files) {
        if (!file.endsWith('.json')) continue;
        const fullPath = path.join(folder, file);
        const stat = fs.statSync(fullPath);
        if (!stat.isFile()) continue;
        totalBytes += stat.size;
        if (totalBytes > MAX_IPC_TEXT_BYTES) {
            throw new Error('Import folder exceeds 50 MB JSON limit');
        }
        const content = fs.readFileSync(fullPath, 'utf8');
        JSON.parse(content);
        data[file.replace(/\.json$/, '')] = content;
    }
    return data;
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1600,
        height: 1000,
        minWidth: 1200,
        minHeight: 700,
        title: 'Azure Network Mapper',
        icon: path.join(__dirname, 'icon.png'),
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true
        }
    });

    mainWindow.loadFile('index.html');

    // Prevent navigation to non-file:// URLs
    mainWindow.webContents.on('will-navigate', (event, url) => {
        if (!url.startsWith('file://')) {
            event.preventDefault();
        }
    });

    // Deny all new window requests
    mainWindow.webContents.setWindowOpenHandler(() => {
        return { action: 'deny' };
    });

    buildMenu();
}

function buildMenu() {
    const template = [
        {
            label: 'File',
            submenu: [
                {
                    label: 'Open Project...',
                    accelerator: 'CmdOrCtrl+O',
                    click: () => openProject()
                },
                {
                    label: 'Save Project',
                    accelerator: 'CmdOrCtrl+S',
                    click: () => mainWindow.webContents.send('menu:save')
                },
                {
                    label: 'Save Project As...',
                    accelerator: 'CmdOrCtrl+Shift+S',
                    click: () => saveProjectAs()
                },
                { type: 'separator' },
                {
                    label: 'Import Azure Export Folder...',
                    click: () => importExportFolder()
                },
                { type: 'separator' },
                { role: 'quit' }
            ]
        },
        {
            label: 'View',
            submenu: [
                { role: 'reload' },
                { role: 'toggleDevTools' },
                { type: 'separator' },
                { role: 'zoomIn' },
                { role: 'zoomOut' },
                { role: 'resetZoom' },
                { type: 'separator' },
                { role: 'togglefullscreen' }
            ]
        },
        {
            label: 'Scan',
            submenu: [
                {
                    label: 'Scan Azure...',
                    accelerator: 'CmdOrCtrl+Shift+A',
                    click: () => mainWindow.webContents.send('menu:scanAzure')
                }
            ]
        },
        {
            label: 'Help',
            submenu: [
                {
                    label: 'About Azure Network Mapper',
                    click: () => {
                        dialog.showMessageBox(mainWindow, {
                            type: 'info',
                            title: 'About',
                            message: `Azure Network Mapper v${pkg.version}`,
                            detail: 'Visualize, analyze, and export Azure network topologies.'
                        });
                    }
                }
            ]
        }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
}

async function openProject() {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
        title: 'Open Azure Map Project',
        filters: [{ name: 'Azure Map', extensions: ['azuremap'] }],
        properties: ['openFile']
    });
    if (!canceled && filePaths.length > 0) {
        try {
            const data = fs.readFileSync(filePaths[0], 'utf8');
            mainWindow.webContents.send('project:load', { data, filePath: filePaths[0] });
        } catch (err) {
            dialog.showErrorBox('Open Failed', err.message);
        }
    }
}

async function saveProjectAs() {
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
        title: 'Save Azure Map Project',
        filters: [{ name: 'Azure Map', extensions: ['azuremap'] }],
        defaultPath: 'network-map.azuremap'
    });
    if (!canceled && filePath) {
        mainWindow.webContents.send('menu:saveAs', filePath);
    }
}

async function importExportFolder() {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
        title: 'Select Azure Export Folder',
        properties: ['openDirectory']
    });
    if (!canceled && filePaths.length > 0) {
        try {
            const folder = filePaths[0];
            const data = readJsonFolder(folder);
            mainWindow.webContents.send('import:folder', data);
        } catch (err) {
            dialog.showErrorBox('Import Failed', err.message);
        }
    }
}

// IPC handlers
ipcMain.handle('azure:check-cli', async () => {
    return new Promise((resolve) => {
        // shell: true needed on Windows to resolve az.cmd; no user input in this call
        const proc = spawn('az', ['--version'], { shell: process.platform === 'win32' });
        let output = '';
        proc.stdout.on('data', d => output += d.toString());
        proc.on('close', code => resolve({ installed: code === 0, version: output.split('\n')[0] }));
        proc.on('error', () => resolve({ installed: false, version: null }));
    });
});

ipcMain.handle('azure:scan', async (event, payload = {}) => {
    const { subscription, resourceGroup } = payload;
    if (currentScanProc) {
        const error = 'A scan is already running';
        mainWindow?.webContents.send('scan:error', error);
        return fail(error);
    }
    const scriptPath = path.join(__dirname, 'export-azure-data.sh');
    if (!fs.existsSync(scriptPath)) {
        const error = 'export-azure-data.sh not found';
        mainWindow?.webContents.send('scan:error', error);
        return fail(error);
    }

    let args;
    try {
        args = buildScanArgs(scriptPath, subscription, resourceGroup);
    } catch (err) {
        mainWindow?.webContents.send('scan:error', err.message);
        return fail(err.message);
    }

    return new Promise((resolve) => {
        // No shell: true -- args are passed directly to bash, preventing shell injection
        const proc = spawn('bash', args, { cwd: __dirname });
        currentScanProc = proc;
        let stdout = '', stderr = '';
        proc.stdout.on('data', d => {
            stdout += d.toString();
            mainWindow.webContents.send('scan:progress', d.toString());
        });
        proc.stderr.on('data', d => stderr += d.toString());
        proc.on('close', code => {
            if (currentScanProc === proc) currentScanProc = null;
            if (code === 0) {
                const outDir = parseOutputDir(stdout);
                let files = null;
                if (outDir) {
                    try {
                        const resolvedOutDir = resolveOutputDir(__dirname, outDir);
                        files = readJsonFolder(resolvedOutDir);
                    } catch (err) {
                        const payload = { code, outDir, error: `Scan completed, but output import failed: ${err.message}` };
                        mainWindow.webContents.send('scan:error', payload.error);
                        resolve(fail(payload.error));
                        return;
                    }
                }
                const payload = { code, outDir, outputDir: outDir, files };
                mainWindow.webContents.send('scan:complete', payload);
                resolve({ success: true, ...payload });
            } else {
                const error = stderr || `Scan failed with exit code ${code}`;
                mainWindow.webContents.send('scan:error', error);
                resolve(fail(error));
            }
        });
        proc.on('error', err => {
            if (currentScanProc === proc) currentScanProc = null;
            mainWindow.webContents.send('scan:error', err.message);
            resolve(fail(err.message));
        });
    });
});

ipcMain.on('azure:abort-scan', () => {
    if (!currentScanProc) return;
    const proc = currentScanProc;
    currentScanProc = null;
    proc.kill();
    mainWindow?.webContents.send('scan:error', 'Scan aborted');
});

ipcMain.handle('file:save', async (event, payload = {}) => {
    const { filePath, data } = payload;
    if (!filePath || !filePath.endsWith('.azuremap')) {
        return fail('Invalid file path: must end with .azuremap');
    }
    try {
        validateTextPayload(data, 'project data');
    } catch (err) {
        return fail(err.message);
    }
    // Resolve and reject paths with traversal segments
    const resolved = path.resolve(filePath);
    if (resolved !== path.normalize(filePath) && resolved !== filePath) {
        return fail('Invalid file path: traversal detected');
    }
    if (resolved.includes('..')) {
        return fail('Invalid file path: traversal detected');
    }
    try {
        fs.writeFileSync(resolved, data, 'utf8');
        return { success: true };
    } catch (err) {
        return fail(err.message);
    }
});

ipcMain.handle('dialog:saveAs', async () => {
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
        title: 'Save Azure Map Project',
        filters: [{ name: 'Azure Map', extensions: ['azuremap'] }],
        defaultPath: 'network-map.azuremap'
    });
    return { canceled, filePath };
});

ipcMain.handle('dialog:openFile', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
        title: 'Open Azure Map Project',
        filters: [{ name: 'Azure Map', extensions: ['azuremap'] }],
        properties: ['openFile']
    });
    if (!canceled && filePaths.length > 0) {
        const stat = fs.statSync(filePaths[0]);
        if (stat.size > MAX_IPC_TEXT_BYTES) throw new Error('Project file exceeds 50 MB limit');
        return fs.readFileSync(filePaths[0], 'utf8');
    }
    return null;
});

ipcMain.handle('dialog:openFolder', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
        title: 'Select Azure Export Folder',
        properties: ['openDirectory']
    });
    if (!canceled && filePaths.length > 0) {
        return readJsonFolder(filePaths[0]);
    }
    return null;
});

ipcMain.handle('file:export', async (event, payload = {}) => {
    const { data, name, filters } = payload;
    const len = byteLength(data);
    if (len == null) return null;
    if (len > MAX_EXPORT_BYTES) throw new Error('Export exceeds 100 MB limit');
    const safeName = path.basename(name || 'export');
    const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
        title: 'Export',
        defaultPath: safeName,
        filters: filters || [{ name: 'All Files', extensions: ['*'] }]
    });
    if (!canceled && filePath) {
        if (data instanceof Uint8Array || Buffer.isBuffer(data)) {
            fs.writeFileSync(filePath, Buffer.from(data));
        } else {
            fs.writeFileSync(filePath, data, 'utf8');
        }
        return filePath;
    }
    return null;
});

ipcMain.handle('file:exportBUDRXlsx', async (event, jsonStr) => {
    try {
        validateTextPayload(jsonStr, 'BUDR export data');
        const data = JSON.parse(jsonStr);
        const xlsxPath = path.join(__dirname, 'libs', 'xlsx.bundle.min.js');
        const sandbox = {};
        vm.createContext(sandbox);
        vm.runInContext(fs.readFileSync(xlsxPath, 'utf8'), sandbox, { filename: xlsxPath });
        const XLSX = sandbox.XLSX;
        if (!XLSX?.utils?.book_new) throw new Error('SheetJS bundle did not load');

        const wb = XLSX.utils.book_new();
        const summaryRows = Object.entries(data.summary || {}).map(([key, value]) => [key, value]);
        XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet([['Metric', 'Value'], ...summaryRows]), 'Summary');

        const assessments = (data.assessments || []).map(a => ({
            Type: a.type || '',
            Resource: a.id || '',
            Name: a.name || '',
            Tier: a.profile?.tier || '',
            RTO: a.profile?.rto || '',
            RPO: a.profile?.rpo || '',
            Signals: a.signals ? Object.entries(a.signals).map(([k, v]) => `${k}=${v}`).join('; ') : ''
        }));
        XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(assessments), 'Assessments');

        const findings = (data.findings || []).map(f => ({
            Severity: f.severity || '',
            Control: f.control || f.id || '',
            Resource: f.resource || '',
            Message: f.message || f.description || '',
            Framework: f.framework || ''
        }));
        XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(findings), 'Findings');

        const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
            title: 'Export BUDR XLSX',
            defaultPath: 'budr-assessment.xlsx',
            filters: [{ name: 'Excel Files', extensions: ['xlsx'] }]
        });
        if (canceled || !filePath) return null;
        const out = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
        fs.writeFileSync(filePath, out);
        return { path: filePath };
    } catch (err) {
        return { error: err.message };
    }
});

// ── Auto-Update ───────────────────────────────────────────────────

function checkForUpdates() {
    try {
        const { autoUpdater } = require('electron-updater');
        autoUpdaterRef = autoUpdater;
        autoUpdater.autoDownload = false;
        if (updateHandlersRegistered) return;
        updateHandlersRegistered = true;
        autoUpdater.on('update-available', (info) => {
            mainWindow?.webContents.send('update:available', {
                version: info.version,
                currentVersion: pkg.version,
                releaseNotes: info.releaseNotes
            });
        });
        autoUpdater.on('download-progress', (info) => {
            mainWindow?.webContents.send('update:downloadProgress', info);
        });
        autoUpdater.on('update-downloaded', () => {
            mainWindow?.webContents.send('update:downloaded');
        });
        autoUpdater.on('error', (err) => {
            mainWindow?.webContents.send('update:error', err.message);
        });
        autoUpdater.checkForUpdates().catch(() => {});
    } catch {}
}

ipcMain.on('update:download', () => {
    autoUpdaterRef?.downloadUpdate().catch(err => {
        mainWindow?.webContents.send('update:error', err.message);
    });
});

ipcMain.on('update:install', () => {
    autoUpdaterRef?.quitAndInstall();
});

// ── App Lifecycle ─────────────────────────────────────────────────

app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
        callback(false);
    });

    // Set dock icon on macOS
    if (process.platform === 'darwin' && app.dock) {
        app.dock.setIcon(path.join(__dirname, 'icon.png'));
    }

    createWindow();

    // Check for updates after a short delay
    setTimeout(checkForUpdates, 5000);

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});
