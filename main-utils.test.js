const {
    SAFE_INPUT,
    MAX_IPC_TEXT_BYTES,
    validateInput,
    validateTextPayload,
    buildScanArgs,
    parseOutputDir,
    resolveOutputDir,
    mapFolderFiles
} = require('./main-utils');

// ============================================================
// validateInput
// ============================================================

describe('validateInput', () => {
    test('accepts alphanumeric string', () => {
        expect(validateInput('mySubscription123')).toBe(true);
    });

    test('accepts hyphens and underscores', () => {
        expect(validateInput('my-subscription_name')).toBe(true);
    });

    test('accepts dots', () => {
        expect(validateInput('sub.name.v2')).toBe(true);
    });

    test('accepts spaces', () => {
        expect(validateInput('My Azure Subscription')).toBe(true);
    });

    test('accepts slashes', () => {
        expect(validateInput('team/project')).toBe(true);
    });

    test('accepts parentheses', () => {
        expect(validateInput('Visual Studio Enterprise (MPN)')).toBe(true);
    });

    test('accepts GUID-like subscription ID', () => {
        expect(validateInput('a1b2c3d4-e5f6-7890-abcd-ef1234567890')).toBe(true);
    });

    test('rejects semicolons (command chaining)', () => {
        expect(validateInput('sub; rm -rf /')).toBe(false);
    });

    test('rejects backticks (command substitution)', () => {
        expect(validateInput('sub`whoami`')).toBe(false);
    });

    test('rejects pipe (command piping)', () => {
        expect(validateInput('sub | cat /etc/passwd')).toBe(false);
    });

    test('rejects $() (command substitution)', () => {
        expect(validateInput('$(whoami)')).toBe(false);
    });

    test('rejects && (command chaining)', () => {
        expect(validateInput('sub && echo pwned')).toBe(false);
    });

    test('rejects || (command chaining)', () => {
        expect(validateInput('sub || echo pwned')).toBe(false);
    });

    test('rejects newlines', () => {
        expect(validateInput('sub\nwhoami')).toBe(false);
    });

    test('rejects empty string', () => {
        expect(validateInput('')).toBe(false);
    });

    test('rejects null', () => {
        expect(validateInput(null)).toBe(false);
    });

    test('rejects undefined', () => {
        expect(validateInput(undefined)).toBe(false);
    });

    test('rejects number', () => {
        expect(validateInput(42)).toBe(false);
    });

    test('rejects angle brackets', () => {
        expect(validateInput('sub > /tmp/out')).toBe(false);
    });

    test('rejects curly braces', () => {
        expect(validateInput('{echo,pwned}')).toBe(false);
    });

    test('rejects input exceeding max length (256)', () => {
        expect(validateInput('a'.repeat(257))).toBe(false);
    });

    test('accepts input at max length (256)', () => {
        expect(validateInput('a'.repeat(256))).toBe(true);
    });

    test('rejects whitespace-only strings', () => {
        expect(validateInput('   ')).toBe(false);
    });
});

// ============================================================
// validateTextPayload
// ============================================================

describe('validateTextPayload', () => {
    test('accepts strings under the limit', () => {
        expect(validateTextPayload('hello', 'test')).toBe('hello');
    });

    test('rejects non-strings', () => {
        expect(() => validateTextPayload(Buffer.from('x'), 'test')).toThrow('expected string');
    });

    test('rejects strings over the configured limit', () => {
        expect(() => validateTextPayload('abcd', 'test', 3)).toThrow('exceeds');
    });

    test('default limit is 50 MB', () => {
        expect(MAX_IPC_TEXT_BYTES).toBe(50 * 1024 * 1024);
    });
});

// ============================================================
// buildScanArgs
// ============================================================

describe('buildScanArgs', () => {
    const scriptPath = '/app/export-azure-data.sh';

    test('builds args with subscription only', () => {
        const args = buildScanArgs(scriptPath, 'my-sub');
        expect(args).toEqual([scriptPath, '-s', 'my-sub']);
    });

    test('builds args with subscription and resource group', () => {
        const args = buildScanArgs(scriptPath, 'my-sub', 'rg-prod');
        expect(args).toEqual([scriptPath, '-s', 'my-sub', '-g', 'rg-prod']);
    });

    test('skips resource group when falsy', () => {
        const args = buildScanArgs(scriptPath, 'my-sub', '');
        expect(args).toEqual([scriptPath, '-s', 'my-sub']);
    });

    test('skips resource group when undefined', () => {
        const args = buildScanArgs(scriptPath, 'my-sub', undefined);
        expect(args).toEqual([scriptPath, '-s', 'my-sub']);
    });

    test('throws on empty subscription', () => {
        expect(() => buildScanArgs(scriptPath, '')).toThrow('Subscription is required');
    });

    test('throws on null subscription', () => {
        expect(() => buildScanArgs(scriptPath, null)).toThrow('Subscription is required');
    });

    test('throws on unsafe subscription', () => {
        expect(() => buildScanArgs(scriptPath, 'sub; rm -rf /')).toThrow('unsafe characters');
    });

    test('throws on unsafe resource group', () => {
        expect(() => buildScanArgs(scriptPath, 'my-sub', 'rg$(whoami)')).toThrow('unsafe characters');
    });

    test('accepts GUID subscription', () => {
        const args = buildScanArgs(scriptPath, 'a1b2c3d4-e5f6-7890-abcd-ef1234567890');
        expect(args[2]).toBe('a1b2c3d4-e5f6-7890-abcd-ef1234567890');
    });

    test('accepts subscription with spaces and parens', () => {
        const args = buildScanArgs(scriptPath, 'Visual Studio Enterprise (MPN)');
        expect(args[2]).toBe('Visual Studio Enterprise (MPN)');
    });

    test('trims subscription and resource group values', () => {
        const args = buildScanArgs(scriptPath, ' my-sub ', ' rg-prod ');
        expect(args).toEqual([scriptPath, '-s', 'my-sub', '-g', 'rg-prod']);
    });
});

// ============================================================
// parseOutputDir
// ============================================================

describe('parseOutputDir', () => {
    test('parses "Output directory:" line from multi-line output', () => {
        const stdout = [
            'Setting subscription to: my-sub',
            'Output directory: azure-export-my-sub-20250215-120000',
            'Exporting: Virtual Networks...',
            '  -> vnets.json (5 items)',
            'Export complete: azure-export-my-sub-20250215-120000',
            'To load: Use Upload in Azure Network Mapper'
        ].join('\n');
        expect(parseOutputDir(stdout)).toBe('azure-export-my-sub-20250215-120000');
    });

    test('returns last non-empty line as fallback', () => {
        const stdout = 'line1\nline2\nlast-line\n';
        expect(parseOutputDir(stdout)).toBe('last-line');
    });

    test('handles single line', () => {
        expect(parseOutputDir('only-line')).toBe('only-line');
    });

    test('returns null for empty string', () => {
        expect(parseOutputDir('')).toBe(null);
    });

    test('returns null for null', () => {
        expect(parseOutputDir(null)).toBe(null);
    });

    test('returns null for undefined', () => {
        expect(parseOutputDir(undefined)).toBe(null);
    });

    test('trims whitespace from output dir line', () => {
        const stdout = 'Output directory:   azure-export-my-sub  \n';
        expect(parseOutputDir(stdout)).toBe('azure-export-my-sub');
    });

    test('handles trailing newlines in fallback', () => {
        const stdout = 'some-dir\n\n\n';
        expect(parseOutputDir(stdout)).toBe('some-dir');
    });
});

// ============================================================
// resolveOutputDir
// ============================================================

describe('resolveOutputDir', () => {
    const baseDir = process.platform === 'win32' ? 'C:\\app' : '/app';

    test('resolves relative output directory under base', () => {
        expect(resolveOutputDir(baseDir, 'azure-export-sub-20260101')).toBe(
            require('path').resolve(baseDir, 'azure-export-sub-20260101')
        );
    });

    test('rejects absolute output directory', () => {
        const absolute = process.platform === 'win32' ? 'C:\\tmp\\export' : '/tmp/export';
        expect(() => resolveOutputDir(baseDir, absolute)).toThrow('absolute paths');
    });

    test('rejects traversal outside base', () => {
        expect(() => resolveOutputDir(baseDir, '../outside')).toThrow('traversal');
    });

    test('rejects missing output directory', () => {
        expect(() => resolveOutputDir(baseDir, '')).toThrow('not reported');
    });
});

// ============================================================
// mapFolderFiles
// ============================================================

describe('mapFolderFiles', () => {
    test('maps JSON files to basename keys', () => {
        const files = ['vnets.json', 'nsgs.json', 'readme.txt'];
        const reader = (f) => `content-of-${f}`;
        const result = mapFolderFiles(files, reader);
        expect(result).toEqual({
            'vnets': 'content-of-vnets.json',
            'nsgs': 'content-of-nsgs.json'
        });
    });

    test('skips non-JSON files', () => {
        const files = ['data.csv', 'notes.txt', 'only.json'];
        const reader = (f) => `content-of-${f}`;
        const result = mapFolderFiles(files, reader);
        expect(Object.keys(result)).toEqual(['only']);
    });

    test('returns empty object for empty file list', () => {
        const result = mapFolderFiles([], () => '');
        expect(result).toEqual({});
    });

    test('returns empty object for null file list', () => {
        const result = mapFolderFiles(null, () => '');
        expect(result).toEqual({});
    });

    test('uses provided readFile function', () => {
        const mockRead = jest.fn().mockReturnValue('{"data":true}');
        mapFolderFiles(['test.json'], mockRead);
        expect(mockRead).toHaveBeenCalledWith('test.json');
        expect(mockRead).toHaveBeenCalledTimes(1);
    });

    test('handles files with dots in name', () => {
        const files = ['route-tables.json'];
        const reader = () => '[]';
        const result = mapFolderFiles(files, reader);
        expect(result).toHaveProperty('route-tables');
    });

    test('propagates readFile errors to caller', () => {
        const files = ['bad.json'];
        const reader = () => { throw new Error('ENOENT'); };
        expect(() => mapFolderFiles(files, reader)).toThrow('ENOENT');
    });
});

// ============================================================
// preload.js API shape
// ============================================================

describe('preload.js API shape', () => {
    test('exports expected electronAPI methods', () => {
        // Static analysis: read the file and verify expected API surface
        const fs = require('fs');
        const path = require('path');
        const content = fs.readFileSync(path.join(__dirname, 'preload.js'), 'utf8');

        const expectedMethods = [
            'checkCli',
            'scanAzure',
            'saveFile',
            'saveAs',
            'onMenuSave',
            'onMenuSaveAs',
            'onMenuScanAzure',
            'onProjectLoad',
            'onImportFolder',
            'onScanProgress'
        ];

        for (const method of expectedMethods) {
            expect(content).toContain(method);
        }
    });

    test('uses contextBridge.exposeInMainWorld', () => {
        const fs = require('fs');
        const path = require('path');
        const content = fs.readFileSync(path.join(__dirname, 'preload.js'), 'utf8');
        expect(content).toContain('contextBridge.exposeInMainWorld');
    });

    test('uses contextIsolation pattern (no nodeIntegration)', () => {
        const fs = require('fs');
        const path = require('path');
        const content = fs.readFileSync(path.join(__dirname, 'preload.js'), 'utf8');
        // Should use ipcRenderer.invoke (not direct require of electron modules)
        expect(content).toContain('ipcRenderer.invoke');
        expect(content).toContain('ipcRenderer.on');
        // Should NOT expose ipcRenderer object directly to renderer
        expect(content).not.toMatch(/ipcRenderer\s*[,\n]/);
    });

    test('listener APIs return targeted unsubscribe functions', () => {
        const fs = require('fs');
        const path = require('path');
        const content = fs.readFileSync(path.join(__dirname, 'preload.js'), 'utf8');
        expect(content).not.toContain('removeAllListeners');
        expect(content).toContain('removeListener(channel, listener)');
        expect(content).toContain('return () => ipcRenderer.removeListener(channel, listener)');
    });

    test('BrowserWindow uses Electron sandbox and denies permission prompts by default', () => {
        const fs = require('fs');
        const path = require('path');
        const content = fs.readFileSync(path.join(__dirname, 'main.js'), 'utf8');

        expect(content).toContain('sandbox: true');
        expect(content).toContain('setPermissionRequestHandler');
        expect(content).toContain('callback(false)');
    });

    test('all preload invoke/send channels have matching main process handlers', () => {
        const fs = require('fs');
        const path = require('path');
        const preload = fs.readFileSync(path.join(__dirname, 'preload.js'), 'utf8');
        const main = fs.readFileSync(path.join(__dirname, 'main.js'), 'utf8');

        const invoked = [...preload.matchAll(/ipcRenderer\.invoke\('([^']+)'/g)].map(m => m[1]);
        const sent = [...preload.matchAll(/ipcRenderer\.send\('([^']+)'/g)].map(m => m[1]);
        const handled = new Set([...main.matchAll(/ipcMain\.handle\('([^']+)'/g)].map(m => m[1]));
        const listened = new Set([...main.matchAll(/ipcMain\.on\('([^']+)'/g)].map(m => m[1]));

        expect(invoked.filter(channel => !handled.has(channel))).toEqual([]);
        expect(sent.filter(channel => !listened.has(channel))).toEqual([]);
    });

    test('all preload listener channels are sent by main process', () => {
        const fs = require('fs');
        const path = require('path');
        const preload = fs.readFileSync(path.join(__dirname, 'preload.js'), 'utf8');
        const main = fs.readFileSync(path.join(__dirname, 'main.js'), 'utf8');

        const rendererListeners = [...preload.matchAll(/ipcRenderer\.on\('([^']+)'/g)].map(m => m[1]);
        const mainSends = new Set([...main.matchAll(/webContents\.send\('([^']+)'/g)].map(m => m[1]));
        const missing = rendererListeners.filter(channel => !mainSends.has(channel));

        expect(missing).toEqual([]);
    });
});

// ============================================================
// SAFE_INPUT regex edge cases
// ============================================================

describe('SAFE_INPUT regex', () => {
    test('matches typical Azure subscription names', () => {
        expect(SAFE_INPUT.test('Pay-As-You-Go')).toBe(true);
        expect(SAFE_INPUT.test('Visual Studio Enterprise (MPN)')).toBe(true);
        expect(SAFE_INPUT.test('my-company-prod-001')).toBe(true);
    });

    test('matches typical resource group names', () => {
        expect(SAFE_INPUT.test('rg-prod-eastus-001')).toBe(true);
        expect(SAFE_INPUT.test('NetworkWatcherRG')).toBe(true);
        expect(SAFE_INPUT.test('MC_myRG_myAKS_eastus')).toBe(true);
    });

    test('rejects shell metacharacters', () => {
        const dangerous = [';', '`', '|', '$', '&', '<', '>', '{', '}', '[', ']', '!', '#', '~', '"', "'", '\\'];
        for (const char of dangerous) {
            expect(SAFE_INPUT.test(`safe${char}unsafe`)).toBe(false);
        }
    });
});
