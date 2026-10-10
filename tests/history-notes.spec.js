const { test, expect } = require('@playwright/test');

const vnet = '/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/current';
const project = { _format: 'azuremap', _version: '1.0', annotations: {}, textareas: { in_vnets: [{ id: vnet, name: 'current', location: 'eastus', addressSpace: { addressPrefixes: ['10.0.0.0/16'] } }] } };

test.beforeEach(async ({ page }) => {
  await page.goto('http://localhost:8377/');
  await page.locator('#loadProjectInput').setInputFiles({ name: 'current.azuremap', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(project)) });
  await expect(page.locator('.vpc-group')).toHaveCount(1);
  await expect(page.locator('#loadingOverlay')).toBeHidden();
  await page.locator('#timelineBtn').click();
  await expect(page.locator('.timeline-dot')).toHaveCount(1);
});

async function addNote(page, text) {
  await page.locator('#notesBtn').click();
  await page.locator('#notesAddBtn').click();
  await page.locator('#noteNewResource').selectOption(vnet);
  await page.locator('#noteNewText').fill(text);
  await page.locator('#noteAddSave').click();
  await expect(page.locator('#notesPanelBody')).toContainText(text);
}

async function notes(page) {
  return page.evaluate(() => ({ current: _getAllNotes().map(n => n.text), persisted: Object.values(JSON.parse(localStorage.getItem(_NOTES_KEY) || '{}')).flat().map(n => n.text) }));
}

test('viewing history preserves current notes through Return and reload', async ({ page }) => {
  await addNote(page, 'Keep current note');
  await page.locator('.timeline-dot').first().click();
  await expect(page.locator('#historyBanner')).toBeVisible();
  await expect(page.locator('#notesAddBtn')).toBeDisabled();
  await expect(page.locator('#notesPanelBody')).toContainText('Historical notes are read-only');
  await page.evaluate(rid => { addAnnotation(rid, 'Historical edit', 'info', false); updateAnnotation(rid, 0, 'Changed'); deleteAnnotation(rid, 0); }, vnet);
  expect(await notes(page)).toEqual({ current: [], persisted: ['Keep current note'] });
  await page.locator('#historyReturn').click();
  await expect(page.locator('#notesAddBtn')).toBeEnabled();
  await expect(page.locator('#notesPanelBody')).toContainText('Keep current note');
  expect(await notes(page)).toEqual({ current: ['Keep current note'], persisted: ['Keep current note'] });
  await page.reload();
  await page.locator('#restoreYes').click();
  await expect(page.locator('.vpc-group')).toHaveCount(1);
  await page.locator('#notesBtn').click();
  await expect(page.locator('#notesPanelBody')).toContainText('Keep current note');
  expect(await notes(page)).toEqual({ current: ['Keep current note'], persisted: ['Keep current note'] });
});

test('restoring a snapshot deliberately commits its notes and permits current editing', async ({ page }) => {
  await addNote(page, 'Later note');
  await page.locator('.timeline-dot').first().click();
  await page.locator('#historyRestore').click();
  await expect(page.locator('#historyBanner')).toBeHidden();
  expect(await notes(page)).toEqual({ current: [], persisted: [] });
  await page.locator('#notesAddBtn').click();
  await page.locator('#noteNewResource').selectOption(vnet);
  await page.locator('#noteNewText').fill('Restored current note');
  await page.locator('#noteAddSave').click();
  await page.locator('.note-edit-btn').click();
  await page.locator('.note-card textarea').fill('Edited current note');
  await page.locator('.note-card .btn-save').click();
  expect(await notes(page)).toEqual({ current: ['Edited current note'], persisted: ['Edited current note'] });
  await page.locator('.note-del-btn').click();
  expect(await notes(page)).toEqual({ current: [], persisted: [] });
});

test('historical notes disable editing and Clear discards the suspended session', async ({ page }) => {
  await addNote(page, 'Historical note');
  await page.locator('#in_vnets').fill(JSON.stringify([{ ...project.textareas.in_vnets[0], name: 'renamed' }]));
  await page.evaluate(() => takeSnapshot('With note'));
  await expect(page.locator('.timeline-dot')).toHaveCount(2);
  await page.locator('#notesPanelClose').click();
  await page.locator('.timeline-dot').last().click();
  await page.locator('#notesBtn').click();
  await expect(page.locator('.note-edit-btn')).toBeDisabled();
  await expect(page.locator('.note-del-btn')).toBeDisabled();
  await page.locator('#clearBtn').click();
  await expect(page.locator('#historyBanner')).toBeHidden();
  await expect(page.locator('#in_vnets')).toBeEditable();
  await expect(page.locator('#in_vnets')).toHaveValue('');
  expect(await page.evaluate(() => ({ history: _viewingHistory, suspended: _currentSnapshot, count: _snapshots.length, context: AppRenderContext.createRenderContext().rlCtx }))).toEqual({ history: false, suspended: null, count: 0, context: null });
  await page.evaluate(() => _returnToCurrent());
  await expect(page.locator('#in_vnets')).toHaveValue('');
  expect(await page.evaluate(() => AppRenderContext.createRenderContext().rlCtx)).toBeNull();
});

test('loading the demo exits history and retains its built-in notes', async ({ page }) => {
  await page.locator('.timeline-dot').first().click();
  await page.locator('#loadDemo').click();
  await expect.poll(() => page.evaluate(() => AppRenderContext.createRenderContext().rlCtx?.vnets?.length || 0)).toBeGreaterThan(2);
  await expect(page.locator('#historyBanner')).toBeHidden();
  await expect(page.locator('#in_vnets')).toBeEditable();
  expect(await page.evaluate(() => ({ history: _viewingHistory, suspended: _currentSnapshot, notes: _getAllNotes().length }))).toEqual({ history: false, suspended: null, notes: 7 });
  await page.evaluate(() => _returnToCurrent());
  expect(await page.evaluate(() => AppRenderContext.createRenderContext().rlCtx.vnets.length)).toBeGreaterThan(2);
});
