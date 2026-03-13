// Preferences persistence module
// OPTIMIZED: Fixed double localStorage read in savePrefs()

const PREFS_KEY = 'azureNetMapPrefs';

// Load preferences from localStorage
function loadPrefs() {
  try {
    const r = localStorage.getItem(PREFS_KEY);
    return r ? JSON.parse(r) : {};
  } catch (e) {
    return {};
  }
}

// Global preferences object - prototype-free to prevent pollution (Object.create(null))
const _prefs = Object.assign(Object.create(null), loadPrefs());

// Save preferences - OPTIMIZED: no longer re-reads localStorage
// Old: called loadPrefs() every time (getItem + JSON.parse)
// New: merges into in-memory _prefs, writes once
function savePrefs(p) {
  for (const k of Object.keys(p)) {
    if (!Object.hasOwn(p, k)) continue;
    _prefs[k] = p[k];
  }
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(_prefs));
  } catch (e) {
    // Silent fail OK - localStorage might be disabled
  }
}

export { _prefs, loadPrefs, savePrefs };
