// Browser storage adapter owns local/session storage access for app-core regions.
function createBrowserStorageAdapter(global){
  function storageFor(kind){
    try {
      var storage = kind === 'session' ? global.sessionStorage : global.localStorage;
      if (storage && typeof storage.getItem === 'function') return storage;
    } catch (e) {}
    return null;
  }

  function get(key, kind){
    var storage = storageFor(kind);
    if (!storage) return null;
    try { return storage.getItem(key); } catch (e) { return null; }
  }

  function set(key, value, kind){
    var storage = storageFor(kind);
    if (!storage) return false;
    try {
      storage.setItem(key, value);
      return true;
    } catch (e) {
      return false;
    }
  }

  function remove(key, kind){
    var storage = storageFor(kind);
    if (!storage) return false;
    try {
      storage.removeItem(key);
      return true;
    } catch (e) {
      return false;
    }
  }

  return { get: get, set: set, remove: remove };
}

var AppBrowserStorage = createBrowserStorageAdapter(typeof window !== 'undefined' ? window : globalThis);

if (typeof window !== 'undefined') {
  window.AppBrowserStorage = AppBrowserStorage;
  if (window.AppModules) window.AppModules.AppBrowserStorage = AppBrowserStorage;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = createBrowserStorageAdapter;
}
