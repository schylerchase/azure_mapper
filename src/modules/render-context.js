// Runtime render context bridge.
//
// The plain-script app-core regions still share state through legacy globals.
// This helper gives future extracted modules one explicit read/write surface
// while the remaining regions are migrated away from direct global access.

let _rlCtx = null;
var _sgById = new Map();
let _mapSvg = null, _mapZoom = null, _mapG = null;
var _complianceFindings = (typeof globalThis !== 'undefined' && globalThis._complianceFindings) || [];

(function initRenderContext(global) {
  if (!global) return;

  function createRenderContext(overrides) {
    const ctx = {
      get rlCtx() { return typeof _rlCtx !== 'undefined' ? _rlCtx : global._rlCtx || null; },
      set rlCtx(value) { if (typeof _rlCtx !== 'undefined') _rlCtx = value; global._rlCtx = value; },
      get mapSvg() { return typeof _mapSvg !== 'undefined' ? _mapSvg : global._mapSvg || null; },
      set mapSvg(value) { if (typeof _mapSvg !== 'undefined') _mapSvg = value; global._mapSvg = value; },
      get mapZoom() { return typeof _mapZoom !== 'undefined' ? _mapZoom : global._mapZoom || null; },
      set mapZoom(value) { if (typeof _mapZoom !== 'undefined') _mapZoom = value; global._mapZoom = value; },
      get mapG() { return typeof _mapG !== 'undefined' ? _mapG : global._mapG || null; },
      set mapG(value) { if (typeof _mapG !== 'undefined') _mapG = value; global._mapG = value; },
      get securityGroupsById() { return typeof _sgById !== 'undefined' ? _sgById : global._sgById || new Map(); },
      set securityGroupsById(value) { if (typeof _sgById !== 'undefined') _sgById = value; global._sgById = value; },
      get complianceFindings() { return typeof _complianceFindings !== 'undefined' ? _complianceFindings : global._complianceFindings || []; },
      set complianceFindings(value) {
        var findings = value || [];
        if (typeof _complianceFindings !== 'undefined') _complianceFindings = findings;
        global._complianceFindings = findings;
      },
      showToast: function(message, type) {
        if (typeof global._showToast === 'function') global._showToast(message, type);
      },
      downloadBlob: function(blob, name) {
        if (typeof global.downloadBlob === 'function') return global.downloadBlob(blob, name);
        throw new Error('downloadBlob is not available');
      }
    };
    return Object.assign(ctx, overrides || {});
  }

  global.AppRenderContext = { createRenderContext };
  if (global.AppModules) global.AppModules.RenderContext = global.AppRenderContext;
})(typeof window !== 'undefined' ? window : globalThis);
