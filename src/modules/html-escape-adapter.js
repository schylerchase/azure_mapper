// HTML escape adapter owns markup escaping and the legacy _escHtml shim.
function createHtmlEscapeAdapter(){
  function escape(value){
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  return { escape: escape };
}

var AppHtml = createHtmlEscapeAdapter();

function _escHtml(value){
  return AppHtml.escape(value);
}

if (typeof window !== 'undefined') {
  window.AppHtml = AppHtml;
  window._escHtml = _escHtml;
  if (window.AppModules) window.AppModules.AppHtml = AppHtml;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = createHtmlEscapeAdapter;
}
