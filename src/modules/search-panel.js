// SearchPanel owns the resource search overlay, cached search index, and result rows.
// Search result navigation is delegated to ResourceNavigation.
var SearchPanel = (function() {
  var searchIndex = null;
  var searchIndexCtx = null;

  function renderContext() {
    return AppRenderContext.createRenderContext();
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function buildIndex(ctx) {
    return SearchIndex.buildSearchIndex(ctx);
  }

  function invalidate() {
    searchIndex = null;
    searchIndexCtx = null;
  }

  function currentIndex(ctx) {
    if (searchIndexCtx !== ctx) {
      searchIndex = buildIndex(ctx);
      searchIndexCtx = ctx;
    }
    return searchIndex;
  }

  function searchNotes(query, matches) {
    if (typeof _getAllNotes !== 'function') return;
    _getAllNotes().forEach(function(note) {
      if (matches.length >= 30) return;
      var text = (note.text || '').toLowerCase();
      var resourceNameText = typeof _getResourceName === 'function' ? (_getResourceName(note.resourceId) || '').toLowerCase() : '';
      if (text.includes(query) || resourceNameText.includes(query)) {
        matches.push({
          type: 'Note',
          name: (note.text || '').slice(0, 50),
          id: note.resourceId,
          extra: note.category || '',
          acct: ''
        });
      }
    });
  }

  function findMatches(query, ctx) {
    var matches = [];
    var index = currentIndex(ctx);
    matches = SearchIndex.findSearchMatches(index, query, 30);
    searchNotes(query, matches);
    return matches;
  }

  function open() {
    var overlay = byId('searchOverlay');
    var input = byId('searchInput');
    var results = byId('searchResults');
    if (!overlay || !input || !results) return;
    overlay.style.display = 'block';
    input.value = '';
    input.focus();
    results.textContent = '';
  }

  function close() {
    var overlay = byId('searchOverlay');
    if (overlay) overlay.style.display = 'none';
  }

  function renderResultRow(result, isMultiAccount) {
    var row = document.createElement('div');
    row.style.cssText = 'padding:8px 12px;cursor:pointer;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px';
    row.addEventListener('click', function(event) {
      event.stopPropagation();
      close();
      ResourceNavigation.openSearchResult(result);
    });

    var type = document.createElement('span');
    type.style.cssText = 'font-size:9px;color:var(--accent-cyan);font-weight:600;width:50px';
    type.textContent = result.type;
    row.appendChild(type);

    var name = document.createElement('span');
    name.style.cssText = 'flex:1;font-size:12px;color:var(--text-primary)';
    name.textContent = result.name;
    row.appendChild(name);

    if (isMultiAccount && result.acct && result.acct !== 'default') {
      var badge = document.createElement('span');
      badge.style.cssText = 'font-size:8px;padding:1px 5px;border-radius:3px;background:' + (getAccountColor(result.acct) || 'var(--bg-tertiary)') + ';color:#000;font-weight:600;white-space:nowrap';
      badge.textContent = result.acct;
      row.appendChild(badge);
    }

    var extra = document.createElement('span');
    extra.style.cssText = 'font-size:10px;color:var(--text-muted)';
    extra.textContent = result.extra;
    row.appendChild(extra);
    return row;
  }

  function renderNoResults() {
    var node = document.createElement('div');
    node.style.cssText = 'padding:20px;text-align:center;color:var(--text-muted);font-size:12px';
    node.textContent = 'No results';
    return node;
  }

  function updateResults(query, ctx, target) {
    var fragment = document.createDocumentFragment();
    var matches = findMatches(query, ctx);
    var isMultiAccount = !!ctx._multiTenant;
    matches.forEach(function(match) {
      fragment.appendChild(renderResultRow(match, isMultiAccount));
    });
    if (!matches.length) fragment.appendChild(renderNoResults());
    target.textContent = '';
    target.appendChild(fragment);
  }

  function handleInput() {
    var query = this.value.toLowerCase().trim();
    var results = byId('searchResults');
    var ctx = renderContext().rlCtx;
    if (!results) return;
    if (!query || !ctx) {
      results.textContent = '';
      return;
    }
    updateResults(query, ctx, results);
  }

  function init() {
    var openButton = byId('searchBtn');
    var backdrop = byId('searchBackdrop');
    var input = byId('searchInput');
    if (openButton) openButton.addEventListener('click', open);
    if (backdrop) backdrop.addEventListener('click', close);
    if (input) input.addEventListener('input', handleInput);
  }

  init();

  return {
    open: open,
    close: close,
    invalidate: invalidate,
    buildIndex: buildIndex
  };
})();
