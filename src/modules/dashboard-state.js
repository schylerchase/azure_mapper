// DashboardState owns live dashboard tab, account filter, and BUDR UI state.
var _udashTab = null;
var _udashAcctFilter = 'all';
var _budrDashState = { tierFilter: 'all', search: '', sort: 'tier' };
var _BUDR_TIER_META = {
  protected: { name: 'Protected', color: '#10b981', icon: '' },
  partial: { name: 'Partially Protected', color: '#f59e0b', icon: '' },
  at_risk: { name: 'At Risk', color: '#ef4444', icon: '' },
  unknown: { name: 'Not Assessed', color: '#64748b', icon: '?' }
};

function createDashboardState(options){
  var opts = options || {};
  var tab = opts.tab || null;
  var accountFilter = opts.accountFilter || 'all';
  var budrDashState = opts.budrDashState || { tierFilter: 'all', search: '', sort: 'tier' };

  function publish(){
    if(typeof opts.onChange === 'function'){
      opts.onChange({
        tab: tab,
        accountFilter: accountFilter,
        budrDashState: budrDashState
      });
    }
  }

  function getTab(){
    return tab;
  }

  function setTab(tabId){
    tab = tabId || null;
    publish();
    return tab;
  }

  function getAccountFilter(){
    return accountFilter;
  }

  function setAccountFilter(accountId){
    accountFilter = accountId || 'all';
    publish();
    return accountFilter;
  }

  function getBudrDashState(){
    return budrDashState;
  }

  function resetBudrDashState(){
    budrDashState = { tierFilter: 'all', search: '', sort: 'tier' };
    publish();
    return budrDashState;
  }

  function filterByAccount(items, resolveLabel){
    if(!Array.isArray(items)) return [];
    if(!accountFilter || accountFilter === 'all') return items;
    var id = accountFilter;
    var label = typeof resolveLabel === 'function' ? resolveLabel(id) : '';
    return items.filter(function(item){
      var account = item._subscriptionId || item._accountId || item.account || '';
      return account === id || account === label;
    });
  }

  return {
    getTab: getTab,
    setTab: setTab,
    getAccountFilter: getAccountFilter,
    setAccountFilter: setAccountFilter,
    getBudrDashState: getBudrDashState,
    resetBudrDashState: resetBudrDashState,
    filterByAccount: filterByAccount,
    tierMeta: _BUDR_TIER_META
  };
}

var DashboardState = createDashboardState({
  onChange: function(state){
    _udashTab = state.tab;
    _udashAcctFilter = state.accountFilter;
    _budrDashState = state.budrDashState;
  }
});

function _udashFilterByAccount(items){
  return DashboardState.filterByAccount(items, function(id){
    return typeof _rptAccountLabel === 'function' ? _rptAccountLabel(id) : '';
  });
}

function getUdashTab(){ return DashboardState.getTab(); }
function setUdashTab(tabId){ return DashboardState.setTab(tabId); }
function getUdashAcctFilter(){ return DashboardState.getAccountFilter(); }
function setUdashAcctFilter(accountId){ return DashboardState.setAccountFilter(accountId); }
function getBudrDashState(){ return DashboardState.getBudrDashState(); }
function resetBudrDashState(){ return DashboardState.resetBudrDashState(); }

if (typeof window !== 'undefined') {
  window.DashboardState = DashboardState;
  window.getUdashTab = getUdashTab;
  window.setUdashTab = setUdashTab;
  window.getUdashAcctFilter = getUdashAcctFilter;
  window.setUdashAcctFilter = setUdashAcctFilter;
  window.getBudrDashState = getBudrDashState;
  window.resetBudrDashState = resetBudrDashState;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = createDashboardState;
}
