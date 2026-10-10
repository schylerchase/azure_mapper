// Notification adapter owns app-wide toast delivery and the legacy _showToast shim.
var AppNotifications = (function(global){
  function show(message, typeOrDuration){
    if (typeof global.showToast !== 'function') {
      console.log(message);
      return;
    }

    var duration = typeof typeOrDuration === 'number' ? typeOrDuration : 3000;
    global.showToast(message, duration);
  }

  return { show };
})(typeof window !== 'undefined' ? window : globalThis);

function _showToast(message, typeOrDuration){
  return AppNotifications.show(message, typeOrDuration);
}

if (typeof window !== 'undefined') {
  window.AppNotifications = AppNotifications;
  if (window.AppModules) window.AppModules.AppNotifications = AppNotifications;
}
