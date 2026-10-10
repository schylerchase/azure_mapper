// MapViewportCompatibility owns the stable browser publish point for MapViewport.
// The explicit assignment protects the public name when app-core is minified.

(function(global){
  if(!global || typeof MapViewport === 'undefined') return;
  global.MapViewport = MapViewport;
  if(global.AppModules) global.AppModules.MapViewport = MapViewport;
})(typeof window !== 'undefined' ? window : globalThis);
