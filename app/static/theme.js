/* View settings (theme, table style, density), applied before the first paint: loaded without
   defer in <head>, no inline script under the CSP. Stored per browser and per site address
   (localStorage "view"); nothing stored means the defaults: system theme, plain compact tables.
   The settings menu itself is in app.js. */
(function () {
  "use strict";
  var view = {};
  try { view = JSON.parse(localStorage.getItem("view") || "{}") || {}; } catch (e) { /* defaults */ }
  var root = document.documentElement;
  if (view.theme === "light" || view.theme === "dark") { root.setAttribute("data-theme", view.theme); }
  ["head", "rows", "hover", "lines"].forEach(function (key) {
    if (view[key] === true) { root.setAttribute("data-tbl-" + key, "on"); }
  });
  if (view.density === "comfortable") { root.setAttribute("data-density", "comfortable"); }
})();
