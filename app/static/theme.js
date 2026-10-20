/* View settings (theme, table style, density, collapsed sidebar), applied before the first paint: loaded without
   defer in <head>, no inline script under the CSP. Only differences from DEFAULTS are stored, per
   browser and per site address (localStorage "view"). The settings menu is in app.js, which uses
   window.appView from here. */
(function () {
  "use strict";
  var DEFAULTS = { theme: "system", head: true, rows: true, hover: true, lines: true, density: "compact", nav: "expanded" };
  var FLAGS = ["head", "rows", "hover", "lines"];

  function read() {
    var stored = {};
    try { stored = JSON.parse(localStorage.getItem("view") || "{}") || {}; } catch (e) { /* defaults */ }
    var view = {};
    Object.keys(DEFAULTS).forEach(function (key) {
      view[key] = Object.prototype.hasOwnProperty.call(stored, key) ? stored[key] : DEFAULTS[key];
    });
    return view;
  }

  function save(view) {
    var diff = {};
    Object.keys(DEFAULTS).forEach(function (key) {
      if (view[key] !== DEFAULTS[key]) { diff[key] = view[key]; }
    });
    try { localStorage.setItem("view", JSON.stringify(diff)); } catch (e) { /* private mode: this page only */ }
  }

  function apply(view) {
    var root = document.documentElement;
    if (view.theme === "light" || view.theme === "dark") { root.setAttribute("data-theme", view.theme); }
    else { root.removeAttribute("data-theme"); }
    FLAGS.forEach(function (key) {
      if (view[key] === true) { root.setAttribute("data-tbl-" + key, "on"); }
      else { root.removeAttribute("data-tbl-" + key); }
    });
    if (view.density === "comfortable") { root.setAttribute("data-density", "comfortable"); }
    else { root.removeAttribute("data-density"); }
    if (view.nav === "collapsed") { root.setAttribute("data-nav", "collapsed"); }
    else { root.removeAttribute("data-nav"); }
  }

  window.appView = { flags: FLAGS, read: read, save: save, apply: apply };
  apply(read());
})();
