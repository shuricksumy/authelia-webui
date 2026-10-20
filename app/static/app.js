/* No inline scripts (strict CSP): everything the UI needs beyond HTMX lives here. */
(function () {
  "use strict";

  function meta(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el ? el.getAttribute("content") : "";
  }

  function currentRev() {
    var section = document.getElementById("rules-section");
    return section && section.dataset.rev ? section.dataset.rev : meta("rev");
  }

  // CSRF token and draft revision on every state-changing request.
  document.addEventListener("htmx:configRequest", function (event) {
    event.detail.headers["X-CSRF-Token"] = meta("csrf-token");
    if (event.detail.verb !== "get" && event.detail.parameters.rev === undefined) {
      event.detail.parameters.rev = currentRev();
    }
  });

  // 409 (draft changed elsewhere) and 422 (refused / invalid) carry a message worth showing.
  document.addEventListener("htmx:beforeSwap", function (event) {
    var status = event.detail.xhr.status;
    if (status === 409 || status === 422 || status === 404) {
      event.detail.shouldSwap = true;
      event.detail.isError = false;
    }
  });
  document.addEventListener("htmx:responseError", function (event) {
    var flash = document.getElementById("flash");
    if (!flash) { return; }
    flash.className = "flash error";
    flash.textContent = event.detail.xhr.status === 403
      ? "Forbidden. Your session may have expired: reload the page."
      : "The request failed (" + event.detail.xhr.status + "). Reload the page and try again.";
  });

  // A checkbox that unlocks a button (e.g. "I accept these changes" -> Apply).
  document.addEventListener("change", function (event) {
    var box = event.target;
    if (!box.matches || !box.matches("input[data-enables]")) { return; }
    var target = document.getElementById(box.getAttribute("data-enables"));
    if (target) { target.disabled = !box.checked; }
  });

  // The Clipboard API exists only on HTTPS / localhost, and an iframe needs permission for it
  // (the emergency door over plain HTTP, a dashboard embed). Fall back to execCommand("copy"); if
  // that fails too, select the text so Ctrl/Cmd+C works, and say so on the button.
  function copyText(text, input, button) {
    var label = button.dataset.label || button.textContent;
    button.dataset.label = label;
    function done(message) {
      clearTimeout(button._reset);
      if (button.classList.contains("act")) {  // an icon button: a small tip instead of new text
        button.dataset.tip = message;
        button._reset = setTimeout(function () { delete button.dataset.tip; }, 2500);
        return;
      }
      button.textContent = message;
      button._reset = setTimeout(function () { button.textContent = label; }, 2500);
    }
    function legacy() {
      var field = input;
      var temporary = null;
      if (!field) {  // inside a modal dialog only its own children can take focus
        temporary = document.createElement("textarea");
        temporary.value = text;
        temporary.setAttribute("readonly", "");
        temporary.className = "visually-hidden";
        (button.closest("dialog") || document.body).appendChild(temporary);
        field = temporary;
      }
      var hidden = field.type === "password";
      if (hidden) { field.type = "text"; }  // a masked field cannot be selected for copying
      field.focus();
      field.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      if (hidden) { field.type = "password"; }
      if (temporary) { temporary.remove(); }
      if (ok) { done("Copied"); }
      else {
        if (input) { input.type = "text"; input.focus(); input.select(); }
        done("Press Ctrl/Cmd+C");
      }
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done("Copied"); }, legacy);
    } else {
      legacy();
    }
  }

  // Copy buttons: data-copy="text" or data-copy-from="input id". Reveal: data-reveal="input id".
  document.addEventListener("click", function (event) {
    var copy = event.target.closest("[data-copy], [data-copy-from]");
    if (copy) {
      var source = copy.getAttribute("data-copy-from");
      var text = source ? document.getElementById(source).value : copy.getAttribute("data-copy");
      copyText(text, source ? document.getElementById(source) : null, copy);
      return;
    }
    var reveal = event.target.closest("[data-reveal]");
    if (reveal) {
      var input = document.getElementById(reveal.getAttribute("data-reveal"));
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      reveal.textContent = hidden ? "Hide" : "Show";
    }
  });

  // Close dialogs.
  document.addEventListener("click", function (event) {
    var closer = event.target.closest("[data-close]");
    if (!closer) { return; }
    var modal = document.getElementById("modal");
    if (modal) { modal.innerHTML = ""; }  // a one-time secret leaves the page with its dialog
    var next = closer.getAttribute("data-done-href");
    if (next) { window.location.assign(next); }
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      var modal = document.getElementById("modal");
      // A one-time secret closes only through its "Done" (after "I have copied it").
      if (modal && modal.firstChild && !modal.querySelector(".secret-dialog")) { modal.innerHTML = ""; }
    }
  });

  // Dismissible result banners (per job id, remembered in this browser only).
  function dismissed() {
    try { return JSON.parse(localStorage.getItem("dismissed-jobs") || "[]"); } catch (e) { return []; }
  }
  function applyDismissals() {
    var list = dismissed();
    document.querySelectorAll("[data-dismissable]").forEach(function (el) {
      if (list.indexOf(el.dataset.jobId) !== -1) { el.hidden = true; }
    });
  }
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-dismiss]");
    if (!button) { return; }
    var banner = button.closest("[data-dismissable]");
    var list = dismissed();
    list.push(banner.dataset.jobId);
    try { localStorage.setItem("dismissed-jobs", JSON.stringify(list.slice(-20))); } catch (e) { /* private mode */ }
    banner.hidden = true;
    recountNotes();
  });
  document.addEventListener("DOMContentLoaded", function () { applyDismissals(); recountNotes(); });

  // Notifications (the bell in the top bar): the server counts them; dismissing or marking one
  // as seen updates the count, its colour (worst first) and the button's name here.
  function recountNotes() {
    var list = document.querySelector("[data-notes]");
    var badge = document.querySelector("[data-bell-count]");
    if (!list || !badge) { return; }
    var items = Array.prototype.filter.call(list.querySelectorAll("[data-note]"), function (el) { return !el.hidden; });
    var levels = items.map(function (el) { return el.getAttribute("data-note"); });
    var worst = levels.indexOf("error") !== -1 ? "error" : (levels.indexOf("warn") !== -1 ? "warn" : "info");
    badge.textContent = String(items.length);
    badge.hidden = items.length === 0;
    badge.className = "bell-count " + worst;
    var summary = badge.closest("summary");
    if (summary) { summary.setAttribute("aria-label", "Notifications (" + items.length + ")"); }
  }
  document.addEventListener("htmx:afterSettle", recountNotes);

  // Applying restarts Authelia, which signs everyone out (memory sessions): the progress poll then
  // fails or is redirected to the portal. Wait until Authelia answers again (a redirect to the
  // login means it is up), then continue on the result page, which survives the login.
  var pollFailures = 0;
  var restartMode = false;
  function inProgressPanel(event) {
    return event.target && event.target.closest && event.target.closest("#apply-progress");
  }
  document.addEventListener("htmx:afterRequest", function (event) {
    if (inProgressPanel(event) && event.detail.successful) { pollFailures = 0; }
  });
  document.addEventListener("htmx:sendError", function (event) {
    if (!inProgressPanel(event)) { return; }
    pollFailures += 1;
    if (pollFailures >= 3 && !restartMode) { enterRestartMode(); }
  });
  function enterRestartMode() {
    restartMode = true;
    var note = document.getElementById("restart-note");
    if (note) { note.hidden = false; }
    var tries = 0;
    var timer = setInterval(function () {
      tries += 1;
      fetch("/apply/result", { redirect: "manual", credentials: "same-origin", cache: "no-store" })
        .then(function (response) {
          // "opaqueredirect": Authelia is back and wants a login; ok: the session survived.
          if (response.type === "opaqueredirect" || response.ok) {
            clearInterval(timer);
            window.location.href = "/apply/result";
          }
        })
        .catch(function () { /* still restarting */ });
      if (tries > 120) { clearInterval(timer); window.location.href = "/apply/result"; }
    }, 1500);
  }

  // Drag and drop ordering (buttons are the keyboard/touch alternative).
  function initSortable() {
    var body = document.getElementById("rules-body");
    if (!body || body.dataset.sortable !== "1" || typeof Sortable === "undefined") { return; }
    if (body._sortable) { body._sortable.destroy(); }
    body._sortable = Sortable.create(body, {
      handle: ".drag-handle",
      animation: 120,
      ghostClass: "sortable-ghost",
      onEnd: function (evt) {
        if (evt.oldIndex === evt.newIndex) { return; }
        htmx.ajax("POST", "/rules/move", {
          target: "#rules-section",
          swap: "outerHTML",
          values: { src: evt.oldIndex, dst: evt.newIndex }
        });
      }
    });
  }
  document.addEventListener("DOMContentLoaded", initSortable);
  document.addEventListener("htmx:afterSettle", initSortable);

  // Resizable columns on every table.data[data-colkey]: drag the edge of a header cell, double-click
  // it to go back to the default. Widths are a per-browser convenience (localStorage), shared by
  // tables with the same key (all rules tables); the card layout on narrow screens ignores them.
  // The column without a width class stays flexible and absorbs the difference.
  var MIN_COL_PX = 40;
  function widthKey(table) {
    return "cols:" + table.dataset.colkey + ":" + table.querySelectorAll("colgroup col").length;
  }
  function savedWidths(table) {
    try { return JSON.parse(localStorage.getItem(widthKey(table)) || "null") || []; } catch (e) { return []; }
  }
  function applyWidths(table) {
    var widths = savedWidths(table);
    table.querySelectorAll("colgroup col").forEach(function (col, i) {
      col.style.width = widths[i] ? widths[i] + "px" : "";  // CSSOM: allowed by the CSP
    });
  }
  function initResize() {
    document.querySelectorAll("table.data[data-colkey]").forEach(function (table) {
      applyWidths(table);
      if (table.dataset.resizable) { return; }
      table.dataset.resizable = "1";
      var cells = table.querySelectorAll("thead tr:first-child th");
      cells.forEach(function (th, i) {
        if (i === cells.length - 1) { return; }
        var grip = document.createElement("span");
        grip.className = "col-grip";
        grip.title = "Drag to resize, double-click to reset";
        grip.dataset.col = String(i);
        th.appendChild(grip);
      });
    });
  }
  function isFlexible(col) { return !/\bw-/.test(col.className); }
  document.addEventListener("pointerdown", function (event) {
    var grip = event.target.closest && event.target.closest(".col-grip");
    if (!grip || event.button !== 0) { return; }
    event.preventDefault();
    var table = grip.closest("table");
    var cols = table.querySelectorAll("colgroup col");
    var cells = table.querySelectorAll("thead tr:first-child th");
    var edge = Number(grip.dataset.col);
    // The edge between i and i+1 sizes column i; when i is the flexible one, it sizes i+1 instead.
    var target = isFlexible(cols[edge]) && cols[edge + 1] ? edge + 1 : edge;
    var sign = target === edge ? 1 : -1;
    var start = event.clientX;
    var startWidth = cells[target].getBoundingClientRect().width;
    grip.setPointerCapture(event.pointerId);
    grip.classList.add("active");
    document.body.classList.add("col-resizing");
    function move(e) {
      var width = Math.max(MIN_COL_PX, Math.round(startWidth + sign * (e.clientX - start)));
      cols[target].style.width = width + "px";
    }
    function end() {
      grip.removeEventListener("pointermove", move);
      grip.removeEventListener("pointerup", end);
      grip.removeEventListener("pointercancel", end);
      grip.classList.remove("active");
      document.body.classList.remove("col-resizing");
      var widths = Array.prototype.map.call(cols, function (col) {
        return col.style.width ? parseInt(col.style.width, 10) : null;
      });
      try { localStorage.setItem(widthKey(table), JSON.stringify(widths)); } catch (e) { /* private mode */ }
      document.querySelectorAll('table.data[data-colkey="' + table.dataset.colkey + '"]').forEach(applyWidths);
    }
    grip.addEventListener("pointermove", move);
    grip.addEventListener("pointerup", end);
    grip.addEventListener("pointercancel", end);
  });
  document.addEventListener("dblclick", function (event) {
    var grip = event.target.closest && event.target.closest(".col-grip");
    if (!grip) { return; }
    var table = grip.closest("table");
    try { localStorage.removeItem(widthKey(table)); } catch (e) { /* private mode */ }
    document.querySelectorAll('table.data[data-colkey="' + table.dataset.colkey + '"]').forEach(applyWidths);
  });
  document.addEventListener("DOMContentLoaded", initResize);
  document.addEventListener("htmx:afterSettle", initResize);

  // View menu: theme, table style and density. theme.js (window.appView) holds the defaults and
  // applies the stored values before the first paint; here they are changed, saved and shown.
  // Other open tabs of the same site follow through the storage event.
  function showView(view) {
    window.appView.apply(view);
    var collapse = document.querySelector("[data-nav-collapse]");
    if (collapse) {
      var label = view.nav === "collapsed" ? "Expand the menu" : "Collapse the menu";
      collapse.setAttribute("aria-label", label);
      collapse.title = label;
    }
    var panel = document.querySelector("[data-view-panel]");
    if (!panel) { return; }
    panel.querySelectorAll('input[type="radio"]').forEach(function (input) {
      input.checked = view[input.name.replace(/^view-/, "")] === input.value;
    });
    window.appView.flags.forEach(function (key) {
      var box = panel.querySelector('input[name="view-' + key + '"]');
      if (box) { box.checked = view[key] === true; }
    });
  }
  document.addEventListener("change", function (event) {
    var input = event.target;
    if (!input.closest || !input.closest("[data-view-panel]") || !window.appView) { return; }
    var view = window.appView.read();
    view[input.name.replace(/^view-/, "")] = input.type === "checkbox" ? input.checked : input.value;
    window.appView.save(view);
    showView(view);
  });
  document.addEventListener("click", function (event) {
    if (event.target.closest && event.target.closest("[data-reset-widths]")) {
      try {
        Object.keys(localStorage).forEach(function (k) { if (k.indexOf("cols:") === 0) { localStorage.removeItem(k); } });
      } catch (e) { /* private mode */ }
      document.querySelectorAll("table.data[data-colkey]").forEach(applyWidths);
      return;
    }
    // a click outside an open menu (View, notifications) closes it
    document.querySelectorAll("[data-view-menu][open], [data-bell-menu][open]").forEach(function (menu) {
      if (!menu.contains(event.target)) { menu.removeAttribute("open"); }
    });
  });
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") { return; }
    document.querySelectorAll("[data-view-menu][open], [data-bell-menu][open]").forEach(function (menu) {
      menu.removeAttribute("open");
    });
  });
  window.addEventListener("storage", function (event) {
    if (event.key === "view" && window.appView) { showView(window.appView.read()); }
  });

  // Sidebar: on a wide screen "Collapse" keeps only the icons (saved with the View settings); on a
  // narrow one the menu button opens it as a drawer over the page (backdrop or Esc closes it).
  function setDrawer(open) {
    var toggle = document.querySelector("[data-nav-toggle]");
    var backdrop = document.querySelector("[data-nav-close]");
    document.documentElement.toggleAttribute("data-nav-open", open);
    if (toggle) { toggle.setAttribute("aria-expanded", open ? "true" : "false"); }
    if (backdrop) { backdrop.hidden = !open; }
  }
  document.addEventListener("click", function (event) {
    if (!event.target.closest) { return; }
    if (event.target.closest("[data-nav-toggle]")) {
      setDrawer(!document.documentElement.hasAttribute("data-nav-open"));
    } else if (event.target.closest("[data-nav-close]")) {
      setDrawer(false);
    } else if (event.target.closest("[data-nav-collapse]") && window.appView) {
      var view = window.appView.read();
      view.nav = view.nav === "collapsed" ? "expanded" : "collapsed";
      window.appView.save(view);
      showView(view);
    }
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && document.documentElement.hasAttribute("data-nav-open")) { setDrawer(false); }
  });

  // Esc closes the editor drawer (its close link), unless a dialog or a menu is open on top of it
  // or the key was meant for a form field (typed text is never thrown away by Esc). Capture phase:
  // it must see the dialog before the dialog's own Esc handler removes it.
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape" || event.defaultPrevented) { return; }
    var modal = document.getElementById("modal");
    if ((modal && modal.firstChild) || document.querySelector("[data-view-menu][open], [data-bell-menu][open]")) { return; }
    if (document.documentElement.hasAttribute("data-nav-open")) { return; }
    if (event.target.closest && event.target.closest("input, textarea, select, [contenteditable]")) { return; }
    var close = document.querySelector("#panel [data-panel-close]");
    if (close) { close.click(); }
  }, true);
  document.addEventListener("DOMContentLoaded", function () {
    if (window.appView) { showView(window.appView.read()); }
  });
})();
