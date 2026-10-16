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

  // Close dialogs.
  document.addEventListener("click", function (event) {
    var closer = event.target.closest("[data-close]");
    if (!closer) { return; }
    var modal = document.getElementById("modal");
    if (modal) { modal.innerHTML = ""; }
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      var modal = document.getElementById("modal");
      if (modal && modal.firstChild) { modal.innerHTML = ""; }
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
  });
  document.addEventListener("DOMContentLoaded", applyDismissals);

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
})();
