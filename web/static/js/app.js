// Общее поведение UI: сайдбар, модалки, тосты, копирование. Без inline-кода (CSP).
(function () {
  'use strict';

  var KEY = 'tgproxy.sidebar.collapsed';
  var root = document.documentElement;

  // ---- сайдбар ----
  function syncSidebar() {
    var btn = document.getElementById('sb-toggle');
    if (!btn) { return; }
    var open = !root.classList.contains('sb-collapsed');
    var label = open ? btn.getAttribute('data-label-open') : btn.getAttribute('data-label-closed');
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    if (label) {
      btn.setAttribute('aria-label', label);
      btn.setAttribute('title', label);
    }
  }

  // Анимация ширины не должна «зависать» посередине (фоновая вкладка/панель не гонит кадры):
  // через TTL после переключения transition отключается и колонка встаёт в итоговую ширину.
  var settleTimer = 0;
  var SETTLE_MS = 260;

  function toggleSidebar() {
    var collapsed = !root.classList.contains('sb-collapsed');
    root.classList.remove('sb-settled');
    root.classList.toggle('sb-collapsed', collapsed);
    window.clearTimeout(settleTimer);
    settleTimer = window.setTimeout(function () { root.classList.add('sb-settled'); }, SETTLE_MS);
    try { window.localStorage.setItem(KEY, collapsed ? '1' : '0'); } catch (e) { /* ignore */ }
    syncSidebar();
  }

  // ---- модалки (<dialog>) ----
  function openModal(id) {
    var d = document.getElementById(id);
    if (d && typeof d.showModal === 'function' && !d.open) { d.showModal(); }
  }

  function closeModal(el) {
    var d = el.closest('dialog');
    if (d && d.open) { d.close(); }
  }

  // ---- тосты ----
  var TOAST_TTL = 6000;

  function dismissToast(t) {
    if (t && t.parentNode) { t.parentNode.removeChild(t); }
  }

  function armToast(t) {
    if (t.getAttribute('data-armed')) { return; }
    t.setAttribute('data-armed', '1');
    if (t.getAttribute('data-sticky') !== 'true') {
      window.setTimeout(function () { dismissToast(t); }, TOAST_TTL);
    }
  }

  function watchToasts() {
    var box = document.getElementById('toasts');
    if (!box || typeof MutationObserver === 'undefined') { return; }
    var scan = function () {
      var items = box.querySelectorAll('.toast');
      for (var i = 0; i < items.length; i++) { armToast(items[i]); }
    };
    new MutationObserver(scan).observe(box, { childList: true });
    scan();
  }

  // ---- копирование ----
  function copyFrom(btn) {
    var src = document.getElementById(btn.getAttribute('data-copy'));
    if (!src || !navigator.clipboard) { return; }
    var text = 'value' in src && src.value ? src.value : src.textContent;
    navigator.clipboard.writeText(text).then(function () {
      btn.setAttribute('data-copied', 'true');
      window.setTimeout(function () { btn.removeAttribute('data-copied'); }, 1500);
    });
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!(t instanceof Element)) { return; }
    var el;
    if ((el = t.closest('#sb-toggle'))) { toggleSidebar(); return; }
    if ((el = t.closest('[data-modal-open]'))) { openModal(el.getAttribute('data-modal-open')); return; }
    if ((el = t.closest('[data-modal-close]'))) { closeModal(el); return; }
    if ((el = t.closest('[data-toast-close]'))) { dismissToast(el.closest('.toast')); return; }
    if ((el = t.closest('[data-copy]'))) { copyFrom(el); return; }
    if (t.tagName === 'DIALOG' && t.open) { t.close(); } // клик по подложке
  });

  // ---- автоотправка кода (TOTP): набрано N цифр -> submit (htmx перехватывает событие submit) ----
  // Один раз на значение: повтор только после того, как код изменили.
  document.addEventListener('input', function (e) {
    var el = e.target;
    if (!(el instanceof HTMLInputElement) || !el.hasAttribute('data-autosubmit')) { return; }
    var need = parseInt(el.getAttribute('data-autosubmit'), 10);
    var digits = el.value.replace(/\D/g, '');
    if (digits.length !== need) { el.removeAttribute('data-autosubmitted'); return; }
    if (el.getAttribute('data-autosubmitted') === digits || !el.form) { return; }
    el.setAttribute('data-autosubmitted', digits);
    if (typeof el.form.requestSubmit === 'function') {
      el.form.requestSubmit();
    } else {
      var b = el.form.querySelector('button[type=submit]');
      if (b) { b.click(); }
    }
  });

  // htmx: HX-Trigger {"toast": {"kind":"ok","message":"…"}} -> тост (textContent, без innerHTML)
  document.addEventListener('toast', function (e) {
    var box = document.getElementById('toasts');
    var d = e.detail || {};
    if (!box || !d.message) { return; }
    var t = document.createElement('div');
    t.className = 'toast toast-' + (['ok', 'warn', 'err', 'info'].indexOf(d.kind) >= 0 ? d.kind : 'info');
    var m = document.createElement('span');
    m.textContent = String(d.message);
    t.appendChild(m);
    box.appendChild(t);
  });

  function init() { syncSidebar(); watchToasts(); }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
