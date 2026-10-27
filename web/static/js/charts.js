// Живой график «Обзора» (uPlot) и обновление KPI. Без inline-кода (CSP): всё из data-* атрибутов.
//
// Разметка:  [data-chart] data-range data-poll-ms data-url data-summary-url
//   внутри:  [data-chart-plot] (холст), [data-chart-empty] (пустое состояние)
// Рядом (в секции .ov-chart): [data-live-toggle], [data-live-label], [data-updated], [data-chart-tip];
// KPI на странице: [data-kpi="rps|err_pct|r429|agents|inflight"], [data-kpi-hint="rps|agents"].
(function () {
  'use strict';

  var RANGE_SEC = { '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800 };
  var ANIM_MS = 600;
  var DENY_LABELS = {
    no_rule: 'нет правила', key_required: 'нужен ключ', bad_key: 'неверный ключ',
    rate_limited: 'лимит', banned: 'бан'
  };
  var MIN_POLL = 2000;
  var MAX_POLL = 60000;
  var CHART_H = 240;

  var instances = new WeakMap();
  var reduceMotion = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;

  // ---- утилиты ----
  function css(name, fallback) {
    var v = window.getComputedStyle(document.documentElement).getPropertyValue(name);
    v = v ? v.trim() : '';
    return v || fallback;
  }

  function rgba(hex, a) {
    var m = /^#([0-9a-f]{6})$/i.exec(hex);
    if (!m) { return null; }
    var n = parseInt(m[1], 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }

  function num(v, d) { return Number(v).toFixed(d).replace('.', ','); }
  function fmtRPS(v) { return v < 10 ? num(v, 1) : String(Math.round(v)); }
  function pad(n) { return n < 10 ? '0' + n : String(n); }

  function fmtTime(ts, withDate) {
    var d = new Date(ts * 1000);
    var t = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    return withDate ? pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + ' ' + t : t;
  }

  function noMotion() { return !!(reduceMotion && reduceMotion.matches); }
  function ease(t) { return 1 - Math.pow(1 - t, 3); }
  function setText(el, text) { if (el && el.textContent !== text) { el.textContent = text; } }

  function toNum(v) { var n = Number(v); return isFinite(n) ? n : 0; }

  // ---- график ----
  function Chart(el) {
    this.el = el;
    this.root = el.closest('.ov-chart') || el.parentNode;
    this.plotEl = el.querySelector('[data-chart-plot]') || el;
    this.emptyEl = el.querySelector('[data-chart-empty]');
    this.tipEl = this.root.querySelector('[data-chart-tip]');
    this.liveBtn = this.root.querySelector('[data-live-toggle]');
    this.liveLabel = this.root.querySelector('[data-live-label]');
    this.updEl = this.root.querySelector('[data-updated]');

    this.range = el.getAttribute('data-range') || '24h';
    this.windowSec = RANGE_SEC[this.range] || 86400;
    var pm = parseInt(el.getAttribute('data-poll-ms'), 10) || 5000;
    this.pollMs = Math.min(MAX_POLL, Math.max(MIN_POLL, pm));
    this.url = el.getAttribute('data-url') || '/api/v1/stats/timeseries';
    this.summaryUrl = el.getAttribute('data-summary-url') || '';
    this.defaultTip = this.tipEl ? this.tipEl.textContent : '';

    this.data = [[], [], [], [], []]; // t, ok, err, r429, denied
    this.denyBy = []; // разбивка отказов по причинам для тултипа, параллельно data[0]
    this.stepSec = 0;
    this.live = true;
    this.destroyed = false;
    this.u = null;
    this.timer = 0;
    this.agoTimer = 0;
    this.raf = 0;
    this.abort = null;
    this.lastOkAt = Date.now();
    this.pausedAt = 0;
    var now = Math.floor(Date.now() / 1000);
    this.view = { min: now - this.windowSec, max: now };

    this.onToggle = this.toggle.bind(this);
    this.onVisibility = this.visibility.bind(this);
    this.start();
  }

  Chart.prototype.start = function () {
    var self = this;
    if (typeof window.uPlot !== 'function') {
      this.showEmpty('График недоступен', true);
      return;
    }
    if (this.liveBtn) { this.liveBtn.addEventListener('click', this.onToggle); }
    document.addEventListener('visibilitychange', this.onVisibility);
    if (typeof ResizeObserver === 'function') {
      this.ro = new ResizeObserver(function () { self.resize(); });
      this.ro.observe(this.plotEl);
    }
    this.renderLive();
    this.loadInitial();
    this.startAgo();
  };

  Chart.prototype.destroy = function () {
    if (this.destroyed) { return; }
    this.destroyed = true;
    window.clearTimeout(this.timer);
    window.clearInterval(this.agoTimer);
    if (this.raf) { window.cancelAnimationFrame(this.raf); }
    if (this.abort) { this.abort.abort(); }
    if (this.ro) { this.ro.disconnect(); }
    if (this.liveBtn) { this.liveBtn.removeEventListener('click', this.onToggle); }
    document.removeEventListener('visibilitychange', this.onVisibility);
    if (this.u) { this.u.destroy(); this.u = null; }
    instances.delete(this.el);
  };

  // Элемент убрали из DOM (htmx-подмена) — прибираемся сами.
  Chart.prototype.alive = function () {
    if (this.destroyed) { return false; }
    if (!document.body.contains(this.el)) { this.destroy(); return false; }
    return true;
  };

  Chart.prototype.showEmpty = function (text, force) {
    if (!this.emptyEl) { return; }
    if (text) { this.emptyEl.textContent = text; }
    this.emptyEl.hidden = !(force || this.data[0].length === 0);
  };

  // ---- сеть ----
  Chart.prototype.getJSON = function (url, signal) {
    return window.fetch(url, {
      credentials: 'same-origin', cache: 'no-store', signal: signal,
      headers: { 'Accept': 'application/json' }
    }).then(function (res) {
      if (res.status === 401) { window.location.assign('/login'); throw new Error('unauthorized'); }
      if (!res.ok) { throw new Error('http ' + res.status); }
      return res.json();
    });
  };

  Chart.prototype.seriesURL = function (since) {
    var u = this.url + (this.url.indexOf('?') >= 0 ? '&' : '?') + 'range=' + encodeURIComponent(this.range);
    if (since) { u += '&since=' + since; }
    return u;
  };

  Chart.prototype.loadInitial = function () {
    var self = this;
    this.abort = new AbortController();
    this.getJSON(this.seriesURL(0), this.abort.signal).then(function (s) {
      if (!self.alive()) { return; }
      self.stepSec = toNum(s.step_sec);
      self.append(s.points || []);
      self.create();
      self.markOk();
      self.pollSummary();
      self.schedule();
    }).catch(function (e) {
      if (!self.alive() || (e && e.name === 'AbortError')) { return; }
      self.showEmpty('Не удалось загрузить данные', true);
      self.schedule(); // повторим тем же опросом
    });
  };

  Chart.prototype.append = function (points) {
    var d = this.data, last = d[0].length ? d[0][d[0].length - 1] : 0, added = 0;
    for (var i = 0; i < points.length; i++) {
      var p = points[i], t = toNum(p.t);
      if (t === last && last) { // открытое 5m-окно растёт: перезаписываем последнюю точку
        var k = d[0].length - 1;
        d[1][k] = toNum(p.ok_rps); d[2][k] = toNum(p.err_rps); d[3][k] = toNum(p.r429_rps);
        d[4][k] = toNum(p.denied_rps); this.denyBy[k] = p.denied_by || null;
        added++;
        continue;
      }
      if (t < last) { continue; }
      d[0].push(t); d[1].push(toNum(p.ok_rps)); d[2].push(toNum(p.err_rps)); d[3].push(toNum(p.r429_rps));
      d[4].push(toNum(p.denied_rps)); this.denyBy.push(p.denied_by || null);
      last = t; added++;
    }
    return added;
  };

  Chart.prototype.trim = function () {
    var d = this.data, n = d[0].length;
    if (!n) { return; }
    var cutoff = d[0][n - 1] - this.windowSec - this.stepSec; // одна точка запаса слева — линия не обрывается
    var k = 0;
    while (k < n - 1 && d[0][k] < cutoff) { k++; }
    if (k > 0) { for (var s = 0; s < 5; s++) { d[s].splice(0, k); } this.denyBy.splice(0, k); }
  };

  Chart.prototype.target = function () {
    var d = this.data, n = d[0].length;
    var max = n ? d[0][n - 1] : Math.floor(Date.now() / 1000);
    return { min: max - this.windowSec, max: max };
  };

  // ---- uPlot ----
  Chart.prototype.create = function () {
    var self = this;
    this.trim();
    this.view = this.target();
    this.showEmpty('Данных пока нет');

    var cOK = css('--accent', '#2DD4BF'), cErr = css('--orange', '#FB923C'), c429 = css('--tg', '#A78BFA');
    var cDenied = css('--err', '#F87171');
    var muted = css('--muted', '#9AA3B2'), border = css('--border', '#262B36');
    var font = '11px ' + css('--font-mono', 'ui-monospace, monospace');
    function ser(label, color) {
      return { label: label, stroke: color, width: 2, fill: rgba(color, 0.12), points: { show: false } };
    }
    var opts = {
      width: Math.max(this.plotEl.clientWidth, 200),
      height: this.plotEl.clientHeight || CHART_H,
      legend: { show: false },
      cursor: { drag: { x: false, y: false }, y: false, points: { size: 7 } },
      scales: {
        x: { time: true, range: function () { return [self.view.min, self.view.max]; } },
        y: { range: function (u, min, max) { return [0, Math.max(1, (max || 0) * 1.15)]; } }
      },
      axes: [
        {
          stroke: muted, font: font, grid: { stroke: border, width: 1 }, ticks: { stroke: border, width: 1 },
          values: function (u, splits) {
            var withDate = self.windowSec > 86400;
            return splits.map(function (v) {
              var d = new Date(v * 1000), hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
              return withDate ? pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + ' ' + hm : hm;
            });
          }
        },
        {
          stroke: muted, font: font, size: 48, grid: { stroke: border, width: 1 }, ticks: { show: false },
          values: function (u, vals) { return vals.map(function (v) { return v === Math.round(v) ? String(v) : num(v, 1); }); }
        }
      ],
      series: [
        {},
        ser('успешные', cOK),
        ser('ошибки прокси', cErr),
        ser('429 Telegram', c429),
        ser('отказы', cDenied)
      ],
      hooks: { setCursor: [function (u) { self.onCursor(u); }] }
    };
    this.plotEl.textContent = '';
    this.u = new window.uPlot(opts, this.data, this.plotEl);
  };

  Chart.prototype.resize = function () {
    var self = this;
    if (!this.u || this.resizing) { return; }
    this.resizing = true;
    window.requestAnimationFrame(function () {
      self.resizing = false;
      if (!self.u || self.destroyed) { return; }
      var w = Math.max(self.plotEl.clientWidth, 200), h = self.plotEl.clientHeight || CHART_H;
      if (w !== self.u.width || h !== self.u.height) { self.u.setSize({ width: w, height: h }); }
    });
  };

  Chart.prototype.onCursor = function (u) {
    if (!this.tipEl) { return; }
    var i = u.cursor.idx, d = this.data;
    if (i === null || i === undefined || !d[0].length || i >= d[0].length) {
      setText(this.tipEl, this.defaultTip);
      this.tipEl.removeAttribute('data-active');
      return;
    }
    var txt = fmtTime(d[0][i], this.windowSec > 86400) +
      ' · успешные ' + fmtRPS(d[1][i]) + ' rps' +
      ' · ошибки ' + fmtRPS(d[2][i]) +
      ' · 429: ' + fmtRPS(d[3][i]) +
      ' · отказы ' + fmtRPS(d[4][i]) + this.denyDetail(i);
    setText(this.tipEl, txt);
    this.tipEl.setAttribute('data-active', 'true');
  };

  // Разбивка отказов по причинам: « (нет правила 0,2; неверный ключ 1,1)».
  Chart.prototype.denyDetail = function (i) {
    var by = this.denyBy[i];
    if (!by) { return ''; }
    var parts = [];
    for (var k in DENY_LABELS) {
      if (Object.prototype.hasOwnProperty.call(DENY_LABELS, k) && toNum(by[k]) > 0) {
        parts.push(DENY_LABELS[k] + ' ' + fmtRPS(toNum(by[k])));
      }
    }
    return parts.length ? ' (' + parts.join('; ') + ')' : '';
  };

  // Новые точки: дописываем, сдвигаем окно (с плавной анимацией), если не reduced-motion.
  Chart.prototype.apply = function () {
    if (!this.u) { this.create(); return; }
    this.trim();
    this.showEmpty('Данных пока нет');
    var from = { min: this.view.min, max: this.view.max }, to = this.target();
    if (this.raf) { window.cancelAnimationFrame(this.raf); this.raf = 0; }
    this.u.setData(this.data, true); // x-диапазон пока прежний (range() отдаёт this.view), y пересчитывается
    if (noMotion() || document.hidden) {
      this.view = to;
      this.u.setScale('x', { min: to.min, max: to.max });
      return;
    }
    var self = this, t0 = null;
    function frame(ts) {
      if (self.destroyed || !self.u) { return; }
      if (t0 === null) { t0 = ts; }
      var k = Math.min(1, (ts - t0) / ANIM_MS), e = ease(k);
      self.view = { min: from.min + (to.min - from.min) * e, max: from.max + (to.max - from.max) * e };
      self.u.setScale('x', { min: self.view.min, max: self.view.max });
      self.raf = k < 1 ? window.requestAnimationFrame(frame) : 0;
    }
    this.raf = window.requestAnimationFrame(frame);
  };

  // ---- опрос ----
  Chart.prototype.schedule = function () {
    window.clearTimeout(this.timer);
    if (this.destroyed || !this.live || document.hidden) { return; }
    var self = this;
    this.timer = window.setTimeout(function () { self.poll(); }, this.pollMs);
  };

  Chart.prototype.poll = function () {
    var self = this;
    if (!this.alive() || !this.live || document.hidden) { return; }
    if (!this.u) { this.loadInitial(); return; }
    var d = this.data, last = d[0].length ? d[0][d[0].length - 1] : 0;
    if (this.abort) { this.abort.abort(); }
    this.abort = new AbortController();
    var signal = this.abort.signal;
    this.getJSON(this.seriesURL(last), signal).then(function (s) {
      if (!self.alive()) { return; }
      if (self.append(s.points || []) > 0) { self.apply(); }
      self.markOk();
    }).catch(function (e) {
      if (e && e.name === 'AbortError') { return; }
      self.renderAgo(true);
    }).then(function () {
      if (self.alive() && !signal.aborted) { self.schedule(); }
    });
    this.pollSummary(signal);
  };

  // KPI обновляются тем же опросом; ошибка сводки график не ломает.
  Chart.prototype.pollSummary = function (signal) {
    if (!this.summaryUrl) { return; }
    var self = this;
    this.getJSON(this.summaryUrl, signal || (this.abort && this.abort.signal)).then(function (k) {
      if (self.alive()) { updateKPI(self.root.ownerDocument, k); }
    }).catch(function () { /* следующий тик */ });
  };

  Chart.prototype.markOk = function () {
    this.lastOkAt = Date.now();
    this.renderAgo(false);
  };

  // ---- Live / Пауза ----
  Chart.prototype.toggle = function () {
    this.live = !this.live;
    window.clearTimeout(this.timer);
    if (this.abort) { this.abort.abort(); }
    if (this.live) {
      this.pausedAt = 0;
      this.poll();
    } else {
      this.pausedAt = Date.now();
    }
    this.renderLive();
    this.renderAgo(false);
  };

  Chart.prototype.renderLive = function () {
    if (!this.liveBtn) { return; }
    this.liveBtn.setAttribute('aria-pressed', this.live ? 'true' : 'false');
    this.liveBtn.setAttribute('title', this.live ? 'Остановить обновление' : 'Возобновить обновление');
    var dot = this.liveBtn.querySelector('.live-dot');
    if (dot) { dot.classList.toggle('dot-live', this.live); }
    setText(this.liveLabel, this.live ? 'Live · опрос ' + Math.round(this.pollMs / 1000) + ' с' : 'Пауза');
  };

  Chart.prototype.renderAgo = function (failed) {
    if (!this.updEl) { return; }
    var now = Date.now();
    if (!this.live) {
      setText(this.updEl, 'на паузе ' + Math.max(0, Math.round((now - this.pausedAt) / 1000)) + ' с');
      return;
    }
    var s = Math.max(0, Math.round((now - this.lastOkAt) / 1000));
    setText(this.updEl, (failed ? 'нет связи · ' : '') + 'обновлено ' + s + ' с назад');
  };

  Chart.prototype.startAgo = function () {
    var self = this;
    window.clearInterval(this.agoTimer);
    this.agoTimer = window.setInterval(function () {
      if (self.alive()) { self.renderAgo(false); }
    }, 1000);
  };

  // Скрытая вкладка: опрос и таймеры стоят; при возврате — сразу догоняем по since.
  Chart.prototype.visibility = function () {
    if (!this.alive()) { return; }
    if (document.hidden) {
      window.clearTimeout(this.timer);
      window.clearInterval(this.agoTimer);
      if (this.abort) { this.abort.abort(); }
      if (this.raf) { window.cancelAnimationFrame(this.raf); this.raf = 0; }
      return;
    }
    this.startAgo();
    if (this.u) { this.view = this.target(); this.u.setScale('x', { min: this.view.min, max: this.view.max }); }
    if (this.live) { this.poll(); }
  };

  // ---- KPI ----
  function setKPI(doc, key, text) { setText(doc.querySelector('[data-kpi="' + key + '"]'), text); }
  function setHint(doc, key, text) { setText(doc.querySelector('[data-kpi-hint="' + key + '"]'), text); }

  function toneClass(doc, key, cls) {
    var card = doc.querySelector('[data-kpi-card="' + key + '"]');
    if (!card) { return; }
    card.classList.remove('kpi-warn', 'kpi-err');
    if (cls) { card.classList.add(cls); }
  }

  function updateKPI(doc, k) {
    if (!k) { return; }
    var pct = toNum(k.proxy_err_pct);
    setKPI(doc, 'rps', fmtRPS(toNum(k.rps)));
    setHint(doc, 'rps', 'пик за 24 ч: ' + fmtRPS(toNum(k.peak_rps)));
    setKPI(doc, 'err_pct', num(pct, 1) + ' %');
    toneClass(doc, 'err_pct', pct >= 5 ? 'kpi-err' : (pct >= 1 ? 'kpi-warn' : ''));
    setKPI(doc, 'r429', String(toNum(k.r429)));
    setKPI(doc, 'inflight', String(toNum(k.inflight)));
    var up = toNum(k.agents_up), total = toNum(k.agents_total);
    setKPI(doc, 'agents', up + ' / ' + total);
    setHint(doc, 'agents', total === 0 ? 'нет агентов' : (up === total ? 'все в работе' : (total - up) + ' недоступно'));
    toneClass(doc, 'agents', total > 0 && up === 0 ? 'kpi-err' : '');
  }

  // ---- жизненный цикл ----
  function mount(root) {
    if (!root || !root.querySelectorAll) { return; }
    var list = [];
    if (root.matches && root.matches('[data-chart]')) { list.push(root); }
    var found = root.querySelectorAll('[data-chart]');
    for (var i = 0; i < found.length; i++) { list.push(found[i]); }
    list.forEach(function (el) {
      if (!instances.has(el)) { instances.set(el, new Chart(el)); }
    });
  }

  function unmount(root) {
    if (!root || !root.querySelectorAll) { return; }
    var list = [];
    if (root.matches && root.matches('[data-chart]')) { list.push(root); }
    var found = root.querySelectorAll('[data-chart]');
    for (var i = 0; i < found.length; i++) { list.push(found[i]); }
    list.forEach(function (el) {
      var c = instances.get(el);
      if (c) { c.destroy(); }
    });
  }

  document.addEventListener('htmx:load', function (e) { mount(e.target); });
  document.addEventListener('htmx:beforeCleanupElement', function (e) { unmount(e.target); });

  function init() { mount(document); }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
