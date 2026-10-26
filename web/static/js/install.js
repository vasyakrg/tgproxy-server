// Шаг «Установка» мастера «Новый агент»: журнал и статусы шагов по SSE. Без inline-кода (CSP).
// Используется нативный EventSource: при обрыве браузер сам переподключается и шлёт Last-Event-ID,
// сервер отдаёт пропущенные события. (htmx-ext-sse пересоздаёт соединение и теряет Last-Event-ID.)
// События: step, log, done, fail (имя fail, а не error: error — служебное событие самого EventSource).
(function () {
  'use strict';

  var root = document.getElementById('install-job');
  if (!root || typeof window.EventSource === 'undefined') { return; }

  var eventsURL = root.getAttribute('data-events-url');
  var statusURL = root.getAttribute('data-status-url');
  var stepsBox = document.getElementById('job-steps');
  var logBox = document.getElementById('job-log');
  var stateEl = document.getElementById('job-state');
  var timeEl = document.getElementById('job-time');
  var connEl = document.getElementById('job-conn');
  var okBox = document.getElementById('job-ok');
  var failBox = document.getElementById('job-fail');
  var failText = document.getElementById('job-fail-text');

  var started = parseInt(root.getAttribute('data-started'), 10) || Date.now();
  var finished = parseInt(root.getAttribute('data-finished'), 10) || 0;
  var lastSeq = 0;
  var closed = false;
  var es = null;
  var STATE_LABEL = { running: 'выполняется', done: 'готово', failed: 'не удалось' };

  function pad(n) { return n < 10 ? '0' + n : String(n); }

  function renderTime() {
    var end = finished || Date.now();
    var s = Math.max(0, Math.floor((end - started) / 1000));
    timeEl.textContent = Math.floor(s / 60) + ':' + pad(s % 60);
  }

  function setState(state) {
    root.setAttribute('data-state', state);
    stateEl.textContent = STATE_LABEL[state] || state;
  }

  function stepItem(key) {
    var items = stepsBox.querySelectorAll('.job-step');
    for (var i = 0; i < items.length; i++) {
      if (items[i].getAttribute('data-step') === key) { return items[i]; }
    }
    return null;
  }

  function setStep(d) {
    var li = stepItem(d.step);
    if (!li) {
      li = document.createElement('li');
      li.className = 'job-step';
      li.setAttribute('data-step', d.step);
      var mark = document.createElement('span');
      mark.className = 'job-mark mono';
      mark.setAttribute('aria-hidden', 'true');
      var label = document.createElement('span');
      label.className = 'job-label';
      var st = document.createElement('span');
      st.className = 'sr-only job-status';
      li.appendChild(mark); li.appendChild(label); li.appendChild(st);
      stepsBox.appendChild(li);
    }
    li.setAttribute('data-status', d.status);
    if (d.message) { li.querySelector('.job-label').textContent = d.message; }
    li.querySelector('.job-status').textContent = d.status;
  }

  function addLog(d) {
    var atBottom = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 24;
    var t = d.at ? new Date(d.at) : new Date();
    var line = document.createElement('span');
    if (d.level === 'warn' || d.level === 'error') { line.className = 'log-' + d.level; }
    line.textContent = '[' + pad(t.getHours()) + ':' + pad(t.getMinutes()) + ':' + pad(t.getSeconds()) + '] ' + d.message + '\n';
    logBox.appendChild(line);
    if (atBottom) { logBox.scrollTop = logBox.scrollHeight; }
  }

  function finish(ok, message) {
    closed = true;
    if (es) { es.close(); }
    finished = finished || Date.now();
    connEl.hidden = true;
    setState(ok ? 'done' : 'failed');
    okBox.hidden = !ok;
    failBox.hidden = ok;
    if (!ok && message) { failText.textContent = message; }
    renderTime();
  }

  // data события: {seq, kind, step, status, level, message, at}
  function handle(kind, ev) {
    var d;
    try { d = JSON.parse(ev.data); } catch (e) { return; }
    var seq = d.seq || parseInt(ev.lastEventId, 10) || 0;
    if (seq && seq <= lastSeq) { return; } // повтор после переподключения
    if (seq) { lastSeq = seq; }
    if (kind === 'step') { setStep(d); }
    else if (kind === 'log') { addLog(d); }
    else if (kind === 'done') { addLog(d); finish(true, ''); }
    else if (kind === 'fail') { addLog({ level: 'error', message: d.message, at: d.at }); finish(false, d.message); }
  }

  // Поток закрыт окончательно (не автопереподключение): узнаём итог по снимку задачи.
  function fallbackStatus() {
    if (closed || !window.fetch) { return; }
    window.fetch(statusURL, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!j || closed) { return; }
        if (j.state === 'done') { finish(true, ''); }
        else if (j.state === 'failed') { finish(false, j.error || ''); }
        else { window.setTimeout(connect, 3000); }
      })
      .catch(function () { window.setTimeout(connect, 3000); });
  }

  function connect() {
    if (closed) { return; }
    es = new EventSource(eventsURL);
    es.onopen = function () { connEl.hidden = true; };
    ['step', 'log', 'done', 'fail'].forEach(function (kind) {
      es.addEventListener(kind, function (ev) { handle(kind, ev); });
    });
    es.onerror = function () {
      if (closed) { return; }
      if (es.readyState === 2) { fallbackStatus(); return; }
      connEl.hidden = false; // CONNECTING: браузер переподключится сам с Last-Event-ID
    };
  }

  renderTime();
  if (!finished) { window.setInterval(function () { if (!finished) { renderTime(); } }, 1000); }
  connect();
})();
