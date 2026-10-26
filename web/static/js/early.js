// Применяет сохранённое состояние сайдбара до первой отрисовки (без мигания).
(function () {
  try {
    if (window.localStorage.getItem('tgproxy.sidebar.collapsed') === '1') {
      document.documentElement.classList.add('sb-collapsed');
    }
  } catch (e) { /* localStorage недоступен — остаётся развёрнутым */ }
})();
