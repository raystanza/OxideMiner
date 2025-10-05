function formatHashrate(hps) {
  // hps = hashes per second (Number)
  if (!Number.isFinite(hps)) return '-';
  if (hps >= 1e9) { return (hps / 1e9).toFixed(3) + ' GH/s'; }
  if (hps >= 1e3) { return (hps / 1e3).toFixed(3) + ' KH/s'; }
  return hps.toFixed(2) + ' H/s';
}

const intFmt = new Intl.NumberFormat('en-US');

function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return '-';
  const totalSeconds = Math.max(0, Math.floor(seconds));
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const secs = totalSeconds % 60;

  const parts = [];
  if (days > 0) parts.push(days + 'd');
  parts.push(String(hours).padStart(2, '0') + 'h');
  parts.push(String(minutes).padStart(2, '0') + 'm');
  parts.push(String(secs).padStart(2, '0') + 's');
  return parts.join(' ');
}

async function fetchStats() {
  try {
    const response = await fetch('/api/stats');
    const data = await response.json();
    document.getElementById('hashrate').textContent = formatHashrate(Number(data.hashrate));
    document.getElementById('hashes').textContent = intFmt.format(Number(data.hashes_total));
    document.getElementById('accepted').textContent = data.shares.accepted;
    document.getElementById('rejected').textContent = data.shares.rejected;
    document.getElementById('dev_accepted').textContent = data.shares.dev_accepted;
    document.getElementById('dev_rejected').textContent = data.shares.dev_rejected;
    const poolEl = document.getElementById('pool');
    poolEl.textContent = data.pool || '-';
    poolEl.title = data.pool || '';

    document.getElementById('connected').textContent = data.connected ? 'Yes' : 'No';
    document.getElementById('tls').textContent = data.tls ? 'Yes' : 'No';
    const timing = data.timing || {};
    document.getElementById('system_uptime').textContent =
      formatDuration(Number(timing.system_uptime_seconds));
    document.getElementById('mining_time').textContent =
      formatDuration(Number(timing.mining_time_seconds));
    updateFooter(data);
  } catch (e) {
    console.error('Failed to fetch stats', e);
  }
}

/* Refresh/polling interval handling */
(function initPolling() {
  const POLL_KEY = 'oxide_poll_ms';
  const select = document.getElementById('polling-select');
  const allowed = [1000, 5000, 10000, 30000, 60000];
  let pollTimer = null;

  function normalize(ms) {
    const n = parseInt(ms, 10);
    return allowed.includes(n) ? n : 1000;
  }

  function apply(ms) {
    const n = normalize(ms);
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(fetchStats, n);
    if (select && select.value !== String(n)) select.value = String(n);
    try { localStorage.setItem(POLL_KEY, String(n)); } catch (_) {}
  }

  // Initial value (persisted or default 1s)
  const saved = (() => {
    try { return parseInt(localStorage.getItem(POLL_KEY), 10); } catch (_) { return NaN; }
  })();
  apply(saved);

  if (select) {
    select.addEventListener('change', () => {
      apply(select.value);
      fetchStats(); // immediate refresh on change
    });
  }

  // Optional: pause when tab not visible to save cycles
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (pollTimer) clearInterval(pollTimer);
    } else {
      apply(select ? select.value : saved);
      fetchStats();
    }
  });
})();

/* Theme handling */

(function initTheme() {
  const THEME_KEY = 'oxide_theme';
  const body = document.body;
  const select = document.getElementById('theme-select');

  function applyTheme(theme) {
    const allowed = ['light', 'dark', 'monero'];
    const t = allowed.includes(theme) ? theme : 'light';
    body.setAttribute('data-theme', t);
    if (select && select.value !== t) select.value = t;
    try { localStorage.setItem(THEME_KEY, t); } catch (_) {}
  }

  // Initial theme (persisted or default "light")
  const saved = (() => {
    try { return localStorage.getItem(THEME_KEY); } catch (_) { return null; }
  })();
  applyTheme(saved || 'light');

  // Hook up selector
  if (select) {
    select.addEventListener('change', () => applyTheme(select.value));
  }
})();

function updateFooter(data) {
  // try common fields; harmless if absent
  const version = data.version || data.pkg_version || data.pkg || null;
  const vEl = document.getElementById('version');
  const tEl = document.getElementById('last-updated');

  if (vEl) vEl.textContent = version ? `v${version}` : '';
  if (tEl) tEl.textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

fetchStats();