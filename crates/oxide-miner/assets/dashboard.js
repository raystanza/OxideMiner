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

function formatIsoLocal(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return isNaN(d) ? null : d.toLocaleString();
}

async function fetchStats() {
  try {
    const response = await fetch('/api/stats');
    const data = await response.json();
    document.getElementById('hashrate').textContent = formatHashrate(Number(data.hashrate));
    document.getElementById('hashes').textContent = intFmt.format(Number(data.hashes_total));
    const shares = data.shares || {};
    const sharesEl = document.getElementById('shares');
    if (sharesEl) {
      const accepted = Number.isFinite(Number(shares.accepted)) ? shares.accepted : '-';
      const rejected = Number.isFinite(Number(shares.rejected)) ? shares.rejected : '-';
      sharesEl.textContent = `${accepted} / ${rejected}`;
    }

    const devSharesEl = document.getElementById('dev_shares');
    if (devSharesEl) {
      const devAccepted = Number.isFinite(Number(shares.dev_accepted)) ? shares.dev_accepted : '-';
      const devRejected = Number.isFinite(Number(shares.dev_rejected)) ? shares.dev_rejected : '-';
      devSharesEl.textContent = `${devAccepted} / ${devRejected}`;
    }
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

  // Pause when tab not visible to save cycles
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
  const el = document.getElementById('build-details');
  if (!el) return;

  const build = data.build || {};
  const version = data.version || build.version || data.pkg_version || data.pkg;
  const fullHash = build.commit_hash || null;
  const shortHash = build.commit_hash_short || (fullHash ? fullHash.slice(0, 7) : null);
  const commitTime = formatIsoLocal(build.commit_timestamp);
  const buildTime  = formatIsoLocal(build.build_timestamp);
  const parts = [];
  if (version) parts.push(`v${version}`);
  if (shortHash) {
    if (fullHash) {
      const url = `https://github.com/raystanza/OxideMiner/commit/${fullHash}`;
      parts.push(`commit <a href="${url}" target="_blank" rel="noopener noreferrer">${shortHash}</a>`);
    } else {
      parts.push(`commit ${shortHash}`);
    }
  }
  parts.push(`updated ${new Date().toLocaleTimeString()}`);
  //if (commitTime) parts.push(`committed ${commitTime}`);
  //if (buildTime)  parts.push(`built ${buildTime}`);

  el.innerHTML = parts.join(' <span class="sep">•</span> ');
}

fetchStats();