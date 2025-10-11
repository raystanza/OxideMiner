const controlElements = Array.from(document.querySelectorAll('.toolbar select'));

function setControlsDisabled(disabled) {
  controlElements.forEach((el) => {
    el.disabled = disabled;
    if (disabled) {
      el.setAttribute('aria-disabled', 'true');
    } else {
      el.removeAttribute('aria-disabled');
    }
  });
}

const loading = (() => {
  const overlay = document.getElementById('loading-overlay');
  const messageEl = document.getElementById('loading-message');
  const errorEl = document.getElementById('loading-error');
  const spinnerEl = overlay ? overlay.querySelector('.loading-spinner') : null;

  function showBase() {
    if (!overlay) return;
    overlay.classList.remove('is-hidden', 'has-error');
    overlay.setAttribute('aria-busy', 'true');
    if (spinnerEl) {
      spinnerEl.hidden = false;
    }
    if (errorEl) {
      errorEl.textContent = '';
    }
    setControlsDisabled(true);
  }

  function updateAttempt(attempt, maxAttempts, nextDelayMs) {
    showBase();
    if (!messageEl) return;
    let text = 'Loading miner stats...';
    if (attempt > 1) {
      text += ` (retry ${attempt} of ${maxAttempts})`;
      if (Number.isFinite(nextDelayMs) && nextDelayMs > 0) {
        const seconds = (nextDelayMs / 1000).toFixed(1).replace(/\.0$/, '');
        text += ` – retrying in ${seconds}s`;
      }
    }
    messageEl.textContent = text;
  }

  function hide() {
    if (!overlay) return;
    overlay.classList.add('is-hidden');
    overlay.classList.remove('has-error');
    overlay.setAttribute('aria-busy', 'false');
    if (spinnerEl) {
      spinnerEl.hidden = true;
    }
    setControlsDisabled(false);
  }

  function error(message) {
    if (!overlay) return;
    overlay.classList.remove('is-hidden');
    overlay.classList.add('has-error');
    overlay.setAttribute('aria-busy', 'false');
    if (spinnerEl) {
      spinnerEl.hidden = true;
    }
    if (messageEl) {
      messageEl.textContent = 'Unable to load miner stats';
    }
    if (errorEl) {
      errorEl.textContent = message;
    }
    setControlsDisabled(false);
  }

  return { updateAttempt, hide, error };
})();

loading.updateAttempt(1, 20);

function formatHashrate(hps) {
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
  return Number.isNaN(d.getTime()) ? null : d.toLocaleString();
}

function applyStats(data) {
  const hashrateEl = document.getElementById('hashrate');
  if (hashrateEl) {
    hashrateEl.textContent = formatHashrate(Number(data.hashrate));
  }
  const hashesEl = document.getElementById('hashes');
  if (hashesEl) {
    hashesEl.textContent = intFmt.format(Number(data.hashes_total));
  }

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
  if (poolEl) {
    const pool = data.pool || '-';
    poolEl.textContent = pool;
    poolEl.title = pool !== '-' ? pool : '';
  }

  const connectedEl = document.getElementById('connected');
  if (connectedEl) {
    connectedEl.textContent = data.connected ? 'Yes' : 'No';
  }

  const tlsEl = document.getElementById('tls');
  if (tlsEl) {
    tlsEl.textContent = data.tls ? 'Yes' : 'No';
  }

  const timing = data.timing || {};
  const systemUptimeEl = document.getElementById('system_uptime');
  if (systemUptimeEl) {
    systemUptimeEl.textContent = formatDuration(Number(timing.system_uptime_seconds));
  }
  const miningTimeEl = document.getElementById('mining_time');
  if (miningTimeEl) {
    miningTimeEl.textContent = formatDuration(Number(timing.mining_time_seconds));
  }

  updateFooter(data);
}

async function requestStatsJson() {
  let response;
  try {
    response = await fetch('/api/stats', { cache: 'no-store' });
  } catch (networkError) {
    const error = new Error('Network error while requesting miner stats');
    error.cause = networkError;
    throw error;
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} while fetching miner stats`);
  }

  try {
    return await response.json();
  } catch (parseError) {
    const error = new Error('Failed to parse miner stats response');
    error.cause = parseError;
    throw error;
  }
}

async function updateStats() {
  const data = await requestStatsJson();
  applyStats(data);
  return data;
}

function fetchStatsSafe() {
  updateStats().catch((err) => {
    console.error('Failed to fetch stats', err);
  });
}

const pollingController = (() => {
  const POLL_KEY = 'oxide_poll_ms';
  const select = document.getElementById('polling-select');
  const allowed = [1000, 5000, 10000, 30000, 60000];

  let pollTimer = null;
  let currentInterval = 1000;
  let isReady = false;

  function normalize(ms) {
    const n = parseInt(ms, 10);
    return allowed.includes(n) ? n : 1000;
  }

  function stop() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function startTimer() {
    stop();
    if (!isReady) return;
    pollTimer = setInterval(fetchStatsSafe, currentInterval);
  }

  function applyInterval(ms, { persist = true, immediate = false } = {}) {
    const n = normalize(ms);
    currentInterval = n;
    if (select && select.value !== String(n)) {
      select.value = String(n);
    }
    if (persist) {
      try {
        localStorage.setItem(POLL_KEY, String(n));
      } catch (_) {}
    }
    startTimer();
    if (immediate && isReady) {
      fetchStatsSafe();
    }
  }

  const saved = (() => {
    try {
      return parseInt(localStorage.getItem(POLL_KEY), 10);
    } catch (_) {
      return NaN;
    }
  })();

  applyInterval(saved, { persist: false });

  if (select) {
    select.addEventListener('change', () => {
      applyInterval(select.value, { immediate: true });
    });
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stop();
    } else {
      startTimer();
      if (isReady) {
        fetchStatsSafe();
      }
    }
  });

  return {
    notifyReady() {
      if (isReady) return;
      isReady = true;
      startTimer();
    },
    stop,
  };
})();

async function loadStatsWithRetry() {
  const maxAttempts = 20;
  const baseDelay = 3000;
  const backoffFactor = 1.5;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    loading.updateAttempt(attempt, maxAttempts);
    try {
      await updateStats();
      return;
    } catch (error) {
      console.error('Failed to fetch stats', error);
      if (attempt === maxAttempts) {
        throw error;
      }
      const delay = Math.round(baseDelay * Math.pow(backoffFactor, attempt - 1));
      loading.updateAttempt(attempt + 1, maxAttempts, delay);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}

(async () => {
  try {
    await loadStatsWithRetry();
    loading.hide();
    pollingController.notifyReady();
  } catch (error) {
    loading.error('Failed to load stats after multiple attempts. Check the miner CLI for errors.');
  }
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

  const saved = (() => {
    try { return localStorage.getItem(THEME_KEY); } catch (_) { return null; }
  })();
  applyTheme(saved || 'light');

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
