(() => {
if (window.__OXIDE_DASHBOARD_BOOTED__) {
  console.warn('Oxide dashboard already initialized; skipping duplicate bootstrap.');
  return;
}
window.__OXIDE_DASHBOARD_BOOTED__ = true;

const controlElements = Array.from(document.querySelectorAll('.toolbar select'));
const themeSelect = document.getElementById('theme-select');

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

function formatUnixTimestamp(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  const d = new Date(seconds * 1000);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleString();
}

function applyStats(data) {
  const hashrateEl = document.getElementById('hashrate');
  if (hashrateEl) {
    const avg = formatHashrate(Number(data.hashrate_avg ?? data.hashrate));
    const instant = formatHashrate(Number(data.instant_hashrate));
    hashrateEl.textContent = `${avg} / ${instant}`;
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

  const modeEl = document.getElementById('mode');
  if (modeEl) {
    const mode = typeof data.mode === 'string' ? data.mode : '-';
    modeEl.textContent = mode !== '-' ? mode.charAt(0).toUpperCase() + mode.slice(1) : '-';
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

  const solo = data.solo || {};
  const nodeHeightEl = document.getElementById('node_height');
  if (nodeHeightEl) {
    const height = Number(solo.node_height);
    nodeHeightEl.textContent = Number.isFinite(height) ? intFmt.format(height) : '-';
  }

  const templateHeightEl = document.getElementById('template_height');
  if (templateHeightEl) {
    const height = Number(solo.template_height);
    templateHeightEl.textContent = Number.isFinite(height) ? intFmt.format(height) : '-';
  }

  const templateAgeEl = document.getElementById('template_age');
  if (templateAgeEl) {
    const ageValue = solo.template_age_seconds;
    const age = Number(ageValue);
    const valid = ageValue !== null && ageValue !== undefined && Number.isFinite(age);
    templateAgeEl.textContent = valid ? formatDuration(age) : '-';
  }

  const blocks = solo.blocks || {};
  const soloBlocksEl = document.getElementById('solo_blocks');
  if (soloBlocksEl) {
    const accepted = Number.isFinite(Number(blocks.accepted)) ? blocks.accepted : '-';
    const rejected = Number.isFinite(Number(blocks.rejected)) ? blocks.rejected : '-';
    const submitted = Number.isFinite(Number(blocks.submitted)) ? blocks.submitted : '-';
    soloBlocksEl.textContent = `${accepted} / ${rejected} (${submitted})`;
  }

  const lastSubmitEl = document.getElementById('last_submit');
  if (lastSubmitEl) {
    const last = solo.last_submit;
    if (last && typeof last === 'object') {
      const outcome = typeof last.outcome === 'string' ? last.outcome : 'unknown';
      const detail = typeof last.detail === 'string' ? last.detail : '';
      const when = formatUnixTimestamp(Number(last.timestamp));
      let text = outcome;
      if (detail) {
        text += `: ${detail}`;
      }
      if (when) {
        text += ` (${when})`;
      }
      lastSubmitEl.textContent = text;
    } else {
      lastSubmitEl.textContent = '-';
    }
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
(function initThemePicker() {
  if (!window.themeManager) return;

  function renderOptions(list) {
    if (!themeSelect) return;
    themeSelect.innerHTML = '';
    list.forEach((theme) => {
      const opt = document.createElement('option');
      opt.value = theme.id;
      const label = theme.kind === 'plugin' ? `${theme.name} (plugin)` : theme.name;
      opt.textContent = label;
      themeSelect.appendChild(opt);
    });
  }

  function syncSelect(activeId) {
    if (!themeSelect) return;
    if (activeId && themeSelect.value !== activeId) {
      themeSelect.value = activeId;
    }
  }

  themeManager.ensureThemes().then((list) => {
    renderOptions(list);
    return themeManager.applySavedTheme();
  }).then(() => {
    syncSelect(themeManager.activeTheme || 'light');
  });

  if (themeSelect) {
    themeSelect.addEventListener('change', () => {
      themeManager.applyTheme(themeSelect.value);
    });
  }

  themeManager.onChange((id) => syncSelect(id));
})();

(function initPluginsMenu() {
  const button = document.getElementById('plugins-menu-button');
  const menu = document.getElementById('plugins-menu');
  if (!button || !menu) return;

  function closeMenu() {
    menu.classList.remove('open');
    button.setAttribute('aria-expanded', 'false');
  }

  function toggleMenu(event) {
    event.preventDefault();
    const isOpen = menu.classList.toggle('open');
    button.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  }

  button.addEventListener('click', toggleMenu);

  document.addEventListener('click', (event) => {
    if (!menu.contains(event.target) && event.target !== button) {
      closeMenu();
    }
  });

  menu.addEventListener('click', () => closeMenu());
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

})();
