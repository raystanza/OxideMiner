(() => {
if (window.__OXIDE_DASHBOARD_BOOTED__) {
  console.warn('Oxide dashboard already initialized; skipping duplicate bootstrap.');
  return;
}
window.__OXIDE_DASHBOARD_BOOTED__ = true;

const controlElements = Array.from(document.querySelectorAll('.toolbar select'));
const themeSelect = document.getElementById('theme-select');
const cardElements = Array.from(document.querySelectorAll('.card'));
const modeBannerTitleEl = document.getElementById('mode-banner-title');
const modeBannerSubtitleEl = document.getElementById('mode-banner-subtitle');
const zmqTerminalEl = document.getElementById('zmq_terminal');
let lastZmqFeedText = '';

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
  if (hps < 0) return '-';

  const units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s', 'ZH/s', 'YH/s'];
  let value = hps;
  let idx = 0;

  while (value >= 1000 && idx < units.length - 1) {
    value /= 1000;
    idx++;
  }

  const decimals = idx === 0 ? 2 : 3;
  return `${value.toFixed(decimals)} ${units[idx]}`;
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

function formatTimeShort(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  const d = new Date(seconds * 1000);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

function isNearBottom(el) {
  const threshold = 24;
  return el.scrollHeight - el.scrollTop - el.clientHeight < threshold;
}

function formatZmqLine(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const when = formatTimeShort(Number(entry.ts)) || '--:--:--';
  const summary = typeof entry.summary === 'string' && entry.summary ? entry.summary : '';
  const topic = typeof entry.topic === 'string' && entry.topic ? entry.topic : '';
  const text = summary || topic || 'event';
  return `[${when}] ${text}`;
}

function updateZmqTerminal(zmq) {
  if (!zmqTerminalEl) return;
  const entries = Array.isArray(zmq.recent) ? zmq.recent : [];
  let lines = [];
  if (entries.length === 0) {
    if (zmq.enabled) {
      lines = ['Waiting for ZMQ events...'];
    } else {
      lines = ['ZMQ disabled.'];
    }
  } else {
    lines = entries.map(formatZmqLine).filter(Boolean);
  }

  const text = lines.join('\n');
  if (text === lastZmqFeedText) return;

  const shouldScroll = isNearBottom(zmqTerminalEl);
  zmqTerminalEl.textContent = text;
  lastZmqFeedText = text;
  if (shouldScroll) {
    zmqTerminalEl.scrollTop = zmqTerminalEl.scrollHeight;
  }
}

function normalizeMode(value) {
  if (typeof value !== 'string') return null;
  const mode = value.trim().toLowerCase();
  if (!mode) return null;
  return mode;
}

function readZmqState(data) {
  const solo = data && typeof data === 'object' ? data.solo || {} : {};
  const soloZmq = solo && typeof solo === 'object' ? solo.zmq || {} : {};

  const enabled = typeof data.solo_zmq_enabled === 'boolean'
    ? data.solo_zmq_enabled
    : (typeof soloZmq.enabled === 'boolean' ? soloZmq.enabled : false);
  const connected = typeof data.solo_zmq_connected === 'boolean'
    ? data.solo_zmq_connected
    : (typeof soloZmq.connected === 'boolean' ? soloZmq.connected : false);

  const eventsRaw = data.solo_zmq_events_total ?? soloZmq.events_total;
  const eventsTotal = Number.isFinite(Number(eventsRaw)) ? Number(eventsRaw) : null;

  const lastEventRaw = data.solo_zmq_last_event_timestamp ?? soloZmq.last_event_timestamp;
  const lastEventTimestamp = Number.isFinite(Number(lastEventRaw)) ? Number(lastEventRaw) : null;

  const lastTopicRaw = data.solo_zmq_last_topic ?? soloZmq.last_topic;
  const lastTopic = typeof lastTopicRaw === 'string' && lastTopicRaw ? lastTopicRaw : null;

  const recentRaw = Array.isArray(soloZmq.recent)
    ? soloZmq.recent
    : (Array.isArray(data.solo_zmq_recent) ? data.solo_zmq_recent : []);

  return {
    enabled: Boolean(enabled),
    connected: Boolean(connected),
    eventsTotal,
    lastEventTimestamp,
    lastTopic,
    recent: recentRaw,
  };
}

function formatZmqTopic(topic) {
  if (!topic) return null;
  const parts = String(topic).split('-');
  const last = parts[parts.length - 1];
  if (!last) return topic;
  return last
    .split('_')
    .map((part) => part ? part[0].toUpperCase() + part.slice(1) : '')
    .join(' ')
    .trim();
}

function buildModeInfo(rawMode, normalizedMode, zmq, stats) {
  if (normalizedMode === 'pool') {
    const poolFromTop = stats && typeof stats.pool === 'string' && stats.pool ? stats.pool : null;
    const poolFromConfig = stats && stats.config && stats.config.values && stats.config.values.pool ? stats.config.values.pool : null;
    const pool = poolFromTop || poolFromConfig || null;
    const connected = Boolean(stats && typeof stats.connected === 'boolean' ? stats.connected : false);
    return {
      title: 'Pool mining',
      subtitle: `Mining on ${pool || '-'}; ${connected ? 'Connected' : 'Disconnected'}.`,
      shortLabel: 'Pool',
    };
  }

  if (normalizedMode === 'solo') {
    if (zmq.enabled) {
      const status = zmq.connected
        ? 'ZMQ connected; See ZMQ Feed below.'
        : 'ZMQ enabled; waiting for events.';
      return {
        title: 'Solo mining (ZMQ)',
        subtitle: status,
        shortLabel: 'Solo (ZMQ)',
      };
    }
    return {
      title: 'Solo mining (polling)',
      subtitle: 'Using polling mode for solo mining stats.',
      shortLabel: 'Solo (polling)',
    };
  }

  const raw = typeof rawMode === 'string' && rawMode ? rawMode : 'Unknown';
  const pretty = raw.charAt(0).toUpperCase() + raw.slice(1);
  return {
    title: `Mode: ${pretty}`,
    subtitle: '',
    shortLabel: pretty,
  };
}

function updateModeBanner(modeInfo) {
  if (modeBannerTitleEl) {
    modeBannerTitleEl.textContent = modeInfo.title;
  }
  if (modeBannerSubtitleEl) {
    if (modeInfo.subtitle) {
      modeBannerSubtitleEl.textContent = modeInfo.subtitle;
      modeBannerSubtitleEl.hidden = false;
    } else {
      modeBannerSubtitleEl.textContent = '';
      modeBannerSubtitleEl.hidden = true;
    }
  }
}

function updateCardVisibility(mode, zmqEnabled) {
  const normalized = mode === 'pool' || mode === 'solo' ? mode : null;
  cardElements.forEach((card) => {
    let visible = true;
    const modeAttr = card.getAttribute('data-mode');
    if (modeAttr) {
      if (!normalized) {
        visible = true;
      } else {
        const allowed = modeAttr
          .split(',')
          .map((entry) => entry.trim().toLowerCase())
          .filter(Boolean);
        visible = allowed.includes(normalized);
      }
    }

    const requires = card.getAttribute('data-requires');
    if (visible && requires) {
      if (requires === 'zmq') {
        visible = Boolean(zmqEnabled);
      }
    }

    card.hidden = !visible;
  });
}

function updateZmqCards(zmq) {
  const connectedEl = document.getElementById('zmq_connected');
  if (connectedEl) {
    connectedEl.textContent = zmq.connected ? 'Yes' : 'No';
  }

  const eventsEl = document.getElementById('zmq_events');
  if (eventsEl) {
    eventsEl.textContent = zmq.eventsTotal !== null ? intFmt.format(zmq.eventsTotal) : '-';
  }

  const lastEventEl = document.getElementById('zmq_last_event');
  if (lastEventEl) {
    const parts = [];
    const topicLabel = formatZmqTopic(zmq.lastTopic);
    if (topicLabel) {
      parts.push(topicLabel);
    }
    const when = formatUnixTimestamp(zmq.lastEventTimestamp);
    if (when) {
      parts.push(when);
    }
    lastEventEl.textContent = parts.length > 0 ? parts.join(' - ') : '-';
  }
}

function applyStats(data) {
  const modeNormalized = normalizeMode(data.mode);
  const zmq = readZmqState(data);
  const rawMode = typeof data.mode === 'string' ? data.mode : (data.config && data.config.values && data.config.values.mode) || null;
  const modeInfo = buildModeInfo(rawMode, modeNormalized, zmq, data);
  updateModeBanner(modeInfo);
  updateCardVisibility(modeNormalized, zmq.enabled);

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
    modeEl.textContent = modeInfo.shortLabel || '-';
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

  updateZmqCards(zmq);
  updateZmqTerminal(zmq);
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
