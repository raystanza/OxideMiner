const STORAGE_THEME_KEY = 'perf_viz.theme.v1';
const STORAGE_LAYOUTS_KEY = 'perf_viz.layouts.v1';
const STORAGE_SESSION_KEY = 'perf_viz.session.v1';

const THEME_PRESETS = {
  Nebula: {
    '--bg0': '#0d1118',
    '--bg1': '#131a25',
    '--bg2': '#1a2333',
    '--txt': '#e7edf7',
    '--muted': '#9fb0c8',
    '--accent': '#4cb7ff',
    '--accent2': '#ffb454',
    '--good': '#4ec9a2',
    '--bad': '#ff7a8a',
    '--card': '#111a27cc',
    '--card-solid': '#111a27',
    '--border': '#2d3f59',
    '--surface': '#0c131f',
    '--surface-border': '#26334a',
    '--input-bg': '#0f1622',
    '--input-border': '#2a3b56',
    '--btn-grad-a': '#2f75bb',
    '--btn-grad-b': '#21496f',
    '--btn-border': '#3e7ab4',
    '--btn2-grad-a': '#5a5f7a',
    '--btn2-grad-b': '#393d52',
    '--btn2-border': '#70789d',
  },
  Slate: {
    '--bg0': '#0f1115',
    '--bg1': '#171b22',
    '--bg2': '#242a34',
    '--txt': '#eef2f8',
    '--muted': '#adb8cb',
    '--accent': '#88b4ff',
    '--accent2': '#ffd27c',
    '--good': '#58d1bb',
    '--bad': '#ff8ea1',
    '--card': '#171d26cc',
    '--card-solid': '#171d26',
    '--border': '#3a4658',
    '--surface': '#111721',
    '--surface-border': '#2b3546',
    '--input-bg': '#101723',
    '--input-border': '#38465c',
    '--btn-grad-a': '#5d7fa8',
    '--btn-grad-b': '#395675',
    '--btn-border': '#7595bb',
    '--btn2-grad-a': '#6a6c7f',
    '--btn2-grad-b': '#4a4c5a',
    '--btn2-border': '#888aa1',
  },
  Ember: {
    '--bg0': '#170f0b',
    '--bg1': '#22160f',
    '--bg2': '#302018',
    '--txt': '#fff2e7',
    '--muted': '#d6b8a2',
    '--accent': '#ff9d5c',
    '--accent2': '#ffd37a',
    '--good': '#4fd0a8',
    '--bad': '#ff798e',
    '--card': '#26170fcc',
    '--card-solid': '#26170f',
    '--border': '#5a3c2a',
    '--surface': '#1d130e',
    '--surface-border': '#4a2d20',
    '--input-bg': '#21140e',
    '--input-border': '#66422f',
    '--btn-grad-a': '#d6743d',
    '--btn-grad-b': '#8e4a27',
    '--btn-border': '#e08c52',
    '--btn2-grad-a': '#8a5a48',
    '--btn2-grad-b': '#623f33',
    '--btn2-border': '#a8725b',
  },
  Aurora: {
    '--bg0': '#081414',
    '--bg1': '#0d1f1d',
    '--bg2': '#153432',
    '--txt': '#e9fffd',
    '--muted': '#a7d4cd',
    '--accent': '#4cf0d3',
    '--accent2': '#9af093',
    '--good': '#65e6b5',
    '--bad': '#ff8ca6',
    '--card': '#0e2421cc',
    '--card-solid': '#0e2421',
    '--border': '#2a5952',
    '--surface': '#0a1b1a',
    '--surface-border': '#244a46',
    '--input-bg': '#0d1c1b',
    '--input-border': '#2f605a',
    '--btn-grad-a': '#2eb89f',
    '--btn-grad-b': '#1d7668',
    '--btn-border': '#4ed2bb',
    '--btn2-grad-a': '#4e756f',
    '--btn2-grad-b': '#35514d',
    '--btn2-border': '#6d9891',
  },
};

let options = null;
let lastPrefetch = null;
let lastCorr = null;
let lastMatrix = null;
let lastAtlas = null;
let activeTab = 'prefetch';
let selectedAnomalyId = null;

const DEFAULT_LAYOUTS = {
  'Prefetch Explorer - Stability Sweep': {
    version: 2,
    activeTab: 'prefetch',
    theme: 'Slate',
    prefetch: { host: 'All', scenario: 'All', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'perf',
      xMetric: 'prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'mode',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '8000',
      maxMetrics: '18',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '120',
      maxTimeline: '180',
    },
  },
  'Prefetch Explorer - Intel Focus': {
    version: 2,
    activeTab: 'prefetch',
    theme: 'Nebula',
    prefetch: { host: 'Intel', scenario: 'All', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'effective_prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'scenario',
      host: 'Intel',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '7000',
      maxMetrics: '16',
    },
    atlas: {
      host: 'Intel',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '140',
      maxTimeline: '180',
    },
  },
  'Prefetch Explorer - AMD JIT Off': {
    version: 2,
    activeTab: 'prefetch',
    theme: 'Ember',
    prefetch: { host: 'AMD', scenario: 'All', mode: 'All', jit: 'off', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'effective_prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'setting_kind',
      host: 'AMD',
      mode: 'All',
      jit: 'off',
      scenario: 'All',
      maxPoints: '9000',
      maxMetrics: '18',
    },
    atlas: {
      host: 'AMD',
      mode: 'All',
      jit: 'off',
      scenario: 'All',
      maxAnomalies: '180',
      maxTimeline: '220',
    },
  },
  'Prefetch Explorer - Light Scenario': {
    version: 2,
    activeTab: 'prefetch',
    theme: 'Slate',
    prefetch: { host: 'All', scenario: 'light_jit_off', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'effective_prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'scenario',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'light_jit_off',
      maxPoints: '8000',
      maxMetrics: '16',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'light_jit_off',
      maxAnomalies: '120',
      maxTimeline: '180',
    },
  },
  'Prefetch Explorer - Portable Sweep': {
    version: 2,
    activeTab: 'prefetch',
    theme: 'Nebula',
    prefetch: { host: 'All', scenario: 'All', mode: 'Portable', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'perf',
      xMetric: 'prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'host',
      host: 'All',
      mode: 'Portable',
      jit: 'All',
      scenario: 'All',
      maxPoints: '7000',
      maxMetrics: '18',
    },
    atlas: {
      host: 'All',
      mode: 'Portable',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '140',
      maxTimeline: '180',
    },
  },
  'Correlation Studio - Perf Drivers': {
    version: 2,
    activeTab: 'corr',
    theme: 'Nebula',
    prefetch: { host: 'All', scenario: 'All', mode: 'All', jit: 'All', onlyNs: false },
    correlation: {
      dataset: 'perf',
      xMetric: 'prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'mode',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '8000',
      maxMetrics: '20',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '120',
      maxTimeline: '180',
    },
  },
  'Correlation Studio - Manifest Distance': {
    version: 2,
    activeTab: 'corr',
    theme: 'Aurora',
    prefetch: { host: 'All', scenario: 'All', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'effective_prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'scenario',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '8000',
      maxMetrics: '24',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '120',
      maxTimeline: '180',
    },
  },
  'Correlation Studio - JIT Contrast': {
    version: 2,
    activeTab: 'corr',
    theme: 'Aurora',
    prefetch: { host: 'All', scenario: 'All', mode: 'All', jit: 'All', onlyNs: false },
    correlation: {
      dataset: 'perf',
      xMetric: 'jit_compile_ns_total',
      yMetric: 'ns_per_hash',
      colorBy: 'jit',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '10000',
      maxMetrics: '24',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '140',
      maxTimeline: '240',
    },
  },
  'Correlation Studio - Host Buckets': {
    version: 2,
    activeTab: 'corr',
    theme: 'Slate',
    prefetch: { host: 'All', scenario: 'All', mode: 'All', jit: 'All', onlyNs: false },
    correlation: {
      dataset: 'perf',
      xMetric: 'hashes_per_sec',
      yMetric: 'ns_per_hash',
      colorBy: 'host',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '12000',
      maxMetrics: '22',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '150',
      maxTimeline: '220',
    },
  },
  'Correlation Studio - Manifest Drift Lens': {
    version: 2,
    activeTab: 'corr',
    theme: 'Ember',
    prefetch: { host: 'All', scenario: 'All', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'run_index',
      yMetric: 'ns_per_hash',
      colorBy: 'setting_kind',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '9000',
      maxMetrics: '18',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '160',
      maxTimeline: '240',
    },
  },
  'Analytics Atlas - Quality Audit': {
    version: 2,
    activeTab: 'atlas',
    theme: 'Slate',
    prefetch: { host: 'All', scenario: 'All', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'perf',
      xMetric: 'prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'host',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '6000',
      maxMetrics: '18',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '160',
      maxTimeline: '220',
    },
  },
  'Analytics Atlas - Drift Sentinel': {
    version: 2,
    activeTab: 'atlas',
    theme: 'Aurora',
    prefetch: { host: 'All', scenario: 'All', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'run_index',
      yMetric: 'ns_per_hash',
      colorBy: 'setting_kind',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxPoints: '7000',
      maxMetrics: '20',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '220',
      maxTimeline: '300',
    },
  },
  'Analytics Atlas - Intel Portable': {
    version: 2,
    activeTab: 'atlas',
    theme: 'Nebula',
    prefetch: { host: 'Intel', scenario: 'All', mode: 'Portable', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'effective_prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'scenario',
      host: 'Intel',
      mode: 'Portable',
      jit: 'All',
      scenario: 'All',
      maxPoints: '7000',
      maxMetrics: '20',
    },
    atlas: {
      host: 'Intel',
      mode: 'Portable',
      jit: 'All',
      scenario: 'All',
      maxAnomalies: '200',
      maxTimeline: '260',
    },
  },
  'Analytics Atlas - AMD JIT Off Audit': {
    version: 2,
    activeTab: 'atlas',
    theme: 'Ember',
    prefetch: { host: 'AMD', scenario: 'All', mode: 'All', jit: 'off', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'effective_prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'setting_kind',
      host: 'AMD',
      mode: 'All',
      jit: 'off',
      scenario: 'All',
      maxPoints: '8000',
      maxMetrics: '20',
    },
    atlas: {
      host: 'AMD',
      mode: 'All',
      jit: 'off',
      scenario: 'All',
      maxAnomalies: '240',
      maxTimeline: '280',
    },
  },
  'Analytics Atlas - Light Scenario Focus': {
    version: 2,
    activeTab: 'atlas',
    theme: 'Aurora',
    prefetch: { host: 'All', scenario: 'light_jit_off', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'effective_prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'setting_kind',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'light_jit_off',
      maxPoints: '7000',
      maxMetrics: '18',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'light_jit_off',
      maxAnomalies: '160',
      maxTimeline: '220',
    },
  },
  'Analytics Atlas - Fast Scenario Focus': {
    version: 2,
    activeTab: 'atlas',
    theme: 'Slate',
    prefetch: { host: 'All', scenario: 'fast_jit_conservative', mode: 'All', jit: 'All', onlyNs: true },
    correlation: {
      dataset: 'manifest',
      xMetric: 'effective_prefetch_distance',
      yMetric: 'ns_per_hash',
      colorBy: 'scenario',
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'fast_jit_conservative',
      maxPoints: '7000',
      maxMetrics: '18',
    },
    atlas: {
      host: 'All',
      mode: 'All',
      jit: 'All',
      scenario: 'fast_jit_conservative',
      maxAnomalies: '160',
      maxTimeline: '220',
    },
  },
};

function q(id) {
  return document.getElementById(id);
}

function fmt(v, digits = 5) {
  return v === null || v === undefined || Number.isNaN(v) ? '-' : Number(v).toFixed(digits);
}

function allOrValue(v) {
  return v && v !== 'All' ? v : '';
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function setLayoutMessage(message) {
  q('layoutMsg').textContent = message || '';
}

function setExportMessage(message) {
  q('exportMsg').textContent = message || '';
}

function setAtlasMessage(message) {
  q('atlasMsg').textContent = message || '';
}

function safeJsonParse(raw, fallback) {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch (_err) {
    return fallback;
  }
}

function csvEscape(v) {
  const s = String(v ?? '');
  if (/[",\n]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function fetchJson(url) {
  return fetch(url).then((res) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  });
}

function fillSelect(id, values, selected) {
  const el = q(id);
  if (!el) return;
  const curr = selected ?? el.value;
  el.innerHTML = '';
  (values || []).forEach((v) => {
    const option = document.createElement('option');
    option.value = v;
    option.textContent = v;
    el.appendChild(option);
  });
  if ([...el.options].some((o) => o.value === curr)) {
    el.value = curr;
  }
}

function setSelectIfPossible(id, value) {
  if (value === undefined || value === null) return;
  const el = q(id);
  if (!el) return;
  const wanted = String(value);
  const exact = [...el.options].find((o) => o.value === wanted);
  if (exact) {
    el.value = exact.value;
    return;
  }
  const ci = [...el.options].find(
    (o) => o.value.toLowerCase() === wanted.toLowerCase(),
  );
  if (ci) {
    el.value = ci.value;
  }
}

function valuesUnionWithAll(...lists) {
  const map = new Map();
  for (const list of lists) {
    for (const value of list || []) {
      if (!value || value === 'All') continue;
      const normalized = String(value).trim().toLowerCase();
      if (!normalized) continue;
      if (!map.has(normalized)) {
        if (normalized === 'intel') {
          map.set(normalized, 'Intel');
        } else if (normalized === 'amd') {
          map.set(normalized, 'AMD');
        } else {
          map.set(normalized, normalized);
        }
      }
    }
  }
  return ['All', ...[...map.values()].sort((a, b) => a.localeCompare(b))];
}

function renderStatCards(containerId, rows) {
  const el = q(containerId);
  if (!el) return;
  el.innerHTML = rows
    .map(
      ([k, v]) => `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div></div>`,
    )
    .join('');
}

function currentDataset() {
  return q('corrDataset').value || 'perf';
}

function plotLayoutBase(extra = {}) {
  return {
    paper_bgcolor: cssVar('--surface'),
    plot_bgcolor: cssVar('--surface'),
    font: { color: cssVar('--txt') },
    margin: { l: 58, r: 24, t: 38, b: 56 },
    legend: { orientation: 'h' },
    ...extra,
  };
}

function activateTab(tab) {
  if (!['prefetch', 'corr', 'atlas'].includes(tab)) {
    activeTab = 'prefetch';
  } else {
    activeTab = tab;
  }

  const prefetchActive = activeTab === 'prefetch';
  const corrActive = activeTab === 'corr';
  const atlasActive = activeTab === 'atlas';

  q('prefetchSection').classList.toggle('hidden', !prefetchActive);
  q('prefetchControls').classList.toggle('hidden', !prefetchActive);

  q('corrSection').classList.toggle('hidden', !corrActive);
  q('corrControls').classList.toggle('hidden', !corrActive);

  q('atlasSection').classList.toggle('hidden', !atlasActive);
  q('atlasControls').classList.toggle('hidden', !atlasActive);

  q('tabPrefetch').classList.toggle('active', prefetchActive);
  q('tabCorr').classList.toggle('active', corrActive);
  q('tabAtlas').classList.toggle('active', atlasActive);
}

function populateThemeSelector() {
  fillSelect('themePreset', Object.keys(THEME_PRESETS), q('themePreset').value || 'Nebula');
}

function applyTheme(themeName, opts = {}) {
  const { persist = true, rerender = true, storeSession = true } = opts;
  const resolved = THEME_PRESETS[themeName] ? themeName : 'Nebula';
  const preset = THEME_PRESETS[resolved];
  const root = document.documentElement;
  Object.entries(preset).forEach(([key, value]) => root.style.setProperty(key, value));
  q('themePreset').value = resolved;

  if (persist) localStorage.setItem(STORAGE_THEME_KEY, resolved);
  if (rerender) rerenderCachedCharts();
  if (storeSession) saveSessionState();
}

function readLayoutsStore() {
  return safeJsonParse(localStorage.getItem(STORAGE_LAYOUTS_KEY), {});
}

function writeLayoutsStore(store) {
  localStorage.setItem(STORAGE_LAYOUTS_KEY, JSON.stringify(store));
}

function layoutCatalog() {
  const custom = readLayoutsStore();
  const catalog = {};
  Object.entries(DEFAULT_LAYOUTS).forEach(([name, state]) => {
    catalog[name] = { builtin: true, state };
  });
  Object.entries(custom).forEach(([name, item]) => {
    if (item && item.state) {
      catalog[name] = { builtin: false, state: item.state, savedAt: item.savedAt || null };
    }
  });
  return catalog;
}

function isBuiltinLayout(name) {
  return Object.prototype.hasOwnProperty.call(DEFAULT_LAYOUTS, name);
}

function refreshLayoutList(selectedName = '') {
  const catalog = layoutCatalog();
  const names = Object.keys(catalog).sort((a, b) => {
    const aBuiltin = catalog[a].builtin ? 0 : 1;
    const bBuiltin = catalog[b].builtin ? 0 : 1;
    return aBuiltin - bBuiltin || a.localeCompare(b);
  });
  fillSelect('layoutSelect', ['(none)', ...names], selectedName || q('layoutSelect').value || '(none)');
}

function captureLayoutState() {
  return {
    version: 2,
    activeTab,
    theme: q('themePreset').value || 'Nebula',
    prefetch: {
      host: q('pfHost').value,
      scenario: q('pfScenario').value,
      mode: q('pfMode').value,
      jit: q('pfJit').value,
      onlyNs: q('pfOnlyNs').checked,
    },
    correlation: {
      dataset: q('corrDataset').value,
      xMetric: q('corrX').value,
      yMetric: q('corrY').value,
      colorBy: q('corrColor').value,
      host: q('corrHost').value,
      mode: q('corrMode').value,
      jit: q('corrJit').value,
      scenario: q('corrScenario').value,
      maxPoints: q('corrMaxPoints').value,
      maxMetrics: q('corrMaxMetrics').value,
    },
    atlas: {
      host: q('atlasHost').value,
      mode: q('atlasMode').value,
      jit: q('atlasJit').value,
      scenario: q('atlasScenario').value,
      maxAnomalies: q('atlasMaxAnomalies').value,
      maxTimeline: q('atlasMaxTimeline').value,
    },
  };
}

async function applyLayoutState(layout, opts = {}) {
  const { refresh = true, storeSession = false, applyLayoutTheme = false } = opts;
  if (!layout || typeof layout !== 'object') return;

  if (layout.theme && applyLayoutTheme) {
    applyTheme(layout.theme, { persist: true, rerender: false, storeSession: false });
  }

  if (layout.prefetch) {
    setSelectIfPossible('pfHost', layout.prefetch.host);
    setSelectIfPossible('pfScenario', layout.prefetch.scenario);
    setSelectIfPossible('pfMode', layout.prefetch.mode);
    setSelectIfPossible('pfJit', layout.prefetch.jit);
    q('pfOnlyNs').checked = !!layout.prefetch.onlyNs;
  }

  if (layout.correlation) {
    setSelectIfPossible('corrDataset', layout.correlation.dataset || 'perf');
    syncCorrSelectorsByDataset();
    setSelectIfPossible('corrX', layout.correlation.xMetric);
    setSelectIfPossible('corrY', layout.correlation.yMetric);
    setSelectIfPossible('corrColor', layout.correlation.colorBy);
    setSelectIfPossible('corrHost', layout.correlation.host);
    setSelectIfPossible('corrMode', layout.correlation.mode);
    setSelectIfPossible('corrJit', layout.correlation.jit);
    setSelectIfPossible('corrScenario', layout.correlation.scenario);
    if (layout.correlation.maxPoints) q('corrMaxPoints').value = layout.correlation.maxPoints;
    if (layout.correlation.maxMetrics) q('corrMaxMetrics').value = layout.correlation.maxMetrics;
  }

  if (layout.atlas) {
    setSelectIfPossible('atlasHost', layout.atlas.host);
    setSelectIfPossible('atlasMode', layout.atlas.mode);
    setSelectIfPossible('atlasJit', layout.atlas.jit);
    setSelectIfPossible('atlasScenario', layout.atlas.scenario);
    if (layout.atlas.maxAnomalies) q('atlasMaxAnomalies').value = layout.atlas.maxAnomalies;
    if (layout.atlas.maxTimeline) q('atlasMaxTimeline').value = layout.atlas.maxTimeline;
  }

  activateTab(layout.activeTab || 'prefetch');

  if (refresh) {
    await refreshPrefetch();
    await refreshCorrelation();
    await refreshAtlas();
  }

  if (storeSession) {
    saveSessionState();
  }
}

function saveSessionState() {
  localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(captureLayoutState()));
}

async function restoreSessionState() {
  const session = safeJsonParse(localStorage.getItem(STORAGE_SESSION_KEY), null);
  if (!session) return;
  await applyLayoutState(session, { refresh: false, storeSession: false, applyLayoutTheme: false });
}

function saveNamedLayout() {
  const name = (q('layoutName').value || '').trim();
  if (!name) {
    setLayoutMessage('Layout name is required.');
    return;
  }
  if (isBuiltinLayout(name)) {
    setLayoutMessage(`Layout '${name}' is a built-in default. Use a different name to save a custom variant.`);
    return;
  }
  const store = readLayoutsStore();
  store[name] = { savedAt: new Date().toISOString(), state: captureLayoutState() };
  writeLayoutsStore(store);
  refreshLayoutList(name);
  q('layoutSelect').value = name;
  setLayoutMessage(`Saved layout '${name}'.`);
  saveSessionState();
}

async function loadSelectedLayout() {
  const name = q('layoutSelect').value;
  if (!name || name === '(none)') {
    setLayoutMessage('Select a layout to load.');
    return;
  }
  const catalog = layoutCatalog();
  const item = catalog[name];
  if (!item || !item.state) {
    setLayoutMessage(`Layout '${name}' was not found.`);
    return;
  }
  q('layoutName').value = name;
  await applyLayoutState(item.state, { refresh: true, storeSession: true, applyLayoutTheme: false });
  setLayoutMessage(
    item.builtin
      ? `Loaded built-in layout '${name}'. Theme kept as '${q('themePreset').value}'.`
      : `Loaded custom layout '${name}'. Theme kept as '${q('themePreset').value}'.`,
  );
}

function deleteSelectedLayout() {
  const name = q('layoutSelect').value;
  if (!name || name === '(none)') {
    setLayoutMessage('Select a layout to delete.');
    return;
  }
  if (isBuiltinLayout(name)) {
    setLayoutMessage(`Built-in layout '${name}' cannot be deleted.`);
    return;
  }
  const store = readLayoutsStore();
  if (!store[name]) {
    setLayoutMessage(`Layout '${name}' was not found.`);
    return;
  }
  delete store[name];
  writeLayoutsStore(store);
  refreshLayoutList('(none)');
  setLayoutMessage(`Deleted layout '${name}'.`);
}

function syncCorrSelectorsByDataset() {
  const ds = currentDataset();
  if (ds === 'manifest') {
    fillSelect('corrX', options.manifest_metrics, q('corrX').value || 'effective_prefetch_distance');
    fillSelect('corrY', options.manifest_metrics, q('corrY').value || 'ns_per_hash');
    fillSelect('corrColor', options.color_options_manifest, q('corrColor').value || 'scenario');
    fillSelect('corrHost', options.hosts_manifest, q('corrHost').value || 'All');
    fillSelect('corrMode', options.modes_manifest, q('corrMode').value || 'All');
    fillSelect('corrJit', options.jits_manifest, q('corrJit').value || 'All');
    fillSelect('corrScenario', options.scenarios_manifest, q('corrScenario').value || 'All');
    q('corrScenarioWrap').classList.remove('hidden');
  } else {
    fillSelect('corrX', options.perf_metrics, q('corrX').value || 'prefetch_distance');
    fillSelect('corrY', options.perf_metrics, q('corrY').value || 'ns_per_hash');
    fillSelect('corrColor', options.color_options_perf, q('corrColor').value || 'mode');
    fillSelect('corrHost', options.hosts_perf, q('corrHost').value || 'All');
    fillSelect('corrMode', options.modes_perf, q('corrMode').value || 'All');
    fillSelect('corrJit', options.jits_perf, q('corrJit').value || 'All');
    fillSelect('corrScenario', ['All'], 'All');
    q('corrScenarioWrap').classList.add('hidden');
  }
}

function syncAtlasSelectors() {
  fillSelect('atlasHost', valuesUnionWithAll(options.hosts_manifest, options.hosts_perf), q('atlasHost').value || 'All');
  fillSelect('atlasMode', valuesUnionWithAll(options.modes_manifest, options.modes_perf), q('atlasMode').value || 'All');
  fillSelect('atlasJit', valuesUnionWithAll(options.jits_manifest, options.jits_perf), q('atlasJit').value || 'All');
  fillSelect('atlasScenario', valuesUnionWithAll(options.scenarios_manifest), q('atlasScenario').value || 'All');
}

async function refreshPrefetch() {
  const params = new URLSearchParams({
    host: allOrValue(q('pfHost').value),
    scenario: allOrValue(q('pfScenario').value),
    mode: allOrValue(q('pfMode').value),
    jit: allOrValue(q('pfJit').value),
    only_with_ns_per_hash: q('pfOnlyNs').checked ? 'true' : 'false',
  });
  const data = await fetchJson(`/api/prefetch?${params.toString()}`);
  lastPrefetch = data;
  renderPrefetch(data);
  saveSessionState();
}

function renderPrefetch(data) {
  renderStatCards('prefetchStats', [
    ['Rows', data.stats.count],
    ['Min ns/hash', fmt(data.stats.min)],
    ['Median ns/hash', fmt(data.stats.median)],
    ['Mean ns/hash', fmt(data.stats.mean)],
    ['Max ns/hash', fmt(data.stats.max)],
  ]);

  Plotly.react(
    'pfScatter',
    [
      {
        x: data.fixed_points.map((p) => p[0]),
        y: data.fixed_points.map((p) => p[1]),
        mode: 'markers',
        type: 'scatter',
        name: 'fixed',
        marker: { size: 6, color: '#56a7ff' },
      },
      {
        x: data.auto_points.map((p) => p[0]),
        y: data.auto_points.map((p) => p[1]),
        mode: 'markers',
        type: 'scatter',
        name: 'auto',
        marker: { size: 7, color: '#ffa955' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Distance vs ns_per_hash' },
      xaxis: { title: 'distance' },
      yaxis: { title: 'ns_per_hash' },
    }),
    { responsive: true },
  );

  Plotly.react(
    'pfDrift',
    [
      {
        type: 'bar',
        x: data.drift.map((d) => d.label),
        y: data.drift.map((d) => d.drift_pct),
        marker: { color: data.drift.map((d) => (d.drift_pct >= 0 ? '#ff8a9a' : '#57cfa0')) },
      },
    ],
    plotLayoutBase({
      title: { text: 'Run-order Drift by Setting (%)' },
      xaxis: { title: 'setting', tickangle: -20, automargin: true },
      yaxis: { title: 'drift %' },
    }),
    { responsive: true },
  );

  Plotly.react(
    'pfHeatmap',
    [
      {
        type: 'heatmap',
        x: data.heatmap.x_distances,
        y: data.heatmap.y_scenarios,
        z: data.heatmap.z_values,
        colorscale: 'Turbo',
        colorbar: { title: 'mean ns/hash' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Scenario x Distance Heatmap (mean ns_per_hash)' },
      xaxis: { title: 'distance' },
      yaxis: { title: 'scenario', automargin: true },
    }),
    { responsive: true },
  );
}

async function refreshCorrelation() {
  const params = new URLSearchParams({
    dataset: currentDataset(),
    x_metric: q('corrX').value,
    y_metric: q('corrY').value,
    color_by: q('corrColor').value,
    host: allOrValue(q('corrHost').value),
    mode: allOrValue(q('corrMode').value),
    jit: allOrValue(q('corrJit').value),
    scenario: allOrValue(q('corrScenario').value),
    max_points: String(q('corrMaxPoints').value || 8000),
  });
  const data = await fetchJson(`/api/correlation?${params.toString()}`);
  lastCorr = data;

  const matrixParams = new URLSearchParams({
    dataset: currentDataset(),
    host: allOrValue(q('corrHost').value),
    mode: allOrValue(q('corrMode').value),
    jit: allOrValue(q('corrJit').value),
    scenario: allOrValue(q('corrScenario').value),
    max_metrics: String(q('corrMaxMetrics').value || 18),
    coverage_sort: 'true',
  });
  const matrix = await fetchJson(`/api/matrix?${matrixParams.toString()}`);
  lastMatrix = matrix;

  renderCorrelation(data, matrix);
  saveSessionState();
}

function renderCorrelation(data, matrix) {
  renderStatCards('corrStats', [
    ['Pairs', data.points.length],
    ['Pearson r', fmt(data.pearson_r)],
    ['R²', fmt(data.r_squared)],
    ['Slope', fmt(data.regression?.slope)],
    ['Intercept', fmt(data.regression?.intercept)],
  ]);

  const grouped = {};
  for (const p of data.points) {
    if (!grouped[p.color]) grouped[p.color] = { x: [], y: [] };
    grouped[p.color].x.push(p.x);
    grouped[p.color].y.push(p.y);
  }

  const scatterTraces = Object.entries(grouped).map(([k, v]) => ({
    type: 'scatter',
    mode: 'markers',
    name: k,
    x: v.x,
    y: v.y,
    marker: { size: 5, opacity: 0.82 },
  }));

  if (data.regression && data.points.length > 1) {
    const xs = data.points.map((p) => p.x);
    const xmin = Math.min(...xs);
    const xmax = Math.max(...xs);
    scatterTraces.push({
      type: 'scatter',
      mode: 'lines',
      name: 'regression',
      x: [xmin, xmax],
      y: [
        data.regression.slope * xmin + data.regression.intercept,
        data.regression.slope * xmax + data.regression.intercept,
      ],
      line: { color: '#ff6e78', width: 2 },
    });
  }

  Plotly.react(
    'corrScatter',
    scatterTraces,
    plotLayoutBase({
      title: { text: `Scatter: ${data.y_metric} vs ${data.x_metric}` },
      xaxis: { title: data.x_metric },
      yaxis: { title: data.y_metric },
    }),
    { responsive: true },
  );

  Plotly.react(
    'corrDensity',
    [
      {
        type: 'histogram2d',
        x: data.points.map((p) => p.x),
        y: data.points.map((p) => p.y),
        colorscale: 'Viridis',
        nbinsx: 40,
        nbinsy: 40,
        colorbar: { title: 'count' },
      },
    ],
    plotLayoutBase({
      title: { text: `Density: ${data.y_metric} vs ${data.x_metric}` },
      xaxis: { title: data.x_metric },
      yaxis: { title: data.y_metric },
    }),
    { responsive: true },
  );

  Plotly.react(
    'corrHistX',
    [
      {
        type: 'histogram',
        x: data.points.map((p) => p.x),
        marker: { color: '#67aefc' },
        nbinsx: 50,
      },
    ],
    plotLayoutBase({
      title: { text: `Distribution: ${data.x_metric}` },
      xaxis: { title: data.x_metric },
      yaxis: { title: 'count' },
    }),
    { responsive: true },
  );

  Plotly.react(
    'corrHistY',
    [
      {
        type: 'histogram',
        x: data.points.map((p) => p.y),
        marker: { color: '#ffc069' },
        nbinsx: 50,
      },
    ],
    plotLayoutBase({
      title: { text: `Distribution: ${data.y_metric}` },
      xaxis: { title: data.y_metric },
      yaxis: { title: 'count' },
    }),
    { responsive: true },
  );

  Plotly.react(
    'corrGroupBars',
    [
      {
        type: 'bar',
        x: data.group_stats.map((g) => g.group),
        y: data.group_stats.map((g) => g.mean),
        marker: { color: '#6dd5b2' },
        error_y: { type: 'data', array: data.group_stats.map((g) => g.stddev), visible: true },
      },
    ],
    plotLayoutBase({
      title: { text: 'Group Mean ± StdDev (Y metric)' },
      xaxis: { title: 'group', tickangle: -20, automargin: true },
      yaxis: { title: data.y_metric },
    }),
    { responsive: true },
  );

  q('topCorrTable').innerHTML = data.top_correlations
    .slice(0, 30)
    .map((r) => `<tr><td>${r.metric}</td><td>${fmt(r.pearson_r)}</td><td>${r.pairs}</td></tr>`)
    .join('');

  Plotly.react(
    'corrMatrix',
    [
      {
        type: 'heatmap',
        x: matrix.metrics,
        y: matrix.metrics,
        z: matrix.r_values,
        zmin: -1,
        zmax: 1,
        zmid: 0,
        colorscale: 'RdBu',
        colorbar: { title: 'Pearson r' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Correlation Matrix (click cell to drill down)' },
      xaxis: { tickangle: -35, automargin: true },
      yaxis: { automargin: true },
    }),
    { responsive: true },
  );

  const matrixEl = q('corrMatrix');
  if (typeof matrixEl.removeAllListeners === 'function') matrixEl.removeAllListeners('plotly_click');
  matrixEl.on('plotly_click', (ev) => {
    const point = ev.points?.[0];
    if (!point) return;
    q('corrX').value = point.x;
    q('corrY').value = point.y;
    refreshCorrelation().catch((err) => {
      console.error(err);
      setExportMessage(`Correlation refresh failed: ${err}`);
    });
  });
}

function heatmapToZ(payload, key) {
  return (payload?.cells || []).map((row) => row.map((cell) => (cell ? cell[key] : null)));
}

async function refreshAtlas() {
  const params = new URLSearchParams({
    host: allOrValue(q('atlasHost').value),
    mode: allOrValue(q('atlasMode').value),
    jit: allOrValue(q('atlasJit').value),
    scenario: allOrValue(q('atlasScenario').value),
    max_anomalies: String(q('atlasMaxAnomalies').value || 120),
    max_timeline_points: String(q('atlasMaxTimeline').value || 180),
  });
  const data = await fetchJson(`/api/analytics?${params.toString()}`);
  lastAtlas = data;
  renderAtlas(data);
  saveSessionState();

  const activeFilters = [
    allOrValue(q('atlasHost').value) && `host=${q('atlasHost').value}`,
    allOrValue(q('atlasMode').value) && `mode=${q('atlasMode').value}`,
    allOrValue(q('atlasJit').value) && `jit=${q('atlasJit').value}`,
    allOrValue(q('atlasScenario').value) && `scenario=${q('atlasScenario').value}`,
  ]
    .filter(Boolean)
    .join(', ');
  setAtlasMessage(activeFilters ? `Atlas refreshed with: ${activeFilters}` : 'Atlas refreshed with global scope.');
}

function renderAtlas(data) {
  q('atlasScope').textContent = `Scope: ${data.scope}`;
  renderAtlasOverview(data.overview);
  renderAtlasCoverage(data.coverage);
  renderAtlasQuality(data.quality);
  renderAtlasStability(data.stability);
  renderAtlasBenchmark(data.host_benchmark);
  renderAtlasPareto(data.pareto);
  renderAtlasAnomalies(data.anomalies);
  renderAtlasTimeline(data.timeline);
}

function renderAtlasOverview(overview) {
  renderStatCards('atlasKpis', [
    ['Scope Perf Rows', overview.scope_perf_rows],
    ['Scope Manifest Rows', overview.scope_manifest_rows],
    ['Files', overview.total_files],
    ['Hosts', overview.total_hosts],
    ['Modes', overview.total_modes],
    ['JIT Values', overview.total_jits],
    ['Scenarios', overview.total_scenarios],
    ['Parse Errors', overview.parse_errors],
    ['Parse Error Rate %', fmt(overview.parse_error_rate_pct, 2)],
    ['Latest Delta', overview.latest_delta_pct === null ? '-' : `${fmt(overview.latest_delta_pct, 2)}%`],
  ]);

  q('atlasIngestHealth').innerHTML = (overview.ingest_health || [])
    .map((card) => `
      <div class="stat">
        <div class="k">${card.title}</div>
        <div class="v">${card.value}</div>
        <div class="muted">${card.detail}</div>
      </div>
    `)
    .join('');

  const snapshots = overview.snapshots || [];
  Plotly.react(
    'ovSnapshots',
    [
      {
        type: 'scatter',
        mode: 'lines+markers',
        name: 'perf rows',
        x: snapshots.map((s) => s.bucket),
        y: snapshots.map((s) => s.perf_rows),
        line: { color: '#67aefc', width: 2 },
      },
      {
        type: 'scatter',
        mode: 'lines+markers',
        name: 'manifest rows',
        x: snapshots.map((s) => s.bucket),
        y: snapshots.map((s) => s.manifest_rows),
        line: { color: '#ffbe6b', width: 2 },
      },
      {
        type: 'bar',
        name: 'files',
        x: snapshots.map((s) => s.bucket),
        y: snapshots.map((s) => s.files),
        marker: { color: '#6cd3b1', opacity: 0.45 },
        yaxis: 'y2',
      },
    ],
    plotLayoutBase({
      title: { text: `Snapshot Deltas (${overview.latest_delta_label})` },
      xaxis: { title: 'date bucket', tickangle: -25, automargin: true },
      yaxis: { title: 'rows' },
      yaxis2: { title: 'files', overlaying: 'y', side: 'right' },
      barmode: 'overlay',
    }),
    { responsive: true },
  );

  const schemaTotals = overview.schema_totals || [];
  Plotly.react(
    'ovSchemaTotals',
    [
      {
        type: 'bar',
        orientation: 'h',
        y: schemaTotals.map((r) => r.name).reverse(),
        x: schemaTotals.map((r) => r.count).reverse(),
        marker: { color: '#9e8cff' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Schema Distribution (Top)' },
      xaxis: { title: 'file count' },
      yaxis: { title: 'schema', automargin: true },
    }),
    { responsive: true },
  );
}

function renderAtlasCoverage(coverage) {
  Plotly.react(
    'covHostMode',
    [
      {
        type: 'heatmap',
        x: coverage.host_mode.x_labels,
        y: coverage.host_mode.y_labels,
        z: heatmapToZ(coverage.host_mode, 'value'),
        colorscale: 'Viridis',
        colorbar: { title: 'count' },
      },
    ],
    plotLayoutBase({ title: { text: 'Host x Mode Coverage Count' }, xaxis: { title: 'mode' }, yaxis: { title: 'host' } }),
    { responsive: true },
  );

  Plotly.react(
    'covHostModeMissing',
    [
      {
        type: 'heatmap',
        x: coverage.host_mode.x_labels,
        y: coverage.host_mode.y_labels,
        z: heatmapToZ(coverage.host_mode, 'missing_pct'),
        colorscale: 'RdYlBu',
        reversescale: true,
        colorbar: { title: 'missing %' },
      },
    ],
    plotLayoutBase({ title: { text: 'Host x Mode Missingness Overlay (ns/hash)' }, xaxis: { title: 'mode' }, yaxis: { title: 'host' } }),
    { responsive: true },
  );

  Plotly.react(
    'covHostJit',
    [
      {
        type: 'heatmap',
        x: coverage.host_jit.x_labels,
        y: coverage.host_jit.y_labels,
        z: heatmapToZ(coverage.host_jit, 'value'),
        colorscale: 'Portland',
        colorbar: { title: 'count' },
      },
    ],
    plotLayoutBase({ title: { text: 'Host x JIT Coverage Count' }, xaxis: { title: 'jit' }, yaxis: { title: 'host' } }),
    { responsive: true },
  );

  Plotly.react(
    'covScenarioDistance',
    [
      {
        type: 'heatmap',
        x: coverage.scenario_distance.x_labels,
        y: coverage.scenario_distance.y_labels,
        z: heatmapToZ(coverage.scenario_distance, 'value'),
        colorscale: 'Turbo',
        colorbar: { title: 'count' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Scenario x Distance Coverage Count' },
      xaxis: { title: 'distance', tickangle: -20, automargin: true },
      yaxis: { title: 'scenario', automargin: true },
    }),
    { responsive: true },
  );
}

function renderAtlasQuality(quality) {
  const parseRows = quality.parse_errors_by_extension || [];
  Plotly.react(
    'qualityParseErrors',
    [
      {
        type: 'bar',
        x: parseRows.map((r) => r.name),
        y: parseRows.map((r) => r.count),
        marker: { color: '#ff8a9a' },
      },
    ],
    plotLayoutBase({ title: { text: 'Parse Errors by File Type' }, xaxis: { title: 'extension' }, yaxis: { title: 'errors' } }),
    { responsive: true },
  );

  const nullPerf = (quality.null_rates_perf || []).slice(0, 25);
  Plotly.react(
    'qualityNullPerf',
    [
      {
        type: 'bar',
        orientation: 'h',
        y: nullPerf.map((r) => r.column).reverse(),
        x: nullPerf.map((r) => r.missing_pct).reverse(),
        marker: { color: '#59c9f8' },
      },
    ],
    plotLayoutBase({ title: { text: 'Perf Null Rate by Column (Top)' }, xaxis: { title: 'missing %' }, yaxis: { automargin: true } }),
    { responsive: true },
  );

  const nullManifest = (quality.null_rates_manifest || []).slice(0, 25);
  Plotly.react(
    'qualityNullManifest',
    [
      {
        type: 'bar',
        orientation: 'h',
        y: nullManifest.map((r) => r.column).reverse(),
        x: nullManifest.map((r) => r.missing_pct).reverse(),
        marker: { color: '#f7bf62' },
      },
    ],
    plotLayoutBase({ title: { text: 'Manifest Null Rate by Column (Top)' }, xaxis: { title: 'missing %' }, yaxis: { automargin: true } }),
    { responsive: true },
  );

  const schemaRows = quality.schema_time_series || [];
  const buckets = [...new Set(schemaRows.map((r) => r.bucket))].sort((a, b) => a.localeCompare(b));
  const schemas = [...new Set(schemaRows.map((r) => r.schema))].sort((a, b) => a.localeCompare(b));
  const traces = schemas.map((schema) => ({
    type: 'bar',
    name: schema,
    x: buckets,
    y: buckets.map((bucket) => {
      const row = schemaRows.find((r) => r.bucket === bucket && r.schema === schema);
      return row ? row.count : 0;
    }),
  }));

  Plotly.react(
    'qualitySchemaTime',
    traces,
    plotLayoutBase({
      title: { text: 'Schema Version Distribution Over Time' },
      xaxis: { title: 'date bucket', tickangle: -25, automargin: true },
      yaxis: { title: 'files' },
      barmode: 'stack',
    }),
    { responsive: true },
  );
}

function renderAtlasStability(stability) {
  Plotly.react(
    'stabilityCvHist',
    [
      {
        type: 'histogram',
        x: stability.cv_distribution || [],
        nbinsx: 48,
        marker: { color: '#84c9ff' },
      },
    ],
    plotLayoutBase({ title: { text: 'CV% Distribution' }, xaxis: { title: 'cv %' }, yaxis: { title: 'count' } }),
    { responsive: true },
  );

  const drift = stability.drift_control || [];
  Plotly.react(
    'stabilityDriftControl',
    [
      {
        type: 'scatter',
        mode: 'lines+markers',
        name: 'drift',
        x: drift.map((d) => `${d.timestamp} · ${d.key}`),
        y: drift.map((d) => d.drift_pct),
        marker: { size: 6, color: '#ffb677' },
      },
      {
        type: 'scatter',
        mode: 'lines',
        name: 'center',
        x: drift.map((d) => `${d.timestamp} · ${d.key}`),
        y: drift.map((d) => d.center_line),
        line: { color: '#5abaff', dash: 'dot' },
      },
      {
        type: 'scatter',
        mode: 'lines',
        name: 'UCL',
        x: drift.map((d) => `${d.timestamp} · ${d.key}`),
        y: drift.map((d) => d.upper_control),
        line: { color: '#ff8395', dash: 'dash' },
      },
      {
        type: 'scatter',
        mode: 'lines',
        name: 'LCL',
        x: drift.map((d) => `${d.timestamp} · ${d.key}`),
        y: drift.map((d) => d.lower_control),
        line: { color: '#7ad8b4', dash: 'dash' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Run-order Drift Control Chart' },
      xaxis: { title: 'scenario · setting', tickangle: -35, automargin: true },
      yaxis: { title: 'drift %' },
    }),
    { responsive: true },
  );

  const stable = stability.stable_top || [];
  const unstable = stability.unstable_top || [];
  const combined = [
    ...stable.map((r) => ({ ...r, bucket: 'stable' })),
    ...unstable.map((r) => ({ ...r, bucket: 'unstable' })),
  ];

  Plotly.react(
    'stabilityRepeatability',
    [
      {
        type: 'bar',
        x: combined.map((r) => `${r.scenario} | ${r.setting}`),
        y: combined.map((r) => r.repeatability_score),
        marker: { color: combined.map((r) => (r.bucket === 'stable' ? '#58d1bb' : '#ff8ea1')) },
      },
    ],
    plotLayoutBase({
      title: { text: 'Repeatability Score (Stable vs Unstable)' },
      xaxis: { title: 'group', tickangle: -35, automargin: true },
      yaxis: { title: 'score' },
    }),
    { responsive: true },
  );

  q('stableTopTable').innerHTML = stable
    .map((r) => `<tr><td>${r.scenario}</td><td>${r.setting}</td><td>${fmt(r.repeatability_score, 3)}</td><td>${r.rows}</td></tr>`)
    .join('');

  q('unstableTopTable').innerHTML = unstable
    .map((r) => `<tr><td>${r.scenario}</td><td>${r.setting}</td><td>${fmt(r.repeatability_score, 3)}</td><td>${r.rows}</td></tr>`)
    .join('');
}

function renderAtlasBenchmark(bench) {
  const groups = (bench.groups || []).slice().sort((a, b) => b.rows - a.rows).slice(0, 42);
  const labels = groups.map((g) => `${g.host} | ${g.mode} | ${g.jit}`);

  Plotly.react(
    'benchNsNorm',
    [
      {
        type: 'bar',
        x: labels,
        y: groups.map((g) => g.ns_normalized),
        marker: { color: '#7bb8ff' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Normalized ns_per_hash (higher is better)' },
      xaxis: { title: 'host|mode|jit', tickangle: -35, automargin: true },
      yaxis: { title: 'normalized score' },
    }),
    { responsive: true },
  );

  Plotly.react(
    'benchHpsNorm',
    [
      {
        type: 'bar',
        x: labels,
        y: groups.map((g) => g.hps_normalized),
        marker: { color: '#ffc26f' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Normalized hashes_per_sec (higher is better)' },
      xaxis: { title: 'host|mode|jit', tickangle: -35, automargin: true },
      yaxis: { title: 'normalized score' },
    }),
    { responsive: true },
  );

  const deltas = (bench.pairwise_deltas || []).slice(0, 48).reverse();
  Plotly.react(
    'benchPairwiseDelta',
    [
      {
        type: 'bar',
        orientation: 'h',
        y: deltas.map((d) => `${d.mode} | ${d.jit} | ${d.host}`),
        x: deltas.map((d) => d.delta_ns_pct),
        error_x: { type: 'data', array: deltas.map((d) => d.delta_ci95_pct || 0), visible: true },
        marker: { color: deltas.map((d) => (d.delta_ns_pct <= 0 ? '#58d1bb' : '#ff8ea1')) },
      },
    ],
    plotLayoutBase({
      title: { text: 'Pairwise Delta vs Best Host in Mode/JIT (ns_per_hash %)' },
      xaxis: { title: 'delta % vs baseline (negative is better)' },
      yaxis: { automargin: true },
    }),
    { responsive: true },
  );

  q('benchGroupTable').innerHTML = (bench.groups || [])
    .slice(0, 120)
    .map(
      (g) =>
        `<tr><td>${g.host}</td><td>${g.mode}</td><td>${g.jit}</td><td>${g.rows}</td><td>${fmt(g.mean_ns_per_hash, 5)}</td><td>${fmt(g.mean_hashes_per_sec, 2)}</td></tr>`,
    )
    .join('');
}

function renderAtlasPareto(pareto) {
  const points = pareto.points || [];
  const frontierSet = new Set(pareto.frontier_ids || []);
  const frontier = points.filter((p) => frontierSet.has(p.id));
  frontier.sort((a, b) => a.cv_pct - b.cv_pct);

  Plotly.react(
    'paretoScatter',
    [
      {
        type: 'scatter',
        mode: 'markers',
        name: 'all candidates',
        x: points.map((p) => p.cv_pct),
        y: points.map((p) => p.mean_ns_per_hash),
        text: points.map((p) => `${p.scenario} | ${p.setting} | d=${p.distance ?? 'n/a'} | rows=${p.rows}`),
        hovertemplate: '%{text}<br>cv=%{x:.3f}%<br>mean ns/hash=%{y:.5f}<extra></extra>',
        marker: {
          size: points.map((p) => Math.max(6, Math.min(20, 4 + p.rows / 2))),
          color: '#69aefb',
          opacity: 0.55,
          line: { width: 0.5, color: '#d0e7ff' },
        },
      },
      {
        type: 'scatter',
        mode: 'lines+markers',
        name: 'pareto frontier',
        x: frontier.map((p) => p.cv_pct),
        y: frontier.map((p) => p.mean_ns_per_hash),
        text: frontier.map((p) => `${p.scenario} | ${p.setting}`),
        hovertemplate: '%{text}<br>cv=%{x:.3f}%<br>mean ns/hash=%{y:.5f}<extra></extra>',
        marker: { size: 9, color: '#ff8e6b' },
        line: { width: 2, color: '#ff8e6b' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Pareto Frontier: mean ns_per_hash vs CV%' },
      xaxis: { title: 'cv % (lower is better)' },
      yaxis: { title: 'mean ns_per_hash (lower is better)' },
    }),
    { responsive: true },
  );

  const frontierRows = frontier.slice(0, 40);
  q('paretoTable').innerHTML = frontierRows
    .map(
      (p) =>
        `<tr><td>${p.scenario}</td><td>${p.setting}</td><td>${p.distance ?? '-'}</td><td>${p.rows}</td><td>${fmt(p.mean_ns_per_hash, 5)}</td><td>${fmt(p.cv_pct, 3)}</td></tr>`,
    )
    .join('');
}

function renderAtlasAnomalies(anomalyData) {
  const anomalies = anomalyData.anomalies || [];

  const byReason = {};
  anomalies.forEach((a) => {
    byReason[a.reason] = (byReason[a.reason] || 0) + 1;
  });

  Plotly.react(
    'anomalyScatter',
    [
      {
        type: 'scatter',
        mode: 'markers',
        x: anomalies.map((a) => a.robust_z),
        y: anomalies.map((a) => a.ns_per_hash),
        text: anomalies.map((a) => `${a.id} | ${a.host} | ${a.scenario} | ${a.setting}`),
        hovertemplate: '%{text}<br>z=%{x:.4f}<br>ns/hash=%{y:.5f}<extra></extra>',
        marker: {
          size: 8,
          color: anomalies.map((a) => a.reason),
          colorscale: 'Turbo',
          showscale: false,
        },
      },
    ],
    plotLayoutBase({
      title: { text: `Anomaly Scatter (median=${fmt(anomalyData.global_median_ns, 5)}, MAD=${fmt(anomalyData.global_mad_ns, 5)})` },
      xaxis: { title: 'robust z-score' },
      yaxis: { title: 'ns_per_hash' },
    }),
    { responsive: true },
  );

  Plotly.react(
    'anomalyReasonBars',
    [
      {
        type: 'bar',
        x: Object.keys(byReason),
        y: Object.values(byReason),
        marker: { color: '#ff9ba7' },
      },
    ],
    plotLayoutBase({ title: { text: 'Anomaly Reason Counts' }, xaxis: { title: 'reason' }, yaxis: { title: 'rows' } }),
    { responsive: true },
  );

  q('anomalyTable').innerHTML = anomalies
    .map(
      (a) =>
        `<tr class="row-selectable" data-anomaly-id="${a.id}"><td>${a.id}</td><td>${a.host}</td><td>${a.scenario}</td><td>${a.setting}</td><td>${fmt(a.ns_per_hash, 5)}</td><td>${fmt(a.robust_z, 4)}</td><td>${a.reason}</td></tr>`,
    )
    .join('');

  const selected = anomalies.find((a) => a.id === selectedAnomalyId) || anomalies[0] || null;
  if (selected) {
    selectedAnomalyId = selected.id;
  }
  renderAnomalyDetail(selected);
}

function renderAnomalyDetail(anomaly) {
  if (!anomaly) {
    q('anomalyDetail').textContent = 'No anomalies for current scope.';
    Plotly.react('anomalySeries', [], plotLayoutBase({ title: { text: 'Group Series' } }), { responsive: true });
    return;
  }

  q('anomalyDetail').textContent = [
    `ID: ${anomaly.id}`,
    `Host/Mode/JIT: ${anomaly.host} | ${anomaly.mode} | ${anomaly.jit}`,
    `Scenario/Setting: ${anomaly.scenario} | ${anomaly.setting}`,
    `Run Index: ${anomaly.run_index ?? 'n/a'}`,
    `ns_per_hash: ${fmt(anomaly.ns_per_hash, 6)}`,
    `hashes_per_sec: ${fmt(anomaly.hashes_per_sec, 3)}`,
    `robust_z: ${fmt(anomaly.robust_z, 4)}`,
    `iqr_low/high: ${fmt(anomaly.iqr_low, 6)} / ${fmt(anomaly.iqr_high, 6)}`,
    `deviation_vs_group_median: ${anomaly.deviation_pct_from_group_median === null ? '-' : `${fmt(anomaly.deviation_pct_from_group_median, 3)}%`}`,
    `reason: ${anomaly.reason}`,
    `source_path: ${anomaly.source_path}`,
    `artifact_csv: ${anomaly.artifact_csv ?? '-'}`,
    `artifact_stdout: ${anomaly.artifact_stdout ?? '-'}`,
    `artifact_stderr: ${anomaly.artifact_stderr ?? '-'}`,
  ].join('\n');

  const series = anomaly.group_series || [];
  Plotly.react(
    'anomalySeries',
    [
      {
        type: 'box',
        y: series,
        name: 'group distribution',
        marker: { color: '#67aefc' },
      },
      {
        type: 'scatter',
        mode: 'markers',
        x: ['selected'],
        y: [anomaly.ns_per_hash],
        name: 'selected anomaly',
        marker: { size: 12, color: '#ff7d8a', symbol: 'x' },
      },
    ],
    plotLayoutBase({ title: { text: 'Anomaly Drill-down: Group Distribution' }, yaxis: { title: 'ns_per_hash' } }),
    { responsive: true },
  );
}

function renderAtlasTimeline(timeline) {
  const points = timeline.points || [];
  const changePoints = timeline.change_points || [];

  Plotly.react(
    'timelineTrend',
    [
      {
        type: 'scatter',
        mode: 'lines+markers',
        name: 'perf mean ns/hash',
        x: points.map((p) => p.bucket),
        y: points.map((p) => p.perf_mean_ns_per_hash),
        line: { color: '#67aefc', width: 2 },
      },
      {
        type: 'scatter',
        mode: 'lines+markers',
        name: 'manifest mean ns/hash',
        x: points.map((p) => p.bucket),
        y: points.map((p) => p.manifest_mean_ns_per_hash),
        line: { color: '#ffc26f', width: 2 },
      },
      {
        type: 'scatter',
        mode: 'lines+markers',
        name: 'perf mean hashes/sec',
        x: points.map((p) => p.bucket),
        y: points.map((p) => p.perf_mean_hashes_per_sec),
        yaxis: 'y2',
        line: { color: '#61d0aa', width: 2, dash: 'dot' },
      },
      {
        type: 'scatter',
        mode: 'markers',
        name: 'change points',
        x: changePoints.map((c) => c.bucket),
        y: changePoints.map((c) => c.to_value),
        text: changePoints.map((c) => `${c.metric}: ${fmt(c.pct_change, 2)}%`),
        hovertemplate: '%{text}<extra></extra>',
        marker: { size: 10, color: '#ff8a9a', symbol: 'diamond' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Timeline Trend + Regression Watch' },
      xaxis: { title: 'date bucket', tickangle: -25, automargin: true },
      yaxis: { title: 'ns_per_hash' },
      yaxis2: { title: 'hashes_per_sec', overlaying: 'y', side: 'right' },
    }),
    { responsive: true },
  );

  Plotly.react(
    'timelineRows',
    [
      {
        type: 'bar',
        name: 'perf rows',
        x: points.map((p) => p.bucket),
        y: points.map((p) => p.perf_rows),
        marker: { color: '#7ab7ff' },
      },
      {
        type: 'bar',
        name: 'manifest rows',
        x: points.map((p) => p.bucket),
        y: points.map((p) => p.manifest_rows),
        marker: { color: '#ffbf77' },
      },
    ],
    plotLayoutBase({ title: { text: 'Row Volume Timeline' }, xaxis: { title: 'date bucket', tickangle: -25, automargin: true }, yaxis: { title: 'rows' }, barmode: 'stack' }),
    { responsive: true },
  );

  q('timelineChangeTable').innerHTML = changePoints
    .map(
      (c) =>
        `<tr><td>${c.bucket}</td><td>${c.metric}</td><td>${fmt(c.pct_change, 2)}%</td><td>${fmt(c.from_value, 5)}</td><td>${fmt(c.to_value, 5)}</td></tr>`,
    )
    .join('');
}

function rerenderCachedCharts() {
  if (lastPrefetch) renderPrefetch(lastPrefetch);
  if (lastCorr && lastMatrix) renderCorrelation(lastCorr, lastMatrix);
  if (lastAtlas) renderAtlas(lastAtlas);
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportPointsCsv() {
  if (!lastCorr) {
    setExportMessage('Run Correlation Studio first.');
    return;
  }
  const header = ['group', lastCorr.x_metric, lastCorr.y_metric].map(csvEscape).join(',');
  const rows = lastCorr.points.map((p) => [p.color, p.x, p.y].map(csvEscape).join(','));
  downloadText(`corr_points_${Date.now()}.csv`, [header, ...rows].join('\n'));
  setExportMessage('Exported points CSV.');
}

function exportTopCsv() {
  if (!lastCorr) {
    setExportMessage('Run Correlation Studio first.');
    return;
  }
  const header = ['target_metric', 'metric', 'pearson_r', 'pairs'].map(csvEscape).join(',');
  const rows = lastCorr.top_correlations.map((r) => [lastCorr.y_metric, r.metric, r.pearson_r, r.pairs].map(csvEscape).join(','));
  downloadText(`corr_top_${Date.now()}.csv`, [header, ...rows].join('\n'));
  setExportMessage('Exported top-correlation CSV.');
}

function exportScatterPng() {
  Plotly.downloadImage('corrScatter', { format: 'png', filename: `corr_scatter_${Date.now()}`, scale: 2 });
  setExportMessage('Requested scatter PNG export.');
}

function exportMatrixPng() {
  Plotly.downloadImage('corrMatrix', { format: 'png', filename: `corr_matrix_${Date.now()}`, scale: 2 });
  setExportMessage('Requested matrix PNG export.');
}

function bindSessionChangeEvents() {
  [
    'pfHost',
    'pfScenario',
    'pfMode',
    'pfJit',
    'pfOnlyNs',
    'corrDataset',
    'corrX',
    'corrY',
    'corrColor',
    'corrHost',
    'corrMode',
    'corrJit',
    'corrScenario',
    'corrMaxPoints',
    'corrMaxMetrics',
    'atlasHost',
    'atlasMode',
    'atlasJit',
    'atlasScenario',
    'atlasMaxAnomalies',
    'atlasMaxTimeline',
  ].forEach((id) => {
    const el = q(id);
    if (!el) return;
    el.addEventListener('change', () => saveSessionState());
  });
}

function resetAtlasFilters() {
  q('atlasHost').value = 'All';
  q('atlasMode').value = 'All';
  q('atlasJit').value = 'All';
  q('atlasScenario').value = 'All';
  q('atlasMaxAnomalies').value = '120';
  q('atlasMaxTimeline').value = '180';
}

async function boot() {
  options = await fetchJson('/api/options');

  fillSelect('pfHost', options.hosts_manifest, 'All');
  fillSelect('pfScenario', options.scenarios_manifest, 'All');
  fillSelect('pfMode', options.modes_manifest, 'All');
  fillSelect('pfJit', options.jits_manifest, 'All');

  fillSelect('corrDataset', ['perf', 'manifest'], 'perf');
  syncCorrSelectorsByDataset();
  syncAtlasSelectors();

  populateThemeSelector();
  const storedTheme = localStorage.getItem(STORAGE_THEME_KEY) || 'Nebula';
  applyTheme(storedTheme, { persist: true, rerender: false, storeSession: false });

  refreshLayoutList('(none)');
  await restoreSessionState();

  q('tabPrefetch').addEventListener('click', () => {
    activateTab('prefetch');
    saveSessionState();
  });
  q('tabCorr').addEventListener('click', () => {
    activateTab('corr');
    saveSessionState();
  });
  q('tabAtlas').addEventListener('click', () => {
    activateTab('atlas');
    saveSessionState();
  });

  q('refreshPrefetch').addEventListener('click', () => {
    refreshPrefetch().catch((err) => {
      console.error(err);
      setLayoutMessage(`Prefetch refresh failed: ${err}`);
    });
  });

  q('refreshCorr').addEventListener('click', () => {
    refreshCorrelation().catch((err) => {
      console.error(err);
      setExportMessage(`Correlation refresh failed: ${err}`);
    });
  });

  q('refreshAtlas').addEventListener('click', () => {
    refreshAtlas().catch((err) => {
      console.error(err);
      setAtlasMessage(`Atlas refresh failed: ${err}`);
    });
  });

  q('resetAtlas').addEventListener('click', () => {
    resetAtlasFilters();
    refreshAtlas().catch((err) => {
      console.error(err);
      setAtlasMessage(`Atlas refresh failed: ${err}`);
    });
  });

  q('corrDataset').addEventListener('change', () => {
    syncCorrSelectorsByDataset();
    refreshCorrelation().catch((err) => {
      console.error(err);
      setExportMessage(`Correlation refresh failed: ${err}`);
    });
  });

  q('swapAxes').addEventListener('click', () => {
    const x = q('corrX').value;
    q('corrX').value = q('corrY').value;
    q('corrY').value = x;
    saveSessionState();
  });

  q('themePreset').addEventListener('change', () => {
    applyTheme(q('themePreset').value, { persist: true, rerender: true, storeSession: true });
    setLayoutMessage(`Theme set to '${q('themePreset').value}'.`);
  });

  q('saveLayout').addEventListener('click', saveNamedLayout);
  q('loadLayout').addEventListener('click', () => {
    loadSelectedLayout().catch((err) => {
      console.error(err);
      setLayoutMessage(`Layout load failed: ${err}`);
    });
  });
  q('deleteLayout').addEventListener('click', deleteSelectedLayout);
  q('saveSession').addEventListener('click', () => {
    saveSessionState();
    setLayoutMessage('Session saved.');
  });

  q('layoutSelect').addEventListener('change', () => {
    const selected = q('layoutSelect').value;
    if (selected && selected !== '(none)') q('layoutName').value = selected;
  });

  q('exportPointsCsv').addEventListener('click', exportPointsCsv);
  q('exportTopCsv').addEventListener('click', exportTopCsv);
  q('exportScatterPng').addEventListener('click', exportScatterPng);
  q('exportMatrixPng').addEventListener('click', exportMatrixPng);

  q('anomalyTable').addEventListener('click', (ev) => {
    const tr = ev.target.closest('tr[data-anomaly-id]');
    if (!tr || !lastAtlas) return;
    const id = tr.getAttribute('data-anomaly-id');
    const anomaly = (lastAtlas.anomalies?.anomalies || []).find((a) => a.id === id);
    if (!anomaly) return;
    selectedAnomalyId = anomaly.id;
    renderAnomalyDetail(anomaly);
  });

  bindSessionChangeEvents();

  await refreshPrefetch();
  await refreshCorrelation();
  await refreshAtlas();

  window.addEventListener('beforeunload', saveSessionState);
}

boot().catch((err) => {
  console.error(err);
  alert(`perf_viz failed to initialize: ${err}`);
});
