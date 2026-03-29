const STORAGE_THEME_KEY = 'perf_viz.theme.v1';
const STORAGE_EXPLANATION_FILTERS_KEY = 'perf_viz.explanations.filters.v1';

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

let lastData = null;
let options = null;

function q(id) {
  return document.getElementById(id);
}

function fmt(v, digits = 4) {
  return v === null || v === undefined || Number.isNaN(v) ? 'n/a' : Number(v).toFixed(digits);
}

function allOrValue(v) {
  return v && v !== 'All' ? v : '';
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function setMessage(msg) {
  q('explainMsg').textContent = msg || '';
}

function fetchJson(url) {
  return fetch(url).then((res) => {
    if (!res.ok) {
      throw new Error(`${res.status} ${res.statusText}`);
    }
    return res.json();
  });
}

function fillSelect(id, values, selected) {
  const el = q(id);
  const curr = selected ?? el.value;
  el.innerHTML = '';
  values.forEach((v) => {
    const opt = document.createElement('option');
    opt.value = v;
    opt.textContent = v;
    el.appendChild(opt);
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

function populateThemeSelector() {
  fillSelect('themePreset', Object.keys(THEME_PRESETS), q('themePreset').value || 'Nebula');
}

function applyTheme(themeName, persist = true) {
  const resolved = THEME_PRESETS[themeName] ? themeName : 'Nebula';
  const preset = THEME_PRESETS[resolved];
  const root = document.documentElement;
  Object.entries(preset).forEach(([key, value]) => root.style.setProperty(key, value));
  q('themePreset').value = resolved;
  if (persist) {
    localStorage.setItem(STORAGE_THEME_KEY, resolved);
  }
  if (lastData) {
    renderExplanations(lastData);
  }
}

function plotLayoutBase(extra = {}) {
  return {
    paper_bgcolor: cssVar('--surface'),
    plot_bgcolor: cssVar('--surface'),
    font: { color: cssVar('--txt') },
    margin: { l: 58, r: 24, t: 36, b: 52 },
    legend: { orientation: 'h' },
    ...extra,
  };
}

function renderCards(cards) {
  q('explainCards').innerHTML = cards
    .map(
      (card) =>
        `<div class="stat"><div class="k">${card.title}</div><div class="v">${card.value}</div><div class="muted">${card.detail}</div></div>`,
    )
    .join('');
}

function renderFindings(findings) {
  q('findingsList').innerHTML = findings
    .map((f) => `<li><strong>${f.title}</strong><div class="muted">${f.explanation}</div></li>`)
    .join('');
}

function renderAutoFixed(summary) {
  const delta = summary.delta_pct_auto_vs_fixed;
  const tone = delta === null ? 'muted' : delta <= 0 ? 'mono' : 'mono';
  const deltaText = delta === null ? 'n/a' : `${delta.toFixed(2)}%`;
  q('autoFixedBox').innerHTML = `
    <div class="row" style="gap: 16px;">
      <div><div class="muted">Auto rows</div><div class="mono">${summary.auto_rows}</div></div>
      <div><div class="muted">Fixed rows</div><div class="mono">${summary.fixed_rows}</div></div>
      <div><div class="muted">Auto mean ns/hash</div><div class="mono">${fmt(summary.auto_mean_ns_per_hash, 5)}</div></div>
      <div><div class="muted">Fixed mean ns/hash</div><div class="mono">${fmt(summary.fixed_mean_ns_per_hash, 5)}</div></div>
      <div><div class="muted">Delta auto vs fixed</div><div class="${tone}">${deltaText}</div></div>
    </div>
  `;
}

function renderHostChart(hostCounts) {
  Plotly.react(
    'hostChart',
    [
      {
        type: 'bar',
        x: hostCounts.map((h) => h.name),
        y: hostCounts.map((h) => h.count),
        marker: { color: '#6fb6ff' },
      },
    ],
    plotLayoutBase({
      title: { text: 'Rows In Scope By Host' },
      xaxis: { title: 'host' },
      yaxis: { title: 'rows' },
    }),
    { responsive: true },
  );
}

function renderScenarioChart(scores) {
  const take = 10;
  const seen = new Set();
  const best = scores.slice(0, take);
  const worst = scores.slice(Math.max(0, scores.length - take));
  const combined = [];
  for (const row of best) {
    if (!seen.has(row.scenario)) {
      combined.push({ ...row, bucket: 'best' });
      seen.add(row.scenario);
    }
  }
  for (const row of worst) {
    if (!seen.has(row.scenario)) {
      combined.push({ ...row, bucket: 'worst' });
      seen.add(row.scenario);
    }
  }

  Plotly.react(
    'scenarioChart',
    [
      {
        type: 'bar',
        x: combined.map((r) => r.scenario),
        y: combined.map((r) => r.mean_ns_per_hash),
        marker: {
          color: combined.map((r) => (r.bucket === 'best' ? '#57cfa0' : '#ff8a9a')),
        },
        text: combined.map((r) => `${r.rows} rows`),
        hovertemplate: 'scenario=%{x}<br>mean ns/hash=%{y:.5f}<br>%{text}<extra></extra>',
      },
    ],
    plotLayoutBase({
      title: { text: 'Scenario Extremes (Best + Worst Mean ns/hash)' },
      xaxis: { title: 'scenario', tickangle: -20, automargin: true },
      yaxis: { title: 'mean ns_per_hash' },
    }),
    { responsive: true },
  );
}

function renderDriftChart(hotspots) {
  const top = hotspots.slice(0, 16).reverse();
  Plotly.react(
    'driftChart',
    [
      {
        type: 'bar',
        orientation: 'h',
        y: top.map((h) => h.key),
        x: top.map((h) => h.drift_pct),
        marker: {
          color: top.map((h) => (h.drift_pct >= 0 ? '#ff8a9a' : '#57cfa0')),
        },
        text: top.map((h) => `${h.rows} rows`),
        hovertemplate: 'setting=%{y}<br>drift=%{x:.4f}%<br>%{text}<extra></extra>',
      },
    ],
    plotLayoutBase({
      title: { text: 'Largest Run-order Drift Hotspots' },
      xaxis: { title: 'drift %' },
      yaxis: { title: 'scenario|setting', automargin: true },
    }),
    { responsive: true },
  );
}

function renderCorrTables(perfRows, manifestRows) {
  q('perfCorrTable').innerHTML = perfRows
    .map((r) => `<tr><td>${r.metric}</td><td>${fmt(r.pearson_r, 5)}</td><td>${r.pairs}</td></tr>`)
    .join('');
  q('manifestCorrTable').innerHTML = manifestRows
    .map((r) => `<tr><td>${r.metric}</td><td>${fmt(r.pearson_r, 5)}</td><td>${r.pairs}</td></tr>`)
    .join('');
}

function renderExplanations(data) {
  lastData = data;
  renderCards(data.cards || []);
  renderFindings(data.findings || []);
  renderAutoFixed(data.auto_vs_fixed || {});
  renderHostChart(data.host_counts || []);
  renderScenarioChart(data.scenario_scores || []);
  renderDriftChart(data.drift_hotspots || []);
  renderCorrTables(data.perf_top_correlations || [], data.manifest_top_correlations || []);
}

async function refreshExplanations() {
  const params = new URLSearchParams({
    host: allOrValue(q('exHost').value),
    mode: allOrValue(q('exMode').value),
    jit: allOrValue(q('exJit').value),
    scenario: allOrValue(q('exScenario').value),
  });
  const data = await fetchJson(`/api/explanations?${params.toString()}`);
  renderExplanations(data);
  saveExplanationFilters();
  const activeFilters = [
    allOrValue(q('exHost').value) && `host=${q('exHost').value}`,
    allOrValue(q('exMode').value) && `mode=${q('exMode').value}`,
    allOrValue(q('exJit').value) && `jit=${q('exJit').value}`,
    allOrValue(q('exScenario').value) && `scenario=${q('exScenario').value}`,
  ]
    .filter(Boolean)
    .join(', ');
  setMessage(
    activeFilters
      ? `Explanations refreshed with filters: ${activeFilters}`
      : 'Explanations refreshed with no filters (global dataset).',
  );
}

function saveExplanationFilters() {
  const snapshot = {
    host: q('exHost').value,
    mode: q('exMode').value,
    jit: q('exJit').value,
    scenario: q('exScenario').value,
  };
  localStorage.setItem(STORAGE_EXPLANATION_FILTERS_KEY, JSON.stringify(snapshot));
}

function restoreExplanationFilters() {
  const savedRaw = localStorage.getItem(STORAGE_EXPLANATION_FILTERS_KEY);
  if (!savedRaw) return;
  let saved = null;
  try {
    saved = JSON.parse(savedRaw);
  } catch (_err) {
    return;
  }
  if (!saved || typeof saved !== 'object') return;
  setSelectIfPossible('exHost', saved.host);
  setSelectIfPossible('exMode', saved.mode);
  setSelectIfPossible('exJit', saved.jit);
  setSelectIfPossible('exScenario', saved.scenario);
}

function resetExplanationFilters() {
  q('exHost').value = 'All';
  q('exMode').value = 'All';
  q('exJit').value = 'All';
  q('exScenario').value = 'All';
  saveExplanationFilters();
}

function populateExplanationFilterControls() {
  fillSelect('exHost', valuesUnionWithAll(options.hosts_manifest, options.hosts_perf), 'All');
  fillSelect('exMode', valuesUnionWithAll(options.modes_manifest, options.modes_perf), 'All');
  fillSelect('exJit', valuesUnionWithAll(options.jits_manifest, options.jits_perf), 'All');
  fillSelect('exScenario', valuesUnionWithAll(options.scenarios_manifest), 'All');
}

async function boot() {
  options = await fetchJson('/api/options');
  populateExplanationFilterControls();
  restoreExplanationFilters();

  populateThemeSelector();
  const storedTheme = localStorage.getItem(STORAGE_THEME_KEY) || 'Nebula';
  applyTheme(storedTheme, false);

  q('themePreset').addEventListener('change', () => {
    applyTheme(q('themePreset').value, true);
    setMessage(`Theme set to '${q('themePreset').value}'.`);
  });

  q('refreshExplain').addEventListener('click', () => {
    refreshExplanations().catch((err) => {
      console.error(err);
      setMessage(`Refresh failed: ${err}`);
    });
  });

  q('resetExplain').addEventListener('click', () => {
    resetExplanationFilters();
    refreshExplanations().catch((err) => {
      console.error(err);
      setMessage(`Refresh failed: ${err}`);
    });
  });

  ['exHost', 'exMode', 'exJit', 'exScenario'].forEach((id) => {
    const el = q(id);
    if (!el) return;
    el.addEventListener('change', () => {
      saveExplanationFilters();
      refreshExplanations().catch((err) => {
        console.error(err);
        setMessage(`Refresh failed: ${err}`);
      });
    });
  });

  await refreshExplanations();
}

boot().catch((err) => {
  console.error(err);
  alert(`Failed to load explanations page: ${err}`);
});
