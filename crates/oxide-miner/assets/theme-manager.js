(function () {
  const STORAGE_KEY = 'oxideminer.theme_id';
  let themes = [];
  let activeThemeId = null;
  let readyPromise = null;
  let listeners = [];
  let cssNode = null;
  let scriptNodes = [];

  function builtInThemes() {
    return [
      { id: 'light', name: 'Light', version: 'built-in', kind: 'built-in' },
      { id: 'dark', name: 'Dark', version: 'built-in', kind: 'built-in' },
      { id: 'monero', name: 'Monero', version: 'built-in', kind: 'built-in' },
    ];
  }

  function notify() {
    listeners.forEach((fn) => {
      try { fn(activeThemeId); } catch (err) { console.error(err); }
    });
  }

  function persist(id) {
    try { localStorage.setItem(STORAGE_KEY, id); } catch (_) { /* ignore */ }
  }

  function clearPersisted() {
    try { localStorage.removeItem(STORAGE_KEY); } catch (_) { /* ignore */ }
  }

  function getSavedTheme() {
    try { return localStorage.getItem(STORAGE_KEY); } catch (_) { return null; }
  }

  async function fetchThemes() {
    try {
      const resp = await fetch('/api/plugins/themes', { cache: 'no-store' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      themes = Array.isArray(data) ? data : [];
    } catch (err) {
      console.warn('Failed to load themes list', err);
      themes = builtInThemes();
    }
    if (!themes || themes.length === 0) {
      themes = builtInThemes();
    }
    return themes;
  }

  function ensureThemes() {
    if (!readyPromise) {
      readyPromise = fetchThemes();
    }
    return readyPromise;
  }

  function removePluginAssets() {
    if (cssNode) {
      cssNode.remove();
      cssNode = null;
    }
    scriptNodes.forEach((node) => node.remove());
    scriptNodes = [];
    const mount = document.getElementById('theme-root');
    if (mount) {
      mount.innerHTML = '';
    }
  }

  function setBodyTheme(themeId) {
    if (themeId) {
      document.body.setAttribute('data-theme', themeId);
    }
  }

  async function loadHtml(url) {
    const mount = document.getElementById('theme-root');
    if (!mount || !url) return;
    try {
      const resp = await fetch(url, { cache: 'no-store' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const html = await resp.text();
      mount.innerHTML = html;
    } catch (err) {
      console.warn('Failed to load theme HTML fragment', err);
    }
  }

  function loadScripts(urls) {
    urls.forEach((url) => {
      const script = document.createElement('script');
      script.src = url;
      script.defer = false;
      script.async = false;
      document.head.appendChild(script);
      scriptNodes.push(script);
    });
  }

  async function applyTheme(themeId, { persistSelection = true } = {}) {
    await ensureThemes();
    const theme = themes.find((t) => t.id === themeId);
    if (!theme) {
      return false;
    }

    if (theme.kind === 'built-in') {
      removePluginAssets();
      setBodyTheme(theme.id);
      activeThemeId = theme.id;
      if (persistSelection) persist(theme.id);
      notify();
      return true;
    }

    if (!theme.entry_css_url) {
      console.warn('Theme missing entry_css_url', theme);
      return false;
    }

    removePluginAssets();

    cssNode = document.createElement('link');
    cssNode.rel = 'stylesheet';
    cssNode.href = theme.entry_css_url;
    cssNode.id = 'plugin-theme-style';
    document.head.appendChild(cssNode);

    if (Array.isArray(theme.entry_js_urls) && theme.entry_js_urls.length > 0) {
      loadScripts(theme.entry_js_urls);
    }

    if (theme.entry_html_url) {
      await loadHtml(theme.entry_html_url);
    }

    setBodyTheme(theme.id);
    activeThemeId = theme.id;
    if (persistSelection) persist(theme.id);
    notify();
    return true;
  }

  async function applySavedTheme() {
    const saved = getSavedTheme();
    if (saved) {
      const ok = await applyTheme(saved, { persistSelection: false }).catch(() => false);
      if (ok) return true;
    }
    await applyTheme('light', { persistSelection: false });
    return true;
  }

  function reset() {
    removePluginAssets();
    setBodyTheme('light');
    activeThemeId = 'light';
    clearPersisted();
    notify();
  }

  function onChange(cb) {
    listeners.push(cb);
    return () => {
      listeners = listeners.filter((fn) => fn !== cb);
    };
  }

  window.themeManager = {
    ensureThemes,
    getThemes: () => themes.slice(),
    applyTheme,
    applySavedTheme,
    reset,
    onChange,
    get activeTheme() { return activeThemeId; },
  };
})();
