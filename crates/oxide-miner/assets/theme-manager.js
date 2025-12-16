(function () {
  const STORAGE_KEY = 'oxideminer.theme_id';
  const THEME_COOKIE = 'oxideminer_theme';
  const COOKIE_MAX_AGE = 60 * 60 * 24 * 365; // 1 year
  let themes = [];
  let activeThemeId = null;
  let readyPromise = null;
  let listeners = [];
  let cssNode = null;
  let scriptNodes = [];
  let bootedFromEntryHtml = false;

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

  function writeThemeCookie(id) {
    try {
      if (id) {
        const encoded = encodeURIComponent(id);
        document.cookie = `${THEME_COOKIE}=${encoded}; Path=/; Max-Age=${COOKIE_MAX_AGE}; SameSite=Lax`;
      } else {
        document.cookie = `${THEME_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax`;
      }
    } catch (_) {
      // ignore
    }
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

  function loadScripts(urls) {
    urls.forEach((url) => {
      const existing = document.querySelector(`script[data-plugin-theme-script="${url}"]`);
      if (existing) {
        scriptNodes.push(existing);
        return;
      }
      const script = document.createElement('script');
      script.src = url;
      script.defer = false;
      script.async = false;
      script.dataset.pluginThemeScript = url;
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

    const hasEntryHtml = Boolean(theme.entry_html_url);
    const isCurrentEntryTheme = document.body?.getAttribute('data-theme') === theme.id;
    const onThemesPage = window.location.pathname.startsWith('/plugins/themes');

    if (theme.kind === 'built-in') {
      // When leaving an entry HTML theme, reload to the default dashboard shell.
      if (bootedFromEntryHtml && !isCurrentEntryTheme) {
        persistSelection && persist(theme.id);
        writeThemeCookie(theme.id);
        window.location.assign('/');
        return true;
      } else {
        removePluginAssets();
        setBodyTheme(theme.id);
        activeThemeId = theme.id;
        if (persistSelection) persist(theme.id);
        writeThemeCookie(theme.id);
        bootedFromEntryHtml = false;
        notify();
        return true;
      }
    }

    if (!theme.entry_css_url) {
      console.warn('Theme missing entry_css_url', theme);
      return false;
    }

    // Themes with entry_html are treated as full-page entrypoint overrides; reload so only one dashboard mounts.
    if (hasEntryHtml) {
      activeThemeId = theme.id;
      if (persistSelection) persist(theme.id);
      writeThemeCookie(theme.id);
      bootedFromEntryHtml = !onThemesPage;

      if (!onThemesPage && !isCurrentEntryTheme) {
        window.location.assign('/');
        return true;
      }

      // On the themes page (or already on the entry theme), avoid reloads and skip HTML injection;
      // load CSS for visual consistency but keep the page intact.
      removePluginAssets();
      cssNode = document.createElement('link');
      cssNode.rel = 'stylesheet';
      cssNode.href = theme.entry_css_url;
      cssNode.id = 'plugin-theme-style';
      document.head.appendChild(cssNode);

      setBodyTheme(theme.id);
      notify();
      return true;
    }

    // CSS/JS only (no entry HTML): apply in-place.
    removePluginAssets();

    cssNode = document.createElement('link');
    cssNode.rel = 'stylesheet';
    cssNode.href = theme.entry_css_url;
    cssNode.id = 'plugin-theme-style';
    document.head.appendChild(cssNode);

    if (Array.isArray(theme.entry_js_urls) && theme.entry_js_urls.length > 0) {
      loadScripts(theme.entry_js_urls);
    }

    setBodyTheme(theme.id);
    activeThemeId = theme.id;
    if (persistSelection) persist(theme.id);
    writeThemeCookie(theme.id);
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
    writeThemeCookie(null);
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
