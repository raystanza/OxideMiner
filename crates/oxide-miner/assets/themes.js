(function () {
  const listEl = document.getElementById('themes-list');
  const resetBtn = document.getElementById('reset-theme');
  const menuBtn = document.getElementById('plugins-menu-button');
  const menu = document.getElementById('plugins-menu');

  function renderThemes(themes) {
    if (!listEl) return;
    listEl.innerHTML = '';
    if (!themes || themes.length === 0) {
      const empty = document.createElement('p');
      empty.textContent = 'No themes found in plugins/themes.';
      listEl.appendChild(empty);
      return;
    }

    themes.forEach((theme) => {
      const card = document.createElement('article');
      card.className = 'theme-card';
      card.setAttribute('data-theme-id', theme.id);

      const header = document.createElement('header');
      const title = document.createElement('div');
      title.innerHTML = `<strong>${theme.name}</strong>`;
      const meta = document.createElement('div');
      meta.className = 'meta';
      meta.textContent = `${theme.kind === 'plugin' ? 'Plugin' : 'Built-in'} • v${theme.version}`;
      header.appendChild(title);
      header.appendChild(meta);
      card.appendChild(header);

      if (theme.description) {
        const desc = document.createElement('p');
        desc.textContent = theme.description;
        card.appendChild(desc);
      }

      if (theme.preview_url) {
        const img = document.createElement('img');
        img.className = 'theme-preview';
        img.src = theme.preview_url;
        img.alt = `${theme.name} preview`;
        card.appendChild(img);
      }

      const actions = document.createElement('div');
      actions.className = 'theme-actions';
      const applyBtn = document.createElement('button');
      applyBtn.type = 'button';
      applyBtn.textContent = 'Apply';
      applyBtn.addEventListener('click', () => {
        themeManager.applyTheme(theme.id).catch((err) => console.error(err));
      });
      actions.appendChild(applyBtn);

      card.appendChild(actions);
      listEl.appendChild(card);
    });
  }

  function initMenu() {
    if (!menuBtn || !menu) return;
    function closeMenu() {
      menu.classList.remove('open');
      menuBtn.setAttribute('aria-expanded', 'false');
    }
    menuBtn.addEventListener('click', (event) => {
      event.preventDefault();
      const isOpen = menu.classList.toggle('open');
      menuBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });
    document.addEventListener('click', (event) => {
      if (!menu.contains(event.target) && event.target !== menuBtn) {
        closeMenu();
      }
    });
    menu.addEventListener('click', () => closeMenu());
  }

  function init() {
    if (!window.themeManager) return;
    themeManager.ensureThemes().then((themes) => {
      renderThemes(themes);
      return themeManager.applySavedTheme();
    }).catch((err) => console.error(err));

    if (resetBtn) {
      resetBtn.addEventListener('click', () => themeManager.reset());
    }

    initMenu();
  }

  init();
})();
