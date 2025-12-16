# Dashboard theme plugins

OxideMiner can load dashboard-only themes from the repository without changing the miner binary. Themes live under `plugins/themes/<id>/` and are picked up at startup when the bundled dashboard is in use.

> Note: Because of 'quirks' your custom CSS needs to include a value for '--shadow-dark' and '--shadow-light'

## Directory layout

```bash
plugins/
  themes/
    aurora/
      theme.json
      theme.css
      theme.js        # optional
      theme.html      # optional
      preview.png     # optional (png/jpg/jpeg)
```

## Manifest (`theme.json`)

```json
{
  "id": "aurora",
  "name": "Aurora",
  "version": "1.0.0",
  "description": "Neon dashboard skin",
  "author": "you",
  "license": "MIT",
  "entry_css": "theme.css",
  "entry_js": ["theme.js"],
  "entry_html": "theme.html",
  "preview_image": "preview.png"
}
```

Required fields:

- `id`: matches the folder name; lowercase letters, digits, `.`, `_`, `-` only.
- `name`: display name.
- `version`: semantic version string.
- `entry_css`: relative path to the main stylesheet inside the theme folder.

Optional fields:

- `entry_js`: a string or list of JS files to load when the theme is active.
- `entry_html`: HTML fragment injected into `#theme-root` on the page.
- `preview_image`: preview path. If omitted, `preview.png|jpg|jpeg` is auto-detected at the theme root.
- `description`, `author`, `license` for display purposes.

## Safety & validation

- Paths must stay inside the theme directory; traversal or absolute paths are rejected.
- Malformed manifests are skipped with a warning instead of crashing the miner.
- Assets are served from `/plugins/themes/<id>/...` with content-type sniffing disabled.

## Using themes

1. Place the theme under `plugins/themes/`.
2. Start the miner with the default dashboard (`--api-port <port>` without `--dashboard-dir`).
3. Open the hamburger menu -> Plugins -> Themes (or visit `/plugins/themes`).
4. Apply a theme to load its CSS/JS/HTML immediately. Selection is stored in `localStorage` and mirrored to a cookie so reloads keep the chosen look.
5. Use "Reset to default" to return to the built-in Light/Dark/Monero options.

> The `--dashboard-dir` flag still serves an entirely custom dashboard. The plugin system only augments the bundled UI and will not replace a custom dashboard.

## Theme HTML overrides

When a theme includes `theme.html` (or declares `entry_html`), the default dashboard entrypoint (`/` or `/dashboard.html`) is served from that file whenever the theme is active. This only applies to the bundled dashboard; custom dashboards loaded via `--dashboard-dir` are never overridden.
