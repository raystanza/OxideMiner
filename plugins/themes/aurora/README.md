# Aurora theme (reference)

A reference dashboard theme that demonstrates:

- Safe HTML override (`theme.html`) that mirrors the bundled dashboard structure.
- CSS variables and lightweight glow/glass effects.
- Theme-specific wrapper layers that do not break required dashboard IDs.

## Files

- `theme.json` — manifest with entry points for CSS/JS/HTML.
- `theme.css` — aurora gradients, glassmorphism, and badges.
- `theme.js` — tiny banner indicating the theme is active.
- `theme.html` — dashboard entrypoint override; keeps required containers and script tags.
- `preview.png` — visual preview for the themes gallery.

## Notes for modders

- Keep the required elements intact: `#loading-overlay`, `#theme-root`, metric cards with their IDs, and the two scripts (`/theme-manager.js`, `/dashboard.js`).
- You can add wrapper layers (like the `.aurora-backdrop`) as long as they do not block interactions.
- If you add more assets, place them next to the manifest and reference them with relative paths inside the folder.
