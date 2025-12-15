# Web3 Glass theme

Dark neon gradients with glassy cards and a subtle grid backdrop.

## Files

- `theme.json` — manifest with CSS/HTML entry points.
- `theme.css` — glassmorphism styles and neon palette.
- `theme.html` — dashboard override preserving required IDs/scripts.
- `preview.png` — preview for the themes gallery.

## Notes

- Body uses `data-theme="web3"` to scope styles.
- Background layers `.web3-gradient` and `.web3-grid` are decorative and non-interactive.
- Keep the two script tags (`/theme-manager.js` and `/dashboard.js`) untouched so the dashboard logic loads.
