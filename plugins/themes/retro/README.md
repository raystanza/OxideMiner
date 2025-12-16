# Retro CRT theme

Classic terminal vibe with green phosphor accents and a subtle scanline overlay.

## Files

- `theme.json` — manifest with CSS/HTML entry points.
- `theme.css` — CRT palette, scanlines, monospace type.
- `theme.html` — dashboard override preserving required IDs/scripts.
- `preview.png` — preview for the themes gallery.

## Notes

- Body uses `data-theme="retro"` to scope styles.
- The `.crt-overlay` is decorative and pointer-events are disabled to avoid blocking the UI.
- Keep `/theme-manager.js` and `/dashboard.js` script tags intact.
