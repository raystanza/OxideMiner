(function () {
  const banner = document.createElement('div');
  banner.textContent = 'Aurora theme active';
  banner.style.position = 'fixed';
  banner.style.bottom = '16px';
  banner.style.right = '16px';
  banner.style.padding = '10px 14px';
  banner.style.borderRadius = '12px';
  banner.style.background = 'linear-gradient(135deg, rgba(124,254,255,0.25), rgba(204,102,255,0.25))';
  banner.style.color = '#d9e8ff';
  banner.style.fontWeight = '600';
  banner.style.boxShadow = '0 10px 30px rgba(0,0,0,0.35)';
  banner.style.zIndex = '50';
  banner.id = 'aurora-theme-banner';

  document.addEventListener('DOMContentLoaded', () => {
    const existing = document.getElementById('aurora-theme-banner');
    if (!existing) {
      document.body.appendChild(banner);
      setTimeout(() => banner.remove(), 4000);
    }
  });
})();
