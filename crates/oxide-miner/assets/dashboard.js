async function update() {
  try {
    const resp = await fetch('/api/stats');
    const j = await resp.json();
    document.getElementById('hashrate').textContent = j.hashrate.toFixed(2) + ' H/s';
    document.getElementById('hashes_total').textContent = j.hashes_total;
    document.getElementById('pool').textContent = j.pool;
    document.getElementById('connection').textContent = j.connected ? 'Connected' : 'Disconnected';
    document.getElementById('shares_accepted').textContent = j.shares.accepted;
    document.getElementById('shares_rejected').textContent = j.shares.rejected;
    document.getElementById('shares_dev_accepted').textContent = j.shares.dev_accepted;
    document.getElementById('shares_dev_rejected').textContent = j.shares.dev_rejected;
  } catch (err) {
    console.error('Failed to fetch stats', err);
  }
}

setInterval(update, 1000);
update();
