async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) return;
        const data = await response.json();
        document.getElementById('hashrate').textContent = data.hashrate.toFixed(2) + ' H/s';
        document.getElementById('hashes').textContent = data.hashes_total;
        document.getElementById('pool').textContent = data.pool;
        document.getElementById('connected').textContent = data.connected ? 'Yes' : 'No';
        document.getElementById('shares_accepted').textContent = data.shares.accepted;
        document.getElementById('shares_rejected').textContent = data.shares.rejected;
        document.getElementById('shares_dev_accepted').textContent = data.shares.dev_accepted;
        document.getElementById('shares_dev_rejected').textContent = data.shares.dev_rejected;
    } catch (err) {
        console.error('Failed to fetch stats', err);
    }
}

setInterval(fetchStats, 1000);
fetchStats();
