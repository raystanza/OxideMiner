async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        document.getElementById('hashrate').textContent = data.hashrate.toFixed(2) + ' H/s';
        document.getElementById('hashes').textContent = data.hashes_total;
        document.getElementById('accepted').textContent = data.shares.accepted;
        document.getElementById('rejected').textContent = data.shares.rejected;
        document.getElementById('dev_accepted').textContent = data.shares.dev_accepted;
        document.getElementById('dev_rejected').textContent = data.shares.dev_rejected;
        document.getElementById('pool').textContent = data.pool;
        document.getElementById('connected').textContent = data.connected ? 'Yes' : 'No';
        document.getElementById('tls').textContent = data.tls ? 'Yes' : 'No';
    } catch (e) {
        console.error('Failed to fetch stats', e);
    }
}

setInterval(fetchStats, 1000);
fetchStats();
