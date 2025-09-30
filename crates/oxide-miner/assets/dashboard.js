function formatHashrate(hps) {
    // hps = hashes per second (Number)
    if (!Number.isFinite(hps)) return '-';
    if (hps >= 1e9) { // 1,000,000,000 H/s -> GH/s
        return (hps / 1e9).toFixed(3) + ' GH/s';
    }
    if (hps >= 1e3) { // 1,000 H/s -> KH/s
        return (hps / 1e3).toFixed(3) + ' KH/s';
    }
    return hps.toFixed(2) + ' H/s';
}

const intFmt = new Intl.NumberFormat('en-US');

async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        document.getElementById('hashrate').textContent = formatHashrate(Number(data.hashrate));
        document.getElementById('hashes').textContent = intFmt.format(Number(data.hashes_total));
        document.getElementById('accepted').textContent = data.shares.accepted;
        document.getElementById('rejected').textContent = data.shares.rejected;
        document.getElementById('dev_accepted').textContent = data.shares.dev_accepted;
        document.getElementById('dev_rejected').textContent = data.shares.dev_rejected;
        const poolEl = document.getElementById('pool');
        poolEl.textContent = data.pool || '-';
        poolEl.title = data.pool || '';

        document.getElementById('connected').textContent = data.connected ? 'Yes' : 'No';
        document.getElementById('tls').textContent = data.tls ? 'Yes' : 'No';
    } catch (e) {
        console.error('Failed to fetch stats', e);
    }
}

setInterval(fetchStats, 1000);
fetchStats();
