async function update() {
    try {
        const resp = await fetch('/api/stats');
        const data = await resp.json();
        document.getElementById('pool').textContent = data.pool;
        document.getElementById('status').textContent = data.connected ? 'Connected' : 'Disconnected';
        document.getElementById('hashrate').textContent = data.hashrate.toFixed(2);
        document.getElementById('hashes').textContent = data.hashes_total;
        document.getElementById('accepted').textContent = data.shares.accepted;
        document.getElementById('rejected').textContent = data.shares.rejected;
        document.getElementById('dev_accepted').textContent = data.shares.dev_accepted;
        document.getElementById('dev_rejected').textContent = data.shares.dev_rejected;
    } catch (e) {
        console.error('Failed to fetch stats', e);
    }
}

setInterval(update, 1000);
update();
