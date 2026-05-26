
// ─────────────────────────────────────────
// NEAP — Alerts Page Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";
let allAlerts = [];
let currentFilter = 'ALL';

function checkAuth() {
    const token = localStorage.getItem('neap-token');
    if (!token) { window.location.href = 'login.html'; return null; }
    return token;
}

function loadUser() {
    const username = localStorage.getItem('neap-user') || 'Admin';
    document.getElementById('user-name').textContent = username;
    document.getElementById('user-avatar').textContent = username.charAt(0).toUpperCase();
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('collapsed');
    document.getElementById('main-content').classList.toggle('expanded');
}

function toggleSettings() {
    document.getElementById('settings-submenu').classList.toggle('open');
    document.getElementById('settings-chevron').classList.toggle('open');
}

function handleLogout() {
    localStorage.removeItem('neap-token');
    localStorage.removeItem('neap-user');
    window.location.href = 'login.html';
}

// ─── Load Alerts ───
async function loadAlerts() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/alerts`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success) {
            allAlerts = data.date.alerts || [];
            updateStats();
            renderAlertCards(allAlerts.filter(a => a.estado_alerta === 'ACTIVE'));
            renderAlertsTable(allAlerts);
        }
    } catch (err) {
        console.error('Load alerts error:', err);
    }
}

// ─── Stats ───
function updateStats() {
    document.getElementById('count-active').textContent   = allAlerts.filter(a => a.estado_alerta === 'ACTIVE').length;
    document.getElementById('count-resolved').textContent = allAlerts.filter(a => a.estado_alerta === 'RESOLVED').length;
    document.getElementById('count-critical').textContent = allAlerts.filter(a => a.tipo_alerta === 'CRITICAL').length;
}

// ─── Alert Cards ───
function renderAlertCards(alerts) {
    const container = document.getElementById('alerts-container');

    if (!alerts.length) {
        container.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="1.5" width="48" height="48" stroke="var(--text-muted)">
                    <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                    <path d="M13.73 21a2 2 0 01-3.46 0"/>
                </svg>
                <p>No active alerts</p>
            </div>`;
        return;
    }

    container.innerHTML = alerts.map(alert => `
        <div class="alert-card ${alert.tipo_alerta === 'HIGH' ? 'high-card' : ''}" id="alert-card-${alert.id_alerta}">
            <div class="alert-card-icon">${alert.tipo_alerta === 'CRITICAL' ? '🔴' : '🔶'}</div>
            <div class="alert-card-info">
                <div class="alert-card-title">${alert.tipo_alerta} Risk Alert</div>
                <div class="alert-card-meta">Alert #${alert.id_alerta} · ${formatDate(alert.data_hora)}</div>
            </div>
            <div class="alert-card-actions">
                <button class="resolve-btn" onclick="resolveAlert(${alert.id_alerta})">Resolve</button>
            </div>
        </div>
    `).join('');
}

// ─── Table ───
function renderAlertsTable(alerts) {
    const tbody = document.getElementById('alerts-body');

    if (!alerts.length) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">No alerts yet</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(alert => `
        <tr>
            <td class="text-muted text-sm">#${alert.id_alerta}</td>
            <td>${getTypeBadge(alert.tipo_alerta)}</td>
            <td>${getStatusBadge(alert.estado_alerta)}</td>
            <td class="text-muted text-sm">${formatDate(alert.data_hora)}</td>
            <td>
                ${alert.estado_alerta === 'ACTIVE'
                    ? `<button class="resolve-btn" onclick="resolveAlert(${alert.id_alerta})">Resolve</button>`
                    : '<span class="text-muted text-sm">—</span>'
                }
            </td>
        </tr>
    `).join('');
}

// ─── Filter ───
function filterAlerts(btn, filter) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = filter;

    const filtered = filter === 'ALL' ? allAlerts : allAlerts.filter(a => a.estado_alerta === filter);
    renderAlertsTable(filtered);
}

// ─── Resolve ───
async function resolveAlert(id) {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/alerts/${id}/resolve`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            loadAlerts();
        }
    } catch (err) {
        console.error('Resolve error:', err);
    }
}

async function resolveAll() {
    const token = checkAuth();
    if (!token) return;

    try {
        await fetch(`${API_URL}/dashboard/alerts/resolve-all`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        loadAlerts();
    } catch (err) {
        console.error('Resolve all error:', err);
    }
}

function getTypeBadge(type) {
    if (type === 'CRITICAL') return '<span class="badge badge-critical">CRITICAL</span>';
    if (type === 'HIGH')     return '<span class="badge badge-high">HIGH</span>';
    return `<span class="badge">${type}</span>`;
}

function getStatusBadge(status) {
    if (status === 'ACTIVE')   return '<span class="badge badge-critical">ACTIVE</span>';
    if (status === 'RESOLVED') return '<span class="badge badge-low">RESOLVED</span>';
    return status;
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString('en-GB', {
        day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
    });
}

document.addEventListener('DOMContentLoaded', () => {
    loadUser();
    loadAlerts();
    setInterval(loadAlerts, 20000);
});