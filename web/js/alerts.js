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
                <p>Sem alertas ativos</p>
            </div>`;
        return;
    }

    container.innerHTML = alerts.map(alert => `
        <div class="alert-card ${alert.tipo_alerta === 'HIGH' ? 'high-card' : ''}" id="alert-card-${alert.id_alerta}">
            <div class="alert-card-icon">${alert.tipo_alerta === 'CRITICAL' ? '🔴' : '🔶'}</div>
            <div class="alert-card-info">
                <div class="alert-card-title">Alerta de Risco ${alert.tipo_alerta}</div>
                <div class="alert-card-meta">Alerta #${alert.id_alerta} · ${formatDate(alert.data_hora)}</div>
            </div>
            <div class="alert-card-actions">
                <button class="resolve-btn block-btn" onclick="blockSender(${alert.id_alerta})">
                    🚫 Bloquear
                </button>
                <button class="resolve-btn" onclick="resolveAlert(${alert.id_alerta})">
                    ✅ Resolver
                </button>
            </div>
        </div>
    `).join('');
}

// ─── Table ───
function renderAlertsTable(alerts) {
    const tbody = document.getElementById('alerts-body');

    if (!alerts.length) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px;">Sem alertas ainda</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(alert => `
        <tr>
            <td class="text-muted text-sm">#${alert.id_alerta}</td>
            <td>${getTypeBadge(alert.tipo_alerta)}</td>
            <td>${getStatusBadge(alert.estado_alerta)}</td>
            <td class="text-muted text-sm">${formatDate(alert.data_hora)}</td>
            <td>
                ${alert.estado_alerta === 'ACTIVE' ? `
                    <button class="resolve-btn block-btn" onclick="blockSender(${alert.id_alerta})" style="margin-right:4px">
                        🚫 Bloquear
                    </button>
                    <button class="resolve-btn" onclick="resolveAlert(${alert.id_alerta})">
                        ✅ Resolver
                    </button>
                ` : '<span class="text-muted text-sm">—</span>'}
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

        if (response.ok) loadAlerts();
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

// ─── Block Sender ───
// ─── Block Sender ───
function blockSender(id_alerta) {
    // Show custom modal instead of confirm()
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'block-modal';
    modal.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <div class="modal-icon">🚫</div>
                <div>
                    <div class="modal-title">Bloquear Remetente</div>
                    <div class="modal-subtitle">Esta ação não pode ser desfeita facilmente</div>
                </div>
            </div>

            <div class="modal-ai-verdict">
                ⚠️ Todos os emails futuros deste remetente serão marcados automaticamente como <strong>PHISHING</strong> com score 100.
            </div>

            <div class="modal-footer" style="gap:12px;">
                <button class="btn btn-secondary" onclick="closeBlockModal()">Cancelar</button>
                <button class="btn btn-danger" onclick="confirmBlock(${id_alerta})">🚫 Bloquear</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
    modal.addEventListener('click', function(e) {
        if (e.target === modal) closeBlockModal();
    });
}

function closeBlockModal() {
    const modal = document.getElementById('block-modal');
    if (modal) modal.remove();
}

async function confirmBlock(id_alerta) {
    closeBlockModal();
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/alerts/${id_alerta}/block`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Show success modal
            const successModal = document.createElement('div');
            successModal.className = 'modal-overlay';
            successModal.id = 'success-modal';
            successModal.innerHTML = `
                <div class="modal">
                    <div class="modal-header">
                        <div class="modal-icon">✅</div>
                        <div>
                            <div class="modal-title">Remetente Bloqueado</div>
                            <div class="modal-subtitle">Bloqueado com sucesso</div>
                        </div>
                    </div>
                    <div class="modal-ai-verdict">
                        🚫 <strong>${data.sender}</strong> foi adicionado à lista negra. Todos os emails futuros deste remetente serão automaticamente marcados como PHISHING.
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary" onclick="document.getElementById('success-modal').remove(); loadAlerts();">Percebido</button>
                    </div>
                </div>
            `;
            document.body.appendChild(successModal);
        } else {
            alert(data.detail || 'Erro ao bloquear remetente.');
        }
    } catch (err) {
        alert('Não foi possível bloquear o remetente.');
    }
}

// ─── Badges ───
function getTypeBadge(type) {
    if (type === 'CRITICAL') return '<span class="badge badge-critical">CRÍTICO</span>';
    if (type === 'HIGH')     return '<span class="badge badge-high">ALTO</span>';
    return `<span class="badge">${type}</span>`;
}

function getStatusBadge(status) {
    if (status === 'ACTIVE')   return '<span class="badge badge-critical">ATIVO</span>';
    if (status === 'RESOLVED') return '<span class="badge badge-low">RESOLVIDO</span>';
    return status;
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString('pt-PT', {
        day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
    });
}

document.addEventListener('DOMContentLoaded', () => {
    loadUser();
    loadAlerts();
    setInterval(loadAlerts, 20000);
});