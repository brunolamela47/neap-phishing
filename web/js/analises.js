// ─────────────────────────────────────────
// NEAP — Análises Page Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";
let allAnalises = [];
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

// ─── Load Analises ───
async function loadAnalises() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/emails/`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success) {
            allAnalises = data.date.emails || [];
            updateStats();
            renderAnalises(allAnalises);
        }
    } catch (err) {
        console.error('Load analises error:', err);
    }
}

// ─── Update Stats ───
function updateStats() {
    document.getElementById('count-low').textContent      = allAnalises.filter(e => e.nivel_risco === 'LOW').length;
    document.getElementById('count-medium').textContent   = allAnalises.filter(e => e.nivel_risco === 'MEDIUM').length;
    document.getElementById('count-high').textContent     = allAnalises.filter(e => e.nivel_risco === 'HIGH').length;
    document.getElementById('count-critical').textContent = allAnalises.filter(e => e.nivel_risco === 'CRITICAL').length;
}

// ─── Filter ───
function filterByRisk(btn, risk) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = risk;
    applyFilters();
}

function searchAnalises(query) {
    applyFilters(query);
}

function applyFilters(query = '') {
    let filtered = allAnalises;

    if (currentFilter !== 'ALL') {
        filtered = filtered.filter(e => e.nivel_risco === currentFilter);
    }

    if (query) {
        filtered = filtered.filter(e =>
            e.remetente.toLowerCase().includes(query.toLowerCase()) ||
            e.assunto.toLowerCase().includes(query.toLowerCase())
        );
    }

    renderAnalises(filtered);
}

// ─── Render ───
function renderAnalises(list) {
    const tbody = document.getElementById('analises-body');

    if (!list.length) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text-muted);padding:32px;">No analyses found</td></tr>`;
        return;
    }

    tbody.innerHTML = list.map(e => `
        <tr>
            <td class="text-muted text-sm">#${e.id_email}</td>
            <td class="mono text-sm">${e.remetente}</td>
            <td>${e.assunto}</td>
            <td><strong>${e.score}</strong></td>
            <td class="text-muted text-sm">—</td>
            <td class="text-muted text-sm">—</td>
            <td>${getRiskBadge(e.nivel_risco)}</td>
            <td>${getResultBadge(e.resultado)}</td>
            <td class="text-muted text-sm">${formatDate(e.data_hora)}</td>
        </tr>
    `).join('');
}

function getRiskBadge(risk) {
    const map = {
        'LOW':      '<span class="badge badge-low">LOW</span>',
        'MEDIUM':   '<span class="badge badge-medium">MEDIUM</span>',
        'HIGH':     '<span class="badge badge-high">HIGH</span>',
        'CRITICAL': '<span class="badge badge-critical">CRITICAL</span>',
    };
    return map[risk] || risk;
}

function getResultBadge(result) {
    if (result === 'PHISHING')   return '<span class="badge badge-critical">PHISHING</span>';
    if (result === 'LEGITIMATE') return '<span class="badge badge-low">LEGITIMATE</span>';
    if (result === 'SUSPICIOUS') return '<span class="badge badge-medium">SUSPICIOUS</span>';
    return result;
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString('en-GB', {
        day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
    });
}

document.addEventListener('DOMContentLoaded', () => {
    loadUser();
    loadAnalises();
});
