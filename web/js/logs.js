// ─────────────────────────────────────────
// NEAP — Logs Page Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";
let allLogs = [];

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

// ─── Load Logs ───
async function loadLogs() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/logs`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success) {
            allLogs = data.date.logs || [];
            renderTerminal(allLogs);
            renderLogs(allLogs);
        }
    } catch (err) {
        console.error('Load logs error:', err);
    }
}

// ─── Terminal View ───
function renderTerminal(logs) {
    const terminal = document.getElementById('terminal-body');

    if (!logs.length) {
        terminal.innerHTML = '<span class="terminal-placeholder">No logs found...</span>';
        return;
    }

    terminal.innerHTML = logs.map(log => `
        <span class="terminal-line">
            <span class="time">[${formatTime(log.data_hora)}]</span>
            <span class="event">${log.evento}</span>
            SPF:<span class="${getAuthClass(log.spf)}">${log.spf || 'NONE'}</span>
            DKIM:<span class="${getAuthClass(log.dkim)}">${log.dkim || 'NONE'}</span>
            DMARC:<span class="${getAuthClass(log.dmarc)}">${log.dmarc || 'NONE'}</span>
            ${log.ip_origem ? `IP:<span class="none">${log.ip_origem}</span>` : ''}
        </span>
    `).join('');

    terminal.scrollTop = terminal.scrollHeight;
}

function getAuthClass(val) {
    if (val === 'PASS') return 'pass';
    if (val === 'FAIL') return 'fail';
    return 'none';
}

// ─── Render Table ───
function renderLogs(logs) {
    const tbody = document.getElementById('logs-body');

    if (!logs.length) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:32px;">No logs yet</td></tr>`;
        return;
    }

    tbody.innerHTML = logs.map(log => `
        <tr>
            <td class="text-muted text-sm">#${log.id_log}</td>
            <td>${log.evento}</td>
            <td><span class="auth-${(log.spf || 'none').toLowerCase()}">${log.spf || 'NONE'}</span></td>
            <td><span class="auth-${(log.dkim || 'none').toLowerCase()}">${log.dkim || 'NONE'}</span></td>
            <td><span class="auth-${(log.dmarc || 'none').toLowerCase()}">${log.dmarc || 'NONE'}</span></td>
            <td class="mono text-sm">${log.ip_origem || '—'}</td>
            <td class="text-muted text-sm">${formatDate(log.data_hora)}</td>
        </tr>
    `).join('');
}

function searchLogs(query) {
    const filtered = allLogs.filter(log =>
        (log.evento || '').toLowerCase().includes(query.toLowerCase()) ||
        (log.ip_origem || '').toLowerCase().includes(query.toLowerCase())
    );
    renderLogs(filtered);
}

async function exportLogs(format) {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/export?format=${format}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const blob = await response.blob();
        const url  = window.URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = `neap-logs.${format}`;
        a.click();
        window.URL.revokeObjectURL(url);
    } catch (err) {
        alert('Export failed.');
    }
}

function formatTime(dateStr) {
    if (!dateStr) return '--:--:--';
    return new Date(dateStr).toLocaleTimeString('en-GB');
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString('en-GB', {
        day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
    });
}

document.addEventListener('DOMContentLoaded', () => {
    loadUser();
    loadLogs();
    setInterval(loadLogs, 15000);
});
