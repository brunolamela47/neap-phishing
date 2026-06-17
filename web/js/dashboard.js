// ─────────────────────────────────────────
// NEAP — Dashboard Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";
let emailChart = null;
let riskChart = null;
let ws = null;
// ─── Auth Check ───
function checkAuth() {
    const token = localStorage.getItem('neap-token');
    if (!token) {
        window.location.href = 'login.html';
        return null;
    }
    return token;
}

function connectWebSocket() {
    ws = new WebSocket('ws://localhost:8000/ws');

    ws.onopen = () => {
        console.log('WebSocket connected');
        updateLiveIndicator(true);
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'phishing_alert') {
            // Flash dashboard
            showLiveAlert(data);
            // Refresh stats
            loadStats();
        }
    };

    ws.onclose = () => {
        console.log('WebSocket disconnected — reconnecting...');
        updateLiveIndicator(false);
        setTimeout(connectWebSocket, 3000); // Reconnect after 3s
    };

    ws.onerror = (err) => {
        console.error('WebSocket error:', err);
    };
}

function showLiveAlert(data) {
    // Create flash notification on dashboard
    const alert = document.createElement('div');
    alert.className = 'live-alert';
    alert.innerHTML = `
        <div class="live-alert-content">
            <span class="live-alert-icon">🚨</span>
            <div>
                <strong>Phishing Detetado — ${data.nivel}</strong>
                <div class="text-sm">De: ${data.remetente} · Score: ${data.score}/100</div>
            </div>
            <button onclick="this.parentElement.parentElement.remove()">✕</button>
        </div>
    `;
    document.body.appendChild(alert);

    // Auto remove after 5 seconds
    setTimeout(() => alert.remove(), 5000);
}

function updateLiveIndicator(connected) {
    const dot = document.querySelector('.live-dot');
    if (dot) {
        dot.style.background = connected ? '#10b981' : '#ef4444';
    }
}

// ─── Load User ───
function loadUser() {
    const username = localStorage.getItem('neap-user') || 'Admin';
    document.getElementById('user-name').textContent = username;
    document.getElementById('user-avatar').textContent = username.charAt(0).toUpperCase();
}

// ─── Sidebar Toggle ───
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const main    = document.getElementById('main-content');
    sidebar.classList.toggle('collapsed');
    main.classList.toggle('expanded');
}

// ─── Settings Dropdown ───
function toggleSettings() {
    const submenu  = document.getElementById('settings-submenu');
    const chevron  = document.getElementById('settings-chevron');
    submenu.classList.toggle('open');
    chevron.classList.toggle('open');
}

// ─── Chart Filter ───
function setFilter(btn, period) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    loadChartData(period);
}

// ─── Load Dashboard Data ───
async function loadDashboard() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/stats`, {
            headers: { "Authorization": `Bearer ${token}` }
        });

        if (response.status === 401) {
            window.location.href = 'login.html';
            return;
        }

        const data = await response.json();

        if (data.success) {
            const d = data.date;

            // Update metric cards
           animateNumber('total-emails',   d.total_emails   || 0);
animateNumber('total-phishing', d.total_phishing || 0);
animateNumber('total-legit',    d.total_legit    || 0);
animateNumber('avg-score',      d.avg_score      || 0);

// Trends
document.getElementById('trend-total').textContent    = d.trend_total    || '+0%';
document.getElementById('trend-phishing').textContent = d.trend_phishing || '+0%';
document.getElementById('trend-legit').textContent    = d.trend_legit    || '+0%';

// Score bar
document.getElementById('score-bar-fill').style.width = `${d.avg_score || 0}%`;

            // Alert badge
            const badge = document.getElementById('alert-badge');
            badge.textContent = d.total_alerts || 0;
            badge.dataset.count = d.total_alerts || 0;

            // Recent emails table
            renderRecentEmails(d.recent_emails || []);
        }
    } catch (err) {
        console.error('Dashboard load error:', err);
    }
}

// ─── Animate Number ───
function animateNumber(id, target) {
    const el    = document.getElementById(id);
    const start = 0;
    const duration = 800;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed  = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const value    = Math.floor(progress * target);
        el.textContent = value;
        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

// ─── Render Recent Emails ───
function renderRecentEmails(emails) {
    const tbody = document.getElementById('recent-emails-body');

    if (!emails.length) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:32px;">No emails analyzed yet</td></tr>`;
        return;
    }

    tbody.innerHTML = emails.map(email => `
        <tr>
            <td class="mono text-sm">${email.remetente}</td>
            <td>${email.assunto}</td>
            <td><strong>${email.score}</strong></td>
            <td>${getRiskBadge(email.nivel_risco)}</td>
            <td>${getResultBadge(email.resultado)}</td>
            <td class="text-muted text-sm">${formatDate(email.data_hora)}</td>
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

// ─── Load Chart Data ───
async function loadChartData(period = '7d') {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/chart?period=${period}`, {
            headers: { "Authorization": `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success) {
            renderEmailChart(data.date.labels, data.date.phishing, data.date.legitimate);
        }
    } catch (err) {
        renderEmailChart([], [], []);
    }
}

// ─── Render Email Chart ───
function renderEmailChart(labels, phishing, legitimate) {
    const ctx = document.getElementById('emailChart').getContext('2d');
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const gridColor = isDark ? '#2a2a2a' : '#f0f0f0';
    const textColor = isDark ? '#a0a0a0' : '#6b6b6b';

    if (emailChart) emailChart.destroy();

    emailChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels.length ? labels : ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],
            datasets: [
                {
                    label: 'Phishing',
                    data: phishing.length ? phishing : [0,0,0,0,0,0,0],
                    borderColor: '#ef4444',
                    backgroundColor: '#ef444415',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: '#ef4444',
                },
                {
                    label: 'Legitimate',
                    data: legitimate.length ? legitimate : [0,0,0,0,0,0,0],
                    borderColor: '#10b981',
                    backgroundColor: '#10b98115',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: '#10b981',
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
            },
            scales: {
                x: {
                    grid: { color: gridColor },
                    ticks: { color: textColor, font: { size: 11 } }
                },
                y: {
                    grid: { color: gridColor },
                    ticks: { color: textColor, font: { size: 11 }, stepSize: 1 },
                    beginAtZero: true
                }
            }
        }
    });
}

// ─── Render Risk Chart ───
function renderRiskChart(low=0, medium=0, high=0, critical=0) {
    const ctx = document.getElementById('riskChart').getContext('2d');

    if (riskChart) riskChart.destroy();

    riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: [low, medium, high, critical],
                backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#ef4444'],
                borderWidth: 0,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            cutout: '65%'
        }
    });
}

// ─── Export Logs ───
async function exportLogs(format) {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/export/save?format=${format}`, {
            headers: { "Authorization": `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success) {
            alert(`✅ Ficheiro guardado no Ambiente de Trabalho!\n\n${data.path}`);
        } else {
            alert('Erro ao guardar ficheiro.');
        }

    } catch (err) {
        console.error('Export error:', err);
        alert('Erro ao exportar.');
    }
}
// ─── Logout ───
async function handleLogout() {
    // Clear session file
    await fetch("http://localhost:8000/auth/clear-session", { method: "POST" });
    localStorage.removeItem('neap-token');
    localStorage.removeItem('neap-user');
    localStorage.removeItem('neap-remember');
    window.location.href = 'login.html';
}

// ─── Init ───
document.addEventListener('DOMContentLoaded', () => {
    loadUser();
    loadDashboard();
    connectWebSocket();
    setInterval(loadStats, 30000);
    loadChartData('7d');
    renderRiskChart(0, 0, 0, 0);

    // Auto refresh every 30 seconds
    setInterval(loadDashboard, 30000);
});
