// ─────────────────────────────────────────
// NEAP — Emails Page Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";
let allEmails = [];

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

// ─── Form ───
function showAnalyzeForm() {
    document.getElementById('analyze-form').classList.add('show');
}

function hideAnalyzeForm() {
    document.getElementById('analyze-form').classList.remove('show');
    document.getElementById('result-card').classList.remove('show');
}

// ─── Analyze ───
async function handleAnalyze() {
    const token   = checkAuth();
    const sender  = document.getElementById('email-sender').value.trim();
    const subject = document.getElementById('email-subject').value.trim();
    const body    = document.getElementById('email-body').value.trim();
    const spf     = document.getElementById('email-spf').value;
    const dkim    = document.getElementById('email-dkim').value;
    const dmarc   = document.getElementById('email-dmarc').value;
    const btn     = document.getElementById('analyze-btn');

    if (!sender || !subject || !body) {
        alert('Please fill in all required fields.');
        return;
    }

    btn.textContent = 'Analyzing...';
    btn.classList.add('loading');

    try {
        const response = await fetch(`${API_URL}/emails/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ remetente: sender, assunto: subject, corpo: body, spf, dkim, dmarc })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showResult(data.date);
            loadEmails();
        } else {
            alert(data.detail || 'Analysis failed.');
        }

    } catch (err) {
        alert('Cannot connect to server.');
    }

    btn.textContent = 'Analyze Email';
    btn.classList.remove('loading');
}

// ─── Show Result ───
function showResult(result) {
    const card     = document.getElementById('result-card');
    const icon     = document.getElementById('result-icon');
    const title    = document.getElementById('result-title');
    const subtitle = document.getElementById('result-subtitle');
    const score    = document.getElementById('result-score');
    const bar      = document.getElementById('result-score-bar');
    const details  = document.getElementById('result-details');

    const riskMap = {
        'LOW':      { emoji: '✅', class: 'low',      label: 'Legitimate Email' },
        'MEDIUM':   { emoji: '⚠️', class: 'medium',   label: 'Suspicious Email' },
        'HIGH':     { emoji: '🔶', class: 'high',     label: 'Likely Phishing' },
        'CRITICAL': { emoji: '🔴', class: 'critical', label: 'Phishing Detected' },
    };

    const risk = riskMap[result.risk_level] || { emoji: '?', class: '', label: result.result };

    card.className = `card result-card show ${risk.class}`;
    icon.textContent = risk.emoji;
    title.textContent = risk.label;
    subtitle.textContent = `Risk Level: ${result.risk_level} · Result: ${result.result}`;
    score.textContent = result.final_score;
    bar.style.width = `${result.final_score}%`;

    const keywords = result.details?.keyword_analysis?.found_keywords || [];
    const urls     = result.details?.url_analysis?.found_patterns || [];

    details.innerHTML = [
        `<span class="detail-tag">Heuristic: ${result.heuristic_score}</span>`,
        `<span class="detail-tag">Auth Penalty: +${result.auth_penalty}</span>`,
        `<span class="detail-tag">Keywords: ${keywords.length}</span>`,
        `<span class="detail-tag">Suspicious URLs: ${urls.length}</span>`,
        ...keywords.slice(0, 5).map(k => `<span class="detail-tag">"${k}"</span>`)
    ].join('');
}

// ─── Load Emails ───
async function loadEmails() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/emails/`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success) {
            allEmails = data.date.emails || [];
            renderEmails(allEmails);
        }
    } catch (err) {
        console.error('Load emails error:', err);
    }
}

// ─── Render Emails ───
function renderEmails(emails) {
    const tbody = document.getElementById('emails-body');

    if (!emails.length) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:32px;">No emails yet</td></tr>`;
        return;
    }

    tbody.innerHTML = emails.map(e => `
        <tr>
            <td class="text-muted text-sm">#${e.id_email}</td>
            <td class="mono text-sm">${e.remetente}</td>
            <td>${e.assunto}</td>
            <td><strong>${e.score}</strong></td>
            <td>${getRiskBadge(e.nivel_risco)}</td>
            <td>${getResultBadge(e.resultado)}</td>
            <td class="text-muted text-sm">${formatDate(e.data_hora)}</td>
        </tr>
    `).join('');
}

function filterEmails(query) {
    const filtered = allEmails.filter(e =>
        e.remetente.toLowerCase().includes(query.toLowerCase()) ||
        e.assunto.toLowerCase().includes(query.toLowerCase())
    );
    renderEmails(filtered);
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
    loadEmails();
});
