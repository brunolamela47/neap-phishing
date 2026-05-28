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
            showAIModal({
                final_score:     data.date.final_score,
                risk_level:      data.date.risk_level,
                result:          data.date.result,
                heuristic_score: data.date.heuristic_score,
                ml_score:        data.date.ml_score || 0,
                ai_score:        data.date.ai_score || 0,
                ai_details:      data.date.ai_details || {}
            });
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
        'LOW':      { emoji: '✅', class: 'low',      label: 'Email Legítimo' },
        'MEDIUM':   { emoji: '⚠️', class: 'medium',   label: 'Email Suspeito' },
        'HIGH':     { emoji: '🔶', class: 'high',     label: 'Provável Phishing' },
        'CRITICAL': { emoji: '🔴', class: 'critical', label: 'Phishing Detetado' },
    };

    const risk = riskMap[result.risk_level] || { emoji: '?', class: '', label: result.result };

    card.className = `card result-card show ${risk.class}`;
    icon.textContent = risk.emoji;
    title.textContent = risk.label;
    subtitle.textContent = `Nível de Risco: ${result.risk_level} · Resultado: ${result.result}`;
    score.textContent = result.final_score;
    bar.style.width = `${result.final_score}%`;

    const keywords = result.details?.keyword_analysis?.found_keywords || [];
    const urls     = result.details?.url_analysis?.found_patterns || [];

    details.innerHTML = [
        `<span class="detail-tag">Heurística: ${result.heuristic_score}</span>`,
        `<span class="detail-tag">Penalidade Auth: +${result.auth_penalty}</span>`,
        `<span class="detail-tag">Palavras suspeitas: ${keywords.length}</span>`,
        `<span class="detail-tag">URLs suspeitos: ${urls.length}</span>`,
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
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:32px;">Sem emails ainda</td></tr>`;
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
            <td>
                <button class="btn-ai" onclick="loadAIModal(${e.id_email})">
                    🤖 IA
                </button>
            </td>
        </tr>
    `).join('');
}

// ─── Load AI Modal from DB ───
async function loadAIModal(id_email) {
    const token = checkAuth();

    try {
        const response = await fetch(`${API_URL}/emails/${id_email}/ai`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success) {
            const d = data.date;

            let reasons = [];
            try {
                let cleaned = d.ai_reasons || '[]';
                cleaned = cleaned.replace(/'/g, '"');
                reasons = JSON.parse(cleaned);
            } catch {
                reasons = d.ai_reasons ? [d.ai_reasons] : [];
            }

            const resultToRisk = {
                'PHISHING':        'CRITICAL',
                'LIKELY PHISHING': 'HIGH',
                'SUSPICIOUS':      'MEDIUM',
                'LEGITIMATE':      'LOW'
            };

            const risk_level = d.nivel_risco || resultToRisk[d.resultado] || 'MEDIUM';

            showAIModal({
                final_score:     d.score || 0,
                risk_level:      risk_level,
                result:          d.resultado || 'UNKNOWN',
                heuristic_score: 0,
                ml_score:        0,
                ai_score:        d.ai_confidence || 0,
                ai_details: {
                    available:            true,
                    verdict:              d.ai_verdict || d.resultado,
                    confidence:           d.ai_confidence || 0,
                    reasons:              reasons,
                    risk_indicators:      [],
                    impersonated_company: d.impersonated_company || null,
                    official_domain:      d.official_domain || null,
                    sender_domain:        d.sender_domain || null,
                    domain_match:         d.domain_match ?? null
                }
            });
        }
    } catch (err) {
        console.error('AI modal error:', err);
        alert('Não foi possível carregar a análise de IA.');
    }
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
    if (result === 'PHISHING')        return '<span class="badge badge-critical">PHISHING</span>';
    if (result === 'LIKELY PHISHING') return '<span class="badge badge-high">LIKELY PHISHING</span>';
    if (result === 'LEGITIMATE')      return '<span class="badge badge-low">LEGITIMATE</span>';
    if (result === 'SUSPICIOUS')      return '<span class="badge badge-medium">SUSPICIOUS</span>';
    return result;
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString('pt-PT', {
        day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
    });
}

// ─── IMAP ───
function showImapForm() {
    document.getElementById('imap-form').classList.add('show');
    document.getElementById('analyze-form').classList.remove('show');
}

function hideImapForm() {
    document.getElementById('imap-form').classList.remove('show');
}

function toggleImapPassword() {
    const input = document.getElementById('imap-password');
    input.type = input.type === 'password' ? 'text' : 'password';
}

async function handleImap() {
    const token    = checkAuth();
    const email    = document.getElementById('imap-email').value.trim();
    const password = document.getElementById('imap-password').value;
    const limit    = document.getElementById('imap-limit').value;
    const btn      = document.getElementById('imap-btn');

    if (!email || !password) {
        alert('Por favor preenche todos os campos.');
        return;
    }

    btn.textContent = 'A ligar...';
    btn.classList.add('loading');

    try {
        const response = await fetch(`${API_URL}/emails/imap`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ email, password, limit: parseInt(limit) })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(`✅ ${data.date.count} emails analisados com sucesso!`);
            hideImapForm();
            loadEmails();
        } else {
            alert(data.detail || 'Falha na ligação IMAP.');
        }

    } catch (err) {
        alert('Não foi possível ligar ao servidor.');
    }

    btn.textContent = 'Buscar & Analisar';
    btn.classList.remove('loading');
}

// ─── Show AI Modal ───
function showAIModal(result) {
    const riskMap = {
        'LOW':      { emoji: '✅', color: '#10b981', label: 'Email Legítimo' },
        'MEDIUM':   { emoji: '⚠️', color: '#f59e0b', label: 'Email Suspeito' },
        'HIGH':     { emoji: '🔶', color: '#f97316', label: 'Provável Phishing' },
        'CRITICAL': { emoji: '🔴', color: '#ef4444', label: 'Phishing Detetado' },
    };

    const risk      = riskMap[result.risk_level] || { emoji: '❓', color: '#6366f1', label: result.result };
    const aiDetails = result.ai_details || {};
    const reasons   = aiDetails.reasons || [];
    const indicators = aiDetails.risk_indicators || [];
    const aiVerdict  = aiDetails.verdict || result.result;
    const aiConf     = aiDetails.confidence || 0;

    let explanation = "";
    if (aiVerdict === "PHISHING") {
        explanation = `Este email é <strong>phishing</strong> com ${aiConf}% de confiança.`;
    } else {
        explanation = `Este email parece <strong>legítimo</strong> com ${aiConf}% de confiança.`;
    }

    if (reasons.length > 0 && typeof reasons[0] === 'string') {
        explanation += ` ${reasons[0]}`;
    }

    const reasonsHTML = [...reasons, ...indicators]
        .filter(r => typeof r === 'string')
        .map(r => `
            <div class="modal-reason">
                <span class="modal-reason-dot"></span>
                <span>${r}</span>
            </div>
        `).join('');

    // Domain verification block
    const domainHTML = aiDetails.impersonated_company ? `
        <div class="modal-domain-check">
            <div class="domain-row">
                <span class="domain-label">Empresa impersonada:</span>
                <span class="domain-value">${aiDetails.impersonated_company}</span>
            </div>
            <div class="domain-row">
                <span class="domain-label">Domínio oficial:</span>
                <span class="domain-value domain-official">${aiDetails.official_domain || '—'}</span>
            </div>
            <div class="domain-row">
                <span class="domain-label">Domínio do remetente:</span>
                <span class="domain-value ${aiDetails.domain_match ? 'domain-match' : 'domain-mismatch'}">
                    ${aiDetails.sender_domain || '—'} ${aiDetails.domain_match ? '✅' : '❌'}
                </span>
            </div>
        </div>
    ` : '';

    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'ai-modal';
    modal.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <div class="modal-icon">${risk.emoji}</div>
                <div>
                    <div class="modal-title">${risk.label}</div>
                    <div class="modal-subtitle">Análise de IA concluída</div>
                </div>
            </div>

            <div class="modal-score">
                <div class="modal-score-value" style="color:${risk.color}">${result.final_score}</div>
                <div class="modal-score-info">
                    <span class="modal-score-label">Score de Phishing</span>
                    <div class="score-bar">
                        <div class="score-bar-fill" style="width:${result.final_score}%"></div>
                    </div>
                </div>
            </div>

            <div class="modal-ai-verdict">
                🤖 <strong>Análise IA:</strong> ${explanation}
            </div>

            ${domainHTML}

            <div class="modal-layers">
                <div class="modal-layer">
                    <span class="modal-layer-label">Heurística</span>
                    <span class="modal-layer-value">${result.heuristic_score || 0}</span>
                </div>
                <div class="modal-layer">
                    <span class="modal-layer-label">Modelo ML</span>
                    <span class="modal-layer-value">${Math.round(result.ml_score || 0)}</span>
                </div>
                <div class="modal-layer">
                    <span class="modal-layer-label">Score IA</span>
                    <span class="modal-layer-value">${Math.round(result.ai_score || 0)}</span>
                </div>
            </div>

            ${reasonsHTML ? `<div class="modal-reasons">${reasonsHTML}</div>` : ''}

            <div class="modal-footer">
                <button class="btn btn-primary" onclick="closeAIModal()">Percebido</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
    modal.addEventListener('click', function(e) {
        if (e.target === modal) closeAIModal();
    });
}

function closeAIModal() {
    const modal = document.getElementById('ai-modal');
    if (modal) modal.remove();
}

document.addEventListener('DOMContentLoaded', () => {
    loadUser();
    loadEmails();
});