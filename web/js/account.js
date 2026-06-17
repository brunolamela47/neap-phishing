// ─────────────────────────────────────────
// NEAP — Account Page Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";

function checkAuth() {
    const token = localStorage.getItem('neap-token');
    if (!token) { window.location.href = 'login.html'; return null; }
    return token;
}

function loadUser() {
    const username = localStorage.getItem('neap-user') || 'Admin';
    document.getElementById('user-name').textContent = username;
    document.getElementById('user-avatar').textContent = username.charAt(0).toUpperCase();
    document.getElementById('account-username').textContent = username;
    document.getElementById('account-avatar').textContent = username.charAt(0).toUpperCase();
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('collapsed');
    document.getElementById('main-content').classList.toggle('expanded');
}

function handleLogout() {
    fetch(`${API_URL}/auth/clear-session`, { method: 'POST' });
    localStorage.clear();
    window.location.href = 'login.html';
}

// ─── Load Account Info ───
async function loadAccountInfo() {
    const token = checkAuth();
    if (!token) return;

    try {
        const statsRes = await fetch(`${API_URL}/dashboard/stats`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const stats = await statsRes.json();

        if (stats.success) {
            document.getElementById('stat-emails').textContent   = stats.date.total_emails   || 0;
            document.getElementById('stat-phishing').textContent = stats.date.total_phishing || 0;
        }

        await loadBlockedSenders();
        await loadImapSettings();

    } catch (err) {
        console.error('Load account error:', err);
    }
}

// ─── Load Blocked Senders ───
async function loadBlockedSenders() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/blocked`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success) {
            const blocked = data.date.blocked || [];
            document.getElementById('blocked-count').textContent = blocked.length;
            document.getElementById('stat-blocked').textContent  = blocked.length;

            const list = document.getElementById('blocked-list');

            if (!blocked.length) {
                list.innerHTML = `<div class="empty-blocked"><p class="text-muted text-sm">Nenhum remetente bloqueado</p></div>`;
                return;
            }

            list.innerHTML = blocked.map(b => `
                <div class="blocked-item">
                    <div>
                        <div class="blocked-sender">🚫 ${b.sender}</div>
                        <div class="blocked-date">Bloqueado em ${formatDate(b.blocked_at)}</div>
                    </div>
                    <button class="unblock-btn" onclick="unblockSender(${b.id_blocked}, '${b.sender}')">
                        ✅ Desbloquear
                    </button>
                </div>
            `).join('');
        }
    } catch (err) {
        console.error('Load blocked error:', err);
    }
}

// ─── Unblock Sender ───
async function unblockSender(id, sender) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.id = 'unblock-modal';
    modal.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <div class="modal-icon">✅</div>
                <div>
                    <div class="modal-title">Desbloquear Remetente</div>
                    <div class="modal-subtitle">Confirma a ação</div>
                </div>
            </div>
            <div class="modal-ai-verdict">
                O remetente <strong>${sender}</strong> voltará a ser analisado normalmente.
            </div>
            <div class="modal-footer" style="gap:12px;">
                <button class="btn btn-secondary" onclick="document.getElementById('unblock-modal').remove()">Cancelar</button>
                <button class="btn btn-primary" onclick="confirmUnblock(${id})">✅ Desbloquear</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
}

async function confirmUnblock(id) {
    const token = checkAuth();
    document.getElementById('unblock-modal')?.remove();

    try {
        const response = await fetch(`${API_URL}/dashboard/blocked/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) await loadBlockedSenders();
    } catch (err) {
        console.error('Unblock error:', err);
    }
}

// ─── Change Password ───
async function changePassword() {
    const token   = checkAuth();
    const current = document.getElementById('current-password').value;
    const newPass = document.getElementById('new-password').value;
    const confirm = document.getElementById('confirm-password').value;
    const msg     = document.getElementById('password-msg');

    msg.className = 'account-msg';

    if (!current || !newPass || !confirm) {
        msg.textContent = 'Por favor preenche todos os campos.';
        msg.className = 'account-msg error';
        return;
    }

    if (newPass !== confirm) {
        msg.textContent = 'As passwords não coincidem.';
        msg.className = 'account-msg error';
        return;
    }

    if (newPass.length < 6) {
        msg.textContent = 'A nova password deve ter pelo menos 6 caracteres.';
        msg.className = 'account-msg error';
        return;
    }

    try {
        const response = await fetch(`${API_URL}/auth/change-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ current_password: current, new_password: newPass })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            msg.textContent = '✅ Password alterada com sucesso!';
            msg.className = 'account-msg success';
            document.getElementById('current-password').value = '';
            document.getElementById('new-password').value     = '';
            document.getElementById('confirm-password').value = '';
        } else {
            msg.textContent = data.detail || 'Erro ao alterar password.';
            msg.className = 'account-msg error';
        }
    } catch (err) {
        msg.textContent = 'Não foi possível ligar ao servidor.';
        msg.className = 'account-msg error';
    }
}

// ─── IMAP Settings ───
async function loadImapSettings() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/emails/imap/credentials`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.success && data.date) {
            document.getElementById('imap-email-setting').value    = data.date.email    || '';
            document.getElementById('imap-password-setting').value = data.date.password || '';
            document.getElementById('imap-interval').value         = data.date.interval || 30;
            document.getElementById('auto-check-toggle').checked   = data.date.auto_check || false;
            document.getElementById('account-email').textContent   = data.date.email    || '—';
        }
    } catch (err) {
        console.error('Load IMAP settings error:', err);
    }
}

async function saveImapSettings() {
    const token      = checkAuth();
    const email      = document.getElementById('imap-email-setting').value.trim();
    const password   = document.getElementById('imap-password-setting').value;
    const interval   = document.getElementById('imap-interval').value;
    const auto_check = document.getElementById('auto-check-toggle').checked;
    const msg        = document.getElementById('imap-msg');

    msg.className = 'account-msg';

    if (!email || !password) {
        msg.textContent = 'Por favor preenche o email e a password.';
        msg.className = 'account-msg error';
        return;
    }

    try {
        const response = await fetch(`${API_URL}/emails/imap/credentials`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                email,
                password,
                limit: 20,
                interval: parseInt(interval),
                auto_check: auto_check ? 1 : 0
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            msg.textContent = '✅ Configurações IMAP guardadas!';
            msg.className = 'account-msg success';
        } else {
            msg.textContent = 'Erro ao guardar configurações.';
            msg.className = 'account-msg error';
        }
    } catch (err) {
        msg.textContent = 'Não foi possível ligar ao servidor.';
        msg.className = 'account-msg error';
    }
}

async function toggleAutoCheck() {
    const token   = checkAuth();
    const enabled = document.getElementById('auto-check-toggle').checked;

    try {
        await fetch(`${API_URL}/emails/imap/autocheck`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ enabled })
        });
    } catch (err) {
        console.error('Toggle auto check error:', err);
    }
}

// ─── Theme Toggle ───
function handleThemeToggle() {
    toggleTheme();
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    document.getElementById('theme-toggle-check').checked = isDark;
}

function initThemeCheckbox() {
    const isDark   = document.documentElement.getAttribute('data-theme') === 'dark';
    const checkbox = document.getElementById('theme-toggle-check');
    if (checkbox) checkbox.checked = isDark;
}

// ─── Export PDF ───
async function exportPDF() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/export/save?format=pdf`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            alert(`✅ PDF guardado no Ambiente de Trabalho!\n\n${data.path}`);
        } else {
            alert('Erro ao gerar PDF: ' + data.message);
        }
    } catch (err) {
        alert('Não foi possível gerar o PDF.');
    }
}

// ─── Export CSV ───
async function exportCSV() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/export/save?format=csv`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        if (data.success) {
            alert(`✅ CSV guardado no Ambiente de Trabalho!\n\n${data.path}`);
        } else {
            alert('Erro ao exportar CSV: ' + data.message);
        }
    } catch (err) {
        alert('Não foi possível exportar o CSV.');
    }
}

// ─── Webhooks ───
async function loadWebhooks() {
    const token = checkAuth();
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/dashboard/webhooks`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();

        if (data.success && data.date) {
            document.getElementById('discord-url').value       = data.date.discord_url      || '';
            document.getElementById('slack-url').value         = data.date.slack_url         || '';
            document.getElementById('telegram-token').value    = data.date.telegram_token    || '';
            document.getElementById('telegram-chat-id').value  = data.date.telegram_chat_id  || '';
        }
    } catch (err) {
        console.error('Load webhooks error:', err);
    }
}

async function saveWebhooks() {
    const token = checkAuth();
    const msg   = document.getElementById('webhook-msg');
    msg.className = 'account-msg';

    try {
        const response = await fetch(`${API_URL}/dashboard/webhooks`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                discord_url:      document.getElementById('discord-url').value.trim(),
                slack_url:        document.getElementById('slack-url').value.trim(),
                telegram_token:   document.getElementById('telegram-token').value.trim(),
                telegram_chat_id: document.getElementById('telegram-chat-id').value.trim()
            })
        });

        const data = await response.json();
        if (data.success) {
            msg.textContent = '✅ Webhooks guardados!';
            msg.className = 'account-msg success';
        }
    } catch (err) {
        msg.textContent = 'Erro ao guardar webhooks.';
        msg.className = 'account-msg error';
    }
}

async function testWebhook() {
    const token = checkAuth();
    const msg   = document.getElementById('webhook-msg');
    msg.className = 'account-msg';
    msg.textContent = '⏳ A enviar teste...';
    msg.style.display = 'block';

    try {
        const response = await fetch(`${API_URL}/dashboard/webhooks/test`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                discord_url:      document.getElementById('discord-url').value.trim(),
                slack_url:        document.getElementById('slack-url').value.trim(),
                telegram_token:   document.getElementById('telegram-token').value.trim(),
                telegram_chat_id: document.getElementById('telegram-chat-id').value.trim()
            })
        });

        const data = await response.json();
        if (data.success) {
            msg.textContent = '✅ Teste enviado! Verifica o Discord/Slack/Telegram.';
            msg.className = 'account-msg success';
        }
    } catch (err) {
        msg.textContent = 'Erro ao testar webhook.';
        msg.className = 'account-msg error';
    }
}

// ─── Format Date ───
function formatDate(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleDateString('pt-PT', {
        day: '2-digit', month: 'short', year: 'numeric'
    });
}

// ─── Modal CSS ───
const modalStyle = document.createElement('style');
modalStyle.textContent = `
.modal-overlay { position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);z-index:9999;display:flex;align-items:center;justify-content:center; }
.modal { background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius-lg);padding:28px;max-width:420px;width:calc(100% - 48px);box-shadow:var(--shadow-lg); }
.modal-header { display:flex;align-items:center;gap:16px;margin-bottom:20px; }
.modal-icon { font-size:2rem; }
.modal-title { font-size:1.1rem;font-weight:600;color:var(--text-primary); }
.modal-subtitle { font-size:0.82rem;color:var(--text-muted);margin-top:2px; }
.modal-ai-verdict { background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius-md);padding:14px 16px;margin-bottom:20px;font-size:0.875rem;line-height:1.6; }
.modal-footer { display:flex;justify-content:flex-end;gap:12px; }
`;
document.head.appendChild(modalStyle);

document.addEventListener('DOMContentLoaded', () => {
    loadUser();
    loadAccountInfo();
    initThemeCheckbox();
    loadWebhooks();
});

