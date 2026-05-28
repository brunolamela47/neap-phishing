// ─────────────────────────────────────────
// NEAP — Login Page Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";

async function handleLogin() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const remember = document.getElementById('remember-me').checked;
    const errorMsg = document.getElementById('error-msg');
    const btn      = document.getElementById('login-btn');

    errorMsg.classList.remove('show');

    if (!username || !password) {
        errorMsg.textContent = "Por favor preenche todos os campos.";
        errorMsg.classList.add('show');
        return;
    }

    btn.classList.add('loading');
    btn.textContent = "A entrar...";

    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Save token
            localStorage.setItem('neap-token', data.date.token);
            localStorage.setItem('neap-user', data.date.username);
            localStorage.setItem('neap-remember', remember ? '1' : '0');
            if (remember) {
        await saveSession(data.date.token, data.date.username, true);
    }
            window.location.href = 'dashboard.html';
        } else {
            errorMsg.textContent = data.detail || "Credenciais inválidas.";
            errorMsg.classList.add('show');
            document.getElementById('password').value = '';
        }

    } catch (err) {
        errorMsg.textContent = "Não foi possível ligar ao servidor.";
        errorMsg.classList.add('show');
    }

    btn.classList.remove('loading');
    btn.textContent = "Entrar";
}

function togglePassword() {
    const input = document.getElementById('password');
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Enter key support
document.getElementById('password').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') handleLogin();
});