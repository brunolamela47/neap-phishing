// ─────────────────────────────────────────
// NEAP — Login Page Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";

async function handleLogin() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorMsg = document.getElementById('error-msg');
    const btn      = document.getElementById('login-btn');

    // Reset error
    errorMsg.classList.remove('show');

    // Basic validation
    if (!username || !password) {
        errorMsg.textContent = "Please fill in all fields.";
        errorMsg.classList.add('show');
        return;
    }

    // Loading state
    btn.classList.add('loading');
    btn.textContent = "Signing in...";

    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Save token and username in localStorage
            localStorage.setItem('neap-token', data.date.token);
            localStorage.setItem('neap-user', data.date.username);
            window.location.href = 'dashboard.html';
        } else {
            errorMsg.textContent = data.detail || "Invalid credentials.";
            errorMsg.classList.add('show');
            document.getElementById('password').value = '';
        }

    } catch (err) {
        errorMsg.textContent = "Cannot connect to server. Make sure the API is running.";
        errorMsg.classList.add('show');
    }

    // Reset button
    btn.classList.remove('loading');
    btn.textContent = "Sign in";
}

function togglePassword() {
    const input = document.getElementById('password');
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Enter key support
document.getElementById('password').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') handleLogin();
});