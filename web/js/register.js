// ─────────────────────────────────────────
// NEAP — Register Page Logic
// ─────────────────────────────────────────

const API_URL = "http://localhost:8000";

async function handleRegister() {
    const username = document.getElementById('username').value.trim();
    const email    = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const errorMsg   = document.getElementById('error-msg');
    const successMsg = document.getElementById('success-msg');
    const btn        = document.getElementById('register-btn');

    // Reset messages
    errorMsg.classList.remove('show');
    successMsg.classList.remove('show');

    // Basic validation
    if (!username || !email || !password) {
        errorMsg.textContent = "Please fill in all fields.";
        errorMsg.classList.add('show');
        return;
    }

    if (password.length < 6) {
        errorMsg.textContent = "Password must be at least 6 characters.";
        errorMsg.classList.add('show');
        return;
    }

    // Loading state
    btn.classList.add('loading');
    btn.textContent = "Creating account...";

    try {
        const response = await fetch(`${API_URL}/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            successMsg.classList.add('show');
            document.getElementById('username').value = '';
            document.getElementById('email').value    = '';
            document.getElementById('password').value = '';
        } else {
            errorMsg.textContent = data.detail || "Registration failed.";
            errorMsg.classList.add('show');
        }

    } catch (err) {
        errorMsg.textContent = "Cannot connect to server. Make sure the API is running.";
        errorMsg.classList.add('show');
    }

    // Reset button
    btn.classList.remove('loading');
    btn.textContent = "Create account";
}

function togglePassword() {
    const input = document.getElementById('password');
    input.type = input.type === 'password' ? 'text' : 'password';
}

// Enter key support
document.getElementById('password').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') handleRegister();
});
