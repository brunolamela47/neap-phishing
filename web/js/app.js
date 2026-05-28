function toggleTheme() {
    const html = document.documentElement;
    const icon = document.getElementById('theme-icon');
    const current = html.getAttribute('data-theme');

    if (current === 'dark') {
        html.setAttribute('data-theme', 'light');
        localStorage.setItem('neap-theme', 'light');
        if (icon) icon.textContent = '🌙';
    } else {
        html.setAttribute('data-theme', 'dark');
        localStorage.setItem('neap-theme', 'dark');
        if (icon) icon.textContent = '☀️';
    }
}

// ─── Token Storage ───
// PyWebView file:// doesn't always persist localStorage
// We save token via the API to a local file instead

async function saveSession(token, username, remember) {
    if (!remember) return;
    try {
        await fetch("http://localhost:8000/auth/save-session", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token, username })
        });
    } catch (err) {
        console.log('Could not save session');
    }
}

async function loadSavedSession() {
    try {
        const response = await fetch("http://localhost:8000/auth/load-session");
        const data = await response.json();
        if (data.success && data.date.token) {
            localStorage.setItem('neap-token', data.date.token);
            localStorage.setItem('neap-user', data.date.username);
            return true;
        }
    } catch (err) {
        return false;
    }
    return false;
}
// Apply saved theme on page load
(function () {
    const saved = localStorage.getItem('neap-theme') || 'light';
    document.documentElement.setAttribute('data-theme', saved);
    const icon = document.getElementById('theme-icon');
    if (icon) icon.textContent = saved === 'dark' ? '☀️' : '🌙';
})();
