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

// Apply saved theme on page load
(function () {
    const saved = localStorage.getItem('neap-theme') || 'light';
    document.documentElement.setAttribute('data-theme', saved);
    const icon = document.getElementById('theme-icon');
    if (icon) icon.textContent = saved === 'dark' ? '☀️' : '🌙';
})();
