// Site-wide JavaScript

// Auto-dismiss alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function () {
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
});

// XSS Protection - Sanitize user input display
function sanitizeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// CSRF Token helper
function getCSRFToken() {
    return document.querySelector('input[name="__RequestVerificationToken"]')?.value;
}

// Session timeout warning
let sessionTimeout;
let warningTimeout;

function resetSessionTimer() {
    clearTimeout(sessionTimeout);
    clearTimeout(warningTimeout);

    // Warn 2 minutes before timeout
    warningTimeout = setTimeout(function () {
        if (confirm('Your session is about to expire. Click OK to stay logged in.')) {
            fetch('/api/keepalive', { method: 'POST' });
            resetSessionTimer();
        }
    }, 28 * 60 * 1000); // 28 minutes

    // Logout at 30 minutes
    sessionTimeout = setTimeout(function () {
        alert('Your session has expired. Please log in again.');
        window.location.href = '/Account/Login';
    }, 30 * 60 * 1000); // 30 minutes
}

// Initialize session timer if user is authenticated
if (document.querySelector('.navbar-text')) {
    resetSessionTimer();

    // Reset timer on user activity
    ['click', 'keypress', 'scroll', 'mousemove'].forEach(function (event) {
        document.addEventListener(event, function () {
            resetSessionTimer();
        }, { passive: true, once: false });
    });
}