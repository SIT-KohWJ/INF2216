// SITinform — site-wide JS
// Page-specific scripts are loaded separately (e.g. upload.js for /submit)

// Password show/hide toggle.
// Any `.register-input-icon` sitting next to a password field (login, register,
// etc.) becomes a clickable eye that toggles the field between masked and plain
// text. The input is captured at wire-up time while it is still type=password.
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.register-input-icon').forEach(function (icon) {
        var wrap = icon.parentElement;
        var input = wrap ? wrap.querySelector('input[type="password"]') : null;
        if (!input) {
            return;
        }

        icon.removeAttribute('aria-hidden');
        icon.setAttribute('role', 'button');
        icon.setAttribute('tabindex', '0');
        icon.setAttribute('aria-label', 'Show password');
        icon.style.cursor = 'pointer';

        function toggle() {
            var show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            icon.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
            var i = icon.querySelector('i');
            if (i) {
                i.classList.toggle('fa-eye', !show);
                i.classList.toggle('fa-eye-slash', show);
            }
        }

        icon.addEventListener('click', toggle);
        icon.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                toggle();
            }
        });
    });

    // Confirmation prompt before submitting a destructive/irreversible form.
    // Add data-confirm="message" to the <form> to require an OK first.
    document.querySelectorAll('form[data-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (!window.confirm(form.dataset.confirm)) {
                e.preventDefault();
            }
        });
    });

    // Copy-to-clipboard button for the report reference number (reports/view.html).
    document.querySelectorAll('.wb-report-view__copy-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(btn.dataset.reference);
            }
        });
    });

    // Status filter dropdown (investigator_dashboard.html).
    const filter = document.getElementById('investigator-status-filter');
    const rows = document.querySelectorAll('[data-case-row]');
    if (filter && rows.length) {
        filter.addEventListener('change', function () {
            const selected = this.value;
            rows.forEach(function (row) {
                const status = row.dataset.status || '';
                row.style.display = (!selected || status === selected) ? '' : 'none';
            });
        });
    }
});
