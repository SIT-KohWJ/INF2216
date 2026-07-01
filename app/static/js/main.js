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
});
