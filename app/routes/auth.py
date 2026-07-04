from datetime import datetime

from flask import Blueprint, flash, make_response, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db, limiter
from app.forms import LoginForm, LoginOtpForm, PasswordChangeForm, PasswordResetForm, PasswordResetRequestForm, RegistrationForm
from app.models import RevokedToken, User
from app.services.auth_service import AuthService
from app.services.crypto_service import crypto_service
from app.services.otp_service import OtpService
import uuid

# How long a user has, after a correct password, to enter the emailed 2FA
# code before the pending-login state expires and they must start over.
_TWOFA_WINDOW_SECONDS = 600  # 10 minutes


def _dest_for(user):
    """Post-login landing page for a user, based on role."""
    if user.role in ['system_admin', 'report_admin']:
        return url_for('admin.dashboard')
    if user.role == 'investigator':
        return url_for('reports.investigator_dashboard')
    return url_for('reports.dashboard')


def _establish_session(user, remember_email):
    """Create the authenticated session AFTER both factors have passed.

    This is the block that used to live inline in login(); it is deliberately
    only reachable once the emailed OTP (second factor) is verified.
    """
    # Regenerate session to prevent session-fixation attacks.
    session.clear()
    # "Remember Me" here only pre-fills the email next time; it does NOT
    # keep the user logged in (no long-lived remember cookie), and the
    # password is never stored anywhere.
    login_user(user, remember=False)
    # _sid is the revocable session identifier; _session_created_at is
    # the watermark checked against User.sessions_invalidated_at.
    session['_sid'] = str(uuid.uuid4())
    session['_session_created_at'] = datetime.utcnow().isoformat()

    response = make_response(redirect(_dest_for(user)))
    if remember_email:
        # 30-day, HttpOnly cookie holding only the email address.
        response.set_cookie(
            'remembered_email', remember_email,
            max_age=30 * 24 * 3600, httponly=True, samesite='Lax',
            secure=request.is_secure,
        )
    else:
        response.delete_cookie('remembered_email')
    return response

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('reports.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user, message = AuthService.register_user(
            email=form.email.data,
            password=form.password.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
        )
        if user:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')
    return render_template('auth/register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        if current_user.role in ['system_admin', 'report_admin']:
            return redirect(url_for('admin.dashboard'))
        if current_user.role == 'investigator':
            return redirect(url_for('reports.investigator_dashboard'))
        return redirect(url_for('reports.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        ip_address = request.remote_addr
        user = AuthService.authenticate_user(form.email.data, form.password.data, ip_address)
        if user:
            # First factor (password) passed. Do NOT log in yet — start the
            # email second factor. Stash only the user id, the remember-email
            # preference, and a timestamp; never the password.
            OtpService.initiate_login_2fa(user)
            session.clear()
            session['_2fa_user_id'] = user.id
            session['_2fa_started_at'] = datetime.utcnow().isoformat()
            session['_2fa_remember_email'] = (
                form.email.data.lower().strip() if form.remember.data else None
            )
            crypto_service.log_audit_action(
                action='login_2fa_challenged',
                acting_user=user, acting_role=user.role,
                details='Password verified; email 2FA code sent',
                ip_address=ip_address,
            )
            flash('We\'ve emailed you a verification code to finish signing in.', 'info')
            return redirect(url_for('auth.login_verify'))
        else:
            flash('Invalid email or password.', 'danger')

    # On GET, pre-fill the email (and tick the box) from the remembered cookie.
    if request.method == 'GET':
        remembered = request.cookies.get('remembered_email')
        if remembered:
            form.email.data = remembered
            form.remember.data = True
    return render_template('auth/login.html', form=form)


@auth_bp.route('/login/verify', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login_verify():
    """Second step of login: verify the emailed 2FA code, then sign in.

    Reachable only after login() has verified the password and stashed the
    pending user in the session. The actual authenticated session is created
    here (via _establish_session) and nowhere else on the 2FA path.
    """
    if current_user.is_authenticated:
        return redirect(_dest_for(current_user))

    user_id = session.get('_2fa_user_id')
    started_at = session.get('_2fa_started_at')
    if not user_id or not started_at:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))

    # Enforce the pending-login window independently of the OTP expiry.
    try:
        started = datetime.fromisoformat(started_at)
    except (TypeError, ValueError):
        started = None
    if started is None or (datetime.utcnow() - started).total_seconds() > _TWOFA_WINDOW_SECONDS:
        session.clear()
        flash('Your login session timed out. Please sign in again.', 'warning')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(id=user_id, is_active=True).first()
    if not user:
        session.clear()
        flash('Please log in again.', 'warning')
        return redirect(url_for('auth.login'))

    form = LoginOtpForm()
    if form.validate_on_submit():
        success, message = OtpService.verify_otp(user.email, form.otp.data.strip())
        if success:
            remember_email = session.get('_2fa_remember_email')
            crypto_service.log_audit_action(
                action='user_login',
                acting_user=user, acting_role=user.role,
                details='User logged in (password + email 2FA)',
                ip_address=request.remote_addr,
            )
            # _establish_session clears the session (dropping the _2fa_* keys)
            # before creating the authenticated one.
            return _establish_session(user, remember_email)
        else:
            crypto_service.log_audit_action(
                action='login_2fa_failed',
                acting_user=user, acting_role=user.role,
                details='Incorrect or expired 2FA code at login',
                ip_address=request.remote_addr,
            )
            flash(message, 'danger')

    # Mask the email in the UI so a shoulder-surfer can't read the full address.
    local, _, domain = user.email.partition('@')
    masked_email = (local[:2] + '***@' + domain) if len(local) > 2 else ('***@' + domain)
    return render_template('auth/login_verify.html', form=form, masked_email=masked_email)


@auth_bp.route('/login/resend', methods=['POST'])
@limiter.limit("2 per minute")
def login_resend():
    """Resend the login 2FA code for the pending login, if any."""
    user_id = session.get('_2fa_user_id')
    if not user_id:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))
    user = User.query.filter_by(id=user_id, is_active=True).first()
    if user:
        OtpService.initiate_login_2fa(user)
        # Reset the pending window so the resent code has a full window.
        session['_2fa_started_at'] = datetime.utcnow().isoformat()
    flash('A new verification code has been sent to your email.', 'info')
    return redirect(url_for('auth.login_verify'))


@auth_bp.route('/logout')
@login_required
def logout():
    sid = session.get('_sid')
    if sid:
        db.session.add(RevokedToken(token_jti=sid, reason='logout'))
        db.session.commit()
    crypto_service.log_audit_action(
        action='user_logout',
        acting_user=current_user, acting_role=current_user.role,
        details='User logged out',
        ip_address=request.remote_addr,
    )
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
@limiter.limit("3 per minute")
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        success, message = AuthService.update_user_password(
            current_user, form.current_password.data, form.new_password.data
        )
        if success:
            # Revoke this specific session; User.invalidate_all_sessions() in
            # the service already bumps the global watermark for all others.
            sid = session.get('_sid')
            if sid:
                db.session.add(RevokedToken(token_jti=sid, reason='password_change'))
                db.session.commit()
            logout_user()
            session.clear()
            flash(message + ' Please log in again with your new password.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')
    return render_template('auth/change_password.html', form=form)


@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('reports.dashboard'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        # OtpService creates an OTP record for every valid SIT email and only
        # sends the actual email when an active account exists — non-enumerating.
        OtpService.initiate_for_email(email)
        session['_otp_email'] = email
        flash('If that address is registered, a one-time password has been sent to it.', 'info')
        return redirect(url_for('otp.verify'))
    return render_template('auth/forgot_password.html', form=form)


@auth_bp.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def reset_password():
    # Token arrives via query-string after OTP verification (GET) and is
    # re-submitted as a hidden field on form POST.
    token = request.args.get('token', '').strip() or request.form.get('token', '').strip()
    if not token:
        flash('Invalid or missing reset link. Please start the password reset process again.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    form = PasswordResetForm()

    # Pre-fill the hidden token field on GET so it round-trips through the form.
    if request.method == 'GET':
        form.token.data = token

    if form.validate_on_submit():
        success, message = AuthService.reset_password(form.token.data, form.new_password.data)
        if success:
            flash('Password reset successfully. Please log in with your new password.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')
            return redirect(url_for('auth.forgot_password'))

    return render_template('auth/reset_password.html', form=form)


@auth_bp.route('/account')
@login_required
def account():
    from app.services.report_service import ReportService
    unread_notifications = None
    if current_user.role == 'whistleblower':
        unread_notifications = ReportService.count_unread_notifications(current_user.id)
    return render_template('auth/account.html', unread_notifications=unread_notifications)


@auth_bp.route('/logout_all', methods=['POST'])
@login_required
def logout_all():
    # The session model tracks only the current session id (_sid); revoking it
    # ends this session immediately. A full multi-device registry is a known
    # limitation, so this is scoped to the active session (D9).
    sid = session.get('_sid')
    if sid:
        db.session.add(RevokedToken(token_jti=sid, reason='logout_all'))
        db.session.commit()
    crypto_service.log_audit_action(action='logout_all', acting_user=current_user, acting_role=current_user.role, details='User ended active session from account settings', ip_address=request.remote_addr)
    logout_user()
    session.clear()
    flash('Your active session has been ended. Please log in again.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    # FR-W4: visiting this endpoint submits a deletion REQUEST for System Admin
    # review and deactivates the account immediately, then logs the user out.
    # It does not delete directly; final deletion is done by a System Admin.
    success, message = AuthService.request_account_deletion(current_user)
    if success:
        sid = session.get('_sid')
        if sid:
            db.session.add(RevokedToken(token_jti=sid, reason='account_deletion_requested'))
            db.session.commit()
        logout_user()
        session.clear()
        flash(message, 'info')
    else:
        flash(message, 'danger')
    return redirect(url_for('auth.login'))
