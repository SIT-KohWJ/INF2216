from datetime import datetime

from flask import Blueprint, current_app, flash, make_response, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db, limiter
from app.forms import LoginForm, PasswordChangeForm, PasswordResetForm, PasswordResetRequestForm, RegistrationForm
from app.models import RevokedToken, User
from app.services.auth_service import AuthService
from app.services.crypto_service import crypto_service
from app.services.otp_service import OtpService
import uuid

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('reports.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        first_name = form.first_name.data.strip()
        last_name = form.last_name.data.strip()
        valid, message = AuthService.validate_registration(
            email=email,
            password=form.password.data,
            first_name=first_name,
            last_name=last_name,
        )
        if valid:
            # Account is not created yet — only after the OTP below is verified.
            # The password is hashed now so the plaintext never has to be
            # carried across the OTP round-trip.
            session['_pending_registration'] = {
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'password_hash': User.hash_password(form.password.data),
            }
            session['_otp_register_email'] = email
            OtpService.initiate_for_registration(email, first_name)
            # Non-enumerating: identical message whether or not this email is
            # already registered — only OtpService decides whether an OTP is
            # actually sent.
            flash('If this email is available for registration, a one-time password has been sent to it.', 'info')
            return redirect(url_for('otp.verify_registration'))
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

            if user.role in ['system_admin', 'report_admin']:
                dest = url_for('admin.dashboard')
            elif user.role == 'investigator':
                dest = url_for('reports.investigator_dashboard')
            else:
                dest = url_for('reports.dashboard')
            response = make_response(redirect(dest))
            if form.remember.data:
                # 30-day, HttpOnly cookie holding only the email address.
                response.set_cookie(
                    'remembered_email', form.email.data.lower().strip(),
                    max_age=30 * 24 * 3600, httponly=True, samesite='Lax',
                    secure=current_app.config['SESSION_COOKIE_SECURE'],
                )
            else:
                response.delete_cookie('remembered_email')
            return response
        else:
            flash('Invalid email or password.', 'danger')

    # On GET, pre-fill the email (and tick the box) from the remembered cookie.
    if request.method == 'GET':
        remembered = request.cookies.get('remembered_email')
        if remembered:
            form.email.data = remembered
            form.remember.data = True
    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout', methods=['POST'])
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
    # FR-W4: submitting this endpoint (POST only) files a deletion REQUEST for
    # System Admin review and deactivates the account immediately, then logs
    # the user out. It does not delete directly; final deletion is done by a
    # System Admin. GET only renders the confirmation page below — it must
    # never trigger the deletion itself, since GET requests aren't CSRF-checked.
    if request.method == 'GET':
        return render_template('auth/delete_account.html')

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
