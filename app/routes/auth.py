from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db, limiter
from app.forms import LoginForm, PasswordChangeForm, PasswordResetForm, PasswordResetRequestForm, RegistrationForm
from app.models import RevokedToken
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
        if current_user.role in ['system_admin', 'admin']:
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
            login_user(user, remember=form.remember.data)
            # _sid is the revocable session identifier; _session_created_at is
            # the watermark checked against User.sessions_invalidated_at.
            session['_sid'] = str(uuid.uuid4())
            session['_session_created_at'] = datetime.utcnow().isoformat()

            if user.role in ['system_admin', 'admin']:
                return redirect(url_for('admin.dashboard'))
            elif user.role == 'investigator':
                return redirect(url_for('reports.investigator_dashboard'))
            else:
                return redirect(url_for('reports.dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('auth/login.html', form=form)


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


@auth_bp.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        success, message = AuthService.request_account_deletion(current_user)
        if success:
            sid = session.get('_sid')
            if sid:
                db.session.add(RevokedToken(token_jti=sid, reason='account_deletion'))
                db.session.commit()
            logout_user()
            session.clear()
            flash(message, 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')
    return render_template('auth/delete_account.html')
