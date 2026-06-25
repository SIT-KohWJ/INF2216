from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app.services.auth_service import AuthService
from app.services.crypto_service import crypto_service
from app.forms import RegistrationForm, LoginForm, PasswordChangeForm, PasswordResetRequestForm, PasswordResetForm
from app import limiter, db
from app.models import RevokedToken
import uuid

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('reports.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user, message = AuthService.register_user(email=form.email.data, password=form.password.data, first_name=form.first_name.data, last_name=form.last_name.data)
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
        return redirect(url_for('reports.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        ip_address = request.remote_addr
        user = AuthService.authenticate_user(form.email.data, form.password.data, ip_address)
        if user:
            session.clear()  #regenerate session ID to prevent session fixation
            login_user(user, remember=form.remember.data)
            session['_sid'] = str(uuid.uuid4())  #trackable session token for revocation
            if user.role in ['system_admin', 'admin']:
                return redirect(url_for('admin.dashboard'))
            elif user.role == 'investigator':
                return redirect(url_for('reports.investigator_dashboard'))
            else:
                return redirect(url_for('reports.dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    sid = session.get('_sid')
    if sid:
        db.session.add(RevokedToken(token_jti=sid, reason='logout'))
        db.session.commit()
    crypto_service.log_audit_action(action='user_logout', acting_user=current_user, acting_role=current_user.role, details='User logged out', ip_address=request.remote_addr)
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
        success, message = AuthService.update_user_password(current_user, form.current_password.data, form.new_password.data)
        if success:
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
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        success, result = AuthService.request_password_reset(form.email.data)
        flash('If the email exists, a reset link has been sent.', 'info')
        return redirect(url_for('auth.reset_password'))
    return render_template('auth/forgot_password.html', form=form)


@auth_bp.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def reset_password():
    form = PasswordResetForm()
    if form.validate_on_submit():
        success, message = AuthService.reset_password(form.token.data, form.new_password.data)
        if success:
            flash('Password reset successfully. Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')
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
