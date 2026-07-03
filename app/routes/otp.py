"""OTP verification blueprint — intentionally separate from auth.py.

Defence-in-depth chain for password reset:
  1. /auth/forgot_password  — rate-limited; creates OTP; emails to registered address only
  2. /otp/verify            — rate-limited independently; verifies OTP; issues PasswordResetToken
  3. /auth/reset_password   — validates PasswordResetToken (only exists after OTP success)

This module owns step 2 and enforces that a valid PasswordResetToken is
never issued unless an OTP was first verified. The auth blueprint (step 3)
trusts the token but never creates it itself.
"""
from datetime import datetime, timedelta

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app import db, limiter
from app.forms import OtpVerifyForm
from app.models import PasswordResetToken, User
from app.services.auth_service import AuthService
from app.services.crypto_service import crypto_service
from app.services.otp_service import OtpService

otp_bp = Blueprint('otp', __name__, url_prefix='/otp')


@otp_bp.route('/verify', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify():
    email = session.get('_otp_email')
    if not email:
        flash('Please request a password reset first.', 'warning')
        return redirect(url_for('auth.forgot_password'))

    form = OtpVerifyForm()
    if form.validate_on_submit():
        otp_input = form.otp.data.strip()
        success, message = OtpService.verify_otp(email, otp_input)

        if success:
            user = User.query.filter_by(email=email, is_active=True).first()

            if user:
                # Invalidate any pending reset tokens before issuing a new one
                # so old links can never be reused.
                PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({'used': True})
                db.session.flush()

                expiry_minutes = 15
                token_value = crypto_service.generate_password_reset_token()
                reset_token = PasswordResetToken(
                    user_id=user.id,
                    token=token_value,
                    expires_at=datetime.utcnow() + timedelta(minutes=expiry_minutes),
                )
                db.session.add(reset_token)
                db.session.commit()

                crypto_service.log_audit_action(
                    action='otp_verified',
                    acting_user=user,
                    acting_role=user.role,
                    details='OTP verified; time-limited password-reset token issued',
                    ip_address=request.remote_addr,
                )

                session.pop('_otp_email', None)
                flash('Identity verified. Please set your new password.', 'success')
                return redirect(url_for('auth.reset_password', token=token_value))
            else:
                # Email has no registered account. Non-enumerating: clear session
                # and fall through to the login page silently.
                session.pop('_otp_email', None)
                flash('If your account exists, a password reset link has been prepared.', 'info')
                return redirect(url_for('auth.login'))
        else:
            flash(message, 'danger')

    return render_template('auth/verify_otp.html', form=form, email=email)


@otp_bp.route('/verify_registration', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def verify_registration():
    """Step 2 of registration: verify the OTP, then — only on success —
    create the account from the pending data stashed in session at step 1.
    A student cannot end up with an account without first proving control
    of the email address they registered with.
    """
    email = session.get('_otp_register_email')
    pending = session.get('_pending_registration')
    if not email or not pending or pending.get('email') != email:
        flash('Please start the registration process again.', 'warning')
        return redirect(url_for('auth.register'))

    form = OtpVerifyForm()
    if form.validate_on_submit():
        otp_input = form.otp.data.strip()
        success, message = OtpService.verify_otp(
            email, otp_input, restart_hint="Please register again."
        )

        if success:
            user, msg = AuthService.complete_registration(
                email=pending['email'],
                password_hash=pending['password_hash'],
                first_name=pending['first_name'],
                last_name=pending['last_name'],
            )
            session.pop('_otp_register_email', None)
            session.pop('_pending_registration', None)

            if user:
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash(msg, 'danger')
                return redirect(url_for('auth.register'))
        else:
            flash(message, 'danger')

    return render_template('auth/verify_registration_otp.html', form=form, email=email)
