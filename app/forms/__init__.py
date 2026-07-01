from flask_wtf import FlaskForm
from wtforms import (
    BooleanField, DateField, FileField, HiddenField, PasswordField,
    SelectField, StringField, SubmitField, TextAreaField,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, ValidationError

from app.services.auth_service import AuthService


# ---------------------------------------------------------------------------
# Auth forms
# ---------------------------------------------------------------------------

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords do not match.')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        if not AuthService.validate_email(email.data):
            raise ValidationError('Must use an @singaporetech.edu.sg or @sit.singaporetech.edu.sg email address.')

    def validate_password(self, password):
        valid, msg = AuthService.validate_password(password.data)
        if not valid:
            raise ValidationError(msg)


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords do not match.')])
    submit = SubmitField('Change Password')

    def validate_new_password(self, new_password):
        valid, msg = AuthService.validate_password(new_password.data)
        if not valid:
            raise ValidationError(msg)


class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

    def validate_email(self, email):
        if not AuthService.validate_email(email.data):
            raise ValidationError('Must use an @singaporetech.edu.sg or @sit.singaporetech.edu.sg email address.')


class OtpVerifyForm(FlaskForm):
    otp = StringField('One-Time Password', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify OTP')

    def validate_otp(self, otp):
        if not otp.data.isdigit():
            raise ValidationError('OTP must be a 6-digit number.')


class PasswordResetForm(FlaskForm):
    # Hidden field: pre-filled from the URL query-string in the route, not typed by the user.
    token = HiddenField('Token', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords do not match.')])
    submit = SubmitField('Reset Password')

    def validate_new_password(self, new_password):
        valid, msg = AuthService.validate_password(new_password.data)
        if not valid:
            raise ValidationError(msg)


# ---------------------------------------------------------------------------
# Report forms
# ---------------------------------------------------------------------------

class ReportForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=255)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=10000)])
    category = SelectField('Category', choices=[
        ('academic_misconduct', 'Academic Misconduct'),
        ('financial_misconduct', 'Financial Misconduct'),
        ('harassment', 'Harassment'),
        ('policy_violation', 'Policy Violation'),
        ('ethical_concern', 'Ethical Concern'),
        ('other', 'Other'),
    ], validators=[DataRequired()])
    evidence = FileField('Evidence Files')
    submit = SubmitField('Submit Report')


class InvestigationNoteForm(FlaskForm):
    note = TextAreaField('Note', validators=[DataRequired(), Length(max=5000)])
    submit = SubmitField('Add Note')


class InvestigationPlanForm(FlaskForm):
    investigator_full_name = StringField('Investigator Full Name', validators=[DataRequired(), Length(max=128)])
    investigator_job_title = StringField('Investigator Job Title', validators=[DataRequired(), Length(max=128)])
    investigator_staff_id = StringField('Investigator Staff ID', validators=[DataRequired(), Length(max=64)])
    planning_date = DateField('Planning Date', format='%Y-%m-%d', validators=[DataRequired()])
    case_overview = TextAreaField('Case Overview', validators=[DataRequired(), Length(max=5000)])
    incident_date = DateField('Incident Date', format='%Y-%m-%d', validators=[DataRequired()])
    incident_time = TimeField('Incident Time', format='%H:%M', validators=[DataRequired()])
    incident_where = StringField('Incident Where', validators=[DataRequired(), Length(max=255)])
    submit = SubmitField('Save Investigation Plan')


class OutcomeForm(FlaskForm):
    outcome = SelectField('Outcome', choices=[
        ('action_taken', 'Action Taken'),
        ('dismissed', 'Dismissed'),
        ('referred', 'Referred'),
        ('insufficient_evidence', 'Insufficient Evidence'),
    ], validators=[DataRequired()])
    outcome_details = TextAreaField('Details', validators=[DataRequired(), Length(max=5000)])
    submit = SubmitField('Recommend Outcome')


class AssignInvestigatorForm(FlaskForm):
    investigator = SelectField('Investigator', coerce=str, validators=[DataRequired()])
    submit = SubmitField('Assign Investigator')


class UserManagementForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = SelectField('Role', choices=[
        ('whistleblower', 'Whistleblower'),
        ('investigator', 'Investigator'),
        ('report_admin', 'Report Admin'),
        ('system_admin', 'System Admin'),
    ], validators=[DataRequired()])
    submit = SubmitField('Create User')

    def validate_email(self, email):
        if not AuthService.validate_email(email.data):
            raise ValidationError('Must use an @singaporetech.edu.sg or @sit.singaporetech.edu.sg email address.')

    def validate_password(self, password):
        valid, msg = AuthService.validate_password(password.data)
        if not valid:
            raise ValidationError(msg)


class RoleChangeForm(FlaskForm):
    role = SelectField('New Role', choices=[
        ('whistleblower', 'Whistleblower'),
        ('investigator', 'Investigator'),
        ('report_admin', 'Report Admin'),
        ('system_admin', 'System Admin'),
    ], validators=[DataRequired()])
    submit = SubmitField('Change Role')


class ReportFilterForm(FlaskForm):
    category = SelectField('Category', choices=[
        ('', 'All Categories'),
        ('academic_misconduct', 'Academic Misconduct'),
        ('financial_misconduct', 'Financial Misconduct'),
        ('harassment', 'Harassment'),
        ('policy_violation', 'Policy Violation'),
        ('ethical_concern', 'Ethical Concern'),
        ('other', 'Other'),
    ], default='')
    status = SelectField('Status', choices=[
        ('', 'All Statuses'),
        ('Received', 'Received'),
        ('Triaged', 'Triaged'),
        ('Investigating', 'Investigating'),
        ('Resolved', 'Resolved'),
    ], default='')
    search = StringField('Search')
    date_from = DateField('From Date', format='%Y-%m-%d', validators=[Optional()])
    date_to = DateField('To Date', format='%Y-%m-%d', validators=[Optional()])
    submit = SubmitField('Filter')
