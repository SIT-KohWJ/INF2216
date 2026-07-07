import unicodedata

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField, DateField, TimeField, FileField, HiddenField,
    PasswordField, SelectField, StringField, SubmitField, TextAreaField,
)
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, Regexp, ValidationError,
)

from app.services.auth_service import AuthService


# ---------------------------------------------------------------------------
# Shared: block emoji + invisible/control Unicode in free-text fields, while
# allowing any language/script (accented letters, CJK, Tamil, Arabic, etc.).
# ---------------------------------------------------------------------------

_EMOJI_RANGES = (
    (0x1F1E6, 0x1F1FF),  # regional indicator symbols (flag emoji)
    (0x1F300, 0x1FAFF),  # misc symbols/pictographs .. symbols & pictographs ext-A
    (0x2600, 0x27BF),    # misc symbols & dingbats
    (0x2B00, 0x2BFF),    # misc symbols and arrows (e.g. star emoji)
    (0xFE00, 0xFE0F),    # variation selectors (emoji presentation form)
    (0x1F000, 0x1F0FF),  # mahjong/domino/playing card symbols
)
# Unicode general categories with no legitimate purpose in free text:
# Cc=control, Cf=format (zero-width joiners, RTL/LTR overrides, BOM),
# Cs=surrogate, Co=private-use, Cn=unassigned.
_BLOCKED_CATEGORIES = {'Cc', 'Cf', 'Cs', 'Co', 'Cn'}
_ALLOWED_WHITESPACE = {'\n', '\r', '\t'}


def no_emoji_or_control_chars(form, field):
    for ch in field.data or '':
        if ch in _ALLOWED_WHITESPACE:
            continue
        code_point = ord(ch)
        if any(lo <= code_point <= hi for lo, hi in _EMOJI_RANGES):
            raise ValidationError('Emoji are not allowed.')
        if unicodedata.category(ch) in _BLOCKED_CATEGORIES:
            raise ValidationError('Invisible or control characters are not allowed.')


# ---------------------------------------------------------------------------
# Auth forms
# ---------------------------------------------------------------------------

# Letters, plus apostrophe/hyphen/space for real names (O'Brien, Anne-Marie, Mary Jane).
# Must start with a letter — blocks emojis, digits, and symbol-only input.
NAME_REGEX = r"\A[A-Za-z][A-Za-z'\- ]*\Z"
NAME_REGEX_MESSAGE = "Only letters, apostrophes, hyphens, and spaces are allowed."


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=64), Regexp(NAME_REGEX, message=NAME_REGEX_MESSAGE)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=64), Regexp(NAME_REGEX, message=NAME_REGEX_MESSAGE)])
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
    # Deliberately no Length(min=...) or digit-format validator here: those
    # would tell an unauthenticated visitor exactly how long/what shape the
    # OTP is (view-source or the validation error would reveal it). A
    # mismatched value is instead rejected uniformly by OtpService.verify_otp,
    # which consumes an attempt either way — same outcome, no format leak.
    # The upper bound only guards against pathologically large input.
    otp = StringField('One-Time Password', validators=[DataRequired(), Length(max=32)])
    submit = SubmitField('Verify OTP')


class LoginOtpForm(FlaskForm):
    otp = StringField('Verification Code', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify & Sign In')

    def validate_otp(self, otp):
        if not otp.data.isdigit():
            raise ValidationError('Code must be a 6-digit number.')


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
    title = StringField('Title', validators=[DataRequired(), Length(max=100), no_emoji_or_control_chars])
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=10000), no_emoji_or_control_chars])
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
    note = TextAreaField('Note', validators=[DataRequired(), Length(max=5000), no_emoji_or_control_chars])
    submit = SubmitField('Add Note')


class InvestigationPlanForm(FlaskForm):
    investigator_full_name = StringField('Investigator Full Name', validators=[DataRequired(), Length(max=128), Regexp(NAME_REGEX, message=NAME_REGEX_MESSAGE)])
    investigator_job_title = StringField('Investigator Job Title', validators=[DataRequired(), Length(max=128), no_emoji_or_control_chars])
    investigator_staff_id = StringField('Investigator Staff ID', validators=[DataRequired(), Length(max=64), no_emoji_or_control_chars])
    planning_date = DateField('Planning Date', format='%Y-%m-%d', validators=[DataRequired()])
    case_overview = TextAreaField('Case Overview', validators=[DataRequired(), Length(max=5000), no_emoji_or_control_chars])
    incident_date = DateField('Incident Date', format='%Y-%m-%d', validators=[DataRequired()])
    incident_time = TimeField('Incident Time', format='%H:%M', validators=[DataRequired()])
    incident_where = StringField('Incident Where', validators=[DataRequired(), Length(max=255), no_emoji_or_control_chars])
    submit = SubmitField('Save Investigation Plan')


class OutcomeForm(FlaskForm):
    outcome = SelectField('Outcome', choices=[
        ('action_taken', 'Action Taken'),
        ('dismissed', 'Dismissed'),
        ('referred', 'Referred'),
        ('insufficient_evidence', 'Insufficient Evidence'),
    ], validators=[DataRequired()])
    outcome_details = TextAreaField('Details', validators=[DataRequired(), Length(max=5000), no_emoji_or_control_chars])
    submit = SubmitField('Recommend Outcome')


class AssignInvestigatorForm(FlaskForm):
    investigator = SelectField('Investigator', coerce=str, validators=[DataRequired()])
    submit = SubmitField('Assign Investigator')


class UserManagementForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=64), Regexp(NAME_REGEX, message=NAME_REGEX_MESSAGE)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=64), Regexp(NAME_REGEX, message=NAME_REGEX_MESSAGE)])
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
