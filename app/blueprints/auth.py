from flask import Blueprint, flash, redirect, render_template, request, url_for
from ..extensions import limiter
from ..services.user_service import (
    RegistrationError,
    RegistrationValidationError,
    UserService,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    values = {"email": "", "full_name": ""}
    errors = {}

    if request.method == "POST":
        values["email"] = request.form.get("email", "")
        values["full_name"] = request.form.get("full_name", "")
        password = request.form.get("password", "")

        try:
            UserService.register(
                email=values["email"],
                password=password,
                full_name=values["full_name"],
            )
        except RegistrationValidationError as exc:
            errors = exc.field_errors
        except RegistrationError as exc:
            flash(str(exc), "error")
        except Exception:
            flash(UserService.GENERIC_FAILURE_MESSAGE, "error")
        else:
            flash("Registration successful. Please sign in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html", errors=errors, values=values)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")   # brute-force mitigation (C1)
def login():
    if request.method == "POST":
        # TODO: AuthService.verify_password + issue_token, generic errors on fail
        raise NotImplementedError("D1: login flow")
    return render_template("auth/login.html")


@auth_bp.post("/logout")
def logout():
    # TODO: AuthService.revoke_token(current jti)
    raise NotImplementedError("D: logout / token revocation")
