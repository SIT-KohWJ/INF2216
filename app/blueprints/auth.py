from flask import Blueprint, render_template, request
from ..extensions import limiter

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


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
