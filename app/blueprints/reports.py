from flask import Blueprint, render_template, request
from ..extensions import limiter

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/new", methods=["GET", "POST"])
@limiter.limit("10 per hour")    # submission throttle (C2)
def new_report():
    if request.method == "POST":
        # TODO: ValidationService.sanitise -> ReportService.submit
        raise NotImplementedError("FR-W: submit report")
    return render_template("reports/new.html")


@reports_bp.get("/<uuid:public_id>")
def view_report(public_id):
    # TODO: AccessControlService.can_view_report before rendering (E2/E4)
    raise NotImplementedError("E4: view report with authz")
