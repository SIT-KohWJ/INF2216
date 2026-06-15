from flask import Blueprint

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.get("/")
def dashboard():
    # TODO: require admin/system_admin role; triage queue + audit log view
    raise NotImplementedError("FR-AD: admin dashboard")
