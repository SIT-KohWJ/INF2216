from flask import Blueprint

investigations_bp = Blueprint("investigations", __name__, url_prefix="/investigations")


@investigations_bp.get("/")
def dashboard():
    # TODO: require investigator role; list assigned reports
    raise NotImplementedError("FR-I: investigator dashboard")
