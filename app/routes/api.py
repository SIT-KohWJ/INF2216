from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from app.services.report_service import ReportService
from app.services.audit_service import AuditService

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/reports', methods=['GET'])
@login_required
def get_reports():
    reports = ReportService.get_reports_for_user(current_user)
    report_list = [{'id': r.id, 'reference_number': r.reference_number, 'title': r.title, 'category': r.category, 'status': r.status, 'created_at': r.created_at.isoformat() if r.created_at else None} for r in reports]
    return jsonify({'reports': report_list})


@api_bp.route('/reports/<report_id>', methods=['GET'])
@login_required
def get_report(report_id):
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        return jsonify({'error': error}), 403
    decrypted_data = ReportService.decrypt_report_data(report)
    return jsonify({'id': report.id, 'reference_number': report.reference_number, 'title': report.title, 'description': report.description, 'category': report.category, 'status': report.status, 'decrypted_data': decrypted_data})


@api_bp.route('/audit', methods=['GET'])
@login_required
def get_audit_logs():
    logs = AuditService.get_audit_logs(limit=100)
    return jsonify({'logs': [{'id': log.id, 'action': log.action, 'timestamp': log.timestamp.isoformat() if log.timestamp else None, 'acting_role': log.acting_role, 'details': log.details} for log in logs]})


@api_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    from app.models import Report
    stats = {
        'total': Report.query.count(),
        'received': Report.query.filter_by(status='Received').count(),
        'triaged': Report.query.filter_by(status='Triaged').count(),
        'planning': Report.query.filter_by(status='Planning').count(),
        'investigating': Report.query.filter_by(status='Investigating').count(),
        'under_review': Report.query.filter_by(status='Under Review').count(),
        'closed': Report.query.filter_by(status='Closed').count()
    }
    return jsonify(stats)


@api_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})
