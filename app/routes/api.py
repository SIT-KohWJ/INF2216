from flask import Blueprint, jsonify, g, request
from flask_login import login_required, current_user

from app import db
from app.models import Report, User
from app.securityfeature import require_permission, AuditService
from app.services.report_service import ReportService
from sqlalchemy import func

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/reports', methods=['GET'])
@login_required
def get_reports():
    """Return reports visible to *current_user* (own reports for whistleblower,
    assigned reports for investigator, all reports for report_admin).

    Decrypted titles/descriptions are NOT included in the API response --
    only the encrypted `title` placeholder column. The web UI decrypts on the
    server-side render; the JSON API deliberately exposes only metadata.
    """
    reports = ReportService.get_reports_for_user(current_user)
    report_list = [{
        'id': r.id,
        'reference_number': r.reference_number,
        'title': r.title,            # placeholder "[Encrypted Report]" -- no PII
        'category': r.category,
        'status': r.status,
        'created_at': r.created_at.isoformat() if r.created_at else None,
    } for r in reports]
    return jsonify({'reports': report_list})


@api_bp.route('/reports/<report_id>', methods=['GET'])
@login_required
def get_report(report_id):
    # Reuse the service-layer ownership check (whistleblower/investigator IDOR).
    report, error = ReportService.get_report_by_id(report_id, current_user)
    if error:
        return jsonify({'error': error, 'request_id': g.get('request_id', '-')}), 403
    # NOTE: deliberately do NOT return decrypted_data via the JSON API.
    # The HTML view page decrypts server-side; exposing decrypted content
    # over /api/* would let a Burp attacker harvest report bodies without
    # the CSRF-protected form flow.
    return jsonify({
        'id': report.id,
        'reference_number': report.reference_number,
        'title': report.title,                  # placeholder only
        'description': report.description,      # placeholder only
        'category': report.category,
        'status': report.status,
        'severity': report.severity,
        'created_at': report.created_at.isoformat() if report.created_at else None,
    })


@api_bp.route('/audit', methods=['GET'])
@login_required
@require_permission('api.view_audit')
def get_audit_logs():
    """Return audit logs scoped to the caller's role.

    report_admin  -> report-scoped actions only (REPORT_ACTIONS)
    system_admin  -> system-scoped actions only (SYSTEM_ACTIONS)

    This endpoint was previously open to ANY authenticated user (including
    whistleblowers), which leaked the entire audit log over JSON. The
    @require_permission decorator now restricts it to admins only.
    """
    if current_user.role == 'report_admin':
        logs = AuditService.get_report_audit_logs(limit=100)
    else:
        logs = AuditService.get_system_audit_logs(limit=100)
    return jsonify({'logs': [{
        'id': log.id,
        'action': log.action,
        'timestamp': log.timestamp.isoformat() if log.timestamp else None,
        'acting_role': log.acting_role,
        # Deliberately omit acting_user_id, target_id, ip_address, details
        # from the JSON API -- those are admin-console-only fields. The
        # HTML audit_logs.html template still shows them (it's behind the
        # same auth), but the JSON endpoint is more exposed (no CSRF token
        # required for GET) so it's minimised.
        'target_type': log.target_type,
    } for log in logs]})


@api_bp.route('/stats', methods=['GET'])
@login_required
@require_permission('api.view_stats')
def get_stats():
    """Role-aware aggregate stats.

    - whistleblower  -> counts of THEIR OWN reports, broken down by status
                        (so they can see "I have 2 received, 1 investigating"
                        without exposing anyone else's data).
    - report_admin   -> system-wide report counts by status + by category,
                        plus a per-user breakdown (so the admin can see
                        "which investigators have how many open cases").
    - system_admin   -> system-wide user counts + role distribution
                        (system_admin doesn't work with reports, they work
                        with users).
    """
    if current_user.role == 'whistleblower':
        base_q = Report.query.filter_by(user_id=current_user.id)
        stats = {
            'scope': 'own_reports',
            'total': base_q.count(),
            'received':      base_q.filter_by(status='Received').count(),
            'triaged':       base_q.filter_by(status='Triaged').count(),
            'planning':      base_q.filter_by(status='Planning').count(),
            'investigating': base_q.filter_by(status='Investigating').count(),
            'under_review':  base_q.filter_by(status='Under Review').count(),
            'closed':        base_q.filter_by(status='Closed').count(),
        }
        return jsonify(stats)

    if current_user.role == 'report_admin':
        # System-wide report stats + per-investigator load.
        by_status = {
            'total':         Report.query.count(),
            'received':      Report.query.filter_by(status='Received').count(),
            'triaged':       Report.query.filter_by(status='Triaged').count(),
            'planning':      Report.query.filter_by(status='Planning').count(),
            'investigating': Report.query.filter_by(status='Investigating').count(),
            'under_review':  Report.query.filter_by(status='Under Review').count(),
            'closed':        Report.query.filter_by(status='Closed').count(),
        }
        by_category = dict(
            db.session.query(Report.category, func.count(Report.id))
            .group_by(Report.category).all()
        )
        # Per-investigator open-case count. We expose only the investigator's
        # full name (computed server-side from first+last, never the reporter's
        # identity). group_by on User.id (the PK) so two investigators with the
        # same name don't get merged.
        inv_rows = (
            db.session.query(
                (User.first_name + ' ' + User.last_name).label('full_name'),
                func.count(Report.id).label('open_cases'),
            )
            .join(Report, Report.investigator_id == User.id)
            .filter(Report.status != 'Closed')
            .group_by(User.id)
            .all()
        )
        return jsonify({
            'scope': 'system_reports',
            'by_status': by_status,
            'by_category': {k: v for k, v in by_category.items()},
            'investigator_load': [{'name': n, 'open_cases': c} for n, c in inv_rows],
        })

    # system_admin
    role_counts = dict(
        db.session.query(User.role, func.count(User.id))
        .group_by(User.role).all()
    )
    return jsonify({
        'scope': 'system_users',
        'total_users': User.query.count(),
        'active_users': User.query.filter_by(is_active=True).count(),
        'suspended_users': User.query.filter_by(is_active=False).count(),
        'by_role': {k: v for k, v in role_counts.items()},
    })


@api_bp.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})
