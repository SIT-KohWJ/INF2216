#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User, Report, ReportStatusHistory
from app.services.crypto_service import crypto_service
import json


def init_db():
    app = create_app('development')
    with app.app_context():
        db.create_all()
        print("Initializing database with test data...")

        test_users = [
            {'email': 'whistleblower1@sit.singaporetech.edu.sg', 'password': 'Password123!', 'first_name': 'Alice', 'last_name': 'Tan', 'role': 'whistleblower'},
            {'email': 'whistleblower2@sit.singaporetech.edu.sg', 'password': 'Password123!', 'first_name': 'Bob', 'last_name': 'Lim', 'role': 'whistleblower'},
            {'email': 'investigator1@sit.singaporetech.edu.sg', 'password': 'Password123!', 'first_name': 'Charlie', 'last_name': 'Wong', 'role': 'investigator'},
            {'email': 'reportadmin@sit.singaporetech.edu.sg', 'password': 'Admin123!', 'first_name': 'Report', 'last_name': 'Admin', 'role': 'report_admin'},
            {'email': 'sysadmin@sit.singaporetech.edu.sg', 'password': 'Sysadmin123!', 'first_name': 'System', 'last_name': 'Admin', 'role': 'system_admin'},
        ]

        for user_data in test_users:
            existing_user = User.query.filter_by(email=user_data['email']).first()
            if not existing_user:
                user = User(email=user_data['email'], first_name=user_data['first_name'], last_name=user_data['last_name'], role=user_data['role'])
                user.set_password(user_data['password'])
                db.session.add(user)
                print(f"  Created user: {user.email}")

        db.session.commit()

        users = User.query.all()
        whistleblowers = [u for u in users if u.role == 'whistleblower']
        investigators = [u for u in users if u.role == 'investigator']

        existing_reports = Report.query.count()
        if existing_reports == 0 and len(whistleblowers) > 0:
            test_reports = [
                {'user': whistleblowers[0], 'title': 'Academic Misconduct Report', 'description': 'Observed a student submitting plagiarized work.', 'category': 'academic_misconduct', 'severity': 'medium', 'status': 'Received'},
                {'user': whistleblowers[1] if len(whistleblowers) > 1 else whistleblowers[0], 'title': 'Financial Concern', 'description': 'Noticed irregularities in departmental expense reports.', 'category': 'financial_misconduct', 'severity': 'high', 'status': 'Triaged'},
                {'user': whistleblowers[0], 'title': 'Harassment Incident', 'description': 'Witnessed inappropriate behavior in the workplace.', 'category': 'harassment', 'severity': 'critical', 'status': 'Investigating'},
            ]

            for report_data in test_reports:
                report_json = {'title': report_data['title'], 'description': report_data['description'], 'category': report_data['category']}
                encrypted_data = crypto_service.encrypt_data(json.dumps(report_json))
                reference_number = crypto_service.generate_reference_number()
                report = Report(submitter_hash=crypto_service.generate_user_hash(report_data['user'].id), title=report_data['title'], description=report_data['description'], category=report_data['category'], severity=report_data['severity'], status=report_data['status'], encrypted_data=encrypted_data, user_id=report_data['user'].id, reference_number=reference_number)
                if report_data['status'] != 'Received' and investigators:
                    report.investigator_id = investigators[0].id
                if report_data['status'] == 'Investigating':
                    report.outcome = 'action_taken'
                    report.outcome_details = 'Investigation in progress.'
                db.session.add(report)
                db.session.commit()
                status_history = ReportStatusHistory(report_id=report.id, old_status='New', new_status=report_data['status'], changed_by_role=report_data['user'].role)
                db.session.add(status_history)
                db.session.commit()
                print(f"  Created report: {report.title} (Ref: {reference_number}, Status: {report.status})")

        print("\nDatabase initialization complete!")
        print(f"Created {len(test_users)} users\n")
        print("Login Credentials:")
        for user_data in test_users:
            print(f"  {user_data['email']}: {user_data['password']} ({user_data['role']})")


if __name__ == '__main__':
    init_db()
