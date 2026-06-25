#!/usr/bin/env python3
"""
SITinform - Secure Whistleblowing Platform
Main application entry point
"""

from app import create_app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
