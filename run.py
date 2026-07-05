#!/usr/bin/env python3
"""
SITinform - Secure Whistleblowing Platform
Main application entry point
"""

import os

from app import create_app

if __name__ == '__main__':
    app = create_app()
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(
        debug=debug_mode,
        host=os.environ.get('FLASK_RUN_HOST', '127.0.0.1'),
        port=int(os.environ.get('FLASK_RUN_PORT', 5000)),
    )
