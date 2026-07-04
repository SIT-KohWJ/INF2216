"""WSGI entry point. gunicorn imports `app` from here (see Dockerfile CMD)."""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Local dev only; in containers gunicorn runs this module.
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(
        debug=debug_mode,
        host=os.environ.get('FLASK_RUN_HOST', '127.0.0.1'),
        port=int(os.environ.get('FLASK_RUN_PORT', 5000)),
    )
