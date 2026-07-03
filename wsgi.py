"""WSGI entry point. gunicorn imports `app` from here (see Dockerfile CMD)."""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # Local dev only; in containers gunicorn runs this module.
    app.run(host="0.0.0.0", port=5000, debug=True)
