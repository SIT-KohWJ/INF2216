"""Shared extension instances. Created here, bound to the app in create_app()
so there is no global app object and tests can build isolated apps."""
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
csrf = CSRFProtect()
# default_limits empty: apply explicit @limiter.limit(...) on sensitive routes
# (login, report submission) per C1/C2 rather than throttling everything.
limiter = Limiter(key_func=get_remote_address, default_limits=[])
