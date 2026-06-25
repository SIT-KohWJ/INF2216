# SITinform - Secure Whistleblowing Platform

## Project Structure

```
sitinform/
├── app/                  # Main application package
│   ├── __init__.py        # Flask app initialization
│   ├── config.py          # Configuration settings
│   ├── models.py          # Database models
│   ├── routes/             # Route handlers
│   │   ├── __init__.py
│   │   ├── auth.py         # Authentication routes
│   │   ├── reports.py      # Report-related routes
│   │   ├── admin.py        # Admin routes
│   │   └── api.py          # API endpoints
│   ├── services/          # Business logic services
│   │   ├── __init__.py
│   │   ├── auth_service.py # Authentication services
│   │   ├── report_service.py # Report services
│   │   ├── audit_service.py # Audit logging
│   │   └── crypto_service.py # Cryptographic operations
│   ├── utils/              # Utility functions
│   │   ├── __init__.py
│   │   ├── decorators.py    # Custom decorators
│   │   ├── validators.py   # Input validation
│   │   └── helpers.py      # Helper functions
│   ├── static/            # Static files
│   │   ├── css/            # CSS files
│   │   ├── js/             # JavaScript files
│   │   └── images/         # Image assets
│   └── templates/         # HTML templates
│       ├── base.html      # Base template
│       ├── auth/           # Authentication templates
│       ├── reports/        # Report templates
│       └── admin/          # Admin templates
├── migrations/            # Database migration scripts
├── tests/                 # Test files
│   ├── unit/               # Unit tests
│   └── integration/       # Integration tests
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variables template
└── run.py                 # Application entry point
```

## Setup Instructions

1. **Install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Set up environment variables**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Initialize database**:
```bash
flask db init
flask db migrate
flask db upgrade
```

4. **Run the application**:
```bash
python run.py
```

## Security Features

- HMAC-SHA256 for user anonymity
- AES-256-GCM for data encryption
- ECDSA for audit log signing
- Role-based access control
- Comprehensive audit logging
- Secure session management

## Development Guidelines

1. Follow OWASP security practices
2. Use parameterized queries only
3. Validate all user inputs
4. Implement proper error handling
5. Write comprehensive tests
