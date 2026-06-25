# SITinform - Local Run Instructions

## 🚀 Quick Start

The application is fully configured and ready to run on your local machine!

### Step 1: Navigate to Project Directory

```bash
cd /home/kali/SSDProj/ProjCodes
```

### Step 2: Run the Application

```bash
# Option 1: Use the run script
./run_local.sh

# Option 2: Manual run
source venv/bin/activate
python run.py
```

### Step 3: Access the Application

Open your web browser and go to: **http://localhost:5000**

## 🔑 Test Credentials

The system comes with pre-configured test users:

### Whistleblower Accounts
- **Email**: `whistleblower1@sit.singaporetech.edu.sg`
- **Password**: `Password123!`
- **Role**: Whistleblower (can submit and view own reports)

- **Email**: `whistleblower2@sit.singaporetech.edu.sg`
- **Password**: `Password123!`
- **Role**: Whistleblower

### Investigator Account
- **Email**: `investigator1@sit.singaporetech.edu.sg`
- **Password**: `Password123!`
- **Role**: Investigator (can view and investigate assigned reports)

### Admin Accounts
- **Email**: `admin@sit.singaporetech.edu.sg`
- **Password**: `Admin123!`
- **Role**: Admin (can manage reports and users)

- **Email**: `sysadmin@sit.singaporetech.edu.sg`
- **Password**: `Sysadmin123!`
- **Role**: System Admin (full system access)

## 📝 First Time Setup (Already Done)

The following has already been completed:

1. ✅ Virtual environment created (`venv/`)
2. ✅ All dependencies installed
3. ✅ Database initialized with test data
4. ✅ Test users created
5. ✅ Sample reports created

## 🛠️ Troubleshooting

### If you get port conflicts

```bash
# Kill process on port 5000
sudo lsof -i :5000
kill -9 <PID>

# Then restart
./run_local.sh
```

### If you need to reset the database

```bash
rm sitinform.db
python init_db.py
```

### If you get dependency errors

```bash
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 📋 Application Features

### Available Features

- ✅ User registration and login
- ✅ Anonymous report submission
- ✅ Evidence file uploads
- ✅ Report status tracking
- ✅ Investigation workflow
- ✅ Role-based dashboards
- ✅ Comprehensive audit logging
- ✅ Data encryption (AES-256-GCM)
- ✅ User anonymity (HMAC-SHA256)
- ✅ Digital signatures (ECDSA)

### Security Features

- 🔒 Secure password hashing (bcrypt)
- 🔒 CSRF protection on all forms
- 🔒 Rate limiting on sensitive endpoints
- 🔒 Secure session management
- 🔒 Input validation and sanitization
- 🔒 Parameterized SQL queries
- 🔒 Role-based access control

## 🎯 What to Test

1. **Whistleblower Flow**:
   - Login as whistleblower1
   - Submit a new report
   - View your reports
   - Check report status

2. **Investigator Flow**:
   - Login as investigator1
   - View assigned reports
   - Add investigation notes
   - Update report status

3. **Admin Flow**:
   - Login as admin
   - View all reports
   - Assign investigators
   - Update report statuses
   - View audit logs
   - Check security monitoring

## 📚 Documentation

- **COMPLETION_SUMMARY.md**: Overview of implementation
- **IMPLEMENTATION_SUMMARY.md**: Detailed technical documentation
- **README.md**: Project structure and setup

## 🎉 Enjoy!

The SITinform platform is fully functional and ready for you to explore all the secure whistleblowing features. The application demonstrates:

- Strong cryptographic protections
- Comprehensive security controls
- Clean, maintainable code
- Production-ready architecture

**Have fun testing the application!** 🚀
