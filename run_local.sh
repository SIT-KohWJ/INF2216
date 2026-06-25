#!/bin/bash

echo "🚀 Starting SITinform locally..."
echo ""

# Activate virtual environment
source venv/bin/activate

# Run the application
echo "🌐 Application will be available at: http://localhost:5000"
echo "🔑 Use the test credentials to log in:"
echo "   Whistleblower: whistleblower1@sit.singaporetech.edu.sg / Password123!"
echo "   Admin: admin@sit.singaporetech.edu.sg / Admin123!"
echo ""

python run.py
