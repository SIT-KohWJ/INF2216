#!/bin/bash

# SITinform Setup Script

echo "🚀 Setting up SITinform..."

# Create virtual environment
echo "🐍 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Copy environment file
echo "📄 Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ Created .env file from .env.example"
    echo "📝 Please edit .env with your configuration"
else
    echo "✅ .env file already exists"
fi

# Initialize database
echo "🗃️ Initializing database..."
python init_db.py

# Run application
echo "🌐 Starting application..."
echo "📌 Application will be available at http://localhost:5000"
echo "🔑 Use the credentials printed above to log in"

python run.py
