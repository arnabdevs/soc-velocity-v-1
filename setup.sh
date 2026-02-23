#!/bin/bash
echo "🛡️ AEGIS SOC ENGINE SETUP"
echo "Installing system dependencies..."

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt-get update
    sudo apt-get install nmap -y
elif [[ "$OSTYPE" == "darwin"* ]]; then
    brew install nmap
else
    echo "Please install Nmap manually from https://nmap.org/download.html"
fi

echo "Installing python dependencies..."
pip install -r backend/requirements.txt

echo "✅ Setup complete. Run 'python backend/app.py' to start."
