#!/bin/bash

# EthicCheck Quick Setup Script
# Run this to set up the project in one command

set -e  # Exit on error

echo "🛡️  EthicCheck Setup Script"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "📌 Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.9"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}❌ Python 3.9+ required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Python $PYTHON_VERSION detected${NC}"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo ""
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}✅ Virtual environment created${NC}"
else
    echo -e "${YELLOW}⚠️  Virtual environment already exists${NC}"
fi

# Activate virtual environment
echo ""
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo "⬆️  Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install dependencies
echo ""
echo "📚 Installing dependencies..."
echo "   This may take a few minutes..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Dependencies installed successfully${NC}"
else
    echo -e "${RED}❌ Failed to install dependencies${NC}"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo ""
    echo "🔐 Setting up environment variables..."
    cp .env.example .env
    
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT: Please edit .env and add your Groq API key${NC}"
    echo ""
    echo "Get your API key from: https://console.groq.com"
    echo ""
    read -p "Press Enter to open .env in your default editor..." 
    
    # Try to open in default editor
    if command -v nano &> /dev/null; then
        nano .env
    elif command -v vim &> /dev/null; then
        vim .env
    else
        echo "Please manually edit .env file and add your GROQ_API_KEY"
    fi
else
    echo -e "${YELLOW}⚠️  .env file already exists${NC}"
fi

# Create necessary directories
echo ""
echo "📁 Creating project directories..."
mkdir -p data logs models temp
echo -e "${GREEN}✅ Directories created${NC}"

# Create Streamlit config if needed
if [ ! -d ".streamlit" ]; then
    mkdir -p .streamlit
    cat > .streamlit/config.toml << EOF
[theme]
primaryColor = "#667eea"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f8f9fa"
textColor = "#262730"
font = "sans serif"

[server]
port = 8501
enableCORS = false
maxUploadSize = 200
EOF
    echo -e "${GREEN}✅ Streamlit config created${NC}"
fi

# Test imports
echo ""
echo "🧪 Testing installation..."
python3 << EOF
try:
    import streamlit
    import groq
    import sentence_transformers
    import PyPDF2
    print("✅ All core packages imported successfully")
except ImportError as e:
    print(f"❌ Import error: {e}")
    exit(1)
EOF

# Check for Groq API key
echo ""
echo "🔑 Checking for Groq API key..."
if grep -q "your_groq_api_key_here" .env 2>/dev/null; then
    echo -e "${RED}❌ Please set your GROQ_API_KEY in .env file${NC}"
    echo ""
    echo "Steps:"
    echo "1. Go to https://console.groq.com"
    echo "2. Sign up and get an API key"
    echo "3. Edit .env and replace 'your_groq_api_key_here' with your key"
else
    echo -e "${GREEN}✅ Groq API key appears to be set${NC}"
fi

# Print success message
echo ""
echo "======================================"
echo -e "${GREEN}✨ Setup Complete! ✨${NC}"
echo "======================================"
echo ""
echo "🚀 To start the application:"
echo "   1. Activate virtual environment: source venv/bin/activate"
echo "   2. Run the app: streamlit run app.py"
echo ""
echo "🌐 The app will open at: http://localhost:8501"
echo ""
echo "📚 Next steps:"
echo "   - Read README.md for usage instructions"
echo "   - Check DEPLOYMENT.md for deployment options"
echo "   - Run tests: pytest tests/"
echo ""
echo "💡 Quick commands:"
echo "   Start app:     streamlit run app.py"
echo "   Run tests:     pytest tests/"
echo "   Update deps:   pip install -r requirements.txt --upgrade"
echo ""

# Ask if user wants to start the app now
read -p "Would you like to start the app now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "🚀 Starting EthicCheck..."
    echo "   Press Ctrl+C to stop"
    echo ""
    streamlit run app.py
fi
