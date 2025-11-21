@echo off
REM EthicCheck Quick Setup Script for Windows

echo ================================
echo  EthicCheck Setup Script
echo ================================
echo.

REM Check Python installation
echo [1/7] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.9+ from python.org
    pause
    exit /b 1
)
python --version
echo [OK] Python found
echo.

REM Create virtual environment
echo [2/7] Creating virtual environment...
if not exist "venv" (
    python -m venv venv
    echo [OK] Virtual environment created
) else (
    echo [INFO] Virtual environment already exists
)
echo.

REM Activate virtual environment
echo [3/7] Activating virtual environment...
call venv\Scripts\activate.bat
echo.

REM Upgrade pip
echo [4/7] Upgrading pip...
python -m pip install --upgrade pip --quiet
echo [OK] Pip upgraded
echo.

REM Install dependencies
echo [5/7] Installing dependencies...
echo This may take a few minutes...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo [OK] Dependencies installed
echo.

REM Create .env file
echo [6/7] Setting up environment variables...
if not exist ".env" (
    copy .env.example .env
    echo [INFO] Created .env file from template
    echo.
    echo IMPORTANT: Please edit .env and add your Groq API key
    echo Get your key from: https://console.groq.com
    echo.
    pause
    notepad .env
) else (
    echo [INFO] .env file already exists
)
echo.

REM Create directories
echo [7/7] Creating project directories...
if not exist "data" mkdir data
if not exist "logs" mkdir logs
if not exist "models" mkdir models
if not exist "temp" mkdir temp
if not exist ".streamlit" mkdir .streamlit

REM Create Streamlit config
if not exist ".streamlit\config.toml" (
    (
        echo [theme]
        echo primaryColor = "#667eea"
        echo backgroundColor = "#ffffff"
        echo secondaryBackgroundColor = "#f8f9fa"
        echo textColor = "#262730"
        echo font = "sans serif"
        echo.
        echo [server]
        echo port = 8501
        echo enableCORS = false
        echo maxUploadSize = 200
    ) > .streamlit\config.toml
    echo [OK] Streamlit config created
)
echo.

REM Test installation
echo Testing installation...
python -c "import streamlit; import groq; import sentence_transformers; print('[OK] All packages imported successfully')"
echo.

echo ================================
echo  Setup Complete!
echo ================================
echo.
echo To start the application:
echo   1. Run: venv\Scripts\activate
echo   2. Run: streamlit run app.py
echo.
echo The app will open at: http://localhost:8501
echo.
echo Next steps:
echo   - Read README.md for usage instructions
echo   - Edit .env and add your GROQ_API_KEY
echo   - Check DEPLOYMENT.md for deployment options
echo.

REM Ask to start app
set /p start="Would you like to start the app now? (y/n): "
if /i "%start%"=="y" (
    echo.
    echo Starting EthicCheck...
    echo Press Ctrl+C to stop
    echo.
    streamlit run app.py
)

pause
