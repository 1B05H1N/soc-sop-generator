@echo off
setlocal enabledelayedexpansion

echo.
echo ========================================
echo   SOC SOP Generator - Windows Setup
echo ========================================
echo.

:: Check if Python is installed
echo [1/8] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
) else (
    echo SUCCESS: Python found
    python --version
)

:: Check if pip is available
echo.
echo [2/8] Checking pip installation...
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not available
    echo Installing pip...
    python -m ensurepip --upgrade
) else (
    echo SUCCESS: pip found
    pip --version
)

:: Check if Git is installed
echo.
echo [3/8] Checking Git installation...
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Git is not installed or not in PATH
    echo Please install Git from https://git-scm.com/download/win
    echo This is optional but recommended for version control
) else (
    echo SUCCESS: Git found
    git --version
)

:: Create virtual environment
echo.
echo [4/8] Creating virtual environment...
if exist venv (
    echo Virtual environment already exists
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo SUCCESS: Virtual environment created
)

:: Activate virtual environment
echo.
echo [5/8] Activating virtual environment...
call venv\Scripts\activate
if %errorlevel% neq 0 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)
echo SUCCESS: Virtual environment activated

:: Upgrade pip
echo.
echo [6/8] Upgrading pip...
python -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo WARNING: Failed to upgrade pip, continuing anyway...
) else (
    echo SUCCESS: pip upgraded
)

:: Install dependencies
echo.
echo [7/8] Installing dependencies...
if exist requirements.txt (
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install dependencies
        echo Trying individual package installation...
        pip install click requests pandas
    )
) else (
    echo WARNING: requirements.txt not found, installing basic packages...
    pip install click requests pandas
)

:: Create directories
echo.
echo [8/8] Creating directories...
if not exist input mkdir input
if not exist output mkdir output
echo SUCCESS: Directories created

:: Test installation
echo.
echo [TEST] Testing installation...
python -c "import click, requests, pandas; print('SUCCESS: All packages installed successfully!')" 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Package test failed
    echo Please check the installation and try again
) else (
    echo SUCCESS: Package test passed
)

:: Test main script
echo.
echo [TEST] Testing main script...
python main.py --help >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Main script test failed
    echo Please check the installation and try again
) else (
    echo SUCCESS: Main script test passed
)

echo.
echo ========================================
echo   Setup Complete!
echo ========================================
echo.
echo SUCCESS: Virtual environment: venv
echo SUCCESS: Dependencies installed
echo SUCCESS: Directories created: input/, output/
echo.
echo Next steps:
echo 1. Create .env file with your Confluence credentials
echo 2. Add your rule data to the input/ directory
echo 3. Test with: python main.py --help
echo 4. Generate SOPs: python main.py generate --input input/your_file.json --output output/
echo 5. Upload to Confluence: python main.py upload-to-confluence --input input/your_file.json --confluence-parent "PARENT_ID"
echo.
echo To activate the environment later:
echo    venv\Scripts\activate
echo.
echo To deactivate the environment:
echo    deactivate
echo.

:: Create .env template if it doesn't exist
if not exist .env (
    echo Creating .env template...
    (
        echo # Confluence Configuration
        echo CONFLUENCE_URL=https://your-domain.atlassian.net
        echo CONFLUENCE_USERNAME=your-email@domain.com
        echo CONFLUENCE_API_TOKEN=your-api-token
        echo CONFLUENCE_SPACE_KEY=YOUR_SPACE_KEY
    ) > .env
    echo SUCCESS: .env template created - please update with your credentials
)

pause 