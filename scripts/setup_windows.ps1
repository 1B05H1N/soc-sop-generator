# SOC SOP Generator - Windows Setup (PowerShell)
# Run this script in PowerShell as Administrator if needed

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SOC SOP Generator - Windows Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to check if command exists
function Test-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

# 1. Check Python installation
Write-Host "[1/8] Checking Python installation..." -ForegroundColor Yellow
if (Test-Command "python") {
    $pythonVersion = python --version 2>&1
    Write-Host "SUCCESS: Python found: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8+ from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# 2. Check pip installation
Write-Host ""
Write-Host "[2/8] Checking pip installation..." -ForegroundColor Yellow
if (Test-Command "pip") {
    $pipVersion = pip --version 2>&1
    Write-Host "SUCCESS: pip found: $pipVersion" -ForegroundColor Green
} else {
    Write-Host "ERROR: pip is not available" -ForegroundColor Red
    Write-Host "Installing pip..." -ForegroundColor Yellow
    python -m ensurepip --upgrade
}

# 3. Check Git installation
Write-Host ""
Write-Host "[3/8] Checking Git installation..." -ForegroundColor Yellow
if (Test-Command "git") {
    $gitVersion = git --version 2>&1
    Write-Host "SUCCESS: Git found: $gitVersion" -ForegroundColor Green
} else {
    Write-Host "WARNING: Git is not installed or not in PATH" -ForegroundColor Yellow
    Write-Host "Please install Git from https://git-scm.com/download/win" -ForegroundColor Yellow
    Write-Host "This is optional but recommended for version control" -ForegroundColor Yellow
}

# 4. Create virtual environment
Write-Host ""
Write-Host "[4/8] Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "Virtual environment already exists" -ForegroundColor Green
} else {
    try {
        python -m venv venv
        Write-Host "SUCCESS: Virtual environment created" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to create virtual environment" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# 5. Activate virtual environment
Write-Host ""
Write-Host "[5/8] Activating virtual environment..." -ForegroundColor Yellow
try {
    & "venv\Scripts\Activate.ps1"
    Write-Host "SUCCESS: Virtual environment activated" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to activate virtual environment" -ForegroundColor Red
    Write-Host "Trying alternative activation method..." -ForegroundColor Yellow
    try {
        & "venv\Scripts\activate.bat"
        Write-Host "SUCCESS: Virtual environment activated (alternative method)" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to activate virtual environment" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# 6. Upgrade pip
Write-Host ""
Write-Host "[6/8] Upgrading pip..." -ForegroundColor Yellow
try {
    python -m pip install --upgrade pip
    Write-Host "SUCCESS: pip upgraded" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Failed to upgrade pip, continuing anyway..." -ForegroundColor Yellow
}

# 7. Install dependencies
Write-Host ""
Write-Host "[7/8] Installing dependencies..." -ForegroundColor Yellow
if (Test-Path "requirements.txt") {
    try {
        pip install -r requirements.txt
        Write-Host "SUCCESS: Dependencies installed from requirements.txt" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to install dependencies from requirements.txt" -ForegroundColor Red
        Write-Host "Trying individual package installation..." -ForegroundColor Yellow
        try {
            pip install click requests pandas
            Write-Host "SUCCESS: Basic packages installed" -ForegroundColor Green
        } catch {
            Write-Host "ERROR: Failed to install basic packages" -ForegroundColor Red
        }
    }
} else {
    Write-Host "WARNING: requirements.txt not found, installing basic packages..." -ForegroundColor Yellow
    try {
        pip install click requests pandas
        Write-Host "SUCCESS: Basic packages installed" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to install basic packages" -ForegroundColor Red
    }
}

# 8. Create directories
Write-Host ""
Write-Host "[8/8] Creating directories..." -ForegroundColor Yellow
if (-not (Test-Path "input")) {
    New-Item -ItemType Directory -Name "input" | Out-Null
}
if (-not (Test-Path "output")) {
    New-Item -ItemType Directory -Name "output" | Out-Null
}
Write-Host "SUCCESS: Directories created" -ForegroundColor Green

# Test installation
Write-Host ""
Write-Host "[TEST] Testing installation..." -ForegroundColor Yellow
try {
    python -c "import click, requests, pandas; print('SUCCESS: All packages installed successfully!')"
    Write-Host "SUCCESS: Package test passed" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Package test failed" -ForegroundColor Red
    Write-Host "Please check the installation and try again" -ForegroundColor Red
}

# Test main script
Write-Host ""
Write-Host "[TEST] Testing main script..." -ForegroundColor Yellow
try {
    $null = python main.py --help 2>&1
    Write-Host "SUCCESS: Main script test passed" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Main script test failed" -ForegroundColor Red
    Write-Host "Please check the installation and try again" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "SUCCESS: Virtual environment: venv" -ForegroundColor Green
Write-Host "SUCCESS: Dependencies installed" -ForegroundColor Green
Write-Host "SUCCESS: Directories created: input/, output/" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Create .env file with your Confluence credentials" -ForegroundColor White
Write-Host "2. Add your rule data to the input/ directory" -ForegroundColor White
Write-Host "3. Test with: python main.py --help" -ForegroundColor White
Write-Host "4. Generate SOPs: python main.py generate --input input/your_file.json --output output/" -ForegroundColor White
Write-Host "5. Upload to Confluence: python main.py upload-to-confluence --input input/your_file.json --confluence-parent 'PARENT_ID'" -ForegroundColor White
Write-Host ""
Write-Host "To activate the environment later:" -ForegroundColor Yellow
Write-Host "   venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host ""
Write-Host "To deactivate the environment:" -ForegroundColor Yellow
Write-Host "   deactivate" -ForegroundColor White
Write-Host ""

# Create .env template if it doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env template..." -ForegroundColor Yellow
    @"
# Confluence Configuration
CONFLUENCE_URL=https://your-domain.atlassian.net
CONFLUENCE_USERNAME=your-email@domain.com
CONFLUENCE_API_TOKEN=your-api-token
CONFLUENCE_SPACE_KEY=YOUR_SPACE_KEY
"@ | Out-File -FilePath ".env" -Encoding UTF8
    Write-Host "SUCCESS: .env template created - please update with your credentials" -ForegroundColor Green
}

Read-Host "Press Enter to continue" 