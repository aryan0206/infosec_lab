@echo off
setlocal
cd /d "%~dp0"
set "PYTHON_CMD="
if defined IS_LAB_PYTHON (
    "%IS_LAB_PYTHON%" -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD="%IS_LAB_PYTHON%""
)
if not defined PYTHON_CMD (
    py -3 -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD=py -3"
)
if not defined PYTHON_CMD (
    python -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD=python"
)
if not defined PYTHON_CMD (
    python3 -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD=python3"
)
if not defined PYTHON_CMD (
    echo Python 3.10+ was not found. Set IS_LAB_PYTHON to its full executable path.
    goto :end
)
%PYTHON_CMD% -B check_setup.py
if errorlevel 1 goto :end
%PYTHON_CMD% -B exam_router.py
:end
pause
