@echo off
setlocal
cd /d "%~dp0"
if /i "%~1"=="/setup" goto :setup
if /i "%~1"=="/wheelhouse" goto :wheelhouse
:menu
echo.
echo IS LAB ENDSEM - EXAM PC TOOLKIT
echo 1 Check examination PC readiness
echo 2 Set up requirements in this folder
echo 3 Launch solution builder
echo 4 Open generated submissions
echo 0 Exit
set "CHOICE="
set /p "CHOICE=Choice: "
if errorlevel 1 exit /b 0
if "%CHOICE%"=="0" exit /b 0
if "%CHOICE%"=="1" goto :check
if "%CHOICE%"=="2" goto :setup
if "%CHOICE%"=="3" goto :builder
if "%CHOICE%"=="4" goto :output
echo Invalid choice. Enter a listed number.
goto :menu
:check
call :find_python
if not defined PYTHON_CMD goto :missing
%PYTHON_CMD% -B exam_readiness.py
if errorlevel 1 echo Read the issue and NEXT ACTION above before using the builder.
goto :menu
:setup
call :find_python
if not defined PYTHON_CMD goto :missing
%PYTHON_CMD% -B exam_setup.py
if errorlevel 1 echo Setup did not complete. Read the message above.
if /i "%~1"=="/setup" goto :done
goto :menu
:builder
call :find_python
if not defined PYTHON_CMD goto :missing
%PYTHON_CMD% -B master_builder.py
if errorlevel 1 echo Builder stopped. Read the error above, then retry.
goto :menu
:output
if not exist "exam_output" mkdir "exam_output"
explorer.exe "%~dp0exam_output"
if errorlevel 1 echo Could not open File Explorer. Folder: %~dp0exam_output
goto :menu
:wheelhouse
call :find_python
if not defined PYTHON_CMD goto :missing
echo Prepare wheels only when you know the exam PC Windows architecture and Python version.
set /p "TARGET_PY=Target Python minor (for example 3.12): "
set /p "TARGET_PLATFORM=Target wheel platform (win_amd64, win_arm64, win32): "
%PYTHON_CMD% -B prepare_wheelhouse.py --python "%TARGET_PY%" --platform "%TARGET_PLATFORM%"
goto :done
:missing
echo.
echo NOT READY: No supported CPython 3.10 through 3.14 interpreter was found.
echo The Python toolkit cannot run on this PC yet. Python cannot be installed with pip.
echo Next action: ask permission for a user-local Python 3.12 installation, then try option 1.
echo Installed launcher entries, if any:
py -0p 2>nul
if /i "%~1"=="/setup" goto :done
if /i "%~1"=="/wheelhouse" goto :done
goto :menu
:find_python
set "PYTHON_CMD="
if not defined PYTHON_CMD if exist "%~dp0.venv\Scripts\python.exe" (
    set "CANDIDATE="%~dp0.venv\Scripts\python.exe""
    call :probe
)
if not defined PYTHON_CMD if defined IS_LAB_PYTHON (
    set "CANDIDATE="%IS_LAB_PYTHON%""
    call :probe
)
if not defined PYTHON_CMD (set "CANDIDATE=py -3.12"&call :probe)
if not defined PYTHON_CMD (set "CANDIDATE=py -3.14"&call :probe)
if not defined PYTHON_CMD (set "CANDIDATE=py -3.13"&call :probe)
if not defined PYTHON_CMD (set "CANDIDATE=py -3.11"&call :probe)
if not defined PYTHON_CMD (set "CANDIDATE=py -3.10"&call :probe)
if not defined PYTHON_CMD (set "CANDIDATE=python"&call :probe)
if not defined PYTHON_CMD (set "CANDIDATE=python3"&call :probe)
for %%V in (312 313 314 311 310) do if not defined PYTHON_CMD if exist "%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe" (
    set "CANDIDATE="%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe""
    call :probe
)
if not defined PYTHON_CMD if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
    set "CANDIDATE="%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe""
    call :probe
)
exit /b
:probe
%CANDIDATE% -c "import sys;sys.exit(not ((3,10)<=sys.version_info[:2]<=(3,14)))" >nul 2>&1
if not errorlevel 1 set "PYTHON_CMD=%CANDIDATE%"
exit /b
:done
echo.
pause
exit /b
