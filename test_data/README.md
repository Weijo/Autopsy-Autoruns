# Test data

`setup.bat` script used to generate persistence keys

Keys generated:
- Registry Run keys
    - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    - HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
    - HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    - HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
- Active Setup
    - HKLM\Software\Microsoft\Active Setup\Installed Components\{Malware}
- Scheduled Tasks
    - SCHTASKS /CREATE /SC HOURLY /TN "System\Setup" /TR "C:\Windows\Temp\setup.bat" /F
    - SCHTASKS /CREATE /SC DAILY /TN "System\Nothing" /TR "cmd /C 'net user sus sus /add'" /RL HIGHEST /F
- Service
    - sc create persistence binpath="cmd.exe /k C:\Windows\Temp\malware.bat" start="auto" obj="LocalSystem" /f
- WinLogon
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v Userinit /t REG_SZ /d C:\Windows\Temp\malware.bat /f
    - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v Shell /t REG_SZ /d "explorer.exe, C:\Windows\Temp\malware.bat" /f
