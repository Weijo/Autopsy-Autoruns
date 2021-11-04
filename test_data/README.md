# Test data

`setup.bat` script used to generate persistence keys

## Keys generated
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


## Test Data

Tested with Microsoft's Windows 10 VMware link [here](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)

1. Run `setup.bat` inside the vm and shut the machine down.

2. Add the windows 10 vmdk as a data source

3. Run autopsy autoruns plugin

Note: do not take a snapshot before running as the changes will be placed in a 001.vmdk file which can't be processed by autopsy. 
unless you figured out a way to do it anyway