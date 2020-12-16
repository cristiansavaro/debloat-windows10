Write-Host "Setting windows update active hours..."
$registryPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
Set-ItemProperty -Path "${registryPath}" -Name "ActiveHoursStart" -Value "8"
Set-ItemProperty -Path "${registryPath}" -Name "ActiveHoursEnd" -Value "20"
