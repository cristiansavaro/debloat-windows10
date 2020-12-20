function Test-DesktopIconHidden {            
  [CmdletBinding(SupportsShouldProcess=$false)]
  Param()

  Process {
    $Shell = New-Object -ComObject "Shell.Application"
    $Shell.GetSetting(0x4000)
  }
}

function Test-RegistryKeyValue {
  [CmdletBinding(SupportsShouldProcess=$false)]
  Param([Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)] [string]$Path,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipeline=$true)] [string]$Value)

  Process {
    if (Test-Path $Path) {
      $Key=Get-Item -LiteralPath $Path
      if ($Key.GetValue($Value, $null) -ne $null) { $true } else { $false }
    }
    else { $false }
  }
}

$RegPath="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$KeyList=@(@{Name="TaskbarGlomLevel";     Value=1; Description="Combine taskbar buttons"},
           @{Name="TaskbarSmallIcons";    Value=1; Description="Use small taskbar buttons"},
           @{Name="HideFileExt";          Value=0; Description="Hide file extensions"},
           @{Name="HideIcons";            Value=0; Description="Hide Desktop icons"},
           @{Name="Hidden";               Value=1; Description="Show Hidden files"},
           @{Name="HideDrivesWithNoMedia";Value=1; Description="Show all drives"},
           @{Name="HideMergeConflicts";   Value=0; Description="Hide merge conflicts"},
           @{Name="ListviewShadow";       Value=0; Description="ListviewShadow"},
           @{Name="MMTaskbarEnabled";     Value=0; Description="MMTaskbarEnabled"},
           @{Name="SharingWizardOn";      Value=0; Description="Use Sharing Wizard"},
           @{Name="TaskbarAnimations";    Value=1; Description="TaskbarAnimations"})

for ($i=0; $i -lt $KeyList.Count; $i++) {
  if (Test-RegistryKeyValue -Path $RegPath -Value $KeyList[$i].Name) {
    if ((Get-ItemPropertyValue -Path $RegPath -Name $KeyList[$i].Name) -eq $KeyList[$i].Value) {
      Write-Verbose "$($KeyList[$i].Description) is already set"
    }
    else { Set-ItemProperty -Path $RegPath -Name $KeyList[$i].Name -Value $KeyList[$i].Value }
  }
  else { New-ItemProperty -Path $RegPath -Name $KeyList[$i].Name -Value $KeyList[$i].Value -PropertyType DWORD -Force > $null }
}

$RegPath="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$KeyList=@(@{Name="{20D04FE0-3AEA-1069-A2D8-08002B30309D}"; Value=0; Description="My Computer icon"},
           #@{Name="{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}"; Value=0; Description="Control Panel icon"},
           @{Name="{59031a47-3f72-44a7-89c5-5595fe6b30ee}"; Value=0; Description="User Files icon"},
           @{Name="{645FF040-5081-101B-9F08-00AA002F954E}"; Value=0; Description="Recycle Bin icon"},
           @{Name="{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}"; Value=0; Description="Network icon"},
           @{Name="{018D5C66-4533-4307-9B53-224DE2ED1FE6}"; Value=0; Description="Unknown icon"})

for ($i=0; $i -lt $KeyList.Count; $i++) {
  if (Test-RegistryKeyValue -Path $RegPath -Value $KeyList[$i].Name) {
    if ((Get-ItemPropertyValue -Path $RegPath -Name $KeyList[$i].Name) -eq $KeyList[$i].Value) {
      Write-Verbose "$($KeyList[$i].Description) is already set"
    }
    else { Set-ItemProperty -Path $RegPath -Name $KeyList[$i].Name -Value $KeyList[$i].Value }
  }
  else { New-ItemProperty -Path $RegPath -Name $KeyList[$i].Name -Value $KeyList[$i].Value -PropertyType DWORD -Force > $null }
}
