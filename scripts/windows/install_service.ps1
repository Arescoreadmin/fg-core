$ErrorActionPreference = "Stop"

$serviceName = "FrostGateAgent"
$displayName = "FrostGate Agent"
$programData = Join-Path $env:ProgramData "FrostGate\agent"
$configPath = Join-Path $programData "config.json"
$exePath = Join-Path $PSScriptRoot "..\..\dist\frostgate-agent.exe"

New-Item -ItemType Directory -Path $programData -Force | Out-Null
icacls $programData /inheritance:r | Out-Null
icacls $programData /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

if (-not (Test-Path $configPath)) {
  @{ api_base_url = "https://core.example"; heartbeat_interval = 30 } |
    ConvertTo-Json | Set-Content -Path $configPath -Encoding UTF8
}

sc.exe create $serviceName binPath= "\"$exePath\"" start= auto DisplayName= "$displayName" | Out-Null
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe start $serviceName | Out-Null
Write-Host "Installed $serviceName"
