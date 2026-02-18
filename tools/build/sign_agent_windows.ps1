param(
  [string]$ExePath = "dist/frostgate-agent.exe"
)

$ErrorActionPreference = "Stop"

if (-not $env:FG_SIGN_CERT_PATH -or -not $env:FG_SIGN_CERT_PASSWORD) {
  Write-Host "No signing certificate configured; leaving artifact unsigned"
  exit 0
}

signtool.exe sign /f $env:FG_SIGN_CERT_PATH /p $env:FG_SIGN_CERT_PASSWORD /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $ExePath
Write-Host "Signed $ExePath"
