$ErrorActionPreference = "Stop"
python -m pip install pyinstaller
pyinstaller --onefile --name frostgate-agent agent/main.py

$distDir = Join-Path $PWD "dist"
$exe = Join-Path $distDir "frostgate-agent.exe"
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
$sha | Out-File -FilePath "$exe.sha256" -Encoding ascii

$manifest = @{
  file = "frostgate-agent.exe"
  sha256 = $sha
  version = "mvp1"
  build_timestamp = (Get-Date).ToUniversalTime().ToString("o")
  git_sha = (git rev-parse HEAD)
  signed = $false
}
$manifest | ConvertTo-Json | Out-File -FilePath "$distDir/manifest.json" -Encoding utf8
Write-Host "built $exe"
