$ErrorActionPreference = 'Stop'
$projectDirectory = $PSScriptRoot
$localPython = Join-Path $projectDirectory '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $localPython)) {
    $localPython = Join-Path $projectDirectory '.venv-repro\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $localPython)) {
    Write-Host 'Create .venv and install requirements.lock first; see README.md.'
    exit 1
}
$env:PYTHONPATH = Join-Path $projectDirectory 'src'
& $localPython -B -m phishing_analyzer
exit $LASTEXITCODE
