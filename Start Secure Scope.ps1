$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$bundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (Test-Path -LiteralPath $bundledPython) {
    & $bundledPython (Join-Path $PSScriptRoot 'main.py')
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    py -3 (Join-Path $PSScriptRoot 'main.py')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    python (Join-Path $PSScriptRoot 'main.py')
} else {
    Write-Host 'Install Python 3.11 or later, then run this launcher again.'
    Read-Host 'Press Enter to close'
}
