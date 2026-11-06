# Sample test-only certificate issuance from an extracted checkout.
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
py -3.13 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw 'Python environment setup failed' }
$py = Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $py -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
& $py run_tests.py
if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed' }
& $py run_x509lab.py demo --root public-demo
if ($LASTEXITCODE -ne 0) { throw 'Demo issuance failed' }
& $py run_x509lab.py verify-demo --root public-demo
if ($LASTEXITCODE -ne 0) { throw 'Demo verification failed' }
Write-Host 'Public test demo complete; outputs are under artifacts/public-demo/'
