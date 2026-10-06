# Deploy ConfigMask to the internal Ubuntu server.
# Run this on the PC that can reach the server and holds the SSH key:
#   powershell -ExecutionPolicy Bypass -File .\deploy\deploy.ps1

param(
    [string]$Server = "172.16.40.200",
    [string]$User = "sysadmin",
    [string]$KeyDir = "C:\Users\User\.ssh",
    [string]$KeyPath = "",
    [string]$Dest = "/opt/tools/configmask",
    [string]$Port = "5599"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $KeyPath) {
    $names = @("id_ed25519", "id_rsa", "id_ecdsa", "id_ed25519_sk")
    foreach ($name in $names) {
        $candidate = Join-Path $KeyDir $name
        if (Test-Path -LiteralPath $candidate) {
            $KeyPath = $candidate
            break
        }
    }
}
if (-not $KeyPath -or -not (Test-Path -LiteralPath $KeyPath)) {
    Write-Error "No private key found in $KeyDir. Pass -KeyPath with the key file (not the .pub)."
}

Write-Host "Using key $KeyPath"
Write-Host "Installing to ${User}@${Server}:${Dest} on port ${Port}"

$ssh = @("-i", $KeyPath, "-o", "StrictHostKeyChecking=accept-new")
$target = "${User}@${Server}"

& ssh @ssh $target "sudo mkdir -p '$Dest' && sudo chown ${User}:${User} '$Dest'"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$archive = Join-Path $env:TEMP "configmask-deploy.tgz"
if (Test-Path $archive) { Remove-Item -Force $archive }
Push-Location $Root
try {
    & tar -czf $archive `
        --exclude=.git `
        --exclude=.env `
        --exclude=data `
        --exclude=tests `
        --exclude=__pycache__ `
        --exclude=.pytest_cache `
        --exclude=*.db `
        .
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

& scp @ssh $archive "${target}:/tmp/configmask-deploy.tgz"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Remove-Item -Force $archive

$extract = "mkdir -p '$Dest' && tar -xzf /tmp/configmask-deploy.tgz -C '$Dest' && rm -f /tmp/configmask-deploy.tgz && chmod 755 '$Dest/deploy/remote-install.sh'"
& ssh @ssh $target $extract
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# -t lets sudo ask for a password if this account is not passwordless.
& ssh @ssh -t $target "CONFIGMASK_PORT='$Port' bash '$Dest/deploy/remote-install.sh'"
exit $LASTEXITCODE
