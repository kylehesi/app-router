# Downloads wintun.dll from the official site, verifies its WireGuard signature and
# copies it into the build folders (target\debug, target\release).
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1

$ErrorActionPreference = 'Stop'
$version = '0.14.1'
$url = "https://www.wintun.net/builds/wintun-$version.zip"
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $root "third_party\wintun-$version"

if (-not (Test-Path "$work\wintun\bin\amd64\wintun.dll")) {
    New-Item -ItemType Directory -Force $work | Out-Null
    $zip = Join-Path $work 'wintun.zip'
    Write-Host "Downloading: $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $work -Force
    Remove-Item $zip
}

$dll = "$work\wintun\bin\amd64\wintun.dll"

# Verify that the DLL is signed by WireGuard LLC and that the signature is valid.
$sig = Get-AuthenticodeSignature $dll
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
    Remove-Item -Recurse -Force $work
    throw "Invalid wintun.dll signature! (Status: $($sig.Status), Signer: $($sig.SignerCertificate.Subject))"
}
Write-Host "Signature verified: $($sig.SignerCertificate.Subject)"

foreach ($profile in 'debug', 'release') {
    $dest = Join-Path $root "target\$profile"
    New-Item -ItemType Directory -Force $dest | Out-Null
    Copy-Item $dll $dest -Force
    Write-Host "Copied: $dest\wintun.dll"
}
