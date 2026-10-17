# wintun.dll'yi resmi siteden indirir, WireGuard imzasını doğrular ve
# derleme klasörlerine (target\debug, target\release) kopyalar.
#
# Kullanım:  powershell -ExecutionPolicy Bypass -File scripts\fetch-wintun.ps1

$ErrorActionPreference = 'Stop'
$version = '0.14.1'
$url = "https://www.wintun.net/builds/wintun-$version.zip"
$root = Split-Path -Parent $PSScriptRoot
$work = Join-Path $root "third_party\wintun-$version"

if (-not (Test-Path "$work\wintun\bin\amd64\wintun.dll")) {
    New-Item -ItemType Directory -Force $work | Out-Null
    $zip = Join-Path $work 'wintun.zip'
    Write-Host "İndiriliyor: $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $work -Force
    Remove-Item $zip
}

$dll = "$work\wintun\bin\amd64\wintun.dll"

# DLL'nin WireGuard LLC tarafından imzalandığını ve imzanın geçerli olduğunu doğrula.
$sig = Get-AuthenticodeSignature $dll
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
    Remove-Item -Recurse -Force $work
    throw "wintun.dll imzası geçersiz! (Durum: $($sig.Status), İmzalayan: $($sig.SignerCertificate.Subject))"
}
Write-Host "İmza doğrulandı: $($sig.SignerCertificate.Subject)"

foreach ($profile in 'debug', 'release') {
    $dest = Join-Path $root "target\$profile"
    New-Item -ItemType Directory -Force $dest | Out-Null
    Copy-Item $dll $dest -Force
    Write-Host "Kopyalandı: $dest\wintun.dll"
}
