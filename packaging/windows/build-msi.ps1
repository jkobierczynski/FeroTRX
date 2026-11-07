# Builds the FeroTRX Windows installer (.msi) with the WiX Toolset 5.
#
#   packaging\windows\build-msi.ps1 [-BinDir target\release] [-Out dist] [-Name ferotrx-vX.Y.Z-x86_64-windows]
#
# Run from the repository root after `cargo build --release -p ferotrx-cli -p ferotrx-gui`.
# Installs WiX (a .NET tool) when it is missing; needs the .NET SDK.
param(
    [string]$BinDir = "target\release",
    [string]$Out = "dist",
    [string]$Name = ""
)
$ErrorActionPreference = "Stop"
$WixVersion = "5.0.2"

$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$cargo = Get-Content "$root\Cargo.toml" -Raw
if ($cargo -notmatch '(?ms)^\[workspace\.package\].*?^version = "(\d+\.\d+\.\d+)"') {
    throw "no [workspace.package] version in Cargo.toml"
}
$version = $Matches[1]
if (-not $Name) { $Name = "ferotrx-v$version-x86_64-windows" }

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    dotnet tool install --global wix --version $WixVersion
    $env:PATH = "$env:PATH;$env:USERPROFILE\.dotnet\tools"
}
wix extension add --global "WixToolset.UI.wixext/$WixVersion"
if ($LASTEXITCODE -ne 0) { throw "wix extension add failed" }

New-Item -ItemType Directory -Force $Out | Out-Null
$bin = (Resolve-Path $BinDir).Path
$msi = Join-Path (Resolve-Path $Out).Path "$Name.msi"
wix build "$root\packaging\windows\ferotrx.wxs" `
    -ext WixToolset.UI.wixext `
    -arch x64 `
    -d "Version=$version" `
    -d "BinDir=$bin" `
    -d "SrcDir=$root" `
    -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
Remove-Item -ErrorAction SilentlyContinue ([IO.Path]::ChangeExtension($msi, ".wixpdb"))
Write-Host "built $msi"
