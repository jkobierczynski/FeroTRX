# Signs the Windows packages of a FeroTRX release with your code signing
# certificate (for example Certum SimplySign: log in to SimplySign Desktop
# first, so the certificate shows up in your certificate store).
#
#   packaging\windows\sign-release.ps1 -Tag v0.38.0 [-Subject "Jurgen ..."] [-Thumbprint ABC...]
#
# Run it on Windows, from a checkout of the repository at that tag, after the
# Release workflow has published the release. It
#   1. downloads the release's Windows .zip and SHA256SUMS (with `gh`),
#   2. signs ferotrx.exe and ferotrx-gui.exe in it (signtool, RFC 3161 time
#      stamp, so the signatures stay valid after the certificate expires),
#   3. builds the .msi again from the signed programs (build-msi.ps1) and
#      signs the .msi,
#   4. zips the signed programs again, fixes SHA256SUMS and replaces the three
#      files on the release.
#
# -From DIR takes the .zip from a folder instead of a release and -NoUpload
# leaves the results in -Out; CI uses both with a throwaway certificate.
# Without -Subject or -Thumbprint, signtool picks the best code signing
# certificate in your store by itself.
param(
    [string]$Tag = "",
    [string]$From = "",
    [string]$Subject = "",
    [string]$Thumbprint = "",
    [string]$TimestampUrl = "http://time.certum.pl",
    [string]$Out = "dist\signed",
    [switch]$NoUpload
)
$ErrorActionPreference = "Stop"
$Repo = "jkobierczynski/FeroTRX"

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $found = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -eq "x64" } |
        Sort-Object { [version]($_.Directory.Parent.Name -replace '[^0-9.]', '') } -Descending |
        Select-Object -First 1
    if ($found) { return $found.FullName }
    throw "signtool.exe not found: install the Windows SDK (its 'Signing Tools for Desktop Apps' part)"
}

if (-not $Tag -and -not $From) { throw "give -Tag vX.Y.Z (a published release) or -From DIR" }
if (-not $NoUpload -and -not $Tag) { throw "uploading needs -Tag; add -NoUpload to only sign" }
if (-not $From -and -not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "gh (GitHub CLI) not found: install it and run 'gh auth login'"
}
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet not found: the .NET SDK is needed to build the installer (WiX)"
}
$signtool = Find-SignTool
Write-Host "signtool: $signtool"

# The installer takes its version, examples and docs from this checkout, so
# it has to be the tagged one.
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
$cargo = Get-Content "$root\Cargo.toml" -Raw
if ($cargo -notmatch '(?ms)^\[workspace\.package\].*?^version = "(\d+\.\d+\.\d+)"') {
    throw "no [workspace.package] version in Cargo.toml"
}
$version = $Matches[1]
if ($Tag -and $Tag -ne "v$version") {
    throw "this checkout is version $version, not ${Tag}: run 'git checkout $Tag' first"
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("ferotrx-sign-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $work, $Out | Out-Null
$Out = (Resolve-Path $Out).Path
try {
    $download = Join-Path $work "download"
    if ($From) {
        $download = (Resolve-Path $From).Path
    } else {
        gh release download $Tag --repo $Repo --dir $download --pattern "*-x86_64-windows.zip" --pattern "SHA256SUMS"
        if ($LASTEXITCODE -ne 0) { throw "could not download release $Tag" }
    }
    $zip = @(Get-ChildItem -Path $download -Filter "*-x86_64-windows.zip")
    if ($zip.Count -ne 1) { throw "expected one *-x86_64-windows.zip in $download, found $($zip.Count)" }
    $zip = $zip[0]
    $name = $zip.BaseName

    $unpacked = Join-Path $work "unpacked"
    Expand-Archive -Path $zip.FullName -DestinationPath $unpacked
    $bin = Join-Path $unpacked $name
    $exes = @("$bin\ferotrx.exe", "$bin\ferotrx-gui.exe")
    foreach ($exe in $exes) { if (-not (Test-Path $exe)) { throw "$exe is missing from $($zip.Name)" } }

    $select = @()
    if ($Thumbprint) { $select = @("/sha1", ($Thumbprint -replace '\s', '')) }
    elseif ($Subject) { $select = @("/n", $Subject) }
    else { $select = @("/a") }
    $stamp = @()
    if ($TimestampUrl) { $stamp = @("/tr", $TimestampUrl, "/td", "sha256") }

    function Sign([string[]]$files) {
        & $signtool sign /fd sha256 @select @stamp /d FeroTRX /du "https://github.com/$Repo" @files
        if ($LASTEXITCODE -ne 0) { throw "signing failed: $files" }
        & $signtool verify /pa @files
        if ($LASTEXITCODE -ne 0) { throw "the signature does not verify: $files" }
    }

    Sign $exes
    & "$bin\ferotrx.exe" --version
    if ($LASTEXITCODE -ne 0) { throw "the signed ferotrx.exe does not run" }

    $signedZip = Join-Path $Out $zip.Name
    Remove-Item -ErrorAction SilentlyContinue $signedZip
    Compress-Archive -Path $bin -DestinationPath $signedZip

    & "$PSScriptRoot\build-msi.ps1" -BinDir $bin -Out $Out -Name $name
    $msi = Join-Path $Out "$name.msi"
    Sign @($msi)

    $files = @($signedZip, $msi)
    $sums = Join-Path $download "SHA256SUMS"
    if (Test-Path $sums) {
        $lines = [Collections.Generic.List[string]]::new()
        $replaced = @{}
        foreach ($f in $files) { $replaced[[IO.Path]::GetFileName($f)] = $f }
        foreach ($line in Get-Content $sums) {
            $file = ($line -split '\s+', 2)[1]
            if ($file) { $file = $file.TrimStart('*') }
            if ($file -and $replaced.ContainsKey($file)) {
                $hash = (Get-FileHash -Algorithm SHA256 $replaced[$file]).Hash.ToLower()
                $lines.Add("$hash  $file")
                $replaced.Remove($file)
            } else {
                $lines.Add($line)
            }
        }
        foreach ($file in $replaced.Keys) {
            $hash = (Get-FileHash -Algorithm SHA256 $replaced[$file]).Hash.ToLower()
            $lines.Add("$hash  $file")
        }
        $newSums = Join-Path $Out "SHA256SUMS"
        # sha256sum's format: LF line ends, no byte order mark.
        [IO.File]::WriteAllText($newSums, ($lines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
        $files += $newSums
    }

    if ($NoUpload) {
        Write-Host "signed, not uploaded:"
        $files | ForEach-Object { Write-Host "  $_" }
    } else {
        gh release upload $Tag --repo $Repo --clobber @files
        if ($LASTEXITCODE -ne 0) { throw "uploading to release $Tag failed" }
        Write-Host "release $Tag now has the signed packages:"
        $files | ForEach-Object { Write-Host "  $([IO.Path]::GetFileName($_))" }
    }
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $work
}
