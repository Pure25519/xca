<#
Builds OpenSSL 4.1 for Windows (x64, MSVC) from source, reproducibly (BTD-252).

There is no official Windows binary distribution of OpenSSL 4.1, so the build of
XCA with MSVC takes OpenSSL from this script:

- the release tarball of openssl-4.1.0 from GitHub, checked against its pinned
  SHA-256 (the same pin as the Linux build image of bxc-pki);
- Configure VC-WIN64A with the prefix given, shared libraries
  (libcrypto-4-x64.dll, libssl-4-x64.dll), no legacy module;
- SOURCE_DATE_EPOCH fixed to the release date, so the build date compiled into
  the library does not change from one build to the next.

Needs, in an "x64 Native Tools Command Prompt for VS 2022" or after
Launch-VsDevShell -Arch amd64: cl and nmake (Visual Studio 2022 Build Tools),
Perl (Strawberry Perl) and NASM on PATH. PowerShell 7.

Usage, from any directory:
    pwsh -File release\build-openssl-msvc.ps1 -Prefix "$env:ProgramFiles\OpenSSL-Win64"
Then configure XCA with -DOPENSSL_ROOT_DIR=<prefix> (README.md, Windows).
#>
param(
    [string]$Prefix = "$env:ProgramFiles\OpenSSL-Win64",
    [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) 'xca-openssl-build')
)
$ErrorActionPreference = 'Stop'

$Version = 'openssl-4.1.0'
$Sha256 = '50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd'
$Url = "https://github.com/openssl/openssl/releases/download/$Version/$Version.tar.gz"
# 2026-10-23, the release date of OpenSSL 4.1.0
$env:SOURCE_DATE_EPOCH = '1792713600'

foreach ($tool in 'cl', 'nmake', 'perl', 'nasm') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool not found on PATH: run in a VS 2022 x64 developer shell with Perl and NASM"
    }
}

New-Item -ItemType Directory -Force $WorkDir | Out-Null
$tarball = Join-Path $WorkDir "$Version.tar.gz"
if (-not (Test-Path $tarball)) {
    Invoke-WebRequest -Uri $Url -OutFile $tarball
}
$actual = (Get-FileHash -Algorithm SHA256 $tarball).Hash.ToLowerInvariant()
if ($actual -ne $Sha256) {
    Remove-Item $tarball
    throw "SHA-256 of $Version.tar.gz is $actual, expected $Sha256"
}

$src = Join-Path $WorkDir $Version
if (Test-Path $src) { Remove-Item -Recurse -Force $src }
tar -xzf $tarball -C $WorkDir
if ($LASTEXITCODE) { throw "tar failed" }

Push-Location $src
try {
    perl Configure VC-WIN64A "--prefix=$Prefix" "--openssldir=$Prefix\ssl" no-module
    if ($LASTEXITCODE) { throw "Configure failed" }
    nmake
    if ($LASTEXITCODE) { throw "nmake failed" }
    nmake install_sw
    if ($LASTEXITCODE) { throw "nmake install_sw failed" }
} finally {
    Pop-Location
}

$dll = Join-Path $Prefix 'bin\libcrypto-4-x64.dll'
if (-not (Test-Path $dll)) { throw "$dll missing after the install" }
& (Join-Path $Prefix 'bin\openssl.exe') version -a
