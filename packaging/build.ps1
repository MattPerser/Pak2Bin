<#
.SYNOPSIS
    Build the release artifacts: the pip wheel and the compiled GUI binary.

.DESCRIPTION
    Nuitka compiles to C, which produces a smaller binary than PyInstaller and
    trips far fewer antivirus heuristics -- which matters for an ECU tool, since
    those get looked at hard.

    Signing is a separate step (packaging\sign.ps1) so that a build can be
    reproduced on a machine that has no access to the signing key.

.EXAMPLE
    .\packaging\build.ps1
    .\packaging\build.ps1 -OneFile
#>
[CmdletBinding()]
param(
    # One self-contained .exe instead of a folder. Slower to start, simpler to
    # ship, and it is the outer executable that carries the signature.
    #
    # Without this the GUI build is a *folder*: the .exe will not run on its own,
    # it needs every Qt DLL beside it. Ship the whole folder, or use -OneFile.
    [switch] $OneFile,

    # Build without Subaru's pack database baked in. The binary then reads the
    # database from an installed copy of FlashWrite, or from --db / --key. Use
    # this for anything you publish, unless you have cleared redistributing it.
    [switch] $NoDatabase,

    # Also build pak2bin.exe: one onefile binary that is the GUI from
    # Explorer and the CLI from a shell.
    [switch] $Cli,

    [string] $Python = 'py',
    [string] $PythonArgs = '-3.11',
    [string] $OutputDir = 'build-nuitka',
    [switch] $SkipWheel
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not $SkipWheel) {
        Write-Host "== wheel + sdist ==" -ForegroundColor Cyan
        & $Python $PythonArgs -m build
        if ($LASTEXITCODE -ne 0) { throw "python -m build failed" }
    }

    Write-Host "== compiled GUI ==" -ForegroundColor Cyan
    $nuitka = @(
        $PythonArgs, '-m', 'nuitka',
        '--standalone',
        '--enable-plugin=pyside6',
        '--windows-console-mode=disable',
        # The pack database is package data and must travel with the binary.
        '--include-package=subaru_pak',
        '--include-package-data=subaru_pak',
        '--include-data-dir=subaru_pak/gui/art=subaru_pak/gui/art',
        "--output-dir=$OutputDir",
        '--output-filename=subaru-pak-gui.exe',
        # Shown as the publisher in the file's Details tab. Keep it matching the
        # organisation on the signing certificate; if the CA styles the name
        # differently from the WA SOS registration, follow the certificate.
        '--company-name=DITCH-HOOK LLC',
        '--product-name=Subaru PAK converter',
        '--file-description=Subaru FlashWrite PAK to ROM converter',
        '--file-version=0.1.0.0',
        '--product-version=0.1.0.0',
        '--assume-yes-for-downloads'
    )
    # An icon is optional, but a release binary without one looks unfinished.
    if (Test-Path 'packaging\subaru-pak.ico') {
        $nuitka += '--windows-icon-from-ico=packaging\subaru-pak.ico'
    }
    if ($NoDatabase) { $nuitka += '--noinclude-data-files=subaru_pak/data/*.csv' }
    if ($OneFile) { $nuitka += '--onefile' }
    $nuitka += 'gui_launcher.py'

    & $Python @nuitka
    if ($LASTEXITCODE -ne 0) { throw "nuitka failed" }

    if ($Cli) {
        # One binary that is an app from Explorer and a shell tool from a shell:
        # double-clicked or with paks dropped on it, it opens the window; given
        # a subcommand, it behaves as the CLI. "attach" console mode is what
        # makes that possible -- it uses the parent's console if there is one
        # and never creates a window of its own.
        Write-Host "== unified binary (pak2bin.exe) ==" -ForegroundColor Cyan
        $cliArgs = @(
            $PythonArgs, '-m', 'nuitka',
            '--onefile',
            '--enable-plugin=pyside6',
            '--windows-console-mode=attach',
            "--output-dir=$OutputDir",
            '--output-filename=pak2bin.exe',
            '--include-package=subaru_pak',
            '--include-package-data=subaru_pak',
            '--include-data-dir=subaru_pak/gui/art=subaru_pak/gui/art',
            '--company-name=DITCH-HOOK LLC',
            '--product-name=Subaru PAK converter',
            '--file-description=Subaru FlashWrite PAK to ROM converter',
            '--file-version=0.1.0.0',
            '--product-version=0.1.0.0',
            '--assume-yes-for-downloads'
        )
        if (Test-Path 'packaging\subaru-pak.ico') {
            $cliArgs += '--windows-icon-from-ico=packaging\subaru-pak.ico'
        }
        if ($NoDatabase) { $cliArgs += '--noinclude-data-files=subaru_pak/data/*.csv' }
        $cliArgs += 'cli_launcher.py'
        & $Python @cliArgs
        if ($LASTEXITCODE -ne 0) { throw "nuitka failed for the CLI build" }
    }

    $artifacts = Get-ChildItem -Path dist, $OutputDir -Recurse `
        -Include *.whl, *.tar.gz, subaru-pak-gui.exe, pak2bin.exe -ErrorAction SilentlyContinue

    Write-Host "`nArtifacts:" -ForegroundColor Green
    $artifacts | ForEach-Object { "  {0,10:N1} MB  {1}" -f ($_.Length / 1MB), $_.FullName }

    # Checksums are what lets someone verify a download that is not signed, and
    # they stay useful once it is. Same format as sha256sum(1), so `sha256sum -c`
    # works and Windows users can compare against Get-FileHash.
    if ($artifacts) {
        if (-not (Test-Path dist)) { New-Item -ItemType Directory dist | Out-Null }
        $sums = Join-Path (Resolve-Path dist) 'SHA256SUMS.txt'
        $lines = $artifacts | ForEach-Object {
            "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
        }
        # Not Set-Content: Windows PowerShell writes UTF-8 *with* a BOM, and a
        # BOM on the first line makes `sha256sum -c` reject the whole file. LF
        # endings for the same reason.
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($sums, (($lines -join "`n") + "`n"), $utf8NoBom)
        Write-Host "`nChecksums: $sums" -ForegroundColor Green
        $lines | ForEach-Object { "  $_" }
    }

    Write-Host @"

Next: publish, and sign the .exe first if you have a certificate.
  .\packaging\sign.ps1 -Thumbprint <your cert> -Path <path to pak2bin.exe>
Unsigned is a valid choice -- ship SHA256SUMS.txt alongside the release either way.
"@
}
finally {
    Pop-Location
}
